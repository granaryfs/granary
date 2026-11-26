// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Client authentication in the shipped server configuration, and the
//! identity a
//! verified connection carries.
//! Every server here is built
//! by `server_tls_config`, the one production
//! constructor, and every handshake runs in memory: a `ClientConnection` and
//! a `ServerConnection` shuffling bytes on one thread. **Every refusal
//! asserts a named rustls error and every admission asserts completion**;
//! pump exhaustion is a panic, so a starved harness can never pass as a
//! refusal.
//!
//! **`unwrap()` is a hard error in the helpers below.** `clippy.toml`'s
//! `allow-unwrap-in-tests` covers `#[test]` items, not the plain functions
//! of an integration-test target. The workspace idiom is
//! `.unwrap_or_else(|e| panic!("{e}"))`.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use granary_core::clock::Clock;
use granary_core::enrollment::ClientSpkiDigest;
use granary_core::sheaf::Timestamp;
use granary_net::alpn::GRANARY_ALPN;
use granary_net::identity::{ConnectionIdentity, IdentityError};
use granary_net::pin::{PinnedServerVerifier, spki_digest};
use granary_net::tls::{ClientAuth, TlsConfigError, server_tls_config};
use rcgen::PublicKeyData as _;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, ClientConfig, ClientConnection, ConnectionCommon, Error, ServerConfig,
    ServerConnection, SideData, SignatureScheme,
};

const HOST: &str = "granary.test";

/// 2050-01-01T00:00:00Z: inside every long-lived fixture's validity.
const IN_VALIDITY: i64 = 2_524_608_000;

// ------------------------------------------------------------- the clock

/// A clock a test sets.
#[derive(Debug)]
struct TestClock(AtomicI64);

impl TestClock {
    fn at(secs: i64) -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(secs)))
    }

    fn set(&self, secs: i64) {
        self.0.store(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: self.0.load(Ordering::SeqCst),
            nanos: 0,
        }
    }
}

/// Seconds since the epoch at midnight UTC on the first of `month`.
fn midnight(year: i64, month: i64) -> i64 {
    // Days from the civil date, after Howard Hinnant's `days_from_civil`.
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe - 719_468) * 86_400
}

// --------------------------------------------- the certificate factory

/// A minted certificate and the private key that matches it.
struct Party {
    cert: CertificateDer<'static>,
    key: rcgen::KeyPair,
}

impl Party {
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.serialize_der()))
    }

    /// The SPKI as rcgen encodes it, independently of rustls's parse.
    fn spki(&self) -> Vec<u8> {
        self.key.subject_public_key_info()
    }
}

/// A client CA.
struct Ca {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    cert: CertificateDer<'static>,
}

fn keypair() -> rcgen::KeyPair {
    rcgen::KeyPair::generate().unwrap_or_else(|e| panic!("keypair: {e}"))
}

fn mint_ca(name: &str) -> Ca {
    let key = keypair();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|e| panic!("ca params: {e}"));
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let cert = params
        .self_signed(&key)
        .unwrap_or_else(|e| panic!("ca self-sign: {e}"))
        .der()
        .clone();
    Ca { params, key, cert }
}

/// What a client leaf carries beyond its key and issuer.
struct Profile {
    serial: u64,
    not_before: (i32, u8, u8),
    not_after: (i32, u8, u8),
    eku: Vec<rcgen::ExtendedKeyUsagePurpose>,
    ku: Vec<rcgen::KeyUsagePurpose>,
}

impl Profile {
    /// Long-lived, with `KeyUsage` `digitalSignature` and EKU `clientAuth`:
    /// what an operator is told to issue.
    fn standard() -> Self {
        Self {
            serial: 1,
            not_before: (2020, 1, 1),
            not_after: (2099, 1, 1),
            eku: vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth],
            ku: vec![rcgen::KeyUsagePurpose::DigitalSignature],
        }
    }
}

fn sign_leaf(ca: &Ca, key: rcgen::KeyPair, profile: &Profile) -> Party {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|e| panic!("leaf params: {e}"));
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "granary test client");
    params.serial_number = Some(rcgen::SerialNumber::from(
        profile.serial.to_be_bytes().to_vec(),
    ));
    let (y, m, d) = profile.not_before;
    params.not_before = rcgen::date_time_ymd(y, m, d);
    let (y, m, d) = profile.not_after;
    params.not_after = rcgen::date_time_ymd(y, m, d);
    params.extended_key_usages.clone_from(&profile.eku);
    params.key_usages.clone_from(&profile.ku);
    let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key);
    let cert = params
        .signed_by(&key, &issuer)
        .unwrap_or_else(|e| panic!("sign leaf: {e}"))
        .der()
        .clone();
    Party { cert, key }
}

fn leaf(ca: &Ca, profile: &Profile) -> Party {
    sign_leaf(ca, keypair(), profile)
}

/// The server's own certificate: self-signed, pinned by the client.
fn server_party() -> Party {
    let key = keypair();
    let mut params = rcgen::CertificateParams::new(vec![HOST.to_owned()])
        .unwrap_or_else(|e| panic!("server params: {e}"));
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let cert = params
        .self_signed(&key)
        .unwrap_or_else(|e| panic!("server self-sign: {e}"))
        .der()
        .clone();
    Party { cert, key }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(granary_net::crypto_provider())
}

// -------------------------------------------------------- the configs

fn enrolled_server(server: &Party, ca: &[&Ca], clock: Arc<dyn Clock>) -> ServerConfig {
    server_tls_config(
        vec![server.cert.clone()],
        server.key(),
        ClientAuth::Enrolled {
            ca: ca.iter().map(|ca| ca.cert.clone()).collect(),
            clock,
        },
    )
    .unwrap_or_else(|e| panic!("enrolled server config: {e}"))
}

fn plain_server(server: &Party) -> ServerConfig {
    server_tls_config(vec![server.cert.clone()], server.key(), ClientAuth::None)
        .unwrap_or_else(|e| panic!("server config: {e}"))
}

/// A TLS-1.3 client pinned to `server`, answering a certificate request
/// through `resolver`.
fn client_with(server: &Party, resolver: Arc<dyn ResolvesClientCert>) -> ClientConfig {
    let pin = spki_digest(&server.cert).unwrap_or_else(|e| panic!("pin: {e}"));
    let verifier = PinnedServerVerifier::new(vec![pin], provider())
        .unwrap_or_else(|e| panic!("pin verifier: {e}"));
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| panic!("client versions: {e}"))
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_cert_resolver(resolver);
    config.alpn_protocols = GRANARY_ALPN.iter().map(|p| p.to_vec()).collect();
    config
}

/// A client presenting `credential` with its own key.
fn client_presenting(server: &Party, credential: &Party) -> ClientConfig {
    client_with(server, Counting::presenting(credential).0)
}

/// A client presenting no certificate.
fn anonymous_client(server: &Party) -> ClientConfig {
    client_with(server, Counting::anonymous().0)
}

/// A client-certificate resolver that counts how often it is asked.
#[derive(Debug)]
struct Counting {
    key: Option<Arc<CertifiedKey>>,
    calls: Arc<AtomicUsize>,
}

impl Counting {
    fn with(key: Option<Arc<CertifiedKey>>) -> (Arc<Self>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(Self {
                key,
                calls: Arc::clone(&calls),
            }),
            calls,
        )
    }

    fn anonymous() -> (Arc<Self>, Arc<AtomicUsize>) {
        Self::with(None)
    }

    fn presenting(credential: &Party) -> (Arc<Self>, Arc<AtomicUsize>) {
        let key =
            CertifiedKey::from_der(vec![credential.cert.clone()], credential.key(), &provider())
                .unwrap_or_else(|e| panic!("certified key: {e}"));
        Self::with(Some(Arc::new(key)))
    }
}

impl ResolvesClientCert for Counting {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.key.clone()
    }

    fn has_certs(&self) -> bool {
        true
    }
}

// --------------------------------------------------------------- the pump

const PUMP_LIMIT: usize = 8;

fn transfer<A: SideData, B: SideData>(
    from: &mut ConnectionCommon<A>,
    to: &mut ConnectionCommon<B>,
) -> Result<(), Error> {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire)
            .unwrap_or_else(|e| panic!("write_tls: {e}"));
    }
    let mut rest: &[u8] = &wire;
    while !rest.is_empty() {
        let taken = to
            .read_tls(&mut rest)
            .unwrap_or_else(|e| panic!("read_tls: {e}"));
        assert!(taken > 0, "read_tls consumed nothing with bytes pending");
        to.process_new_packets()?;
    }
    Ok(())
}

fn connect(
    client: ClientConfig,
    server: ServerConfig,
) -> Result<(ClientConnection, ServerConnection), Error> {
    let name = ServerName::try_from(HOST).unwrap_or_else(|e| panic!("server name: {e}"));
    let mut client = ClientConnection::new(Arc::new(client), name)
        .unwrap_or_else(|e| panic!("client connection: {e}"));
    let mut server = ServerConnection::new(Arc::new(server))
        .unwrap_or_else(|e| panic!("server connection: {e}"));
    for _ in 0..PUMP_LIMIT {
        transfer(&mut client, &mut server)?;
        transfer(&mut server, &mut client)?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok((client, server));
        }
    }
    panic!("pump exhausted after {PUMP_LIMIT} iterations: a harness failure, not a refusal");
}

/// A handshake that must complete; the server side's identity.
#[track_caller]
fn admitted(client: ClientConfig, server: ServerConfig) -> ConnectionIdentity {
    match connect(client, server) {
        Ok((_client, server)) => {
            ConnectionIdentity::from_peer_certificates(server.peer_certificates())
                .unwrap_or_else(|e| panic!("identity: {e}"))
        }
        Err(e) => panic!("the handshake was expected to complete, got {e:?}"),
    }
}

/// A handshake that must be refused: the named error.
#[track_caller]
fn refused(client: ClientConfig, server: ServerConfig) -> Error {
    match connect(client, server) {
        Ok(_) => panic!("the handshake was expected to be refused and completed instead"),
        Err(e) => e,
    }
}

fn verified(party: &Party) -> ConnectionIdentity {
    ConnectionIdentity::Verified(ClientSpkiDigest::from_spki_der(&party.spki()))
}

// ======================================================== the trust anchor

/// §13.2 item 16: a certificate from an issuer the server does not trust
/// fails the handshake and never completes as anonymous. The positive
/// controls are the same server with no certificate, and with one from the
/// trusted CA.
#[test]
fn a_certificate_from_another_ca_is_refused_at_the_handshake_never_anonymous() {
    let trusted = mint_ca("trusted client ca");
    let stranger = mint_ca("another ca");
    let server = server_party();
    let clock = TestClock::at(IN_VALIDITY);

    let outsider = leaf(&stranger, &Profile::standard());
    let err = refused(
        client_presenting(&server, &outsider),
        enrolled_server(&server, &[&trusted], clock.clone()),
    );
    assert_eq!(
        err,
        Error::InvalidCertificate(CertificateError::UnknownIssuer)
    );

    assert_eq!(
        admitted(
            anonymous_client(&server),
            enrolled_server(&server, &[&trusted], clock.clone())
        ),
        ConnectionIdentity::Anonymous,
        "the anonymous control"
    );
    let member = leaf(&trusted, &Profile::standard());
    assert_eq!(
        admitted(
            client_presenting(&server, &member),
            enrolled_server(&server, &[&trusted], clock)
        ),
        verified(&member),
        "the trusted control"
    );
}

/// The roots are the given CA certificates and nothing else: with two
/// configured, a leaf of either verifies.
#[test]
fn every_configured_ca_certificate_is_an_anchor() {
    let first = mint_ca("first");
    let second = mint_ca("second");
    let server = server_party();
    let clock = TestClock::at(IN_VALIDITY);
    for ca in [&first, &second] {
        let member = leaf(ca, &Profile::standard());
        assert_eq!(
            admitted(
                client_presenting(&server, &member),
                enrolled_server(&server, &[&first, &second], clock.clone())
            ),
            verified(&member)
        );
    }
}

// =========================================================== the validity

fn is_expired(err: &Error) -> bool {
    matches!(
        err,
        Error::InvalidCertificate(
            CertificateError::Expired | CertificateError::ExpiredContext { .. }
        )
    )
}

fn is_not_yet_valid(err: &Error) -> bool {
    matches!(
        err,
        Error::InvalidCertificate(
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. }
        )
    )
}

/// §13.2 item 16: validity is judged at the `Clock` seam's time. One
/// certificate, valid during 2090 only, is refused before and after it and
/// admitted inside it, with the server's clock the only thing moved. The
/// window is decades from the wall clock, so a server reading the wall
/// clock refuses the admitted arm.
#[test]
fn validity_is_judged_at_the_clock_seams_time() {
    let ca = mint_ca("client ca");
    let server = server_party();
    let profile = Profile {
        not_before: (2090, 1, 1),
        not_after: (2091, 1, 1),
        ..Profile::standard()
    };
    let credential = leaf(&ca, &profile);
    let clock = TestClock::at(midnight(2090, 6));

    assert_eq!(
        admitted(
            client_presenting(&server, &credential),
            enrolled_server(&server, &[&ca], clock.clone())
        ),
        verified(&credential),
        "inside the validity period"
    );

    clock.set(midnight(2091, 6));
    let err = refused(
        client_presenting(&server, &credential),
        enrolled_server(&server, &[&ca], clock.clone()),
    );
    assert!(is_expired(&err), "after the period: {err:?}");

    clock.set(midnight(2089, 6));
    let err = refused(
        client_presenting(&server, &credential),
        enrolled_server(&server, &[&ca], clock.clone()),
    );
    assert!(is_not_yet_valid(&err), "before the period: {err:?}");

    // The clock is read per handshake, not at construction: one config,
    // moved back inside the period, admits again.
    let config = enrolled_server(&server, &[&ca], clock.clone());
    clock.set(midnight(2090, 6));
    assert_eq!(
        admitted(client_presenting(&server, &credential), config),
        verified(&credential)
    );
}

// ======================================================= the key usages

fn is_wrong_purpose(err: &Error) -> bool {
    matches!(
        err,
        Error::InvalidCertificate(
            CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. }
        )
    )
}

/// An extended key usage present without `clientAuth` (a `serverAuth`-only
/// certificate) is refused at the handshake.
#[test]
fn an_extended_key_usage_without_client_auth_is_refused() {
    let ca = mint_ca("client ca");
    let server = server_party();
    let server_only = leaf(
        &ca,
        &Profile {
            eku: vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth],
            ..Profile::standard()
        },
    );
    let err = refused(
        client_presenting(&server, &server_only),
        enrolled_server(&server, &[&ca], TestClock::at(IN_VALIDITY)),
    );
    assert!(is_wrong_purpose(&err), "{err:?}");

    let standard = leaf(&ca, &Profile::standard());
    assert_eq!(
        admitted(
            client_presenting(&server, &standard),
            enrolled_server(&server, &[&ca], TestClock::at(IN_VALIDITY))
        ),
        verified(&standard),
        "the control from the same factory"
    );
}

/// No extended key usage and no `KeyUsage` at all is admitted: an absent EKU
/// allows every purpose (RFC 5280 §4.2.1.12), and `KeyUsage` is not examined.
#[test]
fn a_certificate_with_neither_key_usage_extension_is_admitted() {
    let ca = mint_ca("client ca");
    let server = server_party();
    let bare = leaf(
        &ca,
        &Profile {
            eku: Vec::new(),
            ku: Vec::new(),
            ..Profile::standard()
        },
    );
    assert_eq!(
        admitted(
            client_presenting(&server, &bare),
            enrolled_server(&server, &[&ca], TestClock::at(IN_VALIDITY))
        ),
        verified(&bare)
    );
}

/// **The pinned limit: the X.509 `KeyUsage` extension is not examined.** A
/// leaf whose `KeyUsage` is `keyEncipherment` alone, which does not allow
/// the signature its `CertificateVerify` makes, is admitted, because the
/// pinned webpki ignores `KeyUsage` and nothing else checks it
/// (`server_tls_config`'s docs). If an upgrade starts enforcing `KeyUsage`,
/// this test fails: the limit then has to be reconsidered, not this test
/// silenced.
#[test]
fn key_usage_is_not_examined_the_pinned_limit() {
    let ca = mint_ca("client ca");
    let server = server_party();
    let encipher_only = leaf(
        &ca,
        &Profile {
            eku: vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth],
            ku: vec![rcgen::KeyUsagePurpose::KeyEncipherment],
            ..Profile::standard()
        },
    );
    assert_eq!(
        admitted(
            client_presenting(&server, &encipher_only),
            enrolled_server(&server, &[&ca], TestClock::at(IN_VALIDITY))
        ),
        verified(&encipher_only)
    );
}

// =================================================== proof of possession

/// A client presenting a valid chain while signing with a different key.
/// `CertifiedKey::new` runs no `keys_match`, so the mismatched pair reaches
/// the server's `CertificateVerify` check instead of failing locally.
fn impostor(server: &Party, presented: &Party, signer: &Party) -> ClientConfig {
    let signing_key = provider()
        .key_provider
        .load_private_key(signer.key())
        .unwrap_or_else(|e| panic!("load key: {e}"));
    let certified = CertifiedKey::new(vec![presented.cert.clone()], signing_key);
    assert!(
        certified.keys_match().is_err(),
        "the impostor must genuinely sign with another key, or this proves nothing"
    );
    client_with(server, Counting::with(Some(Arc::new(certified))).0)
}

#[test]
fn a_valid_chain_signed_by_another_key_fails_the_proof_of_possession() {
    let ca = mint_ca("client ca");
    let server = server_party();
    let real = leaf(&ca, &Profile::standard());
    let thief = leaf(&ca, &Profile::standard());

    let err = refused(
        impostor(&server, &real, &thief),
        enrolled_server(&server, &[&ca], TestClock::at(IN_VALIDITY)),
    );
    assert!(
        matches!(
            err,
            Error::InvalidCertificate(CertificateError::BadSignature) | Error::DecryptError
        ),
        "expected a signature refusal, got {err:?}"
    );

    // The control: the same resolver shape, with the matching key.
    let honest = {
        let signing_key = provider()
            .key_provider
            .load_private_key(real.key())
            .unwrap_or_else(|e| panic!("load key: {e}"));
        let certified = CertifiedKey::new(vec![real.cert.clone()], signing_key);
        client_with(&server, Counting::with(Some(Arc::new(certified))).0)
    };
    assert_eq!(
        admitted(
            honest,
            enrolled_server(&server, &[&ca], TestClock::at(IN_VALIDITY))
        ),
        verified(&real)
    );
}

// ======================================================== the two modes

/// `ClientAuth::None` sends no `CertificateRequest`: the client's resolver
/// is never asked. `Enrolled` asks it once per handshake, whether the client
/// then presents a certificate or not.
#[test]
fn the_none_mode_requests_no_certificate_and_the_enrolled_mode_does() {
    let ca = mint_ca("client ca");
    let server = server_party();
    let credential = leaf(&ca, &Profile::standard());

    let (resolver, calls) = Counting::presenting(&credential);
    assert_eq!(
        admitted(client_with(&server, resolver), plain_server(&server)),
        ConnectionIdentity::Anonymous
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no certificate requested");

    let (resolver, calls) = Counting::anonymous();
    assert_eq!(
        admitted(client_with(&server, resolver), plain_server(&server)),
        ConnectionIdentity::Anonymous
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let (resolver, calls) = Counting::presenting(&credential);
    assert_eq!(
        admitted(
            client_with(&server, resolver),
            enrolled_server(&server, &[&ca], TestClock::at(IN_VALIDITY))
        ),
        verified(&credential),
        "the authenticated control"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let (resolver, calls) = Counting::anonymous();
    assert_eq!(
        admitted(
            client_with(&server, resolver),
            enrolled_server(&server, &[&ca], TestClock::at(IN_VALIDITY))
        ),
        ConnectionIdentity::Anonymous,
        "the anonymous control"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// ==================================================== the CA's certificates

/// Every CA certificate must parse: a malformed second one refuses the
/// whole configuration rather than being skipped.
#[test]
fn a_malformed_second_ca_certificate_refuses_the_configuration() {
    let ca = mint_ca("client ca");
    let server = server_party();
    let malformed = [
        CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x01]),
        CertificateDer::from(
            ca.cert
                .as_ref()
                .get(..ca.cert.len() / 2)
                .unwrap_or_default()
                .to_vec(),
        ),
        CertificateDer::from(Vec::new()),
    ];
    for bad in malformed {
        let result = server_tls_config(
            vec![server.cert.clone()],
            server.key(),
            ClientAuth::Enrolled {
                ca: vec![ca.cert.clone(), bad],
                clock: TestClock::at(IN_VALIDITY),
            },
        );
        assert!(
            matches!(result, Err(TlsConfigError::ClientCa { index: 1, .. })),
            "{result:?}"
        );
    }
    // The control: the valid block alone builds.
    let _built = enrolled_server(&server, &[&ca], TestClock::at(IN_VALIDITY));
}

#[test]
fn no_ca_certificate_refuses_the_configuration() {
    let server = server_party();
    let result = server_tls_config(
        vec![server.cert.clone()],
        server.key(),
        ClientAuth::Enrolled {
            ca: Vec::new(),
            clock: TestClock::at(IN_VALIDITY),
        },
    );
    assert!(
        matches!(result, Err(TlsConfigError::NoClientCa)),
        "{result:?}"
    );
}

// =============================================================== the digest

/// The identity is the end entity's SPKI in the enrollment domain: equal to
/// `ClientSpkiDigest::from_spki_der` over the SPKI rcgen encoded, the same
/// across a renewal over the same key, different for a new key, and
/// neither the issuer's SPKI, the whole certificate, nor the server pin's
/// SHA-256 domain.
#[test]
fn the_identity_is_the_leafs_spki_digest_in_the_enrollment_domain() {
    let ca = mint_ca("client ca");
    let server = server_party();
    let clock = TestClock::at(IN_VALIDITY);
    let key_pem = keypair().serialize_pem();
    let reload = || rcgen::KeyPair::from_pem(&key_pem).unwrap_or_else(|e| panic!("key: {e}"));

    let original = sign_leaf(&ca, reload(), &Profile::standard());
    let renewed = sign_leaf(
        &ca,
        reload(),
        &Profile {
            serial: 2,
            not_before: (2021, 1, 1),
            not_after: (2098, 1, 1),
            ..Profile::standard()
        },
    );
    assert_ne!(
        original.cert, renewed.cert,
        "a renewal is another certificate"
    );
    let rekeyed = leaf(&ca, &Profile::standard());

    let identity_of = |party: &Party| {
        admitted(
            client_presenting(&server, party),
            enrolled_server(&server, &[&ca], clock.clone()),
        )
    };
    let ConnectionIdentity::Verified(digest) = identity_of(&original) else {
        panic!("a presented certificate is a verified identity");
    };
    assert_eq!(digest, ClientSpkiDigest::from_spki_der(&original.spki()));
    assert_eq!(identity_of(&renewed), ConnectionIdentity::Verified(digest));
    assert_ne!(identity_of(&rekeyed), ConnectionIdentity::Verified(digest));

    assert_ne!(
        digest,
        ClientSpkiDigest::from_spki_der(&ca.key.subject_public_key_info()),
        "not the issuer's key"
    );
    assert_ne!(
        digest,
        ClientSpkiDigest::from_spki_der(original.cert.as_ref()),
        "not the whole certificate"
    );
    let pin = spki_digest(&original.cert).unwrap_or_else(|e| panic!("pin: {e}"));
    assert_ne!(digest.as_bytes(), &pin, "not the server pin's domain");
}

/// A chain that is present but unreadable is an error, never anonymous;
/// only an absent chain is anonymous.
#[test]
fn an_unreadable_chain_is_an_error_never_anonymous() {
    assert_eq!(
        ConnectionIdentity::from_peer_certificates(None).ok(),
        Some(ConnectionIdentity::Anonymous)
    );
    assert!(matches!(
        ConnectionIdentity::from_peer_certificates(Some(&[])),
        Err(IdentityError::EmptyChain)
    ));
    let garbage = [CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x01])];
    assert!(matches!(
        ConnectionIdentity::from_peer_certificates(Some(&garbage)),
        Err(IdentityError::Unparseable(_))
    ));
    let ca = mint_ca("client ca");
    let member = leaf(&ca, &Profile::standard());
    assert_eq!(
        ConnectionIdentity::from_peer_certificates(Some(std::slice::from_ref(&member.cert))).ok(),
        Some(verified(&member)),
        "the control"
    );
}

#[test]
fn the_midnight_helper_matches_known_instants() {
    assert_eq!(midnight(1970, 1), 0);
    assert_eq!(midnight(2050, 1), IN_VALIDITY);
    assert_eq!(midnight(2000, 3), 951_868_800);
}

/// The identity is the END ENTITY's: with the issuer's certificate after
/// the leaf in the chain, the digest is still the leaf's SPKI, never the
/// last certificate's or the issuer's.
#[test]
fn a_longer_chain_still_identifies_its_end_entity() {
    let ca = mint_ca("the cell");
    let client = leaf(&ca, &Profile::standard());
    let ca_spki = ca.key.subject_public_key_info();
    let chain = [client.cert.clone(), ca.cert.clone()];
    let identity = ConnectionIdentity::from_peer_certificates(Some(&chain))
        .unwrap_or_else(|e| panic!("a two-certificate chain: {e}"));
    assert_eq!(identity, verified(&client));
    assert_ne!(
        identity,
        ConnectionIdentity::Verified(ClientSpkiDigest::from_spki_der(&ca_spki))
    );
}
