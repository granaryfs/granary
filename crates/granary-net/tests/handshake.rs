// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The in-memory TLS handshake harness, and every test of the pinned SPKI
//! verifier and the ALPN admission predicate.
//!
//! A `ClientConnection` and a `ServerConnection` are driven against each
//! other on one thread by shuffling bytes with `write_tls` / `read_tls` /
//! `process_new_packets`. No tokio, no threads, no sockets — so nothing
//! here trips the workspace's concurrency bans and nothing needs an `#[expect]`
//! budget.
//!
//! **The invariant that keeps this suite exhaustion-safe.** A starved pump
//! on a perfectly valid pin also reports "handshake not complete", so a
//! test written as `assert!(result != Complete)` reads a harness bug as a
//! peer refusal and passes green over it. Therefore: **every refusal test
//! asserts a NAMED `rustls` error, and every admission test asserts
//! completion.** Pump exhaustion is a panic, never a returned value, so it
//! can never be confused with either. Keep both halves when adding a test.
//!
//! **`unwrap()` is a hard error in the helpers below.** `clippy.toml`'s
//! `allow-unwrap-in-tests` covers `#[test]` items, not the plain functions
//! in an integration-test target, which is what the harness, the
//! certificate factory and the config builders are. The workspace idiom is
//! `.unwrap_or_else(|e| panic!("{e}"))`.

use std::sync::Arc;
use std::time::Duration;

use granary_net::alpn::{self, ALPN_H2, ALPN_HTTP11, GRANARY_ALPN};
use granary_net::config::parse_pin_set;
use granary_net::pin::{
    PIN_LEN, PIN_SET_MAX, PinSetError, PinnedServerVerifier, SpkiPin, spki_digest,
};
use granary_net::tls::client_tls_config;
use proptest::prelude::*;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, ConnectionCommon, DigitallySignedStruct,
    Error, PeerIncompatible, RootCertStore, ServerConfig, ServerConnection, SideData,
    SignatureScheme,
};

// ---------------------------------------------------------------- fixtures

/// The name every harness certificate carries and every client asks for.
const TEST_HOST: &str = "granary.test";

/// A certificate whose SPKI digest was computed by OpenSSL, outside this
/// crate and outside `rustls`, so that the digest DOMAIN is pinned by
/// something other than the code under test. Public half only: a
/// certificate, no key material;
/// nothing here is private.
///
/// ```bash
/// openssl x509 -in crates/granary-net/tests/fixtures/golden-cert.der \
///   -inform DER -pubkey -noout \
///   | openssl pkey -pubin -outform DER | shasum -a 256
/// ```
const GOLDEN_CERT_DER: &[u8] = include_bytes!("fixtures/golden-cert.der");

/// The output of the pipeline above, transcribed.
const GOLDEN_SPKI_PIN: SpkiPin = [
    0x7c, 0xc7, 0x95, 0x04, 0xb5, 0xa6, 0x04, 0x31, 0x28, 0x8b, 0x68, 0x43, 0x64, 0x6b, 0x09, 0xed,
    0x66, 0xe1, 0x10, 0x34, 0xf1, 0x22, 0x39, 0xd4, 0xd2, 0x08, 0x0f, 0x6f, 0x9a, 0xa9, 0x68, 0x3e,
];

/// RFC 5280 says a `SubjectPublicKeyInfo` is a SEQUENCE; RFC 7469 §2.4
/// hashes it whole. For this fixture's P-256 key that is 91 bytes: `0x30`,
/// a declared length of 89, then the `AlgorithmIdentifier` and the key
/// bits. Asserting the shape keeps "we hash the SPKI" from degrading into
/// "we hash something 32 bytes wide".
const GOLDEN_SPKI_LEN: usize = 91;

/// Seconds from the Unix epoch to 2026-08-16T00:00:00Z, comfortably after
/// the expired fixture's `not_after` of 2001-01-01.
const FIXED_NOW_SECS: u64 = 1_786_838_400;

/// A fixed instant, so the stock-verifier control below is deterministic.
/// The pinned path reads no clock at all, which is why only the control
/// needs this.
fn fixed_now() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(FIXED_NOW_SECS))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(granary_net::crypto_provider())
}

fn server_name() -> ServerName<'static> {
    ServerName::try_from(TEST_HOST).unwrap_or_else(|e| panic!("server name: {e}"))
}

fn golden_cert() -> CertificateDer<'static> {
    CertificateDer::from(GOLDEN_CERT_DER)
}

// ------------------------------------------------- the certificate factory

/// A minted certificate and the private key that matches it.
struct Party {
    cert: CertificateDer<'static>,
    pkcs8: Vec<u8>,
}

impl Party {
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.pkcs8.clone()))
    }

    #[track_caller]
    fn pin(&self) -> SpkiPin {
        digest_of(&self.cert)
    }
}

#[track_caller]
fn digest_of(cert: &CertificateDer<'_>) -> SpkiPin {
    spki_digest(cert).unwrap_or_else(|e| panic!("spki digest: {e}"))
}

fn keypair() -> rcgen::KeyPair {
    rcgen::KeyPair::generate().unwrap_or_else(|e| panic!("keypair: {e}"))
}

/// Issue a self-signed certificate for [`TEST_HOST`] from `key`.
///
/// `serial` and `not_after` are parameters because two certificates over
/// ONE key pair — differing in every field but the SPKI — are what proves
/// the pin is an SPKI pin rather than a whole-certificate pin.
fn issue(key: &rcgen::KeyPair, serial: u64, not_after: (i32, u8, u8)) -> CertificateDer<'static> {
    let mut params = rcgen::CertificateParams::new(vec![TEST_HOST.to_owned()])
        .unwrap_or_else(|e| panic!("cert params: {e}"));
    params.serial_number = Some(rcgen::SerialNumber::from(serial.to_be_bytes().to_vec()));
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    let (year, month, day) = not_after;
    params.not_after = rcgen::date_time_ymd(year, month, day);
    params
        .self_signed(key)
        .unwrap_or_else(|e| panic!("self-sign: {e}"))
        .der()
        .clone()
}

/// A fresh key pair and a long-lived certificate over it.
fn mint(serial: u64) -> Party {
    let key = keypair();
    Party {
        cert: issue(&key, serial, (2099, 1, 1)),
        pkcs8: key.serialize_der(),
    }
}

// ------------------------------------------------------- the config builders

fn pin_verifier(pins: Vec<SpkiPin>) -> Arc<PinnedServerVerifier> {
    Arc::new(
        PinnedServerVerifier::new(pins, provider())
            .unwrap_or_else(|e| panic!("pin set rejected: {e}")),
    )
}

fn client_with(verifier: Arc<dyn ServerCertVerifier>, alpn: &[&[u8]]) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| panic!("client versions: {e}"))
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

/// A TLS-1.2-only client. It exists only to be refused: `rustls`'s
/// `DEFAULT_VERSIONS` is `[&TLS13, &TLS12]` and the `tls12` feature is on
/// by default, so the *default* config would negotiate TLS 1.2 happily.
/// Production configs must explicitly restrict negotiation to TLS 1.3;
/// this harness proves the mechanism.
fn tls12_client(verifier: Arc<dyn ServerCertVerifier>) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap_or_else(|e| panic!("client versions: {e}"))
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = GRANARY_ALPN.iter().map(|p| p.to_vec()).collect();
    config
}

/// The SHIPPING client configuration, built by the one production
/// constructor. Every `production_client_config_*` test below goes
/// through this and nothing else: a per-test config would prove things
/// about a stack assembled in a test, which is precisely what
/// `server_tls_config`'s module docs say the single constructor exists to
/// prevent.
fn production_client(pins: Vec<SpkiPin>) -> ClientConfig {
    client_tls_config(pin_verifier(pins), None).unwrap_or_else(|e| panic!("client config: {e}"))
}

/// A TLS-1.2-only SERVER. The mirror of [`tls12_client`], and the peer
/// the production client's TLS-1.3-only configuration must refuse: TLS 1.2
/// is offered by the far end, not by the client itself.
fn tls12_server(party: &Party, alpn: &[&[u8]]) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap_or_else(|e| panic!("server versions: {e}"))
        .with_no_client_auth()
        .with_single_cert(vec![party.cert.clone()], party.key())
        .unwrap_or_else(|e| panic!("server cert: {e}"));
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

/// Mint a CA and one end-entity certificate it signs.
///
/// This exists for ONE test — the WebPKI-valid but unpinned server. Every
/// other fixture here is self-signed, so a verifier that fell back to the
/// Web PKI would refuse them all and look like it was pinning.
fn mint_ca_and_leaf() -> (CertificateDer<'static>, Party) {
    let ca_key = keypair();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|e| panic!("ca params: {e}"));
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    ca_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .unwrap_or_else(|e| panic!("self-sign ca: {e}"))
        .der()
        .clone();

    let leaf_key = keypair();
    let mut leaf_params = rcgen::CertificateParams::new(vec![TEST_HOST.to_owned()])
        .unwrap_or_else(|e| panic!("leaf params: {e}"));
    leaf_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    leaf_params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .unwrap_or_else(|e| panic!("sign leaf: {e}"))
        .der()
        .clone();

    (
        ca_cert,
        Party {
            cert: leaf,
            pkcs8: leaf_key.serialize_der(),
        },
    )
}

fn server_with(party: &Party, alpn: &[&[u8]]) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| panic!("server versions: {e}"))
        .with_no_client_auth()
        .with_single_cert(vec![party.cert.clone()], party.key())
        .unwrap_or_else(|e| panic!("server cert: {e}"));
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

/// A server presenting a two-certificate chain: `party`'s end-entity plus
/// an unrelated `filler` as an "intermediate". The pin verifier ignores
/// intermediates by design (the pin binds the end-entity SPKI and
/// nothing else), and this helper exists so a test can prove the chain's
/// PRESENCE changes nothing — in either direction. A verifier that
/// fail-opened on a non-empty chain would be a total pin bypass, and no
/// single-cert test can see it.
fn server_with_chain(party: &Party, filler: &Party, alpn: &[&[u8]]) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| panic!("server versions: {e}"))
        .with_no_client_auth()
        .with_single_cert(vec![party.cert.clone(), filler.cert.clone()], party.key())
        .unwrap_or_else(|e| panic!("server chain: {e}"));
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

/// A server presenting `cert` while holding a key that does not match it.
///
/// `CertifiedKey::from_der` would refuse this; `CertifiedKey::new` does not
/// run `keys_match`, which is exactly how a real impostor who has seen one
/// handshake would be configured. The assertion inside is what makes the
/// two impostor tests differ only in the client's verifier.
fn impostor_server(cert: &CertificateDer<'static>, wrong: &Party) -> ServerConfig {
    let provider = provider();
    let key = provider
        .key_provider
        .load_private_key(wrong.key())
        .unwrap_or_else(|e| panic!("load key: {e}"));
    let certified = CertifiedKey::new(vec![cert.clone()], key);
    assert!(
        certified.keys_match().is_err(),
        "the impostor must genuinely hold a different key, or the test proves nothing"
    );
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| panic!("server versions: {e}"))
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    config.alpn_protocols = GRANARY_ALPN.iter().map(|p| p.to_vec()).collect();
    config
}

// ------------------------------------------------------------------ the pump

/// Outer iterations the pump will run before declaring a harness failure.
/// A plain TLS 1.3 handshake needs 2 and a `HelloRetryRequest` needs 3.
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

/// Drive both peers to a completed handshake.
///
/// Returns the first named `rustls` error either peer raises. Running out
/// of iterations PANICS: it is a harness failure and must never be
/// mistakable for a peer's refusal.
fn pump(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), Error> {
    for _ in 0..PUMP_LIMIT {
        transfer(client, server)?;
        transfer(server, client)?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("pump exhausted after {PUMP_LIMIT} iterations — a HARNESS failure, not a refusal");
}

#[track_caller]
fn connect(
    client: ClientConfig,
    server: ServerConfig,
) -> Result<(ClientConnection, ServerConnection), Error> {
    let mut client = ClientConnection::new(Arc::new(client), server_name())
        .unwrap_or_else(|e| panic!("client connection: {e}"));
    let mut server = ServerConnection::new(Arc::new(server))
        .unwrap_or_else(|e| panic!("server connection: {e}"));
    pump(&mut client, &mut server)?;
    Ok((client, server))
}

/// A handshake that must succeed, returning both completed peers.
#[track_caller]
fn expect_handshake(
    client: ClientConfig,
    server: ServerConfig,
) -> (ClientConnection, ServerConnection) {
    match connect(client, server) {
        Ok(pair) => pair,
        Err(e) => panic!("handshake was expected to complete, got {e:?}"),
    }
}

/// A handshake that must be refused, returning the named error.
#[track_caller]
fn expect_refusal(client: ClientConfig, server: ServerConfig) -> Error {
    match connect(client, server) {
        Ok(_) => panic!("handshake was expected to be refused and completed instead"),
        Err(e) => e,
    }
}

// ------------------------------------------------- the broken-verifier control

/// The pinned verifier with its signature methods stubbed out — committed,
/// not described in a commit message, because a suite holding only the
/// "impostor is refused" assertion also passes against a verifier that
/// refuses *everything*.
#[derive(Debug)]
struct StubbedSignatureVerifier(Arc<PinnedServerVerifier>);

impl ServerCertVerifier for StubbedSignatureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// A `DigitallySignedStruct` that is well-formed on the wire and a valid
/// signature over nothing. `DigitallySignedStruct::new` is `pub(crate)`, so
/// its public `Codec` impl is the only way in from outside `rustls`.
fn corrupt_dss() -> DigitallySignedStruct {
    let mut wire = vec![0x04, 0x03, 0x00, 0x08];
    wire.extend_from_slice(&[0xAA; 8]);
    let mut reader = Reader::init(&wire);
    DigitallySignedStruct::read(&mut reader).unwrap_or_else(|e| panic!("dss codec: {e:?}"))
}

#[track_caller]
fn flip_bit(mut digest: SpkiPin, bit: usize) -> SpkiPin {
    let mask = 1u8 << (bit % 8);
    match digest.get_mut(bit / 8) {
        Some(byte) => *byte ^= mask,
        None => panic!("bit {bit} is outside a {PIN_LEN}-byte digest"),
    }
    digest
}

// ============================================================== the pin tests

/// An impostor presenting the PINNED certificate while holding a different
/// private key is refused — the whole reason the signature methods delegate.
#[test]
fn impostor_holding_a_different_key_is_refused() {
    let real = mint(1);
    let thief = mint(2);
    let verifier = pin_verifier(vec![real.pin()]);

    let err = expect_refusal(
        client_with(verifier, &GRANARY_ALPN),
        impostor_server(&real.cert, &thief),
    );
    assert!(
        matches!(
            err,
            Error::InvalidCertificate(CertificateError::BadSignature) | Error::DecryptError
        ),
        "expected a signature refusal, got {err:?}"
    );
}

/// The control: with the signature methods stubbed, the SAME impostor is
/// ADMITTED. The two tests differ in exactly one thing — the verifier — so
/// the one above cannot be passing because the harness refuses everything.
#[test]
fn stubbed_signature_verifier_admits_the_impostor() {
    let real = mint(1);
    let thief = mint(2);
    let stubbed = Arc::new(StubbedSignatureVerifier(pin_verifier(vec![real.pin()])));

    let (client, server) = expect_handshake(
        client_with(stubbed, &GRANARY_ALPN),
        impostor_server(&real.cert, &thief),
    );
    assert!(!client.is_handshaking() && !server.is_handshaking());
}

/// A TLS-1.2-only peer never reaches the certificate, so no handshake in
/// this file can exercise `verify_tls12_signature`. Call it directly
/// instead — with the stub beside it, so "returns Err" is shown to be a
/// property of the delegation and not of the input.
#[test]
fn verify_tls12_signature_delegates_rather_than_asserting() {
    let real = mint(1);
    let verifier = pin_verifier(vec![real.pin()]);
    let stubbed = StubbedSignatureVerifier(Arc::clone(&verifier));
    let dss = corrupt_dss();

    let delegated = verifier.verify_tls12_signature(b"transcript", &real.cert, &dss);
    assert!(
        delegated.is_err(),
        "a corrupted signature must not verify, got {delegated:?}"
    );
    assert!(
        stubbed
            .verify_tls12_signature(b"transcript", &real.cert, &dss)
            .is_ok(),
        "the control must accept it, or the assertion above proves nothing"
    );
}

/// The correct pin is admitted, and the negotiated ALPN token is asserted
/// BY VALUE on both sides.
#[test]
fn correct_pin_is_admitted_and_alpn_agrees_on_both_sides() {
    let real = mint(1);
    let verifier = pin_verifier(vec![real.pin()]);

    let (client, server) = expect_handshake(
        client_with(verifier, &GRANARY_ALPN),
        server_with(&real, &GRANARY_ALPN),
    );
    assert_eq!(client.alpn_protocol(), Some(ALPN_H2));
    assert_eq!(server.alpn_protocol(), Some(ALPN_H2));
    assert!(alpn::admits(client.alpn_protocol()));
    assert!(alpn::admits(server.alpn_protocol()));
}

/// A wrong pin is refused, and specifically as
/// `ApplicationVerificationFailure` — a code `rustls` itself never
/// constructs, so the assertion cannot be satisfied by some unrelated
/// internal failure.
#[test]
fn wrong_pin_is_refused_as_application_verification_failure() {
    let real = mint(1);
    let other = mint(2);
    let verifier = pin_verifier(vec![other.pin()]);

    let err = expect_refusal(
        client_with(verifier, &GRANARY_ALPN),
        server_with(&real, &GRANARY_ALPN),
    );
    assert_eq!(
        err,
        Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
        "got {err:?}"
    );
}

/// A presented certificate CHAIN changes nothing, in either direction.
///
/// Every other handshake test sends a single certificate, so
/// `verify_server_cert`'s `intermediates` argument is empty across the
/// whole suite — and a verifier that fail-opened on a non-empty chain
/// (`if !intermediates.is_empty() { admit }`) would pass every one of
/// them while being a total pin bypass. This test is the one place the
/// argument is non-empty: a wrong pin must still be refused, and the
/// correct pin must still be admitted, with an unrelated filler
/// certificate riding along as an "intermediate" in both cases.
#[test]
fn presented_chain_changes_nothing_for_the_pin() {
    let real = mint(1);
    let filler = mint(2);
    let other = mint(3);

    let err = expect_refusal(
        client_with(pin_verifier(vec![other.pin()]), &GRANARY_ALPN),
        server_with_chain(&real, &filler, &GRANARY_ALPN),
    );
    assert_eq!(
        err,
        Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
        "a wrong pin must be refused even when a chain is presented, got {err:?}"
    );

    let (client, server) = expect_handshake(
        client_with(pin_verifier(vec![real.pin()]), &GRANARY_ALPN),
        server_with_chain(&real, &filler, &GRANARY_ALPN),
    );
    assert!(
        alpn::admits(client.alpn_protocol()),
        "the correct pin must still be admitted with a chain present"
    );
    assert!(alpn::admits(server.alpn_protocol()));
}

/// A wrong pin is refused against a MULTI-ENTRY set too. Without this, a
/// verifier that accepts anything once the set has more than one entry
/// passes the whole suite — which would mean adding the documented backup
/// pin silently disables server authentication.
#[test]
fn wrong_pin_is_refused_against_a_two_entry_set() {
    let real = mint(1);
    let first = mint(2);
    let second = mint(3);
    let verifier = pin_verifier(vec![first.pin(), second.pin()]);

    let err = expect_refusal(
        client_with(verifier, &GRANARY_ALPN),
        server_with(&real, &GRANARY_ALPN),
    );
    assert_eq!(
        err,
        Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
        "got {err:?}"
    );
}

/// An EMPTY pin set refuses everything — **and the set an UNSET
/// VARIABLE parses to is that set.**
///
/// "Not configured yet" is the natural place for a fail-open branch, and
/// nothing else in the suite would notice one.
///
/// **The two halves were both real and never joined.** `parse_pin_set`'s
/// own rows assert that an empty or whitespace value is `Ok(vec![])`,
/// and this row asserted that an empty set refuses a certificate — with
/// nothing anywhere saying the set the parser produces IS the set the
/// verifier refuses. The reasoning was sound and untested, which is the
/// state a "no pins configured means no pinning required" convenience
/// slips into: it would leave both halves green and every connection
/// unauthenticated. So the set below comes out of the parser, from the
/// three renderings an unset variable actually takes.
#[test]
fn empty_pin_set_refuses_everything() {
    let real = mint(1);
    for unset in ["", "   ", "\t\n"] {
        let parsed = parse_pin_set(unset)
            .unwrap_or_else(|e| panic!("{unset:?} is the unset form, not a parse failure: {e}"));
        assert!(
            parsed.is_empty(),
            "{unset:?} must parse to NO pins, got {}",
            parsed.len()
        );
    }
    let verifier =
        pin_verifier(parse_pin_set("").unwrap_or_else(|e| panic!("the unset form parses: {e}")));
    assert!(!verifier.is_pinned(&real.pin()));

    let err = expect_refusal(
        client_with(verifier, &GRANARY_ALPN),
        server_with(&real, &GRANARY_ALPN),
    );
    assert_eq!(
        err,
        Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
        "got {err:?}"
    );
}

/// A two-entry set admits EITHER member, proven with two independent
/// certificates. One certificate matching `pins[0]` would satisfy the naive
/// wording while `contains` short-circuits and the backup slot stays
/// untested.
#[test]
fn two_entry_set_admits_either_certificate() {
    let first = mint(1);
    let second = mint(2);
    let pins = vec![first.pin(), second.pin()];

    for party in [&first, &second] {
        let (client, server) = expect_handshake(
            client_with(pin_verifier(pins.clone()), &GRANARY_ALPN),
            server_with(party, &GRANARY_ALPN),
        );
        assert!(!client.is_handshaking() && !server.is_handshaking());
    }
}

/// The pin is an SPKI pin, not a whole-certificate pin. Two certificates
/// over ONE key pair — different serial, different validity, therefore
/// different DER — must both be admitted by ONE pin. A verifier hashing the
/// whole certificate passes every other test here and then refuses the
/// renewed certificate of an unrotated key.
#[test]
fn one_pin_admits_two_certificates_over_the_same_key() {
    let key = keypair();
    let renewed = Party {
        cert: issue(&key, 0xDEAD_BEEF, (2098, 6, 30)),
        pkcs8: key.serialize_der(),
    };
    let original = Party {
        cert: issue(&key, 1, (2099, 1, 1)),
        pkcs8: key.serialize_der(),
    };
    assert_ne!(
        original.cert.as_ref(),
        renewed.cert.as_ref(),
        "the two certificates must differ in their DER, or this proves nothing"
    );
    assert_eq!(
        original.pin(),
        renewed.pin(),
        "the two certificates share a key pair, so they share an SPKI digest"
    );

    let pins = vec![original.pin()];
    for party in [&original, &renewed] {
        let (client, server) = expect_handshake(
            client_with(pin_verifier(pins.clone()), &GRANARY_ALPN),
            server_with(party, &GRANARY_ALPN),
        );
        assert!(!client.is_handshaking() && !server.is_handshaking());
    }
}

/// An expired certificate is admitted — WITH a control proving it really is
/// expired. "The handshake completed" is also what a valid certificate
/// produces, so without the control this test passes identically when
/// `not_after` was never set.
#[test]
fn expired_certificate_is_admitted_by_the_pin_and_rejected_by_webpki() {
    let key = keypair();
    let expired = Party {
        cert: issue(&key, 7, (2001, 1, 1)),
        pkcs8: key.serialize_der(),
    };

    let mut roots = RootCertStore::empty();
    roots
        .add(expired.cert.clone())
        .unwrap_or_else(|e| panic!("root store: {e}"));
    let stock = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
        .build()
        .unwrap_or_else(|e| panic!("webpki verifier: {e}"));
    let control = stock.verify_server_cert(&expired.cert, &[], &server_name(), &[], fixed_now());
    assert!(
        matches!(
            control,
            Err(Error::InvalidCertificate(
                CertificateError::Expired | CertificateError::ExpiredContext { .. }
            ))
        ),
        "the control certificate must actually be expired, got {control:?}"
    );

    let (client, server) = expect_handshake(
        client_with(pin_verifier(vec![expired.pin()]), &GRANARY_ALPN),
        server_with(&expired, &GRANARY_ALPN),
    );
    assert!(!client.is_handshaking() && !server.is_handshaking());
}

/// A TLS-1.2-only peer is refused. Three configs, not two: asserting that a
/// TLS-1.2 peer fails while every config in the test is TLS-1.3-only tests
/// nothing.
#[test]
fn tls12_only_peer_is_refused() {
    let real = mint(1);
    let pins = vec![real.pin()];

    let (client, server) = expect_handshake(
        client_with(pin_verifier(pins.clone()), &GRANARY_ALPN),
        server_with(&real, &GRANARY_ALPN),
    );
    assert!(!client.is_handshaking() && !server.is_handshaking());

    let err = expect_refusal(
        tls12_client(pin_verifier(pins)),
        server_with(&real, &GRANARY_ALPN),
    );
    assert_eq!(
        err,
        Error::PeerIncompatible(PeerIncompatible::Tls12NotOfferedOrEnabled),
        "got {err:?}"
    );
}

// ------------------------------------------ the digest domain, pinned outside

/// The digest domain is fixed by an externally computed golden value.
///
/// Every other pin test derives its expected digest from the same helper
/// the verifier uses, so all of them pass against a verifier that hashes
/// the `subjectPublicKey` bits alone — while refusing every pin an operator
/// generates with standard tooling. A self-consistent suite is not an
/// interoperable one.
#[test]
fn golden_certificate_matches_the_externally_computed_digest() {
    let cert = golden_cert();
    assert_eq!(
        spki_digest(&cert).unwrap_or_else(|e| panic!("golden digest: {e}")),
        GOLDEN_SPKI_PIN
    );

    let verifier = pin_verifier(vec![GOLDEN_SPKI_PIN]);
    let admitted = verifier.verify_server_cert(&cert, &[], &server_name(), &[], fixed_now());
    assert!(admitted.is_ok(), "golden pin must admit, got {admitted:?}");
}

/// The SPKI whose digest the golden value covers is the whole RFC 5280
/// structure — outer SEQUENCE tag and length included — not the key bits.
#[test]
fn golden_spki_is_a_whole_der_sequence() {
    let cert = golden_cert();
    let parsed = rustls::server::ParsedCertificate::try_from(&cert)
        .unwrap_or_else(|e| panic!("parse golden: {e}"));
    let spki = parsed.subject_public_key_info();
    let bytes: &[u8] = spki.as_ref();
    assert_eq!(bytes.len(), GOLDEN_SPKI_LEN);
    assert_eq!(bytes.first(), Some(&0x30), "SPKI must open a DER SEQUENCE");
    assert_eq!(
        bytes.get(1).copied().map(usize::from),
        Some(GOLDEN_SPKI_LEN - 2),
        "the declared length must cover the rest of the structure"
    );
}

// ------------------------------------------------ the bounded domain, swept

/// `PIN_SET_MAX + 1` pins is a configuration error, not a verifier that
/// quietly accepts. This is what makes the property below exhaustive rather
/// than sampled: the legal domain is finite.
#[test]
fn oversized_pin_set_is_refused_at_construction() {
    let pins: Vec<SpkiPin> = (0..=u8::try_from(PIN_SET_MAX).unwrap_or(u8::MAX))
        .map(|i| {
            let mut pin = [1u8; PIN_LEN];
            pin[0] = i.wrapping_add(1);
            pin
        })
        .collect();
    assert_eq!(pins.len(), PIN_SET_MAX + 1);
    assert_eq!(
        PinnedServerVerifier::new(pins, provider()).err(),
        Some(PinSetError::TooManyPins {
            got: PIN_SET_MAX + 1
        })
    );
}

/// The all-zero digest is refused at construction. Uniform generation never
/// draws it, so no property test would find it — and a zeroed default
/// configuration field is exactly how it would reach production.
#[test]
fn all_zero_pin_is_refused_at_construction() {
    assert_eq!(
        PinnedServerVerifier::new(vec![[0u8; PIN_LEN]], provider()).err(),
        Some(PinSetError::ZeroPin)
    );
    let real = mint(1);
    assert_eq!(
        PinnedServerVerifier::new(vec![[0u8; PIN_LEN], real.pin()], provider()).err(),
        Some(PinSetError::ZeroPin)
    );
}

/// Equality is full-width, enforced per bit. A comparator reading any
/// strict subset of the digest — a four-byte prefix, say — admits every
/// correct pin and rejects every independently generated wrong one, passing
/// everything else here, while an attacker grinds a ~2^32 key search to a
/// certificate whose digest shares the prefix.
#[test]
fn every_single_bit_perturbation_of_a_member_is_a_non_member() {
    let member = GOLDEN_SPKI_PIN;
    let verifier = pin_verifier(vec![member]);
    assert!(verifier.is_pinned(&member));
    for bit in 0..PIN_LEN * 8 {
        let near = flip_bit(member, bit);
        assert_ne!(near, member);
        assert!(
            !verifier.is_pinned(&near),
            "bit {bit} perturbation admitted"
        );
    }
}

/// The same property at handshake level: a pin one bit away from the real
/// server's digest is refused end to end, not merely by the unit predicate.
#[test]
fn handshake_level_near_miss_pin_is_refused() {
    let real = mint(1);
    let near = flip_bit(real.pin(), PIN_LEN * 8 - 1);

    let err = expect_refusal(
        client_with(pin_verifier(vec![near]), &GRANARY_ALPN),
        server_with(&real, &GRANARY_ALPN),
    );
    assert_eq!(
        err,
        Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
        "got {err:?}"
    );
}

/// Pins drawn from the values that break naive implementations: uniform
/// noise, the fail-open sentinel, its all-ones twin, single-bit
/// perturbations of the probe, and the probe itself.
fn pin_strategy(probe: SpkiPin) -> impl Strategy<Value = SpkiPin> {
    prop_oneof![
        4 => proptest::array::uniform32(any::<u8>()),
        1 => Just([0u8; PIN_LEN]),
        1 => Just([0xFFu8; PIN_LEN]),
        3 => (0usize..PIN_LEN * 8).prop_map(move |bit| flip_bit(probe, bit)),
        3 => Just(probe),
    ]
}

proptest! {
    /// Across the ENTIRE legal cardinality range, the verifier admits a
    /// certificate exactly when its SPKI digest is in the set — both
    /// directions — and refuses the set outright when it holds the
    /// sentinel. Bounding the domain is what turns this from a sample into
    /// a sweep: three successive degenerate implementations
    /// (`len() > 1`, `len() >= 3`, `len() >= 9`) each lived one cardinality
    /// above the previous unbounded property.
    #[test]
    fn membership_is_exact_over_the_whole_legal_domain(
        pins in proptest::collection::vec(pin_strategy(GOLDEN_SPKI_PIN), 0..=PIN_SET_MAX)
    ) {
        let cert = golden_cert();
        let built = PinnedServerVerifier::new(pins.clone(), provider());

        if pins.contains(&[0u8; PIN_LEN]) {
            prop_assert_eq!(built.err(), Some(PinSetError::ZeroPin));
            return Ok(());
        }

        let verifier = match built {
            Ok(v) => v,
            Err(e) => return Err(TestCaseError::fail(format!("legal set refused: {e}"))),
        };
        let expected = pins.contains(&GOLDEN_SPKI_PIN);
        prop_assert_eq!(verifier.is_pinned(&GOLDEN_SPKI_PIN), expected);
        prop_assert_eq!(
            verifier
                .verify_server_cert(&cert, &[], &server_name(), &[], fixed_now())
                .is_ok(),
            expected
        );
    }
}

// ============================================================= the ALPN tests

/// The admitted set is both tokens, in the order the server offers them.
#[test]
fn the_granary_alpn_set_is_both_tokens() {
    assert_eq!(GRANARY_ALPN, [ALPN_H2, ALPN_HTTP11]);
    assert_eq!(ALPN_H2, b"h2");
    assert_eq!(ALPN_HTTP11, b"http/1.1");
}

/// An ALPN-omitting client COMPLETES the handshake and negotiates `None` —
/// the measured fact about TLS that makes a non-empty server list a
/// non-gate — and the predicate drops it. A test using a well-behaved
/// client certifies nothing here.
#[test]
fn alpn_omitting_client_completes_and_is_dropped_by_the_predicate() {
    let real = mint(1);

    let (client, server) = expect_handshake(
        client_with(pin_verifier(vec![real.pin()]), &[]),
        server_with(&real, &GRANARY_ALPN),
    );
    assert_eq!(client.alpn_protocol(), None);
    assert_eq!(server.alpn_protocol(), None);
    assert!(!alpn::admits(client.alpn_protocol()));
    assert!(!alpn::admits(None));
}

/// BOTH tokens are admitted. Three clients, not one: a single-token
/// implementation passes the `None` test while violating the
/// mandatory HTTP/1.1 baseline.
#[test]
fn each_member_token_is_negotiated_and_admitted() {
    let real = mint(1);
    for expected in GRANARY_ALPN {
        let (client, server) = expect_handshake(
            client_with(pin_verifier(vec![real.pin()]), &[expected]),
            server_with(&real, &GRANARY_ALPN),
        );
        assert_eq!(client.alpn_protocol(), Some(expected));
        assert_eq!(server.alpn_protocol(), Some(expected));
        assert!(alpn::admits(client.alpn_protocol()));
    }
}

/// A NON-MEMBER token is refused even though it negotiated cleanly.
/// Everything above covers `None` and the two members only, so an
/// implementation equivalent to `negotiated.is_some()` passes all of them
/// while admitting anything a peer advertises.
#[test]
fn non_member_alpn_token_is_dropped_by_the_predicate() {
    let real = mint(1);
    let outsider: &[u8] = b"h3";

    let (client, server) = expect_handshake(
        client_with(pin_verifier(vec![real.pin()]), &[outsider]),
        server_with(&real, &[outsider]),
    );
    assert_eq!(client.alpn_protocol(), Some(outsider));
    assert_eq!(server.alpn_protocol(), Some(outsider));
    assert!(!alpn::admits(client.alpn_protocol()));

    for token in [
        b"spdy/3".as_slice(),
        b"h3".as_slice(),
        b"h2c".as_slice(),
        b"".as_slice(),
        b"h2 ".as_slice(),
        b"H2".as_slice(),
        b"http/1.0".as_slice(),
        b"http/1.11".as_slice(),
    ] {
        assert!(!alpn::admits(Some(token)), "{token:?} was admitted");
    }
}

/// Every OFFERED token binds a protocol, and each binds the right one.
///
/// The offered set and the servable set are two lists that must stay one
/// set. A token added to `GRANARY_ALPN` without a `serves` arm makes the
/// server advertise something the accept path then refuses — the failure
/// looks like a client bug and is not, and no test of either function alone
/// can see it. The by-value arms are the other half: a `serves` that answered
/// with one protocol for both tokens would satisfy a mere `is_some()` check
/// while making the negotiated token decorative again.
#[test]
fn every_offered_token_binds_the_protocol_it_names() {
    for token in GRANARY_ALPN {
        assert!(
            alpn::serves(Some(token)).is_some(),
            "{token:?} is offered but binds no protocol"
        );
    }
    assert_eq!(alpn::serves(Some(ALPN_H2)), Some(alpn::Protocol::Http2));
    assert_eq!(alpn::serves(Some(ALPN_HTTP11)), Some(alpn::Protocol::Http1));
    assert_eq!(alpn::serves(None), None);
    assert_eq!(alpn::serves(Some(b"h3")), None);
}

// -------------------------------------------- the PRODUCTION client config

/// The positive case: the pin the operator configured is INSTALLED by
/// the production constructor, not merely available to be installed. Every
/// other pin test in this file builds its own client config; this one
/// proves the constructor that ships does the same thing.
#[test]
fn production_client_config_admits_the_correct_pin() {
    let real = mint(11);
    let (client, server) = expect_handshake(
        production_client(vec![real.pin()]),
        server_with(&real, &GRANARY_ALPN),
    );
    assert!(!client.is_handshaking() && !server.is_handshaking());
}

/// The production client must refuse a server outside its configured pin set.
/// This negative case needs a WebPKI-VALID fixture to mean anything.
///
/// Every other refusal in this file is against a self-signed certificate,
/// which the Web PKI rejects too — so a constructor that quietly fell back
/// to `WebPkiServerVerifier` would refuse all of them and look like it was
/// pinning. The server here is issued by a CA, and the stock verifier's
/// acceptance is asserted SEPARATELY so the refusal below is shown to be
/// the pin's doing rather than the certificate's.
#[test]
fn production_client_config_refuses_a_webpki_valid_unpinned_server() {
    let (ca, leaf) = mint_ca_and_leaf();

    // The control: the Web PKI is satisfied by this chain.
    let mut roots = RootCertStore::empty();
    roots.add(ca).unwrap_or_else(|e| panic!("root store: {e}"));
    let stock = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
        .build()
        .unwrap_or_else(|e| panic!("webpki verifier: {e}"));
    let control = stock.verify_server_cert(&leaf.cert, &[], &server_name(), &[], fixed_now());
    assert!(
        control.is_ok(),
        "the fixture must be WebPKI-VALID or this test proves nothing, got {control:?}"
    );

    // The production config pins someone else, and refuses it.
    let stranger = mint(12);
    let err = expect_refusal(
        production_client(vec![stranger.pin()]),
        server_with(&leaf, &GRANARY_ALPN),
    );
    assert_eq!(
        err,
        Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure),
        "got {err:?}"
    );
}

/// The production constructor refuses a TLS-1.2-only peer.
///
/// The positive control is the same server at TLS 1.3 — without it this
/// passes identically against a config that refuses everything.
#[test]
fn production_client_config_refuses_a_tls12_only_peer() {
    let real = mint(13);

    let (client, server) = expect_handshake(
        production_client(vec![real.pin()]),
        server_with(&real, &GRANARY_ALPN),
    );
    assert!(
        !client.is_handshaking() && !server.is_handshaking(),
        "the TLS-1.3 control must complete, or the refusal below says nothing"
    );

    let err = expect_refusal(
        production_client(vec![real.pin()]),
        tls12_server(&real, &GRANARY_ALPN),
    );
    assert_eq!(
        err,
        Error::PeerIncompatible(PeerIncompatible::Tls12NotOfferedOrEnabled),
        "a TLS-1.2-only peer must be refused as a version incompatibility, got {err:?}"
    );
}

/// The ALPN list is EMPTY, and this is a hard requirement rather than an
/// omission: `hyper_rustls::HttpsConnectorBuilder::with_tls_config`
/// asserts `alpn_protocols.is_empty()` and PANICS otherwise, then writes
/// the list itself from the enabled protocols. A config that populated it
/// from `GRANARY_ALPN` — the shape `server_tls_config` uses, one line
/// away — aborts the client at construction.
#[test]
fn production_client_config_leaves_alpn_empty() {
    let real = mint(14);
    let config = production_client(vec![real.pin()]);
    assert!(
        config.alpn_protocols.is_empty(),
        "the connector populates ALPN and panics on a pre-filled list, got {:?}",
        config.alpn_protocols
    );
}
