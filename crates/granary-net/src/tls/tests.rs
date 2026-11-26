// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::tls` — the server configuration's resumption
//! settings, its time source, and a reconnect carrying a real ticket.
//!
//! In-crate because the resumption case needs a verifier that counts its
//! calls inside the `Enrolled` configuration, and rustls offers no way to
//! replace a built configuration's verifier: only `enrolled_config` takes
//! one. Everything else about the configuration is the shipped one.
//!
//! Out-of-line: `granary-net`'s non-test artifact has workspace consumers
//! (`granary-client`, `granary-server`), so the module's own tests live in
//! `src/tls/tests.rs` while the module keeps its path.
//!
//! The handshakes run in memory, client and server connections shuffling
//! bytes on one thread. Every refusal asserts a named rustls error and every
//! admission asserts completion; pump exhaustion is a panic.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicUsize, Ordering};

use granary_core::clock::Clock;
use granary_core::sheaf::Timestamp;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoServerSessionStorage, ServerSessionMemoryCache, WebPkiClientVerifier};
use rustls::time_provider::TimeProvider;
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, DigitallySignedStruct, DistinguishedName,
    Error, HandshakeKind, RootCertStore, ServerConfig, ServerConnection, SideData, SignatureScheme,
};

use super::{
    ClientAuth, ClockTime, ResumptionPin, TlsConfigError, enrolled_config, resumption_is_off,
    server_tls_config,
};
use crate::pin::{PinnedServerVerifier, spki_digest};

const HOST: &str = "granary.test";

/// 2050-01-01T00:00:00Z, inside every fixture's validity period.
const IN_VALIDITY: i64 = 2_524_608_000;

// ------------------------------------------------------------ the clock

#[derive(Debug)]
struct TestClock {
    secs: AtomicI64,
    nanos: AtomicU32,
}

impl TestClock {
    fn at(secs: i64) -> Arc<Self> {
        Arc::new(Self {
            secs: AtomicI64::new(secs),
            nanos: AtomicU32::new(0),
        })
    }

    fn set(&self, secs: i64, nanos: u32) {
        self.secs.store(secs, Ordering::SeqCst);
        self.nanos.store(nanos, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: self.secs.load(Ordering::SeqCst),
            nanos: self.nanos.load(Ordering::SeqCst),
        }
    }
}

// --------------------------------------------------------- the fixtures

struct Party {
    cert: CertificateDer<'static>,
    pkcs8: Vec<u8>,
}

impl Party {
    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.pkcs8.clone()))
    }
}

struct Ca {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    cert: CertificateDer<'static>,
}

fn keypair() -> rcgen::KeyPair {
    rcgen::KeyPair::generate().unwrap_or_else(|e| panic!("keypair: {e}"))
}

fn ca() -> Ca {
    let key = keypair();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|e| panic!("ca params: {e}"));
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "granary test client ca");
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let cert = params
        .self_signed(&key)
        .unwrap_or_else(|e| panic!("ca self-sign: {e}"))
        .der()
        .clone();
    Ca { params, key, cert }
}

fn client_leaf(ca: &Ca) -> Party {
    let key = keypair();
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).unwrap_or_else(|e| panic!("{e}"));
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key);
    let cert = params
        .signed_by(&key, &issuer)
        .unwrap_or_else(|e| panic!("sign leaf: {e}"))
        .der()
        .clone();
    Party {
        cert,
        pkcs8: key.serialize_der(),
    }
}

fn server_party() -> Party {
    let key = keypair();
    let mut params =
        rcgen::CertificateParams::new(vec![HOST.to_owned()]).unwrap_or_else(|e| panic!("{e}"));
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let cert = params
        .self_signed(&key)
        .unwrap_or_else(|e| panic!("self-sign: {e}"))
        .der()
        .clone();
    Party {
        cert,
        pkcs8: key.serialize_der(),
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(crate::crypto_provider())
}

/// A TLS-1.3 client pinned to `server`, presenting `credential` when asked.
fn client(server: &Party, credential: &Party) -> ClientConfig {
    let pin = spki_digest(&server.cert).unwrap_or_else(|e| panic!("pin: {e}"));
    let verifier = PinnedServerVerifier::new(vec![pin], provider())
        .unwrap_or_else(|e| panic!("pin verifier: {e}"));
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| panic!("client versions: {e}"))
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(vec![credential.cert.clone()], credential.key())
        .unwrap_or_else(|e| panic!("client credential: {e}"));
    config.alpn_protocols = crate::alpn::GRANARY_ALPN
        .iter()
        .map(|p| p.to_vec())
        .collect();
    config
}

/// The stock verifier `server_tls_config` builds, over `ca`.
fn stock_verifier(ca: &Ca) -> Arc<dyn ClientCertVerifier> {
    let mut roots = RootCertStore::empty();
    roots
        .add(ca.cert.clone())
        .unwrap_or_else(|e| panic!("root: {e}"));
    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
        .allow_unauthenticated()
        .build()
        .unwrap_or_else(|e| panic!("verifier: {e}"))
}

/// A verifier that counts `verify_client_cert` calls and delegates every
/// method to the stock one.
#[derive(Debug)]
struct Counting {
    inner: Arc<dyn ClientCertVerifier>,
    calls: Arc<AtomicUsize>,
}

impl ClientCertVerifier for Counting {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The `Enrolled` configuration over a counting verifier, and its counter.
fn counted_enrolled(server: &Party, ca: &Ca) -> (ServerConfig, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let verifier = Arc::new(Counting {
        inner: stock_verifier(ca),
        calls: Arc::clone(&calls),
    });
    let config = enrolled_config(
        provider(),
        vec![server.cert.clone()],
        server.key(),
        verifier,
        TestClock::at(IN_VALIDITY),
    )
    .unwrap_or_else(|e| panic!("enrolled config: {e}"));
    (config, calls)
}

// ------------------------------------------------------------- the pump

const PUMP_LIMIT: usize = 8;

/// Move every pending byte from `from` to `to`, appending a copy to `seen`.
fn transfer<A: SideData, B: SideData>(
    from: &mut ConnectionCommon<A>,
    to: &mut ConnectionCommon<B>,
    seen: &mut Vec<u8>,
) -> Result<(), Error> {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire)
            .unwrap_or_else(|e| panic!("write_tls: {e}"));
    }
    seen.extend_from_slice(&wire);
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

/// One completed handshake, and the bytes of the client's first flight
/// (its `ClientHello`).
struct Handshake {
    client: ClientConnection,
    server: ServerConnection,
    client_hello: Vec<u8>,
}

#[track_caller]
fn handshake(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) -> Handshake {
    let name = ServerName::try_from(HOST).unwrap_or_else(|e| panic!("name: {e}"));
    let mut client = ClientConnection::new(Arc::clone(client), name)
        .unwrap_or_else(|e| panic!("client connection: {e}"));
    let mut server = ServerConnection::new(Arc::clone(server))
        .unwrap_or_else(|e| panic!("server connection: {e}"));
    let mut client_hello = Vec::new();
    let mut ignored = Vec::new();
    transfer(&mut client, &mut server, &mut client_hello)
        .unwrap_or_else(|e| panic!("client hello refused: {e:?}"));
    for _ in 0..PUMP_LIMIT {
        transfer(&mut server, &mut client, &mut ignored)
            .unwrap_or_else(|e| panic!("handshake refused by the client: {e:?}"));
        transfer(&mut client, &mut server, &mut ignored)
            .unwrap_or_else(|e| panic!("handshake refused by the server: {e:?}"));
        // The server's tickets follow the client's Finished: deliver them.
        transfer(&mut server, &mut client, &mut ignored)
            .unwrap_or_else(|e| panic!("post-handshake refused: {e:?}"));
        if !client.is_handshaking() && !server.is_handshaking() {
            return Handshake {
                client,
                server,
                client_hello,
            };
        }
    }
    panic!("pump exhausted after {PUMP_LIMIT} iterations: a harness failure, not a refusal");
}

/// The PSK identities a `ClientHello` record offers in its
/// `pre_shared_key` extension (RFC 8446 §4.2.11), parsed from the wire.
/// Empty when the extension is absent.
fn offered_psk_identities(flight: &[u8]) -> Vec<Vec<u8>> {
    let mut at = Cursor { bytes: flight };
    assert_eq!(at.u8(), 0x16, "a handshake record");
    at.skip(4); // legacy version, record length
    assert_eq!(at.u8(), 0x01, "a ClientHello");
    at.skip(3 + 2 + 32); // length, legacy version, random
    let session_id = usize::from(at.u8());
    at.skip(session_id);
    let suites = at.u16();
    at.skip(suites);
    let compression = usize::from(at.u8());
    at.skip(compression);
    let mut extensions = at.vector();
    while !extensions.bytes.is_empty() {
        let kind = extensions.u16();
        let mut body = extensions.vector();
        if kind == 41 {
            let mut identities = body.vector();
            let mut out = Vec::new();
            while !identities.bytes.is_empty() {
                let identity = identities.vector();
                out.push(identity.bytes.to_vec());
                identities.skip(4); // obfuscated_ticket_age
            }
            return out;
        }
    }
    Vec::new()
}

struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Cursor<'a> {
        let (head, rest) = self
            .bytes
            .split_at_checked(n)
            .unwrap_or_else(|| panic!("a ClientHello shorter than its lengths"));
        self.bytes = rest;
        Cursor { bytes: head }
    }

    /// A vector with a two-byte length prefix.
    fn vector(&mut self) -> Cursor<'a> {
        let n = self.u16();
        self.take(n)
    }

    fn skip(&mut self, n: usize) {
        let _skipped = self.take(n);
    }

    fn u8(&mut self) -> u8 {
        self.take(1).bytes[0]
    }

    fn u16(&mut self) -> usize {
        let b = self.take(2).bytes;
        usize::from(u16::from_be_bytes([b[0], b[1]]))
    }
}

// ======================================================== the time source

#[test]
fn the_clock_time_reads_the_clock_on_every_call() {
    let clock = TestClock::at(IN_VALIDITY);
    let time = ClockTime::new(clock.clone());
    assert_eq!(
        time.current_time().map(|t| t.as_secs()),
        Some(u64::try_from(IN_VALIDITY).unwrap())
    );
    clock.set(IN_VALIDITY + 7, 999_999_999);
    assert_eq!(
        time.current_time().map(|t| t.as_secs()),
        Some(u64::try_from(IN_VALIDITY + 7).unwrap())
    );
    clock.set(0, 0);
    assert_eq!(time.current_time().map(|t| t.as_secs()), Some(0));
}

#[test]
fn a_time_before_the_epoch_or_with_bad_nanoseconds_is_none_never_clamped() {
    let clock = TestClock::at(-1);
    let time = ClockTime::new(clock.clone());
    assert_eq!(time.current_time(), None, "one second before the epoch");
    clock.set(i64::MIN, 0);
    assert_eq!(time.current_time(), None);
    clock.set(IN_VALIDITY, 1_000_000_000);
    assert_eq!(time.current_time(), None, "nanoseconds out of range");
}

#[test]
fn a_handshake_at_an_unrepresentable_time_fails_and_is_never_anonymous() {
    let ca = ca();
    let server = server_party();
    let credential = client_leaf(&ca);
    let clock = TestClock::at(IN_VALIDITY);
    let config = server_tls_config(
        vec![server.cert.clone()],
        server.key(),
        ClientAuth::Enrolled {
            ca: vec![ca.cert.clone()],
            clock: clock.clone(),
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let config = Arc::new(config);
    let client = Arc::new(client(&server, &credential));

    // The positive control at a representable time.
    let done = handshake(&client, &config);
    assert!(done.server.peer_certificates().is_some());

    clock.set(-5, 0);
    let name = ServerName::try_from(HOST).unwrap_or_else(|e| panic!("{e}"));
    let mut c = ClientConnection::new(Arc::clone(&client), name).unwrap();
    let mut s = ServerConnection::new(Arc::clone(&config)).unwrap();
    let mut seen = Vec::new();
    let mut outcome = Ok(());
    for _ in 0..PUMP_LIMIT {
        outcome =
            transfer(&mut c, &mut s, &mut seen).and_then(|()| transfer(&mut s, &mut c, &mut seen));
        if outcome.is_err() || (!c.is_handshaking() && !s.is_handshaking()) {
            break;
        }
    }
    assert_eq!(outcome, Err(Error::FailedToGetCurrentTime));
}

// ================================================= the resumption pins

/// One setting turned on.
type Mutation = fn(&mut ServerConfig);

#[test]
fn the_enrolled_configuration_has_every_resumption_setting_off() {
    let ca = ca();
    let server = server_party();
    let config = server_tls_config(
        vec![server.cert.clone()],
        server.key(),
        ClientAuth::Enrolled {
            ca: vec![ca.cert.clone()],
            clock: TestClock::at(IN_VALIDITY),
        },
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(!config.session_storage.can_cache());
    assert!(!config.ticketer.enabled());
    assert_eq!(config.send_tls13_tickets, 0);
    assert_eq!(config.max_tls13_tickets, 0);
    assert_eq!(config.max_early_data_size, 0);
    assert_eq!(resumption_is_off(&config), Ok(()));
}

/// Each resumption setting, turned on alone, is refused by the check the
/// construction ends with; the unmutated configuration is the control.
#[test]
fn each_resumption_setting_turned_on_alone_is_refused() {
    let ca = ca();
    let server = server_party();
    let (built, _calls) = counted_enrolled(&server, &ca);
    assert_eq!(resumption_is_off(&built), Ok(()), "the control");

    let cases: [(ResumptionPin, Mutation); 5] = [
        (ResumptionPin::SessionStorage, |c| {
            c.session_storage = ServerSessionMemoryCache::new(8);
        }),
        (ResumptionPin::Ticketer, |c| {
            c.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new()
                .unwrap_or_else(|e| panic!("ticketer: {e}"));
        }),
        (ResumptionPin::SendTickets, |c| c.send_tls13_tickets = 1),
        (ResumptionPin::MaxTickets, |c| c.max_tls13_tickets = 1),
        (ResumptionPin::EarlyData, |c| c.max_early_data_size = 1),
    ];
    for (pin, mutate) in cases {
        let mut config = built.clone();
        mutate(&mut config);
        assert_eq!(resumption_is_off(&config), Err(pin), "{pin:?}");
        assert!(
            TlsConfigError::Resumption(pin)
                .to_string()
                .starts_with("resumption is not off"),
            "{pin:?}"
        );
    }
}

// ============================================ a reconnect carrying a ticket

/// A resumable control issues real tickets and resumes on them; the same
/// client then offers a ticket to the `Enrolled` configuration and gets a
/// full handshake in which its certificate is verified again.
#[track_caller]
fn a_ticket_from(resumable: impl FnOnce(&mut ServerConfig)) {
    let ca = ca();
    let server = server_party();
    let credential = client_leaf(&ca);
    let (enrolled, calls) = counted_enrolled(&server, &ca);
    let mut control = enrolled.clone();
    resumable(&mut control);
    let control = Arc::new(control);
    let enrolled = Arc::new(enrolled);
    let client = Arc::new(client(&server, &credential));

    // First connection to the control: a full handshake, verified once,
    // and tickets delivered.
    let first = handshake(&client, &control);
    assert_eq!(first.client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        offered_psk_identities(&first.client_hello).is_empty(),
        "the first hello has no ticket to offer"
    );

    // The positive control: the control resumes, and nothing is verified.
    let resumed = handshake(&client, &control);
    assert!(
        !offered_psk_identities(&resumed.client_hello).is_empty(),
        "the resuming hello offers a ticket"
    );
    assert_eq!(
        resumed.client.handshake_kind(),
        Some(HandshakeKind::Resumed)
    );
    assert_eq!(
        resumed.server.handshake_kind(),
        Some(HandshakeKind::Resumed)
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a resumption verifies nothing"
    );

    // The same client offers an unconsumed ticket to the Enrolled server.
    let fresh = handshake(&client, &enrolled);
    assert!(
        !offered_psk_identities(&fresh.client_hello).is_empty(),
        "the client must offer a ticket, or this tests nothing"
    );
    assert_eq!(fresh.client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(fresh.server.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the certificate is verified again"
    );
    assert_eq!(
        fresh.server.peer_certificates().and_then(|c| c.first()),
        Some(&credential.cert)
    );
}

#[test]
fn a_stateful_ticket_gets_a_full_handshake_with_its_certificate_verified_again() {
    a_ticket_from(|config| {
        config.session_storage = ServerSessionMemoryCache::new(32);
        config.send_tls13_tickets = 4;
    });
}

#[test]
fn a_stateless_ticket_gets_a_full_handshake_with_its_certificate_verified_again() {
    a_ticket_from(|config| {
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.ticketer =
            rustls::crypto::aws_lc_rs::Ticketer::new().unwrap_or_else(|e| panic!("ticketer: {e}"));
        config.send_tls13_tickets = 4;
    });
}

#[test]
fn production_client_disables_resumption_and_early_data() {
    let party = server_party();
    let verifier =
        PinnedServerVerifier::new(vec![spki_digest(&party.cert).unwrap()], provider()).unwrap();
    let config = super::client_tls_config(Arc::new(verifier), None).unwrap();
    assert!(!config.enable_early_data);
    let client = Arc::new(config);
    let mut server =
        server_tls_config(vec![party.cert.clone()], party.key(), ClientAuth::None).unwrap();
    // Positive control: the peer issues usable stateful tickets.
    server.session_storage = ServerSessionMemoryCache::new(32);
    server.send_tls13_tickets = 4;
    let server = Arc::new(server);
    let first = handshake(&client, &server);
    assert!(first.client.tls13_tickets_received() > 0);
    let next = handshake(&client, &server);
    assert!(offered_psk_identities(&next.client_hello).is_empty());
    assert_eq!(next.client.handshake_kind(), Some(HandshakeKind::Full));
    let mut control = (*client).clone();
    control.resumption = rustls::client::Resumption::in_memory_sessions(32);
    let control = Arc::new(control);
    handshake(&control, &server);
    let resumed = handshake(&control, &server);
    assert!(!offered_psk_identities(&resumed.client_hello).is_empty());
    assert_eq!(
        resumed.client.handshake_kind(),
        Some(HandshakeKind::Resumed)
    );
}
