// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg(test)]

//! The loopback battery: the shipped policy layer driven over a real TLS
//! connection, on both ALPN legs.
//!
//! **§4.3 and §13.2 item 1 make this a MUST rather than a nicety.** §4.3
//! calls its own accept set "library behaviour, not a specification" and
//! requires a loopback test over a real connection, because a minor
//! version bump in an HTTP library can move that set silently and only an
//! end-to-end test notices. Every row below therefore asserts the status
//! AND the `Granary-Error` token AND the §6 metadata it fixes: a
//! status-only assertion cannot tell `unknown-target` from `not-found`,
//! and §8.1 turns on the difference.
//!
//! **Everything here is production code except the store and the
//! certificates.** `granary_net::tls::server_tls_config` builds the TLS
//! configuration, `granary_net::accept::serve` runs the accept loop, and
//! [`GrainService`] is the adapter that ships — so a row that passes is
//! evidence about the server, not about a stack assembled in a test.
//! The store is [`FakeSeam`], the same second implementation
//! `seam_drivable` drives with no HTTP at all.
//!
//! **The clients are deliberately raw.** hyper's own client normalises
//! and refuses: it will not build a request target of `*`, will not send
//! two `If-None-Match` field lines, and will not put a byte outside its
//! own grammar on the wire. Half the rows below exist for exactly those
//! inputs, so the HTTP/1.1 client here writes request bytes by hand and
//! parses the response head by hand, and the HTTP/2 leg drives the `h2`
//! crate directly.
//!
//! **No `sleep` anywhere.** It is banned; `tokio::time::timeout` is
//! deliberately not, so every wait here is a bounded await and every
//! pace is [`pause`].

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use granary_core::binstore::BinStore;
use granary_core::hash::GrainId;
use granary_core::rootstore::{RootStore, format_hint_body};
use granary_net::accept::{AcceptConfig, ShutdownOutcome, serve};
use granary_net::alpn::{ALPN_H2, ALPN_HTTP11};
use granary_net::tls::{ClientAuth, server_tls_config};
use hyper::body::Bytes;
use hyper::http::uri::{Authority, PathAndQuery, Scheme};
use hyper::{HeaderMap, Uri};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::adapter::{
    DRAIN_BUDGET_BYTES, DRAIN_MAX_WAIT, GrainService, READ_BODY_BUDGET_BYTES, READ_PERMITS,
    TEST_WORKER_THREADS, VERIFY_PERMIT_MAX_WAIT, WRITE_ACCEPT_MAX_WAIT, WRITE_BODY_BUDGET_BYTES,
    WRITE_BUDGET_GRANULE_BYTES, WriteBudget, verify_permits,
};
use crate::admission::{DECLARED_MAX_EXTENT, INGEST_UNPACKED_SUM_MAX};
use crate::fake::FakeSeam;
use crate::policy::VerifyPolicy;
use granary_core::binfmt::{BIN_MAX_BYTES, PackedFrame, encode_bin};
use granary_core::manifest::GRAIN_UNPACKED_MAX;
use granary_store::bounds::{META_MAX_BYTES, ROOT_MAX_BYTES};
use granary_store::codec::GrainCodec;

/// The certificate DNS name used by clients with Web PKI verification.
pub(crate) const HOST: &str = "localhost";

pub(crate) fn base_url(addr: SocketAddr) -> String {
    format!("https://{addr}")
}

/// Part I's configured `{base}` (§4.1): none.
const BASE: &str = "";

/// The volume every planted object lives under (§4.3's DNS-1123 label).
const VOLUME: &str = "loop-vol";

/// A volume that exists in no map at all — the state every volume is in
/// before its first `PUT hint` (§5.8, §13.2 item 12).
const EMPTY_VOLUME: &str = "empty-vol";

/// A volume whose hint token is planted with obs-text inside its quotes,
/// which no mint produces and no request can ask for.
const TAGGED_VOLUME: &str = "tagged-vol";

/// The occupied seq.
const SEQ: u64 = 41;

/// The bound on a POSITIVE arm: every expectation it covers is
/// sub-second on an idle machine, and the margin is for macOS scheduling
/// jitter rather than for the behaviour.
const GENEROUS: Duration = Duration::from_secs(15);

/// The bound on a NEGATIVE arm — an event a correct server never
/// produces, so a short bound cannot flake and a long one only slows the
/// suite.
const BRIEF: Duration = Duration::from_millis(400);

/// A verify-permit queue bound long enough that it CANNOT fire, for the
/// rows whose subject is not the bound. See
/// [`Loopback::start_with_permit_wait`] for why the shipped figure is
/// the wrong one to run a debug build's verify storm against.
const PATIENT: Duration = GENEROUS.saturating_mul(40);

/// A verify-permit queue bound short enough that a row can spend it and
/// still be a row rather than a wait.
const IMPATIENT: Duration = Duration::from_millis(250);

/// The one spawn site in this crate's test surface — used by this file
/// AND by [`crate::conformance_http`], [`crate::stream_floor`] and the
/// per-write principal rows (`principal`'s tests), which import it rather
/// than opening exemptions of their own.
///
/// `tokio::spawn` is banned workspace-wide with no test exemption
/// because the simulator cannot sequence a runtime-ordered task. All
/// FOUR callers are on the far side of that boundary, and each spawn
/// exemption's reason must name why the SITE is outside the sim
/// boundary — so it has to state what the four have in common rather
/// than what one of them happens to drive. What they have in common is a
/// real TCP socket under a real TLS session: that is the layer
/// `granary-sim` REPLACES rather than drives, and no `Clock`, `Rng` or
/// simulated store seam is involved in reaching it.
///
/// They reach it by different routes, and one of them is deliberately
/// not the accept loop. This file, `conformance_http` and the principal
/// rows drive the shipped accept loop. `stream_floor` drives `h2::server` DIRECTLY,
/// because its subject is `H2_MAX_CONCURRENT_STREAMS` at values granary
/// does not ship and that constant is not configurable — a harness that
/// could set it through `AcceptConfig` would be exercising a knob that
/// does not exist (`stream_floor.rs:168-174`).
///
/// Routing every task through one wrapper is what keeps the exemption to
/// a single reviewable site however many batteries use it.
#[expect(
    clippy::disallowed_methods,
    reason = "the loopback battery, the over-HTTP conformance run, the per-write principal rows and the h2 stream-floor controls all drive a real TCP socket under a real TLS session — the first three through the shipped accept loop, the last through h2::server directly — which is the layer granary-sim replaces rather than drives"
)]
pub(crate) fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future)
}

/// Wait `gap` without sleeping.
///
/// `tokio::time::sleep` is banned and `tokio::time::timeout` deliberately
/// is not, so a bound around a future that never completes is the pacing
/// primitive this workspace leaves available.
async fn pause(gap: Duration) {
    let _expired = timeout(gap, std::future::pending::<()>()).await;
}

// ------------------------------------------------- the certificate factory

/// A CA and the leaf it signed, minted per server and never written to
/// disk.
pub(crate) struct Certs {
    pub(crate) ca: CertificateDer<'static>,
    pub(crate) leaf: CertificateDer<'static>,
    pub(crate) key: PrivateKeyDer<'static>,
}

pub(crate) fn mint() -> Certs {
    let ca_key = rcgen::KeyPair::generate().unwrap_or_else(|e| panic!("ca keypair: {e}"));
    let mut ca_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).unwrap_or_else(|e| panic!("ca: {e}"));
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "granary loopback ca");
    ca_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let ca = ca_params
        .self_signed(&ca_key)
        .unwrap_or_else(|e| panic!("ca self-sign: {e}"));

    let leaf_key = rcgen::KeyPair::generate().unwrap_or_else(|e| panic!("leaf keypair: {e}"));
    let mut leaf_params =
        rcgen::CertificateParams::new(vec![HOST.to_owned(), "127.0.0.1".to_owned()])
            .unwrap_or_else(|e| panic!("leaf: {e}"));
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, HOST);
    leaf_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    leaf_params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .unwrap_or_else(|e| panic!("leaf sign: {e}"));

    Certs {
        ca: ca.der().clone(),
        leaf: leaf.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    }
}

/// A TLS-1.3 client trusting `ca` and offering exactly one ALPN token.
pub(crate) fn client_config(ca: &CertificateDer<'static>, alpn: &[u8]) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(ca.clone())
        .unwrap_or_else(|e| panic!("trust anchor: {e}"));
    let mut config = ClientConfig::builder_with_provider(Arc::new(granary_net::crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| panic!("client versions: {e}"))
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

async fn tls_connect(
    addr: SocketAddr,
    config: ClientConfig,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|e| panic!("tcp: {e}"));
    let name = ServerName::try_from(HOST).unwrap_or_else(|e| panic!("server name: {e}"));
    TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .unwrap_or_else(|e| panic!("tls: {e}"))
}

// ---------------------------------------------------------- the server side

/// A running `serve` over a real loopback TCP listener, with the fake
/// store it answers from.
struct Loopback {
    addr: SocketAddr,
    ca: CertificateDer<'static>,
    store: Arc<FakeSeam>,
    /// A CLONE of the very service the accept loop is running, kept so a
    /// row can read the two process bounds — the write-body budget and the
    /// verify permit — through the same `Arc`s every connection charges.
    /// A per-service field would read full here while every connection
    /// was saturated, which is precisely the defect the rows check for.
    service: GrainService<FakeSeam>,
    shutdown: watch::Sender<bool>,
    served: JoinHandle<std::io::Result<ShutdownOutcome>>,
}

impl Loopback {
    /// Bind, serve, and plant the fixtures every row set draws on, under
    /// Part I's configured `{base}`.
    ///
    /// **The SHIPPED constructor.** `GrainService::new` is what a
    /// composition root calls, so every row driven from here is evidence
    /// about the server that ships — including that it verifies, which
    /// §13.5 makes the only policy §5.1 permits anything shipped.
    async fn start() -> Self {
        Self::start_at(BASE).await
    }

    /// The same server under an arbitrary `{base}` (§4.1).
    async fn start_at(base: &str) -> Self {
        Self::bind(|store| GrainService::new(store, base, TEST_WORKER_THREADS)).await
    }

    /// §13.5's SEAM-ONLY profile, through the one `#[cfg(test)]` door.
    ///
    /// §13.4 requires both profiles of a conforming implementation and
    /// sends them the same request, so this exists to be driven and to
    /// answer differently — not as a convenience.
    async fn start_seam_only() -> Self {
        Self::bind(|store| {
            GrainService::for_test(
                store,
                BASE,
                VerifyPolicy::seam_only(),
                Some(DECLARED_MAX_EXTENT),
                WRITE_BODY_BUDGET_BYTES,
                READ_BODY_BUDGET_BYTES,
                VERIFY_PERMIT_MAX_WAIT,
                None,
            )
        })
        .await
    }

    /// A VERIFYING server on a budget a row can fill.
    async fn start_with_budget(budget: u64) -> Self {
        Self::bind(|store| {
            GrainService::for_test(
                store,
                BASE,
                VerifyPolicy::verifying(),
                Some(DECLARED_MAX_EXTENT),
                budget,
                READ_BODY_BUDGET_BYTES,
                VERIFY_PERMIT_MAX_WAIT,
                None,
            )
        })
        .await
    }

    /// A VERIFYING server whose verify-permit queue bound is the row's
    /// rather than the shipped one.
    ///
    /// **The shipped five seconds is sized for the build that ships, and
    /// the suite runs a debug one** — blake3 unoptimised is an order of
    /// magnitude slower, so a queue that would clear in milliseconds on
    /// a release build takes seconds here. A row about the queue bound
    /// wants a short wait to spend; a row about anything else wants a
    /// wait long enough that the bound cannot fire and change what the
    /// row is measuring.
    async fn start_with_permit_wait(permit_wait: Duration) -> Self {
        Self::bind(move |store| {
            GrainService::for_test(
                store,
                BASE,
                VerifyPolicy::verifying(),
                Some(DECLARED_MAX_EXTENT),
                WRITE_BODY_BUDGET_BYTES,
                READ_BODY_BUDGET_BYTES,
                permit_wait,
                None,
            )
        })
        .await
    }

    /// A server whose connections are recycled after `lifetime` — the
    /// read-response charge's hold bound, driven end to end.
    async fn start_with_lifetime(lifetime: Duration) -> Self {
        Self::bind_with(
            AcceptConfig {
                connection_max_lifetime: lifetime,
                ..AcceptConfig::default()
            },
            |store| {
                GrainService::for_test(
                    store,
                    BASE,
                    VerifyPolicy::verifying(),
                    Some(DECLARED_MAX_EXTENT),
                    WRITE_BODY_BUDGET_BYTES,
                    READ_BODY_BUDGET_BYTES,
                    VERIFY_PERMIT_MAX_WAIT,
                    None,
                )
            },
        )
        .await
    }

    async fn bind<F>(build: F) -> Self
    where
        F: FnOnce(Arc<FakeSeam>) -> GrainService<FakeSeam>,
    {
        Self::bind_with(AcceptConfig::default(), build).await
    }

    async fn bind_with<F>(config: AcceptConfig, build: F) -> Self
    where
        F: FnOnce(Arc<FakeSeam>) -> GrainService<FakeSeam>,
    {
        let certs = mint();
        let tls = Arc::new(
            server_tls_config(vec![certs.leaf.clone()], certs.key, ClientAuth::None)
                .unwrap_or_else(|e| panic!("server tls config: {e}")),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local addr: {e}"));
        let store = Arc::new(FakeSeam::default());
        plant(&store).await;
        let service = build(Arc::clone(&store));
        let (shutdown, rx) = watch::channel(false);
        let served = spawn(serve(listener, tls, service.clone(), rx, config));
        Self {
            addr,
            ca: certs.ca,
            store,
            service,
            shutdown,
            served,
        }
    }

    async fn h1(&self) -> RawH1 {
        RawH1 {
            stream: tls_connect(self.addr, client_config(&self.ca, ALPN_HTTP11)).await,
            buffered: Vec::new(),
        }
    }

    async fn h2(&self) -> H2 {
        let stream = tls_connect(self.addr, client_config(&self.ca, ALPN_H2)).await;
        let (send, connection) = h2::client::handshake(stream)
            .await
            .unwrap_or_else(|e| panic!("h2 handshake: {e}"));
        let pump = spawn(async move {
            let _ended = connection.await;
        });
        H2 { send, pump }
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        let _observed = self.shutdown.send(true);
        self.served.abort();
    }
}

/// The 100-byte bin §13.4's extent rows are written against.
fn bin_body() -> Vec<u8> {
    vec![0x5a_u8; 100]
}

/// A meta object the fake HOLDS — §13.2 item 11 requires the meta `405`
/// to be asserted against a `grain-id` that is really there.
fn meta_body() -> Vec<u8> {
    b"a meta object the server never parses".to_vec()
}

/// A stored root that is NOT a decodable root (§13.2 item 2): only a
/// non-canonical stored object can tell a byte-for-byte server from one
/// that re-encodes on read.
fn root_body() -> Vec<u8> {
    b"\x00\xffnot a decodable root, and that is the point\x00".to_vec()
}

async fn plant(store: &FakeSeam) {
    let bin = bin_body();
    let digest = *GrainId::of(&bin).digest();
    let planted = store.put_bin(&digest, bin).await;
    assert!(planted.is_ok(), "planting the bin");

    let meta = meta_body();
    let id = GrainId::of(&meta);
    assert!(store.put_meta(VOLUME, &id, meta).await.is_ok());
    assert!(store.put_root(VOLUME, SEQ, root_body()).await.is_ok());
    assert!(store.write_hint(VOLUME, SEQ).await.is_ok());
    // The store whose opaque token carries obs-text inside its quotes.
    // `write_hint` mints ASCII and no request can ask for another shape,
    // so this is the only door to it.
    store.plant_hint(TAGGED_VOLUME, 5, "\"\u{FFFD}\"");
}

/// §13.4's two-profile witness: 100 bytes that are NOT a decodable bin,
/// addressed by their own digest.
///
/// Every check but grain verification passes on it — the digest is
/// right, the body is far inside the cap, the target parses — so the
/// only thing that can separate the two profiles' answers is the one
/// §13.5 says separates them.
fn not_a_decodable_bin() -> Vec<u8> {
    vec![0xa5_u8; 100]
}

/// A bin a conforming packer emits, built through the SHIPPED codec.
fn bin_of(grains: &[Vec<u8>]) -> Vec<u8> {
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let frames: Vec<PackedFrame> = grains
        .iter()
        .map(|grain| PackedFrame {
            id: GrainId::of(grain),
            frame: codec
                .compress_grain(grain)
                .unwrap_or_else(|e| panic!("{e}")),
        })
        .collect();
    encode_bin(&frames).unwrap_or_else(|e| panic!("{e}"))
}

/// A small valid bin: the router-switch row's positive.
fn valid_bin() -> Vec<u8> {
    bin_of(&[
        b"the first grain of a real bin".to_vec(),
        b"the second grain of a real bin".to_vec(),
        b"and a third".to_vec(),
    ])
}

/// How many maximal grains the verify-storm bin carries.
///
/// Sized against a DEBUG build, which is what the suite runs: blake3 is
/// an order of magnitude slower unoptimised, so a bin that would be a
/// blink in release is the whole storm here. Eight maximal grains is
/// 64 MiB of hashing per verify — long enough that a storm of them is
/// still running while a read is served on another connection, short
/// enough that the row costs seconds rather than a minute.
const HEAVY_GRAINS: usize = 8;

/// §13.4's ingest-limit witness: a DECODABLE bin whose frame headers declare a
/// decompressed sum past the ingest limit.
///
/// The frames are one real maximal grain's bytes repeated under
/// FABRICATED index ids, which is what an attacker sends: `decode_bin`
/// checks extents, headers and id UNIQUENESS and never that an id hashes
/// its frame, so the bin decodes and every grain in it would fail
/// verification. The answer must still be the LIMIT's, which is what
/// makes this witness stronger than an honest one.
fn declared_sum_bomb() -> Vec<u8> {
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let grain = vec![0x5a_u8; GRAIN_UNPACKED_MAX as usize];
    let frame = codec
        .compress_grain(&grain)
        .unwrap_or_else(|e| panic!("{e}"));
    // 513 × 8 MiB = 4104 MiB, past the 4096 MiB limit, at a frame count
    // three orders of magnitude under the count cap.
    let count = (INGEST_UNPACKED_SUM_MAX / u64::from(GRAIN_UNPACKED_MAX)) + 1;
    let frames: Vec<PackedFrame> = (0..count)
        .map(|i| PackedFrame {
            id: GrainId::of(&i.to_be_bytes()),
            frame: frame.clone(),
        })
        .collect();
    encode_bin(&frames).unwrap_or_else(|e| panic!("{e}"))
}

/// A LARGE valid bin: hundreds of megabytes of declared grain, in a body
/// of a few kilobytes.
///
/// **Compressible on purpose.** The bin has to be cheap to send and
/// expensive to VERIFY, because what the verify permit bounds is the
/// verify, and a bin that were expensive to send would be measuring the
/// transport instead.
fn heavy_bin() -> Vec<u8> {
    let grains: Vec<Vec<u8>> = (0..HEAVY_GRAINS)
        .map(|i| {
            let mut grain = vec![0x5a_u8; GRAIN_UNPACKED_MAX as usize];
            // DISTINCT plaintexts: `decode_bin` refuses duplicate ids.
            if let Some(first) = grain.first_mut() {
                *first = u8::try_from(i).unwrap_or(0);
            }
            grain
        })
        .collect();
    bin_of(&grains)
}

fn target_for(body: &[u8]) -> String {
    format!("/bin/{}", GrainId::of(body).digest_hex())
}

fn bin_target() -> String {
    format!("/bin/{}", GrainId::of(&bin_body()).digest_hex())
}

fn meta_target() -> String {
    format!("/volume/{VOLUME}/meta/{}", GrainId::of(&meta_body()))
}

fn root_target() -> String {
    format!("/volume/{VOLUME}/root/{}", format_hint_body(SEQ))
}

// --------------------------------------------------- the raw HTTP/1.1 client

/// One parsed response.
struct Reply {
    status: u16,
    /// Field names lowercased; every line, in order, so a duplicate is
    /// visible.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// The response exactly as it arrived, head and content — what §8.4
    /// disclosure rows scan.
    raw: Vec<u8>,
}

impl Reply {
    fn field(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }

    fn token(&self) -> Option<&str> {
        self.field("granary-error")
    }
}

/// How a connection ended.
#[derive(Debug, PartialEq, Eq)]
enum Ending {
    /// A clean end-of-stream — a FIN after a complete response, which is
    /// §5.5's conforming staged close.
    Eof,
    /// A reset in place of the end-of-stream (RFC 9112 §9.6).
    Reset,
    /// Nothing arrived and the socket is still open.
    StillOpen,
}

struct RawH1 {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    buffered: Vec<u8>,
}

impl RawH1 {
    async fn send(&mut self, bytes: &[u8]) {
        self.stream
            .write_all(bytes)
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        self.stream
            .flush()
            .await
            .unwrap_or_else(|e| panic!("flush: {e}"));
    }

    /// Write `bytes`, tolerating a failure — the flood rows write into a
    /// connection the server is entitled to be closing.
    async fn try_send(&mut self, bytes: &[u8]) -> bool {
        self.stream.write_all(bytes).await.is_ok() && self.stream.flush().await.is_ok()
    }

    /// Read whatever is available within `patience`. `false` means
    /// nothing more will come (end of stream, reset, or the bound).
    async fn fill(&mut self, patience: Duration) -> bool {
        // Heap and not a stack array: a 16 KiB buffer inside an async
        // fn inflates every future that awaits it.
        let mut chunk = vec![0_u8; 16 * 1024];
        match timeout(patience, self.stream.read(&mut chunk)).await {
            Ok(Ok(0) | Err(_)) | Err(_) => false,
            Ok(Ok(read)) => {
                self.buffered
                    .extend_from_slice(chunk.get(..read).unwrap_or_default());
                true
            }
        }
    }

    fn head_end(&self) -> Option<usize> {
        self.buffered
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|at| at + 4)
    }

    /// Take one reply if a complete head has arrived within `patience`.
    ///
    /// `has_content` is the request's own shape: a `HEAD` response
    /// declares a length it does not send, so reading one would block
    /// until the bound.
    async fn reply_within(&mut self, patience: Duration, has_content: bool) -> Option<Reply> {
        while self.head_end().is_none() {
            if !self.fill(patience).await {
                return None;
            }
        }
        let end = self.head_end()?;
        let rest = self.buffered.split_off(end);
        let head = std::mem::replace(&mut self.buffered, rest);
        let (status, headers) = parse_head(&head)?;
        let want = if has_content {
            headers
                .iter()
                .find(|(name, _)| name == "content-length")
                .and_then(|(_, value)| value.parse::<usize>().ok())
                .unwrap_or(0)
        } else {
            0
        };
        while self.buffered.len() < want {
            if !self.fill(patience).await {
                break;
            }
        }
        let taken = want.min(self.buffered.len());
        let rest = self.buffered.split_off(taken);
        let body = std::mem::replace(&mut self.buffered, rest);
        let mut raw = head;
        raw.extend_from_slice(&body);
        Some(Reply {
            status,
            headers,
            body,
            raw,
        })
    }

    async fn reply(&mut self, has_content: bool) -> Reply {
        match self.reply_within(GENEROUS, has_content).await {
            Some(reply) => reply,
            None => panic!("no complete response head within {GENEROUS:?}"),
        }
    }

    async fn request(&mut self, bytes: &[u8], has_content: bool) -> Reply {
        self.send(bytes).await;
        self.reply(has_content).await
    }

    /// A `GET` of `target`, on a fresh assertion.
    async fn get(&mut self, target: &str) -> Reply {
        self.request(&h1("GET", target.as_bytes(), &[], None), true)
            .await
    }

    async fn ending(&mut self) -> Ending {
        let mut chunk = vec![0_u8; 1024];
        match timeout(BRIEF, self.stream.read(&mut chunk)).await {
            Ok(Ok(0)) => Ending::Eof,
            Ok(Ok(_)) => Ending::StillOpen,
            Ok(Err(_reset)) => Ending::Reset,
            Err(_expired) => Ending::StillOpen,
        }
    }
}

fn parse_head(raw: &[u8]) -> Option<(u16, Vec<(String, String)>)> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let status = lines
        .next()?
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())?;
    let headers = lines
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    Some((status, headers))
}

/// A raw HTTP/1.1 request. The target and every field value are BYTES,
/// so a row can put a sequence on the wire that no client library would
/// build.
fn h1(method: &str, target: &[u8], fields: &[(&str, &[u8])], body: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(target);
    out.extend_from_slice(b" HTTP/1.1\r\nhost: ");
    out.extend_from_slice(HOST.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in fields {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    if let Some(body) = body {
        out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    if let Some(body) = body {
        out.extend_from_slice(body);
    }
    out
}

/// A chunked request head, with no `Content-Length` and no terminating
/// chunk — the shape §13.2 item 13 needs, where content is still
/// unwritten when the response is produced.
fn h1_chunked_head(method: &str, target: &str) -> Vec<u8> {
    format!("{method} {target} HTTP/1.1\r\nhost: {HOST}\r\ntransfer-encoding: chunked\r\n\r\n")
        .into_bytes()
}

fn chunk(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
    out
}

// ------------------------------------------------------- the HTTP/2 client

struct H2Reply {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl H2Reply {
    fn token(&self) -> Option<&str> {
        self.headers
            .get("granary-error")
            .and_then(|value| value.to_str().ok())
    }
}

struct H2 {
    send: h2::client::SendRequest<Bytes>,
    pump: JoinHandle<()>,
}

impl Drop for H2 {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// An `http` target with an ARBITRARY path, built through `uri::Parts`
/// so the path is whatever the row needs — `*`, `//`, 65 hex characters
/// — rather than whatever a client library is willing to spell.
fn h2_uri(path: &str) -> Uri {
    let mut parts = hyper::http::uri::Parts::default();
    parts.scheme = Some(Scheme::HTTPS);
    parts.authority = Some(Authority::from_static(HOST));
    parts.path_and_query =
        Some(PathAndQuery::try_from(path).unwrap_or_else(|e| panic!("{path}: {e}")));
    Uri::from_parts(parts).unwrap_or_else(|e| panic!("{path}: {e}"))
}

impl H2 {
    /// Open a stream WITHOUT ending it, handing back the response future
    /// and the send half.
    async fn open(
        &mut self,
        method: &str,
        path: &str,
        fields: &[(&str, &str)],
        end: bool,
    ) -> (h2::client::ResponseFuture, h2::SendStream<Bytes>) {
        let byte_fields: Vec<(&str, &[u8])> =
            fields.iter().map(|(k, v)| (*k, v.as_bytes())).collect();
        self.open_bytes(method, path, &byte_fields, end).await
    }

    async fn request(&mut self, method: &str, path: &str, fields: &[(&str, &str)]) -> H2Reply {
        let byte_fields: Vec<(&str, &[u8])> =
            fields.iter().map(|(k, v)| (*k, v.as_bytes())).collect();
        self.request_with_body(method, path, &byte_fields, None)
            .await
    }

    async fn open_bytes(
        &mut self,
        method: &str,
        path: &str,
        fields: &[(&str, &[u8])],
        end: bool,
    ) -> (h2::client::ResponseFuture, h2::SendStream<Bytes>) {
        let mut request = hyper::Request::builder()
            .method(method)
            .uri(h2_uri(path))
            .body(())
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        for (name, value) in fields {
            let name = hyper::header::HeaderName::from_bytes(name.as_bytes())
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let value = hyper::header::HeaderValue::from_bytes(value)
                .unwrap_or_else(|e| panic!("{value:?}: {e}"));
            // APPEND, never insert: the duplicate-field-line rows are
            // exactly what a client that inserts cannot express.
            request.headers_mut().append(name, value);
        }
        // `ready` consumes the handle and hands back a ready one, so
        // the clone is the API's shape rather than a copy of anything.
        self.send = match timeout(GENEROUS, self.send.clone().ready()).await {
            Ok(Ok(ready)) => ready,
            Ok(Err(error)) => panic!("h2 ready: {error}"),
            Err(elapsed) => panic!("h2 never became ready ({elapsed})"),
        };
        self.send
            .send_request(request, end)
            .unwrap_or_else(|e| panic!("h2 send: {e}"))
    }

    async fn request_with_body(
        &mut self,
        method: &str,
        path: &str,
        fields: &[(&str, &[u8])],
        body: Option<&[u8]>,
    ) -> H2Reply {
        let has_body = body.is_some();
        let (response, mut send) = self.open_bytes(method, path, fields, !has_body).await;
        if let Some(body) = body {
            send.send_data(Bytes::copy_from_slice(body), true)
                .unwrap_or_else(|e| panic!("h2 send_data: {e}"));
        }
        collect(response).await
    }
}

async fn collect(response: h2::client::ResponseFuture) -> H2Reply {
    let response = match timeout(GENEROUS, response).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => panic!("h2 response: {error}"),
        Err(elapsed) => panic!("no h2 response within {GENEROUS:?} ({elapsed})"),
    };
    let (parts, mut stream) = response.into_parts();
    let mut body = Vec::new();
    while let Some(piece) = stream.data().await {
        let piece = piece.unwrap_or_else(|e| panic!("h2 body: {e}"));
        body.extend_from_slice(&piece);
        let _released = stream.flow_control().release_capacity(piece.len());
    }
    H2Reply {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body,
    }
}

// ============================================================ row set 1

/// §4.3 and §13.2 item 1 — every degenerate target reaches the grammar
/// and is refused by it, over a real connection, with the token that
/// separates "not a resource here" from "absent object".
///
/// **No panic and no `500` anywhere** is §4.3's totality MUST, and it is
/// asserted by the status itself: every row below is exactly `404`.
#[tokio::test]
async fn degenerate_targets_are_404_unknown_target_on_the_h1_leg() {
    let server = Loopback::start().await;
    let targets: Vec<String> = vec![
        "*".to_owned(),
        "/".to_owned(),
        "//".to_owned(),
        "/..".to_owned(),
        "/bin/../root".to_owned(),
        "/%zz".to_owned(),
        format!("/bin/{}", "a".repeat(63)),
        format!("/bin/{}", "a".repeat(65)),
        format!("/bin/{}G", "a".repeat(63)),
        format!("/bin/{}", "A".repeat(64)),
        format!("/volume/-bad/root/{}", "0".repeat(20)),
        format!("/volume/{VOLUME}/root/{}", "0".repeat(19)),
        format!("/volume/{VOLUME}/root/99999999999999999999"),
        format!("/volume/{VOLUME}/max-seq/"),
        "/unknown".to_owned(),
        // Well-formed UTF-8 non-ASCII: the library hands it over intact
        // and the APPLICATION layer refuses it, which is the half of
        // §4.3's sentence that still holds literally.
        "/café".to_owned(),
        // A query component. §4.1 forms every target by concatenation
        // and §4.3 matches byte-for-byte, so a query-bearing target is
        // not any §4.2 resource — and serving it anyway would mint an
        // unbounded alias space over content intermediaries cache as
        // immutable for a year. The `?` must REACH the grammar: an
        // adapter that hands over only the path serves these two.
        format!("/volume/{VOLUME}/max-seq?q=1"),
        format!("{}?x=1", bin_target()),
    ];
    assert_eq!(targets.len(), 18, "§4.3's degenerate set");

    for target in targets {
        let mut client = server.h1().await;
        let reply = client.get(&target).await;
        assert_eq!(reply.status, 404, "{target}");
        assert_eq!(
            reply.token(),
            Some("unknown-target"),
            "{target}: §8.1 — never the token a client maps to a success"
        );
    }
}

/// The two methods below the protocol's own vocabulary, and the three
/// targets the LIBRARY refuses before any handler.
///
/// The split is §8.2's own scope: the token is REQUIRED on a refusal the
/// application layer generates, and a request the HTTP library rejects
/// below that layer never reaches it — so `400` with no token is the
/// conforming answer there, not a gap.
#[tokio::test]
async fn the_method_and_library_refusals_are_non_5xx_and_split_on_the_token() {
    let server = Loopback::start().await;

    // CONNECT's authority-form target arrives with an EMPTY `uri.path()`,
    // so this `404` is step 1's grammar refusing an empty path rather
    // than a decision about the method — and a non-`2xx` also keeps
    // hyper out of tunnel mode.
    let mut client = server.h1().await;
    let connect = client
        .request(&h1("CONNECT", b"localhost:443", &[], None), true)
        .await;
    assert!(connect.status < 500, "CONNECT: {}", connect.status);
    assert_eq!(connect.status, 404);
    assert_eq!(connect.token(), Some("unknown-target"));

    let mut client = server.h1().await;
    let options = client.request(&h1("OPTIONS", b"*", &[], None), true).await;
    assert!(options.status < 500, "OPTIONS: {}", options.status);
    assert_eq!(options.status, 404);
    assert_eq!(options.token(), Some("unknown-target"));

    // The R6 carve-out: §4.3's "reach the handler intact" does not hold
    // for byte sequences the library's own grammar refuses. An empty
    // target and a target with no leading `/` are refused by the
    // request-line parser; a raw `0x80` is not valid UTF-8 and is
    // refused by the URI parser. All three are `400` from the library,
    // below the layer §8.2 scopes the token to.
    let mut malformed = 0_usize;
    for (name, raw) in [
        (
            "empty target",
            b"GET  HTTP/1.1\r\nhost: localhost\r\n\r\n".to_vec(),
        ),
        (
            "no leading slash",
            b"GET %2Fbin HTTP/1.1\r\nhost: localhost\r\n\r\n".to_vec(),
        ),
        ("raw 0x80", {
            let mut target = b"/bin/".to_vec();
            target.push(0x80);
            h1("GET", &target, &[], None)
        }),
    ] {
        let mut client = server.h1().await;
        client.send(&raw).await;
        let reply = client.reply(true).await;
        assert_eq!(reply.status, 400, "{name}");
        assert_eq!(
            reply.token(),
            None,
            "{name}: the library refused it below the application layer"
        );
        malformed += 1;
    }
    assert_eq!(malformed, 3);
}

// ============================================================ row set 2

/// The same grammar core on the HTTP/2 leg, plus one positive: **the
/// admitted set does not depend on which leg carried the request.**
#[tokio::test]
async fn the_two_legs_agree_on_the_admitted_set() {
    let server = Loopback::start().await;
    let mut client = server.h2().await;

    for path in [
        "*",
        "//",
        &format!("/bin/{}", "a".repeat(65)),
        // The query rows ride on both legs: `:path` carries the query
        // in HTTP/2 exactly as the request-line does in HTTP/1.1.
        &format!("/volume/{VOLUME}/max-seq?q=1"),
    ] {
        let reply = client.request("GET", path, &[]).await;
        assert_eq!(reply.status, 404, "{path}");
        assert_eq!(reply.token(), Some("unknown-target"), "{path}");
    }

    let ranged = client
        .request("GET", &bin_target(), &[("range", "bytes=0-99")])
        .await;
    assert_eq!(ranged.status, 206, "the h2 leg serves what h1 serves");
    assert_eq!(ranged.token(), None);
    assert_eq!(ranged.body, bin_body());
    assert_eq!(
        ranged
            .headers
            .get("content-range")
            .and_then(|value| value.to_str().ok()),
        Some("bytes 0-99/*")
    );
}

// ============================================================ row set 3

/// §13.4's extent rows at the wire, under the SHIPPED declaration.
///
/// The bin is 100 bytes and really there, which is what makes the
/// over-wide rows say something: a server that peeked at the store and
/// refused only what it could not serve would pass every row that names
/// an absent digest and fail these.
#[tokio::test]
async fn the_section_13_4_extent_rows_hold_at_the_wire() {
    let server = Loopback::start().await;
    let target = bin_target();
    let extent = u64::from(DECLARED_MAX_EXTENT);

    let rows: Vec<(String, u16, &str)> = vec![
        (format!("bytes=0-{}", extent - 1), 206, ""),
        (format!("bytes=0-{extent}"), 400, "extent-too-wide"),
        ("bytes=0-".to_owned(), 400, "extent-too-wide"),
        ("bytes=100-".to_owned(), 400, "extent-too-wide"),
        ("bytes=268435456-".to_owned(), 416, "bad-range"),
        (
            "bytes=99999999999999999999-100".to_owned(),
            400,
            "bad-range",
        ),
    ];
    for (value, status, token) in rows {
        let mut client = server.h1().await;
        let reply = client
            .request(
                &h1(
                    "GET",
                    target.as_bytes(),
                    &[("range", value.as_bytes())],
                    None,
                ),
                true,
            )
            .await;
        assert_eq!(reply.status, status, "{value}");
        if token.is_empty() {
            // The short read: the ask is the widest this server admits
            // and the answer is the whole 100-byte object (§7.2).
            assert_eq!(reply.token(), None, "{value}");
            assert_eq!(
                reply.field("content-range"),
                Some("bytes 0-99/*"),
                "{value}"
            );
            assert_eq!(reply.body, bin_body(), "{value}");
        } else {
            assert_eq!(reply.token(), Some(token), "{value}");
            assert!(
                reply.body.is_empty(),
                "{value}: §7.1 refuses WHOLE — never a prefix"
            );
        }
    }

    // The ordinary row, byte for byte, with §6's directives and no
    // validator.
    let mut client = server.h1().await;
    let ranged = client
        .request(
            &h1("GET", target.as_bytes(), &[("range", b"bytes=0-99")], None),
            true,
        )
        .await;
    assert_eq!(ranged.status, 206);
    assert_eq!(ranged.body, bin_body());
    assert_eq!(
        ranged.field("cache-control"),
        Some("max-age=31536000, immutable")
    );
    assert_eq!(ranged.field("etag"), None, "§6: no ETag on a bin response");
    assert_eq!(
        ranged.field("content-type"),
        Some("application/vnd.granary.bin.v1")
    );
}

// ============================================================ row set 4

/// §13.2 item 11 — `HEAD` is `405` on **all five** resources, each with
/// its own `Allow`, and no `Allow` names `HEAD`.
///
/// The meta row runs against a `grain-id` the fake HOLDS: a server that
/// answered `HEAD` would return `200` there and `404` for an absent one,
/// so testing only the absent case cannot tell a refusal from a miss.
#[tokio::test]
async fn head_is_405_on_all_five_resources_with_the_resources_own_allow() {
    let server = Loopback::start().await;
    let rows = [
        (bin_target(), "GET, PUT"),
        (meta_target(), "GET, PUT"),
        (root_target(), "GET, PUT"),
        (format!("/volume/{VOLUME}/max-seq"), "GET"),
        (format!("/volume/{VOLUME}/hint"), "GET, PUT"),
    ];
    assert_eq!(rows.len(), 5, "§4.2 has five resources");

    for (target, allow) in rows {
        let mut client = server.h1().await;
        // A `HEAD` response declares a length it does not send, so the
        // reader must not go looking for content.
        let reply = client
            .request(&h1("HEAD", target.as_bytes(), &[], None), false)
            .await;
        assert_eq!(reply.status, 405, "{target}");
        assert_eq!(reply.token(), Some("method-not-allowed"), "{target}");
        assert_eq!(reply.field("allow"), Some(allow), "{target}");
        assert!(
            !allow.contains("HEAD"),
            "{target}: §4.2 forbids advertising a method the server refuses"
        );
    }

    let mut client = server.h1().await;
    let deleted = client
        .request(&h1("DELETE", bin_target().as_bytes(), &[], None), true)
        .await;
    assert_eq!(deleted.status, 405);
    assert_eq!(deleted.token(), Some("method-not-allowed"));
    assert_eq!(deleted.field("allow"), Some("GET, PUT"));
}

// ============================================================ row set 5

/// §5a.6 and §13.2 item 12 — conditional fields are REFUSED rather than
/// evaluated, the refusal runs AFTER the `404` and the `405`, and the
/// one exempt triple still works in all three of its states.
#[tokio::test]
async fn conditional_fields_are_refused_in_section_5a6s_order() {
    /// An `HTTP-date`, well formed for the two names that carry one.
    const DATE: &[u8] = b"Sat, 01 Jan 2000 00:00:00 GMT";

    let server = Loopback::start().await;

    // The `304` that must not happen: an occupied seq, a conditional,
    // and the answer is the refusal — never `304`.
    //
    // All four of §5a.6's non-exempt names, each with a value that is
    // well formed for its own grammar, so the row is about PRESENCE.
    // The two date-carrying names are the ones a client library will
    // never send by itself and a hand-kept adapter list quietly omits.
    for (name, value) in [
        ("if-match", b"\"anything\"".as_slice()),
        ("if-none-match", b"\"anything\"".as_slice()),
        ("if-modified-since", DATE),
        ("if-unmodified-since", DATE),
    ] {
        let mut client = server.h1().await;
        let occupied = client
            .request(
                &h1("GET", root_target().as_bytes(), &[(name, value)], None),
                true,
            )
            .await;
        assert_eq!(
            (occupied.status, occupied.token()),
            (400, Some("bad-request")),
            "{name}: §13.2 item 12 — refused on presence, and never a 304"
        );
    }

    // The ORDER: step 1 before step 3, and step 2 before step 3.
    let mut client = server.h1().await;
    let malformed = client
        .request(
            &h1("GET", b"/bin/not-a-digest", &[("if-match", b"\"x\"")], None),
            true,
        )
        .await;
    assert_eq!(
        malformed.status, 404,
        "§5a.6: the target grammar runs first"
    );
    assert_eq!(malformed.token(), Some("unknown-target"));

    let mut client = server.h1().await;
    let wrong_method = client
        .request(
            &h1(
                "DELETE",
                bin_target().as_bytes(),
                &[("if-match", b"\"x\"")],
                None,
            ),
            true,
        )
        .await;
    assert_eq!(wrong_method.status, 405, "§5a.6: the method runs before it");
    assert_eq!(wrong_method.token(), Some("method-not-allowed"));
}

/// §5a.6's ONE exempt triple — `If-None-Match` + hint + `GET` — in all
/// three of its states (§13.2 item 12).
///
/// The third is the one a suite that only ever tests the exemption
/// after a `PUT hint` never visits: a volume with no hint object at
/// all, where the answer is neither `304` nor `200`.
#[tokio::test]
async fn the_one_exempt_triple_still_revalidates() {
    let server = Loopback::start().await;
    let hint = format!("/volume/{VOLUME}/hint");

    // The validator the `200` hands out — a client echoes it verbatim.
    let mut client = server.h1().await;
    let polled = client.get(&hint).await;
    assert_eq!(polled.status, 200);
    let validator = polled
        .field("etag")
        .unwrap_or_else(|| panic!("§5.8 makes the hint's ETag REQUIRED"))
        .to_owned();

    let mut client = server.h1().await;
    let matched = client
        .request(
            &h1(
                "GET",
                hint.as_bytes(),
                &[("if-none-match", validator.as_bytes())],
                None,
            ),
            true,
        )
        .await;
    assert_eq!(matched.status, 304, "§5.8: the poll's 304");
    assert_eq!(
        matched.field("etag"),
        Some(validator.as_str()),
        "§6: the same validator the 200 would have carried"
    );
    assert!(matched.body.is_empty());

    let mut client = server.h1().await;
    let stale = client
        .request(
            &h1(
                "GET",
                hint.as_bytes(),
                &[("if-none-match", b"\"stale\"")],
                None,
            ),
            true,
        )
        .await;
    assert_eq!(stale.status, 200, "a stale validator must not match");
    assert_eq!(stale.field("etag"), Some(validator.as_str()));

    // The state every volume is in before its first `PUT hint`: the
    // exemption is not a promise of `200`, and never a `304`.
    let mut client = server.h1().await;
    let absent = client
        .request(
            &h1(
                "GET",
                format!("/volume/{EMPTY_VOLUME}/hint").as_bytes(),
                &[("if-none-match", validator.as_bytes())],
                None,
            ),
            true,
        )
        .await;
    assert_eq!(absent.status, 404);
    assert_eq!(
        absent.token(),
        Some("not-found"),
        "§8.1: the token is what makes this 404 a success on this endpoint"
    );
}

/// The §13.2 item 24 response tuple: status, error token, §6 metadata, and body.
pub(crate) type ResponseTuple = (
    u16,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Bytes,
);

fn response_tuple_h1(reply: &Reply) -> ResponseTuple {
    (
        reply.status,
        reply.token().map(str::to_owned),
        reply.field("content-type").map(str::to_owned),
        reply.field("cache-control").map(str::to_owned),
        reply.field("allow").map(str::to_owned),
        reply.field("etag").map(str::to_owned),
        reply.field("content-range").map(str::to_owned),
        Bytes::copy_from_slice(&reply.body),
    )
}

fn response_tuple_h2(reply: &H2Reply) -> ResponseTuple {
    (
        reply.status,
        reply.token().map(str::to_owned),
        reply
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        reply
            .headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        reply
            .headers
            .get("allow")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        reply
            .headers
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        reply
            .headers
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        Bytes::copy_from_slice(&reply.body),
    )
}

#[path = "../tests/authority_host/shapes.rs"]
pub(crate) mod shapes;
pub(crate) use shapes::*;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "End-to-end transport matrix verifies all request identifier shapes across both HTTP legs"
)]
async fn request_id_shapes_preserve_response_tuple_across_transports() {
    let server = Loopback::start().await;
    let shapes = request_id_shapes();

    let mut hint_client = server.h1().await;
    let hint_polled = hint_client.get(&format!("/volume/{VOLUME}/hint")).await;
    assert_eq!(hint_polled.status, 200);
    let validator = hint_polled
        .field("etag")
        .expect("hint must carry etag")
        .to_owned();

    let bin_target_str = bin_target();
    let root_target_str = root_target();
    let absent_root_str = format!("/volume/{VOLUME}/root/00000000000000000999");
    let malformed_target_str = "/bin/not-a-digest".to_owned();
    let hint_target_str = format!("/volume/{VOLUME}/hint");
    let bin_payload = bin_body();

    let mut h1_cases = 0;
    for req_idx in 0..8 {
        let (method, target, base_fields, body, has_content) = match req_idx {
            0 => (
                "GET",
                bin_target_str.as_str(),
                vec![("range", b"bytes=0-99".as_slice())],
                None,
                true,
            ),
            1 => ("GET", root_target_str.as_str(), vec![], None, true),
            2 => ("GET", absent_root_str.as_str(), vec![], None, true),
            3 => ("GET", malformed_target_str.as_str(), vec![], None, true),
            4 => ("HEAD", bin_target_str.as_str(), vec![], None, false),
            5 => (
                "GET",
                root_target_str.as_str(),
                vec![("if-match", b"\"anything\"".as_slice())],
                None,
                true,
            ),
            6 => (
                "PUT",
                bin_target_str.as_str(),
                vec![],
                Some(bin_payload.as_slice()),
                true,
            ),
            7 => (
                "GET",
                hint_target_str.as_str(),
                vec![("if-none-match", validator.as_bytes())],
                None,
                true,
            ),
            _ => unreachable!(),
        };

        let mut client = server.h1().await;
        let control_reply = client
            .request(
                &h1(method, target.as_bytes(), &base_fields, body),
                has_content,
            )
            .await;
        let control_tuple = response_tuple_h1(&control_reply);

        for shape in &shapes {
            let mut client = server.h1().await;
            let mut req_fields = base_fields.clone();
            req_fields.extend(shape.as_wire_fields());
            let test_reply = client
                .request(
                    &h1(method, target.as_bytes(), &req_fields, body),
                    has_content,
                )
                .await;
            let test_tuple = response_tuple_h1(&test_reply);

            assert_eq!(
                test_tuple, control_tuple,
                "h1 mismatch on request {req_idx}"
            );
            h1_cases += 1;
        }
    }
    assert_eq!(h1_cases, 88);

    let mut h2_cases = 0;
    let mut h2_client = server.h2().await;
    for req_idx in 0..8 {
        let (method, target, base_fields, body) = match req_idx {
            0 => (
                "GET",
                bin_target_str.as_str(),
                vec![("range", b"bytes=0-99".as_slice())],
                None,
            ),
            1 => ("GET", root_target_str.as_str(), vec![], None),
            2 => ("GET", absent_root_str.as_str(), vec![], None),
            3 => ("GET", malformed_target_str.as_str(), vec![], None),
            4 => ("HEAD", bin_target_str.as_str(), vec![], None),
            5 => (
                "GET",
                root_target_str.as_str(),
                vec![("if-match", b"\"anything\"".as_slice())],
                None,
            ),
            6 => (
                "PUT",
                bin_target_str.as_str(),
                vec![],
                Some(bin_payload.as_slice()),
            ),
            7 => (
                "GET",
                hint_target_str.as_str(),
                vec![("if-none-match", validator.as_bytes())],
                None,
            ),
            _ => unreachable!(),
        };

        let control_reply = h2_client
            .request_with_body(method, target, &base_fields, body)
            .await;
        let control_tuple = response_tuple_h2(&control_reply);

        for shape in &shapes {
            let mut req_fields = base_fields.clone();
            req_fields.extend(shape.as_wire_fields());
            let test_reply = h2_client
                .request_with_body(method, target, &req_fields, body)
                .await;
            let test_tuple = response_tuple_h2(&test_reply);

            assert_eq!(
                test_tuple, control_tuple,
                "h2 mismatch on request {req_idx}"
            );
            h2_cases += 1;
        }
    }
    assert_eq!(h2_cases, 88);
}

#[tokio::test]
async fn request_id_whitespace_is_accepted_without_changing_status() {
    let server = Loopback::start().await;
    let mut client = server.h1().await;
    let control = client.get(&root_target()).await;

    let mut client = server.h1().await;
    let replied = client
        .request(
            &h1(
                "GET",
                root_target().as_bytes(),
                &[("granary-request-id", b" a ")],
                None,
            ),
            true,
        )
        .await;

    assert_eq!(
        response_tuple_h1(&replied),
        response_tuple_h1(&control),
        "whitespace-padded request-id must yield the exact control response tuple"
    );
}

#[tokio::test]
async fn request_id_is_never_echoed_in_response_headers() {
    let server = Loopback::start().await;

    let mut client = server.h1().await;
    let replied = client
        .request(
            &h1(
                "GET",
                root_target().as_bytes(),
                &[("granary-request-id", b"echo-check-h1")],
                None,
            ),
            true,
        )
        .await;
    assert_eq!(replied.status, 200);
    assert!(replied.field("granary-request-id").is_none());

    let mut client = server.h2().await;
    let replied_h2 = client
        .request_with_body(
            "GET",
            &root_target(),
            &[("granary-request-id", b"echo-check-h2")],
            None,
        )
        .await;
    assert_eq!(replied_h2.status, 200);
    assert!(replied_h2.headers.get("granary-request-id").is_none());
}

// ============================================================ row set 6

/// **The caller-assertion rows**: the adapter conformance this crate
/// could not check before it had a wire.
///
/// Each row is written so that an adapter which reads the head with
/// `HeaderMap::get`, or which keeps its own list of conditional field
/// names, answers something OTHER than the assertion — a `206` where a
/// `400` is required, a `304` where a `200` is.
#[tokio::test]
async fn the_head_reaches_the_gate_whole() {
    let server = Loopback::start().await;
    let target = bin_target();

    // TWO `Range` field lines, each individually valid. An adapter that
    // forwards the first serves a `206`.
    let mut client = server.h1().await;
    let two_ranges = client
        .request(
            &h1(
                "GET",
                target.as_bytes(),
                &[("range", b"bytes=0-9"), ("range", b"bytes=10-19")],
                None,
            ),
            true,
        )
        .await;
    assert_eq!(
        (two_ranges.status, two_ranges.token()),
        (400, Some("bad-range")),
        "§7.1: two field lines are two ranges, and the gate refuses them"
    );

    // `If-Range` alongside a valid `Range`. An adapter with its own list
    // of conditional names omits this one and serves the `206`.
    let mut client = server.h1().await;
    let if_range = client
        .request(
            &h1(
                "GET",
                target.as_bytes(),
                &[("range", b"bytes=0-9"), ("if-range", b"\"x\"")],
                None,
            ),
            true,
        )
        .await;
    assert_eq!(
        (if_range.status, if_range.token()),
        (400, Some("bad-request")),
        "§5a.6: If-Range is one of the five, and the adapter does not decide that"
    );

    // A name outside the five costs a comparison and changes nothing.
    let mut client = server.h1().await;
    let probed = client
        .request(
            &h1(
                "GET",
                target.as_bytes(),
                &[("range", b"bytes=0-9"), ("x-granary-probe", b"1")],
                None,
            ),
            true,
        )
        .await;
    assert_eq!(probed.status, 206, "an unknown field name is ignored");
    assert_eq!(probed.body.len(), 10);
}

/// Two `If-None-Match` field lines collapse to "no cached validator",
/// **in both orders**.
///
/// The MATCHING-value-first arm is the discriminating one: a
/// `HeaderMap::get` adapter forwards the FIRST line, so matching-first
/// makes it answer the false `304` this row exists to catch. Stale-first
/// would let the same defect pass by coincidence, which is why both
/// orders are here.
///
/// The h2 leg, because hyper's own client will not build a request with
/// duplicate field lines.
#[tokio::test]
async fn duplicate_if_none_match_lines_collapse_in_both_orders() {
    let server = Loopback::start().await;
    let hint = format!("/volume/{VOLUME}/hint");

    let mut client = server.h2().await;
    let polled = client.request("GET", &hint, &[]).await;
    assert_eq!(polled.status, 200);
    let validator = polled
        .headers
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("§5.8 makes the hint's ETag REQUIRED"))
        .to_owned();

    // Matching FIRST: a `get()` adapter answers 304 here.
    let matching_first = client
        .request(
            "GET",
            &hint,
            &[
                ("if-none-match", validator.as_str()),
                ("if-none-match", "\"stale\""),
            ],
        )
        .await;
    assert_eq!(
        matching_first.status, 200,
        "§5a.6: two lines are a value this server cannot match, so the \
         answer is the unconditional one"
    );

    let stale_first = client
        .request(
            "GET",
            &hint,
            &[
                ("if-none-match", "\"stale\""),
                ("if-none-match", validator.as_str()),
            ],
        )
        .await;
    assert_eq!(stale_first.status, 200);

    // The positive control: ONE line with the matching value still
    // revalidates, so the two rows above are a collapse and not a
    // blanket refusal to revalidate at all.
    let single = client
        .request("GET", &hint, &[("if-none-match", validator.as_str())])
        .await;
    assert_eq!(single.status, 304);
}

/// **The non-UTF-8 discriminator.**
///
/// The store holds a hint whose opaque token is the quoted tag
/// `DQUOTE U+FFFD DQUOTE`. The request carries ONE `If-None-Match` line
/// whose value is the raw bytes `DQUOTE 0x80 DQUOTE` — invalid UTF-8
/// INSIDE an otherwise valid quoted strong entity-tag, which hyper
/// delivers because `etagc` admits obs-text.
///
/// A lossy-decoding adapter turns those bytes into exactly the planted
/// token and answers a false `304`. Collapsing to `None` answers the
/// unconditional `200`. A bare `0x80` with no quotes would fail the
/// entity-tag grammar in BOTH implementations and discriminate nothing,
/// which is why the value is shaped like a tag.
#[tokio::test]
async fn a_non_utf8_if_none_match_never_matches_a_planted_tag() {
    let server = Loopback::start().await;
    let hint = format!("/volume/{TAGGED_VOLUME}/hint");

    // The planted tag is really the store's validator: a matching
    // request against it revalidates, so the row below is about the
    // BYTES and not about an unreachable fixture.
    let mut client = server.h1().await;
    let polled = client.get(&hint).await;
    assert_eq!(polled.status, 200);
    assert_eq!(
        polled.field("etag"),
        Some("\"\u{FFFD}\""),
        "the fixture must be the planted tag"
    );

    let mut client = server.h1().await;
    let honest = client
        .request(
            &h1(
                "GET",
                hint.as_bytes(),
                &[("if-none-match", "\"\u{FFFD}\"".as_bytes())],
                None,
            ),
            true,
        )
        .await;
    assert_eq!(
        honest.status, 304,
        "a VALID UTF-8 value byte-matching the token is an honest 304"
    );

    let mut client = server.h1().await;
    let aliased = client
        .request(
            &h1(
                "GET",
                hint.as_bytes(),
                &[("if-none-match", b"\"\x80\"")],
                None,
            ),
            true,
        )
        .await;
    assert_eq!(
        aliased.status, 200,
        "a lossy decode would alias these bytes onto the planted tag"
    );
    assert_eq!(aliased.token(), None);

    // The same bytes on an endpoint the exemption does not cover: the
    // NAME is what §5a.6 refuses on, and a name reaches the gate whatever
    // its value's encoding. An adapter that collects field names only
    // from lines whose values decode answers the unconditional `200`.
    let mut client = server.h1().await;
    let refused = client
        .request(
            &h1(
                "GET",
                root_target().as_bytes(),
                &[("if-none-match", b"\"\x80\"")],
                None,
            ),
            true,
        )
        .await;
    assert_eq!(
        (refused.status, refused.token()),
        (400, Some("bad-request")),
        "§5a.6: only hint + GET is exempt, and the value is never read"
    );
}

// ============================================================ row set 7

/// A `PUT` the GATE refuses, with content — the shape that still reaches
/// the drain now that writes are live.
///
/// `/bin/not-a-digest` fails §4.3's segment grammar at step 1, so no
/// operation is ever parsed and no body cap exists to apply. Every row
/// below sends one of these rather than a real write, which is the
/// Part-II restatement of what the drain is FOR: an accepted write is
/// bounded by its own endpoint's cap on the accept path, and the drain
/// bounds a request no conforming client sends at all.
fn refused_target() -> &'static str {
    "/bin/not-a-digest"
}

/// §5.5 and §13.2 item 13 — the DRAIN branch, still required when writes are accepted.
///
/// Content that ends inside the budget is drained, so no early answer
/// exists, nothing is signalled, and the connection is reusable. The
/// reuse is the assertion: a server that closed on unread content looks
/// identical from the status line alone.
#[tokio::test]
async fn a_gate_refused_write_drains_inside_the_budget_and_keeps_the_connection() {
    let server = Loopback::start().await;
    let before = server.store.objects();

    let mut client = server.h1().await;
    let refused = client
        .request(
            &h1(
                "PUT",
                refused_target().as_bytes(),
                &[],
                Some(&vec![0x11_u8; 1024]),
            ),
            true,
        )
        .await;
    assert_eq!(
        (refused.status, refused.token()),
        (404, Some("unknown-target"))
    );
    assert_eq!(
        refused.field("connection"),
        None,
        "§5.5: a drained refusal signals no tear-down"
    );
    assert_eq!(
        server.store.objects(),
        before,
        "the gate refusal reached the store"
    );

    // The SAME connection then serves a read.
    let again = client.get(&format!("/volume/{VOLUME}/max-seq")).await;
    assert_eq!(again.status, 200, "the connection stayed usable");

    // §13.2 item 13's paced under-cap row: a root-sized body, written in
    // pieces, with no `Expect: 100-continue` — the expectation is what
    // would remove the condition under test.
    let mut client = server.h1().await;
    let body = vec![0x22_u8; 64 * 1024];
    // The head goes out on its own and the content is paced after it, so
    // the declared length is spelled here rather than derived from a
    // body `h1` would have written in one go.
    let head = format!(
        "PUT {} HTTP/1.1\r\nhost: {HOST}\r\ncontent-length: {}\r\n\r\n",
        refused_target(),
        body.len()
    )
    .into_bytes();
    client.send(&head).await;
    for piece in body.chunks(8 * 1024) {
        assert!(client.try_send(piece).await, "no write-side error");
        pause(Duration::from_millis(5)).await;
    }
    let paced = client.reply(true).await;
    assert_eq!((paced.status, paced.token()), (404, Some("unknown-target")));
    assert_eq!(
        paced.field("connection"),
        None,
        "64 KiB is exactly the budget, so this is the drain branch"
    );
    let again = client.get(&format!("/volume/{VOLUME}/max-seq")).await;
    assert_eq!(again.status, 200);

    // A GET carrying content nobody asked for is drained too, and the
    // connection survives it.
    let mut client = server.h1().await;
    let odd = client
        .request(
            &h1(
                "GET",
                format!("/volume/{VOLUME}/max-seq").as_bytes(),
                &[],
                Some(b"hello"),
            ),
            true,
        )
        .await;
    assert_eq!(odd.status, 200);
    assert_eq!(odd.field("connection"), None);
    assert_eq!(client.get(&root_target()).await.status, 200);
}

/// §5.5's TEAR-DOWN branch on the HTTP/1.1 leg: content past the budget
/// is dropped unread, the response carries `Connection: close`, and the
/// connection then ends in a clean end-of-stream rather than a reset.
///
/// The content is sized to the budget deliberately: the drain consumes
/// every byte written, so nothing is left unread at the moment of close
/// and RFC 9112 §9.6's reset from closing with unread content is not
/// provoked by the test itself.
#[tokio::test]
async fn content_past_the_budget_is_torn_down_with_a_signal_on_h1() {
    let server = Loopback::start().await;
    let mut client = server.h1().await;
    client.send(&h1_chunked_head("PUT", refused_target())).await;

    let piece = vec![0x33_u8; 8 * 1024];
    let mut written: u64 = 0;
    // One chunk past the budget and no more, and the stream is never
    // completed: no terminating chunk is ever sent.
    while written <= DRAIN_BUDGET_BYTES {
        if !client.try_send(&chunk(&piece)).await {
            break;
        }
        written = written.saturating_add(u64::try_from(piece.len()).unwrap_or(u64::MAX));
    }
    assert!(written > DRAIN_BUDGET_BYTES, "the budget must be exceeded");

    let torn = client.reply(true).await;
    assert_eq!((torn.status, torn.token()), (404, Some("unknown-target")));
    assert_eq!(
        torn.field("connection"),
        Some("close"),
        "§5.5: the tear-down branch is SIGNALLED"
    );
    assert_eq!(
        client.ending().await,
        Ending::Eof,
        "§5.5: a conforming staged close is a FIN after a complete response"
    );
}

/// The same shape on the HTTP/2 leg, where §5.5's tear-down is the
/// stream reset.
///
/// The reset is read through `SendStream::poll_reset`: the error a
/// continued send returns carries `reason() == None` and cannot pin the
/// code. Then the CONNECTION serves a second stream — the reset ends the
/// stream, not the connection.
#[tokio::test]
async fn content_past_the_budget_resets_the_stream_but_not_the_connection_on_h2() {
    let server = Loopback::start().await;
    let mut client = server.h2().await;
    let (response, mut send) = client.open("PUT", refused_target(), &[], false).await;

    let piece = Bytes::from(vec![0x44_u8; 8 * 1024]);
    let mut written: u64 = 0;
    while written <= DRAIN_BUDGET_BYTES {
        send.reserve_capacity(piece.len());
        match timeout(
            GENEROUS,
            std::future::poll_fn(|context| send.poll_capacity(context)),
        )
        .await
        {
            Ok(Some(Ok(_capacity))) => {}
            // The server answered and reset while we were still sending,
            // which is the behaviour under test rather than a failure.
            Ok(Some(Err(_reset))) => break,
            Ok(None) => break,
            Err(elapsed) => panic!("no h2 capacity within {GENEROUS:?} ({elapsed})"),
        }
        if send.send_data(piece.clone(), false).is_err() {
            break;
        }
        written = written.saturating_add(u64::try_from(piece.len()).unwrap_or(u64::MAX));
    }

    let torn = collect(response).await;
    assert_eq!((torn.status, torn.token()), (404, Some("unknown-target")));
    assert_eq!(
        torn.headers.get("connection"),
        None,
        "RFC 9113 §8.2.2: hyper strips the h1 signal on this leg"
    );

    match timeout(
        GENEROUS,
        std::future::poll_fn(|context| send.poll_reset(context)),
    )
    .await
    {
        Ok(Ok(reason)) => assert_eq!(
            reason,
            h2::Reason::NO_ERROR,
            "§5.5: the h2 tear-down is RST_STREAM(NO_ERROR) after the complete response"
        ),
        Ok(Err(error)) => panic!("poll_reset: {error}"),
        Err(elapsed) => panic!("the stream was never reset within {GENEROUS:?} ({elapsed})"),
    }

    let second = client
        .request("GET", &format!("/volume/{VOLUME}/max-seq"), &[])
        .await;
    assert_eq!(
        second.status, 200,
        "the reset ended the stream, not the connection"
    );
}

/// **The slow-drip discriminator.** A chunked `PUT` that sends a small
/// chunk every so often, forever, staying far under the byte budget.
///
/// A drain whose timeout is armed PER FRAME never fires — every chunk
/// lands inside its own window — so the connection is held for as long
/// as the peer cares to drip, which is the unauthenticated tarpit the
/// bound exists to exclude. A timeout around the WHOLE drain fires, and
/// the refusal arrives with the tear-down signal while the peer is still
/// dripping.
///
/// The row goes red by its own deadline rather than hanging: `DRIPS`
/// gaps are several times [`DRAIN_MAX_WAIT`], so a per-frame
/// implementation runs out of drips with no reply.
#[tokio::test]
async fn a_slow_drip_is_cut_off_by_the_whole_drain_clock() {
    /// Small enough that `DRIPS` of them are three orders of magnitude
    /// under the byte budget: only the clock can end this drain.
    const DRIP: &[u8] = b"0123456789abcdef";
    const GAP: Duration = Duration::from_millis(300);
    /// Six seconds of gaps against a two-second bound.
    const DRIPS: usize = 20;

    assert!(
        GAP.saturating_mul(u32::try_from(DRIPS).unwrap_or(u32::MAX))
            > DRAIN_MAX_WAIT.saturating_mul(2),
        "the row's own deadline must be well clear of the bound it drives"
    );

    let server = Loopback::start().await;
    let mut client = server.h1().await;
    client.send(&h1_chunked_head("PUT", refused_target())).await;

    let mut reply = None;
    let mut drips = 0_usize;
    while drips < DRIPS {
        if !client.try_send(&chunk(DRIP)).await {
            // A failed send is how a TEAR-DOWN reaches a still-writing
            // peer, and the refusal may already be sitting in the
            // receive buffer — read for it before concluding nothing
            // arrived. On stacks that discard buffered data on RST the
            // read can fail; a `None` here is then the real verdict.
            reply = client.reply_within(GAP, true).await;
            break;
        }
        drips += 1;
        if let Some(seen) = client.reply_within(GAP, true).await {
            reply = Some(seen);
            break;
        }
    }

    let torn = reply.unwrap_or_else(|| {
        panic!(
            "no refusal after {drips} drips of {GAP:?}: the drain's bound is \
             armed per frame, so a dripping peer never trips it"
        )
    });
    assert!(
        u64::try_from(drips.saturating_mul(DRIP.len())).unwrap_or(u64::MAX) < DRAIN_BUDGET_BYTES,
        "the byte budget must be nowhere near exceeded: {drips} drips"
    );
    assert_eq!((torn.status, torn.token()), (404, Some("unknown-target")));
    assert_eq!(
        torn.field("connection"),
        Some("close"),
        "the clock, not the byte budget, took the overflow arm"
    );
}

// ============================================================ row set 8

/// §6, §5.7, §5.8 and §13.2 item 2 — the success metadata, and the
/// byte-for-byte rule against a stored object that is not canonical.
#[tokio::test]
async fn the_success_rows_carry_section_6s_metadata() {
    let server = Loopback::start().await;

    let mut client = server.h1().await;
    let root = client.get(&root_target()).await;
    assert_eq!(root.status, 200);
    assert_eq!(
        root.body,
        root_body(),
        "§2.1.1: a server that re-encodes on read fails only against a \
         stored object that is not canonical"
    );
    assert_eq!(
        root.field("content-type"),
        Some("application/vnd.granary.root.v1")
    );

    let head = client.get(&format!("/volume/{VOLUME}/max-seq")).await;
    assert_eq!(head.status, 200);
    assert_eq!(head.body, format_hint_body(SEQ).into_bytes());
    assert_eq!(head.body.len(), 20, "§5.7: exactly 20 ASCII digits");
    assert_eq!(head.field("cache-control"), Some("no-store"));
    assert_eq!(
        head.field("content-type"),
        Some("text/plain; charset=utf-8")
    );

    let hint = client.get(&format!("/volume/{VOLUME}/hint")).await;
    assert_eq!(hint.status, 200);
    assert_eq!(hint.body, format_hint_body(SEQ).into_bytes());
    assert_eq!(hint.field("cache-control"), Some("no-cache"));
    let validator = hint
        .field("etag")
        .unwrap_or_else(|| panic!("§5.8 makes the hint's ETag REQUIRED"));
    assert!(
        validator.starts_with('"') && validator.ends_with('"') && !validator.starts_with("W/"),
        "§5.8: a STRONG entity-tag, quoted: {validator}"
    );

    let meta = client.get(&meta_target()).await;
    assert_eq!(meta.status, 200);
    assert_eq!(meta.body, meta_body());
    assert_eq!(
        meta.field("content-type"),
        Some("application/vnd.granary.meta.v1")
    );
}

/// §4.1 — a configured `{base}` MOVES every target under it, at the wire.
///
/// Part I configures no base, so every other row here would pass against
/// a service that dropped its `base` argument on the floor. This one is
/// served by a second server configured with one, and it is the pair that
/// makes the claim: the target under the base is answered, and the same
/// target WITHOUT it is not a resource at all. A `404` alone would be
/// weak — a server that answers nothing produces it too — so the row
/// carries the token, and the served half is a planted `200`.
#[tokio::test]
async fn a_configured_base_moves_the_targets_under_it() {
    const UNDER: &str = "/g";
    let server = Loopback::start_at(UNDER).await;
    let max_seq = format!("/volume/{VOLUME}/max-seq");

    let mut client = server.h1().await;
    let inside = client.get(&format!("{UNDER}{max_seq}")).await;
    assert_eq!((inside.status, inside.token()), (200, None));
    assert_eq!(
        inside.body,
        format_hint_body(SEQ).into_bytes(),
        "§5.7: the planted head, under the base"
    );

    let mut client = server.h1().await;
    let bare = client.get(&max_seq).await;
    assert_eq!(
        (bare.status, bare.token()),
        (404, Some("unknown-target")),
        "§4.1: outside the configured base there is no resource"
    );
}

/// §8.4 and §13.2 item 9 — **no error response discloses a store key.**
///
/// The `500` row is the one that matters: `get_bin_range` on a range
/// past the end of a stored object is a backend error whose message
/// names what was read, and §8.4 forbids relaying it. The other rows are
/// there so the scan runs over a refusal from every layer.
#[tokio::test]
async fn no_refusal_discloses_what_the_store_said() {
    let server = Loopback::start().await;
    let target = bin_target();

    let mut replies = Vec::new();
    let mut client = server.h1().await;
    // §13.4: past the end of a bin that exists, but under the ceiling —
    // the seam answers a backend error and the server cannot tell it
    // from an outage.
    let failed = client
        .request(
            &h1(
                "GET",
                target.as_bytes(),
                &[("range", b"bytes=200-207")],
                None,
            ),
            true,
        )
        .await;
    assert_eq!((failed.status, failed.token()), (500, Some("internal")));
    assert!(failed.body.is_empty(), "§8.3: a refusal carries no body");
    replies.push(failed);

    for (target, fields) in [
        ("/bin/not-a-digest".to_owned(), Vec::new()),
        (target.clone(), vec![("range", b"bytes=-500".as_slice())]),
        (
            format!("/volume/{EMPTY_VOLUME}/hint"),
            Vec::<(&str, &[u8])>::new(),
        ),
    ] {
        let mut client = server.h1().await;
        replies.push(
            client
                .request(&h1("GET", target.as_bytes(), &fields, None), true)
                .await,
        );
    }

    for reply in &replies {
        assert!(reply.token().is_some(), "§8.2: every refusal carries one");
        let rendered = String::from_utf8_lossy(&reply.raw);
        for fragment in [
            "invalid range",
            "starts at or past",
            "the object",
            "fake seam",
            "mutex poisoned",
        ] {
            assert!(
                !rendered.contains(fragment),
                "§8.4: {fragment:?} reached the wire in {rendered:?}"
            );
        }
    }
}

// =========================================================== row set 12

// §13.4 / §13.5 — INGEST VERIFICATION, over the wire, under both
// declared profiles.

/// **§13.4's two profiles over ONE request.** The same bytes, to the
/// same target, answered `400` + `verify-failed` by the shipped server
/// and `201`/`200` by the seam-only one.
///
/// Both answers are POSITIVE obligations, which is what stops a run from
/// passing by declaring whichever profile suits it: a verifying server
/// declared seam-only fails on the `400` it emits where a `201` was
/// asserted, and the other way round.
#[tokio::test]
async fn the_two_declared_profiles_answer_the_same_request_differently() {
    let body = not_a_decodable_bin();
    let target = target_for(&body);

    // The VERIFYING profile — and it is the SHIPPED constructor, which
    // is §13.5's reachability rule paid at the wire: the only public
    // door hardcodes verification, so this is not a policy the test
    // selected.
    let verifying = Loopback::start().await;
    let before = verifying.store.objects();
    let mut client = verifying.h1().await;
    let refused = client
        .request(&h1("PUT", target.as_bytes(), &[], Some(&body)), true)
        .await;
    assert_eq!(
        (refused.status, refused.token()),
        (400, Some("verify-failed")),
        "§13.4: the verifying profile refuses a body that is not a decodable bin"
    );
    assert_eq!(
        verifying.store.objects(),
        before,
        "§5.1: verification is an admission layer ABOVE the seam"
    );
    // The connection survives: the whole body was read, so nothing is
    // left unread and §5.5 signals nothing.
    assert_eq!(refused.field("connection"), None);
    assert_eq!(client.get(&root_target()).await.status, 200);

    // The SEAM-ONLY profile, through the one `#[cfg(test)]` door.
    let seam_only = Loopback::start_seam_only().await;
    let before = seam_only.store.objects();
    let mut client = seam_only.h1().await;
    let created = client
        .request(&h1("PUT", target.as_bytes(), &[], Some(&body)), true)
        .await;
    assert_eq!(
        (created.status, created.token()),
        (201, None),
        "§13.4: the seam-only profile stores the same bytes"
    );
    let repeated = client
        .request(&h1("PUT", target.as_bytes(), &[], Some(&body)), true)
        .await;
    assert_eq!(
        (repeated.status, repeated.token()),
        (200, None),
        "§13.4: and answers 200 on the repeat"
    );
    assert_eq!(
        seam_only.store.objects(),
        before + 1,
        "one object, stored once"
    );
}

/// **§13.4's verifying-profile-only bomb row.** A DECODABLE bin
/// whose frame headers declare a decompressed sum past the ingest limit
/// is `413` + `too-large`, and the seam-only profile answers `201` on the
/// same request.
///
/// Every grain in the witness would ALSO fail its hash check, so a
/// server that verified before it counted would answer `400` +
/// `verify-failed`. §5.1 makes the precedence normative and this row is
/// where it is observable.
#[tokio::test]
async fn a_bin_declaring_a_sum_past_the_ingest_limit_is_413_too_large() {
    let bomb = declared_sum_bomb();
    let target = target_for(&bomb);
    assert!(
        u64::try_from(bomb.len()).unwrap_or(u64::MAX) < DRAIN_BUDGET_BYTES * 8,
        "the witness is a few hundred kilobytes: the refusal is about what \
         the bin DECLARES, not about its size"
    );

    let verifying = Loopback::start().await;
    let before = verifying.store.objects();
    let mut client = verifying.h1().await;
    let refused = client
        .request(&h1("PUT", target.as_bytes(), &[], Some(&bomb)), true)
        .await;
    assert_eq!(
        (refused.status, refused.token()),
        (413, Some("too-large")),
        "§9.2: never layout-invalid and never verify-failed — the client's \
         action is re-pack smaller and RETRY"
    );
    assert_eq!(verifying.store.objects(), before);

    let seam_only = Loopback::start_seam_only().await;
    let mut client = seam_only.h1().await;
    let created = client
        .request(&h1("PUT", target.as_bytes(), &[], Some(&bomb)), true)
        .await;
    assert_eq!(
        (created.status, created.token()),
        (201, None),
        "§13.4: an admission-layer refusal, not a decode bound"
    );
}

// =========================================================== row set 13

// The counting accept, the per-kind caps, and the clock.

/// **`PUT hint` past its one legal length is `400` + `bad-request`, and
/// NEVER `413`** (§5.9 has no `413` row at all).
///
/// A generic read-up-to-N-then-refuse would answer `413` here, which
/// tells a client to retry a smaller body that has no smaller: the hint
/// is exactly twenty octets or it is malformed. The chunked variant is
/// the same claim with no declared length anywhere, so nothing can be
/// answering from `Content-Length`.
#[tokio::test]
async fn an_over_long_hint_is_400_bad_request_and_never_413() {
    let server = Loopback::start().await;
    let target = format!("/volume/{VOLUME}/hint");

    // The boundary: exactly twenty digits is the one legal body.
    let mut client = server.h1().await;
    let written = client
        .request(
            &h1("PUT", target.as_bytes(), &[], Some(b"00000000000000000009")),
            false,
        )
        .await;
    assert_eq!((written.status, written.token()), (204, None));

    for (name, body) in [
        ("nineteen digits", b"0000000000000000009".to_vec()),
        ("twenty-one digits", b"000000000000000000009".to_vec()),
        ("a kilobyte", vec![b'0'; 1024]),
        ("a megabyte", vec![b'0'; 1024 * 1024]),
    ] {
        let mut client = server.h1().await;
        // `try_send`, because the refusal is entitled to arrive while the
        // peer is still writing — a megabyte declared against a 20-octet
        // cap is refused on the head, and the write half then breaks.
        // That IS the behaviour under test; a panicking write would hide
        // it behind an I/O error.
        let _sent = client
            .try_send(&h1("PUT", target.as_bytes(), &[], Some(&body)))
            .await;
        let refused = client.reply(true).await;
        assert_eq!(
            (refused.status, refused.token()),
            (400, Some("bad-request")),
            "{name}: §5.9's body has one length, so long and malformed are \
             one refusal — a 413 here invents a row the protocol lacks"
        );
    }

    // CHUNKED, so there is no declared length to refuse from.
    let mut client = server.h1().await;
    client.send(&h1_chunked_head("PUT", &target)).await;
    client.send(&chunk(&vec![b'0'; 4096])).await;
    let refused = client.reply(true).await;
    assert_eq!(
        (refused.status, refused.token()),
        (400, Some("bad-request")),
        "with no Content-Length anywhere, the count is of framed bytes"
    );
}

/// **The per-kind `413` boundary, CHUNKED and with no
/// `Content-Length`** — the row a server that sized its refusal from
/// the declared length fails outright.
///
/// The boundary pair is what pins the cap at the cap: exactly
/// `ROOT_MAX_BYTES` is accepted and one octet more is `413`. The meta
/// endpoint carries the same pair at its own, larger bound, so the two
/// rows together show the cap is per-KIND and not one number.
#[tokio::test]
async fn a_chunked_body_past_its_kind_cap_is_413_at_the_cap() {
    let server = Loopback::start().await;

    // ROOT, at the cap: accepted. The server stores roots verbatim, so
    // any bytes will do.
    let at_cap = usize::try_from(ROOT_MAX_BYTES).unwrap_or(usize::MAX);
    let mut client = server.h1().await;
    client
        .send(&h1_chunked_head(
            "PUT",
            &format!("/volume/{VOLUME}/root/00000000000000000101"),
        ))
        .await;
    for piece in vec![0x77_u8; at_cap].chunks(16 * 1024) {
        assert!(client.try_send(&chunk(piece)).await);
    }
    client.send(b"0\r\n\r\n").await;
    let accepted = client.reply(true).await;
    assert_eq!(
        (accepted.status, accepted.token()),
        (201, None),
        "the cap itself is inside the cap"
    );

    // ROOT, one octet past it: `413`, with no declared length anywhere.
    let mut client = server.h1().await;
    client
        .send(&h1_chunked_head(
            "PUT",
            &format!("/volume/{VOLUME}/root/00000000000000000102"),
        ))
        .await;
    let mut written = 0_usize;
    while written <= at_cap {
        if !client.try_send(&chunk(&vec![0x77_u8; 16 * 1024])).await {
            break;
        }
        written += 16 * 1024;
    }
    let refused = client.reply(true).await;
    assert_eq!(
        (refused.status, refused.token()),
        (413, Some("too-large")),
        "past the cap, counted from framed bytes"
    );
    assert_eq!(
        refused.field("connection"),
        Some("close"),
        "content is left unread, so §5.5 signals the tear-down"
    );

    // META carries the SAME pair at its own bound.
    let over = usize::try_from(META_MAX_BYTES).unwrap_or(usize::MAX) + 1;
    let body = vec![0x88_u8; over];
    let mut client = server.h1().await;
    client
        .send(&h1_chunked_head(
            "PUT",
            &format!("/volume/{VOLUME}/meta/{}", GrainId::of(&body)),
        ))
        .await;
    let mut written = 0_usize;
    while written < over {
        let piece = (over - written).min(256 * 1024);
        if !client.try_send(&chunk(&vec![0x88_u8; piece])).await {
            break;
        }
        written += piece;
        if let Some(reply) = client.reply_within(Duration::from_millis(1), true).await {
            assert_eq!((reply.status, reply.token()), (413, Some("too-large")));
            return;
        }
    }
    let refused = client.reply(true).await;
    assert_eq!(
        (refused.status, refused.token()),
        (413, Some("too-large")),
        "the meta cap is META_MAX_BYTES and not the root's"
    );
}

/// **The `413` is READABLE mid-stream, on both legs.** A peer still
/// writing when the cap is crossed must be able to read the status line
/// before the tear-down reaches it — otherwise a client learns only that
/// the connection broke.
#[tokio::test]
async fn a_mid_stream_413_is_readable_on_both_legs() {
    let server = Loopback::start().await;
    let over = usize::try_from(ROOT_MAX_BYTES).unwrap_or(usize::MAX) + 1;

    // h1: chunked, over the root cap, never terminated.
    let mut client = server.h1().await;
    client
        .send(&h1_chunked_head(
            "PUT",
            &format!("/volume/{VOLUME}/root/00000000000000000201"),
        ))
        .await;
    let mut written = 0_usize;
    while written <= over {
        if !client.try_send(&chunk(&vec![0x99_u8; 8 * 1024])).await {
            break;
        }
        written += 8 * 1024;
    }
    let torn = client.reply(true).await;
    assert_eq!((torn.status, torn.token()), (413, Some("too-large")));
    assert_eq!(torn.field("connection"), Some("close"));

    // h2: DATA past the cap, and the CONNECTION survives the stream.
    let mut client = server.h2().await;
    let (response, mut send) = client
        .open(
            "PUT",
            &format!("/volume/{VOLUME}/root/00000000000000000202"),
            &[],
            false,
        )
        .await;
    let piece = Bytes::from(vec![0xaa_u8; 8 * 1024]);
    let mut written = 0_usize;
    while written <= over {
        send.reserve_capacity(piece.len());
        match timeout(
            GENEROUS,
            std::future::poll_fn(|context| send.poll_capacity(context)),
        )
        .await
        {
            Ok(Some(Ok(_capacity))) => {}
            // The server answered and reset while we were still sending,
            // which is the behaviour under test rather than a failure.
            Ok(Some(Err(_reset))) => break,
            Ok(None) => break,
            Err(elapsed) => panic!("no h2 capacity within {GENEROUS:?} ({elapsed})"),
        }
        if send.send_data(piece.clone(), false).is_err() {
            break;
        }
        written += piece.len();
    }
    let torn = collect(response).await;
    assert_eq!((torn.status, torn.token()), (413, Some("too-large")));
    match timeout(
        GENEROUS,
        std::future::poll_fn(|context| send.poll_reset(context)),
    )
    .await
    {
        Ok(Ok(reason)) => assert_eq!(reason, h2::Reason::NO_ERROR),
        Ok(Err(error)) => panic!("poll_reset: {error}"),
        Err(elapsed) => panic!("the stream was never reset within {GENEROUS:?} ({elapsed})"),
    }
    let second = client
        .request("GET", &format!("/volume/{VOLUME}/max-seq"), &[])
        .await;
    assert_eq!(
        second.status, 200,
        "the reset ended the stream, not the connection"
    );
}

/// **The whole-accept clock (the empty-frame flood).** A peer that trickles
/// content far under every byte cap, forever, is refused `503` +
/// `unavailable` when the WHOLE-accept bound expires.
///
/// A byte budget cannot catch this peer and neither can a per-frame
/// clock — every frame lands inside its own window, so the bound is
/// re-armed by the flood it exists to stop. The positive control is the
/// row beside it: a real multi-frame bin inside the clock is `201`.
#[tokio::test]
async fn a_trickling_write_is_shed_when_the_accept_clock_expires() {
    let server = Loopback::start().await;
    let target = target_for(&valid_bin());

    let mut client = server.h2().await;
    let (response, mut send) = client.open("PUT", &target, &[], false).await;
    // Gaps summing well past the bound, at a byte total three orders of
    // magnitude under `BIN_MAX_BYTES`.
    let gap = WRITE_ACCEPT_MAX_WAIT / 10;
    let drips = 40_usize;
    let mut octets = 0_usize;
    for _ in 0..drips {
        if send.send_data(Bytes::from_static(b"."), false).is_err() {
            break;
        }
        octets += 1;
        pause(gap).await;
    }
    assert!(
        u64::try_from(octets).unwrap_or(u64::MAX) < DRAIN_BUDGET_BYTES,
        "the byte cap must be nowhere near reached: {octets} octets"
    );
    let shed = collect(response).await;
    assert_eq!(
        (shed.status, shed.token()),
        (503, Some("unavailable")),
        "the clock, not a byte count, ends a trickling accept"
    );

    // The POSITIVE control: a real bin, in several frames, inside the
    // clock.
    let bin = valid_bin();
    let mut client = server.h2().await;
    let (response, mut send) = client.open("PUT", &target, &[], false).await;
    let mut pieces = bin.chunks(16).peekable();
    while let Some(piece) = pieces.next() {
        let last = pieces.peek().is_none();
        send.send_data(Bytes::copy_from_slice(piece), last)
            .unwrap_or_else(|e| panic!("h2 data: {e}"));
    }
    let created = collect(response).await;
    assert_eq!(
        (created.status, created.token()),
        (201, None),
        "a multi-frame bin inside the clock must be SERVED"
    );
}

/// **The `Content-Length` fast path.** A peer DECLARING more than the cap
/// is refused before a byte of its content is read — and the hint's
/// declaration is still a `400`, not a `413`.
///
/// §5a.2 forbids the declaration STANDING IN for the count and this does
/// not: it refuses on a declaration, which is an answer the counted
/// bound would also give, and it never ACCEPTS on one. The store is
/// untouched either way, and no `100-continue` is emitted.
#[tokio::test]
async fn an_over_cap_content_length_is_refused_without_reading_the_body() {
    let server = Loopback::start().await;
    let before = server.store.objects();

    let mut client = server.h1().await;
    let head = format!(
        "PUT {} HTTP/1.1\r\nhost: {HOST}\r\ncontent-length: {}\r\nexpect: 100-continue\r\n\r\n",
        bin_target(),
        BIN_MAX_BYTES + 1
    );
    client.send(head.as_bytes()).await;
    let refused = client.reply(true).await;
    assert_eq!(
        (refused.status, refused.token()),
        (413, Some("too-large")),
        "a declared length past the cap is refused on the head alone"
    );
    assert_ne!(
        refused.status, 100,
        "§5.5: the refusal answers instead of an interim 100"
    );
    assert_eq!(refused.field("connection"), Some("close"));
    assert_eq!(server.store.objects(), before, "no body was ever read");

    // The hint declares 21 and is `400`, not `413` — the fast path
    // carries the per-kind refusal, not a status of its own.
    let mut client = server.h1().await;
    let head =
        format!("PUT /volume/{VOLUME}/hint HTTP/1.1\r\nhost: {HOST}\r\ncontent-length: 21\r\n\r\n");
    client.send(head.as_bytes()).await;
    let refused = client.reply(true).await;
    assert_eq!(
        (refused.status, refused.token()),
        (400, Some("bad-request"))
    );
}

/// **The transport-rejected arm, and it is DISTINCT from a `413` on both
/// legs.**
///
/// A peer that declares a length and delivers less, or that resets its
/// stream mid-body, has broken its own message. The request's size
/// was never established, so it must not be refused as too large: on
/// h1 the peer reads a `400` + `bad-request` (measured below), and on h2
/// the stream errors. **The assertion is that neither looks like a SIZE
/// refusal** — a `413` here would tell a client its bin was too large
/// when the truth is that its own request never arrived, and it would
/// send that client into a re-pack loop it can never win.
#[tokio::test]
async fn an_under_delivered_body_is_a_transport_failure_and_not_a_refusal() {
    let server = Loopback::start().await;
    let before = server.store.objects();

    // h1: a declared length the peer does not deliver, then a half-close
    // so the server sees end-of-stream 3 996 octets early.
    let mut client = server.h1().await;
    let head = format!(
        "PUT /volume/{VOLUME}/root/00000000000000000301 HTTP/1.1\r\nhost: {HOST}\r\ncontent-length: 4096\r\n\r\n"
    );
    client.send(head.as_bytes()).await;
    client.send(&[0x5b_u8; 100]).await;
    client
        .stream
        .shutdown()
        .await
        .unwrap_or_else(|e| panic!("shutdown: {e}"));

    // **MEASURED: over HTTP/1.1 the peer DOES receive a response.**
    // On this stack, the server
    // sends `400` + `bad-request` and the peer reads it out of its
    // receive buffer before the connection ends. The reason is
    // structural rather than incidental: this `Service`'s error type is
    // `Infallible` — "there is no error a granary server reports by
    // failing to answer" — so the adapter has no way to decline to
    // answer, and hyper writes whatever it is handed.
    //
    // The row asserts what happens on each leg, and
    // the outcome is a CONFORMING one: §8.2 glosses `bad-request` as
    // "anything else about the request this profile rejects", a body the
    // peer declared and did not deliver is exactly that, and the client
    // action is the `Err` the table's own column names. What it must
    // never be is `413` (a re-pack loop the client can never win) or a
    // `2xx` (bytes that were never stored).
    let answered = client.reply_within(BRIEF, true).await;
    let status = answered.map(|reply| reply.status);
    assert_eq!(
        status,
        Some(400),
        "an under-delivered h1 body answers 400 + bad-request on this stack"
    );
    assert_ne!(status, Some(413), "never an over-cap refusal");
    assert_ne!(status, Some(201), "and never a stored one");

    // h2: the stream is RESET by the peer mid-body. The response future
    // must FAIL rather than resolve to a status, and the connection must
    // survive it.
    let mut client = server.h2().await;
    let (response, mut send) = client
        .open(
            "PUT",
            &format!("/volume/{VOLUME}/root/00000000000000000302"),
            &[],
            false,
        )
        .await;
    send.send_data(Bytes::from_static(b"a partial root"), false)
        .unwrap_or_else(|e| panic!("h2 data: {e}"));
    send.send_reset(h2::Reason::CANCEL);
    match timeout(GENEROUS, response).await {
        Ok(Err(_transport)) => {}
        Ok(Ok(reply)) => panic!(
            "a reset stream answered {}: a transport failure is not a refusal",
            reply.status()
        ),
        Err(elapsed) => panic!("the reset stream never settled ({elapsed})"),
    }
    let second = client
        .request("GET", &format!("/volume/{VOLUME}/max-seq"), &[])
        .await;
    assert_eq!(
        second.status, 200,
        "the reset ended the stream, not the connection"
    );

    assert_eq!(
        server.store.objects(),
        before,
        "and nothing partial was stored on either leg"
    );
}

// =========================================================== row set 14

// The PROCESS-wide write-body budget and verify permits, over real connections.

/// **The budget's shed and its RELEASE (park-proof).**
///
/// The budget is filled through the very `Arc` every connection charges,
/// so the shed is deterministic rather than a race: with the budget
/// full, a write is `503` + `unavailable` as soon as its first content
/// frame asks for room; with the charge released, the same write
/// succeeds; and the in-flight count returns to zero after every one of
/// them.
///
/// A budget that only ever filled would look exactly like a server under
/// load, which is why the release is asserted and not assumed.
#[tokio::test]
async fn a_full_write_budget_sheds_503_and_the_budget_returns_to_zero() {
    // One maximal bin's worth: the smallest budget that still admits a
    // conforming write of any kind.
    let server = Loopback::start_with_budget(BIN_MAX_BYTES).await;
    let budget = server.service.write_budget();
    assert_eq!(budget.in_flight(), 0);

    let body = valid_bin();
    let target = target_for(&body);

    // Filled from the outside, through the shared handle.
    let held = budget
        .reserve(BIN_MAX_BYTES)
        .unwrap_or_else(|| panic!("the whole budget"));
    let mut client = server.h1().await;
    let shed = client
        .request(&h1("PUT", target.as_bytes(), &[], Some(&body)), true)
        .await;
    assert_eq!(
        (shed.status, shed.token()),
        (503, Some("unavailable")),
        "a write whose first charge finds no room is shed"
    );
    assert_eq!(
        shed.field("connection"),
        Some("close"),
        "the rest of the body is left unread, so §5.5 signals the tear-down"
    );

    // Released — and the same write now succeeds.
    drop(held);
    assert_eq!(budget.in_flight(), 0);
    let mut client = server.h1().await;
    let created = client
        .request(&h1("PUT", target.as_bytes(), &[], Some(&body)), true)
        .await;
    assert_eq!((created.status, created.token()), (201, None));
    assert_eq!(
        budget.in_flight(),
        0,
        "every reservation the accept path took was released"
    );

    // **And after a REFUSAL that held a reservation**, which is the exit
    // with no client-visible difference and therefore the one a leak
    // hides on: an over-cap body reserves, reads to the cap, refuses,
    // and must still give the budget back.
    let mut client = server.h1().await;
    client
        .send(&h1_chunked_head(
            "PUT",
            &format!("/volume/{VOLUME}/root/00000000000000000451"),
        ))
        .await;
    let mut written = 0_u64;
    while written <= ROOT_MAX_BYTES {
        if !client.try_send(&chunk(&vec![0x66_u8; 16 * 1024])).await {
            break;
        }
        written += 16 * 1024;
    }
    let refused = client.reply(true).await;
    assert_eq!((refused.status, refused.token()), (413, Some("too-large")));
    assert_eq!(
        budget.in_flight(),
        0,
        "the reservation an over-cap body took must come back on the \
         refusing exit too"
    );

    // The same for a VERIFY refusal, which returns from further in.
    let bad = not_a_decodable_bin();
    let mut client = server.h1().await;
    let refused = client
        .request(
            &h1("PUT", target_for(&bad).as_bytes(), &[], Some(&bad)),
            true,
        )
        .await;
    assert_eq!(
        (refused.status, refused.token()),
        (400, Some("verify-failed"))
    );
    assert_eq!(budget.in_flight(), 0, "and on the verify-refusal exit");

    // And it keeps working: a budget that leaked would stop after the
    // first write and never recover.
    for seq in 401..406_u64 {
        let mut client = server.h1().await;
        let written = client
            .request(
                &h1(
                    "PUT",
                    format!("/volume/{VOLUME}/root/{}", format_hint_body(seq)).as_bytes(),
                    &[],
                    Some(b"a root nobody parses"),
                ),
                true,
            )
            .await;
        assert_eq!(written.status, 201, "seq {seq}");
        assert_eq!(budget.in_flight(), 0, "after seq {seq}");
    }
}

/// **The verify permit: SHARED across connections, and it leaves a
/// worker free.**
///
/// Verification runs inline on the connection's worker, so without a
/// permit every worker can be inside a verify at once and nothing
/// answers a read, fires a timer, or honours the shutdown deadline. The
/// discriminating assertion is the READ: it is served on another
/// connection WHILE the permits are exhausted.
///
/// **Multiple connections, and that is the point.** `GrainService` is
/// cloned per connection; a permit that were a plain field would give
/// each connection its own, so a peer would restore unbounded
/// concurrency by opening connections — and this row would then see a
/// FULL semaphore through its own handle while every connection
/// verified, which is exactly what it refuses.
///
/// **The queue BOUND is deliberately out of this row's way.** Six
/// concurrent 64 MiB verifies serialised through one permit take seconds
/// in the debug build the suite runs, and the shipped bound is sized for
/// the release build that ships — so leaving it armed here would make
/// the row's result depend on how loaded the machine is rather than on
/// whether the permit is shared. The bound has a row of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_verifies_serialise_to_the_permit_and_a_read_still_answers() {
    const STORM: u32 = 6;
    assert_eq!(TEST_WORKER_THREADS, 2, "the runtime this row builds");
    let permits = verify_permits(TEST_WORKER_THREADS);
    assert_eq!(permits, 1, "workers - 1, so one worker stays free");

    let server = Loopback::start_with_permit_wait(PATIENT).await;
    assert_eq!(server.service.verify_permits_available(), permits);

    let body = heavy_bin();
    let target = target_for(&body);

    // A storm of verify-heavy writes, each on its OWN connection. They
    // verify one at a time, so the last waits for every one before it:
    // its reply wait scales with the storm, like the permit wait above.
    let mut storm = Vec::new();
    for _ in 0..STORM {
        let mut client = server.h1().await;
        let request = h1("PUT", target.as_bytes(), &[], Some(&body));
        storm.push(spawn(async move {
            client.send(&request).await;
            let reply = client
                .reply_within(GENEROUS.saturating_mul(STORM), true)
                .await
                .unwrap_or_else(|| panic!("no storm reply within {STORM} x {GENEROUS:?}"));
            (reply.status, reply.token().map(str::to_owned))
        }));
    }

    // Wait until the storm actually HOLDS every permit. This is the
    // row's first discriminating assertion: a permit that is never
    // acquired, or that is a plain field each connection clones its own
    // copy of, never reads zero here however long the storm runs.
    let mut waited = 0_u32;
    while server.service.verify_permits_available() > 0 {
        assert!(
            waited < 200,
            "the permits were never exhausted by six concurrent verifies: \
             either nothing acquires one, or each connection has its own"
        );
        waited += 1;
        pause(Duration::from_millis(50)).await;
    }

    // A READ, on a further connection, WHILE every permit is held.
    let mut reader = server.h1().await;
    let read = reader.get(&format!("/volume/{VOLUME}/max-seq")).await;
    assert_eq!(
        read.status, 200,
        "a read must be served while bins are verifying — the verify permit \
         prevents every worker sitting inside a verify"
    );
    assert_eq!(
        server.service.verify_permits_available(),
        0,
        "and the storm was still holding them when it answered"
    );

    for handle in storm {
        let (status, token) = handle.await.unwrap_or_else(|e| panic!("storm: {e}"));
        assert!(
            status == 201 || status == 200,
            "a valid bin must be stored, not refused: {status} {token:?}"
        );
    }
    assert_eq!(
        server.service.verify_permits_available(),
        permits,
        "the permits return to full after completion (RAII on the success path)"
    );

    // And after a mid-verify REFUSAL, which is a different exit.
    let bad = not_a_decodable_bin();
    let mut client = server.h1().await;
    let refused = client
        .request(
            &h1("PUT", target_for(&bad).as_bytes(), &[], Some(&bad)),
            true,
        )
        .await;
    assert_eq!(
        (refused.status, refused.token()),
        (400, Some("verify-failed"))
    );
    assert_eq!(
        server.service.verify_permits_available(),
        permits,
        "the permits return after a refusal too (RAII on EVERY exit path)"
    );
}

/// **The permit is held across the VERIFY, and never across the
/// UPLOAD.**
///
/// The accept path takes the byte reservation first and the permit last,
/// immediately before the seam. Taking the permit earlier — before the
/// reservation, before the content is read — compiles, stores the same
/// objects, and answers every other row in this file identically,
/// because every other row puts its whole body on the wire in one write
/// and its upload is therefore instant. What it costs is the thing the
/// permit is: a resource deliberately smaller than the connection count,
/// which a peer would then hold for a whole accept window per
/// connection. One slow uploader — entirely conforming, well inside the
/// clock — would stop every other connection in the process from
/// verifying at all, which is the denial of service the verify permit exists to
/// prevent rather than one it should manufacture.
///
/// So the discriminating shape is a SLOW upload, and the row reads the
/// order directly while that upload is mid-body: the byte charge is
/// taken AND the permit is free. That pair is the ordering. The
/// behaviour it buys is asserted beside it — a second connection takes
/// the permit, verifies, and is answered, all while the first body is
/// still arriving.
///
/// **The charge it waits on is ONE GRANULE and not the kind's worst
/// case**, which is the same statement with the numbers corrected: a
/// body that has sent sixteen bytes is charged for the granule that
/// covers them, and a row that waited for 256 MiB to appear would be
/// waiting for an accounting fiction rather than for the accept.
///
/// **The slow upload is parked on a signal rather than paced by a
/// clock.** A wall-clock trickle sized to fit inside the accept bound
/// would make this a race against that bound on a loaded machine
/// instead of a statement about the permit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_upload_holds_its_bytes_but_not_the_verify_permit() {
    assert_eq!(TEST_WORKER_THREADS, 2, "the runtime this row builds");
    let permits = verify_permits(TEST_WORKER_THREADS);
    assert_eq!(
        permits, 1,
        "one permit: the two writes cannot both hold one"
    );

    let server = Loopback::start().await;
    assert_eq!(server.service.verify_permits_available(), permits);

    // Two DIFFERENT bins, so each connection's write is its own verify
    // and neither can be answered out of the other's work.
    let slow = valid_bin();
    let slow_target = target_for(&slow);
    let quick = bin_of(&[b"the bin the second connection stores".to_vec()]);
    let quick_target = target_for(&quick);

    let (release, mut parked) = watch::channel(false);
    let mut uploader = server.h1().await;
    let slow_upload = spawn(async move {
        let mut pieces = slow.chunks(16);
        uploader.send(&h1_chunked_head("PUT", &slow_target)).await;
        // Enough on the wire that the server is inside the accept, and
        // nowhere near enough to end the body.
        if let Some(first) = pieces.next() {
            uploader.send(&chunk(first)).await;
        }
        // Bounded by the accept clock: a signal that never came would
        // otherwise leave this task waiting on a `503` it never reads.
        let _released = timeout(WRITE_ACCEPT_MAX_WAIT, parked.changed()).await;
        for piece in pieces {
            uploader.send(&chunk(piece)).await;
        }
        uploader.send(&chunk(b"")).await;
        let reply = uploader.reply(true).await;
        (reply.status, reply.token().map(str::to_owned))
    });

    // Wait for the fact rather than for an interval: the charge
    // appearing IS the server being inside the accept, and a fixed pause
    // is a guess a loaded machine can outrun.
    let mut waited = 0_u32;
    while server.service.write_budget().in_flight() != WRITE_BUDGET_GRANULE_BYTES {
        assert!(
            waited < 8,
            "the slow write holds {} rather than the one granule its first \
             frame is charged, so nothing below is an observation about the \
             accept path",
            server.service.write_budget().in_flight()
        );
        waited += 1;
        pause(WRITE_ACCEPT_MAX_WAIT / 20).await;
    }

    // **The order, read at the instant the charge exists and the body
    // does not.** A permit taken before the content is read shows the
    // exact opposite here.
    assert_eq!(
        server.service.verify_permits_available(),
        permits,
        "a body still arriving must not be holding the verify permit"
    );

    // Short enough that it cannot be met by WAITING for the slow upload:
    // a permit held across that upload is not given back until its
    // accept ends, which is most of a clock away.
    let while_uploading = WRITE_ACCEPT_MAX_WAIT / 4;
    let mut second = server.h1().await;
    second
        .send(&h1("PUT", quick_target.as_bytes(), &[], Some(&quick)))
        .await;
    let created = second
        .reply_within(while_uploading, true)
        .await
        .unwrap_or_else(|| {
            panic!(
                "no answer on the second connection within {while_uploading:?} \
                 while a body was still arriving on the first: its verify is \
                 queued behind a permit the slow UPLOAD is holding"
            )
        });
    assert_eq!(
        (created.status, created.token()),
        (201, None),
        "a second connection must verify and be answered mid-upload"
    );
    assert!(
        !slow_upload.is_finished(),
        "the slow upload must still be in flight, or this row proved nothing"
    );

    // Released: the slow write is conforming and inside every bound, so
    // it must be STORED rather than shed.
    let _observed = release.send(true);
    let (status, token) = slow_upload
        .await
        .unwrap_or_else(|e| panic!("slow upload: {e}"));
    assert_eq!((status, token.as_deref()), (201, None));

    assert_eq!(
        server.service.verify_permits_available(),
        permits,
        "both permits back: RAII released them"
    );
    assert_eq!(
        server.service.write_budget().in_flight(),
        0,
        "and both charges"
    );
}

// =========================================================== row set 15

/// **The router switch: the writes are LIVE.** A valid bin, a root, a
/// meta object and a hint all land through the shipped stack, and the
/// reads still answer.
///
/// Part I refused every one of these `503` before a body byte was read.
/// This row is the single assertion that the refusal is gone and that
/// nothing it protected has broken.
#[tokio::test]
async fn every_write_endpoint_is_live_through_the_shipped_stack() {
    let server = Loopback::start().await;
    let mut client = server.h1().await;

    // PUT bin — and the repeat is `200`, the seam's own novelty bool.
    let bin = valid_bin();
    let bin_at = target_for(&bin);
    let created = client
        .request(&h1("PUT", bin_at.as_bytes(), &[], Some(&bin)), true)
        .await;
    assert_eq!((created.status, created.token()), (201, None));
    let repeat = client
        .request(&h1("PUT", bin_at.as_bytes(), &[], Some(&bin)), true)
        .await;
    assert_eq!((repeat.status, repeat.token()), (200, None));

    // A bin sent to the WRONG address is `400` + `address-mismatch`,
    // before verification spends anything on what it holds.
    let mismatched = client
        .request(&h1("PUT", bin_target().as_bytes(), &[], Some(&bin)), true)
        .await;
    assert_eq!(
        (mismatched.status, mismatched.token()),
        (400, Some("address-mismatch"))
    );

    // PUT meta — the server MUST NOT parse it.
    let meta = b"a meta object under a format this server was never taught".to_vec();
    let meta_at = format!("/volume/{VOLUME}/meta/{}", GrainId::of(&meta));
    let stored = client
        .request(&h1("PUT", meta_at.as_bytes(), &[], Some(&meta)), true)
        .await;
    assert_eq!((stored.status, stored.token()), (201, None));

    // PUT root — created, then the seq is occupied.
    let root_at = format!("/volume/{VOLUME}/root/{}", format_hint_body(777));
    let root = b"\x00\xffnot a decodable root, and that is the point".to_vec();
    let created = client
        .request(&h1("PUT", root_at.as_bytes(), &[], Some(&root)), true)
        .await;
    assert_eq!((created.status, created.token()), (201, None));
    let occupied = client
        .request(&h1("PUT", root_at.as_bytes(), &[], Some(&root)), true)
        .await;
    assert_eq!(
        (occupied.status, occupied.token()),
        (409, Some("already-exists")),
        "§5.5: the seq is occupied — the CLIENT resolves a failed create-only PUT with one get_root of the attempted seq, treating byte-identical contents as its own landed publish"
    );

    // PUT hint — `204`, created or replaced alike.
    let written = client
        .request(
            &h1(
                "PUT",
                format!("/volume/{VOLUME}/hint").as_bytes(),
                &[],
                Some(b"00000000000000000777"),
            ),
            false,
        )
        .await;
    assert_eq!((written.status, written.token()), (204, None));

    // The reads still answer, on the SAME connection.
    assert_eq!(client.get(&root_at).await.status, 200);
    assert_eq!(client.get(&meta_at).await.status, 200);
    assert_eq!(
        client
            .get(&format!("/volume/{VOLUME}/max-seq"))
            .await
            .status,
        200
    );
    assert_eq!(
        client.get(&format!("/volume/{VOLUME}/hint")).await.status,
        200
    );
    let ranged = client
        .request(
            &h1("GET", bin_at.as_bytes(), &[("range", b"bytes=0-9")], None),
            true,
        )
        .await;
    assert_eq!(ranged.status, 206);
}

// =========================================================== row set 16

/// How many bytes each parked uploader puts on the wire before it stops.
///
/// Far below every write cap and below the charging granule, so what a
/// parked write holds is decided by the CHARGING RULE and by nothing
/// else.
const TRICKLE: usize = 16;

/// Park `count` chunked `PUT bin` uploads mid-body and return their
/// handles, each answering its status once `release` is sent.
///
/// **Distinct bodies**, so no upload can be answered out of another's
/// work, and every one of them is a `201` rather than a `200`.
///
/// The uploads are parked on a SIGNAL rather than paced by a clock, and
/// the caller is told how many have reached the wire through `sent`: a
/// row that released on an interval would be racing the accept clock on
/// a loaded machine instead of stating something about the budget.
async fn park_uploads(
    server: &Loopback,
    count: usize,
    parked: &watch::Receiver<bool>,
    sent: &Arc<AtomicUsize>,
) -> Vec<JoinHandle<Option<(u16, Option<String>)>>> {
    let mut handles = Vec::new();
    for which in 0..count {
        let body = bin_of(&[format!("the parked upload number {which}").into_bytes()]);
        let target = target_for(&body);
        let mut uploader = server.h1().await;
        let mut parked = parked.clone();
        let sent = Arc::clone(sent);
        handles.push(spawn(async move {
            let mut pieces = body.chunks(TRICKLE);
            uploader.send(&h1_chunked_head("PUT", &target)).await;
            // Enough on the wire that the server is inside the accept,
            // and nowhere near enough to end the body.
            if let Some(first) = pieces.next() {
                uploader.send(&chunk(first)).await;
            }
            sent.fetch_add(1, Ordering::Release);
            // Bounded by the accept clock: a signal that never came would
            // otherwise leave this task waiting on an answer it never reads.
            let _released = timeout(WRITE_ACCEPT_MAX_WAIT, parked.changed()).await;
            for piece in pieces {
                if !uploader.try_send(&chunk(piece)).await {
                    break;
                }
            }
            let _ended = uploader.try_send(&chunk(b"")).await;
            uploader
                .reply_within(GENEROUS, true)
                .await
                .map(|reply| (reply.status, reply.token().map(str::to_owned)))
        }));
    }
    handles
}

/// Wait until `sent` reaches `count`, or say why nothing below is an
/// observation.
async fn all_on_the_wire(sent: &AtomicUsize, count: usize) {
    let mut waited = 0_u32;
    while sent.load(Ordering::Acquire) < count {
        assert!(
            waited < 20,
            "only {} of {count} uploads reached the wire, so nothing below \
             is an observation about the write budget",
            sent.load(Ordering::Acquire)
        );
        waited += 1;
        pause(WRITE_ACCEPT_MAX_WAIT / 40).await;
    }
}

/// Wait until the budget holds exactly `expected`.
///
/// **The server-side half of the park proof**, and the sharper one: the
/// client-side counter says the bytes left this process, and this says
/// what the server decided they were worth. A wait rather than a read,
/// because the charge lands when the server polls the frame and not when
/// the client writes it.
async fn charged_exactly(budget: &Arc<WriteBudget>, expected: u64) {
    let mut waited = 0_u32;
    while budget.in_flight() != expected {
        assert!(
            waited < 20,
            "the budget holds {} and not the {expected} the parked uploads \
             have actually sent",
            budget.in_flight()
        );
        waited += 1;
        pause(WRITE_ACCEPT_MAX_WAIT / 40).await;
    }
}

/// **A write holds what it SENT, never what its kind might send.**
///
/// The budget is a bound on bytes this process is holding resident. A
/// reservation taken at the endpoint kind's WORST CASE before the body
/// is polled bounds that quantity too — but it bounds it by charging
/// every write 256 MiB, so a budget sized for eight maximal bins admits
/// exactly eight writes of ANY size, and the ninth one-kilobyte upload is
/// shed `503` while the process holds four kilobytes.
///
/// The discriminating shape is therefore several PARKED uploads at once:
/// each has a few bytes on the wire and none has ended its body. Charged
/// at the worst case, the first fills the budget and every other one is
/// shed. Charged at what arrived, all of them fit with the budget barely
/// touched, and all of them are stored when the bodies finish.
#[tokio::test]
async fn parallel_parked_uploads_are_charged_what_they_sent() {
    /// More than a worst-case budget of this size admits at all.
    const UPLOADS: usize = 4;

    // Room for exactly ONE maximal bin: worst-case charging admits one
    // write of any size, and what arrived admits all of them.
    let server = Loopback::start_with_budget(BIN_MAX_BYTES).await;
    let budget = server.service.write_budget();
    assert_eq!(budget.in_flight(), 0);

    let (release, parked) = watch::channel(false);
    let sent = Arc::new(AtomicUsize::new(0));
    let uploads = park_uploads(&server, UPLOADS, &parked, &sent).await;
    all_on_the_wire(&sent, UPLOADS).await;

    // **The charging rule, read at the instant it is discriminating.**
    // Each upload has [`TRICKLE`] bytes on the wire and none has ended
    // its body, so each holds ONE granule and the process holds four —
    // a quarter of a megabyte, against the gibibyte the worst case would
    // have charged for the same four requests.
    charged_exactly(
        budget,
        WRITE_BUDGET_GRANULE_BYTES * u64::try_from(UPLOADS).unwrap_or(u64::MAX),
    )
    .await;

    let _observed = release.send(true);
    for (which, handle) in uploads.into_iter().enumerate() {
        let answered = handle
            .await
            .unwrap_or_else(|e| panic!("upload {which}: {e}"));
        let (status, token) = answered
            .unwrap_or_else(|| panic!("upload {which} was never answered inside {GENEROUS:?}"));
        assert_eq!(
            (status, token.as_deref()),
            (201, None),
            "upload {which} of {UPLOADS} was refused while the process held \
             a few dozen bytes of it: the budget is charging this kind's \
             worst case rather than what arrived"
        );
    }
    assert_eq!(
        budget.in_flight(),
        0,
        "every charge was released: the budget is park-proof"
    );
}

/// **A stalled write cannot shed a conforming write of another kind.**
///
/// The budget is SHARED across every write endpoint, so a charge sized
/// to `PUT bin`'s worst case is taken out of the same pool a `PUT root`
/// and a `PUT hint` draw on. A handful of stalled bins therefore stop
/// this server writing anything at all — unauthenticated, repeatable,
/// and invisible to every row whose upload completes in one write.
///
/// The two kinds asserted here are the SMALL ones on purpose: a root is
/// 64 KiB at its cap and a hint is twenty octets, so a server that
/// refuses them while holding a few dozen bytes of somebody else's bin
/// is refusing on an accounting fiction rather than on load.
#[tokio::test]
async fn stalled_bins_cannot_shed_a_conforming_root_or_hint() {
    const STALLERS: usize = 3;

    let server = Loopback::start_with_budget(BIN_MAX_BYTES).await;
    let budget = server.service.write_budget();

    let (release, parked) = watch::channel(false);
    let sent = Arc::new(AtomicUsize::new(0));
    let stalled = park_uploads(&server, STALLERS, &parked, &sent).await;
    all_on_the_wire(&sent, STALLERS).await;
    charged_exactly(
        budget,
        WRITE_BUDGET_GRANULE_BYTES * u64::try_from(STALLERS).unwrap_or(u64::MAX),
    )
    .await;

    // A conforming root, WHILE the bins are stalled.
    let mut client = server.h1().await;
    let root = client
        .request(
            &h1(
                "PUT",
                format!("/volume/{VOLUME}/root/{}", format_hint_body(881)).as_bytes(),
                &[],
                Some(b"a root nobody parses"),
            ),
            true,
        )
        .await;
    assert_eq!(
        (root.status, root.token()),
        (201, None),
        "a 20-octet root was shed while {STALLERS} stalled bins held the \
         budget: the charge is the kind's worst case, not what arrived"
    );

    // And a hint, which is twenty octets and has no smaller form.
    let mut client = server.h1().await;
    let hint = client
        .request(
            &h1(
                "PUT",
                format!("/volume/{VOLUME}/hint").as_bytes(),
                &[],
                Some(b"00000000000000000881"),
            ),
            false,
        )
        .await;
    assert_eq!(
        (hint.status, hint.token()),
        (204, None),
        "a 20-octet hint was shed while {STALLERS} stalled bins held the budget"
    );

    let _observed = release.send(true);
    for (which, handle) in stalled.into_iter().enumerate() {
        let answered = handle
            .await
            .unwrap_or_else(|e| panic!("stalled {which}: {e}"));
        let (status, token) = answered
            .unwrap_or_else(|| panic!("stalled {which} was never answered inside {GENEROUS:?}"));
        assert_eq!((status, token.as_deref()), (201, None), "stalled {which}");
    }
    assert_eq!(budget.in_flight(), 0, "park-proof");
}

/// **A write queued behind an exhausted verify permit is SHED, not
/// parked.**
///
/// The permit is deliberately smaller than the connection count, so a
/// server whose permits are all held is a server that will make the next
/// write wait — and an acquire with no bound makes it wait for as long as
/// the queue ahead of it takes. The bytes it already read stay charged
/// for the whole of that wait, its connection stays resident, and nothing
/// tells the client to come back later.
///
/// The permit is held from the OUTSIDE, through the same `Arc` every
/// connection acquires from, so the contention is deterministic rather
/// than a storm timed to collide.
#[tokio::test]
async fn a_write_queued_behind_an_exhausted_verify_permit_is_shed() {
    let server = Loopback::start_with_permit_wait(IMPATIENT).await;
    let permits = verify_permits(TEST_WORKER_THREADS);
    assert_eq!(permits, 1, "one permit: holding it exhausts them all");

    let held = server
        .service
        .verify_permits_handle()
        .acquire()
        .await
        .unwrap_or_else(|e| panic!("holding the only permit: {e}"));
    assert_eq!(server.service.verify_permits_available(), 0);

    let body = valid_bin();
    let target = target_for(&body);
    let mut client = server.h1().await;
    client
        .send(&h1("PUT", target.as_bytes(), &[], Some(&body)))
        .await;
    // Comfortably past the bound and far short of a wait that would pass
    // by ACCIDENT: an acquire with no bound never answers at all.
    let within = IMPATIENT.saturating_mul(8);
    let shed = client.reply_within(within, true).await.unwrap_or_else(|| {
        panic!(
            "no answer within {within:?} to a write whose verify permit is \
             held: the acquire has no bound, so the request holds its bytes \
             and its connection for as long as the queue ahead of it"
        )
    });
    assert_eq!(
        (shed.status, shed.token()),
        (503, Some("unavailable")),
        "§5.10: a queue this server will not join is load, and load is \
         `unavailable`"
    );
    assert_eq!(
        server.service.write_budget().in_flight(),
        0,
        "the shed released every byte it had charged"
    );

    // Released — and the same write now succeeds, so the shed above was
    // the permit and not the request.
    drop(held);
    let mut client = server.h1().await;
    let created = client
        .request(&h1("PUT", target.as_bytes(), &[], Some(&body)), true)
        .await;
    assert_eq!((created.status, created.token()), (201, None));
    assert_eq!(server.service.write_budget().in_flight(), 0);
}

// =========================================== read-response bounds

/// **The read charge is HELD while a peer refuses to
/// read, and the connection lifetime is what gives it back.**
///
/// This is the row the whole decision turns on. The byte charge and the
/// hold bound are separately tested and separately meaningless: a charge
/// with no bound on how long it may be held converts a crash a supervisor
/// heals into a permanent `503`, and a lifetime bound with no charge
/// bounds nothing anybody was counting. Only running them together, over
/// a real TLS connection, against a client that stops reading, says
/// whether the pair bounds retained bytes and releases them when the lifetime expires.
///
/// **The stall is HTTP/2 flow control and not a trick.** The client's
/// initial window is 64 KiB and it never calls `release_capacity`, so a
/// 256 KiB response cannot be written; the server holds the buffer, and
/// hyper's `PipeToSendStream` holds a clone of the very `Bytes` the
/// charge rides in. Nothing in the transport envelope ends this: hyper
/// schedules its keep-alive PING from the last frame READ, so a peer in
/// this state looks healthy for as long as it cares to stay there.
///
/// **The park proof is the first assertion, and it is the one that makes
/// the second mean anything.** A budget reading zero at the end is
/// equally consistent with a charge that was never taken, a response that
/// was never produced, and a request that never reached the store. The
/// first assertion says the process was genuinely holding a quarter of a
/// megabyte it could not send at the moment the clock was running.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_reader_gives_the_read_charge_back_at_the_lifetime_bound() {
    /// Comfortably past the h2 initial window (65 535), so the response
    /// CANNOT be written to a client that never opens it.
    const WIDE_BIN: usize = 256 * 1024;
    let lifetime = Duration::from_secs(3);

    let server = Loopback::start_with_lifetime(lifetime).await;
    let bin = vec![0x71_u8; WIDE_BIN];
    let target = target_for(&bin);
    let digest = *GrainId::of(&bin).digest();
    assert!(
        server.store.put_bin(&digest, bin).await.is_ok(),
        "planting the wide bin"
    );
    assert_eq!(server.service.read_budget().in_flight(), 0);

    let mut client = server.h2().await;
    let (response, _send) = client
        .open("GET", &target, &[("range", "bytes=0-262143")], true)
        .await;
    let response = match timeout(GENEROUS, response).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => panic!("h2 response: {error}"),
        Err(elapsed) => panic!("no h2 response within {GENEROUS:?} ({elapsed})"),
    };
    assert_eq!(response.status().as_u16(), 206);
    // HELD, and never read from. Dropping this would make h2 release the
    // stream's capacity and let the server finish writing, which is the
    // opposite of the condition under test.
    let (_parts, _never_read) = response.into_parts();

    // THE PARK PROOF. The charge is taken before the response head is
    // rendered, so it exists by now; what this asserts is that it is
    // still held — the transport could not drain it, and nothing gave it
    // back.
    assert_eq!(
        server.service.read_budget().in_flight(),
        WIDE_BIN as u64,
        "the stalled reader is not holding the WHOLE extent: this row is \
         measuring a response that was already written rather than a \
         hostage one, or a charge that is not the buffer's size"
    );

    // Past the bound. The peer is doing nothing wrong that any other
    // clock in the envelope can see.
    pause(lifetime + BRIEF + BRIEF).await;
    assert_eq!(
        server.service.read_budget().in_flight(),
        0,
        "the charge was held past the connection lifetime: a full read \
         budget would be a permanent 503 sustained by idle streams, which \
         is strictly worse than not having one"
    );
}

/// **The charge comes back on a healthy read, over the wire.**
///
/// The control for the row above, and it fails on a different defect: a
/// charge that leaked on the ORDINARY path would make the budget a
/// countdown to a server that refuses every read, and the lifetime bound
/// would hide it for five minutes at a time rather than fix it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_completed_read_gives_its_charge_back() {
    let server = Loopback::start().await;
    let mut client = server.h2().await;
    assert_eq!(server.service.read_budget().in_flight(), 0);

    for _ in 0..4 {
        let reply = client
            .request("GET", &bin_target(), &[("range", "bytes=0-99")])
            .await;
        assert_eq!(reply.status, 206);
        assert_eq!(reply.body.len(), 100);
    }
    // The bodies are collected and dropped by `collect`, so every charge
    // has been given back by the time the last reply lands.
    assert_eq!(
        server.service.read_budget().in_flight(),
        0,
        "a served read must credit the budget"
    );
    assert_eq!(
        server.service.read_permits_available(),
        READ_PERMITS,
        "and must give its read permit back"
    );
}
