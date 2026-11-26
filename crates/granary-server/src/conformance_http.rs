// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Conformance over HTTP: the SHIPPED [`GrainService`] answering a
//! `granary-client` [`HttpStore`] over a real TLS loopback.
//!
//! **This is the first time the two halves of the protocol meet.** Every
//! other suite drives one side against a fixture the same side wrote: the
//! loopback battery sends request bytes it composed by hand, and
//! granary-client's own tests answer its requests from a stub server. A
//! divergence between what the server emits and what the client believes
//! it emits is invisible to both — each stays self-consistent — and it
//! surfaces here and nowhere else.
//!
//! **What crosses is the SHARED conformance body, not a script written
//! for this file.** `granary_core::testkit::{binstore_conformance,
//! rootstore_conformance}` are the same two bodies the in-core fakes, the
//! simulator's store, `granary-store`'s `object_store` adapter and this
//! crate's [`FakeSeam`] all run. Running them against [`HttpStore`] asks
//! the one question none of those runs can: does the seam still mean the
//! same thing after nine operations have been rendered to HTTP, refused
//! or served by the shipped policy layer, and mapped back?
//!
//! **Why the run lives in the AGPL crate**.
//! `scripts/check-licence-boundary.sh` check 2 fails when any manifest but
//! this crate's own names `granary-server` outside a comment —
//! `[dev-dependencies]` and a `package =` rename included — so a run in
//! granary-client that reached for the server is not a style choice that
//! was rejected, it is a build that does not pass the gate. The edge runs
//! AGPL test target → Apache library, which is the direction the boundary
//! permits, and it adds no package to the lock.
//!
//! **The server is SEAM-ONLY for the two conformance bodies, and it has
//! to be** (§13.5). `binstore_conformance` opens by storing a 100-byte
//! object that is not a decodable bin and requiring `Ok(true)`; the
//! shipped verifying profile answers that request `400` +
//! `verify-failed`, which is §13.4's own two-profile row. The seam-only
//! policy comes through `GrainService::for_test`, the ONE `#[cfg(test)]`
//! door, which a `cargo build` of the binary does not compile.
//!
//! **BOTH halves of that row RUN, against servers.** The seam-only half
//! is the opener's `201` in the binstore row; the verifying half is the
//! SAME bytes PUT to the shipped `GrainService::new` server in the
//! extent row, answered `400`. A row that ran one direction and
//! substituted a local `verify_bin` call for the other would be
//! asserting the primitive, not the profile — §13.4's mechanism is that
//! the request is sent EITHER WAY and both answers are positive
//! obligations on the same bytes.
//!
//! **The §13.4 extent rows go the other way: both servers VERIFY, and
//! only the declared maximum extent moves.** The enforcing arm is the
//! SHIPPED constructor — `GrainService::new` hardcodes the declaration —
//! so that half of the table is evidence about the server that ships,
//! and only the non-enforcing arm needs the test door.
//!
//! **`#[tokio::test]` and not `seam_drivable`'s `block_on`.** That
//! executor is a noop-waker loop that panics on the first `Pending`, and
//! every await here is a real socket.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use granary_client::{AmbientNetwork, HttpStore};
use granary_core::binstore::BinStore;
use granary_core::hash::GrainId;
use granary_core::rootstore::{HintRead, RootStore, RootStoreError};
use granary_net::accept::{AcceptConfig, ShutdownOutcome, serve};
use granary_net::alpn::{ALPN_H2, ALPN_HTTP11, GRANARY_ALPN};
use granary_net::config::render_tls_pin;
use granary_net::pin::{PinnedServerVerifier, SpkiPin, spki_digest};
use granary_net::tls::{ClientAuth, client_tls_config, server_tls_config};
use granary_store::verify::verify_bin;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::adapter::{
    GrainService, READ_BODY_BUDGET_BYTES, TEST_WORKER_THREADS, VERIFY_PERMIT_MAX_WAIT,
    WRITE_BODY_BUDGET_BYTES,
};
use crate::admission::{DECLARED_MAX_EXTENT, INGEST_UNPACKED_SUM_MAX};
use crate::fake::FakeSeam;
use crate::loopback::{HOST, client_config, mint, spawn};
use crate::policy::VerifyPolicy;

/// Part I's configured `{base}` (§4.1): none.
const BASE: &str = "";

/// The bound on a POSITIVE arm — every wait here is sub-second on an idle
/// machine and the margin is for macOS scheduling jitter.
const GENEROUS: Duration = Duration::from_secs(30);

/// The 100-byte object §13.4's extent rows are written against.
fn stored_bin() -> Vec<u8> {
    vec![0x5a_u8; 100]
}

/// The body `binstore_conformance` opens with, spelled here so this file
/// can assert what it IS as well as what the server did with it.
fn conformance_opener() -> Vec<u8> {
    (0..100u8).collect()
}

/// An object planted STRAIGHT INTO the server's store, for the read half
/// of the binstore row — bytes no client in this file ever writes.
///
/// **The content is prose and not a ramp, so an INTERIOR window names
/// its own offset.** [`conformance_opener`]'s `0..100` makes every
/// window look like every other window shifted, and a server that
/// answered a fixed slice would satisfy a read of it somewhere; the five
/// bytes at offset 10 here are `anted`, which occurs at no other offset
/// in this object and in no other fixture this file has.
fn planted_bin() -> Vec<u8> {
    b"granary planted object: bytes the client never wrote".to_vec()
}

/// The volume the PLANTED values live under.
///
/// **A name no conformance body publishes to and no other row here
/// spells.** The shared bodies use `vol-conf`/`vol-other` and the
/// `root-conf-*` family; a server answering these endpoints from a buffer
/// keyed on the fixture volume therefore has nothing at all to answer
/// with here, which is the entire discrimination. DNS-1123-legal, so the
/// volume guard is not what refuses it.
const PLANTED_VOLUME: &str = "planted-read-vol";

/// The seq the planted root lives at — outside every fixture's range
/// (the bodies use 1, 2, 5, 9, 10, `u64::MAX - 1` and `u64::MAX`), so a
/// collision cannot be what makes a read succeed.
const PLANTED_SEQ: u64 = 4_242;

/// The seq the planted HINT names, and it is deliberately NOT
/// [`PLANTED_SEQ`].
///
/// A stale hint is a designed state, so a hint below the head is legal —
/// and it is the one value that separates "the server read the hint
/// object" from "the server answered the hint out of `max_seq`", or out
/// of anything else it already knew.
const PLANTED_HINT_SEQ: u64 = 907;

/// A root planted STRAIGHT INTO the server's store, for the read half of
/// the rootstore row — bytes no client in this file ever writes.
///
/// Not a decodable root and it does not need to be: §5.6 has the server
/// serve root bytes opaquely, and the shared body's own roots are
/// `vec![0xD0]`.
fn planted_root() -> Vec<u8> {
    b"granary planted root: bytes the client never wrote".to_vec()
}

/// The meta-object twin of [`planted_bin`], for `GET meta`'s read half.
fn planted_meta() -> Vec<u8> {
    b"granary planted meta: bytes the client never wrote".to_vec()
}

// ------------------------------------------------------------- the legs

/// Which ALPN token the server OFFERS, and therefore which HTTP version
/// the round trip runs on.
///
/// **The leg is the SERVER's to choose, because the client's offer is not
/// a knob.** [`HttpStore`] builds one connector with `enable_http1()` and
/// `enable_http2()` and always offers `{h2, http/1.1}` — that is
/// the client's mandatory protocol baseline and it is deliberately not
/// configurable. rustls resolves ALPN by the SERVER's preference order,
/// so restricting the server's offer to one token is the only thing that
/// moves negotiation, and it is exactly what a deployment behind an
/// HTTP/1.1-only intermediary looks like to this client.
#[derive(Clone, Copy, Debug)]
enum Leg {
    Http1,
    H2,
}

/// Both legs, so a `for` loop cannot silently run one.
const LEGS: [Leg; 2] = [Leg::Http1, Leg::H2];

impl Leg {
    fn token(self) -> &'static [u8] {
        match self {
            Self::Http1 => ALPN_HTTP11,
            Self::H2 => ALPN_H2,
        }
    }

    /// The token this leg is NOT, so a row can show the server refuses
    /// it. Without that, restricting the offer could be a no-op and both
    /// iterations of every loop below would run the same protocol —
    /// a two-leg claim satisfied by one leg twice.
    fn other(self) -> &'static [u8] {
        match self {
            Self::Http1 => ALPN_H2,
            Self::H2 => ALPN_HTTP11,
        }
    }
}

// ---------------------------------------------------------- the server

/// A running [`serve`] over a real loopback TCP listener, with the fake
/// store it answers from and the SPKI pin a client must present.
struct Server {
    addr: SocketAddr,
    /// `spki_digest` of the leaf this server presents — the ONLY thing
    /// that authenticates it. No name is matched and the Web
    /// PKI plays no part, which is why the base URL below may be a bare
    /// address.
    pin: SpkiPin,
    /// The CA that signed the leaf, so a row can open a RAW connection
    /// beside the client's — the only way to observe what ALPN actually
    /// negotiated, which `HttpStore` does not report.
    ca: CertificateDer<'static>,
    /// The store the server answers from, held so a row can read it
    /// through the SEAM after the client has written through the wire —
    /// which is the difference between "the client agreed with itself"
    /// and "the bytes arrived".
    store: Arc<FakeSeam>,
    shutdown: watch::Sender<bool>,
    /// `Option` so [`Server::shutdown`] can take the handle and AWAIT it
    /// while [`Drop`] stays available as the backstop.
    ///
    /// **[`Drop`]'s abort is UNEXERCISED on the green path, and saying so
    /// is more useful than implying otherwise.** Every row below calls
    /// [`Server::shutdown`], which `take()`s the handle, so by the time
    /// `drop` runs there is nothing left to abort — the branch runs only
    /// for a row that PANICS before its shutdown, and nothing asserts
    /// that it does. Nor is nextest's leak detector the corroboration it
    /// might look like: it reports zero leaks with this `impl` gutted AND
    /// the drain assertions deleted, so it cannot distinguish the two.
    /// The [`ShutdownOutcome::Drained`] assertion that closes every row
    /// is the entire proof of the exit path.
    served: Option<JoinHandle<std::io::Result<ShutdownOutcome>>>,
}

impl Server {
    /// §13.5's SEAM-ONLY profile, through the one `#[cfg(test)]` door,
    /// under the SHIPPED declared extent.
    ///
    /// The shared conformance bodies require this profile and §13.4 says
    /// why: their first `put_bin` stores a 100-byte non-bin and demands
    /// `Ok(true)`, which the verifying profile answers `400` +
    /// `verify-failed`.
    async fn seam_only(leg: Leg) -> Self {
        Self::bind(leg, |store| {
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

    /// §7.1's ENFORCING profile — and it is the SHIPPED constructor, so
    /// this half of §13.4's extent table needs no test door at all.
    async fn enforcing(leg: Leg) -> Self {
        Self::bind(leg, |store| {
            GrainService::new(store, BASE, TEST_WORKER_THREADS)
        })
        .await
    }

    /// §7.1's NON-ENFORCING profile: a server that declares no maximum
    /// extent. Everything else is the shipped configuration, verification
    /// included.
    async fn non_enforcing(leg: Leg) -> Self {
        Self::bind(leg, |store| {
            GrainService::for_test(
                store,
                BASE,
                VerifyPolicy::verifying(),
                None,
                WRITE_BODY_BUDGET_BYTES,
                READ_BODY_BUDGET_BYTES,
                VERIFY_PERMIT_MAX_WAIT,
                None,
            )
        })
        .await
    }

    async fn bind<F>(leg: Leg, build: F) -> Self
    where
        F: FnOnce(Arc<FakeSeam>) -> GrainService<FakeSeam>,
    {
        let certs = mint();
        let pin = spki_digest(&certs.leaf).unwrap_or_else(|e| panic!("spki digest: {e}"));
        let mut tls = server_tls_config(vec![certs.leaf.clone()], certs.key, ClientAuth::None)
            .unwrap_or_else(|e| panic!("server tls config: {e}"));
        // The SHIPPED configuration is what `server_tls_config` built;
        // the one field this narrows is the ALPN offer, and the token it
        // narrows to is drawn from the shipped list rather than spelled
        // again here — so a change to `GRANARY_ALPN` cannot leave this
        // file negotiating a protocol the server no longer offers.
        assert!(
            GRANARY_ALPN.contains(&leg.token()),
            "{leg:?} is not a token the shipped server offers"
        );
        tls.alpn_protocols = vec![leg.token().to_vec()];
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local addr: {e}"));
        let store = Arc::new(FakeSeam::default());
        let service = build(Arc::clone(&store));
        let (shutdown, rx) = watch::channel(false);
        let served = spawn(serve(
            listener,
            Arc::new(tls),
            service,
            rx,
            AcceptConfig::default(),
        ));
        Self {
            addr,
            pin,
            ca: certs.ca,
            store,
            shutdown,
            served: Some(served),
        }
    }

    /// A client pinned to THIS server.
    ///
    /// The base is `https://127.0.0.1:{port}` and the leaf carries a
    /// `127.0.0.1` SAN, so nothing about the name has to be arranged on
    /// either side — the pin is what authenticates, and `HttpStore`
    /// installs a verifier that matches no name at all.
    fn client(&self) -> HttpStore {
        self.client_pinned_to(self.pin)
    }

    fn client_pinned_to(&self, pin: SpkiPin) -> HttpStore {
        HttpStore::new(
            &format!("https://{}", self.addr),
            vec![pin],
            &AmbientNetwork,
        )
        .unwrap_or_else(|e| panic!("http store: {e}"))
    }

    /// The TLS error a client offering ONLY `alpn` gets.
    ///
    /// **This is what makes the leg real.** `HttpStore` offers `{h2,
    /// http/1.1}` on every connection and reports which one it got to
    /// nobody, so a `Leg` that failed to narrow the server's offer would
    /// leave both iterations negotiating the same protocol with every
    /// assertion still green. A client offering only the other token
    /// completing a handshake is exactly that failure, and this is where
    /// it shows up.
    async fn refuses_alpn(&self, alpn: &[u8]) -> String {
        let tcp = TcpStream::connect(self.addr)
            .await
            .unwrap_or_else(|e| panic!("tcp: {e}"));
        let name = ServerName::try_from(HOST).unwrap_or_else(|e| panic!("server name: {e}"));
        match TlsConnector::from(Arc::new(client_config(&self.ca, alpn)))
            .connect(name, tcp)
            .await
        {
            Ok(_stream) => panic!(
                "the server completed a handshake with a client offering only {}, so its ALPN \
                 offer was NOT narrowed and this run's two legs are one leg twice",
                String::from_utf8_lossy(alpn)
            ),
            Err(error) => error.to_string(),
        }
    }

    /// The TLS error a client PINNED TO `pin` gets from this server.
    ///
    /// This connects through [`PinnedServerVerifier`] with the supplied
    /// pin and observes the TLS handshake error directly, below the
    /// `HttpStore` transport-error rendering.
    ///
    /// `alpn` is a token this server OFFERS, so negotiation cannot be
    /// what fails and the certificate is the only thing left to fail on.
    async fn refuses_pin(&self, pin: SpkiPin, alpn: &[u8]) -> String {
        let tcp = TcpStream::connect(self.addr)
            .await
            .unwrap_or_else(|e| panic!("tcp: {e}"));
        let name = ServerName::try_from(HOST).unwrap_or_else(|e| panic!("server name: {e}"));
        let verifier =
            PinnedServerVerifier::new(vec![pin], Arc::new(granary_net::crypto_provider()))
                .unwrap_or_else(|e| panic!("pin set: {e}"));
        let mut config = client_tls_config(Arc::new(verifier), None)
            .unwrap_or_else(|e| panic!("client tls: {e}"));
        config.alpn_protocols = vec![alpn.to_vec()];
        match TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
        {
            Ok(_stream) => panic!(
                "the server completed a handshake with a client pinned to a certificate it does \
                 NOT hold, so the SPKI pin is not what authenticates it"
            ),
            Err(error) => error.to_string(),
        }
    }

    /// Signal the drain and AWAIT it, so a row can assert the accept task
    /// ended rather than assuming it did.
    async fn shutdown(&mut self) -> ShutdownOutcome {
        let _observed = self.shutdown.send(true);
        let Some(handle) = self.served.take() else {
            panic!("shutdown called twice");
        };
        timeout(GENEROUS, handle)
            .await
            .unwrap_or_else(|_| panic!("the accept task did not finish inside {GENEROUS:?}"))
            .unwrap_or_else(|e| panic!("the accept task panicked: {e}"))
            .unwrap_or_else(|e| panic!("serve failed: {e}"))
    }
}

impl Drop for Server {
    /// The backstop for a row that panics before its shutdown. See
    /// [`Server::served`] for why nothing here is exercised green.
    fn drop(&mut self) {
        let _observed = self.shutdown.send(true);
        if let Some(handle) = self.served.take() {
            handle.abort();
        }
    }
}

/// A seam answer that is a REFUSAL carrying `status`.
///
/// [`HttpStore`] maps every status outside an endpoint's own table to
/// [`RootStoreError::UnexpectedStatus`], carrying the number it saw (§8.1's
/// totality rule). So this is how a `400` is told from the `404` that is
/// `NotFound` — which is exactly the discrimination §13.4's extent table
/// turns on.
///
/// **What this CANNOT assert, and why that is structural rather than an
/// omission (§5.2/§8.1).** §13.4's rows 2 and 3 require `400` AND the
/// `extent-too-wide` token; only the status is here. Those rows are
/// `GET`s, and `HttpStore` maps a `GET`'s off-table status through its
/// `unmapped` arm, which records the NUMBER and discards the rest — so
/// that token never reaches a seam caller, and no assertion written at
/// this seam can reach it however it is phrased. The token is pinned where it IS observable: `admission.rs`
/// decides `400` + `extent-too-wide` at the source, and `loopback.rs`
/// asserts the pair on the wire. What this row adds is the half the
/// client can see — that the `400` is told apart from the `404` row 4
/// requires, which is the discrimination §8.1 turns on.
fn refused_with<T: std::fmt::Debug>(got: &Result<T, RootStoreError>, status: u16, why: &str) {
    match got {
        Err(RootStoreError::UnexpectedStatus { status: seen, .. }) if *seen == status => {}
        other => {
            panic!("{why}: want a seam unexpected-status error naming {status}, got {other:?}")
        }
    }
}

/// A seam call a WRONG pin refused — on the transport, and SAYING SO.
///
/// **`transport:` alone is not the assertion.** A bare transport failure
/// for a pin mismatch —
/// `gran cat: remote: object store: transport: client error (Connect)`, as
/// measured — was byte-identical to what a CORRECTLY pinned client aimed at
/// a dead port produced, naming no pin, no certificate and no store the
/// caller had. So this requires the pin diagnosis as well as the
/// fail-closed refusal, and it is asserted HERE because this file is the
/// only place a wrong pin meets the SHIPPED server rather than a stub.
///
/// The pin asserted is the one the client was CONFIGURED with, so a
/// message that named some other pin — the server's, a constant — fails
/// this as surely as one that named none.
///
/// **What it deliberately does NOT assert is where the pin came from.**
/// `HttpStore` is handed a `Vec<SpkiPin>` and knows nothing about the flag or
/// variable behind it, so any source it named would be a guess — and
/// `GRANARY_TLS_PINS`, the obvious one, is a variable `gran cat` does not even
/// read. The client-side row
/// `the_pin_message_names_the_value_and_never_claims_a_provenance` is the one
/// that forbids the guess; this row pins the value.
fn refused_for_the_wrong_pin<T: std::fmt::Debug>(
    got: &Result<T, RootStoreError>,
    stranger: SpkiPin,
    leg: Leg,
) {
    let want = render_tls_pin(&stranger);
    match got {
        Err(RootStoreError::Backend(text))
            if text.starts_with("transport:")
                && text.contains("pin mismatch")
                && text.contains(&want) => {}
        other => panic!(
            "{leg:?}: a WRONG pin must fail on the transport AND say so, naming the \
             configured pin {want}, got {other:?}"
        ),
    }
}

// ============================================================== the rows

/// `BinStore` over HTTP satisfies the SHARED conformance body.
///
/// **The suite runs against the SEAM-ONLY profile, and that is a fact
/// this row proves rather than declares.** Its very first operation
/// stores [`conformance_opener`] — 100 bytes that are not a decodable
/// bin — under its own digest and requires `Ok(true)`. The assertion
/// below shows the shipped verify primitive REFUSES those bytes, so a
/// server that answered `201` to them cannot have been verifying: there
/// is no third possibility in which the fixtures merely happened to
/// satisfy a verifier (§13.4, §13.5). The other direction of that row —
/// a VERIFYING server answering these same bytes `400` — is asserted
/// against a real server in
/// [`the_section_13_4_extent_rows_hold_over_http_under_both_profiles`],
/// so the two-profile claim never rests on the local call alone.
///
/// **And the READ half is proved at the end rather than assumed.** Every
/// read the shared body performs is against bytes the same body just
/// wrote through the same client, and the seam read-back below goes
/// through [`FakeSeam`] — so between them they pin the WRITE crossing,
/// not the READ. A server answering `GET bin` from a canned buffer keyed
/// on the fixture digests satisfies every one of them. The planted
/// object at the end is what does not survive that.
#[tokio::test]
async fn the_http_store_passes_the_shared_binstore_conformance_suite() {
    let opener = conformance_opener();
    let digest = *GrainId::of(&opener).digest();
    assert!(
        verify_bin(&opener, INGEST_UNPACKED_SUM_MAX).is_err(),
        "the suite's opening object must be one a VERIFYING server refuses, or `seam_only` below \
         is decoration and this run says nothing about §13.5"
    );

    for leg in LEGS {
        let mut server = Server::seam_only(leg).await;
        assert_eq!(
            server.store.objects(),
            0,
            "{leg:?}: the shared bodies are documented to take an EMPTY store"
        );

        // The leg is REAL: a client offering only the other token gets
        // no handshake at all, so the two iterations of this loop are two
        // protocols and not one twice.
        let alpn_refusal = server.refuses_alpn(leg.other()).await;
        assert!(
            alpn_refusal.contains("NoApplicationProtocol"),
            "{leg:?}: want the RFC 7301 alert, got {alpn_refusal:?}"
        );

        // THE NEGATIVE CONTROL, before the suite. Without it, every
        // assertion below is satisfied by a client that never opened a
        // connection at all — and this is also the whole of the server's
        // authentication, so a run that never showed a wrong
        // pin being refused has not shown the pin is consulted.
        let stranger = spki_digest(&mint().leaf).unwrap_or_else(|e| panic!("stranger pin: {e}"));
        assert_ne!(stranger, server.pin, "the stranger's pin must differ");
        // NAMED first, then mapped. The raw connection runs the very
        // verifier `HttpStore::new` installs, so its alert says the PIN
        // is what rejected the server; the seam-level text below says
        // the same thing after `HttpStore` has read the chain,
        // and the two agreeing is what makes the diagnosis a
        // measurement rather than a rendering of a rendering.
        let pin_refusal = server.refuses_pin(stranger, leg.token()).await;
        assert!(
            pin_refusal.contains("ApplicationVerificationFailure"),
            "{leg:?}: want the pin verifier's own alert, got {pin_refusal:?}"
        );
        let refused = server
            .client_pinned_to(stranger)
            .get_bin_range(&digest, 0, 8)
            .await;
        refused_for_the_wrong_pin(&refused, stranger, leg);
        assert_eq!(
            server.store.objects(),
            0,
            "{leg:?}: a refused handshake reaches no store"
        );

        {
            let client = server.client();
            granary_core::testkit::binstore_conformance(&client).await;
        }

        // It crossed the WIRE. Read back through the SEAM — the store's
        // own method, not the client that wrote it — so a client
        // agreeing with itself cannot satisfy this.
        assert_eq!(
            server.store.get_bin_range(&digest, 0, 100).await,
            Ok(opener.clone()),
            "{leg:?}: the bytes must be in the SERVER's store — or `conformance_opener` has \
             drifted from `binstore_conformance`'s own opener"
        );
        assert_eq!(
            server.store.objects(),
            2,
            "{leg:?}: exactly what the body writes — one bin, one meta object under `vol-conf`; \
             the invalid-volume rows never reach a store because no target can be spelled for them"
        );
        // ---- the READ half, which nothing above reaches --------------
        //
        // Bytes the client NEVER WROTE, planted through the seam under a
        // digest no fixture in this file and no fixture in the shared
        // body produces — `Ok(true)` is the store itself reporting the
        // digest was novel, so a collision cannot go unnoticed. Read
        // back through the WIRE at an INTERIOR offset: a server serving
        // a canned buffer keyed on the fixture digests has nothing to
        // answer with, and one that ignores the offset or the length
        // answers a window that is not `anted`.
        let planted = planted_bin();
        let planted_digest = *GrainId::of(&planted).digest();
        assert_ne!(
            planted_digest, digest,
            "{leg:?}: the planted object must not be the suite's own"
        );
        assert_eq!(
            server.store.put_bin(&planted_digest, planted).await,
            Ok(true),
            "{leg:?}: the plant goes through the SEAM, so no handler and no client is involved \
             in arming it — and `true` is the store reporting the digest was novel"
        );
        assert_eq!(
            server.client().get_bin_range(&planted_digest, 10, 5).await,
            Ok(b"anted".to_vec()),
            "{leg:?}: the server must serve STORED bytes — these crossed the wire outbound only, \
             and the window is interior on both sides"
        );

        // `GET meta` is this seam's OTHER addressed read and the same
        // hole was open on it: every `get_meta` the shared body performs
        // is of bytes the same body just `put_meta`'d through the same
        // client, so a server answering `vol-conf` out of a buffer it
        // filled on the way in satisfies all of them. Planted under
        // [`PLANTED_VOLUME`], which that buffer has never heard of.
        let meta = planted_meta();
        let meta_id = GrainId::of(&meta);
        assert_eq!(
            server
                .store
                .put_meta(PLANTED_VOLUME, &meta_id, meta.clone())
                .await,
            Ok(true),
            "{leg:?}: the plant goes through the SEAM — and `true` is the store reporting the id \
             was novel, so a collision with a fixture cannot go unnoticed"
        );
        assert_eq!(
            server.client().get_meta(PLANTED_VOLUME, &meta_id).await,
            Ok(meta),
            "{leg:?}: `GET meta` must serve STORED bytes — nothing wrote these through the wire"
        );

        assert_eq!(
            server.shutdown().await,
            ShutdownOutcome::Drained,
            "{leg:?}: the accept task must DRAIN — a row that leaves it resident has proved \
             nothing about the exit path"
        );
    }
}

/// `RootStore` over HTTP satisfies the SHARED conformance body.
///
/// The seam-only profile again, and for the same reason the module doc
/// gives: both bodies run against one server shape so a divergence
/// cannot hide behind a difference in how they were stood up. Nothing
/// here PUTs a bin, so the policy is not what this row turns on — the
/// CAS semantics, the seq-0 rule and the hint's revalidation are.
#[tokio::test]
async fn the_http_store_passes_the_shared_rootstore_conformance_suite() {
    for leg in LEGS {
        let mut server = Server::seam_only(leg).await;
        assert_eq!(
            server.store.objects(),
            0,
            "{leg:?}: the shared bodies are documented to take an EMPTY store"
        );

        // The leg is REAL: a client offering only the other token gets
        // no handshake at all, so the two iterations of this loop are two
        // protocols and not one twice.
        let alpn_refusal = server.refuses_alpn(leg.other()).await;
        assert!(
            alpn_refusal.contains("NoApplicationProtocol"),
            "{leg:?}: want the RFC 7301 alert, got {alpn_refusal:?}"
        );

        // The same negative control, on this seam's own cheapest call.
        let stranger = spki_digest(&mint().leaf).unwrap_or_else(|e| panic!("stranger pin: {e}"));
        assert_ne!(stranger, server.pin, "the stranger's pin must differ");
        let pin_refusal = server.refuses_pin(stranger, leg.token()).await;
        assert!(
            pin_refusal.contains("ApplicationVerificationFailure"),
            "{leg:?}: want the pin verifier's own alert, got {pin_refusal:?}"
        );
        let refused = server
            .client_pinned_to(stranger)
            .max_seq("root-conf-cas")
            .await;
        refused_for_the_wrong_pin(&refused, stranger, leg);

        {
            let client = server.client();
            granary_core::testkit::rootstore_conformance(&client).await;
        }

        // It crossed the WIRE, read back through the SEAM: the CAS
        // winner's bytes, and a head that only the numeric maximum
        // produces — "10" sorts below "9" as text.
        assert_eq!(
            server.store.get_root("root-conf-cas", 1).await,
            Ok(Some(b"the root the first writer created".to_vec())),
            "{leg:?}: the winner's bytes must be in the SERVER's store"
        );
        assert_eq!(
            server.store.max_seq("root-conf-max").await,
            Ok(Some(10)),
            "{leg:?}: the roots the body published must really be there"
        );

        // ---- the READ half, which nothing above reaches --------------
        //
        // Everything so far proves the WRITE crossing and only that:
        // every read the shared body performs is of a value the SAME
        // body just wrote through the SAME client, and the two seam
        // read-backs above go the other way. A server that answered
        // `GET root`, `max-seq` and `GET hint` out of a buffer keyed on
        // the fixture volumes and seqs — filled as the client wrote —
        // satisfies every one of them.
        //
        // What does not survive that: values planted through the SEAM,
        // under a volume no body publishes to, read back THROUGH the
        // client. The hint names a DIFFERENT seq from the root, so a
        // server answering the hint from what it knows about roots is
        // caught too.
        let root = planted_root();
        assert_eq!(
            server
                .store
                .put_root(PLANTED_VOLUME, PLANTED_SEQ, root.clone())
                .await,
            Ok(()),
            "{leg:?}: the plant goes through the SEAM, so no handler and no client is involved \
             in arming it — and put-if-absent succeeding says the seq was free"
        );
        assert_eq!(
            server
                .store
                .write_hint(PLANTED_VOLUME, PLANTED_HINT_SEQ)
                .await,
            Ok(()),
            "{leg:?}: the hint is planted the same way"
        );

        let client = server.client();
        assert_eq!(
            client.get_root(PLANTED_VOLUME, PLANTED_SEQ).await,
            Ok(Some(root)),
            "{leg:?}: `GET root` must serve STORED bytes — nothing wrote these through the wire"
        );
        assert_eq!(
            client.max_seq(PLANTED_VOLUME).await,
            Ok(Some(PLANTED_SEQ)),
            "{leg:?}: `max-seq` must be computed over the STORE — this volume's only root \
             arrived through the seam"
        );
        match client.read_hint(PLANTED_VOLUME, None).await {
            Ok(HintRead::Current { seq, token }) => {
                assert_eq!(
                    seq, PLANTED_HINT_SEQ,
                    "{leg:?}: `GET hint` must serve the STORED hint — and this seq is not the \
                     volume's head, so a server deriving it from anything else is caught here"
                );
                assert!(
                    token.0.starts_with('"') && token.0.ends_with('"'),
                    "{leg:?}: §5.8 requires a strong entity-tag, got {token:?}"
                );
            }
            other => panic!(
                "{leg:?}: `GET hint` on a volume whose hint was planted through the seam must \
                 read Current; got {other:?}"
            ),
        }

        assert_eq!(
            server.shutdown().await,
            ShutdownOutcome::Drained,
            "{leg:?}: the accept task must DRAIN — a row that leaves it resident has proved \
             nothing about the exit path"
        );
    }
}

/// §13.4's declared-maximum-extent rows, over HTTP, under BOTH profiles.
///
/// **Both servers VERIFY and only the declaration moves**, so the
/// enforcing half runs against the SHIPPED constructor — `GrainService::new`
/// names `DECLARED_MAX_EXTENT` itself — and only the non-enforcing half
/// needs the `#[cfg(test)]` door.
///
/// **The enforcing arm also carries §13.4's two-profile PUT row**, in
/// the direction the conformance run cannot take. That row's mechanism
/// is that the SAME 100 non-bin bytes are sent to both profiles and both
/// answers are positive obligations: the seam-only server's `201` is
/// `binstore_conformance`'s opening operation, and the verifying
/// server's `400` is asserted here, against `GrainService::new`. It
/// costs no extra server — this arm already IS a verifying shipped one.
///
/// **Row 3 is the row the table exists for**, and it is the one that
/// fails if a single profile is stood up twice: the bin is really there
/// and the honest answer is 100 bytes, so an enforcing server refusing
/// the ASK and a non-enforcing server serving the ANSWER are two
/// positive obligations on identical bytes. Row 4 is the block's other
/// control — the boundary ask is admitted by both, and its `404` proves
/// the request passed the extent check and reached the store, which a
/// server that refused every range could never produce.
///
/// **§13.4's row 1 (`Range: bytes=0-`) is not expressible here, and that
/// is a property of the client rather than a gap.** The open-ended form
/// has no `RequestedExtent` to come out of — `HttpStore` renders exactly
/// one `bytes={first}-{last}` per ranged read — so no caller of the seam
/// can produce that request. The loopback battery sends it as raw bytes;
/// this file cannot, and a helper that could would be a second way to
/// spell a target.
#[tokio::test]
async fn the_section_13_4_extent_rows_hold_over_http_under_both_profiles() {
    let stored = stored_bin();
    let present = *GrainId::of(&stored).digest();
    let absent = *GrainId::of(b"a bin no server holds").digest();
    // §13.4's two-profile PUT row, the bytes half: the very object
    // `binstore_conformance` opens with, so the two profiles are asked
    // about ONE input and not about two that merely resemble each other.
    let opener_digest = *GrainId::of(&conformance_opener()).digest();
    // The mapped `len` of `bytes=0-{E}` is `E + 1` — one past the
    // declaration, which is what makes rows 2 and 3 over-wide.
    let over = DECLARED_MAX_EXTENT + 1;

    for leg in LEGS {
        // ---- enforcing, and it is the SHIPPED constructor ------------
        let mut enforcing = Server::enforcing(leg).await;
        let alpn_refusal = enforcing.refuses_alpn(leg.other()).await;
        assert!(
            alpn_refusal.contains("NoApplicationProtocol"),
            "{leg:?}: want the RFC 7301 alert, got {alpn_refusal:?}"
        );
        assert_eq!(
            enforcing.store.put_bin(&present, stored.clone()).await,
            Ok(true),
            "{leg:?}: the 100-byte bin is planted through the seam, so no ingest policy is \
             involved in arming rows 3"
        );
        {
            let client = enforcing.client();
            refused_with(
                &client.get_bin_range(&absent, 0, over).await,
                400,
                &format!("{leg:?}: enforcing row 2, an over-wide ask for an absent bin"),
            );
            refused_with(
                &client.get_bin_range(&present, 0, over).await,
                400,
                &format!(
                    "{leg:?}: enforcing row 3 — the bin IS there and the honest answer is 100 \
                     bytes; §7.1 refuses the ASK anyway"
                ),
            );
            // **Row 4's `Err(NotFound)` is the whole of what this seam
            // can say, and that is structural (§5.2/§8.1).** §13.4 requires
            // `404` + `not-found`; §5.2's bin-404 mapping deliberately
            // ignores the token, because `NotFound` means the same thing
            // whatever the server named it — so no caller of the seam
            // observes `not-found`, here or anywhere. `handlers.rs` pins
            // the pair at the source and `loopback.rs` pins it on the
            // wire. What the row adds is that the boundary ask PASSED
            // the extent gate and reached the store at all, which a
            // server refusing every range could not produce.
            assert_eq!(
                client.get_bin_range(&absent, 0, DECLARED_MAX_EXTENT).await,
                Err(RootStoreError::NotFound),
                "{leg:?}: enforcing row 4 — the boundary ask is admitted and reaches the store"
            );

            // **The one SUCCESSFUL round trip against the SHIPPED
            // constructor.** Every other client call in this file that
            // reaches `GrainService::new` is a refusal — 400, 400, 404,
            // 400 — and every success anywhere here goes through the
            // `#[cfg(test)]` `for_test` door. So a `GrainService::new`
            // that answered nothing correctly at all would satisfy the
            // file end to end, which for a suite whose entire claim is
            // "the client and the server meet over the wire" is the gap.
            // The bin is really there (planted through the seam above),
            // the ask is inside the declaration, and the answer must be
            // the stored bytes.
            assert_eq!(
                client.get_bin_range(&present, 0, 100).await,
                Ok(stored.clone()),
                "{leg:?}: the SHIPPED server must SERVE — this is the only successful \
                 client-to-server round trip in this file that does not go through the \
                 `#[cfg(test)]` door"
            );

            // §13.4's TWO-PROFILE PUT ROW, verifying half — the same
            // bytes `binstore_conformance` opens with, answered by the
            // SHIPPED constructor. Without this the claim "a verifying
            // server refuses them" rests on a local `verify_bin` call in
            // the binstore row, which is evidence about the primitive
            // and not about the server.
            refused_with(
                &client.put_bin(&opener_digest, conformance_opener()).await,
                400,
                &format!(
                    "{leg:?}: §13.4's two-profile PUT row — the VERIFYING server must refuse the \
                     100 non-bin bytes the seam-only server stores"
                ),
            );
        }
        assert_eq!(
            enforcing.store.objects(),
            1,
            "{leg:?}: only the planted bin — a refused PUT must not have stored anything"
        );
        assert_eq!(enforcing.shutdown().await, ShutdownOutcome::Drained);

        // ---- non-enforcing, through the one `#[cfg(test)]` door ------
        let mut non_enforcing = Server::non_enforcing(leg).await;
        assert_eq!(
            non_enforcing.store.put_bin(&present, stored.clone()).await,
            Ok(true)
        );
        {
            let client = non_enforcing.client();
            // The absent-bin rows here say `Err(NotFound)` and no more,
            // for the reason the enforcing row 4 above spells out: the
            // `404` + `not-found` pair is pinned at `handlers.rs` and at
            // the wire in `loopback.rs`, and the seam carries the status
            // as a variant with the token dropped (§5.2/§8.1).
            assert_eq!(
                client.get_bin_range(&absent, 0, over).await,
                Err(RootStoreError::NotFound),
                "{leg:?}: non-enforcing row 2 — no extent gate, so the ask reaches the store"
            );
            assert_eq!(
                client.get_bin_range(&present, 0, over).await,
                Ok(stored.clone()),
                "{leg:?}: non-enforcing row 3 — 100 bytes, the short read §7.2 licenses; this is \
                 the assertion that fails if both arms stand up the same profile"
            );
            assert_eq!(
                client.get_bin_range(&absent, 0, DECLARED_MAX_EXTENT).await,
                Err(RootStoreError::NotFound),
                "{leg:?}: non-enforcing row 4"
            );
        }
        assert_eq!(non_enforcing.shutdown().await, ShutdownOutcome::Drained);
    }
}

#[cfg(unix)]
mod intents;
