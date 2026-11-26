// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `RootStore + BinStore` over the grain protocol.
//!
//! **The whole point is that the client stops holding bucket
//! credentials**: the nine seam operations become nine HTTPS
//! requests to a server that is authenticated by SPKI pin and
//! nothing else. The Web PKI plays no part, no name is matched, and no
//! clock is read on the TLS path.
//!
//! **Response bytes are UNTRUSTED INPUT** and are treated that way even
//! though the connection is authenticated (§5a.2, §5a.3): TLS proves who
//! sent the bytes and proves nothing about what they are, and the bucket
//! behind a pinned server is not itself authenticated — an object planted
//! directly in it is inside the threat model. So every read here is
//! bounded by a COUNTING reader, no buffer is ever sized from a
//! peer-advertised length, and every ranged answer runs §7.2's extent gate
//! before a byte of it is used.
//!
//! **The status map is a function of (endpoint, status), never of status
//! alone** (§8.1). `404` carries four different meanings on this protocol
//! and three of them are successes, so each of those three additionally
//! requires `Granary-Error: not-found` before it is mapped that way — a
//! `404` from a reverse proxy, a captive portal, or the right server under
//! the wrong base path would otherwise be reported as "this volume has no
//! roots".
//!
//! **The error type is [`RootStoreError`], reused rather than mirrored.**
//! The seams return it, the shared conformance bodies assert its variants,
//! and a parallel enum would split the surface at the one boundary that
//! must not lose information. TLS and transport failures are
//! `Backend`; answers granary declines — over a cap, an extent the request
//! could not have produced — are `RefusedResponse`, because a transport
//! failure invites a retry while a response that violates its own extent
//! will violate it again. Construction is the exception, and gets
//! [`HttpStoreError`]: nothing has been asked of a store yet.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crate::credential::ClientCredential;
use crate::retry::{self, RetryClass};
use granary_core::binfmt::BIN_MAX_BYTES;
use granary_core::binstore::BinStore;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::netid::NetworkIdentity;
use granary_core::rootstore::{
    HintRead, HintToken, RefusalKind, RootStore, RootStoreError, SEQ_KEY_DIGITS, filter_above,
    format_hint_body, parse_hint_body,
};
use granary_net::pin::{PinSetError, PinnedServerVerifier, SpkiPin};
use granary_net::tls::client_tls_config;
use granary_store::bounds::{META_MAX_BYTES, ROOT_MAX_BYTES};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{
    CONTENT_RANGE, CONTENT_TYPE, ETAG, HeaderName, HeaderValue, IF_NONE_MATCH, RANGE,
};
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};

/// Application retry choices, independent of the connector's disabled retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetryPolicy {
    /// No second application attempt unless the first request was returned
    /// provably unsent.
    Never,
    /// Retry only a remote refused stream, whose request was not processed.
    CreateRoot,
    /// Retry a refused stream or a classified connection failure once for
    /// reads and idempotent writes (`put_bin`, `put_meta`, `put_hint`).
    Idempotent,
}
impl RetryPolicy {
    pub(crate) fn permits(self, class: RetryClass) -> bool {
        if class == RetryClass::Unsent {
            return true;
        }
        matches!(
            (self, class),
            (
                Self::CreateRoot | Self::Idempotent,
                RetryClass::StreamRefused
            ) | (Self::Idempotent, RetryClass::ConnectionFailed)
        )
    }
}

/// The `Granary-Error` field (§8.2). Lowercase because `HeaderName` is,
/// and the comparison happens on the parsed name rather than on text.
pub(crate) const GRANARY_ERROR: HeaderName = HeaderName::from_static("granary-error");

/// The `Granary-Request-Id` field (§9.1).
const GRANARY_REQUEST_ID: HeaderName = HeaderName::from_static("granary-request-id");

/// Maximum length of a `Granary-Request-Id` field value (§9.1).
const REQUEST_ID_MAX: usize = 64;

fn is_request_id_shaped(value: &str) -> bool {
    (1..=REQUEST_ID_MAX).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn insert_request_id(headers: &mut hyper::HeaderMap) {
    if let Some(op) = crate::observe::current_operation_id()
        && is_request_id_shaped(&op)
        && let Ok(value) = HeaderValue::from_str(&op)
    {
        headers.insert(GRANARY_REQUEST_ID, value);
    }
}

/// The one token that completes a success-`404` (§8.1, §8.2).
const TOKEN_NOT_FOUND: &str = "not-found";

/// How many links of a transport failure's `source()` chain are rendered
/// into the message.
///
/// **A bound and not a `while let`.** `Error::source` is a trait method
/// and its contract does not forbid a cycle, so an implementation
/// returning `Some(self)` would build a string forever on the one path a
/// caller reaches when something has already gone wrong. The measured
/// chains are two and three links (a wrong pin and a refused connection
/// respectively), so this is an order of margin over anything the
/// shipped connector produces, and truncating a pathological chain
/// costs a diagnostic rather than the process.
const CHAIN_MAX: usize = 16;

/// Render `error`'s whole `source()` chain onto the END of `text`, one
/// link's `Display` per step, bounded at [`CHAIN_MAX`] links — no prefix,
/// no pin sentence, and no allocation of its own: the caller owns the
/// buffer, and writes straight into whatever it already holds.
///
/// **An into-form and not a `-> String`, because [`HttpStore::transport_failure`]
/// already owns a buffer by the time it needs this.** A `-> String` here
/// would make every operator-facing message pay for a second allocation
/// and a copy on top of the one `transport_failure`'s own `"transport: "`
/// prefix already made — the chain is the expensive
/// part (up to [`CHAIN_MAX`] `Display` calls), the prefix is four bytes,
/// and neither caller has a reason to want them in separate strings.
///
/// Shared by [`HttpStore::transport_failure`] and `HttpStore::send`'s
/// retry diagnostic: the outer `Display` alone is exactly the
/// same string for three distinct causes, so it is insufficient — CLASS A's
/// own shapes render as the bare `"client error (SendRequest)"` — so
/// the first attempt's diagnostic-only typed debug event needs the
/// same chain a person reading the final error gets, not less.
fn render_chain_into(text: &mut String, error: &(dyn std::error::Error + 'static)) {
    use core::fmt::Write as _;

    let mut link = Some(error);
    for depth in 0..CHAIN_MAX {
        let Some(current) = link else { break };
        if depth > 0 {
            text.push_str(": ");
        }
        // Infallible on a String; discarded rather than unwrapped, the
        // way `Target::bin` discards its own.
        let _ = write!(text, "{current}");
        link = current.source();
    }
}

/// How long the TCP connect to `{base}` may take before this store gives
/// up on the peer.
///
/// **The bound the through-the-server route did not have.** `--direct-s3`
/// — the route this one REPLACED as the default — inherits
/// `object_store`'s clocks, five seconds of connect among them; making
/// the granary route the default therefore removed a bound that existed
/// rather than adding an unbounded path nobody had before. This restores
/// the connect half of it.
///
/// **What it covers and what it does not.** `HttpConnector`'s clock is
/// the TCP connect and nothing else: the peer that swallows the SYN, the
/// address that blackholes, the NAT binding that is gone. A peer that
/// completes TCP and then stalls the TLS handshake — or completes the
/// handshake and then says nothing — is NOT this constant's problem; it
/// is [`SEAM_DEADLINE_BASE`]'s, the per-call deadline that covers
/// everything from here to the end of the call.
///
/// **Ten seconds, twice the five the replaced route inherited.** A
/// connect to a reachable peer completes in one round trip; the budget
/// only has to cover a path bad enough to need SYN retransmits, and it is
/// spent once per publish here rather than once per request. What it must
/// never be is anything near the per-call deadline — see the `const _`
/// below.
///
/// **NOT a per-request timeout, deliberately.** The one-probe rule
/// (§5a.4) turns on `put_root` having no clock OF ITS OWN
/// TCP-CONNECT KIND — a `PUT root` cut off mid-connect is AMBIGUOUS in
/// exactly the way one cut off mid-call is, and the flow resolves the
/// ambiguity by probing rather than by guessing either way. This
/// constant staying connect-only rather than widening to cover the rest
/// of the call is what keeps that ambiguity confined to one clock
/// ([`SEAM_DEADLINE_BASE`]) instead of two ticking at different rates.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The connect clock has to be INSIDE the smallest per-call deadline,
/// gated at compile time.
///
/// At or above it the seam deadline always fires first, and the connect
/// timeout becomes configuration no run can reach — a bound that reads
/// as present and is not. `as_secs` is `const`, so the check costs a
/// build and nothing else.
const _: () = assert!(
    CONNECT_TIMEOUT.as_secs() < SEAM_DEADLINE_BASE.as_secs(),
    "CONNECT_TIMEOUT must be inside SEAM_DEADLINE_BASE, or the connect \
     clock is unreachable and a dead peer costs the whole per-call deadline"
);

/// The BASE of every seam call's size-scaled deadline: the
/// longest one seam call may run without EITHER completing or failing
/// before it is a wedged peer, cut. Scaled by `seam_deadline` for a
/// call whose transfer has a meaningful size; used unscaled (as the
/// deadline itself) for a call whose transfer does not — `max_seq`'s
/// listing, and every call whose own read cap or body is smaller than
/// one second's worth of [`SEAM_FLOOR_RATE_BYTES_PER_SEC`].
///
/// **REPLACES a fixed TOTAL over the whole flow, not a per-request
/// figure that existed before.** The seam carried no clock of its own
/// kind before this one, by design (§5a.4) — `crate::publish` wrapped
/// the WHOLE publish at 15 minutes and `crate::resolve` the whole
/// resolve at 1 hour, so a peer that answered every OTHER call and
/// wedged on exactly one still cost the caller the full total with the
/// probe unrun. The idle form bounds each call instead: a COMPLETED
/// call is progress, and an operation is a finite sequence of bounded
/// calls plus bounded local work, so a wedged peer is cut at its own
/// call rather than at the end of an arbitrary total.
///
/// **Forty-five seconds, derived — the slowest CONFORMING answer must
/// be received, not cut.** A conforming server may spend its full
/// store-dispatch budget — thirty seconds, §5.10's "refusing load"
/// figure (named, not imported: the client conforms to the protocol,
/// not to `granary-server`'s source) — before answering `503`, and
/// that `503` IS the congestion signal this crate types as
/// `Unavailable` so the fetcher's AIMD can react. A base at or under
/// that figure loses the race every time (this clock starts before
/// connect and covers both RTT halves), converting the shed signal
/// into a never-retry `Elapsed` at exactly the operating point the
/// signal exists for. So: 30 s dispatch + [`CONNECT_TIMEOUT`] (10 s,
/// a cold pool's worst case, spent inside this same clock) + 5 s of
/// path margin. For a wedged peer on a base-sized call that is 20 times
/// sooner than a 15-minute whole-flow total and 80 times sooner than a
/// 60-minute one; the floor rate below DELAYS that cut for large
/// transfers — past both totals for a maximal bin — and never removes it. For a
/// maximal bin (`granary_core::binfmt::BIN_MAX_BYTES`, 256 MiB) a
/// 15-minute total refuses anything below roughly 291 KiB/s, while this
/// deadline (45 s + 256 MiB at [`SEAM_FLOOR_RATE_BYTES_PER_SEC`], about
/// 4,141 s) admits it down to 64 KiB/s. A smaller call gets a
/// proportionally tighter deadline, so a slow SMALL transfer can be cut
/// sooner than a 15-minute total would cut it.
///
/// **What the scaled term does NOT override: the server's connection
/// lifetime.** A single transfer whose scaled deadline runs past
/// `CONNECTION_MAX_LIFETIME` (5 min) meets the server's transport-level
/// rotation first and surfaces as a transport reset: that wall is the
/// server's, independent of this deadline. The deadline here bounds the
/// WAIT; it does not
/// promise a connection outlives it. The `const _` below keeps the
/// BASE inside one connection life, which is the coupling that is this
/// clock's to keep.
pub const SEAM_DEADLINE_BASE: Duration = Duration::from_secs(45);

const fn seam_deadline_secs(transfer_size: u64) -> u64 {
    SEAM_DEADLINE_BASE.as_secs() + transfer_size / SEAM_FLOOR_RATE_BYTES_PER_SEC
}

const AUTHORITY_STATUS_MAX_BYTES: u64 = 0;
const AUTHORITY_PUBLISH_MAX_BYTES: u64 = ROOT_MAX_BYTES;
const AUTHORITY_PROBE_MAX_BYTES: u64 = ROOT_MAX_BYTES;
const AUTHORITY_INTENT_READBACK_MAX_BYTES: u64 = granary_core::intent::READBACK_MAX_BYTES as u64;
const AUTHORITY_DEADLINE_MAX_SECS: u64 = 61;
const GOAWAY_SETTLE_SECS: u64 = 10;

const _: () = assert!(
    SEAM_DEADLINE_BASE.as_secs() < granary_net::accept::CONNECTION_MAX_LIFETIME.as_secs(),
    "a base-sized seam call must fit inside one server connection life, \
     or every small call is cut by the rotation instead of its own clock"
);

const _: () = {
    assert!(seam_deadline_secs(AUTHORITY_STATUS_MAX_BYTES) <= AUTHORITY_DEADLINE_MAX_SECS);
    assert!(seam_deadline_secs(AUTHORITY_PUBLISH_MAX_BYTES) <= AUTHORITY_DEADLINE_MAX_SECS);
    assert!(seam_deadline_secs(AUTHORITY_PROBE_MAX_BYTES) <= AUTHORITY_DEADLINE_MAX_SECS);
    assert!(seam_deadline_secs(AUTHORITY_INTENT_READBACK_MAX_BYTES) == AUTHORITY_DEADLINE_MAX_SECS);
    assert!(
        AUTHORITY_DEADLINE_MAX_SECS + GOAWAY_SETTLE_SECS
            <= granary_net::accept::CONNECTION_DRAIN_GRACE.as_secs(),
        "61 s authority deadline plus 10 s settle must fit inside the 75 s connection drain grace"
    );
};

/// The floor sustained transfer rate a seam call's scaled deadline still
/// admits before treating it as a wedge rather than a slow honest
/// transfer.
///
/// **64 KiB/s, not derived from any measured link — a floor below which
/// nothing this filesystem is meant to serve runs today** (see
/// [`SEAM_DEADLINE_BASE`]'s own derivation for the comparison against the
/// total it replaces). A call legitimately slower than this either does
/// not exist in a working deployment or is itself the wedge this bound
/// exists to cut.
pub const SEAM_FLOOR_RATE_BYTES_PER_SEC: u64 = 64 * 1024;

/// One seam call's deadline: [`SEAM_DEADLINE_BASE`] plus `transfer_size`
/// scaled by [`SEAM_FLOOR_RATE_BYTES_PER_SEC`], integer seconds, FLOOR
/// division.
///
/// **Floor, not ceiling or round.** The base already dominates every
/// transfer this protocol caps (a maximal bin at the floor rate adds
/// under 4200 s to a 30 s base — see `SEAM_DEADLINE_BASE`'s own
/// derivation), so the fractional second a floor drops is never the
/// difference between a completed call and a cut one; rounding up would
/// cost nothing here and round down is the simpler operation `u64`
/// division already performs.
pub(crate) fn seam_deadline(transfer_size: u64) -> Duration {
    Duration::from_secs(seam_deadline_secs(transfer_size))
}

/// The client's explicit HTTP/2 per-STREAM receive window
/// is sized to [`granary_core::thresh::MAX_GRAIN`]
/// — the chunker's target grain — so no stream can hold more of the
/// connection window than one target grain's worth, and 64/2 = 32
/// streams fill the pipe at the fetch window. This is a FAIRNESS bound,
/// not a payload ceiling: a legal frame can exceed it (compressed
/// frames run to `FRAME_COMP_MAX`, ~8 MiB; meta reads to 16 MiB) and
/// then paces across `WINDOW_UPDATE` round trips as h2 replenishes the
/// window — slower, never stalled.
pub(crate) const H2_STREAM_WINDOW: u32 = 2 * 1024 * 1024;

/// The client's explicit HTTP/2 CONNECTION receive window.
/// Sized to [`crate::fetcher::FETCH_INFLIGHT_BYTES`] so the
/// transport itself paces the same byte budget the fetcher already
/// bounds — see `crate::fetcher`'s module doc for the distinct RESIDENT
/// pool this does and does not cover: this is a transport
/// pacing window, not a second copy of the fetcher's own retention
/// charge.
pub(crate) const H2_CONN_WINDOW: u32 = 64 * 1024 * 1024;

const _: () = assert!(
    H2_CONN_WINDOW as u64 == crate::fetcher::FETCH_INFLIGHT_BYTES,
    "the connection window must equal the fetcher's own in-flight byte \
     budget — the transport should enforce what the fetcher already \
     bounds, not a different number"
);
const _: () = assert!(
    H2_CONN_WINDOW as u64 / H2_STREAM_WINDOW as u64 == crate::fetcher::FETCH_WINDOW as u64,
    "conn / stream must equal the fetch window: 64 MiB / 2 MiB = 32 \
     streams fills the pipe at FETCH_WINDOW"
);
const _: () = assert!(
    H2_STREAM_WINDOW as u64 >= granary_core::thresh::MAX_GRAIN as u64,
    "one stream's share of the connection window is one target grain — \
     narrower and every ordinary grain pays WINDOW_UPDATE round trips; \
     larger legal frames pace across them by design"
);

/// The connector type, named once so the [`Client`] field below can state
/// its body type explicitly. `Full<Bytes>` is not incidental: it is what
/// pins every request body to an in-memory buffer of known length, which
/// is what the seam hands over (`Vec<u8>`), and what makes a streaming
/// request body a compile error rather than a design drift.
type Connector = HttpsConnector<HttpConnector>;

/// Why an [`HttpStore`] could not be built.
///
/// Construction errors are separate from [`RootStoreError`] on purpose:
/// nothing has been asked of a store yet, so none of the seam's outcomes
/// — not found, already exists, refused response — can apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpStoreError {
    /// The endpoint authority contains userinfo.
    Userinfo,
    /// `{base}` is not an absolute `https` URL with no trailing slash
    /// (§4.1).
    BadBase {
        /// The rule the value violated.
        reason: String,
    },
    /// The pin set was refused (`granary_net::pin::PinnedServerVerifier`).
    Pins(PinSetError),
    /// rustls refused the client configuration.
    Tls(String),
}

impl std::fmt::Display for HttpStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Userinfo => f.write_str("endpoint userinfo is not permitted"),
            Self::BadBase { reason } => write!(f, "base url: {reason}"),
            Self::Pins(e) => write!(f, "tls pin set: {e}"),
            Self::Tls(e) => write!(f, "client tls config: {e}"),
        }
    }
}

impl std::error::Error for HttpStoreError {}

/// The URL builders, and the newtype that makes them the ONLY ones.
///
/// **`Target`'s field is private to this module, so the literal is
/// unbuildable outside it**, and [`HttpStore::get`]/[`HttpStore::put`]
/// take nothing else. That is the mechanism, and it replaces a
/// convention: a method added later cannot hand them a
/// `format!("{base}/volume/{volume}/…")` — it is a type error at the call
/// site rather than a finding at review time — so every target in this
/// file comes out of one of the two constructors below and inherits
/// §4.3's grammars, and §13.3's volume refusal, by construction.
mod target {
    use granary_core::hash::DIGEST_LEN;
    use granary_core::root::VolumeName;
    use granary_core::rootstore::RootStoreError;

    /// A `{base}`-rooted target (§4.2), built here and nowhere else.
    pub(super) struct Target(String);

    impl Target {
        /// The target as the URI parser takes it.
        pub(super) fn as_str(&self) -> &str {
            &self.0
        }

        /// `{base}/bin/{digest}` (§4.2 row 1/2).
        ///
        /// The digest is rendered as §4.3's grammar spells it: exactly 64
        /// LOWERCASE hex characters. Uppercase is a different segment, not
        /// the same one — every grammar in §4.3 is total, with no case
        /// folding.
        pub(super) fn bin(base: &str, digest: &[u8; DIGEST_LEN]) -> Self {
            use core::fmt::Write as _;
            let mut out = String::with_capacity(base.len() + 5 + DIGEST_LEN * 2);
            out.push_str(base);
            out.push_str("/bin/");
            for b in digest {
                // Infallible on a String; the result is discarded the way
                // `GrainId::digest_hex` discards it, rather than unwrapped.
                let _ = write!(out, "{b:02x}");
            }
            Self(out)
        }

        /// `{base}/volume/{volume}/{tail}`, and §13.3's volume refusal.
        ///
        /// **THE CHECK LIVES HERE, not at each call site.** A name is KEY
        /// MATERIAL: validating it is part of the CONTRACT, not
        /// of any one adapter, and a client that let the server answer
        /// instead would get a `404` back — which on three endpoints is a
        /// SUCCESS shape. At seven call sites it was seven chances to
        /// forget and one more with every method added.
        ///
        /// What makes it unforgettable is the private field above rather
        /// than this function's fallible return: a `Result` can be built
        /// and dropped, but a volume target that skipped the check cannot
        /// be *spelled* outside this module.
        ///
        /// No character outside `[a-z0-9-]` survives the check, which is
        /// why nothing is encoded (§4.3: clients MUST NOT percent-encode
        /// any character in these segments — every character used is
        /// already legal in a path segment, so encoding one produces a
        /// different, invalid segment rather than the same one).
        pub(super) fn volume(base: &str, volume: &str, tail: &str) -> Result<Self, RootStoreError> {
            VolumeName::new(volume.to_owned()).map_err(|e| RootStoreError::InvalidVolume {
                reason: e.to_string(),
            })?;
            let mut out = String::with_capacity(base.len() + 9 + volume.len() + tail.len());
            out.push_str(base);
            out.push_str("/volume/");
            out.push_str(volume);
            out.push_str(tail);
            Ok(Self(out))
        }
    }
}

use self::extent::RequestedExtent;
use self::target::Target;

/// The client's own process-wide response-byte counter — bytes
/// COUNTED as they are framed off a response body, in
/// [`read_capped`], never a length inferred at `Ok(Some(out))`.
///
/// **A SEPARATE piece of code from `granary-server`'s `WriteBudget`,
/// deliberately.** This crate is Apache; the server's counter lives in
/// the AGPL crate. The RULE (frame-level counting, CAS-loop-plus-poison
/// on overflow, never a `static`) is shared; the type is not.
///
/// This counter accepts the exact total `u64::MAX` and poisons only on
/// arithmetic overflow. The metrics counter reserves `u64::MAX` as invalid
/// and uses relaxed observations. Keeping separate types preserves the wire
/// instrument's full-range, acquire/release contract without changing metrics.
///
/// **NEVER a `static`, for the same reason `WriteBudget` is not one**: a
/// process-global has no injectable start value, so the poison row could
/// never fire, and under a shared test process a global reads whatever
/// the previous row left.
#[derive(Debug, Default)]
struct ResponseByteCounter {
    bytes: AtomicU64,
    poisoned: AtomicBool,
}

impl ResponseByteCounter {
    const fn new() -> Self {
        Self {
            bytes: AtomicU64::new(0),
            poisoned: AtomicBool::new(false),
        }
    }

    /// [`ResponseByteCounter::new`], with `bytes` starting at `start` —
    /// the door the poison row needs, the same shape as
    /// `WriteBudget::new_with_request_bytes` on the server side.
    #[cfg(test)]
    const fn new_at(start: u64) -> Self {
        Self {
            bytes: AtomicU64::new(start),
            poisoned: AtomicBool::new(false),
        }
    }

    /// Count `bytes` that just arrived as one DATA frame — a
    /// hand-written compare-and-swap loop, never `fetch_add`, for the
    /// same reason `WriteBudget::record_frame` gives: `fetch_add` WRAPS
    /// on overflow, which is the fail-open direction for an
    /// upper-bound gate. On overflow this stores the reserved sentinel
    /// `u64::MAX` and sets the sticky poison bit instead.
    ///
    /// **The poison FLAG is stored BEFORE the
    /// sentinel VALUE, not after** — the same reordering, and the same
    /// reason, as `WriteBudget::record_frame`'s own fix: [`Self::total`]
    /// reads flag-then-value, so storing value-then-flag left a window
    /// where a concurrent reader could observe the sentinel `u64::MAX`
    /// with the flag still `false` and report it as a genuine total.
    /// Unreachable in practice (2^64 bytes), but free to correct.
    fn record_frame(&self, bytes: u64) {
        let mut current = self.bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                self.poisoned.store(true, Ordering::Release);
                self.bytes.store(u64::MAX, Ordering::Release);
                return;
            };
            match self.bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_won) => return,
                Err(observed) => current = observed,
            }
        }
    }

    /// The total, or `None` if poisoned.
    fn total(&self) -> Option<u64> {
        if self.poisoned.load(Ordering::Acquire) {
            return None;
        }
        Some(self.bytes.load(Ordering::Acquire))
    }
}

/// The OPAQUE, `pub` handle onto an [`HttpStore`]'s
/// process-wide response-byte counter — kept opaque, so
/// `ResponseByteCounter` itself can stay private, the same shape the
/// server's `WireByteHandle` uses around its own (`pub(crate)`)
/// `WriteBudget`.
#[derive(Debug, Clone)]
pub struct WireByteHandle(Arc<ResponseByteCounter>);

impl WireByteHandle {
    /// The response-byte total, or `None` if poisoned.
    #[must_use]
    pub fn total(&self) -> Option<u64> {
        self.0.total()
    }
}

/// The nine seam operations over §5's endpoints.
///
/// Session facades are constructed through [`Self::with_metrics`].
/// ```compile_fail
/// fn copy_store(store: &granary_client::HttpStore) {
///     let _: granary_client::HttpStore = (*store).clone();
/// }
/// ```
#[derive(Debug)]
pub struct HttpStore {
    /// The configured `{base}`, verified once at construction and stored
    /// AS GIVEN. Targets are formed by concatenation (§4.1) — never by
    /// re-rendering a parsed URL, which would normalise the operator's
    /// path out from under them.
    base: String,
    /// The validated TLS and socket policy retained so each runtime-bound
    /// facade can build its own connection pool without rebuilding the
    /// verifier or client credential.
    connector: Connector,
    client: Client<Connector, Full<Bytes>>,
    /// The pin set this store's verifier was built over, KEPT so a
    /// handshake refusal can name it.
    ///
    /// The verifier owns certificate membership. This retained operand also
    /// binds intent operations to the exact configured authority and pin set;
    /// it does not replace the verifier's connection check.
    ///
    /// **Naming it in an error leaks nothing.** `pin.rs` records why
    /// both operands are public — "the certificate is broadcast in every
    /// handshake and the pin is configuration" — which is the same
    /// reason its membership test is allowed to be variable-time.
    pins: Vec<SpkiPin>,
    /// The TLS key identity, retained after the credential enters the connector.
    key_identity: Option<crate::FileIdentity>,
    /// The client's process-wide response-byte counter — `Arc`, because
    /// the store is shared across a mount's tasks, and every clone of
    /// this `Arc` must charge the SAME counter rather than one each.
    /// See [`ResponseByteCounter`]'s own doc for why this is a separate
    /// type from the server's `WriteBudget`.
    wire: Arc<ResponseByteCounter>,
    metrics: Option<crate::ClientMetrics>,
}

impl crate::MountMetrics for HttpStore {
    fn client_metrics(&self) -> Option<&crate::ClientMetrics> {
        self.metrics.as_ref()
    }
}

impl HttpStore {
    /// Build a store against `base`, pinning `pins`.
    ///
    /// `network` supplies network identity, READ ONCE here and not cached: Phase 1
    /// has no cache for a network change to invalidate (see
    /// `netid`), and reading it is what keeps the seam a
    /// compile-time obligation rather than a note in a document.
    ///
    /// # Errors
    /// [`HttpStoreError`] — a base that is not an absolute `https` URL
    /// without a trailing slash, a pin set the verifier refuses, or a
    /// rustls configuration failure.
    pub fn new(
        base: &str,
        pins: Vec<SpkiPin>,
        network: &impl NetworkIdentity,
    ) -> Result<Self, HttpStoreError> {
        Self::with_client_credential(base, pins, network, None)
    }

    /// Build a store against `base`, pinning `pins`, presenting `credential`
    /// to a server that asks for a client certificate.
    ///
    /// `None` is a client with no credential configured: against a server
    /// with an authority, its connections are anonymous, and its writes are
    /// refused `403` + `no-principal` (§3.2 rule 4). The credential is
    /// installed in the TLS configuration before the connection pool
    /// exists, so every connection this store makes presents it.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn with_client_credential(
        base: &str,
        pins: Vec<SpkiPin>,
        network: &impl NetworkIdentity,
        credential: Option<ClientCredential>,
    ) -> Result<Self, HttpStoreError> {
        let base = check_base(base)?;
        // CLONED before the verifier takes ownership, and the order is
        // the point: the verifier is what refuses an over-large set and
        // the all-zero sentinel, so a set kept here is a set that
        // already passed those. `PIN_SET_MAX` is 8, so the copy is at
        // most 256 bytes, once per store.
        let mut kept = pins.clone();
        kept.sort_unstable();
        kept.dedup();
        let verifier = PinnedServerVerifier::new(pins, Arc::new(granary_net::crypto_provider()))
            .map_err(HttpStoreError::Pins)?;
        let key_identity = credential.as_ref().map(ClientCredential::key_file_identity);
        let certified = credential.map(ClientCredential::into_certified_key);
        let tls = client_tls_config(Arc::new(verifier), certified.as_ref())
            .map_err(|e| HttpStoreError::Tls(e.to_string()))?;
        // ORDER IS LOAD-BEARING, in three places.
        //
        // `https_only()` and never `https_or_http()`: the second admits an
        // `http://` target through the SAME connector, and a plaintext
        // connection runs no certificate verifier at all — so the pin is
        // not "checked and passed", it is never consulted.
        //
        // TODAY this is defence in depth with no reachable bypass, and it
        // is kept as a lock rather than deleted as dead code. `check_base`
        // refuses a non-`https` base; every target is that base plus
        // segments drawn from `[a-z0-9-]` and hex grammars, so no segment
        // can introduce a scheme; and hyper-util's legacy client follows no
        // redirects, so no response can retarget a request. Each of those
        // three is a separate thing to change, and the first one to change
        // silently is what this line is here for.
        //
        // `enable_http1()` BEFORE `enable_http2()`: `enable_http2()` alone
        // writes an ALPN list of `{h2}`, dropping `http/1.1` — the
        // MANDATORY protocol baseline. Called in this order the list
        // is `{h2, http/1.1}`, which is what `granary_net::alpn` says the
        // protocol offers.
        //
        // The `tls` config arrives with an EMPTY `alpn_protocols`, which
        // `with_tls_config` asserts: it rewrites the list itself, and
        // panics on a pre-filled one.
        //
        // `wrap_connector` and not `build()`, for one reason: `build()`
        // constructs `HttpConnector::new()` internally and there is no
        // way to reach it afterwards, so a connect clock can only be set
        // on a connector this code owns. Three of the lines below
        // are then obligatory rather than optional — `enforce_http(false)`
        // is what `build()` does for us and dropping it makes every
        // `https` target fail as "invalid URL, scheme must be http", so it
        // is not optional hygiene, it is the reason the wrapped form works
        // at all; `set_nodelay(true)` is the other default `build()` would
        // NOT have given us either, and is its own paragraph below.
        //
        // `set_nodelay(true)` is the THIRD obligatory line, and it is the
        // one nothing here asked for. `HttpConnector`'s own default is
        // `nodelay: false` (hyper-util 0.1.20,
        // `client/legacy/connect/http.rs:235`), so wrapping a connector
        // this code owns — to set the connect timeout above — silently opts every
        // granary connection INTO Nagle's algorithm. `reqwest`, which
        // builds the same connector, sets `nodelay: true` in its own
        // builder default (`reqwest 0.13.4 async_impl/client.rs:368`);
        // the default is lost precisely because `build()` is not used.
        //
        // What Nagle costs here, measured on Linux. With
        // Nagle on, a SMALL write issued while earlier bytes are still
        // unacknowledged is held by the kernel until the peer's delayed
        // ACK fires — up to ~40 ms on Linux. That is exactly this
        // client's shape: a cut call writes `RST_STREAM`, and the next
        // call's `HEADERS` is a small write immediately behind it with
        // that reset still unacknowledged. Measured cost of the stall:
        // the follow-up request did not reach the peer for ~15 ms of
        // real time, on a LOOPBACK socket. On macOS the stall was not
        // observed.
        //
        // The regression gate is behavioural and lives in
        // `tests/http_store.rs`: the three `put_root`-deadline rows
        // (`a_blackholed_put_root_probes_before_surfacing`,
        // `a_landed_but_blackholed_put_root_reports_success_via_the_probe`,
        // `a_fully_parked_peer_cannot_wedge_commit_past_both_deadlines`)
        // each issue a probe immediately behind a cut call under a
        // PAUSED clock, so the ~15 ms stall lands outside the virtual
        // deadline. Demonstrated both ways on aarch64 Linux: all three
        // FAIL with this line removed and PASS with it present, on the
        // same commit and the same container.
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(CONNECT_TIMEOUT));
        http.set_nodelay(true);
        http.set_keepalive(Some(Duration::from_mins(1)));
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_only()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);
        let client = Self::build_client(connector.clone());
        // Read the network identity once. Not stored: a cache is the Phase-2 mechanism
        // this deliberately does not build.
        let _network = network.current();
        Ok(Self {
            base,
            connector,
            client,
            pins: kept,
            key_identity,
            wire: Arc::new(ResponseByteCounter::new()),
            metrics: None,
        })
    }

    /// A request facade for one session, with its own connection pool and the
    /// existing wire instrument while attributing metrics only to this handle.
    #[must_use]
    pub fn with_metrics(&self, metrics: crate::ClientMetrics) -> Self {
        metrics.set_available(crate::MetricsGroup::Transport, true);
        self.fresh_pool_facade(Some(metrics))
    }

    /// Writable admission's read view gets its own pool and shares the instrument.
    pub(crate) fn writable_read_facade(&self) -> Self {
        self.fresh_pool_facade(self.metrics.clone())
    }

    /// Build a client whose pool will be driven by the runtime that first uses it.
    fn build_client(connector: Connector) -> Client<Connector, Full<Bytes>> {
        // `retry_canceled_requests` DEFAULTS TO TRUE in hyper-util, and
        // that default is wrong for this protocol. It re-sends a request
        // that was disrupted on a REUSED pooled connection before it
        // started — invisible to the caller, and for `PUT root` that is
        // precisely the blind retry §5a.4 forbids, converting an ambiguity
        // the ONE-PROBE RULE can resolve into a guess it cannot. Each
        // client serves all nine seams, so the seam with the strictest
        // requirement decides: no retry, anywhere.
        //
        // hyper-util consults the flag at TWO sites, not one: together
        // with `connection_reused` when a disrupted request can be taken
        // back un-sent (0.1.20, `src/client/legacy/client.rs:257` — that
        // branch's error kind is `Canceled`), and ALONE at `:376-377`
        // when a pool checkout returns an already-closed connection
        // (`Connect`) — so `false` also surfaces a lost checkout race as
        // a transport error rather than a transparent re-checkout, on
        // all nine seams. What `false` does NOT govern: a request the h2
        // layer accepted and cannot hand back fails as `SendRequest`
        // with the flag never consulted (`:335-338`, the `Nope` branch).
        // The measured sub-millisecond race — a close landing between
        // the pool's liveness filter (`pool.rs:300-307`) last polling
        // and a checkout being handed out — produced exactly that
        // `SendRequest` shape, so flipping this flag would not have
        // retried it; one millisecond of settle and the filter catches
        // the close instead. That remedy is the reason-scoped seam
        // retry; this flag stays false because it is reason-agnostic
        // and measured irrelevant to the Nope branch. Anyone deleting
        // this line as unreachable configuration should read §5a.4
        // first.
        // §9.5's discipline applied to the client end:
        // the two HTTP/2 windows STATED rather than inherited, and
        // adaptive sizing turned explicitly OFF — hyper's own default,
        // made explicit rather than left implicit. The `const _`
        // witnesses above tie both windows to the fetcher's own W and
        // byte budget, so the three cannot drift apart silently.
        Client::builder(TokioExecutor::new())
            .retry_canceled_requests(false)
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_mins(4))
            .pool_max_idle_per_host(1)
            .http2_initial_stream_window_size(H2_STREAM_WINDOW)
            .http2_initial_connection_window_size(H2_CONN_WINDOW)
            .http2_adaptive_window(false)
            .build(connector)
    }

    /// Preserve the authenticated connector and shared observations while
    /// giving another runtime a connection pool of its own.
    fn fresh_pool_facade(&self, metrics: Option<crate::ClientMetrics>) -> Self {
        let connector = self.connector.clone();
        let client = Self::build_client(connector.clone());
        Self {
            base: self.base.clone(),
            connector,
            client,
            pins: self.pins.clone(),
            key_identity: self.key_identity,
            wire: Arc::clone(&self.wire),
            metrics,
        }
    }

    fn request_attempt(
        &self,
        req: Request<Full<Bytes>>,
    ) -> impl std::future::Future<Output = Result<Response<Incoming>, hyper_util::client::legacy::Error>>
    {
        if let Some(metrics) = &self.metrics {
            metrics.record_transport(
                crate::ByteDirection::Up,
                hyper::body::Body::size_hint(req.body())
                    .exact()
                    .unwrap_or(0),
            );
        }
        self.client.request(req)
    }

    /// The loaded TLS key identity for protected-file publication exclusions.
    #[must_use]
    pub const fn key_file_identity(&self) -> Option<crate::FileIdentity> {
        self.key_identity
    }

    /// The public handle a caller reads the process-wide response-byte
    /// total from at clean exit — the SAME `Arc` every clone of this
    /// store's counter charges.
    #[must_use]
    pub fn wire_bytes(&self) -> WireByteHandle {
        WireByteHandle(Arc::clone(&self.wire))
    }

    /// `{base}/bin/{digest}` (§4.2 row 1/2), spelled by [`Target::bin`].
    fn bin_url(&self, digest: &[u8; DIGEST_LEN]) -> Target {
        Target::bin(&self.base, digest)
    }

    /// `{base}/volume/{volume}/{tail}` (§4.2), spelled by
    /// [`Target::volume`] — which is where §13.3's volume refusal lives,
    /// and the only place a volume name becomes addressing.
    fn volume_url(&self, volume: &str, tail: &str) -> Result<Target, RootStoreError> {
        Target::volume(&self.base, volume, tail)
    }

    /// Issue a request under an explicit retry policy. Every policy may resend
    /// once when the HTTP stack returns the request provably unsent. Other
    /// policies retry AT MOST ONCE for two failure classes:
    /// a remote `REFUSED_STREAM` reset on any seam, or, except on `put_root`,
    /// a connection failure from the closed list: an I/O failure in the
    /// source chain or remote GOAWAY. Other failures are not retried here.
    /// NO self-timeout of its own: the per-call deadline wraps the whole
    /// seam call one level up, in each [`RootStore`]/[`BinStore`] method —
    /// both attempts this function may make, plus the caller's own
    /// response-body read — so a CLASS A/B retry never gets a fresh clock;
    /// it spends what is left of the same budget the first attempt
    /// already drew on.
    ///
    /// `seam` names the caller for a diagnostic-only retry line.
    /// `policy` is `CreateRoot` for `put_root`: a connection failure there
    /// may have landed, and the ONE-PROBE RULE (§5.5) is `put_root`'s only
    /// ambiguity resolution outside CLASS A. See
    /// [`crate::retry::RetryClass`] for the two classes this decides
    /// between.
    ///
    /// The body is cloned BEFORE the first attempt. `body.clone()` is a
    /// refcounted `O(1)` `Bytes` bump; `parts.clone()` is honestly NOT
    /// free — it clones a `HeaderMap`, a real, bounded heap allocation
    /// paid on every call, retried or not, because hyper CONSUMES the
    /// request and returns nothing usable on failure, so there is no
    /// cheaper structure under this design that still lets a retry
    /// rebuild the request without depending on how much of the first
    /// attempt's body hyper already consumed — which is the property
    /// cloning before rather than after a failure buys.
    ///
    /// **The one residual CLASS B can leave, adjudicated and accepted at
    /// plan time.** A `ConnectionFailed` retry draws a connection from
    /// the SAME pool the first attempt did, and the pool can in
    /// principle hand back a SECOND dead connection — the retry then
    /// fails too, and that failure surfaces to the caller exactly as any
    /// other second-attempt failure does (honestly, never silently).
    /// The window is narrow — a connection whose send just failed is not
    /// reinserted, and the pool filters closed idles before handing one
    /// out — and it is UPHELD rather than closed: a known, bounded
    /// residual, not a gap nobody looked at.
    ///
    /// An `Unsent` resend also returns to the pool rather than retaining the
    /// failed dispatcher. A canceled dispatcher is no longer open and is
    /// filtered from checkout, while a failed connection attempt never
    /// entered the pool, so the second attempt uses a fresh connection.
    /// Source-less cancellation remains excluded because this public error
    /// surface cannot prove that shape returned the request.
    ///
    /// HTTP/1.1 graceful close has a separate residual: a request written
    /// while the server's FIN is in flight is not proven unsent and remains a
    /// failure on `Never`. Granary's client offers h2 first; third-party h1
    /// clients receive only the guarantee that the current response may
    /// finish before the connection closes.
    ///
    /// # Cancellation safety
    /// Cancellation ends this wait. A sent write can still be decided remotely.
    pub(crate) async fn send(
        &self,
        req: Request<Full<Bytes>>,
        seam: &'static str,
        policy: RetryPolicy,
    ) -> Result<Response<Incoming>, RootStoreError> {
        let (mut parts, body) = req.into_parts();
        insert_request_id(&mut parts.headers);
        let retry_req = Request::from_parts(parts.clone(), body.clone());
        let first_req = Request::from_parts(parts, body);
        match self.request_attempt(first_req).await {
            Ok(resp) => Ok(resp),
            Err(first_err) => {
                let class = retry::classify_lib_error(&first_err);
                let should_retry = policy.permits(class);
                if !should_retry {
                    return Err(self.transport_failure(&first_err));
                }
                // Retain the seam and retry class; provider error chains stay local.
                crate::observe::OperatorDiagnostic::seam_attempt_failed_retrying_once(
                    crate::observe::HttpSeam::from_adapter(seam),
                    match class {
                        crate::retry::RetryClass::Unsent => crate::observe::WireRetryClass::Unsent,
                        crate::retry::RetryClass::StreamRefused => {
                            crate::observe::WireRetryClass::StreamRefused
                        }
                        crate::retry::RetryClass::ConnectionFailed => {
                            crate::observe::WireRetryClass::ConnectionFailed
                        }
                        crate::retry::RetryClass::NotRetryable => {
                            crate::observe::WireRetryClass::NotRetryable
                        }
                    },
                    if granary_net::pin::is_pin_rejection(&first_err) {
                        crate::FailureClass::Refused
                    } else {
                        crate::FailureClass::Unavailable
                    },
                )
                .emit();
                self.request_attempt(retry_req)
                    .await
                    .map_err(|second_err| self.transport_failure(&second_err))
            }
        }
    }

    /// One hyper connect/send failure, rendered for a person.
    ///
    /// **The bug this replaces was `format!("transport: {e}")`.** `{e}`
    /// renders only the OUTER `Display`, and every failure this client
    /// can suffer on the way to a byte — a refused connection, a DNS
    /// miss, a TLS version mismatch, a wrong SPKI pin — arrives wearing
    /// the same four words, `client error (Connect)`. Nothing was
    /// swallowed by rustls or by hyper: the reason is on the `source()`
    /// chain and this function was throwing it away. The observed
    /// result — `gran cat: remote: object store: transport: client error
    /// (Connect)` for a wrong pin, from which an operator can learn
    /// nothing at all.
    ///
    /// **The failure itself is untouched.** A pin miss fails the
    /// handshake closed, as pin authentication requires, and nothing here
    /// runs before that decision or changes it. Only the rendering moved.
    ///
    /// The pin sentence is added on a TYPED test and never on the
    /// status: see [`granary_net::pin::is_pin_rejection`] for why that
    /// answer is definite, and for the seven-class list that makes
    /// guessing from `is_connect()` worse than saying nothing.
    ///
    /// **It names the pin VALUE and never where the pin came from.**
    /// A message ending `GRANARY_TLS_PINS holds …` would be false for
    /// `gran cat`: that command does
    /// not read that variable — `parse_cat` refuses to, and says so —
    /// and `--pin` overrides it on the publish route, so an operator who
    /// typed the flag would be pointed at an unset or stale variable and
    /// told it was the source of the pin that had just failed — the
    /// same diagnostic misdirection the pin diagnosis exists to
    /// remove. [`HttpStore::new`] receives a `Vec<SpkiPin>` and is told
    /// nothing about its origin; `main.rs` knows the origin and already
    /// hedges as `--pin (or GRANARY_TLS_PINS)` wherever it speaks about
    /// one. The layer that has the fact is the layer that states it.
    ///
    /// **The rendered text is NOT clipped, and the asymmetry with
    /// `granary-server`'s `handlers::STORE_DETAIL_MAX` is deliberate.**
    /// That clip exists because a store's error can embed an endpoint's
    /// whole response body and lands in a queue bounded in LINES. Every
    /// link here is a connect-phase failure — hyper's fixed strings, the
    /// platform's `strerror`, rustls's closed enum — none of which
    /// carries a peer-supplied body, no response has been read yet, and
    /// the destination is one message a person reads once rather than a
    /// per-request log line. [`CHAIN_MAX`] is the bound that matters on
    /// this path, and it bounds the LINKS.
    fn transport_failure(&self, error: &(dyn std::error::Error + 'static)) -> RootStoreError {
        use core::fmt::Write as _;

        let mut text = String::from("transport: ");
        render_chain_into(&mut text, error);
        if granary_net::pin::is_pin_rejection(error) {
            let _ = write!(text, " — pin mismatch: {}", self.rendered_pins());
        }
        RootStoreError::Backend(text)
    }

    /// What this client was configured to accept, in §9a's spelling —
    /// the one an operator can compare with their own configuration
    /// character for character, wherever they wrote it.
    ///
    /// **The empty set gets its own sentence, and it is the one an
    /// operator is most likely to need.** `PinnedServerVerifier::new`
    /// accepts an empty set and refuses every certificate — "not
    /// configured yet" must never mean "accept anything" — so a client
    /// with no pins authenticates nobody, and rendering that as an empty
    /// list would say the pins do not match when there are none.
    ///
    /// Neither sentence names a variable or a flag: see
    /// [`Self::transport_failure`] for why this layer cannot know which
    /// one the operator used.
    fn rendered_pins(&self) -> String {
        if self.pins.is_empty() {
            return "this client has no TLS pins configured, and an empty set refuses every \
                    certificate"
                .to_owned();
        }
        let rendered = self
            .pins
            .iter()
            .map(granary_net::config::render_tls_pin)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "the server's certificate matches none of this client's configured TLS pins: {rendered}"
        )
    }

    /// Construct an authority request through the same volume grammar gate.
    pub(crate) fn authority_request(
        &self,
        volume: &str,
        tail: &str,
        method: Method,
        body: Bytes,
    ) -> Result<Request<Full<Bytes>>, RootStoreError> {
        let url = self.volume_url(volume, tail)?;
        Request::builder()
            .method(method)
            .uri(url.as_str())
            .body(Full::new(body))
            .map_err(|e| RootStoreError::Backend(format!("request: {e}")))
    }

    pub(crate) fn intent_scope_matches(
        &self,
        scope: &granary_core::retained_submission::Scope,
    ) -> bool {
        self.base.as_bytes() == scope.authority_base && self.pins == scope.pins
    }

    /// Count actual response frames under a caller-supplied bound.
    ///
    /// # Cancellation safety
    /// Cancellation drops the unread body. Already received frames remain counted.
    pub(crate) async fn authority_body<B>(
        &self,
        body: B,
        cap: usize,
    ) -> Result<Option<Vec<u8>>, RootStoreError>
    where
        B: hyper::body::Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Display,
    {
        read_capped(body, cap, &self.wire, self.metrics.as_ref()).await
    }

    /// A `PUT` with the object's content type, answered by its status and
    /// its `Granary-Error` token.
    ///
    /// The token is kept so a refusal reaches the caller as the HTTP answer
    /// it was (`PUT bin: 403 no-principal`) rather than as a bare status; it
    /// is extracted by [`error_token`]'s single-token rule. The body is not
    /// read.
    ///
    /// `seam` and `policy` are forwarded to [`Self::send`]
    /// verbatim, retry class included.
    ///
    /// **What a CLASS B retry can do to `put_bin`/`put_meta`'s
    /// created-vs-existed `bool` — accepted, not overlooked.** If
    /// the FIRST attempt actually landed and only its RESPONSE was lost
    /// to a died connection, the retried `PUT` observes `200` (already
    /// there) rather than `201` (created) — the object is
    /// content-addressed, so the bytes it lands are identical either
    /// way, and this is an ACCOUNTING undercount, never a correctness or
    /// corruption one. `gran publish`'s "uploaded" counts can therefore
    /// undercount by the same one object on the rare connection this
    /// retry recovers; nothing downstream reads that count for anything
    /// but a human-facing summary.
    async fn put(
        &self,
        url: Target,
        content_type: &'static str,
        bytes: Vec<u8>,
        seam: &'static str,
        policy: RetryPolicy,
    ) -> Result<PutAnswer, RootStoreError> {
        let req = Request::builder()
            .method(Method::PUT)
            .uri(url.as_str())
            .header(CONTENT_TYPE, content_type)
            .body(Full::new(Bytes::from(bytes)))
            .map_err(|e| RootStoreError::Backend(format!("request: {e}")))?;
        let resp = self.send(req, seam, policy).await?;
        Ok(PutAnswer {
            status: resp.status(),
            token: error_token(&resp).map(str::to_owned),
        })
    }

    /// `seam` and `policy` are forwarded to [`Self::send`]
    /// verbatim, retry class included.
    async fn get(
        &self,
        url: Target,
        seam: &'static str,
        policy: RetryPolicy,
    ) -> Result<Response<Incoming>, RootStoreError> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(url.as_str())
            .body(Full::new(Bytes::new()))
            .map_err(|e| RootStoreError::Backend(format!("request: {e}")))?;
        self.send(req, seam, policy).await
    }

    /// A `GET` carrying the ONE `Range` form §7.1 defines.
    ///
    /// The header value comes from the [`RequestedExtent`] and from
    /// nowhere else, so the value a ranged read sends and the value
    /// [`extent_gate`] checks the answer against are the same two numbers,
    /// rendered once. Never a suffix-range, never open-ended, never more
    /// than one range-spec — none of those has a `RequestedExtent` to come
    /// out of.
    ///
    /// `seam` and `policy` are forwarded to [`Self::send`]
    /// verbatim, retry class included.
    async fn get_ranged(
        &self,
        url: Target,
        extent: &RequestedExtent,
        seam: &'static str,
        policy: RetryPolicy,
    ) -> Result<Response<Incoming>, RootStoreError> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(url.as_str())
            .header(RANGE, extent.header())
            .body(Full::new(Bytes::new()))
            .map_err(|e| RootStoreError::Backend(format!("request: {e}")))?;
        self.send(req, seam, policy).await
    }
}

/// `application/vnd.granary.bin.v1` (§5.1).
const CT_BIN: &str = "application/vnd.granary.bin.v1";
/// `application/vnd.granary.meta.v1` (§5.3).
const CT_META: &str = "application/vnd.granary.meta.v1";
/// `application/vnd.granary.root.v1` (§5.5).
pub(crate) const CT_ROOT: &str = "application/vnd.granary.root.v1";
/// The hint's body is 20 ASCII digits and nothing else (§5.9).
const CT_HINT: &str = "text/plain; charset=utf-8";

/// Validate `{base}` once (§4.1) and return it AS GIVEN.
///
/// **A parse, then concatenation — not a URL builder.** Prefer the existing
/// parser and concatenation over adding a convenience dependency.
/// Every target below is
/// `{base}` plus segments drawn from grammars that admit no character
/// needing an escape, so a URL crate would be a dependency bought to avoid
/// a `+`.
pub(crate) fn check_base(base: &str) -> Result<String, HttpStoreError> {
    let bad = |reason: &str| HttpStoreError::BadBase {
        reason: reason.to_owned(),
    };
    if base.contains('#') {
        // A fragment truncates the target at the URI parser, so
        // `{base}#x` + `/bin/…` would address `{base}` (§4.3).
        return Err(bad("a base URL may not carry a fragment"));
    }
    check_endpoint_userinfo(base)?;
    let uri: Uri = base.parse().map_err(|_| bad("invalid endpoint URL"))?;
    if uri.scheme_str() != Some("https") {
        // The pin is only consulted on a TLS connection. An `http://`
        // base is not "unpinned", it is unauthenticated.
        return Err(bad("must be an absolute https:// URL"));
    }
    if uri.authority().is_none() {
        return Err(bad("must name a host"));
    }
    if uri.query().is_some() {
        return Err(bad("a base URL may not carry a query"));
    }
    if base.ends_with('/') {
        // `{base}/` + `/bin/…` is `//bin/…`, whose empty segment fails
        // §4.3's grammar at every server — a 404 on every request.
        return Err(bad("must not end in '/'"));
    }
    Ok(base.to_owned())
}

/// Reject userinfo without narrowing a route's own endpoint accept set.
pub(crate) fn check_endpoint_userinfo(endpoint: &str) -> Result<(), HttpStoreError> {
    if endpoint.split_once("://").is_some_and(|(_, rest)| {
        rest.split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| authority.contains('@'))
    }) {
        return Err(HttpStoreError::Userinfo);
    }
    Ok(())
}

/// A `PUT`'s answer: the status, and the `Granary-Error` token when the
/// response carries exactly one ([`error_token`]).
#[derive(Debug)]
struct PutAnswer {
    status: StatusCode,
    token: Option<String>,
}

impl PutAnswer {
    /// §8.1's totality rule for a `PUT` status the endpoint does not list:
    /// [`unmapped`], with the token named beside the status when there is
    /// one, so `403` + `no-principal` reads `PUT bin: 403 no-principal`.
    /// It is the server's answer, never a transport failure, and nothing
    /// retries it.
    fn unmapped(&self, endpoint: &'static str) -> RootStoreError {
        // A status [`unmapped`] types elsewhere keeps its variant; only the
        // unexpected-status answer gains the token.
        match (
            unmapped(endpoint, self.status),
            self.token.as_deref().filter(|token| is_token_shaped(token)),
        ) {
            (
                RootStoreError::UnexpectedStatus {
                    operation, status, ..
                },
                Some(token),
            ) => RootStoreError::UnexpectedStatus {
                operation,
                status,
                token: Some(token.to_owned()),
            },
            (typed, _) => typed,
        }
    }
}

/// The longest token [`PutAnswer::unmapped`] repeats. §8.2's registry is
/// closed and its longest token is far shorter.
const TOKEN_SHOWN_MAX: usize = 64;

/// Does `token` have §8.2's shape: lowercase letters, digits and `-`, and
/// not longer than [`TOKEN_SHOWN_MAX`]? A peer's other text is not
/// repeated into an error message.
pub(crate) fn is_token_shaped(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= TOKEN_SHOWN_MAX
        && token
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The `Granary-Error` token, if the response carries exactly one that is
/// valid UTF-8.
fn error_token(resp: &Response<Incoming>) -> Option<&str> {
    let mut it = resp.headers().get_all(GRANARY_ERROR).iter();
    let first = it.next()?;
    if it.next().is_some() {
        // Two tokens is not one token. §8.2's registry is closed and the
        // field carries exactly one value.
        return None;
    }
    first.to_str().ok()
}

/// Does this `404` carry the token that completes a SUCCESS mapping
/// (§8.1)?
///
/// The three endpoints where a `404` means `Ok(None)`/`Ok(Missing)`
/// require it, accepting NO other token: `unknown-target` is what a real
/// granary server answers when the base URL's path is wrong, and an absent
/// field is what everything that is not a granary server answers. Both map
/// to a backend error.
fn is_not_found(resp: &Response<Incoming>) -> bool {
    error_token(resp) == Some(TOKEN_NOT_FOUND)
}

/// §8.1's totality rule: any status not listed for an endpoint is a
/// backend error carrying the status, except for the typed precondition
/// and unavailable statuses required by §5.10.
///
/// `endpoint` is `&'static str` because every caller passes a literal
/// (`"GET meta"`, `"PUT root"`, …) — never text a peer supplied — which
/// is what lets [`RootStoreError::Unavailable`] carry it straight
/// through as `operation` with no allocation and no attacker-chosen
/// content.
fn unmapped(endpoint: &'static str, status: StatusCode) -> RootStoreError {
    if status == StatusCode::PRECONDITION_FAILED {
        // §5.10: no granary server generates a 412; the row exists so the
        // map is total for one an intermediary supplies.
        return RootStoreError::Precondition;
    }
    if matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
    ) {
        // A `429` or `503` is a refusal the
        // fetcher's own AIMD backpressure handles, and it must arrive
        // TYPED — folding it into `Backend`'s free-text bucket would
        // make it unclassifiable by anything that isn't reading a
        // rendered string.
        return RootStoreError::Unavailable {
            operation: endpoint,
            status: status.as_u16(),
        };
    }
    RootStoreError::UnexpectedStatus {
        operation: endpoint,
        status: status.as_u16(),
        token: None,
    }
}

/// Read a response body, COUNTING the bytes as they are framed, and cut at
/// `cap`.
///
/// `Ok(None)` means the cap was crossed and the read stopped there;
/// `Ok(Some(bytes))` means the whole body fit.
///
/// **Nothing here is sized from `Content-Length`** (§5a.2). A declared
/// length is an assertion by the peer, and an allocation failure in Rust
/// is an abort rather than a catchable error, so an advertised length is
/// an attacker-controlled allocation request. The buffer starts empty and
/// grows only by bytes that actually arrived, and never past `cap` — a
/// lying `Content-Length` of 4 GiB on a 10-byte body allocates ten bytes
/// here.
///
/// **`counter` is charged AT THE FRAME**, the same rule and the same
/// class of trap the server's `accept_body` closes: a broken frame or
/// an over-cap frame still ARRIVED, so counting only at `Ok(Some(out))`
/// loses both of those arms.
async fn read_capped<B>(
    body: B,
    cap: usize,
    counter: &ResponseByteCounter,
    metrics: Option<&crate::ClientMetrics>,
) -> Result<Option<Vec<u8>>, RootStoreError>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    // Real encoders normally emit no empty DATA frames, while HTTP permits
    // them. Keep three orders of magnitude of tolerance without allowing
    // payload-free frames to make this loop unbounded. HTTP carries at most
    // one trailing header block, enforced separately below.
    const EMPTY_DATA_FRAME_LIMIT: usize = 1_024;

    let mut body = body;
    let mut out: Vec<u8> = Vec::new();
    let mut empty_data_frames: usize = 0;
    let mut saw_trailers = false;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| RootStoreError::Backend(format!("response body: {e}")))?;
        // http-body 1.x: `into_data` hands the frame BACK when it is not a
        // data frame (trailers), rather than panicking or yielding empty.
        let data = match frame.into_data() {
            Ok(data) => data,
            Err(non_data) => {
                if non_data.is_trailers() && !saw_trailers {
                    saw_trailers = true;
                    continue;
                }
                return Err(RootStoreError::RefusedResponse {
                    reason: "response body sent more than one trailer frame".to_owned(),
                    kind: RefusalKind::Framing,
                });
            }
        };
        // Counted here, the moment `data` is in hand — BEFORE the cap
        // comparison and BEFORE `out.extend_from_slice` below, and on
        // every frame that reaches here regardless of what the rest of
        // this loop iteration decides. The trap this closes is on the
        // OTHER side of this point: `frame.map_err(...)?` above returns
        // on a broken frame before any `data` exists, so that arm loses
        // nothing from a PRIOR count — but a count taken only at
        // `Ok(Some(out))` would lose everything already in `out` when a
        // LATER frame breaks, and would lose the over-cap frame itself
        // on the `Ok(None)` cap arm below. Counting here, per frame,
        // survives both.
        counter.record_frame(u64::try_from(data.len()).unwrap_or(u64::MAX));
        if let Some(metrics) = metrics {
            metrics.record_transport(
                crate::ByteDirection::Down,
                u64::try_from(data.len()).unwrap_or(u64::MAX),
            );
        }
        if data.is_empty() {
            empty_data_frames = empty_data_frames.saturating_add(1);
            if empty_data_frames > EMPTY_DATA_FRAME_LIMIT {
                return Err(RootStoreError::RefusedResponse {
                    reason: format!(
                        "response body sent more than {EMPTY_DATA_FRAME_LIMIT} empty DATA frames"
                    ),
                    kind: RefusalKind::NoProgress,
                });
            }
        }
        if out.len().saturating_add(data.len()) > cap {
            // Cut here. The body is dropped unread — the bound is on the
            // TRANSFER, so draining the rest would defeat it. The frame
            // that crossed the cap was already counted above: it DID
            // arrive, even though it is not kept.
            return Ok(None);
        }
        out.extend_from_slice(&data);
    }
    Ok(Some(out))
}

/// Read a body that must fit `cap`, refusing the response if it does not.
///
/// **The cap-exceeded kind here is always [`RefusalKind::OverCap`]**,
/// hardcoded rather than a parameter: every caller (`get_meta`,
/// `get_root`) passes the object class's own read cap, never an
/// extent's width — that caller-dependent case is
/// [`HttpStore::get_bin_range`]'s own `read_capped` call, which does not
/// go through this function.
async fn read_bounded(
    body: Incoming,
    cap: u64,
    what: &str,
    counter: &ResponseByteCounter,
    metrics: Option<&crate::ClientMetrics>,
) -> Result<Vec<u8>, RootStoreError> {
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    match read_capped(body, cap, counter, metrics).await? {
        Some(bytes) => Ok(bytes),
        None => Err(RootStoreError::RefusedResponse {
            reason: format!("{what}: response body exceeds {cap} bytes"),
            kind: RefusalKind::OverCap,
        }),
    }
}

/// Strict unsigned decimal: digits only, no sign, no empty string.
///
/// `str::parse::<u64>` accepts a leading `+`, which would make `+5` and `5`
/// two spellings of one value on a wire this document keeps total.
fn parse_u64_strict(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Parse a `206`'s `Content-Range` as §7.2 requires it: `bytes
/// {first}-{last}/*`, `complete-length` exactly `*`, `last >= first`.
///
/// This is EXTENT-GATE CHECK 0, and it is numbered 0 because it is a
/// precondition of the arithmetic in the later checks rather than a
/// comparison against the request: a client that computed the width with
/// saturating arithmetic instead of refusing a reversed extent here would
/// turn it into a zero-width one and land on check 3 by accident.
fn parse_content_range(value: &str) -> Option<(u64, u64)> {
    let rest = value.strip_prefix("bytes ")?;
    let (range, complete) = rest.split_once('/')?;
    if complete != "*" {
        // §7.2: `complete-length` MUST be `*` here — the seam supplies no
        // object length, so a server that filled in a number invented one.
        return None;
    }
    let (first, last) = range.split_once('-')?;
    let first = parse_u64_strict(first)?;
    let last = parse_u64_strict(last)?;
    if last < first {
        return None;
    }
    Some((first, last))
}

/// Run one seam call under its own size-scaled per-call deadline:
/// [`seam_deadline`] scaled to `transfer_size`, wrapping the
/// WHOLE call — the wire exchange [`HttpStore::send`] performs (both
/// attempts; see that method's own doc on why a retry draws on the same
/// budget rather than a fresh one) AND the response body the caller
/// reads afterward.
///
/// **Covers body streaming AFTER headers, deliberately.** A peer that
/// answers headers promptly and then stalls the BODY is still a wedged
/// peer under the idle form's own definition — neither completed nor
/// failed — and `tokio::time::timeout` is cooperative, firing only where
/// the future it wraps yields. Wrapping the whole call rather than just
/// the header exchange is what puts every await of a call under the same
/// clock. The scaled size term is what keeps that honest: a large body
/// legitimately takes longer to arrive, and the deadline scales with the
/// size the caller declares, never with a flat figure that would refuse
/// a slow link on an ordinary transfer.
///
/// `seam` labels the call for [`RootStoreError::Elapsed`] exactly the
/// way [`HttpStore::send`]'s own `seam` parameter does — a caller-chosen
/// literal, never text a peer supplied.
async fn under_seam_deadline<T>(
    seam: &'static str,
    transfer_size: u64,
    call: impl Future<Output = Result<T, RootStoreError>>,
) -> Result<T, RootStoreError> {
    under_deadline(seam, seam_deadline(transfer_size), call).await
}

/// **The one place a per-call deadline becomes a
/// [`RootStoreError::Elapsed`].** Both routes reach it: the
/// through-the-server seam via [`under_seam_deadline`], which supplies
/// [`seam_deadline`]'s size-scaled idle form, and the direct-S3
/// decorator (`crate::direct_deadline`) which supplies its own flat
/// figure. There is one mapping from "the clock ran out" to the DISTINCT
/// error variant the `rootstore` module doc prescribes, so the two
/// routes cannot drift into reporting a timeout differently — which is
/// the whole reason `commit`'s one-probe branch can treat an elapsed
/// `put_root` identically whichever route produced it.
///
/// It lives HERE rather than in `direct_deadline`, beside the seam
/// deadline this module owns and the doc that explains the idle form.
///
/// Cooperative like every `tokio` timeout, and bounded the way
/// `granary_store`'s own `yield_once` doc states it: a listing walk
/// yields every 128 entries, but tokio's timer driver is polled only
/// every `event_interval` scheduler ticks — so expiry lands after a
/// bounded MULTIPLE of the yield interval, not at the first one.
///
/// `operation` is a caller-chosen literal, never text a peer supplied.
pub(crate) async fn under_deadline<T>(
    operation: &'static str,
    deadline: Duration,
    call: impl Future<Output = Result<T, RootStoreError>>,
) -> Result<T, RootStoreError> {
    match tokio::time::timeout(deadline, call).await {
        Ok(result) => result,
        Err(_elapsed) => Err(RootStoreError::Elapsed {
            operation,
            after: deadline,
        }),
    }
}

impl BinStore for HttpStore {
    async fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        // Transfer size: the request body length (the bytes this call
        // actually sends).
        let size = bytes.len() as u64;
        under_seam_deadline("PUT bin", size, async {
            let answer = self
                .put(
                    self.bin_url(digest),
                    CT_BIN,
                    bytes,
                    "PUT bin",
                    RetryPolicy::Idempotent,
                )
                .await?;
            match answer.status {
                StatusCode::CREATED => Ok(true),
                StatusCode::OK => Ok(false),
                _ => Err(answer.unmapped("PUT bin")),
            }
        })
        .await
    }

    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        // Transfer size: the request body length.
        let size = bytes.len() as u64;
        under_seam_deadline("PUT meta", size, async {
            let url = self.volume_url(volume, &format!("/meta/{id}"))?;
            let answer = self
                .put(url, CT_META, bytes, "PUT meta", RetryPolicy::Idempotent)
                .await?;
            match answer.status {
                StatusCode::CREATED => Ok(true),
                StatusCode::OK => Ok(false),
                _ => Err(answer.unmapped("PUT meta")),
            }
        })
        .await
    }

    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        // Transfer size: META_MAX_BYTES, the cap this read is already
        // bounded to (`read_bounded` below) — the largest this call can
        // legitimately transfer.
        under_seam_deadline("GET meta", META_MAX_BYTES, async {
            let url = self.volume_url(volume, &format!("/meta/{id}"))?;
            let resp = self.get(url, "GET meta", RetryPolicy::Idempotent).await?;
            match resp.status() {
                StatusCode::OK => {
                    read_bounded(
                        resp.into_body(),
                        META_MAX_BYTES,
                        "GET meta",
                        &self.wire,
                        self.metrics.as_ref(),
                    )
                    .await
                }
                // §8.1: BOTH `404`s are errors on this endpoint —
                // `not-found` means the object is absent, `unknown-target`
                // means the base path is wrong — so no token is required
                // to keep a success from being invented here. There is no
                // success to invent.
                StatusCode::NOT_FOUND => Err(RootStoreError::NotFound),
                other => Err(unmapped("GET meta", other)),
            }
        })
        .await
    }

    async fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        // Transfer size: the requested extent's own width — the
        // compressed range this call asks for, before §13.3's rows even
        // build a URL out of it.
        under_seam_deadline("GET bin", u64::from(len), async {
            // §13.3's pre-request rows are the constructor: no URL exists
            // until they have passed, and no `Range` field value either.
            let extent = RequestedExtent::new(offset, len)?;
            let resp = self
                .get_ranged(
                    self.bin_url(digest),
                    &extent,
                    "GET bin",
                    RetryPolicy::Idempotent,
                )
                .await?;
            match resp.status() {
                StatusCode::PARTIAL_CONTENT => {
                    let (first, served_last) = content_range_of(&resp)?;
                    // The gate RETURNS the width it validated. Recomputing
                    // it here would be a second arithmetic path over the
                    // same two numbers, and the only way two such paths
                    // stay in step is that nobody edits either one.
                    let width = extent_gate(&extent, first, served_last)?;
                    // CHECK 5: the body is EXACTLY as long as the extent,
                    // counted as it arrives. Long is a transfer the extent
                    // did not authorise; SHORT is the gap the other four
                    // checks leave wide open — `bytes 10-19/*` with five
                    // bytes passes every one of them and hands the caller
                    // five bytes it believes are ten. Nothing above
                    // compares the body against anything; this is the
                    // only place the two meet.
                    match read_capped(resp.into_body(), width, &self.wire, self.metrics.as_ref())
                        .await?
                    {
                        None => Err(refused("206 body is longer than its declared extent")),
                        Some(bytes) if bytes.len() != width => Err(refused(&format!(
                            "206 body is {} bytes under a {width}-byte extent",
                            width - bytes.len()
                        ))),
                        Some(bytes) => Ok(bytes),
                    }
                }
                // §5.2: no `404` is a success on a bin, so no token is
                // needed to keep one from becoming one.
                StatusCode::NOT_FOUND => Err(RootStoreError::NotFound),
                // §7.2 forbids a `200` in answer to a `Range` on a bin,
                // and §5.2 maps `416`/`400`/`500` to a backend error. Both
                // fall to §8.1's totality rule, which is what this is.
                other => Err(unmapped("GET bin", other)),
            }
        })
        .await
    }
}

impl RootStore for HttpStore {
    /// **The seam deadline does not bypass the ONE-PROBE RULE.** §5.5
    /// forbids a client wrapping "a single PUT of a root in a timeout or
    /// cancellation that returns before the probe runs" — the failure
    /// mode that sentence targets is a DROPPED future with no error to
    /// react to, so the probe never runs at all. That never happens
    /// here: this call always resolves to a value, cut or not, so an
    /// `Elapsed` is exactly as reactable-to as `AlreadyExists` or a
    /// transport error. `commit()` (`crate::publish`) is unconditional
    /// on ANY `put_root` failure, so it runs the SAME probe either way —
    /// no new choreography, and the sentence's "a deadline belongs
    /// around the whole publish, so the probe stays inside the operation
    /// being bounded" still holds, one level up: the bounded operation is
    /// `commit`, not this one future, and the probe (`get_root`) is
    /// inside it exactly as before.
    async fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) -> Result<(), RootStoreError> {
        // Transfer size: the request body length, the same rule every
        // PUT on this seam uses.
        let size = bytes.len() as u64;
        under_seam_deadline("PUT root", size, async {
            let url = self.volume_url(volume, &format!("/root/{}", format_hint_body(seq)))?;
            // NO connection-failure retry (`RetryPolicy::CreateRoot`):
            // a `ConnectionFailed` PUT here is AMBIGUOUS and the caller
            // resolves it with the ONE-PROBE RULE, which a blind retry
            // would short-circuit (§5.5). A CLASS A
            // `REFUSED_STREAM` reset is retried regardless — RFC 9113
            // §8.7 makes THAT one unambiguous, and a lying server that
            // landed the root anyway still converges through the probe
            // above, as exercised by
            // `refused_stream_on_a_lying_server_converges_through_the_probe`.
            let answer = self
                .put(url, CT_ROOT, bytes, "PUT root", RetryPolicy::CreateRoot)
                .await?;
            match answer.status {
                StatusCode::CREATED => Ok(()),
                StatusCode::CONFLICT => Err(RootStoreError::AlreadyExists),
                _ => Err(answer.unmapped("PUT root")),
            }
        })
        .await
    }

    /// Also the ONE-PROBE RULE's probe call (`commit()`, `crate::publish`)
    /// — carrying its OWN seam deadline like every other call, never the
    /// `put_root` it is resolving. A probe that itself elapses is
    /// reported ALONGSIDE the `put_root`'s own error, not in place of
    /// it, at `commit()`'s existing catch-all arm:
    /// `PublishError::ProbeUnresolved` carries both
    /// messages rather than discarding the probe's.
    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        // Transfer size: ROOT_MAX_BYTES, the cap this read is already
        // bounded to.
        under_seam_deadline("GET root", ROOT_MAX_BYTES, async {
            let url = self.volume_url(volume, &format!("/root/{}", format_hint_body(seq)))?;
            let resp = self.get(url, "GET root", RetryPolicy::Idempotent).await?;
            match resp.status() {
                StatusCode::OK => Ok(Some(
                    read_bounded(
                        resp.into_body(),
                        ROOT_MAX_BYTES,
                        "GET root",
                        &self.wire,
                        self.metrics.as_ref(),
                    )
                    .await?,
                )),
                // The `404` is the cheap negative a forward probe asks
                // for — but ONLY when a granary application layer
                // generated it.
                StatusCode::NOT_FOUND if is_not_found(&resp) => Ok(None),
                other => Err(unmapped("GET root", other)),
            }
        })
        .await
    }

    async fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        // Transfer size: SEQ_KEY_DIGITS, the existing cap this read's own
        // `read_capped` call below bounds a hint body to.
        under_seam_deadline("GET hint", SEQ_KEY_DIGITS as u64, async {
            let url = self.volume_url(volume, "/hint")?;
            let mut builder = Request::builder().method(Method::GET).uri(url.as_str());
            if let Some(token) = cached {
                // Echoed VERBATIM. The validator is opaque: a client
                // never derives, parses, compares or interprets it
                // (§5.8). This is the ONE conditional request this
                // profile defines (§5a.6).
                builder = builder.header(IF_NONE_MATCH, token.0.clone());
            }
            let req = builder
                .body(Full::new(Bytes::new()))
                .map_err(|e| RootStoreError::Backend(format!("request: {e}")))?;
            let resp = self.send(req, "GET hint", RetryPolicy::Idempotent).await?;
            match resp.status() {
                StatusCode::OK => {
                    // The `ETag` is REQUIRED and strong on this resource
                    // (§5.8), so a `200` without one is a NON-CONFORMING
                    // answer. It still degrades to `Missing`, and the two
                    // alternatives are both worse than losing one poll.
                    //
                    // ERRORING would let a server that is merely sloppy —
                    // the hint is ADVISORY, and a `200` carrying a
                    // correct body and no validator has told no lie —
                    // wedge every reader on the volume. The hint exists
                    // to save a `max-seq` round trip, so the cost of
                    // ignoring it is one round trip; the cost of failing
                    // on it is the volume.
                    //
                    // FABRICATING a token (`HintToken("")`, the seq
                    // rendered as one, anything) is worse still, because
                    // the token's only use is the next `If-None-Match`.
                    // An invented validator that a server then matches
                    // leaves the reader pinned to a dead seq,
                    // revalidating forever, `304` after every poll, no
                    // error anywhere and head-discovery polling apparently healthy —
                    // the silent stall §5.8 spends a paragraph
                    // forbidding. Degrading loses one poll; inventing
                    // loses the volume's head with no signal at all.
                    let token = resp
                        .headers()
                        .get(ETAG)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    // The bound is 20 bytes, and the first byte past it
                    // already settles the answer: an over-long body is
                    // what a bucket write outside granary produces, and
                    // an implementation that turned it into a hard error
                    // would wedge every reader on that volume through the
                    // one input §5.8 calls the most hostile.
                    let Some(body) = read_capped(
                        resp.into_body(),
                        SEQ_KEY_DIGITS,
                        &self.wire,
                        self.metrics.as_ref(),
                    )
                    .await?
                    else {
                        return Ok(HintRead::Missing);
                    };
                    let (Ok(text), Some(token)) = (std::str::from_utf8(&body), token) else {
                        return Ok(HintRead::Missing);
                    };
                    // A body of `0` parses and names a root that cannot
                    // exist, so it degrades with the rest to `Missing`:
                    // `Current { seq: 0 }` would send every reader
                    // through a doomed `GET root/0` first.
                    match parse_hint_body(text) {
                        Ok(0) | Err(_) => Ok(HintRead::Missing),
                        Ok(seq) => Ok(HintRead::Current {
                            seq,
                            token: HintToken(token),
                        }),
                    }
                }
                // **Only on a request that CARRIED the validator.** §5.8's
                // `304` row is reachable when "the hint exists and its
                // `ETag` matches" — a conditional compares a validator
                // against a representation and cannot conjure one — so a
                // `304` to a request that sent no `If-None-Match` is, in
                // §8.1's words for every other endpoint, "a response to a
                // request no conforming client sent", and it takes the
                // unexpected-status arm like any other. `granary-server`
                // guards the mirror case in the same shape:
                // `HintRead::NotModified` with no cached token has no
                // truthful `ETag` to emit and is `internal()`
                // (`handlers.rs`, §6).
                //
                // Believing it would report "nothing changed" about a
                // token this client never held, and a poll that sent no
                // validator has no cached seq to carry forward —
                // `NotModified` would name nothing, so the head-discovery caller learns
                // neither the head nor that it failed to.
                StatusCode::NOT_MODIFIED if cached.is_some() => Ok(HintRead::NotModified),
                StatusCode::NOT_FOUND if is_not_found(&resp) => Ok(HintRead::Missing),
                other => Err(unmapped("GET hint", other)),
            }
        })
        .await
    }

    async fn write_hint(&self, volume: &str, seq: u64) -> Result<(), RootStoreError> {
        // Transfer size: the request body length, the same rule every
        // PUT on this seam uses — 20 bytes, always, but derived from the
        // actual body rather than restated as a second constant.
        let body = format_hint_body(seq).into_bytes();
        let size = body.len() as u64;
        under_seam_deadline("PUT hint", size, async {
            let url = self.volume_url(volume, "/hint")?;
            let answer = self
                .put(url, CT_HINT, body, "PUT hint", RetryPolicy::Idempotent)
                .await?;
            match answer.status {
                // ONE success status, `204`, whether or not a hint was
                // there: the seam cannot tell those two cases apart, and
                // `201` would assert a creation that is affirmatively
                // untrue on the common path (§5.9, deviation 9).
                StatusCode::NO_CONTENT => Ok(()),
                _ => Err(answer.unmapped("PUT hint")),
            }
        })
        .await
    }

    /// Transfer size: 0 — `max_seq` is a LISTING, not a fetch of an
    /// object whose size the request declares or a format caps; the
    /// response itself is bounded the way `read_hint`'s is
    /// (`SEQ_KEY_DIGITS`), but the seam's own cost here is the server's
    /// listing walk, which no byte count describes. The base alone is
    /// what a listing gets.
    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        under_seam_deadline("GET max-seq", 0, async {
            let resp = self
                .get(
                    self.volume_url(volume, "/max-seq")?,
                    "GET max-seq",
                    RetryPolicy::Idempotent,
                )
                .await?;
            match resp.status() {
                StatusCode::OK => {
                    // §5.7 is the ONE place a 20-digit body does NOT
                    // degrade: a malformed answer here is a protocol
                    // violation, and guessing "the volume has no roots"
                    // would report a populated volume as empty and let a
                    // publish overwrite its own chain. The cap is the
                    // body's exact width, so an over-long body is
                    // malformed by the same rule rather than by a
                    // separate one.
                    let hard =
                        |what: &str| RootStoreError::Backend(format!("max-seq body: {what}"));
                    let Some(body) = read_capped(
                        resp.into_body(),
                        SEQ_KEY_DIGITS,
                        &self.wire,
                        self.metrics.as_ref(),
                    )
                    .await?
                    else {
                        return Err(hard("longer than 20 bytes"));
                    };
                    let text = std::str::from_utf8(&body).map_err(|_| hard("not ASCII digits"))?;
                    let seq = parse_hint_body(text).map_err(|e| hard(&e.to_string()))?;
                    // Seq 0 can hold no root, so an
                    // object planted at that key must not become the
                    // head — it would block the first publish to a fresh
                    // volume forever.
                    if seq == 0 {
                        return Ok(None);
                    }
                    // At the other end of the range, u64::MAX is
                    // RESERVED and can never be a head, so a server
                    // answering it has violated §5.7 — a HARD ERROR, and
                    // deliberately NOT a degrade to Ok(None) the way seq
                    // 0 degrades.
                    //
                    // DO NOT "simplify" this into the branch above. Seq 0
                    // can degrade safely because it MEANS "no valid
                    // root". u64::MAX means no such thing: degrading it
                    // would report a volume with real roots at ordinary
                    // seqs as EMPTY, sending publish down its new-volume
                    // branch to seq 1 — which is precisely the "let a
                    // publish overwrite its own chain" hazard this arm's
                    // opening paragraph exists to prevent. The rule is
                    // NEW rather than covered by the paragraph above:
                    // 18446744073709551615 is exactly 20 ASCII digits AND
                    // fits a u64, so it satisfies both limbs of the
                    // malformed test and reaches here well-formed.
                    if seq == u64::MAX {
                        return Err(hard("u64::MAX is reserved and can never be a head"));
                    }
                    Ok(Some(seq))
                }
                StatusCode::NOT_FOUND if is_not_found(&resp) => Ok(None),
                other => Err(unmapped("GET max-seq", other)),
            }
        })
        .await
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        // The HTTP protocol exposes only the unbounded max-seq endpoint.
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

/// §13.3's pre-request rows, and the value that carries their result.
///
/// **`RequestedExtent`'s fields are private to this module**, so the
/// struct literal is unbuildable outside it and the only way to obtain one
/// is [`RequestedExtent::new`], which is the four rows. [`extent_gate`]
/// takes one BY REFERENCE, so a ranged read added later has nothing to
/// pass the gate unless it went through them — a type error at the call
/// site, where the same rule written as a call-site convention was four
/// `if`s somebody had to remember to copy.
mod extent {
    use granary_core::binfmt::BIN_MAX_BYTES;
    use granary_core::rootstore::RootStoreError;
    use hyper::header::HeaderValue;

    /// A ranged read's requested extent: `[offset, end)`, plus the one
    /// `Range` field value that asks for it.
    pub(super) struct RequestedExtent {
        /// `first-pos`, and what §7.2's check 1 compares against.
        offset: u64,
        /// The requested end, EXCLUSIVE (`offset + len`).
        end: u64,
        /// `bytes={offset}-{end - 1}`, rendered once at construction.
        header: HeaderValue,
    }

    impl RequestedExtent {
        /// §13.3's four pre-request rows, IN ORDER, before a URL exists.
        ///
        /// # Errors
        /// The seam's range error for `len == 0` and for an `offset` at or
        /// past the ceiling; [`RootStoreError::RangeOverflow`] for an
        /// `offset + len` that leaves `u64`.
        pub(super) fn new(offset: u64, len: u32) -> Result<Self, RootStoreError> {
            if len == 0 {
                // §7.4: the byte-range grammar cannot express a zero-length
                // range — `bytes=10-9` is an invalid int-range, not an empty
                // one — and the seam pins `len == 0` as an error.
                return Err(RootStoreError::Backend(
                    "range read: len == 0 has no wire form".to_owned(),
                ));
            }
            let Some(end) = offset.checked_add(u64::from(len)) else {
                return Err(RootStoreError::RangeOverflow);
            };
            if offset >= BIN_MAX_BYTES {
                // No legal bin reaches the ceiling, so this range starts at
                // or past the end of EVERY object that could be at that
                // address. Refused locally so the answer is independent of
                // the server: over the wire it is a `416` whether or not the
                // bin exists, where an in-process implementation answers
                // `NotFound` for an absent one (§13.3).
                return Err(RootStoreError::Backend(format!(
                    "range read: offset {offset} is at or past the {BIN_MAX_BYTES}-byte ceiling"
                )));
            }
            // **`end > BIN_MAX_BYTES` is NOT a fifth row, and the asymmetry
            // with the row above is deliberate.** That row exists for a
            // DIVERGENCE, not for a saved round trip or an allocation bound:
            // §13.3 records that a server answers `416` for an over-ceiling
            // `first-pos` whether or not the bin exists, while the
            // in-process implementations of this trait answer `NotFound` for
            // an absent one — so a client that asked would disagree with
            // them. An extent that merely ENDS past the ceiling has no such
            // divergence: it starts inside every legal object, §7.2's check
            // 2 declares "short is legal", and every implementation of the
            // seam short-reads it identically. Refusing it here would refuse
            // a request that is satisfiable in part — the documented
            // overhang short read — and §13.3's table is closed, so a fifth
            // row is a protocol change and not a client fix.
            //
            // Nothing is allocated from `len` either. The buffer is sized by
            // the SERVED width, which check 4 bounds to `BIN_MAX_BYTES`
            // before a byte is read, so a `Range` asking for 4 GiB buys an
            // attacker a refusal and not a 4 GiB `Vec`.
            let Some(last) = end.checked_sub(1) else {
                // Unreachable — `len != 0` above makes `end >= 1`. Refused
                // rather than subtracted, so no arithmetic on an adversarial
                // extent can panic under `overflow-checks`.
                return Err(RootStoreError::RangeOverflow);
            };
            // The int-range with both positions — the one form §7.1 maps to
            // `(offset, len)` without a clamp. Both numbers are decimal
            // digits, so this conversion cannot fail; it is handled anyway,
            // because "cannot fail" is not the same as "will not panic".
            let header = HeaderValue::from_str(&format!("bytes={offset}-{last}"))
                .map_err(|e| RootStoreError::Backend(format!("range header: {e}")))?;
            Ok(Self {
                offset,
                end,
                header,
            })
        }

        /// The requested `first-pos`.
        pub(super) fn offset(&self) -> u64 {
            self.offset
        }

        /// The requested end, EXCLUSIVE.
        pub(super) fn end(&self) -> u64 {
            self.end
        }

        /// The `Range` field value that asks for exactly this extent.
        pub(super) fn header(&self) -> HeaderValue {
            self.header.clone()
        }
    }
}

/// The seam's refused-response error, spelled once — always
/// [`RefusalKind::Extent`], because every call site is
/// [`HttpStore::get_bin_range`]'s own extent gate (`content_range_of`,
/// `extent_gate`, and the body/extent match this function's own callers
/// run): a ranged read's answer that does not match the extent it asked
/// for.
fn refused(reason: &str) -> RootStoreError {
    RootStoreError::RefusedResponse {
        reason: reason.to_owned(),
        kind: RefusalKind::Extent,
    }
}

/// EXTENT-GATE CHECK 0, the field half: exactly one `Content-Range`, valid
/// UTF-8, matching §7.2's grammar.
fn content_range_of(resp: &Response<Incoming>) -> Result<(u64, u64), RootStoreError> {
    let mut fields = resp.headers().get_all(CONTENT_RANGE).iter();
    let (Some(raw), None) = (fields.next(), fields.next()) else {
        return Err(refused("a 206 must carry exactly one Content-Range field"));
    };
    raw.to_str()
        .ok()
        .and_then(parse_content_range)
        .ok_or_else(|| refused("Content-Range is not `bytes first-last/*`"))
}

/// EXTENT-GATE checks 1–4 (§7.2). Check 0 has already run — it is
/// `parse_content_range`, and it is a precondition of the arithmetic here.
///
/// `req` carries the caller's requested extent end, EXCLUSIVE;
/// `served_last` is the response's `last-pos`, INCLUSIVE (RFC 9110
/// §14.1.2). Counting them the same way is wrong by exactly one byte on
/// every ranged read, so the comparison is `served_last + 1 <= end`.
///
/// Taking a [`RequestedExtent`] rather than two `u64`s is the lock: the
/// only way to obtain one is `RequestedExtent::new`, so a ranged read that
/// skipped §13.3's rows has nothing to call this with.
fn extent_gate(
    req: &RequestedExtent,
    first: u64,
    served_last: u64,
) -> Result<usize, RootStoreError> {
    let (offset, end) = (req.offset(), req.end());
    // CHECK 1: the first position must be the one asked for. Width alone
    // is not enough — a backend that ignored the range answers `0-99` for
    // a request at offset 10, whose width is right and whose bytes are a
    // WRONG SLICE.
    if first != offset {
        return Err(refused(
            "206 Content-Range starts somewhere other than the requested offset",
        ));
    }
    let Some(served_end) = served_last.checked_add(1) else {
        return Err(refused("206 Content-Range last-pos overflows"));
    };
    // CHECK 2: not past the requested extent. Short is legal (the
    // overhang short-read); long is not.
    if served_end > end {
        return Err(refused(
            "206 Content-Range reaches past the requested extent",
        ));
    }
    let Some(width) = served_end.checked_sub(first) else {
        return Err(refused("206 Content-Range is reversed"));
    };
    // CHECK 3: a zero-width extent in answer to a request for real bytes.
    // Unreachable over the wire once check 0 has passed — `incl-range` is
    // inclusive at both ends — and REQUIRED anyway: an implementation of
    // this seam that computes the width by saturating subtraction turns a
    // reversed extent into a zero-width one, and if check 0 is ever
    // softened this is the guard that still catches it.
    if width == 0 {
        return Err(refused("206 declares a zero-width extent"));
    }
    // CHECK 4: refused, never clamped. No legal object can produce a
    // wider extent, and clamping would still admit a 256 MiB transfer for
    // a response already known to be impossible.
    if width > BIN_MAX_BYTES {
        return Err(refused("206 declares an extent wider than BIN_MAX_BYTES"));
    }
    // Bounded by `BIN_MAX_BYTES` (256 MiB) above, so this fits every
    // platform this workspace builds for — and it is a fallible conversion
    // regardless, because "cannot happen" is not the same as "will not
    // panic".
    usize::try_from(width).map_err(|_| refused("206 extent does not fit this platform"))
}

#[cfg(test)]
mod tests;
