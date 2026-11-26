// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// @file-disposition: STAYS — HTTP admission, resource accounting and response construction share the lifetime of one request; publish wire conversion lives in adapter/publish.rs.

//! The hyper adapter: the layer that meets
//! `granary_net::accept::serve`'s `Service<Request<Incoming>>` bound
//! with the policy layer behind it.
//!
//! The adapter composes head admission, the write-only principal and
//! controls gate, body acceptance, and seam dispatch. `admission` owns
//! the target, method and conditional rules; `principal` owns current
//! enrollment; `controls` owns per-principal `429` refusals. Reads bypass
//! the latter two gates. The adapter counts arriving content and orders
//! body-bound, byte-rate and shared-budget refusals before retaining bytes.
//! `handlers` owns verification and the store's answer.
//!
//! **Targets are never decoded, normalised, folded or trimmed.** §4.3 requires a
//! target to reach the grammar as bytes, so the request target's whole
//! path-and-query is handed over verbatim — a query is bytes no grammar
//! accepts, never a component to strip — `Range` arrives as EVERY field
//! line rather than the first, and the field NAMES go over unfiltered:
//! the adapter maintains no list of which names are conditional, because
//! a set the caller picks is not a set.
//!
//! **Hyper stops here.** No type from hyper or `http` escapes this
//! module into `admission`, `handlers` or `wire`, which is what keeps
//! the ordered gate exercisable with no HTTP anywhere.
//!
//! # Per-request instrumentation, at its true strength
//!
//! **For a baseline event the subscriber's FILTER admits, DISPATCH is EXACT and
//! the rendered line is BEST-EFFORT.** That sentence is the whole claim.
//! The leading clause is load-bearing rather than throat-clearing — the
//! shipped subscriber has an `EnvFilter` and it sits ABOVE everything
//! below — and the rest of this section is what makes the sentence true
//! rather than reassuring.
//!
//! Every request opens one `grain_request` span (`request_id`, a
//! BUCKETED `method`, and an optional bounded `wire_request_id`) and emits
//! exactly one `served` event at INFO
//! carrying the wire `status`, §8.2's `error` token where there is one,
//! the `bytes` served, the `overflowed` tear-down bit and the bounded
//! `operation` name. `tracing` hands that event to every registered
//! Layer SYNCHRONOUSLY, on the calling thread. The observer outside fmt sees
//! every request after the writer has accepted or discarded its line,
//! including while the sink is dropping. **For baseline events BELOW the filter,
//! the loss in this process sits at exactly one place**: `LossyStderr`'s
//! `LossyLine::flush`, inside the `fmt` Layer's own `on_event`,
//! downstream of that fan-out. Nothing between the callsite and that
//! flush samples, buffers or coalesces.
//!
//! **The filter is ABOVE the fan-out, and it is not a stderr knob.**
//! `host_subscriber` builds the subscriber under one immutable ceiling, fed
//! from `RUST_LOG` and defaulting to INFO. An `EnvFilter` in that
//! position is the OUTERMOST Layer, and the outermost Layer decides
//! CALLSITE INTEREST for the whole stack: `Layered::register_callsite`
//! goes through `pick_interest`, which returns an outer
//! `Interest::never()` unchanged instead of asking its inner half. So
//! `RUST_LOG=granary_server=warn` does not quieten stderr while the
//! counters keep counting — it stops the `served` callsite firing at
//! all, and every Layer beside `fmt`, a Phase-2 exporter included,
//! receives nothing. There is no arrangement of Layers under that filter
//! which recovers the event.
//!
//! **So an exporter that must not lose events cannot sit under a filter
//! tuned for stderr verbosity.** Stated as a deployment obligation
//! rather than a caveat, it is one of two things: either the process
//! directive stays at or below the level the exporter needs (INFO is the
//! default, and `RUST_LOG` is what an operator raises), or the exporter
//! carries its OWN per-layer `Filter` and the `RUST_LOG` one moves down
//! onto the `fmt` Layer — `pick_interest`'s FIRST branch is
//! `has_layer_filter`, under which the short-circuit above does not
//! happen at all and the global interest becomes the union of the
//! per-layer answers. The host retains the global ceiling; adding an exporter
//! requires an explicit choice about its relationship to that ceiling.
//!
//! `instrumentation_the_env_filter_above_the_stack_suppresses_the_event_for_every_layer`
//! measures restrictive directives on the production constructor. Other rows
//! use that same stack with an explicit TRACE ceiling.
//!
//! **What the exactness buys, and no more.** A Phase-2 exporter is a
//! Layer added beside `fmt`, reading every `grain_request`/`served`
//! event the filter admits with zero loss. What it does NOT buy is the
//! stderr LINE: a dropped line is dropped, and the sink counts the loss
//! in the stream rather than recovering it. So "the counters are exact"
//! means the EVENTS a counter is built from are exact, for the levels
//! the deployment admits. The rendered log is best-effort and is not a
//! counting substrate.
//!
//! **The span TIMINGS cost a second queue slot per request — a price,
//! recorded, not a free field.** `FmtSpan::CLOSE` renders one extra line
//! per request: measured on a `GET` refusal with no request id, 335 bytes for
//! the `served` line alone and 573 for the pair, so the timing line is ~238 bytes
//! and — the part that matters — ONE more slot. When present, `wire_request_id`
//! adds at most 64 bytes of peer input (rendered twice per JSON line, under `span`
//! and `spans`, adding at most 2 × (18 + 64) ≈ 164 bytes per line or ~328 bytes
//! across the pair). `sink::QUEUE_LINES` bounds
//! the sink at 1024 LINES with no byte bound, so behind a stalled writer
//! the queue holds 512 requests' worth of records where the counter
//! alone would hold 1024: **under load the timing line and the counter
//! line compete for the same bounded queue, and the depth at which
//! `served` lines start being discarded is halved on a request the seam
//! ANSWERS.** The sink cannot arbitrate — it sees opaque `Vec<u8>`s in
//! one FIFO and cannot tell an outcome line from a timing line — and
//! nothing else implements a priority either.
//!
//! **On a store-FAILING request the depth is not halved but THIRDED, and
//! that is the figure that matters.** The handlers render one `internal failure`
//! line from three sites in `handlers` — `log_seam_failure` for a store
//! that REPORTS a failure, `contract_violation` for one that reports
//! success and breaks a pinned rule, `codec_failure` for this process's
//! own environment — so such a request renders THREE lines: `internal
//! failure`, `served`, then the `FmtSpan::CLOSE` line. Against the same
//! 1024 slots that is 341 requests' worth of records behind a stalled
//! writer, not 512. The failure figure is the one to plan against, because the
//! outage that produces the extra line is the same class of event that
//! stalls the writer. `log_seam_failure`'s doc in `handlers.rs` carries the
//! acceptance argument from that side; the queue still gives outcome lines no priority.
//!
//! The ordering DOES matter: a discarded `served` costs the status, the
//! token, the operation and the overflow bit, which is the whole
//! counting substrate, while a discarded close costs a duration no instrumentation
//! row asks for. On a request the seam ANSWERS, emission order happens
//! to favour the outcome line — `served` goes first and the span closes
//! after it, so a slot freeing up mid-request helps the line worth
//! keeping — and that is an accident, not a mechanism. **On a
//! store-failing one the accident runs the other way**: `seam_failure`
//! calls `log_seam_failure` BEFORE it returns an `Outcome`,
//! so the diagnostic is emitted AHEAD of
//! `served` and takes a slot `served` would have had. The subscriber uses
//! `FmtSpan::CLOSE`, so this is written down rather than changed;
//! `instrumentation_the_close_span_event_makes_two_rendered_lines_and_a_seam_failure_three`
//! pins BOTH counts exactly — two on a served request, three on a
//! store-failing one, each in its real emission order — so neither a
//! further line nor a reordering can arrive silently.
//!
//! **The shutdown path still forbids a BLOCKING write.**
//! `granary_net::accept::serve` remains log-free from
//! shutdown-observed to outcome; neither constraint is disturbed here. A
//! synchronous Layer dispatch is not a blocking log — it borrows the
//! calling thread for the Layers' own work and never for a write to a
//! destination someone else controls. The one destination that could
//! block is behind the sink's bounded queue, keeping destination writes
//! off the calling thread.
//!
//! Scoped authenticated-request DEBUG output has additional intentional gates:
//! current event-field scope, remaining budget, a nonblocking shared state guard
//! and bounded encoding. These gates do not suppress baseline `served` events.
//! Capture lines compete with baseline and CLOSE lines in the same queue with
//! no priority. The host owns fmt and excludes the capture event from generic
//! formatting, so each accepted capture has only one bounded output route.
//!
//! **No duration comes from a `Clock`.** `FmtSpan::CLOSE` computes
//! `time.busy`/`time.idle` from an `Instant` pair INSIDE
//! `tracing-subscriber`, so no call site in this workspace reads a clock
//! and the `Clock` seam is untouched. It is also the right source: a duration
//! differenced from two wall-clock timestamps is NTP-steppable and can
//! come out negative. The server implements no `Clock` to read anyway.
//! `request_id` is a plain `AtomicU64::fetch_add` — neither a clock nor
//! an RNG, so it trips no seam either.
//!
//! **`operation` AND `overflowed` are what make a mis-set limit
//! countable — `operation` alone is not.** `status` + `error` cannot
//! separate an ingest decompressed-sum refusal from a per-kind body cap: both are
//! `413` + `too-large`, and on a bin both are `put_bin`. The cap stops
//! reading and tears the connection down (`overflowed` set); a refusal
//! that came back from the seam had its content read whole (`overflowed`
//! clear). That pair is the discriminator.
//!
//! **A request whose future is DROPPED mid-flight has a span close and
//! no `served` event, and the absence is the record.** The peer went
//! away, nothing was rendered, and there is no status to count — but the
//! span still closes when the `Instrumented` future is dropped, so the
//! pair "a `grain_request` opened, no `served` followed" is exactly the
//! abandoned request. Nothing here invents a status for it.
//!
//! **Fields have a closed domain, a machine-generated value, or an explicit
//! wire bound.** `wire_request_id` accepts a single value of at most 64 ASCII
//! letters, digits, dots, underscores or hyphens; malformed values are omitted,
//! and the field is never a metric label or counter key.
//! `status` is a `u16`, `bytes` a `u64`, `overflowed` a `bool`,
//! `request_id` a counter, `error` one of §8.2's tokens and `operation`
//! one of [`Operation::name`]'s closed set. The request TARGET appears in no
//! field on the span or the event: it is attacker-controlled with no
//! bound this layer sets, so a peer choosing it would be choosing how
//! much this process writes per request. `method` and `wire_request_id`
//! are the two fields a peer touches. `wire_request_id` is bounded to at
//! most 64 ASCII bytes as described above; `method` goes through
//! [`method_label`] — RFC 9110's eight methods plus `PATCH` rendered as
//! themselves, everything else as one fixed label — which makes the field a
//! `&'static str` from a closed domain.
//!
//! **Bucketing it is not decoration; verbatim it was an amplifier.** RFC
//! 9110's `method` is a bare token with no length rule, so the nearest
//! bound above this layer is hyper's: the h2 leg's
//! `max_header_list_size` (16 KiB, `granary_net::accept`) or the h1
//! leg's read buffer (hyper 1.11's `DEFAULT_MAX_BUFFER_SIZE`, `8192 +
//! 4096 × 100` = 417 792 bytes; `granary_net::accept::envelope` sets no
//! `max_buf_size`). Neither is a log bound, and the render MULTIPLIES
//! what it is given: the JSON formatter writes a span's fields twice per
//! line (once under `span`, once under `spans`) and `FmtSpan::CLOSE`
//! makes two lines, measured at **300 551 rendered bytes for a 100
//! 000-byte method** — on a request refused `405` before any
//! authentication. Against a queue bounded in LINES and not in bytes,
//! that turns 1024 slots into hundreds of megabytes a peer sizes. The
//! unbounded `method` field left the domain open; the domain is
//! closed here for the same reason as `path`:
//! attacker-controlled cardinality lets a peer inflate log volume, and
//! nothing diagnostic is lost: a method outside §4.2's three is a `405`
//! whose `Allow` says what was permitted.

mod status;

use crate::authority::{AuthorityHandle, Submission};
use crate::config::authority::AuthorityConfig;
use crate::controls::{PrincipalControls, WritePermit};
use crate::enrollment::EnrollmentReader;
use crate::principal::{WritePrincipal, resolve_write_principal};
use crate::refusals::RefusalCounters;
use granary_core::enrollment::PrincipalId;
use granary_core::root::VolumeName;
use std::collections::BTreeSet;
pub(crate) mod publish;
use hyper::http::Extensions;
use std::convert::Infallible;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::Poll;
use std::time::Duration;

use granary_core::binfmt::BIN_MAX_BYTES;
use granary_core::binstore::BinStore;
use granary_core::rootstore::{RootStore, SEQ_KEY_DIGITS};
use granary_net::accept::SHUTDOWN_DEADLINE;
use granary_store::bounds::{META_MAX_BYTES, ROOT_MAX_BYTES};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Incoming};
use hyper::header::{
    ALLOW, CACHE_CONTROL, CONNECTION, CONTENT_RANGE, CONTENT_TYPE, ETAG, HeaderName, HeaderValue,
    IF_NONE_MATCH, RANGE, RETRY_AFTER,
};
use hyper::service::Service;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use tokio::sync::{Semaphore, SemaphorePermit, watch};
use tokio::time::timeout;
use tracing::Instrument as _;

use crate::admission::{
    Admitted, Conditionals, DECLARED_MAX_EXTENT, Operation, RequestHead, admit_authority,
    is_intent_target, is_publish_target, is_status_target,
};
use crate::handlers::dispatch;
use crate::policy::VerifyPolicy;
use crate::wire::{Outcome, Status};

// ------------------------------------------------------------- the drain

/// How many bytes of request content a refusal will read and discard
/// before it stops reading and tears the connection down.
///
/// The largest write body (`BIN_MAX_BYTES`) does not size this budget:
/// an accepted write never reaches the refusal drain.
///
/// **The drain handles refusals and content sent with reads.** What
/// reaches it is a request the GATE refused — a target that is not
/// a resource, a method that is not defined, a conditional field this
/// profile does not accept — plus a read that carried content nobody
/// asked for. Every one of those is a request no conforming client
/// sends at all, so the budget is not covering a legitimate write; it is
/// bounding how much of a misdirected one this server will read before
/// hanging up. An accepted write does not come through here: it goes
/// through [`accept_body`], under the per-kind cap its own endpoint
/// declares.
///
/// The equality below therefore survives as a TRIPWIRE rather than as a
/// derivation: `ROOT_MAX_BYTES` is the smallest of the three write caps,
/// so a drain at that figure cannot be larger than any body the accept
/// path would take, and a move of the bound surfaces here to be re-read
/// rather than silently changing what a refusal costs.
pub(crate) const DRAIN_BUDGET_BYTES: u64 = 65_536;

const _: () = {
    assert!(
        DRAIN_BUDGET_BYTES == ROOT_MAX_BYTES,
        "the drain budget is pinned to the smallest write cap; a bound \
         that moved must be re-read here, not silently followed"
    );
    // The relation the sentence above rests on, so "smallest" is checked
    // rather than remembered.
    assert!(ROOT_MAX_BYTES <= META_MAX_BYTES && ROOT_MAX_BYTES <= BIN_MAX_BYTES);
};

/// How long the WHOLE drain may take.
///
/// The other half of the bound, and the half a byte budget cannot
/// supply: a peer that drips one byte at a time stays under
/// [`DRAIN_BUDGET_BYTES`] forever, and an unbounded drain is an
/// unauthenticated tarpit — connections × streams, each held open by a
/// peer doing nothing but proving it is alive.
pub(crate) const DRAIN_MAX_WAIT: Duration = Duration::from_secs(2);

/// How the drain ended, which is what decides whether the response
/// carries a tear-down signal (§5.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Drain {
    /// The request content ended inside both bounds. No early answer
    /// exists, §5.5 is never engaged, and the connection stays reusable.
    Drained,
    /// A bound was exceeded and the rest of the content is dropped
    /// unread. The response is signalled: `Connection: close`.
    Overflowed,
}

/// Read the request content to its end and DISCARD it, bounded by
/// [`DRAIN_BUDGET_BYTES`] and [`DRAIN_MAX_WAIT`].
///
/// **Nothing is accumulated.** Frames are counted and dropped; there is
/// no buffer here to grow, which is what makes this safe to run before
/// the layer that will one day accept a body.
///
/// **ONE clock for the whole drain.** The timeout wraps the entire loop
/// and is never constructed per frame read: a per-frame bound is
/// re-armed by every arriving byte, so a peer that sends one byte inside
/// each window holds the connection forever and the bound never fires.
/// That peer is precisely the tarpit this exists to exclude.
///
/// A read ERROR ends the drain as `Drained`. It is neither of the two
/// bounds this function enforces — the peer broke its own request — and
/// nothing was accumulated either way, so the transport is left to draw
/// its own conclusion about a connection whose content stream failed.
///
/// **Every frame this reads is also counted
/// into `budget`, the same [`WriteBudget::record_frame`] call
/// [`accept_body`]'s own loop makes.** This function is a SECOND
/// frame-reading site: without counting here, a frame could arrive
/// on the wire, be read to completion, and never reach the
/// process-wide counter — an admission refusal, a shed, or a
/// read's own trailing body all drain here, never through `accept_body`,
/// and the bytes they read are real. That is the undercount
/// `record_frame`'s own doc names the fail-open direction for; the ONE
/// documented exemption is `accept_and_dispatch`'s declared-length fast
/// path, which returns before a byte is read and never calls this
/// function at all. Every call site of `drain_to_budget` reaches a
/// `WriteBudget` — the declared-length fast path is the only body-bytes
/// arm that has none to reach, because it has no bytes.
async fn drain_to_budget<B: Body + Unpin>(body: B, budget: &WriteBudget) -> Drain {
    match timeout(DRAIN_MAX_WAIT, drain_frames(body, budget)).await {
        Ok(drain) => drain,
        Err(_expired) => Drain::Overflowed,
    }
}

/// The drain loop itself, with no clock of its own.
async fn drain_frames<B: Body + Unpin>(mut body: B, budget: &WriteBudget) -> Drain {
    use hyper::body::Buf;

    let mut counted: u64 = 0;
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return Drain::Drained;
        };
        if let Some(data) = frame.data_ref() {
            // Saturating, and the direction is the safe one: a count
            // that could wrap would restart the budget at zero.
            let arrived = u64::try_from(data.remaining()).unwrap_or(u64::MAX);
            // Counted AT THE FRAME, mirroring
            // `accept_body`'s own `record_frame` call — before this
            // loop's own cap comparison, and on both of this function's
            // outcomes, never only on `Drain::Drained`. See this
            // function's own doc for why a drained frame must reach the
            // process-wide counter exactly as an accepted one does.
            budget.record_frame(arrived);
            counted = counted.saturating_add(arrived);
            if counted > DRAIN_BUDGET_BYTES {
                return Drain::Overflowed;
            }
        }
    }
    Drain::Drained
}

// ------------------------------------------------------- the accept path

/// How long the WHOLE accept of an admitted write may take.
///
/// **Distinct from [`DRAIN_MAX_WAIT`], and the two are not
/// interchangeable.** The drain covers a refusal body a conforming
/// client never sends, bounded at 64 KiB; the accept covers up to
/// `BIN_MAX_BYTES` of content a conforming client is entitled to send.
/// Two seconds there would refuse every large legitimate bin, and thirty
/// seconds here would hold a refused connection fifteen times longer
/// than the tarpit bound allows.
///
/// Thirty seconds asks about 8.5 MB/s of a peer uploading a maximal bin
/// — well inside any link a publish is worth doing over. It SHOULD
/// become configurable; until then it is a constant, and a constant is
/// what the process test can reason about.
///
/// **It is LONGER than [`SHUTDOWN_DEADLINE`].**
/// A peer trickling one byte a second can remain on the machine for
/// the whole thirty-second accept interval. The drain deadline expires
/// at ten seconds with the connection still resident. The accept is
/// therefore still live when draining runs out of time, which forces
/// the exit path that exists for undrained work.
/// Shortening the accept clock to fit under the shutdown deadline would
/// refuse every large conforming bin. Lengthening the shutdown deadline
/// would make every deploy wait out the slowest upload it happens to
/// catch.
///
/// So the clock is NOT what keeps an upload from outliving a shutdown.
/// [`until_draining`] is: an accept in flight when the drain begins is
/// abandoned and shed at once, which is the same answer this crate's
/// transport already gives a connection that is still handshaking.
///
/// **Shortened under `#[cfg(test)]`**, because the accept-timeout negative is a
/// flood that has to outlast the bound and thirty seconds of it is a
/// test nobody runs. The shipped value is
/// [`WRITE_ACCEPT_MAX_WAIT_SHIPPED`] and a row pins it, so the
/// substitution cannot quietly become the deployment's.
#[cfg(not(test))]
pub(crate) const WRITE_ACCEPT_MAX_WAIT: Duration = WRITE_ACCEPT_MAX_WAIT_SHIPPED;
#[cfg(test)]
pub(crate) const WRITE_ACCEPT_MAX_WAIT: Duration = Duration::from_millis(750);

/// The value a shipped server runs (see [`WRITE_ACCEPT_MAX_WAIT`]).
pub(crate) const WRITE_ACCEPT_MAX_WAIT_SHIPPED: Duration = Duration::from_secs(30);

/// How many bytes of request content this PROCESS will hold across all
/// in-flight writes at once.
///
/// **A byte budget and not a request count, because the quantity at risk
/// is memory.** Without one, the bound on what a node holds resident is
/// the product of every connection and every stream it will accept
/// against the largest body each may send — a figure in the hundreds of
/// terabytes, which is to say no bound at all.
///
/// **What two gibibytes admits is decided by what was SENT, never by
/// which endpoint was addressed**, and the two constants have to be read
/// together: eight concurrent maximal bins, or some thirty-two thousand
/// writes with a [`WRITE_BUDGET_GRANULE_BYTES`] on the wire each, and
/// every mixture in between.
/// Charging the endpoint kind's worst case would instead admit only eight
/// writes of any size. The charge follows the granules that arrived, so a
/// small body costs one granule rather than a maximal body's reservation.
///
/// A FIELD on the service rather than a process static: a test needs a
/// budget it can fill, and a static would make "fill the budget" mean
/// two gibibytes of test.
pub(crate) const WRITE_BODY_BUDGET_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The unit the write budget is charged in, as content arrives.
///
/// **The charge tracks bytes that LANDED, so the unit is a trade rather
/// than a detail.** Per frame is a compare-and-swap on the process's
/// most contended atomic for every 16 KiB an HTTP/2 peer sends. Per body
/// is the endpoint kind's worst case — which charges a one-kilobyte
/// upload 256 MiB, admits exactly eight writes of any size, and lets
/// eight streams that send a byte and stall shed every other write on
/// the server. The granule fixes both ends at once: a peer holds at most
/// one granule it has not sent, and the atomic is touched once per
/// granule, so a maximal bin costs 4096 charges against a gibibyte of
/// hashing.
///
/// Sixty-four kibibytes is `ROOT_MAX_BYTES`, the smallest write cap, and
/// that is the reason for the figure rather than a coincidence: a root
/// or a hint is charged exactly ONCE for its whole body — the same count
/// the worst-case reservation cost it — so the small kinds pay nothing
/// for the change and only the large ones charge more than once. The
/// relations are asserted below rather than remembered.
pub(crate) const WRITE_BUDGET_GRANULE_BYTES: u64 = 64 * 1024;

/// How long an admitted write may wait for a verify permit before it is
/// shed `503` + `unavailable` (§5.10).
///
/// **An acquire with no bound is not a bound.** The permit is
/// deliberately smaller than the connection count, so a saturated server
/// makes the next write queue — and the queue is drawn from every write
/// the budget admits, which is thousands once the charge is what
/// arrived rather than the kind's worst case. A request parked there
/// holds the bytes it already read, its connection and its place in the
/// drain, for however long the whole queue ahead of it takes.
///
/// **Half [`SHUTDOWN_DEADLINE`], and that is the derivation.**
/// Verification is bounded work (the ingest decompressed-sum limit sees
/// to that), so a write that takes the permit at the last legal moment
/// still has the other half of the deadline for the verify that follows.
/// A queue that has not cleared in five seconds is a server that is CPU
/// saturated rather than momentarily busy, and §5.10's `unavailable` is
/// the honest answer to that — telling the client to come back costs it
/// a re-upload, and waiting costs it the same re-upload after a much
/// longer silence.
pub(crate) const VERIFY_PERMIT_MAX_WAIT: Duration = Duration::from_secs(5);

const _: () = {
    // The divisor in `charge_target`, and the smallest thing the budget
    // can hold: a granule larger than the budget admits no write at all.
    assert!(WRITE_BUDGET_GRANULE_BYTES > 0);
    assert!(WRITE_BUDGET_GRANULE_BYTES <= WRITE_BODY_BUDGET_BYTES);
    // The claim the doc above makes about the small kinds. A `>=`, so a
    // cap that shrank keeps it and a cap that grew surfaces here.
    assert!(
        WRITE_BUDGET_GRANULE_BYTES >= ROOT_MAX_BYTES,
        "a root is charged once for its whole body, or the sentence above \
         is false"
    );
    // The permit queue's own derivation, pinned against the deadline it
    // is derived from rather than restated as a number.
    assert!(
        VERIFY_PERMIT_MAX_WAIT.as_secs() <= SHUTDOWN_DEADLINE.as_secs() / 2,
        "a write that takes the permit at the last legal moment must still \
         have the deadline's other half for the verify that follows"
    );
};

/// The aggregate bytes this process may hold in RENDERED READ RESPONSES
/// at once.
///
/// **The read-side twin of [`WRITE_BODY_BUDGET_BYTES`], and it bounds a
/// resource nothing else in this process bounds.** A `GET
/// {base}/bin/{digest}` with a `Range` collects its extent into an owned
/// buffer, and the buffer stays resident while HTTP/2 flow control drains
/// it at the CLIENT's pace. Every control in the transport envelope is a
/// COUNT — 8192 connections, 100 streams each — and their product with
/// §7.1's declared maximum extent is about 58 TiB, which is to say no
/// bound at all: a hundred streams on one connection already retain
/// several gibibytes, and the process dies.
///
/// **HALF the write budget, and that buys MORE requests rather than
/// fewer.** A write's residency is bounded by `BIN_MAX_BYTES`
/// (268 435 456), a read's by [`DECLARED_MAX_EXTENT`] (78 479 383) — so
/// where two gibibytes admits eight concurrent maximal WRITES, one
/// gibibyte admits thirteen concurrent maximal READS, and a great many
/// more of the small ones: a `404`, a `max-seq` and a 707-byte root
/// charge 0, 20 and 707 bytes respectively, because what is charged is
/// what came BACK.
///
/// **A FIELD on the service rather than a process static**, for
/// [`WRITE_BODY_BUDGET_BYTES`]'s reason: a row needs a budget it can
/// fill, and a static would make "fill the budget" mean a gibibyte of
/// test.
pub(crate) const READ_BODY_BUDGET_BYTES: u64 = 1024 * 1024 * 1024;

/// Shared admission count for ranged bin reads, meta reads and authenticated
/// intent readback before store or authority dispatch.
///
/// **This is the bound on what the byte budget cannot see.** The charge
/// is taken on the buffer that came BACK, which is the only figure a peer
/// does not get to declare — but between entering the store and returning,
/// a read is allocating with nothing accounting for it. Reserving the
/// DECLARED extent up front instead fails for the following reason:
/// a reservation sized by a number the peer declares and held for a
/// duration the peer controls is an availability weapon, not a memory
/// bound. A count does not have that property, so a `GET` for an absent
/// digest, or a four-kilobyte read, costs one permit for the length of the
/// store call and nothing else.
///
/// **Eight, with the assertions below bounding the choice.** The
/// per-read model puts the allocator peak at three times the declared
/// extent, and the permitted-pool assertions bound that peak.
///
/// **What an operator has to provision FOR THIS PATH, because nothing
/// else in this process will say it.** [`READ_TRANSIENT_PEAK_BYTES`]
/// states the per-read peak as an upper bound over the model and
/// [`PERMITTED_READ_TRANSIENT_CEILING_BYTES`] the whole permitted path's:
/// 1 883 505 192 bytes, 1.75 GiB, of allocator high-water that NEITHER
/// budget accounts for. A host sized at the two budgets alone meets the
/// OOM killer at the moment eight maximal reads coincide. It is a FLOOR
/// on what the process holds and not the figure itself — the operations
/// that take no permit are absent from it — and that constant's own
/// comment names which and why.
///
/// **Why the permit count is not derived from the read budget alone.** The
/// two quantities are not comparable one for one: the budget bounds bytes
/// held for a duration the PEER sets, flow control at its own pace up to
/// the connection lifetime, and this is an allocator spike inside a
/// store call bounded by the dispatch deadline, at its peak for the
/// length of one `realloc`. Halving the read concurrency of the whole
/// process so that a microsecond spike fits inside a five-minute
/// residency budget prices the wrong risk. What the count IS held to is
/// asserted below and stated here: no single read may peak past the
/// whole read budget, and the PERMITTED PATH's spike may not exceed
/// everything the two budgets do account for — which caps the count at
/// thirteen, not at eight, so eight is a choice inside a stated bound
/// and the paragraph above is the trade it takes.
///
/// **What it costs, stated rather than discovered:** eight is also the
/// concurrency ceiling on the permitted reads — ranged, meta and authenticated
/// intent readback, which contend for the same slots. It bounds concurrent
/// admitted work, not request rate, fairness or worker utilization. Against a network store whose
/// per-call latency dominates, that is a throughput bound as well as a
/// memory bound, and it is the trade this decision takes — an unbounded
/// transient is not the alternative, it is the defect. What NO text
/// states is a relation between this global 8 and the client fetcher's
/// per-client window (32 streams, AIMD floor 4): enough concurrent
/// clients at the floor can hold the pool saturated and a queued read
/// past the permit wait sheds 503, the designed answer to load. The
/// choice of permit count must account for that client-window relation.
///
/// **The residual extends beyond the ranged-read bound:** the
/// permit covers the RANGE path, the META path and authenticated intent
/// readback. The store-read bound was extended
/// with the measured fetcher profile in hand
/// once a `503` became a typed, backpressured answer rather than a hard
/// failure instead of a bare count picked inside a security fix. What
/// remains outside it: `GET root` and `max-seq`, the same transient
/// class with no count bound, held only by the envelope's connection
/// and stream counts — and `GET hint`, outside for the opposite
/// reason, its 20-byte reads too small to be a term at all.
/// These paths contribute different costs; see
/// [`PERMITTED_READ_TRANSIENT_CEILING_BYTES`]'s comment for what the
/// process figure would need and why no process-wide bound is stated.
pub(crate) const READ_PERMITS: usize = 8;

/// The allocator PEAK one ranged read reaches inside the store,
/// uncharged — an upper bound over the model, not the measurement.
///
/// **THREE TIMES [`DECLARED_MAX_EXTENT`], and the factor is the model
/// rather than a margin.** `granary_store::backend::collect_bounded`
/// reserves at most what it delivers — `range_alloc_hint` clamps the
/// reservation to one frame, and the walk refuses a body that does not
/// match its declared extent — so a buffer that outgrows its reservation
/// grows by amortised DOUBLING, which puts the grown capacity under
/// twice the delivered length. `shrink_to_fit` then reallocs down to the
/// exact length, and a `realloc` that moves the bytes holds the old
/// allocation and the new one at the same instant: capacity plus length,
/// hence under three times.
///
/// **The shipped store's own figures sit under it**: 134 742 160 grown
/// against 78 479 383 delivered, peaking at 213 221 543 — 2.72x. Stated
/// as the model and not as that measurement because the measurement is
/// one frame cap away from changing and the model is not; the row
/// `the_transient_figure_covers_the_stores_allocation_peak` recomputes
/// the measurement from the store's constants and fails if the model
/// ever stops covering it.
pub(crate) const READ_TRANSIENT_PEAK_BYTES: u64 =
    modelled_transient_peak(DECLARED_MAX_EXTENT as u64);

/// The 3x envelope over `granary_store`'s buffer behaviour for a read
/// capped at `cap`: reservation never exceeds the cap (one-frame clamp
/// on the range path; the advertised-size gate elsewhere), amortised
/// doubling keeps a grown capacity under twice the delivered length,
/// and the `shrink_to_fit` realloc holds old and new at once — capacity
/// plus length, hence under three times the cap.
///
/// Spelled ONCE so the two sites that certify against it — the ranged
/// peak above and the meta-member witness below — cannot drift apart.
/// It is still a TRANSCRIPTION of another crate's behaviour,
/// now covering both call sites rather than an exported model: the range
/// instance is recomputed from the store's constants by
/// `the_transient_figure_covers_the_stores_allocation_peak`, the meta
/// instance has no such row and rides the same model.
const fn modelled_transient_peak(cap: u64) -> u64 {
    3 * cap
}

/// The uncharged transient of the PERMITTED READ PATH: [`READ_PERMITS`]
/// reads, each at up to [`READ_TRANSIENT_PEAK_BYTES`] — the LARGEST
/// permitted member's per-read peak, the ranged read's.
///
/// **1 883 505 192 bytes — 1.75 GiB — and it is memory no budget in this
/// process accounts for.** The read budget bounds rendered response
/// bodies and the write budget bounds accepted request content; this is
/// neither. It is what the allocator is holding while up to eight
/// PERMITTED reads — ranged or meta — are inside the store at once, and
/// the figure exists as a constant so that a deployment sizing a host
/// has a number to add rather than a paragraph to infer one from.
///
/// **It is NOT the process-wide figure, and the name says so.** This
/// constant was declared as "the PROCESS-wide uncharged transient" and
/// certified as such by the `const _` below, which was false by
/// unbounded terms; that defect is fixed, and a narrower one remains by
/// design. The product's one count is [`READ_PERMITS`], and
/// [`takes_a_read_permit`] now spends it on `GET bin` AND `GET meta`
/// — but the per-read TERM stays the LARGEST permitted member's
/// peak, the ranged read's, because the meta member's own modelled peak
/// sits comfortably under it (a `const _` witness pins `3 *
/// META_MAX_BYTES <= READ_TRANSIENT_PEAK_BYTES`, ~4.7x under). So the
/// constant is the POOL's upper bound rather than a per-member exact
/// figure: it stops being TIGHT the moment a meta read holds a slot the
/// ranged-read peak alone would not have needed, though it remains a
/// bound. TWO store calls of this class still take no permit at all, so
/// no term of theirs appears here — `get_root` up to `ROOT_MAX_BYTES`,
/// 64 KiB, and `max_seq`, which walks an UNCAPPED listing whose own
/// comment argues that no cap can be chosen; `max_seq`'s
/// in-process fold is O(1) — one `u64` — so its currency is backend
/// round trips rather than resident bytes, but what the `ObjectStore`
/// beneath it buffers per listing is likewise unbounded here, and the
/// pinned in-memory one collects every matching key's metadata before
/// yielding. A third, `read_hint`, also takes no permit, but for the
/// opposite reason: its 20-byte reads sit below any term threshold this
/// constant would need to carry.
///
/// **What bounds `get_root` and `max_seq` is not a permit but the
/// transport envelope's COUNTS**, which is the "no bound at all"
/// argument [`READ_BODY_BUDGET_BYTES`] makes about rendered bodies:
/// `MAX_CONNECTIONS` x `H2_MAX_CONCURRENT_STREAMS` is 819 200 requests
/// in flight, and less than a tenth of that envelope already exceeds the
/// bound: `get_root` at 65 536 in flight is already 4 GiB against the
/// 3 GiB the assertion below certifies.
///
/// **So the PROCESS-wide uncharged transient still has no finite Phase-1
/// bound, and no constant in this file states one — resting now on
/// `get_root` and `max_seq` rather than on `get_meta` too.** The NUMBER
/// cannot be repaired merely by adding a partial control:
/// every partial remedy that would give it a bound was measured and
/// created a new denial, and "a permit on every dispatching operation"
/// is the one that lands on this constant — it would cap the
/// cheapest requests this server answers at eight in flight, which
/// [`takes_a_read_permit`] argues against on its own merits. Fixing
/// `get_meta` alone did not repair the process figure either:
/// `get_root`'s arithmetic above still exceeds the certified budgets on
/// its own. An operator sizing a host from this figure is provisioning
/// the PERMITTED READ path and nothing else; what bounds the rest is the
/// question of an unauthenticated peer's aggregate cost, which
/// includes unpermitted dispatches and uncapped listings, and which no
/// number in this module answers today.
pub(crate) const PERMITTED_READ_TRANSIENT_CEILING_BYTES: u64 =
    (READ_PERMITS as u64) * READ_TRANSIENT_PEAK_BYTES;

const _: () = {
    // A zero permit count is a server that answers no range at all, and a
    // `Semaphore::new(0)` parks every read forever with nothing saying so.
    assert!(READ_PERMITS > 0);
    // ONE read's spike, against the budget that will account for what the
    // spike settles into. A single read able to peak past the whole read
    // budget is a request the process cannot serve even when it is
    // otherwise idle, and the extent cap — not the permit count — would
    // be the thing to move.
    assert!(
        READ_TRANSIENT_PEAK_BYTES <= READ_BODY_BUDGET_BYTES,
        "one ranged read's allocator peak must fit under the budget that \
         accounts for what it becomes, or the extent cap is wider than \
         this process can answer at all"
    );
    // Bound the permitted pool's allocator peak against both body
    // budgets. This assertion covers the pool, not the whole process.
    assert!(
        PERMITTED_READ_TRANSIENT_CEILING_BYTES <= READ_BODY_BUDGET_BYTES + WRITE_BODY_BUDGET_BYTES,
        "the permitted pool's uncharged transient (permits x the largest \
         member's per-read allocator peak — the ranged read's; a meta \
         member's peak sits under it, witnessed below) must not exceed \
         what the two body budgets account for, or the numbers a \
         deployment is given are the smaller half of what the process \
         holds"
    );
    // A `get_meta` call shares the permit pool now, so the pool's
    // ceiling stays READ_PERMITS x the RANGED read's peak only while a
    // meta read's own modelled peak fits under that unit. The meta peak
    // reaches the 3x envelope by a DIFFERENT route from the range
    // read's one-frame reservation clamp: `get_bounded` reserves the
    // store's ADVERTISED size — refused before any body byte when it
    // exceeds `META_MAX_BYTES` — so the reservation never exceeds the
    // cap, doubling from an under-advertising store keeps capacity
    // under twice the delivered length, and the shrink realloc holds
    // both at once: under three times the cap, the same envelope
    // `modelled_transient_peak` spells for both members. This is the
    // premise the partition test's `permitted` row leans on (and that
    // row re-asserts it per permitted member, over whatever the
    // predicate admits); a member outgrowing the unit needs the CEILING
    // re-derived, not just this assert moved.
    assert!(
        modelled_transient_peak(META_MAX_BYTES) <= READ_TRANSIENT_PEAK_BYTES,
        "a meta read's modelled allocator peak must fit under one ranged \
         read's, or the permitted-path ceiling is no longer the pool's \
         upper bound with GetMeta sharing it"
    );
};

/// The ceiling on [`verify_permits`],
/// however many workers a host has.
///
/// Verification is bounded WORK, not unbounded work — the ingest
/// decompressed-sum limit sees to that — so the permit count does not
/// need to scale with the machine. What it needs to do is leave the
/// runtime able to answer reads, run timers and honour the shutdown
/// deadline while verifies are in flight, and four concurrent verifies
/// already saturate any deployment this profile targets.
pub(crate) const VERIFY_PERMITS_MAX: usize = 4;

/// How many bins this server verifies AT ONCE.
///
/// **`workers - 1`, floored at one and capped at
/// [`VERIFY_PERMITS_MAX`].** Verification runs inline on the
/// connection's worker — `spawn_blocking` is banned and there
/// is no clock the hashing loop could read to yield against — so a
/// verify OCCUPIES a worker for as long as it runs, up to a few seconds
/// on a maximal bin. The write-body budget bounds the MEMORY eight concurrent
/// writes hold and says nothing about the CPU they occupy; on a
/// small-vCPU host every worker can be inside a verify at once, and then
/// nothing answers a read, nothing fires a timer, and both ten-second
/// deadlines in `granary_net::accept` burn while the process looks
/// healthy.
///
/// Leaving one worker free is the whole design, and it is why a fixed
/// two would be wrong: on a two-worker runtime two permits let two
/// verifies occupy both workers, which is exactly the state this
/// prevents. The floor of one is for a single-worker runtime, where no
/// count can leave a worker free and refusing to verify at all would be
/// worse.
pub(crate) const fn verify_permits(worker_threads: usize) -> usize {
    let leaving_one_free = worker_threads.saturating_sub(1);
    if leaving_one_free < 1 {
        1
    } else if leaving_one_free > VERIFY_PERMITS_MAX {
        VERIFY_PERMITS_MAX
    } else {
        leaving_one_free
    }
}

/// How many worker threads a composition root should build its runtime
/// with — and hand to [`GrainService::new`], which derives the verify
/// permit count from the same number.
///
/// **Pinned rather than left to tokio's default**, even though the value
/// is the same one tokio would pick. The permit count is `workers - 1`,
/// so it is only correct if the two figures are the same figure; a
/// default read independently by the runtime and by this crate is two
/// figures that agree by coincidence, and a tokio release that changed
/// its default would break the relation with nothing saying so.
#[must_use]
pub fn worker_threads() -> usize {
    // Not a clock and not entropy: an environment fact, read once at
    // composition. A host that cannot report it gets one worker, which
    // is a server that runs rather than one that refuses to start.
    std::thread::available_parallelism().map_or(1, NonZeroUsize::get)
}

/// The global in-flight write-body budget.
///
/// Shared across every clone of the service — the accept loop clones one
/// per connection — so the bound is the PROCESS's and not a
/// per-connection allowance an attacker multiplies by opening
/// connections.
#[derive(Debug)]
pub(crate) struct WriteBudget {
    limit: u64,
    in_flight: AtomicU64,
    /// The process-wide count of request-body bytes that have
    /// ARRIVED (a frame landed), never what a peer declared and never
    /// what was charged or kept. Read only by [`WriteBudget::record_frame`]
    /// and the shutdown snapshot writer.
    ///
    /// **NEVER a `static`.** A process-global counter has no injectable
    /// start value, so the poison row below could never fire, and under
    /// a shared test process a global reads whatever the previous row
    /// left — "a fresh counter reads zero" would be meaningless. This
    /// field lives on the instance instead, which is why a fresh
    /// [`WriteBudget::new`] always reads zero.
    request_bytes: AtomicU64,
    /// How many write-cap requests actually reached [`accept_body`] —
    /// the companion to `request_bytes` that keeps a `0` total
    /// ambiguous between "no such request ever arrived" and "every such
    /// request's body was legitimately empty" (the same `Option`
    /// discipline the `served` event's own per-request field keeps).
    requests_with_body: AtomicU64,
    /// Sticky once an addition to `request_bytes` would have overflowed.
    /// The sentinel value ITSELF (`u64::MAX`, stored in `request_bytes`
    /// on the overflowing add) already makes every later add poison too
    /// — `checked_add` on `u64::MAX` is `None` for anything but `+0` —
    /// so this flag exists only so the snapshot writer has a single bit
    /// to read rather than re-deriving "was that MAX legitimate or
    /// poison" from the value alone.
    request_bytes_poisoned: AtomicBool,
    /// The process-wide sum of `served`'s own `bytes` field —
    /// response bytes PRODUCED, never confirmed received. The snapshot
    /// writer demotes this into `response_bytes_produced`; it is never
    /// a client-side total counted from response-body DATA frames and
    /// carries no poison state of its own (see [`WriteBudget::record_response_bytes`]).
    response_bytes_produced: AtomicU64,
}

impl WriteBudget {
    pub(crate) const fn new(limit: u64) -> Self {
        Self {
            limit,
            in_flight: AtomicU64::new(0),
            request_bytes: AtomicU64::new(0),
            requests_with_body: AtomicU64::new(0),
            request_bytes_poisoned: AtomicBool::new(false),
            response_bytes_produced: AtomicU64::new(0),
        }
    }

    /// [`WriteBudget::new`], with `request_bytes` starting at `start`
    /// rather than zero — the door the poison row (row d) needs:
    /// a counter constructed at `u64::MAX - 1` and fed 2 bytes must
    /// poison, and only an injectable start value can put it that close
    /// to the ceiling without two exabytes of real frames.
    #[cfg(test)]
    pub(crate) const fn new_with_request_bytes(limit: u64, start: u64) -> Self {
        Self {
            limit,
            in_flight: AtomicU64::new(0),
            request_bytes: AtomicU64::new(start),
            requests_with_body: AtomicU64::new(0),
            request_bytes_poisoned: AtomicBool::new(false),
            response_bytes_produced: AtomicU64::new(0),
        }
    }

    /// Count `bytes` that just ARRIVED as one DATA frame, toward the
    /// process-wide request-body total — called once per frame, from
    /// [`accept_body`]'s own loop, before that loop's cap comparison and
    /// budget charge and on every one of its five outcomes, never only
    /// on the success arm. See `accept_body`'s own doc for why: a
    /// refused, sheared or reset body still arrived.
    ///
    /// **A hand-written compare-and-swap loop,
    /// not `fetch_add`.** `fetch_add` WRAPS on
    /// overflow, which restarts the total near zero: the fail-open
    /// direction for a counter that feeds an UPPER-bound gate. On an
    /// overflow this stores the reserved sentinel `u64::MAX` and sets
    /// the sticky poison bit instead, and stops — every LATER call also
    /// finds `checked_add` refuse (`u64::MAX + n` overflows for any
    /// `n > 0`), so the poison cannot be un-set by a later, smaller add.
    ///
    /// **The poison FLAG is stored BEFORE the
    /// sentinel VALUE, not after.** [`WriteBudget::request_bytes`] reads
    /// flag-then-value (check the poison bit first; only trust the
    /// value if it says no). Storing value-then-flag left a window,
    /// between the two stores, where a concurrent reader could observe
    /// the sentinel `u64::MAX` with the flag still `false` and report
    /// it as a genuine (if enormous) total rather than as poisoned.
    /// Flag-then-value closes that: a reader who observes the flag set
    /// never reads the value at all, and a reader who observes it unset
    /// reads whatever value preceded this store, never the sentinel.
    /// Unreachable in practice — this counter needs 2^64 bytes to
    /// overflow even once — but the ordering costs nothing to correct.
    fn record_frame(&self, bytes: u64) {
        let mut current = self.request_bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                self.request_bytes_poisoned.store(true, Ordering::Release);
                self.request_bytes.store(u64::MAX, Ordering::Release);
                return;
            };
            match self.request_bytes.compare_exchange_weak(
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

    /// Count one request as having reached [`accept_body`] — called
    /// exactly once per call, regardless of that call's outcome. This is
    /// `requests_with_body`'s whole definition: not "a request that had
    /// a nonempty body", but "a request whose body `accept_body`
    /// actually counted".
    fn record_request_with_body(&self) {
        let _previous = self.requests_with_body.fetch_add(1, Ordering::Relaxed);
    }

    /// The process-wide request-body byte total, or `None` if poisoned —
    /// the shutdown snapshot writer's only door into this counter, kept
    /// as an `Option` rather than a raw `u64` so a caller cannot forget
    /// to check the poison bit before trusting the number.
    pub(crate) fn request_bytes(&self) -> Option<u64> {
        if self.request_bytes_poisoned.load(Ordering::Acquire) {
            return None;
        }
        Some(self.request_bytes.load(Ordering::Acquire))
    }

    /// How many requests reached [`accept_body`], independent of the
    /// poison bit above: a request COUNT never overflows within any run
    /// this process could serve, so it carries no poison state of its
    /// own.
    pub(crate) fn requests_with_body(&self) -> u64 {
        self.requests_with_body.load(Ordering::Acquire)
    }

    /// Add `bytes` to the demoted, informational response-byte total.
    ///
    /// **Saturating, deliberately, and NOT the poison shape above.**
    /// This is never the client-side total counted from response-body
    /// DATA frames — the module doc names it "produced, never confirmed
    /// received" — so there is no upper-bound gate for a wrap to fail
    /// open against; a saturated value is still visibly at the ceiling
    /// rather than silently wrong the way a wrapped one would be.
    fn record_response_bytes(&self, bytes: u64) {
        let mut current = self.response_bytes_produced.load(Ordering::Acquire);
        loop {
            let next = current.saturating_add(bytes);
            match self.response_bytes_produced.compare_exchange_weak(
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

    /// The process-wide response-byte total PRODUCED — see
    /// [`WriteBudget::record_response_bytes`] for why it carries no
    /// poison state.
    pub(crate) fn response_bytes_produced(&self) -> u64 {
        self.response_bytes_produced.load(Ordering::Acquire)
    }

    /// An EMPTY claim on this budget, which always succeeds because it
    /// takes nothing.
    ///
    /// A write starts here and grows its charge as content lands, so a
    /// peer that sends nothing costs nothing and a peer that stalls
    /// holds what it managed to send rather than what its endpoint might
    /// one day carry.
    pub(crate) fn claim(self: &Arc<Self>) -> Reservation {
        Reservation {
            budget: Arc::clone(self),
            bytes: 0,
        }
    }

    /// Take `bytes` out of the budget, or refuse.
    ///
    /// **A hand-written compare-and-swap loop**, the same shape as
    /// [`ReadBudget::take`] and for the same two reasons: two requests
    /// racing the last of the budget cannot both see room, because the
    /// loser re-reads the value the winner wrote and tries again against
    /// it; and the addition is `checked`, so a budget set near `u64::MAX`
    /// cannot wrap into room.
    ///
    /// **Hand-written, and not the standard library's atomic
    /// update-in-a-loop helper — which is what this is underneath.**
    /// That helper is deprecated from Rust 1.98 in favour of a renamed
    /// twin, and the renamed twin does not exist on this workspace's
    /// pinned toolchain, so NEITHER spelling builds warning-free on both
    /// sides of the bump and CI denies warnings. The loop below is what
    /// both names expand to; it is stable under either, and it is the
    /// reason the two budgets read the same.
    ///
    /// `compare_exchange_weak` rather than the strong form: the loop
    /// already re-reads on failure, so a spurious failure costs one extra
    /// iteration and nothing else, and the weak form compiles to a bare
    /// LL/SC pair on the architectures that have one.
    fn take(&self, bytes: u64) -> bool {
        let mut current = self.in_flight.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return false;
            };
            if next > self.limit {
                return false;
            }
            match self.in_flight.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_won) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// A claim already charged with `bytes`, or `None` — the shape a row
    /// fills the budget from the outside with.
    #[cfg(test)]
    pub(crate) fn reserve(self: &Arc<Self>, bytes: u64) -> Option<Reservation> {
        let mut claim = self.claim();
        claim.charge(bytes).then_some(claim)
    }

    /// How many bytes are reserved right now. The park-proof
    /// observation: it returns to zero.
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::Acquire)
    }
}

/// How much a write that has had `counted` bytes land, under a cap of
/// `limit`, must have charged.
///
/// The next granule boundary at or above `counted`, never past the cap —
/// a `PUT hint` has twenty legal octets and is charged twenty, not a
/// granule. The result is always at least `counted`, so the charge can
/// never lag the bytes being held: `counted <= limit` on every call
/// (the cap is enforced before this is asked), and the rounding only
/// ever moves upwards.
fn charge_target(counted: u64, limit: u64) -> u64 {
    let rounded = counted
        .div_ceil(WRITE_BUDGET_GRANULE_BYTES)
        .saturating_mul(WRITE_BUDGET_GRANULE_BYTES);
    if rounded < limit { rounded } else { limit }
}

/// A live charge against a [`WriteBudget`], released on DROP.
///
/// **RAII and not a matched release call, and the difference is the
/// whole point.** The accept path has nine exits — the length
/// fast-path, the clock, the drain, the cap, the byte-rate `429`
/// (`Accepted::RateLimited`), the budget, a transport failure, a refusal
/// and a success — and a release written on each is a release missing
/// from the tenth somebody adds. A value whose
/// destructor releases cannot be exited past, including by an early
/// `return`, by a `?`, or by the future being DROPPED mid-await when the
/// peer disappears — which is the one exit no matched call could ever
/// cover.
///
/// **It GROWS.** A write charges nothing until content lands and then
/// tops up a granule at a time, so the drop releases whatever the charge
/// had reached; there is no shape in which a partial charge escapes,
/// because there is only one value and only one destructor.
#[derive(Debug)]
pub(crate) struct Reservation {
    budget: Arc<WriteBudget>,
    bytes: u64,
}

impl Reservation {
    /// Add `more` bytes to this charge, or refuse it.
    ///
    /// **No await between the take and the bookkeeping**, which is what
    /// makes the pair safe against the future being dropped mid-accept:
    /// there is no point at which the budget has been charged and this
    /// value does not know it, so the destructor always releases exactly
    /// what was taken.
    pub(crate) fn charge(&mut self, more: u64) -> bool {
        if more == 0 {
            return true;
        }
        if !self.budget.take(more) {
            return false;
        }
        // Saturating for the no-panic rule and unreachable in fact: the
        // take above proved `in_flight + more <= limit`, and this
        // charge is part of `in_flight`.
        self.bytes = self.bytes.saturating_add(more);
        true
    }

    /// How much this charge holds right now.
    pub(crate) const fn held(&self) -> u64 {
        self.bytes
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.bytes == 0 {
            return;
        }
        // `fetch_sub` and not a store: the value is shared, and the
        // symmetric CAS is unnecessary because a charge only ever
        // returns what it took.
        let _previous = self
            .budget
            .in_flight
            .fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

// ------------------------------------------------- the read-response budget

/// The global in-flight READ-response byte budget.
///
/// Shared across every clone of the service, for the reason
/// [`WriteBudget`] is: a per-connection allowance is one an attacker
/// multiplies by opening connections, which is not a smaller bound but no
/// bound.
///
/// **A sibling of [`WriteBudget`] and deliberately not the same type.**
/// The write budget grows a granule at a time as content ARRIVES;
/// this one is taken ONCE, at a size that is already known,
/// on content DEPARTING, and its charge has to be `Send + 'static` so it
/// can ride into the response body and be released by whoever drops the
/// last clone of it. Merging them would put a growing charge and a
/// riding one behind the same API for the sake of thirty shared lines.
#[derive(Debug)]
pub(crate) struct ReadBudget {
    limit: u64,
    in_flight: AtomicU64,
}

impl ReadBudget {
    pub(crate) const fn new(limit: u64) -> Self {
        Self {
            limit,
            in_flight: AtomicU64::new(0),
        }
    }

    /// Charge `bytes` to this budget, or refuse.
    ///
    /// **A hand-written compare-and-swap loop**, which is what the
    /// standard library's atomic update-in-a-loop helper is underneath:
    /// two requests racing the last of the budget cannot both see room,
    /// because the loser re-reads the value the winner wrote and tries
    /// again against it. The addition is `checked`, so a budget set near
    /// `u64::MAX` cannot wrap into room.
    ///
    /// `compare_exchange_weak` rather than the strong form: the loop
    /// already re-reads on failure, so a spurious failure costs one extra
    /// iteration and nothing else, and the weak form compiles to a bare
    /// LL/SC pair on the architectures that have one.
    pub(crate) fn take(self: &Arc<Self>, bytes: u64) -> Option<ReadCharge> {
        // An EMPTY charge always succeeds and touches no atomic. A `404`
        // holds nothing, and making it contend for the process's read
        // counter would be a cost paid by the cheapest answer there is.
        if bytes == 0 {
            return Some(ReadCharge {
                budget: Arc::clone(self),
                bytes: 0,
            });
        }
        let mut current = self.in_flight.load(Ordering::Acquire);
        loop {
            let next = current.checked_add(bytes)?;
            if next > self.limit {
                return None;
            }
            match self.in_flight.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_won) => {
                    return Some(ReadCharge {
                        budget: Arc::clone(self),
                        bytes,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// How many bytes are held right now. The park-proof observation: it
    /// goes UP while a response is resident, and back to zero after.
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::Acquire)
    }
}

/// A live charge against a [`ReadBudget`], released on DROP.
///
/// **RAII, and here the destructor is doing something no matched release
/// call could.** This value does not live on the request's stack: it is
/// moved into the response body and dropped by the TRANSPORT, whenever
/// the last clone of the body's bytes goes away — which is after the
/// final frame is written, or when the peer disappears mid-response, or
/// when the connection's lifetime bound closes it under a peer that
/// stopped reading. There is no point in this layer's code where "the
/// response is finished" could be written down, which is exactly why the
/// release is a destructor and not a statement.
#[derive(Debug)]
pub(crate) struct ReadCharge {
    budget: Arc<ReadBudget>,
    bytes: u64,
}

impl Drop for ReadCharge {
    fn drop(&mut self) {
        if self.bytes == 0 {
            return;
        }
        // `fetch_sub` and not a store: the value is shared, and a charge
        // only ever returns what it took.
        let _previous = self
            .budget
            .in_flight
            .fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// A response body and the charge it is holding, as ONE owner.
///
/// This is what makes the charge's lifetime the BODY's lifetime.
/// `Bytes::from_owner` keeps the owner alive for as long as any clone of
/// the resulting `Bytes` exists — including the chunks hyper's HTTP/2
/// writer holds across flow-control waits — and drops it when the last
/// one goes. So the budget is credited when the bytes are actually gone
/// from the process, not when this layer stopped looking at them.
#[derive(Debug)]
struct ChargedBody {
    body: Vec<u8>,
    /// Read by nothing and load-bearing entirely: its `Drop` is the
    /// release. Named with a leading underscore so a future reader does
    /// not "clean up" an unused field.
    _charge: ReadCharge,
}

impl AsRef<[u8]> for ChargedBody {
    fn as_ref(&self) -> &[u8] {
        &self.body
    }
}

/// What a body past the cap for its kind is refused AS.
///
/// Two answers, because §5.9's endpoint has no `413` row at all: a hint
/// body has exactly one legal length, so "too long" and "malformed" are
/// the same refusal and it is `400` + `bad-request`. Answering `413`
/// there would invent a row the protocol does not have and tell a client
/// to retry smaller, which for a 20-octet body means nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OverCap {
    /// §5a.1's object-kind caps: `413` + `too-large`.
    TooLarge,
    /// §5.9's one-length body: `400` + `bad-request`.
    BadRequest,
}

/// The body bound for one write endpoint, and what crossing it means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BodyCap {
    /// The largest body this endpoint accepts, in octets.
    pub(crate) limit: u64,
    over: OverCap,
}

impl BodyCap {
    /// The refusal a body past this cap gets.
    fn refusal(self) -> Outcome {
        match self.over {
            OverCap::TooLarge => Outcome::too_large(),
            OverCap::BadRequest => Outcome::bad_request(),
        }
    }
}

/// The per-kind body cap, or `None` for the five reads — which have no
/// content at all (§4.2) and whose stray content is DRAINED, not
/// accepted.
///
/// **Derived from the parsed operation, never from a field the request
/// carried.** A cap chosen from `Content-Type`, or from a length the
/// peer declared, would be a cap the caller picks.
///
/// The match has no wildcard arm: a new operation is given a cap here
/// or does not compile.
pub(crate) fn write_cap(operation: &Operation<'_>) -> Option<BodyCap> {
    match operation {
        Operation::Intent { operation, .. } => {
            let limit = match operation {
                crate::authority::IntentOperation::Register => {
                    granary_core::intent::REGISTER_MAX_BYTES
                }
                crate::authority::IntentOperation::Release => granary_core::intent::RELEASE_BYTES,
                crate::authority::IntentOperation::Ownership => {
                    granary_core::intent::OWNERSHIP_MAX_BYTES
                }
                crate::authority::IntentOperation::Readback => return None,
            };
            Some(BodyCap {
                limit: u64::try_from(limit).unwrap_or(u64::MAX),
                over: OverCap::TooLarge,
            })
        }
        Operation::PutBin { .. } => Some(BodyCap {
            limit: BIN_MAX_BYTES,
            over: OverCap::TooLarge,
        }),
        Operation::PutMeta { .. } => Some(BodyCap {
            limit: META_MAX_BYTES,
            over: OverCap::TooLarge,
        }),
        Operation::PutRoot { .. } | Operation::Publish { .. } => Some(BodyCap {
            limit: ROOT_MAX_BYTES,
            over: OverCap::TooLarge,
        }),
        Operation::WriteHint { .. } => Some(BodyCap {
            // §5.9: exactly 20 ASCII digits. The cap and the parse agree
            // by construction because both name core's own constant.
            limit: u64::try_from(SEQ_KEY_DIGITS).unwrap_or(u64::MAX),
            over: OverCap::BadRequest,
        }),
        Operation::GetBinRange { .. }
        | Operation::GetMeta { .. }
        | Operation::GetRoot { .. }
        | Operation::MaxSeq { .. }
        | Operation::ReadHint { .. }
        | Operation::VolumeStatus { .. } => None,
    }
}

/// How a counting accept ended.
#[derive(Debug)]
pub(crate) enum Accepted {
    /// The whole body arrived inside the cap.
    Body(Vec<u8>),
    /// The body crossed the cap. Reading STOPPED there — the rest is
    /// never read, which is the difference between a cap and a
    /// measurement.
    TooLarge,
    /// The process budget ran out while the content was still arriving.
    /// Reading stops here too, and the answer is the same `503` an
    /// up-front refusal would have given: the difference is only that
    /// this server waited to find out how large the body actually was
    /// before deciding it could not hold it.
    BudgetExhausted,
    /// The principal has spent its received-content allowance.
    RateLimited(crate::controls::ControlRefusal),
    /// The transport gave up on the content: a declared length the peer
    /// did not deliver, a reset stream, a framing error. **Not a
    /// refusal** — nothing about the request was decided, and the peer
    /// broke its own message.
    TransportRejected,
}

/// Read an admitted write's content, COUNTING the framed bytes, charging
/// what has landed to `charge`, and stopping at `limit`.
///
/// **The count is of bytes that arrived, never of a length the peer
/// declared** (§5a.2, §13.2 item 5). `Content-Length` is advisory: a
/// peer may declare ten bytes and send a gigabyte, and a server that
/// sized its read from the declaration would accept it. The loop counts
/// what it is handed, so a chunked body with no declared length at all
/// is bounded identically — and the declaration is not what is CHARGED
/// either, for the same reason.
///
/// **Nothing is preallocated from a declared length.** The body grows
/// from the frames themselves, so a request that sends nothing costs
/// nothing.
///
/// **The charge is taken BEFORE the bytes are kept, one granule at a
/// time.** That order is the bound: at every await point the budget
/// already holds at least as much as this request is retaining, so the
/// process total can never exceed [`WRITE_BODY_BUDGET_BYTES`] however
/// the frames are cut. A body whose charge is refused mid-stream stops
/// being read, exactly as one past the cap does.
///
/// **What the charge is NOT is a bound on PEAK residency, and the
/// difference is a factor of at least two.** The body exists as the
/// accumulated frames and then as the owned vector handed on, and the
/// vector's own growth reallocates — so the high water mark is a
/// multiple of the charged size and not the charged size itself. The
/// charge bounds how many bytes a peer may have IN FLIGHT, which is what
/// sheds load; it does not bound the allocator. Sizing a deployment's
/// memory from this constant alone will under-provision it.
///
/// **Returns the FRAMED byte count alongside the outcome.** The `served` log
/// event needs this request's own total — never at an
/// outcome arm, the same rule the process-wide counter below follows —
/// so the value travels back regardless of which of the five ways this
/// function ends.
async fn accept_body<B>(
    mut body: B,
    limit: u64,
    charge: &mut Reservation,
    permit: Option<&WritePermit>,
) -> (Accepted, u64)
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    // This request reached the counting accept, regardless of
    // how it ends below — counted once, here, never per outcome arm.
    charge.budget.record_request_with_body();
    #[cfg(feature = "crash-points")]
    crate::authority::crash::note("BODY_WAIT");
    let mut content: Vec<u8> = Vec::new();
    let mut counted: u64 = 0;
    while let Some(frame) = body.frame().await {
        // The peer broke its own message. Classified by POSITION rather
        // than by an error type: this arm is every failure the body
        // underneath can report, and the three refusals this function
        // takes are decided by its own counters.
        let Ok(frame) = frame else {
            return (Accepted::TransportRejected, counted);
        };
        // Trailers are not content, and a body may end with them.
        let Some(data) = frame.data_ref() else {
            continue;
        };
        // Saturating, and the direction is the safe one: a count that
        // could wrap would restart the cap at zero.
        let arrived = u64::try_from(data.len()).unwrap_or(u64::MAX);
        // Counted AT THE FRAME — before the cap comparison and
        // before the budget charge below, and on every one of this
        // function's five outcomes rather than only its success arm.
        // Counting must not depend on returning
        // `Accepted::Body`: a refused, sheared or reset body still
        // arrived, and `reset_then_retry_counts_both_attempts` is the
        // row that catches a regression back to that shape.
        charge.budget.record_frame(arrived);
        counted = counted.saturating_add(arrived);
        // Account the arriving frame even when the body bound wins.
        // No reservation grows and no bytes are retained on either refusal.
        let over_bound = counted > limit;
        let byte_rate = permit
            .map(|permit| permit.charge_bytes(arrived))
            .transpose();
        if over_bound {
            return (Accepted::TooLarge, counted);
        }
        if let Err(refusal) = byte_rate {
            return (Accepted::RateLimited(refusal), counted);
        }
        let owed = charge_target(counted, limit).saturating_sub(charge.held());
        if !charge.charge(owed) {
            return (Accepted::BudgetExhausted, counted);
        }
        content.extend_from_slice(data);
    }
    (Accepted::Body(content), counted)
}

/// Poll `future` to completion unless the process starts DRAINING first,
/// in which case it is abandoned and `None` comes back.
///
/// **Hand-rolled and biased, because `select!` is banned**
/// and a randomised branch order is the property the ban exists to
/// exclude. The drain arm is polled first, so a drain already under way
/// abandons the future rather than reading one more frame from the peer.
///
/// **The level is read on entry, not only the edge.** A receiver whose
/// notification was consumed elsewhere would never see a `changed()`
/// again, so a request arriving after the drain began would run its full
/// clock. An errored `changed()` means every sender is gone, which is a
/// drain and not "nothing happened" — read the other way it would return
/// immediately forever and turn this into a hot loop.
///
/// The future is polled by REFERENCE and dropped only on the abandoning
/// return: it owns the request body, which cannot be started again.
async fn until_draining<F: Future>(
    draining: &mut watch::Receiver<bool>,
    future: F,
) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    loop {
        if *draining.borrow_and_update() {
            return None;
        }
        let raced = {
            let mut changed = std::pin::pin!(draining.changed());
            let mut future = future.as_mut();
            std::future::poll_fn(|context| {
                if let Poll::Ready(observed) = changed.as_mut().poll(context) {
                    return Poll::Ready(Err(observed));
                }
                future.as_mut().poll(context).map(Ok)
            })
            .await
        };
        match raced {
            Ok(output) => return Some(output),
            Err(Err(_every_sender_gone)) => return None,
            // Something was sent; the LEVEL at the top of the loop
            // decides, so a contract-violating `false` re-arms the wait
            // instead of shedding a live upload.
            Err(Ok(())) => {}
        }
    }
}

// ---------------------------------------------------------- the rendering

/// [`Status`] as an `http` status code.
///
/// A total match over a closed enum, with no `from_u16` and no arm that
/// can fail. No wildcard arm: a new status is transcribed here or does not
/// compile.
const fn code(status: Status) -> StatusCode {
    match status {
        Status::Ok => StatusCode::OK,
        Status::Created => StatusCode::CREATED,
        Status::NoContent => StatusCode::NO_CONTENT,
        Status::Accepted => StatusCode::ACCEPTED,
        Status::PartialContent => StatusCode::PARTIAL_CONTENT,
        Status::NotModified => StatusCode::NOT_MODIFIED,
        Status::BadRequest => StatusCode::BAD_REQUEST,
        Status::Forbidden => StatusCode::FORBIDDEN,
        Status::NotFound => StatusCode::NOT_FOUND,
        Status::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
        Status::Conflict => StatusCode::CONFLICT,
        Status::ContentTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        Status::RangeNotSatisfiable => StatusCode::RANGE_NOT_SATISFIABLE,
        Status::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        Status::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        Status::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// `Granary-Error` (§8.2), spelled once.
const GRANARY_ERROR: HeaderName = HeaderName::from_static("granary-error");

/// Insert a field whose value is computed rather than static.
///
/// **The failure arm is unreachable and is written rather than
/// asserted.** `HeaderValue::from_str` refuses only the bytes below
/// `0x20` (bar `HTAB`) and `0x7F`, and none of this function's three
/// callers can produce one: RFC 9110 §8.8.3's `entity-tag` grammar
/// excludes every one of them and was checked in [`ETag`]'s
/// constructor, a `Content-Range` is decimal digits and fixed ASCII
/// punctuation, and a `Retry-After` is decimal digits alone. Omitting the field is the degrade, because the
/// no-panic rule outranks a field on a response that was already built.
///
/// [`ETag`]: crate::wire::ETag
fn insert_computed(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    let rendered = HeaderValue::from_str(value);
    debug_assert!(
        rendered.is_ok(),
        "a field value outside the grammar its constructor checked reached the wire"
    );
    if let Ok(rendered) = rendered {
        headers.insert(name, rendered);
    }
}

/// Transcribe an [`Outcome`] onto the wire.
///
/// Every value but two is a `&'static str` from the closed vocabulary,
/// so it goes over through `HeaderValue::from_static` and cannot fail.
/// The body is MOVED, never copied. `Date` and `Content-Length` are
/// hyper's to supply.
fn render(outcome: Outcome, drain: Drain) -> Response<Full<Bytes>> {
    render_charged(outcome, drain, None)
}

/// [`render`], with the read-budget charge the response body is HOLDING.
///
/// **`render`'s signature is deliberately untouched** and this is the
/// only caller that has a charge to hand over: every refusal, every
/// write answer and every empty-bodied read still goes through the
/// two-argument form, so nothing in this module had to learn about a
/// budget in order to keep compiling.
///
/// `Some` and `None` differ in one thing only — who owns the
/// allocation. `Bytes::from(Vec)` takes the buffer and forgets where it
/// came from; `Bytes::from_owner` takes a [`ChargedBody`] and keeps the
/// charge alongside the bytes, so the release happens on the transport's
/// schedule rather than on this function's.
fn render_charged(
    outcome: Outcome,
    drain: Drain,
    charge: Option<ReadCharge>,
) -> Response<Full<Bytes>> {
    let status = code(outcome.status());
    let mut headers = HeaderMap::new();

    if let Some(token) = outcome.error() {
        headers.insert(GRANARY_ERROR, HeaderValue::from_static(token.as_str()));
    }
    if let Some(content_type) = outcome.content_type() {
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(content_type.as_str()),
        );
    }
    if let Some(cache_control) = outcome.cache_control() {
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static(cache_control.as_str()),
        );
    }
    if let Some(allow) = outcome.allow() {
        headers.insert(ALLOW, HeaderValue::from_static(allow.as_str()));
    }
    if let Some(etag) = outcome.etag() {
        insert_computed(&mut headers, ETAG, etag);
    }
    if let Some(extent) = outcome.extent() {
        // `complete-length` is literally `*`: the seam supplies no
        // object length, so a number here would be invented (§7.2).
        let value = format!("bytes {}-{}/*", extent.first(), extent.last());
        insert_computed(&mut headers, CONTENT_RANGE, &value);
    }
    if let Some(seconds) = outcome.retry_after() {
        // delay-seconds: decimal digits alone (RFC 9110 §10.2.3).
        insert_computed(&mut headers, RETRY_AFTER, &seconds.to_string());
    }
    // ONE unconditional header for both legs: honoured on HTTP/1.1, and
    // stripped by hyper on HTTP/2, where RFC 9113 §8.2.2 would make it a
    // malformed message. The h2 tear-down is hyper's own
    // `RST_STREAM(NO_ERROR)` after the complete response.
    if drain == Drain::Overflowed {
        headers.insert(CONNECTION, HeaderValue::from_static("close"));
    }

    let refusal = outcome.error();
    let body = outcome.into_body();
    let bytes = match charge {
        Some(charge) => Bytes::from_owner(ChargedBody {
            body,
            _charge: charge,
        }),
        None => Bytes::from(body),
    };
    let mut response = Response::new(Full::new(bytes));
    if let Some(reason) = refusal {
        response.extensions_mut().insert(reason);
    }
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

// ------------------------------------------------------ the head, extracted

/// Build the request head from what the request carried.
///
/// **Everything the request carried is handed over.** Values that are
/// not UTF-8 are lossy-decoded, and for these uses lossy is the TOTAL
/// form rather than a repair: `U+FFFD` is outside §7.1's `Range` grammar
/// and outside every §4.3 alphabet, so a lossy-decoded line is refused
/// at the same ordered step that would have refused it as bytes, never
/// accepted. Rejecting non-UTF-8 here instead would move a refusal
/// decision — and its ORDER, which §5a.6 makes normative — out of the
/// gate.
///
/// `If-None-Match` is the one exception and it collapses to `None`
/// instead of decoding: `etagc` admits obs-text, so a lossy-decoded
/// attacker value would pass the entity-tag grammar and reach the seam
/// as a cached validator. Two field lines collapse the same way. §5a.6
/// makes both "a value this server cannot match", whose answer is
/// whatever the unconditional request would have produced.
///
/// The borrowed pieces are the caller's locals, which is why this hands
/// them back rather than owning them: an `Admitted` borrows from the
/// head, and the head borrows from these.
struct HeadParts {
    range_values: Vec<String>,
    field_names: Vec<String>,
}

impl HeadParts {
    fn of(headers: &HeaderMap) -> Self {
        Self {
            // EVERY `Range` field line, in order. `get_all`, never
            // `get`: two attacker lines are two elements, and `admit`
            // refuses more than one.
            range_values: headers
                .get_all(RANGE)
                .iter()
                .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                .collect(),
            // EVERY received field NAME, unfiltered. `keys()` yields
            // each DISTINCT name once, which is sufficient and is not a
            // filter: `admit` reads these for set membership only, no
            // value is read through them, and a duplicate name cannot
            // hide a name.
            field_names: headers
                .keys()
                .map(|name| name.as_str().to_owned())
                .collect(),
        }
    }
}

// ------------------------------------------------------------ the service

/// The handle a composition root arms when the process is going away.
///
/// **This exists because a clock ordering cannot be fixed with a
/// constant here.** The accept clock covers up to `BIN_MAX_BYTES` of
/// legitimate content and is necessarily longer than the transport's
/// drain deadline, whose expiry is a process exit — so a shutdown
/// landing during an ordinary upload would take the hard-exit path with
/// the upload's own bytes as the undrained work. Shortening the accept
/// refuses large conforming bins; lengthening the deadline makes every
/// deploy wait out the slowest upload it catches. What is left is
/// telling the write path, which is what this does.
///
/// **A composition root MUST arm it**: call [`Draining::begin`] from the
/// same trigger that shuts the accept loop down, before the shutdown
/// level goes up, so no window exists in which the loop is draining and
/// the writes are not. A root that forgets gets a server whose writes
/// still run their full clock into the deadline.
#[derive(Clone, Debug)]
pub struct Draining(Arc<watch::Sender<bool>>);

impl Draining {
    /// Tell every in-flight write that this process is going away.
    ///
    /// Idempotent and never fails: `send_replace` does not care whether
    /// anything is listening, so a process with no write in flight is
    /// the same call as one with a thousand.
    pub fn begin(&self) {
        let _previous = self.0.send_replace(true);
    }

    #[cfg(feature = "crash-points")]
    pub(crate) fn test_is_draining(&self) -> bool {
        *self.0.borrow()
    }
}

/// The composition root's read-only door onto the process-wide
/// wire-byte counters — the same `Arc` every serving clone charges, kept
/// OPAQUE so `WriteBudget` itself can stay `pub(crate)` (the crate's
/// curated-surface rule, `lib.rs`'s own doc). `serve_and_exit` reads the
/// totals through it, once, after every connection has drained.
#[derive(Debug, Clone)]
pub struct WireByteHandle(Arc<WriteBudget>);

impl WireByteHandle {
    /// The totals as of THIS call — meaningful only once every
    /// connection is closed, which is `serve_and_exit`'s own obligation
    /// to have arranged before calling it.
    pub(crate) fn totals(&self) -> crate::wire_snapshot::ServerTotals {
        crate::wire_snapshot::ServerTotals {
            request_bytes: self.0.request_bytes(),
            requests_with_body: self.0.requests_with_body(),
            response_bytes_produced: self.0.response_bytes_produced(),
        }
    }
}

/// The process-wide bounds one request is answered under, bundled
/// because they travel together and separately would be three more
/// parameters on every function between the `Service` impl and the
/// accept.
#[derive(Debug)]
struct Bounds<'a> {
    capture: Option<&'a crate::diagnostics::CaptureHandle>,
    debug_grants: Option<&'a crate::debug_grant::reader::DebugGrantReader>,
    authority: Option<&'a AuthorityWrites>,
    /// The process's in-flight write-body budget.
    budget: &'a Arc<WriteBudget>,
    /// The process's in-flight READ-response byte budget. A
    /// separate bound on a separate resource from the one above, and the
    /// two must not be merged: one bounds content arriving, the other
    /// content departing, and a peer can saturate either alone.
    read_budget: &'a Arc<ReadBudget>,
    /// How many bins this process verifies at once.
    permits: &'a Semaphore,
    /// How many ranged reads this process has in the store at once.
    /// Also separate from the verify permit above — that one bounds
    /// inline CPU, this one bounds uncharged buffers.
    read_permits: &'a Semaphore,
    /// How long a write may wait for one of them.
    ///
    /// ONE wait for BOTH queues, and the derivation is the same for each:
    /// half the shutdown deadline, so a request that takes its permit at
    /// the last legal moment still has the deadline's other half for the
    /// work that follows. A second constant would only be a second thing
    /// to get out of step.
    permit_wait: Duration,
    /// How long ONE seam dispatch may take, or `None` for a store
    /// that cannot stop answering. Carried here rather than as a ninth
    /// argument to `answer`, beside the other three process bounds it
    /// belongs with.
    dispatch_deadline: Option<Duration>,
    /// Test-only bound on authority replies (publish, intent); `None`
    /// leaves them on `dispatch_deadline`, as every shipping build does.
    #[cfg(feature = "crash-points")]
    test_reply_deadline: Option<Duration>,
    /// Raised once, by the composition root, when the process is going
    /// away. Owned rather than borrowed because the accept path awaits
    /// on it and `changed` needs `&mut`.
    draining: watch::Receiver<bool>,
}

impl Bounds<'_> {
    /// The bound on an authority reply: the store's `dispatch_deadline`,
    /// unless a crash-points test set its own reply bound.
    fn reply_deadline(&self) -> Option<Duration> {
        #[cfg(feature = "crash-points")]
        if let Some(deadline) = self.test_reply_deadline {
            return Some(deadline);
        }
        self.dispatch_deadline
    }
}

/// The granary server as a hyper [`Service`].
///
/// Cheap to clone — the accept loop clones one per connection — and the
/// clone does NOT require the store to be `Clone`: an `Arc` is what
/// crosses, so a store with a connection pool behind it is shared rather
/// than duplicated.
///
/// **The shared fields are `Arc` because their bounds span connections.**
/// The write-body budget and the verify permit are
/// what stop a peer from multiplying an allowance by opening
/// connections, and a plain field would give every connection its own —
/// which is not a smaller bound, it is no bound.
pub struct GrainService<R> {
    capture: Option<crate::diagnostics::CaptureHandle>,
    debug_grants: Option<crate::debug_grant::reader::DebugGrantReader>,
    store: Arc<R>,
    /// The path component of the configured `{base}` (§4.1). Part I
    /// passes `""`; the plumbing exists so the configuration surface has
    /// somewhere to land.
    base: Arc<str>,
    /// §13.5's ingest admission policy. The production constructor
    /// hardcodes the verifying one.
    policy: VerifyPolicy,
    /// §7.1's declared maximum extent, or `None` for a server that
    /// enforces none. The production constructor hardcodes the floor.
    max_extent: Option<u32>,
    /// SHARED: the process's in-flight write-body budget.
    write_budget: Arc<WriteBudget>,
    authority: Option<Arc<AuthorityWrites>>,
    /// SHARED: the process's in-flight read-response byte budget.
    read_budget: Arc<ReadBudget>,
    /// SHARED: how many bins this process verifies at once.
    verify_permits: Arc<Semaphore>,
    /// SHARED: how many ranged reads are inside the store at once.
    read_permits: Arc<Semaphore>,
    /// How long a write may wait for one of them before it is shed. A
    /// field only so a row can drive the shed without spending the
    /// shipped bound; the production constructor names the constant.
    permit_wait: Duration,
    /// How long ONE seam dispatch may take before the request is
    /// answered §5.10's "refusing load", or `None` for a store that
    /// cannot stop answering. The value belongs to the STORE, so the
    /// composition root that chose the store is what supplies it.
    dispatch_deadline: Option<Duration>,
    /// Test-only bound on authority replies, set by
    /// [`Self::with_test_reply_deadline`]; compiled out of shipping builds.
    #[cfg(feature = "crash-points")]
    test_reply_deadline: Option<Duration>,
    /// SHARED: the level a composition root raises when the process is
    /// going away, so an accept in flight is abandoned rather than run
    /// to a clock longer than the drain deadline.
    draining: Arc<watch::Sender<bool>>,
}

/// Authority admission and observation are shared by every serving clone.
#[derive(Debug)]
struct AuthorityWrites {
    reader: EnrollmentReader,
    controls: Arc<PrincipalControls>,
    volumes: BTreeSet<VolumeName>,
    uninitialised: std::sync::Mutex<BTreeSet<VolumeName>>,
    handle: Option<AuthorityHandle>,
    counters: Arc<RefusalCounters>,
}

impl<R> GrainService<R> {
    /// Share the host's scoped diagnostic capture seam with every serving clone.
    #[must_use]
    pub fn with_capture(mut self, handle: crate::diagnostics::CaptureHandle) -> Self {
        self.capture = Some(handle);
        self
    }

    /// Attach one process-shared demand reader inside the serving runtime.
    /// The handle must be the grant-aware capture returned by `host.subscriber`.
    ///
    /// # Errors
    /// Refuses an unprotected or inaccessible enrollment directory.
    pub fn with_debug_grants(
        mut self,
        host: &crate::debug_grant::DebugGrantHost,
        path: &std::path::Path,
        accept_unsupported: bool,
        capture: crate::diagnostics::CaptureHandle,
    ) -> Result<Self, crate::enrollment::ReaderStartError> {
        self.debug_grants = Some(host.open(path, accept_unsupported, capture.clone())?);
        self.capture = Some(capture);
        Ok(self)
    }

    /// Await a grant refresh begun after arrival, then collect local observation.
    /// Waiting is bounded by 2 seconds; a stall suspends capture and preserves
    /// authorization. Cached observation and public status perform no refresh.
    ///
    /// # Cancellation safety
    /// Dropping this future does not cancel the blocking refresh or application.
    pub async fn fresh_observation(&self) -> Option<crate::authority::Observation> {
        if let Some(reader) = &self.debug_grants {
            let _snapshot = reader.refresh().await;
        }
        self.observation()
    }

    /// Cached, filesystem-independent grant observation, including expiry.
    #[must_use]
    pub fn debug_grant_observation(&self) -> Option<crate::debug_grant::DebugGrantSnapshot> {
        self.debug_grants
            .as_ref()
            .map(crate::debug_grant::reader::DebugGrantReader::observation)
    }

    /// Maintain released rows and enrollment cursors for existing valid log/snapshot pairs.
    /// Startup and periodic passes never initialise or rebind configured volumes.
    /// # Errors
    /// Unavailable enrollment or intent state, or a fenced/stopped authority.
    /// Every failing volume is logged; the return value is the first failure.
    pub async fn maintain_intents(&self) -> Result<(), crate::wire::ErrorToken> {
        use crate::wire::ErrorToken;
        let failed = |error: ErrorToken| {
            tracing::warn!(event = "intent_maintenance_failed", reason = error.as_str());
            error
        };
        let authority = self
            .authority
            .as_ref()
            .ok_or_else(|| failed(ErrorToken::Unavailable))?;
        let handle = authority
            .handle
            .as_ref()
            .ok_or_else(|| failed(ErrorToken::Unavailable))?;
        let enrollment = authority
            .reader
            .current_set()
            .await
            .map_err(|_| failed(ErrorToken::EnrollmentUnavailable))?;
        let mut refused = None;
        for volume in &authority.volumes {
            // NoLog is a normal configured state. A terminal authority still
            // reports failures rather than being hidden by that observation.
            if handle.volume_view(volume) == Some(crate::authority::VolumeView::NoLog)
                && handle.terminal_state().is_none()
            {
                let entered = authority
                    .uninitialised
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(volume.clone());
                if entered {
                    tracing::info!(
                        event = "intent_maintenance_uninitialised",
                        volume = volume.as_str()
                    );
                }
                continue;
            }
            authority
                .uninitialised
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(volume);
            let result = handle.maintain_intents(volume, &enrollment, 86_400).await;
            if let Some(error) = result.error() {
                tracing::warn!(
                    event = "intent_maintenance_failed",
                    volume = volume.as_str(),
                    reason = error.as_str()
                );
                refused.get_or_insert(error);
            }
        }
        refused.map_or(Ok(()), Err)
    }

    /// Synchronously collect operator observation without refreshing enrollment
    /// or asking any worker. Each volume is coherent; process counters retain
    /// their separately sampled semantics. Grant metadata and effective capture share
    /// a coordinator selection; other domains are sampled separately.
    #[must_use]
    pub fn observation(&self) -> Option<crate::authority::Observation> {
        let authority = self.authority.as_ref()?;
        let handle = authority.handle.as_ref()?;
        Some(crate::authority::Observation {
            volumes: handle.volume_views(),
            terminal: handle.terminal_state(),
            enrollment: authority.reader.snapshot(),
            refusals: authority.counters.snapshot(),
            debug_grant: self.debug_grant_observation(),
        })
    }

    /// Require current enrollment, refuse direct roots from `config.volumes`,
    /// route publish through per-principal controls to `handle`, and serve
    /// anonymous status from that same handle's observation.
    /// The host supplies the same configuration used to start the engine
    /// and the process-owned controls and refusal counters shared by all services.
    #[must_use]
    pub fn with_authority_writes(
        mut self,
        reader: EnrollmentReader,
        controls: Arc<PrincipalControls>,
        counters: Arc<RefusalCounters>,
        config: &AuthorityConfig,
        handle: AuthorityHandle,
    ) -> Self {
        self.authority = Some(Arc::new(AuthorityWrites {
            reader,
            controls,
            volumes: config.volumes.keys().cloned().collect(),
            uninitialised: std::sync::Mutex::default(),
            handle: Some(handle),
            counters,
        }));
        self
    }

    #[cfg(test)]
    pub(crate) fn capture_for_test(&self) -> Option<crate::diagnostics::CaptureHandle> {
        self.capture.clone()
    }

    #[cfg(test)]
    pub(crate) fn grant_reader(&self) -> Option<crate::debug_grant::reader::DebugGrantReader> {
        self.debug_grants.clone()
    }

    #[cfg(test)]
    pub(crate) async fn request_for_test<B>(&self, request: Request<B>) -> Response<Full<Bytes>>
    where
        R: RootStore + BinStore,
        B: Body<Data = Bytes> + Unpin,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        respond(
            &*self.store,
            &self.base,
            self.policy,
            self.max_extent,
            Bounds {
                capture: self.capture.as_ref(),
                debug_grants: self.debug_grants.as_ref(),
                authority: self.authority.as_deref(),
                budget: &self.write_budget,
                read_budget: &self.read_budget,
                permits: &self.verify_permits,
                read_permits: &self.read_permits,
                permit_wait: self.permit_wait,
                dispatch_deadline: self.dispatch_deadline,
                #[cfg(feature = "crash-points")]
                test_reply_deadline: self.test_reply_deadline,
                draining: self.draining.subscribe(),
            },
            request,
        )
        .await
    }

    /// The process-owned operator refusal counters, when authority writes are enabled.
    #[must_use]
    pub fn refusal_counters(&self) -> Option<Arc<RefusalCounters>> {
        self.authority.as_ref().map(|a| Arc::clone(&a.counters))
    }

    #[cfg(test)]
    pub(crate) fn with_test_write_controls(
        mut self,
        reader: EnrollmentReader,
        controls: Arc<PrincipalControls>,
    ) -> Self {
        self.authority = Some(Arc::new(AuthorityWrites {
            reader,
            controls,
            volumes: BTreeSet::new(),
            uninitialised: std::sync::Mutex::default(),
            handle: None,
            counters: Arc::new(RefusalCounters::default()),
        }));
        self
    }

    /// A service answering §4.2's resources under `base`, on a runtime
    /// with `worker_threads` workers.
    ///
    /// `base` is the path component of the configured base URL: empty,
    /// or starting with `/` and not ending with one (§4.1). A malformed
    /// value is not repaired — it makes every request answer `404` —
    /// so the shape is asserted here, at the one call per process,
    /// rather than diagnosed from a server that refuses everything.
    ///
    /// **`worker_threads` is the runtime's OWN figure, not an
    /// independent guess**, and it is a parameter for that reason: the
    /// verify permit count is `workers - 1`, which is only a statement
    /// about leaving a worker free if the number is the number the
    /// runtime was built with. [`worker_threads`] is what a composition
    /// root passes to both.
    ///
    /// **This is the only public constructor, and it is where §13.5's
    /// reachability argument and §7.1's accept-set argument are both
    /// paid.** It NAMES the verifying policy and the declared extent
    /// rather than taking them, so no composition root can widen either
    /// — the same shape `admit` uses one layer down, and the reason
    /// `GrainService::for_test` is `#[cfg(test)]`.
    #[must_use]
    pub fn new(store: Arc<R>, base: &str, worker_threads: usize) -> Self {
        Self::with_deadline(store, base, worker_threads, None)
    }

    /// [`GrainService::new`], bounding every seam dispatch.
    ///
    /// **`None` is not "no bound by default", it is "this store cannot
    /// stop answering".** An in-process store answers from a `BTreeMap`
    /// and a deadline on it would fire on a loaded test machine and on
    /// nothing else; a NETWORK store can hang indefinitely, and a
    /// request that hangs with it holds a connection, a write charge and
    /// a verify permit for as long as the peer will wait. The
    /// composition root that CHOSE the store supplies the value, because
    /// that is the only layer that knows which of the two it built.
    ///
    /// **The expiry is a STATUS, never a dropped connection**:
    /// a closed connection reads as retryable to every client in
    /// the stack, and `503`/`unavailable` is the answer §5.10 already
    /// gives for refusing load.
    #[must_use]
    pub fn with_deadline(
        store: Arc<R>,
        base: &str,
        worker_threads: usize,
        dispatch_deadline: Option<Duration>,
    ) -> Self {
        debug_assert!(
            base.is_empty() || (base.starts_with('/') && !base.ends_with('/')),
            "a base path is empty, or `/`-led and not `/`-terminated (§4.1): {base:?}"
        );
        Self {
            capture: None,
            debug_grants: None,
            store,
            base: Arc::from(base),
            policy: VerifyPolicy::verifying(),
            max_extent: Some(DECLARED_MAX_EXTENT),
            authority: None,
            write_budget: Arc::new(WriteBudget::new(WRITE_BODY_BUDGET_BYTES)),
            read_budget: Arc::new(ReadBudget::new(READ_BODY_BUDGET_BYTES)),
            verify_permits: Arc::new(Semaphore::new(verify_permits(worker_threads))),
            read_permits: Arc::new(Semaphore::new(READ_PERMITS)),
            permit_wait: VERIFY_PERMIT_MAX_WAIT,
            dispatch_deadline,
            #[cfg(feature = "crash-points")]
            test_reply_deadline: None,
            draining: Arc::new(watch::channel(false).0),
        }
    }

    /// Bound authority replies separately from store dispatch in crash-point tests.
    #[cfg(feature = "crash-points")]
    #[must_use]
    pub fn with_test_reply_deadline(mut self, deadline: Duration) -> Self {
        self.test_reply_deadline = Some(deadline);
        self
    }

    /// The handle a composition root arms on shutdown.
    ///
    /// Taken from the SAME `Arc` every serving clone reads, which is
    /// what makes one call reach every in-flight write in the process
    /// rather than the connection that happened to be cloned last.
    #[must_use]
    pub fn draining(&self) -> Draining {
        Draining(Arc::clone(&self.draining))
    }

    /// The handle a composition root reads the shutdown wire-byte
    /// snapshot from — the SAME `Arc` every serving clone charges, so the
    /// totals `serve_and_exit` reads after `block_on` returns are the
    /// process's real ones, not a copy taken before the last connection
    /// closed.
    #[must_use]
    pub fn wire_bytes(&self) -> WireByteHandle {
        WireByteHandle(Arc::clone(&self.write_budget))
    }

    /// **The ONE test door, and it opens all three knobs at once.**
    ///
    /// §13.4 needs a seam-only server, §7.1's two profiles need a
    /// declared extent that is not the floor, and the write-budget shed needs a
    /// budget a test can fill — three needs that would otherwise grow
    /// three constructors, and a third constructor is a door somebody
    /// eventually reaches from a composition root. One door, taking
    /// every knob, is auditable in a way three are not: there is exactly
    /// one `#[cfg(test)]` route to a service that is not the shipped
    /// one, and a `cargo build` of the binary does not compile it.
    ///
    /// The verify permit COUNT is the only thing this does NOT open: it
    /// is derived from a pinned worker count, so the verify-permit rows drive a
    /// runtime with that many workers rather than a number they made up.
    /// The permit WAIT is opened, because the shipped five seconds is a
    /// figure sized for a release build and the suite runs a debug one.
    #[cfg(test)]
    #[expect(
        clippy::too_many_arguments,
        reason = "ONE test door, and every knob it opens is a shipped bound a row has to be able to spend; a second constructor would be a second route to a service that is not the shipped one, which is the property this door exists to keep auditable"
    )]
    pub(crate) fn for_test(
        store: Arc<R>,
        base: &str,
        policy: VerifyPolicy,
        max_extent: Option<u32>,
        budget: u64,
        read_budget: u64,
        permit_wait: Duration,
        dispatch_deadline: Option<Duration>,
    ) -> Self {
        Self {
            capture: None,
            debug_grants: None,
            store,
            base: Arc::from(base),
            policy,
            max_extent,
            authority: None,
            write_budget: Arc::new(WriteBudget::new(budget)),
            read_budget: Arc::new(ReadBudget::new(read_budget)),
            verify_permits: Arc::new(Semaphore::new(verify_permits(TEST_WORKER_THREADS))),
            read_permits: Arc::new(Semaphore::new(READ_PERMITS)),
            permit_wait,
            dispatch_deadline,
            #[cfg(feature = "crash-points")]
            test_reply_deadline: None,
            draining: Arc::new(watch::channel(false).0),
        }
    }

    /// The process budget this service shares with its clones — so a row
    /// can watch it fill and, more to the point, watch it EMPTY.
    #[cfg(test)]
    pub(crate) fn write_budget(&self) -> &Arc<WriteBudget> {
        &self.write_budget
    }

    /// The process READ budget this service shares with its clones — so a
    /// row can watch it fill and, more to the point, watch it EMPTY.
    #[cfg(test)]
    pub(crate) fn read_budget(&self) -> &Arc<ReadBudget> {
        &self.read_budget
    }

    /// How many ranged reads this process could start right now.
    #[cfg(test)]
    pub(crate) fn read_permits_available(&self) -> usize {
        self.read_permits.available_permits()
    }

    /// The read-permit semaphore itself, so a row can exhaust it from the
    /// outside — deterministic contention rather than a storm timed to
    /// collide.
    #[cfg(test)]
    pub(crate) fn read_permits_handle(&self) -> &Arc<Semaphore> {
        &self.read_permits
    }

    /// How many verifies this process could start right now.
    ///
    /// Read through the SAME `Arc` the serving clones hold, which is
    /// what makes it evidence about sharing: a per-service permit would
    /// leave this handle reading a full semaphore while every connection
    /// verified.
    #[cfg(test)]
    pub(crate) fn verify_permits_available(&self) -> usize {
        self.verify_permits.available_permits()
    }

    /// The permit semaphore itself, so a row can EXHAUST it from the
    /// outside the way the budget's rows fill the budget — deterministic
    /// contention, rather than a storm timed to collide.
    #[cfg(test)]
    pub(crate) fn verify_permits_handle(&self) -> &Arc<Semaphore> {
        &self.verify_permits
    }
}

/// The worker count the `#[cfg(test)]` door pins, and the count the verify-permit
/// rows must build their runtime with for the permit arithmetic to mean
/// anything.
#[cfg(test)]
pub(crate) const TEST_WORKER_THREADS: usize = 2;

// Hand-written, both of them: a derive would put `R: Clone` and
// `R: Debug` on the impl, and neither is a property a store owes this
// crate — `Arc` is what is cloned, and the store is not printed.
impl<R> Clone for GrainService<R> {
    fn clone(&self) -> Self {
        Self {
            capture: self.capture.clone(),
            debug_grants: self.debug_grants.clone(),
            store: Arc::clone(&self.store),
            base: Arc::clone(&self.base),
            policy: self.policy,
            max_extent: self.max_extent,
            // **`Arc::clone` keeps the write budget and verify permits process-wide.** A
            // `WriteBudget::new(..)` or `Semaphore::new(..)` here would
            // compile, pass every single-connection test, and give each
            // connection its own allowance — restoring exactly the
            // unbounded concurrency both fields exist to remove.
            authority: self.authority.clone(),
            write_budget: Arc::clone(&self.write_budget),
            read_budget: Arc::clone(&self.read_budget),
            verify_permits: Arc::clone(&self.verify_permits),
            read_permits: Arc::clone(&self.read_permits),
            permit_wait: self.permit_wait,
            // A plain copy, and correctly so: a `Duration` is `Copy` and
            // a deadline is a per-request bound, not a shared allowance
            // — there is nothing here for a clone to multiply.
            dispatch_deadline: self.dispatch_deadline,
            #[cfg(feature = "crash-points")]
            test_reply_deadline: self.test_reply_deadline,
            // `Arc::clone` for the same reason as the two above: a
            // fresh channel here would leave every connection but the
            // last one deaf to the drain.
            draining: Arc::clone(&self.draining),
        }
    }
}

impl<R> std::fmt::Debug for GrainService<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrainService")
            .field("base", &self.base)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<R: RootStore + BinStore + 'static> Service<Request<Incoming>> for GrainService<R> {
    type Response = Response<Full<Bytes>>;
    /// **`Infallible`, and that is a property of this layer.** Every
    /// refusal is a response with a status and a token; there is no
    /// error a granary server reports by failing to answer.
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<Incoming>) -> Self::Future {
        let store = Arc::clone(&self.store);
        let base = Arc::clone(&self.base);
        let policy = self.policy;
        let max_extent = self.max_extent;
        let budget = Arc::clone(&self.write_budget);
        let authority = self.authority.clone();
        let capture = self.capture.clone();
        let debug_grants = self.debug_grants.clone();
        let read_budget = Arc::clone(&self.read_budget);
        let permits = Arc::clone(&self.verify_permits);
        let read_permits = Arc::clone(&self.read_permits);
        let permit_wait = self.permit_wait;
        let dispatch_deadline = self.dispatch_deadline;
        #[cfg(feature = "crash-points")]
        let test_reply_deadline = self.test_reply_deadline;
        // Subscribed HERE rather than inside the accept: `subscribe`
        // marks the current value seen, and a receiver made after the
        // level went up would still read `true` — but one made before
        // the request is answered cannot miss an edge either way.
        let draining = self.draining.subscribe();
        Box::pin(async move {
            let bounds = Bounds {
                capture: capture.as_ref(),
                debug_grants: debug_grants.as_ref(),
                authority: authority.as_deref(),
                budget: &budget,
                read_budget: &read_budget,
                permits: &permits,
                read_permits: &read_permits,
                permit_wait,
                dispatch_deadline,
                #[cfg(feature = "crash-points")]
                test_reply_deadline,
                draining,
            };
            Ok(respond(&*store, &base, policy, max_extent, bounds, request).await)
        })
    }
}

/// One request: deal with its content before rendering its response (§5.5).
///
/// **Two shapes, and which one runs is decided by whether the operation
/// has a body at all.**
///
/// A refused request and a READ take the Part-I shape: compute the
/// outcome, DRAIN the content to the budget discarding it, render with
/// the tear-down signal on exactly the overflow arm. The common case
/// costs one `frame()` returning `None`.
///
/// An admitted WRITE takes the accept shape ([`accept_and_dispatch`]):
/// the content is bounded, counted and kept, and only then does the seam
/// see it.
///
/// **§5.5's "the content is dealt with before the response is rendered"
/// holds on both, including admitted writes.** Part I
/// could say something stronger — the outcome was computed before the
/// body was touched — and that sentence is now false, necessarily: a
/// `PUT` outcome is a function of the content. What survives is the
/// property §5.5 actually asks for.
///
/// **This is also where per-request instrumentation lives**, for a
/// reason that is not tidiness: it is the one function that runs exactly
/// once per request and sees both ends of it. The span opens here so it
/// covers gate → dispatch → drain → render, and the `served` event is
/// dispatched here so there is exactly one per request — a counter
/// emitted from [`render`] would be per-RENDER, and a counter emitted at
/// each of the ELEVEN rendering exits below `answer` would be a counter
/// missing from the twelfth somebody adds.
///
/// **Generic in the body for the same reason [`answer`] is**: hyper's
/// `Incoming` has no constructor, so an instrumented path that only
/// accepted one would be unreachable from a unit row and the instrumentation guarantee
/// would be asserted rather than measured.
async fn respond<R, B>(
    store: &R,
    base: &str,
    policy: VerifyPolicy,
    max_extent: Option<u32>,
    bounds: Bounds<'_>,
    request: Request<B>,
) -> Response<Full<Bytes>>
where
    R: RootStore + BinStore,
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = request.into_parts();
    // Public status is a cached projection. Other requests demand observation
    // without delaying anonymous reads; writes await a later refresh below.
    if !is_status_target(parts.uri.path(), base)
        && let Some(reader) = bounds.debug_grants
    {
        reader.trigger();
    }
    // **BEFORE any `Limited` wrap**, and that ordering is load-bearing:
    // `Limited` reports its own size hint, so a declared length read
    // through it would be this server's cap rather than the peer's
    // claim — and the claim is what §5a.2 makes advisory and what the
    // fast-path refusal is entitled to act on.
    let declared_len = body.size_hint().exact();
    // `Relaxed` is the whole ordering this counter needs: nothing is
    // published through it and nothing is read behind it, so the only
    // property asked of the atomic is that no two requests get the same
    // number. `fetch_add` gives that under any ordering.
    let request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    // **`request_id`, a BUCKETED `method`, and `wire_request_id`.**
    // `wire_request_id` is a peer-chosen string admitted only in its validated
    // shape (at most 64 ASCII letters, digits, dots, underscores or hyphens);
    // malformed values are omitted. The target path is absent entirely and
    // the method is rendered through [`method_label`], which has nine possible
    // outputs. The wire number and the §8.2 token are what a counter buckets,
    // and `operation` below is the bounded name of the endpoint.
    let span = tracing::info_span!(
        "grain_request",
        request_id,
        wire_request_id = request_id_field(&parts.headers),
        method = method_label(&parts.method)
    );
    // Cloned BEFORE `bounds` moves into `answer` below — an
    // `Arc` bump, so `served` still has the process-wide handle it needs
    // to demote the response-byte total into, after `bounds` itself is
    // gone.
    let write_budget = Arc::clone(bounds.budget);
    // `.instrument`, never a guard held across an `.await`: an entered
    // span is thread-local, and a future that yields inside one leaves
    // it entered on a worker that has moved to another request.
    async move {
        // Set by `answer` the moment the gate resolves a target to one
        // of §4.2's operations, and left `None` on every refusal
        // that never got that far.
        let mut operation: Option<&'static str> = None;
        // Set by `answer` (by way of `accept_body`) on every
        // request that reaches the counting accept; `None` on every
        // read and on the declared-length fast-path refusal.
        let mut request_bytes: Option<u64> = None;
        let authority = bounds.authority;
        let publish_target = authority.is_some()
            && is_publish_target(
                parts
                    .uri
                    .path_and_query()
                    .map_or(parts.uri.path(), |p| p.as_str()),
                base,
            );
        let status_target = authority.and_then(|a| a.handle.as_ref()).is_some()
            && is_status_target(
                parts
                    .uri
                    .path_and_query()
                    .map_or(parts.uri.path(), |p| p.as_str()),
                base,
            );
        let mut principal = None;
        let mut response = answer(
            store,
            base,
            policy,
            max_extent,
            bounds,
            &parts.method,
            &parts.uri,
            &parts.headers,
            &parts.extensions,
            declared_len,
            body,
            &mut operation,
            &mut request_bytes,
            &mut principal,
        )
        .await;
        let intent_target = authority.is_some()
            && is_intent_target(
                parts
                    .uri
                    .path_and_query()
                    .map_or(parts.uri.path(), |p| p.as_str()),
                base,
            );
        if publish_target || status_target || intent_target {
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
        if let Some(authority) = authority
            && let Some(reason) = response.extensions().get::<crate::wire::ErrorToken>()
        {
            let admission_refusal = parts.method == Method::PUT
                && operation.is_some()
                && matches!(
                    reason,
                    crate::wire::ErrorToken::NoPrincipal
                        | crate::wire::ErrorToken::NotEnrolled
                        | crate::wire::ErrorToken::EnrollmentUnavailable
                        | crate::wire::ErrorToken::AuthorityManaged
                        | crate::wire::ErrorToken::RateLimited
                );
            let publish_refusal = publish_target
                && parts.method == Method::POST
                && ((response.status().is_client_error()
                    && response.status() != StatusCode::CONFLICT)
                    || response.status() == StatusCode::SERVICE_UNAVAILABLE);
            if admission_refusal || publish_refusal || intent_target {
                authority.counters.record(*reason, principal);
            }
        }
        served(&response, operation, request_bytes, &write_budget);
        response
    }
    .instrument(span)
    .await
}

/// The process-wide request counter behind `grain_request`'s
/// `request_id`.
///
/// **Neither a clock nor an RNG, so it crosses neither input seam.** A counter is
/// the whole requirement — a log reader needs to tell one request's
/// lines from another's, and a monotonic integer does that without
/// reading wall time (`Instant::now`, banned outside the `Clock` seam)
/// and without drawing randomness (banned outside `Rng`). It restarts at
/// `0` on every process, which is correct: correlation is within one
/// process's stderr, and the span's own close event carries the timing.
static REQUEST_ID: AtomicU64 = AtomicU64::new(0);

/// The label a non-standard method is logged as.
///
/// One value for the whole open half of RFC 9110's `method` production,
/// which is the point: the exact bytes carry no diagnostic value the
/// status code does not already carry — every method outside §4.2's three
/// is a `405` + `method-not-allowed`, and the `Allow` header the refusal
/// carries says what WAS permitted.
const OTHER_METHOD: &str = "other";

/// `grain_request`'s `method` field, BUCKETED to a closed set.
///
/// **The peer chooses this string and nothing upstream bounds it
/// usefully.** RFC 9110's `method` is a bare token, so `admit` refuses a
/// non-standard one with a `405` — but the refusal happens after the head
/// is parsed, and the head's own bound is hyper's: the h2 leg's
/// `max_header_list_size` is 16 KiB (`granary_net::accept`) and the h1
/// leg's default read buffer is 417 792 bytes, neither of which is a log
/// bound. Rendered verbatim the field is AMPLIFIED on the way out: the
/// JSON formatter writes a span's fields twice per line (once under
/// `span`, once under `spans`) and `FmtSpan::CLOSE` makes two lines per
/// request, measured at **300 551 rendered bytes for a 100 000-byte
/// method** — a factor of three, on a request refused `405` before any
/// authentication. That is the same "attacker-controlled cardinality"
/// the request target is kept out of the log for; the method is kept in,
/// with its domain closed.
///
/// The recognised set is exactly the one [`Method`] names as
/// associated constants — RFC 9110's eight plus RFC 5789's `PATCH` —
/// and every one is rendered as ITSELF so a log reader sees the real
/// verb. Everything else is [`OTHER_METHOD`]. Matched on `as_str`
/// rather than on the constants: `Method`'s extension arms hold a
/// boxed string, so a constant pattern would not be a structural
/// match.
///
/// The return type is the property. A `&'static str` cannot carry a
/// peer's bytes, so this is bounded by construction rather than by the
/// arms below being exhaustive of anything.
fn method_label(method: &Method) -> &'static str {
    match method.as_str() {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "CONNECT" => "CONNECT",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "PATCH" => "PATCH",
        _unrecognised => OTHER_METHOD,
    }
}

/// The per-request outcome counter: one `served` event, at INFO, inside
/// the request's span.
///
/// **Every field is read off the RESPONSE, not off a value carried
/// alongside it**, and that is what makes the event describe what the
/// peer actually got. A `status` threaded down from wherever the outcome
/// was decided is a second spelling of the wire status, free to drift
/// from it; `response.status()` cannot. The one field the response does
/// not carry is `operation`, which the gate resolved and no header
/// records.
///
/// **`overflowed` is read off `Connection: close`, which [`render`]
/// writes on exactly the [`Drain::Overflowed`] arm and on nothing else**
/// (`the_close_signal_is_on_exactly_the_overflowed_arm` pins that, and
/// `render_charged` is the only writer of the field). It is not
/// decoration: with `status` and `error` alone a `413`/`too-large` on a
/// `PUT bin` is ambiguous between the per-kind body cap and the
/// decompressed-sum refusal, because both are `413` + `too-large` +
/// `put_bin`. They differ in exactly this bit — the cap stops reading and
/// tears the connection down, the decompressed-sum refusal comes back from a seam
/// that was reached with the content fully read — so `operation` AND
/// `overflowed` together are what make a mis-set ingest limit countable,
/// which `operation` alone would not.
///
/// **`request_bytes` is a THIRD kind of `Option` field, alongside
/// `error` and `operation`, and keeps the SAME discipline**: `None`
/// records nothing at all, never a `0` a reader could mistake for an
/// empty body that was actually counted. It carries what
/// [`accept_body`] counted for THIS one request — never the
/// process-wide total, which lives on `WriteBudget` and is read
/// only by the shutdown snapshot writer.
///
/// **`write_budget` is where THIS event's `bytes` also lands, summed.**
/// The shutdown snapshot's `response_bytes_produced` is that running
/// total — the DEMOTED number (see the module's doc): produced,
/// never confirmed received, so it is kept for debugging and is never
/// the client-side total counted from response-body DATA frames.
fn served(
    response: &Response<Full<Bytes>>,
    operation: Option<&'static str>,
    request_bytes: Option<u64>,
    write_budget: &WriteBudget,
) {
    // Exact for `Full`, whose whole body is in hand; `0` is the honest
    // reading of a body whose length is unknown, and no such body is
    // constructible here.
    let bytes = response.body().size_hint().exact().unwrap_or(0);
    write_budget.record_response_bytes(bytes);
    // Every token this server writes comes from §8.2's closed vocabulary
    // through `HeaderValue::from_static`, so `to_str` cannot fail; `ok()`
    // rather than an `expect` because the no-panic rule does not take
    // exceptions for a log line.
    let error = response
        .headers()
        .get(GRANARY_ERROR)
        .and_then(|token| token.to_str().ok());
    let overflowed = response.headers().contains_key(CONNECTION);
    // `Option` fields record NOTHING when they are `None`
    // (`tracing_core`'s `impl<T: Value> Value for Option<T>`), so a
    // success carries no `error` key and a gate refusal carries no
    // `operation` key rather than a placeholder either could be confused
    // with.
    tracing::info!(
        status = response.status().as_u16(),
        error,
        bytes,
        request_bytes,
        overflowed,
        operation,
        "served"
    );
}

/// The whole of one request's policy, over a body of any shape.
///
/// Generic in the body so the accept path is drivable with no socket:
/// the write-budget shed, the whole-accept clock and the per-kind cap are all reachable
/// from a unit row this way, and the loopback battery then asserts the
/// same behaviour over a real connection rather than instead of it.
///
/// **`operation` is an OUT-parameter and the shape is deliberate.** The
/// `served` event needs the bounded endpoint name, which only the gate
/// knows, and eleven rendering exits sit below this function. Handing
/// the name back through the return type would rewrite every one of them
/// — the shape where the twelfth exit somebody adds is the one that
/// forgets. Written once, immediately after the gate resolves a target,
/// it is set on exactly the requests that HAVE an operation and left
/// `None` on the refusals that never got one.
///
/// **`request_bytes` is a second out-parameter, the same shape as
/// `operation` and for the same reason.** The `served` field needs
/// this ONE request's own counted body-byte total, which only
/// [`accept_and_dispatch`] (by way of [`accept_body`]) ever produces. It
/// stays `None` on every request that never reaches the counting
/// accept — every read, and the declared-length fast-path refusal,
/// which reads no frame at all — and is set to `Some(counted)` on every
/// one of `accept_body`'s five outcomes once that call has actually
/// run, matching the `Option` discipline the event already keeps for
/// `operation`: absent means "no body was ever counted", never a `0`
/// that could be confused with an empty body that was.
#[expect(
    clippy::too_many_arguments,
    reason = "the request head is passed as its parts because an Admitted borrows from a head that must outlive the dispatch; bundling them would need a struct that owns the borrows. The `operation` out-parameter for the `served` event is the last of them, and its shape is argued above; `request_bytes` is a second out-parameter of the identical shape, for the wire-snapshot work's `served` field"
)]
async fn answer<R, B>(
    store: &R,
    base: &str,
    policy: VerifyPolicy,
    max_extent: Option<u32>,
    bounds: Bounds<'_>,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    extensions: &Extensions,
    declared_len: Option<u64>,
    body: B,
    operation: &mut Option<&'static str>,
    request_bytes: &mut Option<u64>,
    principal_observed: &mut Option<PrincipalId>,
) -> Response<Full<Bytes>>
where
    R: RootStore + BinStore,
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let parts = HeadParts::of(headers);
    let range: Vec<&str> = parts.range_values.iter().map(String::as_str).collect();
    let fields: Vec<&str> = parts.field_names.iter().map(String::as_str).collect();

    // Exactly one field line AND valid UTF-8; anything else is `None`.
    let mut lines = headers.get_all(IF_NONE_MATCH).iter();
    let if_none_match = match (lines.next(), lines.next()) {
        (Some(only), None) => std::str::from_utf8(only.as_bytes()).ok(),
        (None, _) | (Some(_), Some(_)) => None,
    };

    let head = RequestHead {
        method: method.as_str(),
        // The WHOLE remainder of the request target, query included,
        // undecoded and unnormalised. `uri.path()` alone would DROP a
        // query before the gate ever saw it: §4.1 forms every target by
        // concatenation and §4.3 matches byte-for-byte, so
        // `/volume/v/max-seq?q=1` is not a §4.2 resource — but with the
        // query gone it parses as one, and every resource becomes
        // reachable under an unbounded alias space that intermediaries
        // cache as immutable. Handing over the full string lets the `?`
        // fail the grammar at step 1, where §5a.6's order wants it.
        // (Authority-form targets have no path-and-query and fall back
        // to the empty path, which the grammar refuses the same way.)
        path: uri
            .path_and_query()
            .map_or(uri.path(), |target| target.as_str()),
        base,
        range: &range,
        conditionals: Conditionals {
            if_none_match,
            fields: &fields,
        },
        // Advisory, carried, never consulted by the gate (§5a.2).
        declared_len,
    };

    let authority_enabled = bounds.authority.is_some()
        && (!is_status_target(head.path, base)
            || bounds.authority.and_then(|a| a.handle.as_ref()).is_some());
    let admitted = match admit_authority(&head, max_extent, authority_enabled) {
        Ok(admitted) => admitted,
        Err(refusal) => {
            let outcome = refusal.into_outcome();
            let drain = drain_to_budget(body, bounds.budget).await;
            return render(outcome, drain);
        }
    };
    // The BOUNDED name of one of §4.2's endpoints — never the
    // target the peer sent. Set here, before any exit below can be
    // taken, so every answer a resolved operation produces carries it.
    *operation = Some(admitted.operation().name());

    if let Operation::VolumeStatus { volume } = admitted.operation() {
        if let Some(handle) = bounds.authority.and_then(|a| a.handle.as_ref()) {
            return status::answer(handle, volume, body, &bounds).await;
        }
        let drain = drain_to_budget(body, bounds.budget).await;
        return render(Outcome::unknown_target(), drain);
    }

    answer_intent_or_other(
        store,
        policy,
        bounds,
        extensions,
        headers,
        admitted,
        declared_len,
        body,
        request_bytes,
        principal_observed,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Admitted request parts share the adapter lifetime"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Read and write dispatch retain their ordered resource controls"
)]
async fn answer_intent_or_other<R, B>(
    store: &R,
    policy: VerifyPolicy,
    mut bounds: Bounds<'_>,
    extensions: &Extensions,
    headers: &HeaderMap,
    admitted: Admitted<'_>,
    declared_len: Option<u64>,
    body: B,
    request_bytes: &mut Option<u64>,
    principal_observed: &mut Option<PrincipalId>,
) -> Response<Full<Bytes>>
where
    R: RootStore + BinStore,
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if let Operation::Intent {
        volume,
        operation: crate::authority::IntentOperation::Readback,
    } = admitted.operation()
    {
        let Some(authority) = bounds.authority else {
            return render(Outcome::unknown_target(), Drain::Drained);
        };
        // Enrollment refresh is readback work too: the shared pool and
        // permit-wait bound it before any principal lookup or intent access.
        let Ok(Some(Ok(read_permit))) = timeout(
            bounds.permit_wait,
            until_draining(&mut bounds.draining, bounds.read_permits.acquire()),
        )
        .await
        else {
            let drain = drain_to_budget(body, bounds.budget).await;
            return render(Outcome::unavailable(), drain);
        };
        let principal = match resolve_write_principal(extensions, &authority.reader).await {
            Ok(principal) => principal,
            Err(error) => {
                return render(
                    error.outcome(),
                    if declared_len == Some(0) {
                        Drain::Drained
                    } else {
                        Drain::Overflowed
                    },
                );
            }
        };
        *principal_observed = Some(principal.principal);
        if let Some(capture) = bounds.capture {
            capture.authenticated_request(principal.principal, admitted.operation());
        }
        let Some(handle) = authority.handle.as_ref() else {
            return render(Outcome::unknown_target(), Drain::Drained);
        };
        let outcome = match intent_within(
            bounds.reply_deadline(),
            until_draining(
                &mut bounds.draining,
                handle.intent(
                    volume,
                    principal.principal,
                    crate::authority::IntentOperation::Readback,
                    Vec::new(),
                ),
            ),
        )
        .await
        {
            Some(outcome) => outcome,
            None => Outcome::unavailable(),
        };
        let resident = u64::try_from(outcome.body_capacity()).unwrap_or(u64::MAX);
        if let Some(charge) = bounds.read_budget.take(resident) {
            drop(read_permit);
            let drain = drain_to_budget(body, bounds.budget).await;
            return render_charged(outcome, drain, Some(charge));
        }
        let drain = shed_then_drain(outcome, Some(read_permit), body, bounds.budget).await;
        return render(Outcome::unavailable(), drain);
    }

    match write_cap(admitted.operation()) {
        // A READ. §4.2 gives it no content; content that arrives anyway
        // is drained and discarded, exactly as in Part I.
        //
        // **The read path's two bounds live here, and they are two because one
        // number cannot be both.** Before the store there is nothing to
        // charge but the peer's own declaration, and charging that lets
        // the peer consume budget without supplying resident bytes; after the store there is a
        // buffer, and its size is a fact. So: a COUNT permit across the
        // store call, and a BYTE charge on what came back.
        None => {
            // 1 — the count permit, on the two reads this pool covers:
            // the range read, whose buffer no frozen per-kind cap
            // bounds, and the meta read, whose buffer DOES have a
            // frozen cap but whose unpermitted AGGREGATE required
            // the shared count bound. `until_draining` for the same reason the verify
            // queue has it: a request parked on a permit when a
            // SIGTERM lands must not outlive the drain.
            let read_permit = if takes_a_read_permit(&admitted) {
                match timeout(
                    bounds.permit_wait,
                    until_draining(&mut bounds.draining, bounds.read_permits.acquire()),
                )
                .await
                {
                    Ok(Some(Ok(permit))) => Some(permit),
                    // A closed semaphore is not a queue: nothing will
                    // ever issue a permit again, and refusing every read
                    // would be worse than proceeding without a bound this
                    // process no longer has. The verify queue's answer,
                    // for the verify queue's reason.
                    Ok(Some(Err(_closed))) => None,
                    // The queue did not clear, or the process is going
                    // away. Both are load, and §5.10's `unavailable` is
                    // the answer to load. Nothing was read from the
                    // store, so nothing is charged.
                    Ok(None) | Err(_) => {
                        let drain = drain_to_budget(body, bounds.budget).await;
                        return render(Outcome::unavailable(), drain);
                    }
                }
            } else {
                None
            };

            // The dispatch deadline covers the READ arm too. A deadline that bounded only
            // writes would leave every `GET` able to hang on a store
            // that stopped answering — and reads are the arm an
            // unauthenticated peer reaches most cheaply.
            let outcome = dispatch_within(
                store,
                admitted,
                Vec::new(),
                policy,
                bounds.dispatch_deadline,
                &mut bounds.draining,
            )
            .await;

            // 2 — the byte charge, on the buffer that came BACK.
            //
            // **CAPACITY, not length**: the allocation is what stays
            // resident, `Bytes::from` shrinks nothing, and an accounting
            // that under-counts is not an accounting. A `404` charges 0
            // and a short read charges the short read.
            //
            // **Taken while the permit is still held.** That ordering is
            // the whole reason the permit is a bound on the uncharged
            // transient: drop it first and a ninth read could enter the
            // store while this one's buffer is neither permitted nor
            // charged.
            let resident = u64::try_from(outcome.body_capacity()).unwrap_or(u64::MAX);

            // **CHARGED and SHED sequence their releases differently, and
            // the difference is what takes over from the permit.** On the
            // charged path the CHARGE does: these bytes are accounted
            // from here to the response body's destructor, so the permit
            // goes back and the buffer travels with the response. On the
            // shed path NOTHING does — the budget has just said it cannot
            // hold them — so keeping them across the drain would be the
            // bound defeating itself: at the exact moment the process
            // declares itself too loaded to hold this buffer it would
            // hold it anyway, uncharged, with the permit already given
            // back, and N concurrent sheds would each keep an extent
            // resident with nothing accounting for any of them. There the
            // bytes go FIRST and the permit outlives them
            // ([`shed_then_drain`]).
            if let Some(charge) = bounds.read_budget.take(resident) {
                drop(read_permit);
                let drain = drain_to_budget(body, bounds.budget).await;
                render_charged(outcome, drain, Some(charge))
            } else {
                let drain = shed_then_drain(outcome, read_permit, body, bounds.budget).await;
                render(Outcome::unavailable(), drain)
            }
        }
        Some(cap) => {
            let write = match admit_write(
                bounds.authority,
                bounds.capture,
                bounds.debug_grants,
                extensions,
                admitted,
                principal_observed,
            )
            .await
            {
                Ok(write) => write,
                Err(outcome) => {
                    // Refuse without polling content. Only an exact zero
                    // leaves nothing unread; an unknown length still closes.
                    let drain = if declared_len == Some(0) {
                        Drain::Drained
                    } else {
                        Drain::Overflowed
                    };
                    return render(outcome, drain);
                }
            };
            accept_and_dispatch(
                store,
                policy,
                bounds,
                write,
                headers,
                cap,
                declared_len,
                body,
                request_bytes,
            )
            .await
        }
    }
}

/// The admitted operation and its principal's in-flight write permit.
struct AdmittedWrite<'a> {
    admitted: Admitted<'a>,
    authority: Option<(WritePrincipal, WritePermit)>,
}

impl AdmittedWrite<'_> {
    fn permit(&self) -> Option<&WritePermit> {
        self.authority.as_ref().map(|(_, permit)| permit)
    }
}

/// The write-only gate. Target, method and conditionals have already passed.
/// Inventory-based refusal belongs between principal resolution and controls;
/// publish admission uses the same controls with `is_publish = true`.
async fn admit_write<'a>(
    authority: Option<&AuthorityWrites>,
    capture: Option<&crate::diagnostics::CaptureHandle>,
    debug_grants: Option<&crate::debug_grant::reader::DebugGrantReader>,
    extensions: &Extensions,
    admitted: Admitted<'a>,
    principal_observed: &mut Option<PrincipalId>,
) -> Result<AdmittedWrite<'a>, Outcome> {
    let Some(authority) = authority else {
        return Ok(AdmittedWrite {
            admitted,
            authority: None,
        });
    };
    let principal = resolve_write_principal(extensions, &authority.reader)
        .await
        .map_err(crate::principal::PrincipalRefusal::outcome)?;
    *principal_observed = Some(principal.principal);
    if let Some(reader) = debug_grants {
        let _snapshot = reader.refresh().await;
    }
    if let Some(capture) = capture {
        capture.authenticated_request(principal.principal, admitted.operation());
    }
    if let Operation::PutRoot { volume, .. } = admitted.operation()
        && authority.volumes.contains(volume)
    {
        return Err(Outcome::authority_managed());
    }
    // Intent writes and publish share the principal submission allowance.
    let submission = matches!(
        admitted.operation(),
        Operation::Publish { .. } | Operation::Intent { .. }
    );
    let permit = authority
        .controls
        .admit(principal.principal, submission)
        .map_err(crate::controls::ControlRefusal::outcome)?;
    Ok(AdmittedWrite {
        admitted,
        authority: Some((principal, permit)),
    })
}

/// The SHED sequence: give up the bytes, then the permit, then drain.
///
/// **Three statements, and the ORDER is the whole content of the
/// function.** A shed happens because the budget has just refused to
/// account for this buffer; from that instant the buffer is memory
/// nothing is watching, so it must not survive into an await whose length
/// the peer sets. `drain_to_budget` is exactly such an await —
/// [`DRAIN_MAX_WAIT`] of it, times every stream a peer cares to shed on.
/// And the permit goes SECOND, not first: it is the only bound left over
/// bytes the budget cannot see, so releasing it while they are still
/// resident admits the next read into the store against a transient that
/// is already there.
///
/// **Generic over what is being given up, and that is for the test.** The
/// buffer is a `Vec<u8>` inside an [`Outcome`], and a `Vec`'s destructor
/// is unobservable to safe Rust — `unsafe_code` is `forbid` on the
/// workspace line, so a counting allocator is not available to this
/// suite either. A parameter is: a test passes a value whose `Drop` it
/// can watch and reads, from inside the drained body, whether the drop
/// had already happened. Nothing else in this crate can see the
/// difference between the two orderings, because both leave the same
/// status, the same budget and the same permit count behind.
async fn shed_then_drain<T, B: Body + Unpin>(
    holding: T,
    permit: Option<SemaphorePermit<'_>>,
    body: B,
    budget: &WriteBudget,
) -> Drain {
    drop(holding);
    drop(permit);
    drain_to_budget(body, budget).await
}

/// An admitted write: bound the content, keep it, then submit to the
/// authority or dispatch to the store seam.
///
/// **The order is fixed.**
///
/// 1. Publish field validation, then the declared-length FAST PATH.
///    A peer declaring more than the cap is refused without a byte of its content being read and without
///    the budget being touched. §5a.2 forbids the declaration STANDING
///    IN for the count, and this does not: it refuses on it, which is
///    an answer the counted bound would also give, and it never
///    ACCEPTS on it. RFC 9110 §15.5.14 licenses exactly this.
/// 2. An EMPTY budget claim, grown a granule at a time as content lands.
///    The declaration is not what is charged — §5a.2 again — and neither
///    is the endpoint's worst case: a charge sized to what this KIND
///    might send bounds the process correctly and bills a one-kilobyte
///    upload 256 MiB for it, which turns a budget for eight maximal bins
///    into a budget for eight writes of any size at all.
/// 3. The accept clock around the WHOLE counting read. One timeout for
///    the whole accept and never one per frame: a per-frame bound is
///    re-armed by every arriving byte, so a peer trickling one frame
///    inside each window holds its charge forever.
/// 4. The DRAIN RACE, around the same read and around the permit below.
///    The clock in step 3 is longer than the transport's shutdown
///    deadline and cannot be shortened to fit under it, so this is what
///    stops an in-flight upload from turning a deploy's graceful drain
///    into the forced exit.
/// 5. Publish submits to the authority under the dispatch deadline and
///    the drain race, then returns its answer. Other writes acquire the
///    verify permit only where a verify will happen, AFTER
///    the content is in hand and BEFORE the seam call — and bounded,
///    because a queue drawn from every write the budget admits is not
///    something a request may join indefinitely while holding its bytes.
/// 6. Non-publish writes dispatch to the seam under its dispatch deadline
///    and under the SAME drain race ([`dispatch_within`]). Step 4 covers the awaits before the
///    seam and not the one inside it, and a store that stops answering
///    is exactly where a request is parked when a SIGTERM arrives.
///
/// **Everything acquired is RAII.** The charge and the permit are
/// locals; every one of this function's exits — including the future
/// being dropped mid-await when the peer disappears — releases both.
///
/// **The tear-down signal is on exactly the arms that leave content
/// UNREAD**, which is §5.5's own rule and not a per-status table: a
/// `413` from the fast path has a whole body still coming and closes; a
/// `400` from the seam, and a `503` from the permit queue, had their
/// content fully read and do not.
#[expect(
    clippy::too_many_arguments,
    reason = "`request_bytes` is the out-parameter `answer` already carries — see its own doc — threaded one level further to the call that actually produces the value"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Admission, byte charging and dispatch form one ordered request path"
)]
async fn accept_and_dispatch<R, B>(
    store: &R,
    policy: VerifyPolicy,
    mut bounds: Bounds<'_>,
    write: AdmittedWrite<'_>,
    headers: &HeaderMap,
    cap: BodyCap,
    declared_len: Option<u64>,
    body: B,
    request_bytes: &mut Option<u64>,
) -> Response<Full<Bytes>>
where
    R: RootStore + BinStore,
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let admitted = &write.admitted;
    let publish_fields = if matches!(admitted.operation(), Operation::Publish { .. }) {
        let Some(fields) = publish::fields(headers) else {
            return render(Outcome::bad_request(), Drain::Overflowed);
        };
        Some(fields)
    } else {
        None
    };
    // 1 — the declared-length fast path. Reads no frame at all —
    // `accept_body` never runs — so `request_bytes` stays `None`: this
    // arm contributes NOTHING to either counter, stated here and at the
    // process-wide counter's own call site.
    if declared_len.is_some_and(|declared| declared > cap.limit) {
        return render(cap.refusal(), Drain::Overflowed);
    }

    // 2 — an empty claim on the process budget. It holds nothing until
    // content lands, so a peer that sends nothing costs nothing.
    let mut charge = bounds.budget.claim();

    // 3 and 4 — the whole-accept clock, and the drain race inside it.
    // The `else` covers BOTH ways the read can end without content: the
    // clock expired, or the process is going away and the rest of this
    // body is not worth the drain deadline. Both are load, so both are
    // §5.10's answer. **The process-wide counter loses nothing here even
    // so**: it lives on `bounds.budget`, outside this future, so every
    // frame `accept_body` had already counted before the timeout or the
    // drain fired stays counted. What IS lost is this one request's
    // OWN total for the `served` field — the future carrying it was
    // dropped mid-count — so `request_bytes` stays `None` on this arm
    // specifically, a distinct "not recoverable" rather than "no body".
    let Ok(Some((accepted, counted))) = timeout(
        WRITE_ACCEPT_MAX_WAIT,
        until_draining(
            &mut bounds.draining,
            accept_body(body, cap.limit, &mut charge, write.permit()),
        ),
    )
    .await
    else {
        return render(Outcome::unavailable(), Drain::Overflowed);
    };
    // `accept_body` ran to one of its five outcomes below, so this
    // request's counted total is known regardless of which.
    *request_bytes = Some(counted);
    let content = match accepted {
        Accepted::Body(content) => content,
        Accepted::TooLarge => return render(cap.refusal(), Drain::Overflowed),
        Accepted::RateLimited(refusal) => return render(refusal.outcome(), Drain::Overflowed),
        Accepted::BudgetExhausted => return render(Outcome::unavailable(), Drain::Overflowed),
        // The peer broke its own message. There is nothing conforming to
        // say about a request that never arrived, and on h1 hyper has
        // already failed the connection, so this response is a value the
        // peer will not read — written rather than left to a panic or an
        // `Infallible` this layer does not have.
        Accepted::TransportRejected => return render(Outcome::bad_request(), Drain::Overflowed),
    };

    if let Operation::Intent { volume, operation } = admitted.operation() {
        let Some((principal, _)) = &write.authority else {
            return render(Outcome::internal(), Drain::Drained);
        };
        let Some(handle) = bounds.authority.and_then(|a| a.handle.as_ref()) else {
            return render(Outcome::unknown_target(), Drain::Drained);
        };
        let outcome = match intent_within(
            bounds.reply_deadline(),
            until_draining(
                &mut bounds.draining,
                handle.intent(volume, principal.principal, *operation, content),
            ),
        )
        .await
        {
            Some(outcome) => outcome,
            None => Outcome::unavailable(),
        };
        return render(outcome, Drain::Drained);
    }

    if let Operation::Publish { volume } = admitted.operation() {
        let Some((principal, _)) = &write.authority else {
            return render(Outcome::internal(), Drain::Drained);
        };
        let Some(handle) = bounds.authority.and_then(|a| a.handle.as_ref()) else {
            return render(Outcome::internal(), Drain::Drained);
        };
        let Some((epoch, operation)) = publish_fields else {
            return render(Outcome::internal(), Drain::Drained);
        };
        let submission = Submission::new(
            principal.tenant.to_tenant(),
            principal.principal.to_principal(),
            volume.clone(),
            epoch,
            operation,
            content,
        );
        let deadline = bounds.reply_deadline();
        let answer = publication_reply(handle, submission, &mut bounds.draining, deadline).await;
        let outcome = answer
            .as_ref()
            .map_or_else(Outcome::unavailable, publish::outcome);
        return render(outcome, Drain::Drained);
    }

    // 5 — the verify permit, on exactly the requests that verify.
    let _permit = if verifies(admitted, policy) {
        match timeout(
            bounds.permit_wait,
            until_draining(&mut bounds.draining, bounds.permits.acquire()),
        )
        .await
        {
            Ok(Some(Ok(permit))) => Some(permit),
            // A closed semaphore is not a queue: nothing will ever issue
            // a permit again, and refusing to verify would be worse than
            // proceeding without a CPU bound this process no longer has.
            Ok(Some(Err(_closed))) => None,
            // The queue did not clear, or the process is going away.
            // The content was read to its end either way, so nothing is
            // left unread and the connection stays usable.
            Ok(None) | Err(_) => return render(Outcome::unavailable(), Drain::Drained),
        }
    } else {
        None
    };

    let outcome = dispatch_within(
        store,
        write.admitted,
        content,
        policy,
        bounds.dispatch_deadline,
        &mut bounds.draining,
    )
    .await;
    // The content was read to its end, so nothing is left unread and the
    // connection stays usable whatever the seam answered.
    render(outcome, Drain::Drained)
}

/// Wait for an authority publication reply under the gateway's drain race.
pub(crate) async fn publication_reply(
    handle: &crate::AuthorityHandle,
    submission: Submission,
    draining: &mut watch::Receiver<bool>,
    deadline: Option<Duration>,
) -> Option<crate::authority::Answer> {
    #[cfg(feature = "crash-points")]
    let mut dispatched = false;
    #[cfg(feature = "crash-points")]
    let observed = submission.clone();
    // Dropping submit drops only its reply; retransmission converges on
    // the same durable decision if the engine has already accepted it.
    #[cfg(feature = "crash-points")]
    let reply = handle.submit_observed(submission, || {
        dispatched = true;
        observed.observe_dispatch();
    });
    #[cfg(not(feature = "crash-points"))]
    let reply = handle.submit(submission);
    let raced = until_draining(draining, reply);
    let (answer, expired) = if let Some(deadline) = deadline {
        match timeout(deadline, raced).await {
            Ok(answer) => (answer, false),
            Err(_) => (None, true),
        }
    } else {
        (raced.await, false)
    };
    #[cfg(feature = "crash-points")]
    if dispatched && expired {
        crate::authority::crash::observe_dispatch_loss();
    }
    #[cfg(not(feature = "crash-points"))]
    let _ = expired;
    answer
}

/// One seam dispatch, bounded — and RACING THE DRAIN.
///
/// **The clock wraps the WHOLE await**, which is the only shape that
/// bounds anything: the store below has its own retries and its own
/// per-request timeouts, so a bound on one attempt is re-armed by the
/// next and the request outlives every one of them.
///
/// **The clock is not what keeps a dispatch from outliving a shutdown;
/// [`until_draining`] is** — the same answer, and the same mechanism,
/// [`accept_and_dispatch`] gives the counting read and the permit queue.
/// `STORE_DISPATCH_DEADLINE` is thirty seconds and
/// [`SHUTDOWN_DEADLINE`] is ten, and the ordering cannot be fixed by
/// moving either figure: a deadline short enough to fit under the drain
/// would refuse a bucket that is merely slow, and a drain long enough to
/// cover this one would make every deploy wait out the slowest stall it
/// happens to catch. So a request inside the seam when the process
/// starts going away is ABANDONED and shed at once — without it, a
/// SIGTERM arriving mid-dispatch holds its connection for the remaining
/// deadline, the drain expires with the connection resident, and a clean
/// deploy exits `EXIT_DEADLINE_EXPIRED` instead of `0`.
///
/// **The drain arm is a shed, not a rollback, and on a WRITE that
/// matters.** The seam call may already have issued its store
/// operation, and abandoning the future here drops that operation's
/// future rather than undoing it: the object may still land. That is
/// exactly §5.5's "a publish reported FAILED may have LANDED" case, and
/// it is the answer any refusal taken after the seam was entered gives
/// — the client's remedy is the same idempotent re-publish, because
/// every write this server takes is content-addressed or CAS-guarded.
/// The alternative is to keep holding the connection, which is the
/// forced exit this race exists to prevent.
///
/// Both exits render §5.10's `503`/`unavailable` — the SAME
/// [`Outcome::unavailable`] the accept clock, the budget shed and the
/// permit queue already answer with, not a second spelling of it. A
/// dropped connection would be the alternative, and is forbidden here:
/// a client reads a close as retryable, and a status is what
/// keeps the contract. The CALLER decides the tear-down signal, and
/// neither caller reaches this with content unread — so a shed here is
/// `Drain::Drained` and the connection stays usable.
async fn dispatch_within<R: RootStore + BinStore>(
    store: &R,
    admitted: Admitted<'_>,
    content: Vec<u8>,
    policy: VerifyPolicy,
    deadline: Option<Duration>,
    draining: &mut watch::Receiver<bool>,
) -> Outcome {
    // The race is INSIDE the clock, the same nesting the accept uses: a
    // `None` deadline is a store that cannot stop answering, and it is
    // not a licence to outlive the drain.
    let raced = until_draining(draining, dispatch(store, admitted, content, policy));
    let Some(deadline) = deadline else {
        return raced.await.unwrap_or_else(Outcome::unavailable);
    };
    match timeout(deadline, raced).await {
        Ok(Some(outcome)) => outcome,
        // The deadline expired, or the process is going away. Both are
        // load and both are §5.10's answer.
        Ok(None) | Err(_) => Outcome::unavailable(),
    }
}

/// Will this request run `verify_bin`? The verify permit is acquired for
/// exactly these and for nothing else — a `PUT root` waiting behind a
/// verify would be a bound on the wrong thing.
fn verifies(admitted: &Admitted<'_>, policy: VerifyPolicy) -> bool {
    policy.verifies() && matches!(admitted.operation(), Operation::PutBin { .. })
}

/// Will this request take the read-count permit? Acquired for exactly
/// these and for nothing else.
///
/// **The scope, and the trade each member takes it for.** The ranged
/// read: §7.1's declared maximum extent, 78 479 383 bytes, two orders of
/// magnitude above every other read's frozen cap, and no frozen
/// per-kind cap of its own — the largest UNCHARGED transient this
/// server holds (a maximal `PUT bin` body is larger, but it takes a
/// claim on the write budget before the bytes are read).
/// The meta read: a frozen 16 MiB cap, but the binmap-shard fetch path
/// hammers it, and its unpermitted AGGREGATE had no count bound —
/// the permit was extended to it once a measured concurrency profile
/// existed and a `503` reached the client as a typed,
/// backpressured answer rather than a hard failure, satisfying both
/// conditions for extending the pool.
///
/// **Why the remaining three stay outside.** A permit would bound `GET
/// root` and `GET hint` no tighter than their frozen caps already do;
/// `max-seq`'s currency is backend round trips, not resident bytes;
/// and capping the cheapest requests this server answers at
/// eight in flight is an explicitly rejected remedy.
/// What that leaves unbounded is the AGGREGATE of the unpermitted
/// paths, and [`PERMITTED_READ_TRANSIENT_CEILING_BYTES`] states plainly
/// that it does not count them.
fn takes_a_read_permit(admitted: &Admitted<'_>) -> bool {
    matches!(
        admitted.operation(),
        Operation::GetBinRange { .. } | Operation::GetMeta { .. }
    )
}

#[cfg(test)]
mod tests;

fn request_id_field(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all("granary-request-id").iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some()
        || !(1..=64).contains(&value.len())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return None;
    }
    Some(value)
}

async fn intent_within<F: std::future::Future>(deadline: Option<Duration>, future: F) -> F::Output
where
    F::Output: Default,
{
    if let Some(deadline) = deadline {
        timeout(deadline, future).await.unwrap_or_default()
    } else {
        future.await
    }
}
