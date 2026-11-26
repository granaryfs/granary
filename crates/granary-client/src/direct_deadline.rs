// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A per-call deadline for the route the `HttpStore` seam clock
//! cannot reach: every `RootStore`/`BinStore` call made through the
//! direct-S3 remote (`PublishRoute::DirectS3`) runs under its own flat
//! deadline and expires to the DISTINCT `RootStoreError::Elapsed` the
//! `rootstore` module doc prescribes, so `commit`'s unconditional
//! one-probe branch resolves an elapsed `put_root` exactly like any
//! other `put_root` failure.
//!
//! Defence in depth, not the load-bearing bound on every call. Eight of
//! the ten wrapped methods each issue a single S3 request SEQUENCE —
//! `object_store` re-issues a ranged request on a response-body error
//! inside ONE retry context (`src/client/get.rs`'s `retry_stream`), so
//! "one request" is false where "one envelope" is true — already
//! bounded first by [`DIRECT_STORE_REQUEST_TIMEOUT`] (30 s, set
//! explicitly on the builder in `route.rs` rather than left to
//! `object_store`'s own default) plus `object_store`'s own retry
//! envelope on that sequence ([`DIRECT_STORE_RETRY_BUDGET`]/
//! [`DIRECT_STORE_MAX_RETRIES`]/[`DIRECT_STORE_MAX_BACKOFF`]/
//! [`DIRECT_STORE_INIT_BACKOFF`]/[`DIRECT_STORE_BACKOFF_BASE`], also
//! stated explicitly). [`DIRECT_STORE_CALL_DEADLINE`] leaves room for
//! that entire sequence when no credential fetch precedes it.
//!
//! `max_seq` and `max_seq_above` can both walk multiple pages. Only the
//! outer deadline bounds the whole walk because the retry budget is
//! PER PAGE, not per walk:
//! `send_retry` builds a fresh `RetryContext` for every request
//! (`src/client/retry.rs`), so each page of the listing gets its own
//! full [`DIRECT_STORE_RETRY_BUDGET`] and a walk of arbitrarily many
//! pages has no inner bound at all. The number of pages the outer
//! clock allows depends on how long each takes: roughly four
//! fully-throttled pages (225 s of envelope apiece) fit inside the
//! 15 minutes, while pages that answer promptly cost almost nothing
//! and thousands of them fit.
//!
//! The outer clock clears ONE envelope by construction, not every
//! sequence a call might run, and the gap is real rather than
//! theoretical. On the no-static-credential path (`route.rs`'s IMDS
//! fallback), fetching a fresh credential can itself spend up to three
//! retryable requests — a token, a role name, a credential — each
//! under its OWN envelope, before the actual S3 request even starts
//! its own. Those three do NOT have to fail to hurt: each can SUCCEED
//! late, spending most of its envelope and answering, and the S3
//! request that follows is then left less than one full envelope of
//! the outer clock. That is exactly the pre-emption the compile-time
//! assert below exists to prevent — the outer clock deciding an
//! outcome the inner retry sequence was still working — and the assert
//! cannot see it, because it sums ONE envelope and this path runs
//! four.
//!
//! What a cut there costs is bounded and already handled: on
//! `put_root` it lands in `commit`'s one-probe branch like any other
//! `put_root` failure, and on a bin it lands on a put-if-absent PUT
//! that the next publish simply re-attempts. The FIGURE is therefore
//! unchanged in this revision; the choice between raising
//! [`DIRECT_STORE_CALL_DEADLINE`] to clear four envelopes and giving
//! the credential provider a budget of its own is carried in the
//! register, not decided here.

use std::time::Duration;

use granary_core::binstore::BinStore;
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::rootstore::{HintRead, HintToken, RootStore, RootStoreError};

use crate::http_store::under_deadline;

/// 15 minutes, per CALL: each `max_seq` or `max_seq_above` walk gets
/// that whole allowance, and nothing caps the SUM of an honest publish's calls.
/// [`DIRECT_STORE_REQUEST_TIMEOUT`] (plus [`DIRECT_STORE_RETRY_BUDGET`]'s
/// retry envelope and [`DIRECT_STORE_MAX_BACKOFF`]'s capped sleep)
/// bounds each page's S3 request sequence. This deadline caps the time
/// a wedged or malicious listing can spend across pages.
/// (`from_mins`, not `from_secs(900)` — clippy's
/// `duration_suboptimal_units` is deny-by-CI here.)
pub(crate) const DIRECT_STORE_CALL_DEADLINE: Duration = Duration::from_mins(15);

/// `object_store` 0.14.1's own default for `ClientOptions::with_timeout`
/// — 30 seconds — now STATED explicitly at the builder (`route.rs`'s
/// `s3_builder`) rather than left to whatever the dependency's default
/// happens to be on whichever version is locked. Named so
/// [`DIRECT_STORE_CALL_DEADLINE`] has something concrete to be bigger
/// than, and so a future `object_store` upgrade that changes the
/// inherited default cannot silently narrow the gap between the two
/// clocks.
///
/// The single-attempt FLOOR `put_bin` runs against, not a ceiling on the
/// whole PUT. `object_store`'s timeout runs from connect until the
/// response body completes for ONE attempt; a 5xx/429/408 answer, or a
/// connect/request error, IS retried and RESENDS the whole body on each
/// attempt, so a throttled bucket can cost several full uploads of one
/// bin inside the retry envelope below. What is NOT retried is a
/// shorter list than "a bare timeout" (`src/client/retry.rs:434-441`):
/// a TIMEOUT or an INTERRUPTED transfer is retried only for an
/// idempotent request, so neither is retried on `put_bin`'s create-only
/// conditional PUT, which is not marked idempotent; and an UNKNOWN or
/// DECODE error is retried for NO request, idempotent or not. Connect
/// and request errors are always retried, because the request was never
/// sent. Clearing this floor on that one un-retried
/// attempt needs roughly 2.1-8.5 MiB/s sustained for `put_bin`'s whole
/// body (`BIN_TARGET_BYTES`, 64 MiB target, up to `BIN_MAX_BYTES`, 256
/// MiB cap), where `HttpStore`'s own seam deadline instead SCALES with
/// the declared transfer size (`SEAM_DEADLINE_BASE` +
/// `SEAM_FLOOR_RATE_BYTES_PER_SEC`). This figure is deliberately NOT
/// operator-tunable in this revision: a per-request timeout that scales
/// with size (with [`DIRECT_STORE_CALL_DEADLINE`] raised to match — the
/// compile-time assert below forces the pairing) or a multipart upload
/// for large bins is a design change for the route's owner, not made
/// here.
pub(crate) const DIRECT_STORE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// `object_store` 0.14.1's own default `RetryConfig::retry_timeout`
/// (`src/client/retry.rs:252-259`) — the maximum length of time from a
/// request's FIRST attempt after which no further retry is made —
/// STATED explicitly on the builder alongside
/// [`DIRECT_STORE_REQUEST_TIMEOUT`], for the same reason: a future
/// upgrade that changes the inherited default must not silently move
/// the floor [`DIRECT_STORE_CALL_DEADLINE`] has to clear.
pub(crate) const DIRECT_STORE_RETRY_BUDGET: Duration = Duration::from_mins(3);

/// `object_store` 0.14.1's own default `RetryConfig::max_retries`
/// (`src/client/retry.rs:252-259`), stated alongside
/// [`DIRECT_STORE_RETRY_BUDGET`] for the same reason.
pub(crate) const DIRECT_STORE_MAX_RETRIES: usize = 10;

/// `object_store` 0.14.1's own default `BackoffConfig::max_backoff`
/// (`src/client/backoff.rs:40-47`) — the THIRD term of one call's
/// envelope, alongside [`DIRECT_STORE_REQUEST_TIMEOUT`] and
/// [`DIRECT_STORE_RETRY_BUDGET`]. It belongs in the supremum because
/// `RetryContext::exhausted` (`src/client/retry.rs:98-100`) is checked
/// BEFORE the backoff sleep in every retry arm: a retry authorised just
/// under the budget still sleeps up to this figure and then runs a full
/// attempt, so the true worst case is the budget PLUS one more sleep
/// PLUS one more attempt.
///
/// **The per-sleep supremum is `max(init_backoff, max_backoff)`, not
/// `max_backoff` alone.** `Backoff::next` returns
/// [`DIRECT_STORE_INIT_BACKOFF`] VERBATIM on the very first sleep — it
/// hands back the previous `next_backoff_secs`, which starts at
/// `init_backoff`, and only the values it stores for LATER sleeps pass
/// through `max_backoff.min(..)`. So an `init_backoff` above
/// `max_backoff` would produce one sleep above the cap. The two figures
/// below keep that supremum equal to `max_backoff`, and the
/// compile-time assert under them keeps it that way.
pub(crate) const DIRECT_STORE_MAX_BACKOFF: Duration = Duration::from_secs(15);

/// `object_store` 0.14.1's own default `BackoffConfig::init_backoff`
/// (`src/client/backoff.rs:40-47`), stated for the same reason as the
/// other four: the builder names every field of `BackoffConfig`, so the
/// figure this route runs on is this file's and not whichever version
/// happens to be locked.
pub(crate) const DIRECT_STORE_INIT_BACKOFF: Duration = Duration::from_millis(100);

/// `object_store` 0.14.1's own default `BackoffConfig::base`
/// (`src/client/backoff.rs:40-47`) — the multiplier the sleep's upper
/// range grows by. It does not enter the envelope's supremum (every
/// sleep after the first is clamped by [`DIRECT_STORE_MAX_BACKOFF`]);
/// it is named because the builder names every field.
pub(crate) const DIRECT_STORE_BACKOFF_BASE: f64 = 2.0;

/// `Backoff::next` draws each sleep from the range
/// `init_backoff..(next_backoff_secs * base)` — a RANGE with
/// `init_backoff` as its low end. Once a stored `next_backoff_secs` has
/// been clamped down to `max_backoff`, a `max_backoff` BELOW
/// `init_backoff` makes that range empty-or-inverted and
/// `rng.random_range` panics inside the dependency, on the retry path,
/// in production. Nothing in `object_store` refuses the pairing, so it
/// is refused here, at compile time.
const _: () = assert!(
    DIRECT_STORE_MAX_BACKOFF.as_nanos() >= DIRECT_STORE_INIT_BACKOFF.as_nanos(),
    "DIRECT_STORE_MAX_BACKOFF must be at least DIRECT_STORE_INIT_BACKOFF: object_store's \
     Backoff::next draws from init_backoff..(next * base) and clamps the stored next to \
     max_backoff, so a max below init is an inverted range and a panic in the dependency"
);

/// [`DIRECT_STORE_CALL_DEADLINE`] must clear `object_store`'s own retry
/// envelope IN FULL — all three terms, not just the request clock:
/// [`DIRECT_STORE_REQUEST_TIMEOUT`] (the final attempt) plus
/// [`DIRECT_STORE_RETRY_BUDGET`] (the time already spent retrying) plus
/// [`DIRECT_STORE_MAX_BACKOFF`] (the one sleep the budget check can
/// still authorise just before it expires; the assert just above keeps
/// that the per-sleep supremum) — 30 + 180 + 15 = 225 s at these
/// defaults. A per-call deadline at or below that sum would
/// pre-empt `object_store`'s own retry sequence mid-flight — turning a
/// RETRYABLE transient (a 503, say) into a NEVER-RETRIED `Elapsed`, the
/// outer clock deciding an outcome the inner envelope was still working
/// on. Raising any one inner figure raises the floor the outer one must
/// clear. `as_nanos`, the widest unit `Duration` exposes, so the
/// comparison is EXACT: `as_secs` truncates each term to whole seconds
/// and `as_millis` truncates each term's sub-millisecond component, and
/// either could pass a case where the true sum exceeds the deadline by
/// less than the truncated unit — all four are `const`, so exactness
/// costs a build and nothing else.
const _: () = assert!(
    DIRECT_STORE_CALL_DEADLINE.as_nanos()
        > DIRECT_STORE_REQUEST_TIMEOUT.as_nanos()
            + DIRECT_STORE_RETRY_BUDGET.as_nanos()
            + DIRECT_STORE_MAX_BACKOFF.as_nanos(),
    "DIRECT_STORE_CALL_DEADLINE must exceed DIRECT_STORE_REQUEST_TIMEOUT plus \
     DIRECT_STORE_RETRY_BUDGET plus DIRECT_STORE_MAX_BACKOFF (225 s at these \
     defaults), or this decorator's own deadline can fire before object_store's \
     retry envelope has finished working a retryable failure"
);

/// Wraps a `RootStore`/`BinStore` implementor so every call runs under
/// its own flat deadline, expiring to `RootStoreError::Elapsed`
/// rather than hanging forever on a wedged or malicious peer.
///
/// `pub`, and re-exported from `lib.rs` beside the route items: it is
/// the payload of the public `PublishRoute::DirectS3` variant, and a
/// `pub(crate)` payload of a public enum is rustc's `private_interfaces`
/// lint — an error under the deny-warnings gates.
#[derive(Debug)]
pub struct DirectStoreDeadline<S> {
    inner: S,
    deadline: Duration,
}

impl<S> DirectStoreDeadline<S> {
    /// Wrap `inner`; every call runs under `DIRECT_STORE_CALL_DEADLINE`.
    /// Every production decorator therefore carries the asserted
    /// constant — the invariant is structural, not merely tested.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self::with_deadline(inner, DIRECT_STORE_CALL_DEADLINE)
    }

    /// `new` with an arbitrary deadline instead of
    /// `DIRECT_STORE_CALL_DEADLINE`, so a walk that would otherwise take
    /// fifteen real minutes to cut can be driven under an unpaused clock
    /// in milliseconds.
    fn with_deadline(inner: S, deadline: Duration) -> Self {
        Self { inner, deadline }
    }
}

impl<S: RootStore> RootStore for DirectStoreDeadline<S> {
    async fn put_root(&self, volume: &str, seq: u64, bytes: Vec<u8>) -> Result<(), RootStoreError> {
        under_deadline(
            "PUT root",
            self.deadline,
            self.inner.put_root(volume, seq, bytes),
        )
        .await
    }
    async fn get_root(&self, volume: &str, seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        under_deadline("GET root", self.deadline, self.inner.get_root(volume, seq)).await
    }
    async fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> Result<HintRead, RootStoreError> {
        under_deadline(
            "GET hint",
            self.deadline,
            self.inner.read_hint(volume, cached),
        )
        .await
    }
    async fn write_hint(&self, volume: &str, seq: u64) -> Result<(), RootStoreError> {
        under_deadline(
            "PUT hint",
            self.deadline,
            self.inner.write_hint(volume, seq),
        )
        .await
    }
    async fn max_seq(&self, volume: &str) -> Result<Option<u64>, RootStoreError> {
        under_deadline("GET max-seq", self.deadline, self.inner.max_seq(volume)).await
    }
    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        under_deadline(
            "GET max-seq-above",
            self.deadline,
            self.inner.max_seq_above(volume, floor),
        )
        .await
    }
}

impl<S: BinStore> BinStore for DirectStoreDeadline<S> {
    async fn put_bin(
        &self,
        digest: &[u8; DIGEST_LEN],
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        under_deadline("PUT bin", self.deadline, self.inner.put_bin(digest, bytes)).await
    }
    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, RootStoreError> {
        under_deadline(
            "PUT meta",
            self.deadline,
            self.inner.put_meta(volume, id, bytes),
        )
        .await
    }
    async fn get_meta(&self, volume: &str, id: &GrainId) -> Result<Vec<u8>, RootStoreError> {
        under_deadline("GET meta", self.deadline, self.inner.get_meta(volume, id)).await
    }
    async fn get_bin_range(
        &self,
        digest: &[u8; DIGEST_LEN],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, RootStoreError> {
        under_deadline(
            "GET bin",
            self.deadline,
            self.inner.get_bin_range(digest, offset, len),
        )
        .await
    }
}

#[cfg(test)]
mod tests;
