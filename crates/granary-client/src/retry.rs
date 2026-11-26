// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Reason-scoped seam retry.
//!
//! [`classify`] and [`classify_lib_error`] are the whole of the decision
//! `HttpStore::send` acts on — [`RetryClass::Unsent`] is provably off-wire,
//! while CLASS A (`RetryClass::StreamRefused`) and CLASS B
//! (`RetryClass::ConnectionFailed`) carry the protocol's narrower retry
//! permissions. Everything else is
//! `RetryClass::NotRetryable`. The bound (at most one retry, `put_root`
//! excluded from CLASS B) lives at the call site in `http_store.rs`; this
//! module only answers "what kind of failure was this", and it answers
//! that from the `source()` chain, never from a rendered string — three
//! distinct causes shared the string `"SendRequest"` in the measurement
//! that motivated this classifier.

use std::error::Error as StdError;

/// What one failed wire attempt tells us about retrying it.
/// Reasons, never rendered strings — `SendRequest` covered
/// three distinct causes in one measured session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetryClass {
    /// The HTTP stack returned the request without sending it: connection
    /// acquisition failed, or hyper recovered the complete request from a
    /// canceled dispatcher. Safe to send once more on every seam because no
    /// byte or stream id was assigned to the request.
    Unsent,
    /// RFC 9113 §8.7: the server GUARANTEES the stream was closed
    /// before any processing. Safe to re-send once on every seam,
    /// `put_root` included — there is no ambiguity for the one-probe
    /// rule to resolve.
    StreamRefused,
    /// A transport-level failure with no complete response — a CLOSED
    /// list: a died connection (io in the chain), or a remote GOAWAY.
    /// Safe to re-send once on the eight idempotent
    /// seams; NEVER `put_root` — the request
    /// may have landed (and for GOAWAY, h2's teardown broadcast is
    /// unfiltered by stream id, so no per-stream non-processing
    /// guarantee is even expressible at this API).
    ConnectionFailed,
    /// Everything else: a read response, a refused body, a protocol
    /// error. Never retried here.
    NotRetryable,
}

/// Walk the `source()` chain and classify. The h2 downcast is sound
/// because the workspace pins exactly one h2 (the lock gate asserts
/// it) — hyper's h2 and ours are the same compiled crate.
pub(crate) fn classify(err: &(dyn StdError + 'static)) -> RetryClass {
    let mut cur: Option<&(dyn StdError + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(h2e) = e.downcast_ref::<h2::Error>() {
            if h2e.is_reset() && h2e.is_remote() && h2e.reason() == Some(h2::Reason::REFUSED_STREAM)
            {
                // RFC 9113 §8.7 is a REMOTE server's guarantee — a local
                // or library-initiated reset carries none.
                return RetryClass::StreamRefused;
            }
            if h2e.is_go_away() && h2e.is_remote() {
                // Remote GOAWAY: retry-safe for the eight eligible operations
                // whatever the processing state. The caller's allow flag enforces this.
                return RetryClass::ConnectionFailed;
            }
            return RetryClass::NotRetryable;
        }
        if e.is::<std::io::Error>() {
            // The connection died under the request (the measured
            // sub-millisecond checkout race renders here, as does a
            // cut established connection). No complete response
            // exists by construction on this path: a response, once
            // parsed, surfaces as a status, not an io error.
            return RetryClass::ConnectionFailed;
        }
        cur = e.source();
    }
    RetryClass::NotRetryable
}

/// Classify a `hyper_util` client failure, delegating to [`classify`]
/// once `hyper_util`'s own two signals are exhausted.
///
/// `is_connect()` is public on `hyper_util::client::legacy::Error` and
/// proves the request never left connection acquisition and covers both
/// halves of the `retry_canceled_requests(false)` comment
/// in `http_store.rs`: the TCP connect clock
/// ([`crate::http_store::CONNECT_TIMEOUT`]) and a pool checkout that
/// raced a closed connection (hyper-util 0.1.20
/// `client/legacy/client.rs:376-378`, also the `Connect` kind).
///
/// **`is_connect()` is BROAD, and that breadth is accepted rather than
/// narrowed.** `hyper_util` wraps every connector failure as `Connect`:
/// the TCP connect clock, the raced checkout above, and deterministic
/// failures such as DNS, a refused connection, or an SPKI pin rejection.
/// Because [`RetryClass::Unsent`] is permitted on every seam, each call can
/// therefore spend two bounded connect/handshake attempts instead of one on
/// such a failure. The repeated work is accepted: connection acquisition
/// proved that no HTTP request byte was sent, so it cannot change the answer.
///
/// `hyper_util`'s OWN `is_canceled()` — the "request reclaimed un-sent"
/// signal — is private to that crate
/// (`client.rs:1659`, no `pub`), so it cannot be called on `err`
/// directly. What IS reachable is the WRAPPED `hyper::Error` on `err`'s
/// `source()`: `try_send_request`'s `TrySendError::Retryable` arm
/// builds the outer error as `e!(Canceled, err.into_error())`, and
/// `send_request`'s loop — the `retry_canceled_requests` GATE itself,
/// cited by symbol rather than by line because the line has already
/// drifted once — surfaces that error to the caller as-is when the
/// flag is `false`. `err.into_error()` is a `hyper::Error` built at
/// `client::dispatch.rs:223` as `crate::Error::new_canceled()` — whose
/// OWN `is_canceled()` (`hyper::Error::is_canceled`, public) answers
/// true. So the check downcasts one level and asks the inner type.
///
/// A source-less `Canceled` produced on hyper-util's connect and ALPN paths
/// cannot be proven by this public error surface and deliberately remains
/// non-`Unsent`. Omitting it is fail-safe: it costs a resend opportunity and
/// cannot duplicate a request.
///
/// Everything else — an h2 reset or GOAWAY, or an io-kind chain link
/// (hyper's `new_h2` DISCARDS the `h2::Error` and substitutes the
/// unwrapped `io::Error` when `h2::Error::is_io()` — `hyper-1.11.1
/// src/error.rs:492-498` — which is exactly what [`classify`]'s
/// `io::Error` arm is for) — is [`classify`]'s to find on the
/// `source()` chain.
fn reclaimed_unsent(source: Option<&(dyn StdError + 'static)>) -> bool {
    source
        .and_then(|source| source.downcast_ref::<hyper::Error>())
        .is_some_and(hyper::Error::is_canceled)
}

pub(crate) fn classify_lib_error(err: &hyper_util::client::legacy::Error) -> RetryClass {
    if err.is_connect() {
        return RetryClass::Unsent;
    }
    if reclaimed_unsent(err.source()) {
        return RetryClass::Unsent;
    }
    classify(err)
}

#[cfg(test)]
mod tests;
