// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The bound on the HTTP/2 client connection preface.
//!
//! A peer that completes TLS, negotiates `h2` and then says nothing sits in a
//! window nothing else in the envelope can see. `h2` reads the 24-byte client
//! connection preface through a bare `poll_read` loop with no timer, and hyper
//! builds its keep-alive PING machinery only once that read has resolved — so
//! between "TLS finished" and "the preface arrived" no clock on the pinned API
//! is running, and the connection holds its accept-loop permit until the
//! process exits.
//!
//! [`PrefaceDeadline`] is that clock, and the whole of it. The window is
//! exactly plaintext bytes `0..=23` and it CLOSES ITSELF at byte 24, which is
//! where hyper's h2 handshake resolves and `h2_keep_alive_interval` takes over
//! — the SETTINGS frame is not awaited. So the decorator disarms permanently
//! at [`H2_PREFACE_LEN`] rather than staying in the path: everything after
//! that byte belongs to the keep-alive pair, and a decorator still armed then
//! would be killing established connections on a clock meant for setup.
//!
//! **HTTP/2 only.** `GET / HTTP/1.1\r\n\r\n` is 18 bytes — a COMPLETE HTTP/1.1
//! head, under 24 — so the same rule on the HTTP/1.1 leg would fire on a
//! healthy, already-served keep-alive connection. That leg's opening window is
//! bounded by hyper's own `header_read_timeout`, and this one is its mirror.
//!
//! **Above TLS.** The count is a count of PLAINTEXT bytes. Below TLS the
//! handshake's own reads would disarm the bound before the preface window even
//! opens, and that window already has its own timeout.
//!
//! **Where the clock comes from, and why the exemption is MARKED rather than
//! avoided.** `clippy.toml` bans `tokio::time::sleep` by name, and
//! this module calls it anyway, under a per-site `#[expect]` with a reason.
//! The exemption is real: the accept layer is the layer `granary-sim` REPLACES
//! rather than drives, the same basis on which `accept.rs`
//! wraps its awaits in `tokio::time::timeout`, and the `Clock` seam is
//! `now()` and nothing else — no sleep, no timer — so there is no seam API a
//! deadline could route through.
//!
//! It is written this way because the alternative was to route AROUND the
//! lint. A `hyper::rt::Sleep` from `hyper_util`'s `TokioTimer` is
//! `tokio::time::sleep` one layer down, so it would have bounded the window
//! identically while leaving no marker that a banned method is reached from
//! here. `clippy.toml` is explicit that this crate takes its exemptions as
//! per-site `#[expect]`s with reasons "instead of being written around", and
//! an unmarked exemption is one an audit of the seams cannot see.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

/// The length of the HTTP/2 client connection preface (RFC 9113 §3.4).
///
/// Also the exact point at which this bound stops applying, which is why it is
/// a named constant and not a literal: hyper's h2 handshake resolves on this
/// byte and arms the keep-alive from there.
pub(crate) const H2_PREFACE_LEN: usize = 24;

/// Where a decorated connection is in its preface window.
enum State {
    /// The preface is incomplete and this deadline is what bounds it.
    ///
    /// Boxed because `Sleep` is `!Unpin` and the decorator must not be: hyper
    /// requires `Unpin` of the IO it serves.
    Armed(Pin<Box<Sleep>>),
    /// The whole preface has been read. The connection is hyper's to bound
    /// from here, and this decorator is transparent for the rest of its life.
    Disarmed,
    /// The deadline expired. TERMINAL, and that is load-bearing: a decorator
    /// that reports one timeout and then goes transparent is one hyper can
    /// poll straight past.
    Expired,
}

impl State {
    /// The word this state prints as, for [`PrefaceDeadline`]'s `Debug`.
    fn name(&self) -> &'static str {
        match *self {
            Self::Armed(_) => "armed",
            Self::Disarmed => "disarmed",
            Self::Expired => "expired",
        }
    }
}

/// An `AsyncRead`/`AsyncWrite` decorator bounding how long a peer may take to
/// deliver the HTTP/2 client connection preface.
///
/// The deadline is ABSOLUTE: it is created once, in [`Self::new`], and nothing
/// re-creates or re-arms it. An idle-reset timeout is a different guarantee
/// and not the one this needs — a peer dribbling one byte at a time would push
/// a resettable deadline back forever without ever completing the preface.
///
/// Writes are untouched. Only the read side carries a clock.
pub(crate) struct PrefaceDeadline<IO> {
    io: IO,
    state: State,
    /// Cumulative plaintext bytes read. Meaningless once disarmed.
    read: usize,
}

impl<IO> PrefaceDeadline<IO> {
    /// Wrap `io`, giving the peer `within` to deliver the whole preface.
    ///
    /// The deadline is created HERE and never again — that is what makes it
    /// absolute rather than idle-reset.
    #[expect(
        clippy::disallowed_methods,
        reason = "the accept layer is the layer granary-sim replaces rather than drives, so its bounds run on the runtime clock; the Clock seam is now() alone and offers no sleep to route through"
    )]
    pub(crate) fn new(io: IO, within: Duration) -> Self {
        Self {
            io,
            state: State::Armed(Box::pin(tokio::time::sleep(within))),
            read: 0,
        }
    }
}

/// The error a peer sees when its preface never arrived.
fn expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "the http/2 client connection preface did not arrive in time",
    )
}

/// Manual because the inner IO is not required to be `Debug`. It is
/// deliberately not printed — what a reader needs here is whether the bound is
/// still armed and how far the preface got.
impl<IO> std::fmt::Debug for PrefaceDeadline<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrefaceDeadline")
            .field("state", &self.state.name())
            .field("read", &self.read)
            .finish_non_exhaustive()
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for PrefaceDeadline<IO> {
    /// The deadline is polled FIRST, before anything is delegated.
    ///
    /// That order is not a preference. Polling the deadline is also what
    /// registers this task's waker with the timer, so a peer that sends
    /// nothing at all — the case with no other event to wake on — is still
    /// woken when the bound expires.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.state {
            State::Expired => return Poll::Ready(Err(expired())),
            State::Armed(ref mut deadline) => {
                if deadline.as_mut().poll(cx).is_ready() {
                    this.state = State::Expired;
                    return Poll::Ready(Err(expired()));
                }
            }
            State::Disarmed => {}
        }

        // The DELTA, never `buf.filled().len()` outright: an outer layer may
        // hand down a buffer that is already partly filled, and those bytes
        // are not this decorator's to count.
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.io).poll_read(cx, buf);
        let delta = buf.filled().len().saturating_sub(before);

        if matches!(this.state, State::Armed(_)) {
            this.read = this.read.saturating_add(delta);
            if this.read >= H2_PREFACE_LEN {
                // Permanently, and the deadline goes with it.
                this.state = State::Disarmed;
            }
        }
        polled
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for PrefaceDeadline<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    /// Explicit rather than the trait default: the default de-optimises every
    /// vectored write hyper makes, silently.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    /// Same reason: answering `false` here is what makes callers stop offering
    /// vectored writes at all.
    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
