// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::preface` — the bound on the HTTP/2 client
//! connection preface (`PrefaceDeadline`): the window is exactly
//! plaintext bytes `0..=23` and closes itself at `H2_PREFACE_LEN`.
//!
//! Out-of-line: `granary-net`'s non-test artifact has
//! workspace consumers (`granary-client`,
//! `granary-server`), so the module's own tests move out
//! of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

use super::{H2_PREFACE_LEN, PrefaceDeadline};
use std::io;
use std::time::Duration;

/// The bound every test below arms.
///
/// Real time, second-scale on purpose: a paused clock would mean a new
/// dev-dependency feature, and the dependency checklist that comes with
/// it, for no behaviour this could not observe anyway.
const BOUND: Duration = Duration::from_secs(1);

/// A wait long enough to outlive `BOUND` several times over, so an
/// observation is about the decorator rather than about a busy machine.
const PAST_BOUND: Duration = Duration::from_secs(5);

/// The duplex buffer: bigger than anything written here.
const PIPE: usize = 4 * 1024;

/// Feed `n` bytes through the decorator ONE AT A TIME, so the count under
/// test has to accumulate across polls rather than see one big read.
async fn feed(peer: &mut DuplexStream, bounded: &mut PrefaceDeadline<DuplexStream>, n: usize) {
    for _ in 0..n {
        peer.write_all(b"x")
            .await
            .unwrap_or_else(|e| panic!("write: {e}"));
        peer.flush().await.unwrap_or_else(|e| panic!("flush: {e}"));
        let mut one = [0_u8; 1];
        bounded
            .read_exact(&mut one)
            .await
            .unwrap_or_else(|e| panic!("read: {e}"));
    }
}

/// Read once, waiting `PAST_BOUND` for something to happen.
///
/// `Err` is "still pending", which is what a disarmed decorator does on a
/// silent pipe; `Ok(Err(_))` is the deadline firing.
async fn idle_read(bounded: &mut PrefaceDeadline<DuplexStream>) -> Option<io::Error> {
    let mut buf = [0_u8; 8];
    match timeout(PAST_BOUND, bounded.read(&mut buf)).await {
        Err(_still_pending) => None,
        Ok(Ok(n)) => panic!("the pipe was silent, yet {n} bytes arrived"),
        Ok(Err(error)) => Some(error),
    }
}

/// The whole preface, delivered a byte at a time, disarms the bound —
/// permanently, so the deadline passing afterwards is a non-event.
#[tokio::test]
async fn the_whole_preface_across_many_reads_disarms_the_bound() {
    let (mut peer, io) = tokio::io::duplex(PIPE);
    let mut bounded = PrefaceDeadline::new(io, BOUND);

    feed(&mut peer, &mut bounded, H2_PREFACE_LEN).await;

    assert!(
        idle_read(&mut bounded).await.is_none(),
        "a disarmed decorator must never report the preface deadline"
    );
}

/// One byte short of it does NOT. This is the seam a first-byte disarm
/// falls through, and the reason the constant is a length and not a flag.
#[tokio::test]
async fn one_byte_short_of_the_preface_leaves_the_bound_armed() {
    let (mut peer, io) = tokio::io::duplex(PIPE);
    let mut bounded = PrefaceDeadline::new(io, BOUND);

    feed(&mut peer, &mut bounded, H2_PREFACE_LEN - 1).await;

    let error = idle_read(&mut bounded)
        .await
        .unwrap_or_else(|| panic!("{} bytes must not disarm the bound", H2_PREFACE_LEN - 1));
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

/// A `ReadBuf` that arrives ALREADY PARTLY FILLED must not be counted as
/// bytes this decorator read.
///
/// No socket test can construct this: an outer layer handing down a
/// part-filled buffer is invisible from the wire, and counting
/// `buf.filled().len()` outright rather than the delta would disarm the
/// bound here on four bytes.
#[tokio::test]
async fn a_partly_filled_read_buf_counts_only_the_delta() {
    use std::pin::Pin;
    use tokio::io::{AsyncRead, ReadBuf};

    let (mut peer, io) = tokio::io::duplex(PIPE);
    let mut bounded = PrefaceDeadline::new(io, BOUND);

    peer.write_all(b"abcd")
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    peer.flush().await.unwrap_or_else(|e| panic!("flush: {e}"));

    let mut storage = [0_u8; 64];
    let mut buf = ReadBuf::new(&mut storage);
    // Filled well past the preface length before this decorator sees it.
    buf.put_slice(&[0_u8; 40]);
    let filled_before = buf.filled().len();

    std::future::poll_fn(|cx| Pin::new(&mut bounded).poll_read(cx, &mut buf))
        .await
        .unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(
        buf.filled().len(),
        filled_before + 4,
        "the delta this decorator is responsible for is four bytes"
    );

    let error = idle_read(&mut bounded)
        .await
        .unwrap_or_else(|| panic!("four bytes must not disarm the bound"));
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

/// The expiry is STICKY: once fired, every later read reports it again —
/// even one with data waiting, which is exactly what hyper would find.
#[tokio::test]
async fn the_expiry_is_sticky_even_with_data_waiting() {
    let (mut peer, io) = tokio::io::duplex(PIPE);
    let mut bounded = PrefaceDeadline::new(io, BOUND);

    let first = idle_read(&mut bounded)
        .await
        .unwrap_or_else(|| panic!("a silent peer must hit the bound"));
    assert_eq!(first.kind(), io::ErrorKind::TimedOut);

    // The whole preface, arriving too late to matter.
    peer.write_all(&[b'x'; H2_PREFACE_LEN])
        .await
        .unwrap_or_else(|e| panic!("write: {e}"));
    peer.flush().await.unwrap_or_else(|e| panic!("flush: {e}"));

    let mut buf = [0_u8; H2_PREFACE_LEN];
    let again = bounded
        .read(&mut buf)
        .await
        .err()
        .unwrap_or_else(|| panic!("an expired decorator must not serve the bytes"));
    assert_eq!(again.kind(), io::ErrorKind::TimedOut);
}
