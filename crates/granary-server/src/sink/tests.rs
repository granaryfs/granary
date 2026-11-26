// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for `crate::sink` — the composition root's log sink —
//! lossy under backpressure.
//!
//! Out-of-line: `granary-server`'s non-test artifact has
//! its own `[[bin]]` (`granary-server`) and its own
//! `tests/` directory (`crates/granary-server/tests/`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use super::{QUEUE_LINES, lossy};
use std::io::Write;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter as _;

/// A queue held directly by the test, with no asynchronous drain to race assertions.
pub(crate) fn queue() -> (super::LossyStderr, mpsc::Receiver<Vec<u8>>) {
    let (sender, receiver) = mpsc::sync_channel(QUEUE_LINES);
    (
        super::LossyStderr {
            sender,
            dropped: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            debug_gate: None,
        },
        receiver,
    )
}

/// Pause a DEBUG enqueue while the capture guard is owned.
#[derive(Debug)]
pub(crate) struct DebugGate {
    pub(crate) entered: mpsc::SyncSender<()>,
    pub(crate) release: Mutex<mpsc::Receiver<()>>,
}

impl DebugGate {
    pub(crate) fn enter(&self) {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
    }
}

/// Block the real sink's destination, leaving its queue empty after the first dequeue.
pub(crate) fn blocked_destination() -> (super::LossyStderr, mpsc::Sender<()>) {
    let (release, gate) = mpsc::channel();
    let (entered, blocked) = mpsc::sync_channel(1);
    let writer = lossy(Gated {
        entered: Some(entered),
        release: gate,
        seen: Arc::new(Mutex::new(Vec::new())),
        first: true,
    });
    emit(&writer, "block\n");
    blocked.recv().unwrap();
    (writer, release)
}

#[test]
fn capture_debug_enqueue_is_bounded_and_loss_waits_for_a_baseline_line() {
    let (writer, queued) = queue();
    assert!(!writer.try_enqueue_debug(&vec![b'x'; super::DEBUG_LINE_BYTES + 1]));
    let exact = vec![b'x'; super::DEBUG_LINE_BYTES];
    for _ in 0..QUEUE_LINES {
        assert!(writer.try_enqueue_debug(&exact));
    }
    assert!(!writer.try_enqueue_debug(b"lost\n"));
    assert_eq!(queued.recv().unwrap(), exact);
    assert!(writer.try_enqueue_debug(b"debug\n"));
    for _ in 1..QUEUE_LINES {
        assert_eq!(queued.recv().unwrap().len(), super::DEBUG_LINE_BYTES);
    }
    assert_eq!(
        queued.recv().unwrap(),
        b"debug\n",
        "DEBUG must never carry a loss annotation"
    );
    emit(&writer, "baseline\n");
    assert_eq!(
        String::from_utf8(queued.recv().unwrap()).unwrap(),
        "baseline\n",
        "DEBUG loss must not annotate the next baseline line"
    );
    assert_eq!(writer.dropped.load(std::sync::atomic::Ordering::Relaxed), 0);
    // Baseline drops retain their own next-line reporting contract.
    for _ in 0..QUEUE_LINES {
        assert!(writer.try_enqueue_debug(b"filler\n"));
    }
    emit(&writer, "baseline lost\n");
    assert_eq!(writer.dropped.load(std::sync::atomic::Ordering::Relaxed), 1);
    for _ in 0..QUEUE_LINES {
        assert_eq!(queued.recv().unwrap(), b"filler\n");
    }
    emit(&writer, "after\n");
    assert_eq!(
        String::from_utf8(queued.recv().unwrap()).unwrap(),
        "[lossy log sink: 1 line(s) dropped under backpressure]\nafter\n"
    );
}

/// A destination that blocks until released, then records everything.
///
/// The gate is a channel handed to the destination: the writer thread
/// parks in `recv()` inside its first `write_all`, which is exactly
/// the backpressured-stderr shape, with no clock anywhere. On entering
/// that first write it signals `entered` — proof the writer has
/// DEQUEUED the first line and is now blocked, which is what a test
/// waits on before it can reason about how many queue slots are free.
struct Gated {
    entered: Option<mpsc::SyncSender<()>>,
    release: mpsc::Receiver<()>,
    seen: Arc<Mutex<Vec<u8>>>,
    first: bool,
}

impl Write for Gated {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.first {
            self.first = false;
            if let Some(entered) = self.entered.take() {
                let _announced = entered.send(());
            }
            let _released = self.release.recv();
        }
        match self.seen.lock() {
            Ok(mut seen) => seen.extend_from_slice(bytes),
            Err(poisoned) => poisoned.into_inner().extend_from_slice(bytes),
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn emit(writer: &super::LossyStderr, text: &str) {
    let mut line = writer.make_writer();
    let _accepted = line.write(text.as_bytes());
    let _flushed = line.flush();
}

#[test]
fn a_full_queue_drops_and_the_loss_is_reported_in_stream() {
    let (release, gate) = mpsc::channel();
    let (entered, blocked) = mpsc::sync_channel(1);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let writer = lossy(Gated {
        entered: Some(entered),
        release: gate,
        seen: Arc::clone(&seen),
        first: true,
    });

    // Emit "line 0" and WAIT until the writer thread has dequeued it
    // and is blocked in the gate. Without this wait the fillers race
    // that dequeue: if the producer fills all `QUEUE_LINES` slots
    // before "line 0" leaves the channel, the last filler is dropped
    // and the `wait_for` below never sees its marker — a
    // scheduler-dependent hang. After the
    // signal the channel is empty, so the next `QUEUE_LINES` fillers
    // fit exactly and the final five drop.
    emit(&writer, "line 0\n");
    blocked
        .recv()
        .unwrap_or_else(|error| panic!("writer never entered the gate: {error}"));
    for n in 0..QUEUE_LINES + 5 {
        emit(&writer, &format!("filler {n}\n"));
    }

    let _open = release.send(());
    // Wait for the writer to DRAIN THE WHOLE QUEUE before emitting
    // the reporter line: emitting while fillers still occupy the
    // queue races the drain, and the reporter line itself gets
    // dropped by the very lossiness under test — measured as a
    // suite-wedging hang before this wait existed. The last line
    // that fits is deterministic: with "line 0" already dequeued the
    // channel was empty, so fillers 0..QUEUE_LINES-1 fit and the last
    // five drop.
    let last_queued = format!("filler {}\n", QUEUE_LINES - 1);
    wait_for(&seen, &last_queued);

    // The queue is empty now, so this line cannot be dropped, and
    // it carries the report of the exactly-five that were.
    emit(&writer, "after\n");
    let rendered = wait_for(&seen, "after\n");
    assert!(
        rendered.contains("5 line(s) dropped under backpressure"),
        "the loss must be reported in the stream itself: {rendered}"
    );
    assert!(rendered.contains("line 0\n"), "the pre-block line arrived");
}

/// Spin (yielding) until the recorded bytes contain `marker`,
/// returning the rendering. Bounded by the harness's own test
/// timeout rather than a clock read.
fn wait_for(seen: &Arc<Mutex<Vec<u8>>>, marker: &str) -> String {
    loop {
        let rendered = match seen.lock() {
            Ok(seen) => String::from_utf8_lossy(&seen).into_owned(),
            Err(poisoned) => String::from_utf8_lossy(&poisoned.into_inner()).into_owned(),
        };
        if rendered.contains(marker) {
            return rendered;
        }
        std::thread::yield_now();
    }
}

#[test]
fn an_unblocked_sink_passes_lines_through_in_order() {
    let (_release, gate) = mpsc::channel();
    let seen = Arc::new(Mutex::new(Vec::new()));
    // `first: false` — this destination never blocks, so it needs no
    // gate release and no entered signal.
    let writer = lossy(Gated {
        entered: None,
        release: gate,
        seen: Arc::clone(&seen),
        first: false,
    });

    emit(&writer, "first\n");
    emit(&writer, "second\n");

    let rendered = wait_for(&seen, "second\n");
    assert_eq!(rendered, "first\nsecond\n", "in order, nothing invented");
}
