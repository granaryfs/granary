// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for [`super`], at the sibling-directory address a module's own
//! tests take in this crate.
//!
//! Every row here runs on the development host: none of them mounts, and the
//! destination is a fixture rather than the process's real stderr.

//! **No `std::thread::sleep` anywhere below, and no wholesale lint licence.**
//! Polling with a 1 ms sleep, or slowing a fixture with a
//! 200 us one, would need a licence for a disallowed method.
//! `std::thread::sleep` is on this crate's disallowed list — wall time in
//! disguise — and a wholesale suppression at file scope is what
//! `check-fsguard-sites.sh` refuses outright. Every wait here
//! is a `Condvar` instead, woken by the event rather than by a timer, so no
//! row races a clock.
#![cfg(test)]

use super::sink_to_writer as sink_to;
use super::*;
use std::sync::mpsc;
use std::time::Duration;

/// A destination a test controls.
///
/// `hold` makes `write_all` block exactly as a full pipe does, which is the
/// only way to build queue pressure without a real backpressured fd. It is a
/// `Condvar` rather than a sleep so a row never races a timer.
#[derive(Clone, Debug)]
struct Destination {
    state: Arc<(Mutex<DestinationState>, Condvar)>,
}

#[derive(Debug, Default)]
struct DestinationState {
    written: Vec<u8>,
    held: bool,
    /// Per-write delay. A starvation row needs the DESTINATION to be slower
    /// than the producer, or the queue empties between records and the worker
    /// reaches its accounting by luck rather than by priority.
    slow: bool,
    /// How many `write_all` calls have STARTED, including one currently held.
    entered: usize,
}

impl Destination {
    fn new() -> Self {
        Self {
            state: Arc::new((Mutex::new(DestinationState::default()), Condvar::new())),
        }
    }

    fn hold(&self) {
        let (lock, _cv) = &*self.state;
        lock.lock().expect("destination lock").held = true;
    }

    fn slow(&self) {
        let (lock, _cv) = &*self.state;
        lock.lock().expect("destination lock").slow = true;
    }

    fn release(&self) {
        let (lock, cv) = &*self.state;
        lock.lock().expect("destination lock").held = false;
        cv.notify_all();
    }

    fn written(&self) -> String {
        let (lock, _cv) = &*self.state;
        String::from_utf8_lossy(&lock.lock().expect("destination lock").written).into_owned()
    }

    fn entered(&self) -> usize {
        let (lock, _cv) = &*self.state;
        lock.lock().expect("destination lock").entered
    }

    /// Spin until `predicate` holds, or fail the row. Bounded so a regression
    /// is a red rather than a hung suite — the shape this repository already
    /// records for an end-to-end hang test.
    fn wait_until(&self, what: &str, predicate: impl Fn(&DestinationState) -> bool) {
        let (lock, cv) = &*self.state;
        let mut guard = lock.lock().expect("destination lock");
        // The predicate is evaluated UNDER the lock, and re-evaluated after
        // every wake. Checking it outside first is a lost wakeup: the write
        // this row is waiting for can land between the check and the wait,
        // and the notification is then already spent — which is how a first
        // version turned three rows into 120-second timeouts.
        while !predicate(&guard) {
            let (next, timeout) = cv
                .wait_timeout(guard, Duration::from_secs(20))
                .expect("destination lock");
            guard = next;
            assert!(
                !timeout.timed_out() || predicate(&guard),
                "timed out waiting for {what}; destination holds {:?}",
                String::from_utf8_lossy(&guard.written)
            );
        }
    }
}

impl Write for Destination {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.write_all(bytes)?;
        Ok(bytes.len())
    }

    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let (lock, cv) = &*self.state;
        let mut state = lock.lock().expect("destination lock");
        state.entered += 1;
        // Notified BEFORE the hold, so a row waiting for "the worker has
        // entered write_all" is woken by that fact rather than by the write
        // that the hold is preventing.
        cv.notify_all();
        while state.held {
            state = cv.wait(state).expect("destination lock");
        }
        let slow = state.slow;
        state.written.extend_from_slice(bytes);
        cv.notify_all();
        if slow {
            // A DELAY without `std::thread::sleep`: wait on the condvar for a
            // notification that will not come, and let the timeout end it.
            // What the starvation row needs is a destination SLOWER than its
            // producer, not a precise duration.
            let (next, _timeout) = cv
                .wait_timeout(state, Duration::from_micros(200))
                .expect("destination lock");
            state = next;
        }
        drop(state);
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A writer with the SERVER's shape: accumulate, and submit on flush or drop.
///
/// `granary-server`'s own sink cannot be used here — it is AGPL and this
/// crate is Apache, so the licence boundary forbids the dependency — so the
/// contrast is drawn against a local writer built to that shape. It exists
/// for exactly one row, which asserts that it FAILS the per-record test. A
/// row the contrast passes is not testing the property.
struct FlushSubmits {
    line: Vec<u8>,
    out: mpsc::Sender<Vec<u8>>,
}

impl Write for FlushSubmits {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.line.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.line.is_empty() {
            let _sent = self.out.send(std::mem::take(&mut self.line));
        }
        Ok(())
    }
}

impl Drop for FlushSubmits {
    fn drop(&mut self) {
        let _best_effort = self.flush();
    }
}

// ------------------------------------------------------- submission per record

/// A record reaches the destination WITHOUT a flush and WITHOUT the writer
/// being dropped.
///
/// SUBMISSION PER RECORD is the whole of what distinguishes this sink
/// from the server's. The CLI's sink local spans the daemon: a writer that
/// submitted on flush or drop would hold a startup notice in a buffer for the
/// life of the mount. Non-blocking and DELIVERED are different properties.
#[test]
fn a_record_reaches_the_destination_without_a_flush_and_without_a_drop() {
    let destination = Destination::new();
    let (sink, mut worker) = sink_to(destination.clone());
    let mut writer = sink.writer(Stream::Protected);

    writeln!(writer, "pinned root: abc123").expect("a sink write never fails");
    // No flush. No drop. The writer is still alive below this line.
    destination.wait_until("the record to arrive", |st| {
        String::from_utf8_lossy(&st.written).contains("abc123")
    });

    assert!(
        destination.written().contains("pinned root: abc123"),
        "got {:?}",
        destination.written()
    );
    drop(writer);
    worker.close();
}

/// The contrast: a writer with the server's shape FAILS the row above.
///
/// Without this, that row proves only that SOMETHING eventually arrived, and
/// would pass against the very shape this sink was built to replace.
#[test]
fn a_flush_submitting_writer_fails_the_per_record_row() {
    let (out, received) = mpsc::channel();
    let mut writer = FlushSubmits {
        line: Vec::new(),
        out,
    };

    writeln!(writer, "pinned root: abc123").expect("write");
    assert!(
        received.try_recv().is_err(),
        "the server's shape must NOT have submitted yet — if it has, the \
         per-record row above is not testing submission per record"
    );

    drop(writer);
    let submitted = received.try_recv().expect("submitted on drop");
    assert!(String::from_utf8_lossy(&submitted).contains("abc123"));
}

/// A MULTI-LINE message is admitted whole or not at all.
///
/// One `writeln!` can carry two physical lines. An implementation that queued
/// each `write` call would satisfy the single-line row above and, under queue
/// pressure, admit a PREFIX and drop the remainder while returning `Ok` —
/// truncating operator text. The fixture is multi-line for that reason.
#[test]
fn a_multi_line_message_is_one_record() {
    let destination = Destination::new();
    let (sink, mut worker) = sink_to(destination.clone());
    let mut writer = sink.writer(Stream::Protected);

    writeln!(writer, "first half\nsecond half").expect("a sink write never fails");
    destination.wait_until("the whole message", |st| {
        String::from_utf8_lossy(&st.written).contains("second half")
    });

    let written = destination.written();
    assert!(
        written.contains("first half\nsecond half"),
        "the two halves must arrive as one record, got {written:?}"
    );
    assert_eq!(
        destination.entered(),
        1,
        "one message must reach the destination in ONE write_all, got {} — a \
         per-`write` implementation would show more",
        destination.entered()
    );
    drop(writer);
    worker.close();
}

// ------------------------------------------------------------ the accounting

/// An outstanding count appears when NOTHING is submitted after the drop.
///
/// A counter that only prefixes the NEXT admitted record strands itself: fill
/// the queue, drop a record, stop producing, then drain — the count is never
/// reported and every per-record row still passes. The worker rechecks its
/// accounting when both queues are empty, ABOVE its closed check, which is
/// what makes this row possible at all. (These two sentences described an
/// idle TIMEOUT until they were read against the implementation
/// that had removed it — the claim outliving the diff that falsified it.)
#[test]
fn an_outstanding_count_appears_with_nothing_submitted_afterwards() {
    let destination = Destination::new();
    destination.hold();
    let (sink, mut worker) = sink_to(destination.clone());
    let mut writer = sink.writer(Stream::Telemetry);

    // Fill past the telemetry ceiling so at least one is refused. The first
    // message is taken by the worker and held inside `write_all`.
    for n in 0..(CAPACITY + 8) {
        writeln!(writer, "telemetry {n}").expect("a sink write never fails");
    }
    // Nothing more is ever submitted. Not one further record.
    drop(writer);
    destination.release();

    destination.wait_until("the accounting line", |st| {
        String::from_utf8_lossy(&st.written).contains("dropped under backpressure")
    });
    assert!(
        destination.written().contains("telemetry line(s) dropped"),
        "got {:?}",
        destination.written()
    );
    worker.close();
}

/// The SHUTDOWN surfaces an outstanding count too, not only the drain.
///
/// The drain reports when it finds both queues empty; a process that closes
/// before the worker gets there would never see one. Both paths must surface
/// it.
#[test]
fn the_shutdown_surfaces_an_outstanding_count() {
    let destination = Destination::new();
    destination.hold();
    let (sink, mut worker) = sink_to(destination.clone());
    let mut writer = sink.writer(Stream::Telemetry);
    for n in 0..(CAPACITY + 8) {
        writeln!(writer, "telemetry {n}").expect("a sink write never fails");
    }
    drop(writer);
    destination.release();
    worker.close();

    assert!(
        destination.written().contains("dropped under backpressure"),
        "close() must not return before the accounting is written, got {:?}",
        destination.written()
    );
}

// --------------------------------------------- reserved admission and service

/// A protected record is admitted while telemetry has filled its share.
///
/// This is the volume premise made concrete: an ordinary successful startup
/// emits far more telemetry than the queue holds, and without a reserve the
/// operator-facing record arrives to find no room.
#[test]
fn a_protected_record_is_admitted_after_telemetry_fills_its_share() {
    let destination = Destination::new();
    destination.hold();
    let (sink, mut worker) = sink_to(destination.clone());
    let mut telemetry = sink.writer(Stream::Telemetry);
    for n in 0..(CAPACITY * 2) {
        writeln!(telemetry, "telemetry {n}").expect("a sink write never fails");
    }

    let mut protected = sink.writer(Stream::Protected);
    writeln!(protected, "THE REFUSAL REASON").expect("a sink write never fails");
    destination.release();
    destination.wait_until("the protected record", |st| {
        String::from_utf8_lossy(&st.written).contains("THE REFUSAL REASON")
    });

    drop(telemetry);
    drop(protected);
    worker.close();
}

/// Protected records are SERVED before telemetry, and in their own order.
///
/// Reserved admission alone is not sufficient: a drain loop that takes
/// whatever is available lets replenished telemetry overtake an
/// already-admitted protected record and defer it without bound while the
/// destination is draining normally. That is the mechanism's loss, and it is
/// what this row forbids.
#[test]
fn protected_records_are_served_first_and_in_order() {
    let destination = Destination::new();
    destination.hold();
    let (sink, mut worker) = sink_to(destination.clone());
    let mut telemetry = sink.writer(Stream::Telemetry);
    let mut protected = sink.writer(Stream::Protected);

    // One telemetry record is taken by the worker immediately and held inside
    // `write_all`; everything below queues behind it.
    writeln!(telemetry, "T0").expect("write");
    destination.wait_until("the worker to take the first record", |st| st.entered >= 1);
    for n in 1..32 {
        writeln!(telemetry, "T{n}").expect("write");
    }
    writeln!(protected, "protected-first").expect("write");
    writeln!(protected, "protected-second").expect("write");

    destination.release();
    // Wait for the LAST record of the whole batch, not for the protected
    // pair: the telemetry is written AFTER them, so a row that waits for `protected-second`
    // and then asserts about `T31` is racing its own subject. That made this
    // row FLAKY — three of five runs red — which is worse than no row,
    // because a flake teaches a reader to re-run rather than to look.
    destination.wait_until("every record of the batch", |st| {
        String::from_utf8_lossy(&st.written).contains("T31")
    });

    let written = destination.written();
    let first = written
        .find("protected-first")
        .expect("the first protected record");
    let second = written
        .find("protected-second")
        .expect("the second protected record");
    assert!(
        first < second,
        "FIFO within the protected stream, got {written:?}"
    );
    let t31 = written.find("T31").expect("T31 written");
    assert!(
        second < t31,
        "every protected record must precede the telemetry queued before it, got {written:?}"
    );

    drop(telemetry);
    drop(protected);
    worker.close();
}

/// A protected record that cannot be admitted has its loss REPORTED.
///
/// Never dropped silently: that is the one outcome this design exists to
/// forbid. The report is written once the destination drains, which is the
/// module doc's delivery test — if the destination drains freely from now on, is the
/// record delivered or its loss reported?
#[test]
fn a_protected_record_refused_admission_has_its_loss_reported() {
    let destination = Destination::new();
    destination.hold();
    let (sink, mut worker) = sink_to(destination.clone());
    let mut protected = sink.writer(Stream::Protected);

    for n in 0..(CAPACITY * 2) {
        writeln!(protected, "protected {n}").expect("a sink write never fails");
    }
    drop(protected);
    destination.release();

    destination.wait_until("the protected loss report", |st| {
        String::from_utf8_lossy(&st.written).contains("PROTECTED message(s) LOST")
    });
    worker.close();
}

/// `close` returns WITHIN ITS BOUND against a destination that never drains.
///
/// An outright join of the worker thread would make a process
/// closing the sink at exit hang on exactly the wedged stderr this
/// module exists to survive — and a row whose assertion fired would
/// time out instead of failing, which is a red that tells you
/// nothing.
///
/// **The bound is ASSERTED, not observed.** A row that merely waits for
/// `close` to return cannot tell a bounded path from an unbounded one that
/// happened to come back.
#[test]
fn close_returns_within_its_bound_against_a_destination_that_never_drains() {
    let destination = Destination::new();
    destination.hold();
    let (sink, mut worker) = sink_to(destination.clone());
    let mut writer = sink.writer(Stream::Protected);
    writeln!(writer, "a record nobody will ever read").expect("a sink write never fails");
    destination.wait_until("the worker to block inside write_all", |st| st.entered >= 1);
    drop(writer);

    // `close` runs on its OWN thread and this row waits for THAT with a
    // deadline. Calling it here and timing it cannot distinguish a bounded
    // path from an unbounded one: an unbounded `close` never returns, so the
    // row would hang for the whole harness timeout instead of failing — a red
    // that names nothing. A mutant that joins unconditionally reddens this row
    // in under a second.
    let (returned, waiter) = mpsc::channel();
    let on_its_own_thread = std::thread::spawn(move || {
        worker.close();
        let _reported = returned.send(());
    });
    let outcome = waiter.recv_timeout(CLOSE_BOUND * 4);
    assert!(
        outcome.is_ok(),
        "close did not return within {:?} — the EXIT is what this guarantees, \
         never the delivery, and a join on a worker blocked inside write(2) \
         never returns",
        CLOSE_BOUND * 4
    );
    // The destination is released only now, so nothing above raced a drain.
    destination.release();
    let _joined = on_its_own_thread.join();
}

/// A protected LOSS REPORT is not starved by replenished telemetry.
///
/// The report IS the protected guarantee, so it is served at protected
/// priority — not below the telemetry queue. Serving telemetry first
/// can starve the report: fill the queue, refuse a protected
/// record, then keep telemetry non-empty while the destination drains, and
/// the worker never reaches the accounting at all. That is a loss caused by
/// the MECHANISM while the destination is draining normally, which is the one
/// outcome this design forbids — and the module doc's delivery test names it: if the
/// destination drains freely from now on, is the loss reported?
#[test]
fn a_protected_loss_report_is_not_starved_by_replenished_telemetry() {
    let destination = Destination::new();
    destination.hold();
    destination.slow();
    let (sink, mut worker) = sink_to(destination.clone());
    let mut protected = sink.writer(Stream::Protected);
    // Fill the whole queue with protected records so the next one is refused.
    for n in 0..(CAPACITY + 4) {
        writeln!(protected, "protected {n}").expect("a sink write never fails");
    }
    drop(protected);

    // A producer that keeps telemetry available for the whole drain. Without
    // protected-priority accounting the worker prefers it forever.
    let keep_going = Arc::new(Mutex::new(true));
    let feeding = {
        let sink = sink.clone();
        let keep_going = Arc::clone(&keep_going);
        std::thread::spawn(move || {
            let mut telemetry = sink.writer(Stream::Telemetry);
            while *keep_going.lock().expect("flag") {
                let _submitted = writeln!(telemetry, "telemetry");
                std::thread::yield_now();
            }
        })
    };

    destination.release();
    destination.wait_until("the protected loss report", |st| {
        String::from_utf8_lossy(&st.written).contains("PROTECTED message(s) LOST")
    });
    *keep_going.lock().expect("flag") = false;
    let _joined = feeding.join();
    worker.close();
}

// ------------------------------------------------------- the writer's contract

/// The writer reports `Ok` even when the queue refused the message.
///
/// `tracing-subscriber` prints to stderr ITSELF when the
/// configured writer returns an error, which would reintroduce the
/// synchronous write on the very path this sink removes it from. Honesty
/// here is the defect.
#[test]
fn the_writer_reports_ok_when_the_queue_refused() {
    let destination = Destination::new();
    destination.hold();
    let (sink, mut worker) = sink_to(destination.clone());
    let mut writer = sink.writer(Stream::Telemetry);

    for n in 0..(CAPACITY * 2) {
        let outcome = writeln!(writer, "telemetry {n}");
        assert!(
            outcome.is_ok(),
            "record {n} returned an error; a writer that reports backpressure \
             honestly re-creates the synchronous stderr write"
        );
    }
    assert!(writer.flush().is_ok(), "flush never fails either");

    destination.release();
    drop(writer);
    worker.close();
}

/// A destination that is gone for good does not leave a producer waiting.
#[test]
fn a_failing_destination_stops_the_worker_without_blocking_a_producer() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let (sink, mut worker) = sink_to(Broken);
    let mut writer = sink.writer(Stream::Protected);
    for n in 0..(CAPACITY * 2) {
        writeln!(writer, "record {n}").expect("a sink write never fails");
    }
    drop(writer);
    worker.close();
}

/// A bare `write_all` accumulates and submits as ONE record at flush.
///
/// It cannot be per-record — nothing tells this type where such a message
/// ends — but it must never be per-`write`, which would be the truncation
/// the multi-line row forbids.
#[test]
fn bare_writes_submit_as_one_record_at_flush() {
    let destination = Destination::new();
    let (sink, mut worker) = sink_to(destination.clone());
    let mut writer = sink.writer(Stream::Protected);

    writer.write_all(b"one ").expect("write");
    writer.write_all(b"two ").expect("write");
    writer.write_all(b"three\n").expect("write");
    writer.flush().expect("flush");

    destination.wait_until("the assembled record", |st| {
        String::from_utf8_lossy(&st.written).contains("three")
    });
    assert_eq!(
        destination.entered(),
        1,
        "three bare writes must reach the destination as ONE record"
    );
    assert_eq!(destination.written(), "one two three\n");
    drop(writer);
    worker.close();
}

// -------------------------------------------- the subscriber's installation

/// A tracing record emitted with the destination BLOCKED does not block the
/// emitting thread.
///
/// This is the whole point of installing the sink for the subscriber: one
/// line covers the library's entire tracing inventory — the cache modules,
/// the HTTP store, and the structure resolver that emits repeatedly during an
/// ordinary successful startup — without editing a single call site.
///
/// **NOT A MOUNT.** At this point the caller-supplied sink is still real
/// stderr and a mount would still wedge, correctly; that is the next task.
///
/// The bound is ASSERTED on another thread, not observed: a row that emits
/// and then measures cannot tell a non-blocking path from a blocking one that
/// happened to return — it would simply hang.
#[test]
fn a_tracing_record_does_not_block_its_thread_when_the_destination_is_blocked() {
    let destination = Destination::new();
    destination.hold();
    let (sink, mut worker) = sink_to(destination.clone());

    // >>> THE QUEUE IS FILLED THROUGH ITS OWN STATE, NOT THROUGH THE CODE
    // UNDER TEST. <<< Filling it with `writeln!` on another
    // writer — the IDENTICAL call the emitting thread makes
    // below — would, under the defect this row names, block
    // the SETUP first, and the row would hang before reaching
    // its assertion. A hang is not a discriminator: it proves
    // something is wrong without saying what. Pushing straight
    // into the queue leaves the emitting thread as the only
    // caller of the path being tested.
    {
        let mut q = sink.shared.queues.lock().expect("queue lock");
        for n in 0..CAPACITY {
            q.telemetry.push_back(format!("filler {n}\n").into_bytes());
        }
    }

    let (emitted, waiter) = mpsc::channel();
    let emitting = {
        let sink = sink.clone();
        std::thread::spawn(move || {
            // The exact call the fmt layer makes for every tracing event.
            let mut writer = sink.writer(Stream::Telemetry);
            let _written = writeln!(writer, "a record nobody can take right now");
            let _reported = emitted.send(());
        })
    };
    assert!(
        waiter.recv_timeout(Duration::from_secs(10)).is_ok(),
        "the emitting thread blocked on a destination that is not draining — \
         which is the wedge this sink exists to remove"
    );

    destination.release();
    let _joined = emitting.join();
    worker.close();
}

// ------------------------------------------ the caller-supplied mount sink

/// The destination `gran mount` gives `MountSession::open` does not block its
/// caller, proved by handing it one that never drains.
///
/// The library takes `sink` as a PARAMETER precisely so the caller decides.
/// Before this, the call site decided on `std::io::stderr()` — seven
/// `writeln!`s into a blocking handle, on the startup path, before the kernel
/// filesystem exists. This row drives the same shape the call site now does:
/// a PROTECTED writer over a destination that is held for the whole call.
///
/// **The library's own rows that assert what was written into a supplied sink
/// still pass unchanged** — that parameter's testability is why it exists, and
/// nothing about its type changed.
///
/// Asserted on another thread with a deadline, for the reason every bound in
/// this file is: a row that writes and then measures cannot tell a
/// non-blocking path from a blocking one that happened to return.
#[test]
fn the_mount_destination_does_not_block_its_caller() {
    let destination = Destination::new();
    destination.hold();
    let (sink, mut worker) = sink_to(destination.clone());
    // UNDER PRESSURE, or this row proves nothing: seven records fit an empty
    // queue trivially, so a submission that BLOCKS when it must refuse is
    // never reached and the mutant for it survives. The queue is filled
    // through its own state so the setup cannot block on the path under test.
    {
        let mut q = sink.shared.queues.lock().expect("queue lock");
        for n in 0..CAPACITY {
            q.protected
                .push_back((Stream::Protected, format!("filler {n}\n").into_bytes()));
        }
    }

    let (finished, waiter) = mpsc::channel();
    let writing = {
        let sink = sink.clone();
        std::thread::spawn(move || {
            let mut mount_log = sink.writer(Stream::Protected);
            // The seven shapes `MountSession::open` writes, in one go: a
            // multi-line warning and the pinned-root announcement among them.
            for n in 0..7 {
                let _written = writeln!(
                    mount_log,
                    "gran mount: warning {n}: a message that wraps \\\n  onto a second physical line"
                );
            }
            let _reported = finished.send(());
        })
    };
    assert!(
        waiter.recv_timeout(Duration::from_secs(10)).is_ok(),
        "the mount call site blocked on a destination that is not draining — \
         which is the wedge before the kernel filesystem exists"
    );

    destination.release();
    let _joined = writing.join();
    worker.close();
    assert!(
        destination.written().contains("filler 0"),
        "what the queue held must arrive once the destination drains, got {:?}",
        destination.written()
    );
}

#[test]
fn local_and_protected_share_reserved_admission_fifo_and_one_worker() {
    type DrainRecord = (Stream, Vec<u8>, std::thread::ThreadId);
    #[derive(Clone)]
    struct Routed {
        barrier: Destination,
        records: Arc<Mutex<Vec<DrainRecord>>>,
    }
    impl Write for Routed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            unreachable!("per-record route required")
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let barrier = Destination::new();
    barrier.hold();
    let records = Arc::new(Mutex::new(Vec::new()));
    let (sink, mut worker) = start(
        Routed {
            barrier: barrier.clone(),
            records: records.clone(),
        },
        granary_client::LogFormat::Json,
        |route, stream, bytes| {
            route.barrier.write_all(bytes)?;
            route.records.lock().unwrap().push((
                stream,
                bytes.to_vec(),
                std::thread::current().id(),
            ));
            Ok(())
        },
    );
    assert!(sink.submit(Stream::Telemetry, b"blocker\n".to_vec()));
    barrier.wait_until("held worker", |state| state.entered == 1);
    for _ in 0..CAPACITY - PROTECTED_RESERVE {
        assert!(sink.submit(Stream::Telemetry, b"telemetry\n".to_vec()));
    }
    assert!(!sink.submit(Stream::Telemetry, b"refused\n".to_vec()));
    let producer = std::thread::current().id();
    for n in 0..PROTECTED_RESERVE {
        let stream = if n % 2 == 0 {
            Stream::Local
        } else {
            Stream::Protected
        };
        assert!(
            sink.submit(stream, format!("reserved {n}\n").into_bytes()),
            "local/protected reserved admission failed"
        );
    }
    {
        let q = sink.shared.queues.lock().unwrap();
        assert_eq!(q.queued(), CAPACITY);
        assert_eq!(q.protected.len(), PROTECTED_RESERVE);
        assert_eq!(q.dropped_telemetry, 1);
    }
    barrier.release();
    worker.close();
    let records = records.lock().unwrap();
    let worker_id = records[0].2;
    assert_ne!(worker_id, producer);
    assert!(
        records.iter().all(|row| row.2 == worker_id),
        "more than one worker drained"
    );
    for n in 0..PROTECTED_RESERVE {
        let row = &records[n + 1];
        assert_eq!(
            row.0,
            if n % 2 == 0 {
                Stream::Local
            } else {
                Stream::Protected
            },
            "Local/Protected FIFO or priority changed"
        );
        assert_eq!(
            row.1,
            format!("reserved {n}\n").as_bytes(),
            "Local/Protected FIFO or priority changed"
        );
    }
}

#[test]
fn local_overflow_keeps_whole_records_and_reports_local_loss_to_telemetry_file() {
    use granary_client::LocalReporter as _;
    for format in [
        granary_client::LogFormat::Text,
        granary_client::LogFormat::Json,
    ] {
        let original = Destination::new();
        original.hold();
        let dir = crate::tests::ScratchDir::new();
        let file_path = dir.0.join("telemetry.log");
        let file = crate::logging::RotatingFile::open_with(
            &file_path,
            crate::admission::process_credentials().euid,
            u64::MAX,
            0,
        )
        .unwrap();
        let (sink, mut worker) = super::sink_to(crate::logging::Destination::new(
            original.clone(),
            Some(file),
            format,
        ));
        let mut reports = sink.protected_writer();
        reports.report(&granary_client::LocalReport::history());
        original.wait_until("local write entered", |state| state.entered == 1);
        for _ in 0..CAPACITY {
            reports.report(&granary_client::LocalReport::history());
        }
        reports.report(&granary_client::LocalReport::history());
        writeln!(reports, "protected overflow").unwrap();
        {
            let q = sink.shared.queues.lock().unwrap();
            assert_eq!(q.queued(), CAPACITY);
            assert_eq!(q.lost_local, 1);
            assert_eq!(q.lost_protected, 1);
            assert!(
                q.protected
                    .iter()
                    .all(|(stream, bytes)| *stream == Stream::Local
                        && bytes == b"gran mount: history: not checked\n")
            );
            assert!(
                !format!("{q:?}").contains("history"),
                "queue Debug exposed local bytes"
            );
        }
        assert_eq!(format!("{reports:?}"), "<sink-writer>");
        original.release();
        worker.close();
        let local = original.written();
        assert_eq!(local.lines().count(), CAPACITY + 1);
        assert!(
            local
                .lines()
                .all(|line| line == "gran mount: history: not checked")
        );
        let mut file = granary_client::open_regular_read(&file_path).unwrap();
        let mut telemetry = String::new();
        std::io::Read::read_to_string(&mut file, &mut telemetry).unwrap();
        assert!(
            !telemetry.contains("history"),
            "local record reached telemetry file"
        );
        match format {
            granary_client::LogFormat::Json => assert_eq!(
                telemetry,
                "{\"event\":\"log.sink_loss\",\"telemetry_dropped\":0,\"protected_lost\":1,\"local_lost\":1}\n"
            ),
            granary_client::LogFormat::Text => {
                assert!(telemetry.contains("local_lost=1") && telemetry.contains("1 PROTECTED"));
            }
        }
    }
}

#[test]
fn a_failing_original_stderr_is_counted_without_closing_the_telemetry_file() {
    use granary_client::LocalReporter as _;
    struct ClosedPipe;
    impl Write for ClosedPipe {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let dir = crate::tests::ScratchDir::new();
    let file_path = dir.0.join("telemetry.log");
    let file = crate::logging::RotatingFile::open_with(
        &file_path,
        crate::admission::process_credentials().euid,
        u64::MAX,
        0,
    )
    .unwrap();
    let (sink, mut worker) = super::sink_to(crate::logging::Destination::new(
        ClosedPipe,
        Some(file),
        granary_client::LogFormat::Json,
    ));
    let mut reports = sink.protected_writer();
    reports.report(&granary_client::LocalReport::history());
    writeln!(reports, "protected line").unwrap();
    let mut telemetry = sink.writer(Stream::Telemetry);
    writeln!(telemetry, "telemetry after the failed stderr").unwrap();
    drop(telemetry);
    worker.close();
    assert!(worker.drained(), "the worker must finish");
    let mut file = granary_client::open_regular_read(&file_path).unwrap();
    let mut text = String::new();
    std::io::Read::read_to_string(&mut file, &mut text).unwrap();
    assert!(
        text.contains("telemetry after the failed stderr"),
        "later telemetry was lost with the original stderr: {text}"
    );
    // The worker may report the two refusals in one loss record or, if it
    // drains between them, in two; the totals are what must hold.
    let total = |field: &str| -> u64 {
        text.lines()
            .filter(|line| line.contains("\"event\":\"log.sink_loss\""))
            .filter_map(|line| {
                let key = format!("\"{field}\":");
                let rest = &line[line.find(&key)? + key.len()..];
                rest.split(|c: char| !c.is_ascii_digit())
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
            .sum()
    };
    assert_eq!(
        (total("protected_lost"), total("local_lost")),
        (1, 1),
        "the refused local and protected records must be accounted: {text}"
    );
    assert!(
        !text.contains("history"),
        "local bytes reached telemetry: {text}"
    );
}

#[test]
fn local_and_telemetry_destinations_share_one_close_allowance() {
    #[derive(Clone)]
    struct Pair {
        local: Destination,
        telemetry: Destination,
    }
    impl Write for Pair {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            unreachable!("route required")
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for first in [Stream::Local, Stream::Telemetry] {
        let pair = Pair {
            local: Destination::new(),
            telemetry: Destination::new(),
        };
        pair.local.hold();
        pair.telemetry.hold();
        let (sink, mut worker) = start(
            pair.clone(),
            granary_client::LogFormat::Text,
            |dest, stream, bytes| match stream {
                Stream::Local | Stream::Protected => dest.local.write_all(bytes),
                Stream::Telemetry => dest.telemetry.write_all(bytes),
            },
        );
        assert!(sink.submit(first, b"held\n".to_vec()));
        let held = if first == Stream::Local {
            &pair.local
        } else {
            &pair.telemetry
        };
        held.wait_until("first destination entered", |state| state.entered == 1);
        assert!(sink.submit(Stream::Local, b"local\n".to_vec()));
        assert!(sink.submit(Stream::Protected, b"protected\n".to_vec()));
        assert!(sink.submit(Stream::Telemetry, b"telemetry\n".to_vec()));
        let (done, finished) = mpsc::channel();
        let closer = std::thread::spawn(move || {
            worker.close();
            worker.close();
            done.send(()).unwrap();
        });
        finished
            .recv_timeout(Duration::from_millis(800))
            .expect("one joint close bound exceeded");
        assert_eq!(
            pair.local.entered() + pair.telemetry.entered(),
            1,
            "second worker entered another destination"
        );
        pair.local.release();
        pair.telemetry.release();
        closer.join().unwrap();
    }
}

#[test]
fn local_loss_notice_has_reserved_priority_above_queued_telemetry() {
    let destination = Destination::new();
    destination.hold();
    let (sink, mut worker) = sink_to(destination.clone());
    assert!(sink.submit(Stream::Telemetry, b"blocker\n".to_vec()));
    destination.wait_until("worker entered", |state| state.entered == 1);
    for _ in 0..CAPACITY - PROTECTED_RESERVE {
        assert!(sink.submit(Stream::Telemetry, b"telemetry padding\n".to_vec()));
    }
    for _ in 0..PROTECTED_RESERVE {
        assert!(sink.submit(Stream::Local, b"local\n".to_vec()));
    }
    assert!(!sink.submit(Stream::Local, b"lost local\n".to_vec()));
    destination.release();
    worker.close();
    let output = destination.written();
    let notice = output
        .find("local_lost=1")
        .expect("local loss was never reported");
    let telemetry = output
        .find("telemetry padding")
        .expect("queued telemetry premise");
    assert!(
        notice < telemetry,
        "local loss notice lost reserved priority"
    );
    assert_eq!(
        output.lines().filter(|line| *line == "local").count(),
        PROTECTED_RESERVE
    );
}

#[cfg(feature = "overlay-fault-tests")]
use granary_client::{FaultPhase, OverlayFaultPoint};

mod fixtures;
use crate::tests::observability_scan as scan;
use granary_client::{
    Age, CacheAction, ClientEvent, FailureClass, FilterDetail, FilterRejection, FilterSource,
    HttpSeam, IndexFileKind, LogDestination, LogFormat, LogPaths, OperationKind,
    OperatorDiagnostic, Outcome, ProxyVariableName, PublishOperationId, RecoveryClass, RetryReason,
    SignalKind, TeardownCause, WalkOutcome, WireRetryClass,
};

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "all event identities through the real subscriber/queue/destination with predrain and independent bundle assertions"
)]
fn every_event_seeded_sweep_inspects_held_queue_and_each_output_destination() {
    use granary_client::{BundleHistory, LocalConflictStatus, LocalReporter as _};
    use tracing_subscriber::EnvFilter;
    for format in [LogFormat::Text, LogFormat::Json] {
        for policy in [LogPaths::Redacted, LogPaths::Full] {
            for to_file in [false, true] {
                let original = Destination::new();
                original.hold();
                let dir = crate::tests::ScratchDir::new();
                let file_path = dir.0.join("seed-ordinary-log-file");
                let file = to_file.then(|| {
                    crate::logging::RotatingFile::open_with(
                        &file_path,
                        crate::admission::process_credentials().euid,
                        6000,
                        8,
                    )
                    .unwrap()
                });
                let history = BundleHistory::default();
                let (sink, mut worker) = super::sink_to(crate::logging::Destination::with_policy(
                    original.clone(),
                    file,
                    format,
                    policy,
                    history.clone(),
                ));
                // This actual Local write holds the sole worker before telemetry.
                let mut reports = sink.protected_writer();
                reports.report(&granary_client::LocalReport::history());
                original.wait_until("held original-stderr worker", |state| state.entered == 1);
                let dispatch = granary_client::closed_subscriber_with_paths(
                    format,
                    EnvFilter::new("trace"),
                    sink.clone(),
                    policy,
                    history.clone(),
                );
                let mut random = fixtures::SeedRandom;
                let id = granary_client::CorrelationId::draw(&mut random).unwrap();
                tracing::subscriber::with_default(dispatch, || {
                    let span = granary_client::operation_span(OperationKind::Commit, &id);
                    let _entered = span.enter();
                    span.record("kind", "rebase");
                    for event in fixtures::diagnostics() {
                        event.emit();
                    }
                    for event in fixtures::events() {
                        event.emit();
                    }
                    LocalConflictStatus::new(std::path::Path::new(scan::ORDINARY[0]), id)
                        .unwrap()
                        .emit_telemetry();
                    for secret in scan::SECRETS {
                        tracing::warn!(target: "dependency", token = *secret, error = *secret);
                    }
                });
                let inventory: Vec<_> = fixtures::INVENTORY
                    .iter()
                    .chain(fixtures::EVENT_INVENTORY)
                    .map(|(name, _)| *name)
                    .collect();
                // The bundle keeps the INFO-and-above part of what telemetry queued.
                let queued_bundled;
                {
                    let queues = sink.shared.queues.lock().unwrap();
                    let records: Vec<_> = queues
                        .telemetry
                        .iter()
                        .map(|bytes| String::from_utf8(bytes.clone()).unwrap())
                        .collect();
                    assert_eq!(
                        records.len(),
                        // Two typed conflict records, and the dependency callsite inside
                        // the loop, which is one callsite refused once.
                        inventory.len() + 3,
                        "every constructor and refusal must enter queue"
                    );
                    queued_bundled = records.iter().filter(|r| !r.contains("DEBUG")).count();
                    assert!(
                        queued_bundled > 0 && queued_bundled < records.len(),
                        "the bundle level policy must admit some records and not all"
                    );
                    assert_eq!(
                        scan::scan(&records, scan::SECRETS),
                        Ok(()),
                        "queued secret absence before drain"
                    );
                    if policy == LogPaths::Redacted {
                        assert_eq!(
                            scan::scan(&records, scan::ORDINARY),
                            Ok(()),
                            "queued path absence before drain"
                        );
                    }
                    for (record, name) in records.iter().zip(&inventory) {
                        assert!(
                            fixtures::has_identity(record, name),
                            "every independent event identity must reach queue"
                        );
                        assert!(
                            !record.contains("log.record_refused"),
                            "legitimate queued event refused"
                        );
                    }
                }
                original.release();
                worker.close();
                assert!(worker.drained(), "sweep must drain the actual destination");
                let local = original.written();
                let outputs = if to_file {
                    assert!(
                        local == "gran mount: history: not checked\n",
                        "Local tee reached telemetry destination"
                    );
                    let paths = std::iter::once(file_path.clone()).chain((1..=8).map(|index| {
                        file_path.with_file_name(format!("seed-ordinary-log-file.{index}"))
                    }));
                    let reads = paths
                        .map(|path| granary_client::open_regular_read(&path))
                        .filter_map(|result| match result {
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                            result => Some(result),
                        })
                        .map(|result| {
                            let mut file = result?;
                            let mut text = String::new();
                            std::io::Read::read_to_string(&mut file, &mut text)?;
                            Ok(text)
                        });
                    let captures = scan::scan_reads(reads, scan::SECRETS)
                        .expect("output capture unavailable or leaked");
                    assert!(
                        captures.len() > 1,
                        "rotation must create nonempty generations"
                    );
                    captures
                } else {
                    vec![local]
                };
                assert_eq!(
                    scan::scan(&outputs, scan::SECRETS),
                    Ok(()),
                    "destination secret absence"
                );
                if policy == LogPaths::Redacted {
                    assert_eq!(
                        scan::scan(&outputs, scan::ORDINARY),
                        Ok(()),
                        "destination default path absence"
                    );
                } else {
                    assert!(
                        outputs
                            .iter()
                            .any(|output| output.contains(scan::ORDINARY[0])),
                        "full conflict path must reach output"
                    );
                }
                let bundles: Vec<_> = history
                    .snapshot()
                    .records()
                    .iter()
                    .map(|record| String::from_utf8(record.as_bytes().to_vec()).unwrap())
                    .collect();
                assert_eq!(
                    bundles.len(),
                    queued_bundled,
                    "independent prequeue history premise"
                );
                assert_eq!(
                    scan::scan(&bundles, scan::SECRETS),
                    Ok(()),
                    "history secret absence"
                );
                assert_eq!(
                    scan::scan(&bundles, scan::ORDINARY),
                    Ok(()),
                    "history path absence"
                );
                for name in &inventory {
                    assert!(
                        outputs
                            .iter()
                            .any(|output| fixtures::has_identity(output, name)),
                        "every event identity must reach output"
                    );
                }
            }
        }
    }
}
