// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::collections::BTreeMap;
use std::sync::{Mutex, mpsc};

impl CaptureHandle {
    pub(crate) fn with_read_guard<T>(&self, run: impl FnOnce() -> T) -> T {
        let state = self.0.state.read().unwrap();
        let result = run();
        drop(state);
        result
    }
}

#[derive(Debug, Default)]
pub(super) struct Activity {
    pub(super) field_visits: AtomicU64,
    pub(super) state_attempts: AtomicU64,
    pub(super) formats: AtomicU64,
    pub(super) enqueues: AtomicU64,
    before_gate: Mutex<Option<Arc<crate::sink::tests::DebugGate>>>,
}

impl Activity {
    pub(super) fn before_capture(&self) {
        let gate = self.before_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.enter();
        }
    }
}

const P: PrincipalId = PrincipalId::from_bytes([1; 16]);
const Q: PrincipalId = PrincipalId::from_bytes([2; 16]);
const CEILING: &str = "info,granary_server::scoped_capture=debug";

pub(crate) fn entry(id: u64, selector: CaptureSelector) -> CaptureEntry {
    CaptureEntry {
        slot: CaptureSlot(id),
        selector,
        kind: CaptureKind::AuthenticatedRequest,
        level: tracing::Level::DEBUG,
        remaining_lines: MAX_LINES,
        remaining_bytes: MAX_BYTES,
        deadline: None,
        lease: None,
    }
}

fn principal(id: u64, p: PrincipalId) -> CaptureEntry {
    entry(id, CaptureSelector::Principal(p))
}

fn volume(id: u64, v: &str) -> CaptureEntry {
    entry(
        id,
        CaptureSelector::Volume(VolumeName::from_bytes(v.as_bytes()).unwrap()),
    )
}

fn fire(handle: &CaptureHandle, p: PrincipalId, v: &str) {
    handle.authenticated_request(p, &Operation::WriteHint { volume: v });
}

type ObservedEvent = (String, String, BTreeMap<String, String>);

#[derive(Clone, Debug, Default)]
pub(crate) struct Observer {
    pub(crate) events: Arc<Mutex<Vec<ObservedEvent>>>,
}

#[derive(Default)]
struct Observed(BTreeMap<String, String>);

impl tracing::field::Visit for Observed {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.record_str(field, &format!("{value:?}"));
    }
}

impl<S: Subscriber> Layer<S> for Observer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut fields = Observed::default();
        event.record(&mut fields);
        self.events.lock().unwrap().push((
            event.metadata().name().to_owned(),
            event.metadata().level().to_string(),
            fields.0,
        ));
    }
}

pub(crate) fn stack(
    ceiling: &str,
) -> (
    CaptureHandle,
    Observer,
    mpsc::Receiver<Vec<u8>>,
    impl Subscriber + Send + Sync,
) {
    let observer = Observer::default();
    let (sink, lines) = crate::sink::tests::queue();
    let (handle, subscriber) = host_subscriber_with_observer(
        EnvFilter::new(ceiling),
        sink.clone(),
        sink,
        true,
        observer.clone(),
    );
    (handle, observer, lines, subscriber)
}

pub(crate) fn rendered(lines: &mpsc::Receiver<Vec<u8>>) -> Vec<String> {
    lines
        .try_iter()
        .map(|line| String::from_utf8(line).unwrap())
        .collect()
}

#[test]
fn diagnostics_ceiling_refuses_activation_and_blocks_bypassed_capture() {
    for ceiling in [
        "info",
        "off",
        "debug,granary_server::scoped_capture=info",
        "debug,granary_server::scoped_capture=off",
    ] {
        let (handle, observer, lines, subscriber) = stack(ceiling);
        let _default = tracing::subscriber::set_default(subscriber);
        assert_eq!(
            handle.replace(CaptureRevision(0), &[principal(1, P)]),
            Err(CaptureError::Unsupported(CaptureUnsupported::Ceiling)),
            "the immutable target-specific ceiling must refuse activation: {ceiling}"
        );
        // Deliberately bypass only activation. Dispatch must still be stopped by
        // the production constructor's outer ceiling, before the observer.
        handle.0.state.write().unwrap().entries = vec![LiveEntry::new(principal(1, P))];
        handle.0.any.store(true, Ordering::Release);
        fire(&handle, P, "a");
        assert!(
            observer.events.lock().unwrap().is_empty(),
            "ceiling excludes every observer"
        );
        assert!(
            rendered(&lines).is_empty(),
            "bypassed activation cannot bypass dispatch"
        );
    }
    let (handle, observer, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[principal(1, P)])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(
        observer.events.lock().unwrap().len(),
        1,
        "permitting ceiling dispatches"
    );
    assert_eq!(
        rendered(&lines).len(),
        1,
        "permitting ceiling queues capture"
    );
}

#[test]
fn diagnostics_capabilities_and_replacements_are_bounded_and_atomic() {
    let (handle, _, _, _) = stack(CEILING);
    assert_eq!(handle.capabilities().unsupported, None);
    assert_eq!(
        CaptureHandle::new(&EnvFilter::new("debug,[grain_request]=debug"), true)
            .capabilities()
            .unsupported,
        Some(CaptureUnsupported::ContextualCeiling)
    );
    let (sink, _lines) = crate::sink::tests::queue();
    let (unavailable, _subscriber) = host_subscriber(EnvFilter::new("debug"), sink, false);
    assert_eq!(
        unavailable.capabilities().unsupported,
        Some(CaptureUnsupported::Producer)
    );
    assert_eq!(
        unavailable.replace(CaptureRevision(0), &[principal(1, P)]),
        Err(CaptureError::Unsupported(CaptureUnsupported::Producer))
    );
    handle
        .replace(CaptureRevision(0), &[principal(1, P)])
        .unwrap();
    let before = handle.snapshot();
    let mut trace = principal(2, P);
    trace.level = tracing::Level::TRACE;
    let mut lines = principal(2, P);
    lines.remaining_lines = MAX_LINES + 1;
    let mut bytes = principal(2, P);
    bytes.remaining_bytes = MAX_BYTES + 1;
    for invalid in [
        vec![trace],
        vec![lines],
        vec![bytes],
        vec![principal(2, P), principal(2, Q)],
        (2..=66).map(|id| principal(id, P)).collect(),
    ] {
        assert_eq!(
            handle.replace(CaptureRevision(1), &invalid),
            Err(CaptureError::InvalidEntries)
        );
        assert_eq!(
            handle.snapshot(),
            before,
            "validation never partially replaces"
        );
    }
    assert_eq!(
        handle.replace(CaptureRevision(0), &[]),
        Err(CaptureError::StaleRevision)
    );
    assert_eq!(handle.snapshot(), before);
    handle.0.state.write().unwrap().revision = CaptureRevision(u64::MAX);
    assert_eq!(
        handle.replace(CaptureRevision(u64::MAX), &[]),
        Err(CaptureError::RevisionOverflow)
    );
    assert_eq!(handle.snapshot().entries, before.entries);
    let mut buffer = Capped::<3>::default();
    assert!(buffer.write_str("abc").is_ok());
    assert!(buffer.write_str("d").is_err());
    assert_eq!(
        buffer.as_bytes(),
        b"abc",
        "over-bound formatting does not truncate or grow"
    );
}

#[test]
fn diagnostics_retired_ids_cannot_reactivate_or_refill() {
    let (handle, _, _, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[principal(10, P)])
        .unwrap();
    fire(&handle, P, "a");
    handle.replace(CaptureRevision(1), &[]).unwrap();
    let before = handle.snapshot();
    assert_eq!(
        handle.replace(CaptureRevision(2), &[principal(10, P)]),
        Err(CaptureError::RetiredSlot),
        "removed slot IDs must never reactivate"
    );
    assert_eq!(
        handle.replace(CaptureRevision(2), &[principal(9, P)]),
        Err(CaptureError::RetiredSlot)
    );
    assert_eq!(handle.snapshot(), before);
    handle
        .replace(CaptureRevision(2), &[principal(11, P)])
        .unwrap();
    assert_eq!(
        handle.snapshot().entries[0].remaining_lines,
        MAX_LINES,
        "a new monotonic ID represents an explicit new activation"
    );
    handle
        .replace(CaptureRevision(3), &[principal(11, P), principal(20, P)])
        .unwrap();
    assert_eq!(
        handle.replace(
            CaptureRevision(4),
            &[principal(11, P), principal(15, P), principal(20, P)]
        ),
        Err(CaptureError::NonMonotonicSlot)
    );
    handle
        .replace(CaptureRevision(4), &[principal(11, P)])
        .unwrap();
    let before = handle.snapshot();
    handle
        .replace(CaptureRevision(5), &[principal(11, P)])
        .unwrap();
    assert_eq!(
        handle.snapshot().entries,
        before.entries,
        "a live slot below the retirement watermark stays valid"
    );
}

#[test]
fn diagnostics_retained_slots_survive_higher_retirement_without_refill() {
    let (handle, _, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    let mut allowance = principal(1, P);
    allowance.remaining_lines = 3;
    allowance.remaining_bytes = 3 * RESERVATION;
    handle
        .replace(CaptureRevision(0), &[allowance, volume(5, "a")])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(rendered(&lines).len(), 1);
    handle
        .replace(CaptureRevision(1), &[principal(1, P)])
        .unwrap();
    assert_eq!(
        handle.replace(CaptureRevision(2), &[principal(1, P)]),
        Ok(CaptureRevision(3)),
        "retained slot below retirement watermark must remain replaceable"
    );
    assert_eq!(
        handle.replace(CaptureRevision(3), &[principal(1, P), principal(6, Q)]),
        Ok(CaptureRevision(4)),
        "retained slot may coexist with a fresh monotonic slot"
    );
    let before = handle.snapshot();
    assert_eq!(
        before.entries[0].remaining_lines, 2,
        "retained line budget cannot refill"
    );
    assert_eq!(
        before.entries[0].remaining_bytes,
        2 * RESERVATION,
        "retained byte budget cannot refill"
    );
    assert_eq!(before.entries[1].remaining_lines, MAX_LINES);
    assert_eq!(
        handle.replace(
            CaptureRevision(4),
            &[principal(1, P), volume(5, "a"), principal(6, Q)]
        ),
        Err(CaptureError::RetiredSlot),
        "removed slot remains retired beside a live lower slot"
    );
    assert_eq!(handle.snapshot(), before);
    fire(&handle, P, "a");
    assert_eq!(rendered(&lines).len(), 1, "retained slot remains effective");
}

#[test]
fn diagnostics_matching_capture_succeeds_while_a_shared_guard_is_held() {
    let (handle, _, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    let mut allowance = principal(1, P);
    allowance.remaining_lines = 2;
    allowance.remaining_bytes = 2 * RESERVATION;
    handle.replace(CaptureRevision(0), &[allowance]).unwrap();
    // Simulate another capture owning its guard through an enqueue attempt.
    let held = handle.0.state.read().unwrap();
    fire(&handle, P, "a");
    assert_eq!(
        rendered(&lines).len(),
        1,
        "matching capture must succeed while another capture holds a shared guard"
    );
    fire(&handle, Q, "b");
    assert!(rendered(&lines).is_empty());
    fire(&handle, P, "a");
    assert_eq!(rendered(&lines).len(), 1);
    assert_eq!(
        handle.0.counters.contention.load(Ordering::Relaxed),
        0,
        "concurrent captures cannot count as replacement contention"
    );
    assert_eq!(held.entries[0].allowance(), (0, 0));
    drop(held);
    // A writer represents replacement; capture must skip it instead of waiting.
    let replacing = handle.0.state.write().unwrap();
    fire(&handle, P, "a");
    assert!(rendered(&lines).is_empty());
    assert_eq!(handle.0.counters.contention.load(Ordering::Relaxed), 1);
    drop(replacing);
}

#[test]
fn diagnostics_concurrent_captures_reserve_both_budgets_atomically() {
    let (handle, _, lines, subscriber) = stack(CEILING);
    let mut allowance = principal(1, P);
    allowance.remaining_lines = 8;
    allowance.remaining_bytes = 8 * RESERVATION;
    handle.replace(CaptureRevision(0), &[allowance]).unwrap();
    let dispatch = tracing::Dispatch::new(subscriber);
    let ready = Arc::new(std::sync::Barrier::new(16));
    let mut workers = Vec::new();
    for _ in 0..16 {
        let worker = handle.clone();
        let dispatch = dispatch.clone();
        let ready = Arc::clone(&ready);
        workers.push(std::thread::spawn(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                ready.wait();
                fire(&worker, P, "a");
            });
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(
        rendered(&lines).len(),
        8,
        "concurrent captures spend exactly the available reservations"
    );
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.entries[0].remaining_lines, 0);
    assert_eq!(snapshot.entries[0].remaining_bytes, 0);
    assert_eq!(snapshot.counters.admitted, 8);
    assert_eq!(snapshot.counters.budget_suppressed, 8);
    assert_eq!(snapshot.counters.contention, 0);
}

#[test]
fn diagnostics_operation_fields_follow_the_admitted_operation_names() {
    let (handle, _, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[principal(1, P)])
        .unwrap();
    let v = VolumeName::from_bytes(b"a").unwrap();
    let id = granary_core::hash::GrainId::of(b"meta");
    let operations = [
        Operation::Intent {
            volume: v.clone(),
            operation: crate::authority::IntentOperation::Register,
        },
        Operation::Intent {
            volume: v.clone(),
            operation: crate::authority::IntentOperation::Release,
        },
        Operation::Intent {
            volume: v.clone(),
            operation: crate::authority::IntentOperation::Ownership,
        },
        Operation::Intent {
            volume: v.clone(),
            operation: crate::authority::IntentOperation::Readback,
        },
        Operation::Publish { volume: v.clone() },
        Operation::PutBin { digest: [0; 32] },
        Operation::PutMeta { volume: "a", id },
        Operation::PutRoot {
            volume: v.clone(),
            seq: 1,
        },
        Operation::WriteHint { volume: "a" },
    ];
    assert_eq!(
        operations.len(),
        OperationKind::AUTHENTICATED_WRITES.len() + OperationKind::AUTHENTICATED_READS.len()
    );
    for operation in operations {
        handle.authenticated_request(P, &operation);
        let captured = rendered(&lines);
        assert_eq!(
            captured.len(),
            1,
            "every authenticated operation name must remain capturable"
        );
        assert!(
            captured[0].contains(&format!("\"operation\":\"{}\"", operation.name())),
            "capture must derive its operation name from the admitted operation"
        );
    }
    let reads = [
        Operation::VolumeStatus { volume: v.clone() },
        Operation::GetBinRange {
            digest: [0; 32],
            offset: 0,
            len: 1,
        },
        Operation::GetMeta { volume: "a", id },
        Operation::GetRoot { volume: v, seq: 1 },
        Operation::MaxSeq { volume: "a" },
        Operation::ReadHint {
            volume: "a",
            if_none_match: None,
        },
    ];
    for operation in reads {
        tracing::event!(name: "request_authenticated", target: "granary_server::scoped_capture",
            tracing::Level::DEBUG, principal = %P, volume = "a", operation = operation.name());
    }
    assert!(
        rendered(&lines).is_empty(),
        "read operation names cannot enter authenticated capture"
    );
    assert_eq!(handle.snapshot().counters.malformed, 6);
}

#[test]
fn diagnostics_empty_interest_remains_usable_and_has_no_capture_work() {
    let (handle, observer, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    // Prime the exact diagnostic callsite independently of the producer's fast skip.
    for _ in 0..2 {
        tracing::event!(name: "request_authenticated", target: "granary_server::scoped_capture",
            tracing::Level::DEBUG, principal = %P, volume = "a", operation = "write_hint");
        if handle.snapshot().revision.0 == 0 {
            handle
                .replace(CaptureRevision(0), &[principal(1, P)])
                .unwrap();
        }
    }
    assert_eq!(
        observer.events.lock().unwrap().len(),
        1,
        "same registered callsite becomes usable"
    );
    assert_eq!(rendered(&lines).len(), 1);
    handle.replace(CaptureRevision(1), &[]).unwrap();
    let before = handle.snapshot().counters;
    let activity = &handle.0.activity;
    let counts = [
        activity.field_visits.load(Ordering::Relaxed),
        activity.state_attempts.load(Ordering::Relaxed),
        activity.formats.load(Ordering::Relaxed),
        activity.enqueues.load(Ordering::Relaxed),
    ];
    assert_eq!(
        counts, [1; 4],
        "the positive arm visits, checks, formats and queues"
    );
    fire(&handle, P, "a");
    assert_eq!(
        [
            activity.field_visits.load(Ordering::Relaxed),
            activity.state_attempts.load(Ordering::Relaxed),
            activity.formats.load(Ordering::Relaxed),
            activity.enqueues.load(Ordering::Relaxed)
        ],
        counts,
        "empty producer performs no field visit, lock, formatting or enqueue"
    );
    assert_eq!(handle.snapshot().counters, before);
    assert!(rendered(&lines).is_empty());
}

#[test]
fn diagnostics_exact_fields_overlap_and_missing_volume() {
    let (handle, observer, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    let mut first = volume(1, "a");
    first.remaining_lines = 1;
    handle
        .replace(CaptureRevision(0), &[principal(2, P), first])
        .unwrap();
    fire(&handle, Q, "b");
    fire(&handle, P, "a");
    fire(&handle, P, "a");
    let captured = rendered(&lines);
    assert_eq!(
        captured.len(),
        2,
        "ungranted Q/B is silent, overlapping P/A emits once"
    );
    assert!(captured[0].contains("\"slot\":1"));
    assert!(
        captured[1].contains("\"slot\":2"),
        "exhausted lower ID yields to available overlap"
    );
    assert_eq!(
        observer.events.lock().unwrap().len(),
        3,
        "scope suppresses output, not dispatched events"
    );
    handle
        .replace(CaptureRevision(1), &[volume(3, "a")])
        .unwrap();
    handle.authenticated_request(P, &Operation::PutBin { digest: [0; 32] });
    assert!(rendered(&lines).is_empty(), "absent volume never matches");
    fire(&handle, Q, "a");
    assert_eq!(
        rendered(&lines).len(),
        1,
        "volume selectors capture another enrolled principal"
    );
}

#[test]
fn diagnostics_budget_charge_and_retained_slot_cannot_refill() {
    let (handle, _, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    let mut exact = principal(1, P);
    exact.remaining_lines = 1;
    exact.remaining_bytes = RESERVATION;
    handle.replace(CaptureRevision(0), &[exact]).unwrap();
    fire(&handle, P, "a");
    assert_eq!(
        rendered(&lines).len(),
        1,
        "exact allowance admits one bounded line"
    );
    assert_eq!(
        handle.snapshot().entries[0].remaining_lines,
        0,
        "capture must charge its line budget"
    );
    assert_eq!(
        handle.snapshot().entries[0].remaining_bytes,
        0,
        "capture must charge its byte budget"
    );
    fire(&handle, P, "a");
    assert!(rendered(&lines).is_empty(), "next capture is suppressed");
    handle
        .replace(CaptureRevision(1), &[volume(1, "b")])
        .unwrap();
    assert_eq!(
        handle.snapshot().entries[0].remaining_lines,
        0,
        "retained slot replacement must not refill lines"
    );
    assert_eq!(
        handle.snapshot().entries[0].remaining_bytes,
        0,
        "retained slot replacement must not refill bytes"
    );
    fire(&handle, Q, "b");
    assert!(rendered(&lines).is_empty());
    assert_eq!(handle.snapshot().counters.budget_suppressed, 2);
    handle
        .replace(CaptureRevision(2), &[principal(2, P)])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(rendered(&lines).len(), 1, "fresh activation still works");
}

#[test]
fn diagnostics_malformed_and_oversize_fields_drop_without_disclosure() {
    let (handle, observer, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[principal(1, P)])
        .unwrap();
    let long = "secret".repeat(1000);
    tracing::event!(name: "request_authenticated", target: "granary_server::scoped_capture",
        tracing::Level::DEBUG, principal = %P, volume = long.as_str(), operation = "write_hint");
    tracing::event!(name: "request_authenticated", target: "granary_server::scoped_capture",
        tracing::Level::DEBUG, principal = "invalid", volume = "a", operation = "write_hint");
    tracing::event!(name: "request_authenticated", target: "granary_server::scoped_capture",
        tracing::Level::DEBUG, principal = %P, volume = "a", operation = "secret");
    tracing::event!(name: "request_authenticated", target: "granary_server::scoped_capture",
        tracing::Level::DEBUG, volume = "a", operation = "write_hint");
    assert!(
        rendered(&lines).is_empty(),
        "invalid values never reach fmt or the capture queue"
    );
    assert_eq!(handle.snapshot().counters.oversize, 1);
    assert_eq!(handle.snapshot().counters.malformed, 3);
    assert_eq!(handle.snapshot().entries[0].remaining_lines, MAX_LINES);
    fire(&handle, P, "a");
    let positive = rendered(&lines);
    assert_eq!(positive.len(), 1);
    assert!(positive[0].len() <= DEBUG_LINE_BYTES);
    assert_eq!(observer.events.lock().unwrap().len(), 5);
}

#[test]
fn diagnostics_narrow_replacement_rechecks_constructed_event_under_guard() {
    let (entered, paused) = mpsc::sync_channel(1);
    let (resume, release) = mpsc::channel();
    let (sink, lines) = crate::sink::tests::queue();
    let (handle, subscriber) = host_subscriber_with_observer(
        EnvFilter::new(CEILING),
        sink.clone(),
        sink,
        true,
        Observer::default(),
    );
    *handle.0.activity.before_gate.lock().unwrap() =
        Some(Arc::new(crate::sink::tests::DebugGate {
            entered,
            release: Mutex::new(release),
        }));
    handle
        .replace(CaptureRevision(0), &[principal(1, P), volume(2, "a")])
        .unwrap();
    let dispatch = tracing::Dispatch::new(subscriber);
    let producer_handle = handle.clone();
    let producer = std::thread::spawn(move || {
        tracing::dispatcher::with_default(&dispatch, || {
            fire(&producer_handle, Q, "a");
        });
    });
    paused.recv().unwrap();
    handle
        .replace(CaptureRevision(1), &[principal(1, P)])
        .unwrap();
    resume.send(()).unwrap();
    producer.join().unwrap();
    assert!(
        rendered(&lines).is_empty(),
        "constructed event must pass the current scope under the guard"
    );
    assert_eq!(handle.snapshot().counters.admitted, 0);
    // A new subscriber using the same production constructor supplies a positive
    // arm without another pause, and confirms the retained principal is effective.
    let (positive, _, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    positive
        .replace(CaptureRevision(0), &[principal(1, P)])
        .unwrap();
    fire(&positive, P, "a");
    assert_eq!(rendered(&lines).len(), 1);
}

#[test]
fn diagnostics_replacement_waits_for_enqueue_guard_and_contention_suppresses() {
    let (entered, paused) = mpsc::sync_channel(1);
    let (resume, release) = mpsc::channel();
    let (mut sink, lines) = crate::sink::tests::queue();
    sink.debug_gate = Some(Arc::new(crate::sink::tests::DebugGate {
        entered,
        release: Mutex::new(release),
    }));
    let (handle, subscriber) = host_subscriber_with_observer(
        EnvFilter::new(CEILING),
        sink.clone(),
        sink,
        true,
        Observer::default(),
    );
    handle
        .replace(CaptureRevision(0), &[principal(1, P)])
        .unwrap();
    let dispatch = tracing::Dispatch::new(subscriber);
    let worker_dispatch = dispatch.clone();
    let worker_handle = handle.clone();
    let producer = std::thread::spawn(move || {
        tracing::dispatcher::with_default(&worker_dispatch, || fire(&worker_handle, P, "a"));
    });
    paused.recv().unwrap();
    assert!(
        matches!(handle.0.state.try_write(), Err(TryLockError::WouldBlock)),
        "enqueue must still own the final capture guard"
    );
    let (started, ready) = mpsc::channel();
    let (done, returned) = mpsc::channel();
    let replacing = handle.clone();
    let replacement = std::thread::spawn(move || {
        started.send(()).unwrap();
        done.send(replacing.replace(CaptureRevision(1), &[]))
            .unwrap();
    });
    ready.recv().unwrap();
    assert!(matches!(
        returned.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    resume.send(()).unwrap();
    producer.join().unwrap();
    assert_eq!(returned.recv().unwrap(), Ok(CaptureRevision(2)));
    replacement.join().unwrap();
    assert_eq!(
        rendered(&lines).len(),
        1,
        "queued old capture may drain after replacement"
    );
    tracing::dispatcher::with_default(&dispatch, || fire(&handle, P, "a"));
    assert!(
        rendered(&lines).is_empty(),
        "nothing enqueues under the removed scope after return"
    );
    handle
        .replace(CaptureRevision(2), &[principal(2, P)])
        .unwrap();
    let replacement_guard = handle.0.state.write().unwrap();
    tracing::dispatcher::with_default(&dispatch, || fire(&handle, P, "a"));
    assert!(
        rendered(&lines).is_empty(),
        "capture never waits for a replacement's write guard"
    );
    assert_eq!(handle.0.counters.contention.load(Ordering::Relaxed), 1);
    drop(replacement_guard);
}

#[test]
fn diagnostics_poison_disables_until_restart_and_counters_saturate() {
    let (handle, _, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[principal(1, P)])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(rendered(&lines).len(), 1);
    let poisoned = handle.clone();
    assert!(
        // This fixture unwinds only while holding the state guard and never
        // calls the injected clock; the poison refusal is the observed outcome.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = poisoned.0.state.write().unwrap();
            panic!("poison the capture guard");
        }))
        .is_err()
    );
    fire(&handle, P, "a");
    assert_eq!(
        handle.replace(CaptureRevision(1), &[]),
        Err(CaptureError::Poisoned)
    );
    assert!(handle.snapshot().poisoned);
    assert!(handle.snapshot().entries.is_empty());
    assert!(!handle.0.any.load(Ordering::Acquire));
    assert!(rendered(&lines).is_empty());
    let counter = AtomicU64::new(u64::MAX);
    increment(&counter);
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
}

#[derive(Debug)]
struct TestClock {
    time: Mutex<Timestamp>,
    reads: AtomicU64,
}

impl TestClock {
    fn new(time: Timestamp) -> Self {
        Self {
            time: Mutex::new(time),
            reads: AtomicU64::new(0),
        }
    }

    fn set(&self, time: Timestamp) {
        *self.time.lock().unwrap() = time;
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        self.reads.fetch_add(1, Ordering::Relaxed);
        *self.time.lock().unwrap()
    }
}

const BEFORE: Timestamp = Timestamp {
    secs: 100,
    nanos: 41,
};
const DEADLINE: Timestamp = Timestamp {
    secs: 100,
    nanos: 42,
};
const AFTER: Timestamp = Timestamp {
    secs: 100,
    nanos: 43,
};

fn timed(mut entry: CaptureEntry, deadline: Timestamp) -> CaptureEntry {
    entry.deadline = Some(deadline);
    entry.lease = Some(77);
    entry
}

fn conjunction(id: u64, principal: PrincipalId, volume: &str) -> CaptureEntry {
    entry(
        id,
        CaptureSelector::PrincipalAndVolume(
            principal,
            VolumeName::from_bytes(volume.as_bytes()).unwrap(),
        ),
    )
}

fn clock_stack(
    clock: Arc<dyn Clock>,
) -> (
    CaptureHandle,
    Observer,
    mpsc::Receiver<Vec<u8>>,
    impl Subscriber + Send + Sync,
) {
    let observer = Observer::default();
    let (sink, lines) = crate::sink::tests::queue();
    let (handle, subscriber) = subscriber_with_clock_and_observer(
        EnvFilter::new(CEILING),
        sink.clone(),
        sink,
        true,
        Some(clock),
        observer.clone(),
    );
    (handle, observer, lines, subscriber)
}

fn debug_lines(lines: &mpsc::Receiver<Vec<u8>>) -> Vec<String> {
    rendered(lines)
        .into_iter()
        .filter(|line| line.contains("\"event\":\"request_authenticated\""))
        .collect()
}

#[test]
fn diagnostics_deadline_boundary_latches_without_replacement() {
    let clock = Arc::new(TestClock::new(BEFORE));
    let (handle, observer, lines, subscriber) = clock_stack(clock.clone());
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[timed(principal(1, P), DEADLINE)])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(
        debug_lines(&lines).len(),
        1,
        "capture just before the deadline must succeed"
    );
    let allowance = handle.0.state.read().unwrap().entries[0].allowance();
    clock.set(DEADLINE);
    fire(&handle, P, "a");
    assert!(
        debug_lines(&lines).is_empty(),
        "capture at the exact deadline must be refused"
    );
    clock.set(AFTER);
    fire(&handle, P, "a");
    assert!(
        debug_lines(&lines).is_empty(),
        "capture after the deadline must be refused"
    );
    let snapshot = handle.snapshot();
    assert!(
        snapshot.entries.is_empty(),
        "expired scope must disappear without replacement"
    );
    assert_eq!(snapshot.revision, CaptureRevision(1));
    assert_eq!(
        snapshot.counters.expired, 1,
        "one expiry transition per slot"
    );
    assert_eq!(snapshot.counters.expiry_suppressed, 1);
    assert_eq!(snapshot.counters.suppressed, 1);
    assert_eq!(snapshot.counters.admitted, 1);
    assert_eq!(snapshot.counters.queued, 1);
    assert_eq!(
        handle.0.state.read().unwrap().entries[0].allowance(),
        allowance,
        "expired attempts must not spend budget"
    );
    let events = observer.events.lock().unwrap();
    let expiries: Vec<_> = events
        .iter()
        .filter(|event| event.0 == "debug_grant_expire")
        .collect();
    assert_eq!(expiries.len(), 1);
    let fields = &expiries[0].2;
    assert_eq!(fields.get("lease").map(String::as_str), Some("77"));
    assert_eq!(fields.get("slot").map(String::as_str), Some("1"));
    assert_eq!(
        fields.get("capture_revision").map(String::as_str),
        Some("1")
    );
}

#[test]
fn diagnostics_retained_deadline_can_only_shorten() {
    let clock = Arc::new(TestClock::new(BEFORE));
    let (handle, _, lines, subscriber) = clock_stack(clock.clone());
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[timed(principal(1, P), DEADLINE)])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(debug_lines(&lines).len(), 1);
    handle
        .replace(CaptureRevision(1), &[timed(principal(1, P), AFTER)])
        .unwrap();
    assert_eq!(
        handle.snapshot().entries[0].deadline,
        Some(DEADLINE),
        "retained slot deadline cannot move later"
    );
    let mut without_deadline = principal(1, P);
    without_deadline.lease = Some(77);
    handle
        .replace(CaptureRevision(2), &[without_deadline])
        .unwrap();
    assert_eq!(
        handle.snapshot().entries[0].deadline,
        Some(DEADLINE),
        "absent requested deadline cannot remove a retained deadline"
    );
    assert_eq!(
        handle.snapshot().entries[0].lease,
        Some(77),
        "retained expiry keeps its lease identity"
    );
    handle
        .replace(CaptureRevision(3), &[timed(principal(1, P), BEFORE)])
        .unwrap();
    fire(&handle, P, "a");
    assert!(
        debug_lines(&lines).is_empty(),
        "shortened deadline takes effect immediately"
    );
    assert_eq!(
        handle.0.state.read().unwrap().entries[0].deadline,
        Some(BEFORE)
    );
    assert_eq!(
        handle.0.state.read().unwrap().entries[0].allowance(),
        (MAX_LINES - 1, MAX_BYTES - RESERVATION)
    );
    assert_eq!(handle.snapshot().counters.expired, 1);
}

#[test]
fn diagnostics_expiry_latch_survives_replacement_and_clock_rollback() {
    let clock = Arc::new(TestClock::new(BEFORE));
    let (handle, _, lines, subscriber) = clock_stack(clock.clone());
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[timed(principal(1, P), DEADLINE)])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(debug_lines(&lines).len(), 1);
    clock.set(DEADLINE);
    fire(&handle, P, "a");
    assert!(debug_lines(&lines).is_empty());
    assert_eq!(handle.snapshot().counters.expired, 1);
    clock.set(BEFORE);
    assert!(
        handle.snapshot().entries.is_empty(),
        "clock rollback cannot unlatch expiry"
    );
    handle
        .replace(CaptureRevision(1), &[timed(principal(1, P), AFTER)])
        .unwrap();
    assert!(
        handle.snapshot().entries.is_empty(),
        "retained slot expiry latch must survive replacement"
    );
    fire(&handle, P, "a");
    assert!(
        debug_lines(&lines).is_empty(),
        "retained expired slot must never capture again"
    );
    let snapshot = handle.snapshot();
    assert_eq!(
        snapshot.counters.expired, 1,
        "replacement cannot recount observed expiry"
    );
    assert_eq!(snapshot.counters.expiry_suppressed, 1);
    handle
        .replace(CaptureRevision(2), &[timed(principal(2, P), AFTER)])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(
        debug_lines(&lines).len(),
        1,
        "a fresh slot has its own lease and latch"
    );
}

#[test]
fn diagnostics_conjunction_requires_both_fields() {
    let (handle, _, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[conjunction(1, P, "a")])
        .unwrap();
    fire(&handle, P, "b");
    assert!(
        debug_lines(&lines).is_empty(),
        "conjunction must refuse a principal-only match"
    );
    fire(&handle, Q, "a");
    assert!(
        debug_lines(&lines).is_empty(),
        "conjunction must refuse a volume-only match"
    );
    fire(&handle, Q, "b");
    handle.authenticated_request(P, &Operation::PutBin { digest: [0; 32] });
    assert!(
        debug_lines(&lines).is_empty(),
        "missing volume cannot satisfy conjunction"
    );
    fire(&handle, P, "a");
    let captured = debug_lines(&lines);
    assert_eq!(
        captured.len(),
        1,
        "both conjuncts form the positive capture witness"
    );
    assert!(captured[0].contains(&format!("\"principal\":\"{P}\"")));
    assert!(captured[0].contains("\"volume\":\"a\""));
    assert_eq!(handle.snapshot().entries[0].remaining_lines, MAX_LINES - 1);
}

#[test]
fn diagnostics_conjunction_narrowing_keeps_slot_budget_and_enqueue_guard() {
    let (entered, paused) = mpsc::sync_channel(1);
    let (resume, release) = mpsc::channel();
    let (mut sink, lines) = crate::sink::tests::queue();
    sink.debug_gate = Some(Arc::new(crate::sink::tests::DebugGate {
        entered,
        release: Mutex::new(release),
    }));
    let (handle, subscriber) = host_subscriber_with_observer(
        EnvFilter::new(CEILING),
        sink.clone(),
        sink,
        true,
        Observer::default(),
    );
    let mut original = principal(1, P);
    original.remaining_lines = 4;
    original.remaining_bytes = 4 * RESERVATION;
    handle.replace(CaptureRevision(0), &[original]).unwrap();
    let dispatch = tracing::Dispatch::new(subscriber);
    resume.send(()).unwrap();
    tracing::dispatcher::with_default(&dispatch, || fire(&handle, P, "a"));
    paused.recv().unwrap();
    assert_eq!(
        debug_lines(&lines).len(),
        1,
        "principal grant captures the retained volume"
    );
    let worker = handle.clone();
    let worker_dispatch = dispatch.clone();
    let producer = std::thread::spawn(move || {
        tracing::dispatcher::with_default(&worker_dispatch, || fire(&worker, P, "b"));
    });
    paused.recv().unwrap();
    assert!(matches!(
        handle.0.state.try_write(),
        Err(TryLockError::WouldBlock)
    ));
    let (started, ready) = mpsc::channel();
    let (done, returned) = mpsc::channel();
    let control = handle.clone();
    let replacement = std::thread::spawn(move || {
        started.send(()).unwrap();
        done.send(control.replace(CaptureRevision(1), &[conjunction(1, P, "a")]))
            .unwrap();
    });
    ready.recv().unwrap();
    assert!(matches!(
        returned.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    resume.send(()).unwrap();
    producer.join().unwrap();
    assert_eq!(returned.recv().unwrap(), Ok(CaptureRevision(2)));
    replacement.join().unwrap();
    assert_eq!(
        debug_lines(&lines).len(),
        1,
        "previously queued excluded-volume record may drain"
    );
    // A queued release also keeps the wrong-scope mutation from blocking here.
    resume.send(()).unwrap();
    tracing::dispatcher::with_default(&dispatch, || fire(&handle, P, "b"));
    assert!(
        debug_lines(&lines).is_empty(),
        "narrowed conjunction must refuse excluded volume after replace returns"
    );
    let snapshot = handle.snapshot();
    assert_eq!(
        snapshot.entries[0].slot,
        CaptureSlot(1),
        "narrowing must keep the slot"
    );
    assert_eq!(
        snapshot.entries[0].selector,
        conjunction(1, P, "a").selector
    );
    assert_eq!(
        snapshot.entries[0].remaining_lines, 2,
        "narrowing must keep spent line budget"
    );
    assert_eq!(
        snapshot.entries[0].remaining_bytes,
        2 * RESERVATION,
        "narrowing must keep spent byte budget"
    );
    tracing::dispatcher::with_default(&dispatch, || fire(&handle, P, "a"));
    let captured = debug_lines(&lines);
    assert_eq!(
        captured.len(),
        1,
        "narrowed scope still captures the retained volume"
    );
    assert!(captured[0].contains("\"slot\":1,\"revision\":2"));
    assert_eq!(handle.snapshot().entries[0].remaining_lines, 1);
}

#[test]
fn diagnostics_final_deadline_check_prevents_enqueue_after_charging() {
    struct AdvancingClock(Mutex<std::collections::VecDeque<Timestamp>>);
    impl Clock for AdvancingClock {
        fn now(&self) -> Timestamp {
            self.0.lock().unwrap().pop_front().unwrap_or(DEADLINE)
        }
    }
    let clock = Arc::new(AdvancingClock(Mutex::new(
        [BEFORE, BEFORE, DEADLINE].into(),
    )));
    let (handle, _, lines, subscriber) = clock_stack(clock);
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[timed(principal(1, P), DEADLINE)])
        .unwrap();
    fire(&handle, P, "a");
    assert!(
        debug_lines(&lines).is_empty(),
        "final deadline check must refuse enqueue after expiry"
    );
    assert_eq!(
        handle.0.activity.formats.load(Ordering::Relaxed),
        1,
        "pre-expiry attempt reached bounded formatting"
    );
    assert_eq!(handle.0.activity.enqueues.load(Ordering::Relaxed), 0);
    assert_eq!(
        handle.0.state.read().unwrap().entries[0].allowance(),
        (MAX_LINES - 1, MAX_BYTES - RESERVATION),
        "final expiry suppression never refunds the reservation"
    );
    let snapshot = handle.snapshot();
    assert!(snapshot.entries.is_empty());
    assert_eq!(snapshot.counters.expired, 1);
    assert_eq!(snapshot.counters.expiry_suppressed, 1);
    assert_eq!(
        snapshot.counters.admitted, 1,
        "scope and budget admission precedes the final clock check"
    );
}

#[test]
fn diagnostics_snapshot_observes_expiry_and_notifies_outside_guard() {
    #[derive(Clone, Default)]
    struct ExpiryObserver {
        handle: Arc<Mutex<Option<CaptureHandle>>>,
        notices: Arc<AtomicU64>,
    }
    impl<S: Subscriber> Layer<S> for ExpiryObserver {
        fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
            if event.metadata().name() == "debug_grant_expire" {
                let handle = self.handle.lock().unwrap().clone().unwrap();
                assert!(
                    handle.0.state.try_write().is_ok(),
                    "expiry notification must run outside the capture guard"
                );
                self.notices.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    let observer = ExpiryObserver::default();
    let clock = Arc::new(TestClock::new(BEFORE));
    let (sink, lines) = crate::sink::tests::queue();
    let (handle, subscriber) = subscriber_with_clock_and_observer(
        EnvFilter::new(CEILING),
        sink.clone(),
        sink,
        true,
        Some(clock.clone()),
        observer.clone(),
    );
    *observer.handle.lock().unwrap() = Some(handle.clone());
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[timed(principal(1, P), DEADLINE)])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(debug_lines(&lines).len(), 1);
    clock.set(DEADLINE);
    let snapshot = handle.snapshot();
    assert!(
        snapshot.entries.is_empty(),
        "snapshot must hide an expired effective scope"
    );
    assert_eq!(snapshot.counters.expired, 1);
    assert_eq!(
        snapshot.counters.expiry_suppressed, 0,
        "snapshot expiry is not a suppressed request"
    );
    assert_eq!(observer.notices.load(Ordering::Relaxed), 1);
    assert!(handle.snapshot().entries.is_empty());
    assert_eq!(
        observer.notices.load(Ordering::Relaxed),
        1,
        "repeated snapshots never announce twice"
    );
    fire(&handle, P, "a");
    assert!(debug_lines(&lines).is_empty());
    assert_eq!(handle.snapshot().counters.expiry_suppressed, 0);
    assert_eq!(observer.notices.load(Ordering::Relaxed), 1);
    handle
        .replace(CaptureRevision(1), &[timed(principal(2, P), AFTER)])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(debug_lines(&lines).len(), 1);
    clock.set(AFTER);
    fire(&handle, P, "a");
    assert!(debug_lines(&lines).is_empty());
    assert_eq!(
        observer.notices.load(Ordering::Relaxed),
        2,
        "request-side expiry also notifies outside its guard"
    );
}

#[test]
fn diagnostics_concurrent_expiry_is_counted_once_per_slot() {
    let clock = Arc::new(TestClock::new(BEFORE));
    let (handle, observer, lines, subscriber) = clock_stack(clock.clone());
    handle
        .replace(CaptureRevision(0), &[timed(principal(1, P), DEADLINE)])
        .unwrap();
    let dispatch = tracing::Dispatch::new(subscriber);
    tracing::dispatcher::with_default(&dispatch, || fire(&handle, P, "a"));
    assert_eq!(debug_lines(&lines).len(), 1);
    clock.set(DEADLINE);
    let ready = Arc::new(std::sync::Barrier::new(16));
    let mut workers = Vec::new();
    for _ in 0..16 {
        let worker = handle.clone();
        let dispatch = dispatch.clone();
        let ready = ready.clone();
        workers.push(std::thread::spawn(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                ready.wait();
                fire(&worker, P, "a");
            });
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert!(debug_lines(&lines).is_empty());
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.counters.expired, 1);
    assert!((1..=16).contains(&snapshot.counters.expiry_suppressed));
    assert_eq!(
        snapshot.counters.suppressed,
        snapshot.counters.expiry_suppressed
    );
    assert_eq!(snapshot.counters.contention, 0);
    assert_eq!(
        observer
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.0 == "debug_grant_expire")
            .count(),
        1
    );
}

#[test]
fn diagnostics_deadline_free_entries_do_not_read_injected_clock() {
    let clock = Arc::new(TestClock::new(AFTER));
    let (sink, lines) = crate::sink::tests::queue();
    let (handle, subscriber) =
        CaptureHandle::subscriber_with_clock(EnvFilter::new(CEILING), sink, true, clock.clone());
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[principal(1, P)])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(debug_lines(&lines).len(), 1);
    assert_eq!(handle.snapshot().entries[0].remaining_lines, MAX_LINES - 1);
    assert_eq!(
        clock.reads.load(Ordering::Relaxed),
        1,
        "deadline-free capture and snapshot add no clock reads after replacement"
    );
}

#[test]
fn diagnostics_deadline_activation_requires_injection_and_valid_timestamp() {
    let (handle, _, lines, subscriber) = stack(CEILING);
    let _default = tracing::subscriber::set_default(subscriber);
    assert_eq!(
        handle.replace(CaptureRevision(0), &[timed(principal(1, P), DEADLINE)]),
        Err(CaptureError::Unsupported(CaptureUnsupported::Clock)),
        "deadline activation requires an injected clock"
    );
    handle
        .replace(CaptureRevision(0), &[principal(1, P)])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(
        debug_lines(&lines).len(),
        1,
        "deadline-free activation remains available"
    );
    let (clocked, _, _, _) = clock_stack(Arc::new(TestClock::new(BEFORE)));
    let before = clocked.snapshot();
    assert_eq!(
        clocked.replace(
            CaptureRevision(0),
            &[timed(
                principal(1, P),
                Timestamp {
                    secs: 100,
                    nanos: 1_000_000_000
                }
            )]
        ),
        Err(CaptureError::InvalidEntries)
    );
    assert_eq!(
        clocked.snapshot(),
        before,
        "invalid deadline cannot partially activate capture"
    );
}

#[test]
fn diagnostics_expiry_notification_respects_the_immutable_ceiling() {
    let clock = Arc::new(TestClock::new(BEFORE));
    let observer = Observer::default();
    let (sink, lines) = crate::sink::tests::queue();
    let (handle, subscriber) = subscriber_with_clock_and_observer(
        EnvFilter::new("off,granary_server::scoped_capture=debug"),
        sink.clone(),
        sink,
        true,
        Some(clock.clone()),
        observer.clone(),
    );
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[timed(principal(1, P), DEADLINE)])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(
        debug_lines(&lines).len(),
        1,
        "the capture-specific ceiling permits the positive witness"
    );
    clock.set(DEADLINE);
    fire(&handle, P, "a");
    assert!(
        rendered(&lines).is_empty(),
        "expiry notification must remain subject to the host ceiling"
    );
    assert!(
        observer
            .events
            .lock()
            .unwrap()
            .iter()
            .all(|event| event.0 != "debug_grant_expire")
    );
    let snapshot = handle.snapshot();
    assert!(snapshot.entries.is_empty());
    assert_eq!(
        snapshot.counters.expired, 1,
        "the snapshot keeps expiry authoritative when output is filtered"
    );
    assert_eq!(snapshot.counters.expiry_suppressed, 1);
}

#[test]
fn diagnostics_retained_slot_requires_the_same_lease() {
    let clock = Arc::new(TestClock::new(BEFORE));
    let (handle, observer, lines, subscriber) = clock_stack(clock.clone());
    let _default = tracing::subscriber::set_default(subscriber);
    let original = timed(principal(1, P), DEADLINE);
    handle
        .replace(CaptureRevision(0), std::slice::from_ref(&original))
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(debug_lines(&lines).len(), 1);
    let before = handle.snapshot();
    for lease in [Some(88), None] {
        let mut changed = original.clone();
        changed.lease = lease;
        changed.deadline = Some(AFTER);
        assert_eq!(
            handle.replace(CaptureRevision(1), &[changed]),
            Err(CaptureError::LeaseMismatch),
            "a retained slot must refuse a different lease"
        );
        assert_eq!(handle.snapshot(), before, "lease refusal must be atomic");
    }
    handle.replace(CaptureRevision(1), &[original]).unwrap();
    assert_eq!(handle.snapshot().entries[0].remaining_lines, MAX_LINES - 1);
    clock.set(DEADLINE);
    fire(&handle, P, "a");
    assert!(debug_lines(&lines).is_empty());
    let events = observer.events.lock().unwrap();
    let notice = events
        .iter()
        .find(|event| event.0 == "debug_grant_expire")
        .unwrap();
    assert_eq!(notice.2.get("lease").map(String::as_str), Some("77"));
    drop(events);
    let mut new_lease = timed(principal(2, P), AFTER);
    new_lease.lease = Some(88);
    handle.replace(CaptureRevision(2), &[new_lease]).unwrap();
    fire(&handle, P, "a");
    assert_eq!(debug_lines(&lines).len(), 1, "a new lease uses a new slot");
}

#[test]
fn diagnostics_clock_high_water_preserves_an_unobserved_deadline() {
    let clock = Arc::new(TestClock::new(BEFORE));
    let (handle, _, lines, subscriber) = clock_stack(clock.clone());
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(
            CaptureRevision(0),
            &[
                timed(principal(1, P), DEADLINE),
                timed(principal(2, Q), AFTER),
            ],
        )
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(debug_lines(&lines).len(), 1);
    clock.set(DEADLINE);
    // The other slot observes the clock, without observing this slot's expiry.
    fire(&handle, Q, "a");
    assert_eq!(debug_lines(&lines).len(), 1);
    assert!(
        !handle.0.state.read().unwrap().entries[0]
            .expired
            .load(Ordering::Relaxed)
    );
    clock.set(BEFORE);
    fire(&handle, P, "a");
    assert!(
        debug_lines(&lines).is_empty(),
        "clock rollback must not revive a deadline passed without a slot observer"
    );
    let snapshot = handle.snapshot();
    assert_eq!(snapshot.counters.expired, 1);
    assert_eq!(snapshot.counters.expiry_suppressed, 1);
    assert_eq!(snapshot.entries.len(), 1);
    assert_eq!(snapshot.entries[0].slot, CaptureSlot(2));
    fire(&handle, Q, "a");
    assert_eq!(
        debug_lines(&lines).len(),
        1,
        "later deadline remains effective"
    );
}

#[test]
fn diagnostics_replace_latches_an_unobserved_deadline() {
    let clock = Arc::new(TestClock::new(BEFORE));
    let (handle, observer, lines, subscriber) = clock_stack(clock.clone());
    let _default = tracing::subscriber::set_default(subscriber);
    let original = timed(principal(1, P), DEADLINE);
    handle
        .replace(CaptureRevision(0), std::slice::from_ref(&original))
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(debug_lines(&lines).len(), 1);
    clock.set(AFTER);
    let reads = clock.reads.load(Ordering::Relaxed);
    handle.replace(CaptureRevision(1), &[original]).unwrap();
    assert_eq!(
        clock.reads.load(Ordering::Relaxed),
        reads + 1,
        "replacement must take exactly one clock reading"
    );
    assert!(
        handle.0.state.read().unwrap().entries[0]
            .expired
            .load(Ordering::Relaxed),
        "replacement must latch a retained slot whose unobserved deadline passed"
    );
    assert_eq!(handle.0.counters.expired.load(Ordering::Relaxed), 1);
    let events = observer.events.lock().unwrap();
    let notices: Vec<_> = events
        .iter()
        .filter(|event| event.0 == "debug_grant_expire")
        .collect();
    assert_eq!(notices.len(), 1);
    assert_eq!(
        notices[0].2.get("capture_revision").map(String::as_str),
        Some("2")
    );
    assert_eq!(notices[0].2.get("lease").map(String::as_str), Some("77"));
    drop(events);
    clock.set(BEFORE);
    fire(&handle, P, "a");
    assert!(debug_lines(&lines).is_empty());
    assert!(handle.snapshot().entries.is_empty());
    assert_eq!(handle.snapshot().counters.expired, 1);
    assert_eq!(
        handle.0.state.read().unwrap().entries[0].allowance(),
        (MAX_LINES - 1, MAX_BYTES - RESERVATION)
    );
}

#[test]
fn diagnostics_all_latched_slots_restore_the_producer_fast_return() {
    let clock = Arc::new(TestClock::new(BEFORE));
    let (handle, _, lines, subscriber) = clock_stack(clock.clone());
    let _default = tracing::subscriber::set_default(subscriber);
    let entries = [
        timed(principal(1, P), DEADLINE),
        timed(principal(2, Q), AFTER),
    ];
    handle.replace(CaptureRevision(0), &entries).unwrap();
    fire(&handle, P, "a");
    assert_eq!(debug_lines(&lines).len(), 1);
    clock.set(DEADLINE);
    fire(&handle, P, "a");
    assert!(
        handle.0.any.load(Ordering::Acquire),
        "one live slot keeps the producer enabled"
    );
    fire(&handle, Q, "a");
    assert_eq!(debug_lines(&lines).len(), 1);
    clock.set(AFTER);
    fire(&handle, Q, "a");
    assert!(debug_lines(&lines).is_empty());
    assert!(
        !handle.0.any.load(Ordering::Acquire),
        "all latched slots disable the producer"
    );
    let visits = handle.0.activity.field_visits.load(Ordering::Relaxed);
    let attempts = handle.0.activity.state_attempts.load(Ordering::Relaxed);
    let reads = clock.reads.load(Ordering::Relaxed);
    clock.set(BEFORE);
    handle.replace(CaptureRevision(1), &entries).unwrap();
    assert!(
        !handle.0.any.load(Ordering::Acquire),
        "retaining expired slots cannot reenable capture"
    );
    for _ in 0..16 {
        fire(&handle, P, "a");
        fire(&handle, Q, "a");
    }
    assert_eq!(
        handle.0.activity.field_visits.load(Ordering::Relaxed),
        visits
    );
    assert_eq!(
        handle.0.activity.state_attempts.load(Ordering::Relaxed),
        attempts
    );
    assert_eq!(clock.reads.load(Ordering::Relaxed), reads + 1);
    assert!(handle.snapshot().entries.is_empty());
    assert_eq!(handle.snapshot().counters.expired, 2);
    handle.replace(CaptureRevision(2), &[]).unwrap();
    assert_eq!(
        handle.replace(CaptureRevision(3), &entries),
        Err(CaptureError::RetiredSlot)
    );
}

#[test]
fn diagnostics_admitted_counts_before_bounded_formatting() {
    let (sink, lines) = crate::sink::tests::queue();
    let (handle, subscriber) = host_subscriber(EnvFilter::new(CEILING), sink.clone(), true);
    let _default = tracing::subscriber::set_default(subscriber);
    handle
        .replace(CaptureRevision(0), &[principal(1, P)])
        .unwrap();
    fire(&handle, P, "a");
    assert_eq!(debug_lines(&lines).len(), 1);
    let state = handle.0.state.read().unwrap();
    let fields = Fields {
        volume: Some(VolumeName::from_bytes(b"a").unwrap()),
        ..Fields::default()
    };
    // Exercise the capped encoder's refusal without expanding the event allowlist.
    handle.capture_guarded(
        P,
        &fields,
        &"x".repeat(DEBUG_LINE_BYTES),
        &state,
        &sink,
        &mut Vec::new(),
    );
    drop(state);
    let snapshot = handle.snapshot();
    assert_eq!(
        snapshot.counters.admitted, 2,
        "scope and budget admission precedes formatting"
    );
    assert_eq!(snapshot.counters.oversize, 1);
    assert_eq!(snapshot.counters.queued, 1);
    assert_eq!(snapshot.entries[0].remaining_lines, MAX_LINES - 2);
    assert!(
        debug_lines(&lines).is_empty(),
        "oversize output must not enqueue"
    );
}

#[test]
fn diagnostics_clock_high_water_is_exact_across_seconds_and_signed_epochs() {
    let high_water = Arc::new(TimeHighWater::default());
    let origin = Timestamp {
        secs: -2,
        nanos: 999_999_999,
    };
    high_water.origin.set(origin).unwrap();
    let next = Timestamp { secs: -1, nanos: 0 };
    assert_eq!(high_water.observe(next), Some(next));
    assert_eq!(high_water.observe(origin), Some(next));
    let later = Timestamp { secs: 0, nanos: 1 };
    assert_eq!(high_water.observe(later), Some(later));
    assert_eq!(high_water.observe(next), Some(later));
    let mut workers = Vec::new();
    for nanos in 0..16 {
        let high_water = high_water.clone();
        workers.push(std::thread::spawn(move || {
            let _ = high_water.observe(Timestamp { secs: 1, nanos });
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(
        high_water.observe(origin),
        Some(Timestamp { secs: 1, nanos: 15 }),
        "concurrent clock readings must retain the greatest timestamp"
    );
    let beyond = Timestamp {
        secs: i64::MAX,
        nanos: 0,
    };
    assert_eq!(
        high_water.observe(beyond),
        None,
        "unrepresentable elapsed time must fail closed"
    );
    assert_eq!(
        high_water.observe(origin),
        None,
        "elapsed-time failure cannot recover on rollback"
    );
}
