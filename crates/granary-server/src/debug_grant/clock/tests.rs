// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::admission::Operation;
use crate::diagnostics::tests::entry;
use crate::diagnostics::{CaptureHandle, CaptureRevision, CaptureSelector};
use granary_core::enrollment::PrincipalId;
use std::collections::VecDeque;
use tracing_subscriber::EnvFilter;

struct Script(Mutex<VecDeque<Result<Timestamp, ClockFailure>>>);
impl Source for Script {
    fn read(&self) -> Result<Timestamp, ClockFailure> {
        self.0
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(ClockFailure::Source))
    }
}
fn time(secs: i64) -> Timestamp {
    Timestamp { secs, nanos: 0 }
}
fn scripted(values: impl IntoIterator<Item = Result<Timestamp, ClockFailure>>) -> GrantClock {
    GrantClock::from_source(Box::new(Script(Mutex::new(values.into_iter().collect()))))
}

#[test]
fn debug_grant_clock_source_failure_is_shared_and_permanent() {
    let clock = scripted([Ok(time(100)), Err(ClockFailure::Source), Ok(time(200))]);
    assert_eq!(clock.now(), time(100));
    let clone = clock.clone();
    assert_eq!(clone.now(), time(100));
    assert_eq!(clock.failure(), Some(ClockFailure::Source));
    assert_eq!(clock.now(), time(100));
    assert_eq!(clone.failure(), Some(ClockFailure::Source));
}

#[test]
fn debug_grant_clock_elapsed_overflow_latches_without_saturation() {
    let clock = scripted([Ok(time(0)), Ok(time(i64::MAX)), Ok(time(0))]);
    assert_eq!(clock.now(), time(0));
    assert_eq!(
        clock.now(),
        time(i64::MAX),
        "valid observation remains expiry evidence"
    );
    assert_eq!(clock.failure(), Some(ClockFailure::Overflow));
    assert_eq!(clock.now(), time(i64::MAX));
}

#[test]
fn debug_grant_clock_projection_counts_suspend_and_checks_both_overflows() {
    assert_eq!(
        project(-1, 600_000_000_001),
        Ok(time(600)),
        "all elapsed time, including suspend, advances UTC"
    );
    assert_eq!(project(i128::MAX, 1), Err(ClockFailure::Overflow));
    assert_eq!(
        project(i128::from(i64::MAX) * 1_000_000_000, 1_000_000_000),
        Err(ClockFailure::Overflow)
    );
    assert_eq!(
        project(-1, 0),
        Ok(Timestamp {
            secs: -1,
            nanos: 999_999_999
        })
    );
}

#[test]
fn debug_grant_clock_invalid_timestamp_latches_source_failure() {
    let clock = scripted([
        Ok(Timestamp {
            secs: 100,
            nanos: 1_000_000_000,
        }),
        Ok(time(100)),
    ]);
    let _invalid = clock.now();
    assert_eq!(clock.failure(), Some(ClockFailure::Source));
    let _later = clock.now();
    assert_eq!(clock.failure(), Some(ClockFailure::Source));
}

fn capture_with(
    values: impl IntoIterator<Item = Result<Timestamp, ClockFailure>>,
) -> (
    GrantClock,
    CaptureHandle,
    std::sync::mpsc::Receiver<Vec<u8>>,
    impl tracing::Subscriber + Send + Sync,
) {
    let clock = scripted(values);
    let (sink, lines) = crate::sink::tests::queue();
    let (capture, subscriber) = CaptureHandle::subscriber_with_grant_clock(
        EnvFilter::new("info,granary_server::scoped_capture=debug"),
        sink,
        true,
        clock.clone(),
    );
    (clock, capture, lines, subscriber)
}

#[test]
fn debug_grant_clock_failure_disables_capture_and_reactivation() {
    let (clock, capture, lines, subscriber) = capture_with([
        Ok(time(100)),
        Ok(time(100)),
        Ok(time(100)),
        Err(ClockFailure::Source),
        Ok(time(100)),
    ]);
    let _default = tracing::subscriber::set_default(subscriber);
    let p = PrincipalId::from_bytes([1; 16]);
    let mut entry = entry(1, CaptureSelector::Principal(p));
    entry.deadline = Some(time(200));
    capture
        .replace(CaptureRevision(0), &[entry.clone()])
        .unwrap();
    capture.authenticated_request(p, &Operation::WriteHint { volume: "a" });
    assert_eq!(
        crate::diagnostics::tests::rendered(&lines).len(),
        1,
        "known DEBUG producer was effective before failure"
    );
    capture.authenticated_request(p, &Operation::WriteHint { volume: "a" });
    assert!(
        crate::diagnostics::tests::rendered(&lines).is_empty(),
        "failed clock must refuse capture"
    );
    assert!(capture.snapshot().entries.is_empty());
    assert_eq!(clock.failure(), Some(ClockFailure::Source));
    assert!(matches!(
        capture.replace(CaptureRevision(1), &[entry]),
        Err(crate::diagnostics::CaptureError::Unsupported(
            crate::diagnostics::CaptureUnsupported::Clock
        ))
    ));
}

#[test]
fn debug_grant_clock_expiry_at_overflow_latch_wins_once() {
    let (clock, capture, lines, subscriber) =
        capture_with([Ok(time(100)), Ok(time(i64::MAX)), Ok(time(100))]);
    let _default = tracing::subscriber::set_default(subscriber);
    let p = PrincipalId::from_bytes([1; 16]);
    let mut entry = entry(1, CaptureSelector::Principal(p));
    entry.deadline = Some(time(200));
    capture.replace(CaptureRevision(0), &[entry]).unwrap();
    capture.authenticated_request(p, &Operation::WriteHint { volume: "a" });
    assert!(
        crate::diagnostics::tests::rendered(&lines)
            .iter()
            .all(|l| !l.contains("\"level\":\"DEBUG\""))
    );
    assert_eq!(clock.failure(), Some(ClockFailure::Overflow));
    assert_eq!(
        capture.snapshot().counters.expired,
        1,
        "expiry observed at clock failure takes precedence"
    );
    assert_eq!(capture.snapshot().counters.expired, 1);
}

#[test]
fn debug_grant_clock_expiry_observed_before_source_failure_wins() {
    let (clock, capture, _lines, _subscriber) =
        capture_with([Ok(time(100)), Ok(time(200)), Err(ClockFailure::Source)]);
    let p = PrincipalId::from_bytes([1; 16]);
    let mut entry = entry(1, CaptureSelector::Principal(p));
    entry.deadline = Some(time(200));
    capture.replace(CaptureRevision(0), &[entry]).unwrap();
    assert_eq!(capture.snapshot().counters.expired, 1);
    let _failed = clock.now();
    assert_eq!(clock.failure(), Some(ClockFailure::Source));
    assert_eq!(capture.snapshot().counters.expired, 1);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn debug_grant_clock_production_profile_is_explicitly_unsupported() {
    let clock = GrantClock::production();
    assert_eq!(clock.failure(), Some(ClockFailure::UnsupportedProfile));
    assert_eq!(
        clock.failure().unwrap().as_str(),
        "unsupported-clock-profile"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn debug_grant_clock_linux_production_uses_boottime_projection() {
    let clock = GrantClock::production();
    let first = clock.now();
    let second = clock.now();
    assert!(second >= first);
    assert_eq!(clock.failure(), None);
}

#[test]
fn debug_grant_clock_rollback_preserves_high_water_across_repeated_reads() {
    let clock = scripted([
        Ok(time(100)),
        Ok(time(150)),
        Ok(time(100)),
        Ok(time(100)),
        Ok(time(120)),
    ]);
    assert_eq!(clock.now(), time(100));
    assert_eq!(clock.now(), time(150));
    for _ in 0..3 {
        assert_eq!(
            clock.now(),
            time(150),
            "repeated backward readings must never lower grant time"
        );
    }
    assert_eq!(clock.failure(), None);
}
