// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::admission::Operation;
use crate::debug_grant::{
    ServerIncarnation,
    clock::{ClockFailure, GrantClock, Source},
    reader::{DebugGrantReader, ReaderState, Reason as Refusal},
};
use crate::diagnostics::CaptureHandle;
use crate::protected_dir::tests::{Call, Pause, Phase, Recorder};
use granary_core::secure_random::{EntropyUnavailable, SecureRandom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use tracing_subscriber::EnvFilter;

struct Draw(std::collections::VecDeque<u8>);
impl SecureRandom for Draw {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        assert_eq!(dest.len(), 16);
        dest.fill(self.0.pop_front().ok_or(EntropyUnavailable)?);
        Ok(())
    }
}
fn token(n: u8) -> ServerIncarnation {
    ServerIncarnation::draw(&mut Draw([n].into())).unwrap()
}

struct MutableClock(Mutex<Timestamp>);
impl Clock for MutableClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

struct Host {
    reader: DebugGrantReader<Recorder>,
    clock: Arc<MutableClock>,
    capture: CaptureHandle,
    lines: mpsc::Receiver<Vec<u8>>,
    dispatch: tracing::Dispatch,
    ops: Recorder,
}
impl Host {
    fn new(fx: &Fx, incarnation: ServerIncarnation) -> Self {
        Self::on(fx, incarnation, Recorder::new())
    }
    fn on(fx: &Fx, incarnation: ServerIncarnation, ops: Recorder) -> Self {
        let clock = Arc::new(MutableClock(Mutex::new(NOW.0)));
        let grant_clock = GrantClock::injected(clock.clone());
        let (sink, lines) = crate::sink::tests::queue();
        let (capture, subscriber) = CaptureHandle::subscriber_with_grant_clock(
            EnvFilter::new("info,granary_server::scoped_capture=debug"),
            sink,
            true,
            grant_clock.clone(),
        );
        let reader = DebugGrantReader::open_on(
            ops.clone(),
            &fx.dir,
            true,
            incarnation,
            grant_clock,
            capture.clone(),
        )
        .unwrap();
        Self {
            reader,
            clock,
            capture,
            lines,
            dispatch: tracing::Dispatch::new(subscriber),
            ops,
        }
    }
    fn fire(&self, volume: &str) -> Vec<String> {
        tracing::dispatcher::with_default(&self.dispatch, || {
            self.capture
                .authenticated_request(id(1), &Operation::WriteHint { volume });
        });
        crate::diagnostics::tests::rendered(&self.lines)
            .into_iter()
            .filter(|line| line.contains("\"level\":\"DEBUG\""))
            .collect()
    }
}
fn put(fx: &Fx, grant: &DebugGrant) {
    let next = fx.base.join("next");
    std::fs::write(&next, encode_grant(grant).as_bytes()).unwrap();
    chmod(&next, 0o600);
    std::fs::rename(next, fx.dir.join(NAME)).unwrap();
}
fn grant() -> DebugGrant {
    base(GrantScope::Volume(volume("data")))
}
fn version(grant: &DebugGrant, revision: u64, generation: u64) -> GrantFields {
    let mut fields = grant.fields().clone();
    fields.file_revision = revision;
    fields.grant_generation = generation;
    fields
}
fn changed(fields: GrantFields) -> DebugGrant {
    DebugGrant::new(fields).unwrap()
}
fn disabled(state: ReaderState, reason: Refusal) {
    assert_eq!(state, ReaderState::Disabled(reason));
}

fn block_refresh(host: &Host) -> (Arc<Pause>, ReleaseOnDrop) {
    let pause = Arc::new(Pause::default());
    let hook_pause = pause.clone();
    host.ops.set_hook(move |call, phase| {
        if *call == Call::StatPath && phase == Phase::Before {
            hook_pause.arrive_and_wait();
        }
        Ok(())
    });
    let release = ReleaseOnDrop(pause.clone());
    host.reader.trigger();
    assert!(pause.wait_arrived(Duration::from_secs(5)));
    (pause, release)
}

async fn completed_after(host: &Host, sequence: u64) -> crate::debug_grant::reader::ReaderSnapshot {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = host.reader.snapshot();
            if snapshot.sequence > sequence && host.reader.joins_in_flight().is_none() {
                break snapshot;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn debug_grant_reader_restart_rejects_unchanged_bytes_for_second_secure_incarnation() {
    let fx = Fx::new();
    let mut draws = Draw([0x42, 9].into());
    let first_token = ServerIncarnation::draw(&mut draws).unwrap();
    put(&fx, &grant());
    let bytes = fx.bytes().unwrap();
    let first = Host::new(&fx, first_token);
    assert_eq!(first.reader.snapshot().state, ReaderState::Unread);
    assert_eq!(first.reader.refresh().await.state, ReaderState::Applied);
    assert_eq!(
        first.fire("data").len(),
        1,
        "the known producer captures in the first incarnation"
    );
    let second = Host::new(&fx, ServerIncarnation::draw(&mut draws).unwrap());
    let snapshot = second.reader.refresh().await;
    disabled(snapshot.state, Refusal::StaleIncarnation);
    assert_eq!(snapshot.incarnation, Incarnation::from_bytes([9; 16]));
    assert_eq!(
        snapshot.observed.unwrap().fields().incarnation,
        incarnation()
    );
    assert_eq!(Refusal::StaleIncarnation.as_str(), "stale-incarnation");
    assert!(second.fire("data").is_empty());
    assert_eq!(
        fx.bytes().unwrap(),
        bytes,
        "the reader never rewrites stale bytes"
    );
}

#[tokio::test]
async fn debug_grant_reader_prestaged_file_before_secure_draw_is_refused() {
    let fx = Fx::new();
    let mut fields = grant().fields().clone();
    fields.incarnation = Incarnation::from_bytes([9; 16]);
    put(&fx, &changed(fields));
    let bytes = fx.bytes();
    let host = Host::new(&fx, token(0x42));
    disabled(host.reader.refresh().await.state, Refusal::StaleIncarnation);
    assert!(host.fire("data").is_empty());
    assert_eq!(fx.bytes(), bytes);
}

#[tokio::test]
async fn debug_grant_reader_initial_missing_is_disabled_without_retirement() {
    let fx = Fx::new();
    let host = Host::new(&fx, token(0x42));
    disabled(host.reader.refresh().await.state, Refusal::Missing);
    assert_eq!(host.reader.snapshot().counters.retirements, 0);
    put(&fx, &grant());
    assert_eq!(host.reader.refresh().await.state, ReaderState::Applied);
    assert_eq!(host.fire("data").len(), 1);
}

#[tokio::test]
async fn debug_grant_reader_cached_verdict_and_unchanged_bytes_do_not_replace() {
    let fx = Fx::new();
    put(&fx, &grant());
    let host = Host::new(&fx, token(0x42));
    let applied = host.reader.refresh().await;
    host.ops.clear_calls();
    assert_eq!(host.fire("data").len(), 1);
    let unchanged = host.reader.refresh().await;
    assert_eq!(unchanged.capture_revision, applied.capture_revision);
    assert_eq!(unchanged.accepted.unwrap().fields(), grant().fields());
    assert_eq!(unchanged.counters.applications, 1);
    assert_eq!(unchanged.counters.reloads, 1);
    assert_eq!(unchanged.sequence, 2);
    assert!(
        !host
            .ops
            .calls()
            .iter()
            .any(|c| matches!(c, Call::OpenReadAt(_) | Call::ReadAt))
    );
    assert_eq!(host.capture.snapshot().entries[0].remaining_lines, 49);
}

#[tokio::test]
async fn debug_grant_reader_future_issued_thirty_seconds_accepts_thirty_one_refuses() {
    for (ahead, accepts) in [(30, true), (31, false)] {
        let fx = Fx::new();
        let mut fields = grant().fields().clone();
        fields.issued_at.secs += ahead;
        let candidate = changed(fields);
        put(&fx, &candidate);
        let host = Host::new(&fx, token(0x42));
        let snapshot = host.reader.refresh().await;
        if accepts {
            assert_eq!(snapshot.state, ReaderState::Applied);
            assert_eq!(host.fire("data").len(), 1);
        } else {
            disabled(snapshot.state, Refusal::FutureIssued);
            assert_eq!(snapshot.high_revision, candidate.fields().file_revision);
            assert_eq!(
                snapshot.high_generation,
                candidate.fields().grant_generation
            );
            assert!(host.fire("data").is_empty());
        }
    }
}

#[tokio::test]
async fn debug_grant_reader_future_issued_status_preserves_bounded_observed_lead() {
    let cases = [
        (
            NOW.0,
            Timestamp {
                secs: 131,
                nanos: 123,
            },
            grant().fields().expires_at,
            31,
            "retired-generation",
        ),
        (
            NOW.0,
            Timestamp {
                secs: 130,
                nanos: 124,
            },
            grant().fields().expires_at,
            31,
            "retired-generation",
        ),
        (
            Timestamp {
                secs: i64::MIN,
                nanos: 0,
            },
            Timestamp {
                secs: i64::MAX,
                nanos: 1,
            },
            Timestamp {
                secs: i64::MAX,
                nanos: 2,
            },
            u64::MAX,
            "clock-overflow",
        ),
    ];
    let mut count = 0;
    for (now, issued_at, expires_at, lead, next_reason) in cases {
        let fx = Fx::new();
        let mut fields = grant().fields().clone();
        fields.issued_at = issued_at;
        fields.expires_at = expires_at;
        put(&fx, &changed(fields));
        let host = Host::new(&fx, token(0x42));
        *host.clock.0.lock().unwrap() = now;
        let _refused = host.reader.refresh().await;
        let status = host.reader.observation();
        assert_eq!(
            (
                status.reason,
                status.future_issued_lead_secs,
                status.effective
            ),
            (Some("future-issued"), Some(lead), None),
            "local status must report bounded lead measured at refusal: now={now:?}, issued_at={issued_at:?}"
        );
        *host.clock.0.lock().unwrap() = issued_at;
        host.ops.clear_calls();
        assert_eq!(
            host.reader.observation().future_issued_lead_secs,
            Some(lead)
        );
        assert!(
            host.ops.calls().is_empty(),
            "cached lead must perform no I/O"
        );
        let _retired = host.reader.refresh().await;
        let status = host.reader.observation();
        assert_eq!(
            (
                status.reason,
                status.future_issued_lead_secs,
                status.effective
            ),
            (Some(next_reason), None, None),
            "a different verdict must clear the previous refusal's lead"
        );
        count += 1;
    }
    assert_eq!(
        count, 3,
        "integer, fractional and saturating lead cases must run"
    );
    let fx = Fx::new();
    let mut fields = grant().fields().clone();
    fields.issued_at.secs += 30;
    put(&fx, &changed(fields));
    let host = Host::new(&fx, token(0x42));
    let _applied = host.reader.refresh().await;
    let status = host.reader.observation();
    assert_eq!(
        (
            status.state,
            status.future_issued_lead_secs,
            host.fire("data").len()
        ),
        ("applied", None, 1)
    );
}

#[tokio::test]
async fn debug_grant_reader_future_lower_generation_retires_high_water_and_reissue_applies() {
    let fx = Fx::new();
    let original = grant(); // Revision 4, generation 2.
    put(&fx, &original);
    let host = Host::new(&fx, token(0x42));
    assert_eq!(
        (host.reader.refresh().await.state, host.fire("data").len()),
        (ReaderState::Applied, 1)
    );
    let mut fields = version(&original, 5, 1);
    fields.issued_at.secs += 31;
    put(&fx, &changed(fields));
    let refused = host.reader.refresh().await;
    assert_eq!(
        (
            refused.state,
            refused.high_generation,
            refused.retired_generation,
            host.fire("data").len()
        ),
        (ReaderState::Disabled(Refusal::FutureIssued), 2, 2, 0),
        "lower-generation future-issued evidence must retire the applied high-water generation"
    );
    put(&fx, &changed(version(&original, 6, 2)));
    let restored = host.reader.refresh().await;
    assert_eq!(
        (
            restored.state,
            restored.retired_generation,
            host.fire("data").len()
        ),
        (ReaderState::Disabled(Refusal::Retired), 2, 0),
        "a higher revision must not resurrect the retired generation"
    );
    let _revoked = mutate_on(
        &NixOps,
        &fx.dir,
        OPTIONS,
        expected(6),
        &Mutation::Revoke { generation: 2 },
        &NOW,
    )
    .unwrap();
    let reissued = mutate_on(
        &NixOps,
        &fx.dir,
        OPTIONS,
        expected(7),
        &issue(original.fields().scope.clone()),
        &NOW,
    )
    .unwrap();
    assert_eq!(
        (
            reissued.fields().file_revision,
            reissued.fields().grant_generation
        ),
        (8, 3)
    );
    let applied = host.reader.refresh().await;
    assert_eq!(
        (
            applied.state,
            applied.high_generation,
            applied.retired_generation,
            host.fire("data").len()
        ),
        (ReaderState::Applied, 3, 2, 1),
        "the real verb's higher revision and generation must recover capture"
    );
}

#[tokio::test]
async fn debug_grant_reader_forward_step_wait_exceeds_duration_but_revocation_recovers() {
    let mut count = 0;
    for duration in [1, 900] {
        let fx = Fx::new();
        put(&fx, &grant());
        let host = Host::new(&fx, token(0x42));
        assert_eq!(host.reader.refresh().await.state, ReaderState::Applied);
        let stepped = Fixed(Timestamp {
            secs: 3700,
            nanos: 123,
        });
        let mut mutation = issue(grant().fields().scope.clone());
        if let Mutation::Issue(ref mut issue) = mutation {
            issue.duration = duration;
        }
        let future =
            mutate_on(&NixOps, &fx.dir, OPTIONS, expected(4), &mutation, &stepped).unwrap();
        assert_eq!(
            (
                future.fields().file_revision,
                future.fields().grant_generation
            ),
            (5, 3)
        );
        disabled(host.reader.refresh().await.state, Refusal::FutureIssued);
        // Undo the 3600-second step, then wait the maximum grant duration.
        let after_wait = Fixed(Timestamp {
            secs: 1000,
            nanos: 123,
        });
        let result = mutate_on(
            &NixOps,
            &fx.dir,
            OPTIONS,
            expected(5),
            &mutation,
            &after_wait,
        );
        assert!(
            matches!(result, Err(Error::Refused("live-grant"))),
            "after waiting 900 seconds, duration={duration}, result={result:?}"
        );
        let _revoked = mutate_on(
            &NixOps,
            &fx.dir,
            OPTIONS,
            expected(5),
            &Mutation::Revoke { generation: 3 },
            &after_wait,
        )
        .unwrap();
        let reissued = mutate_on(
            &NixOps,
            &fx.dir,
            OPTIONS,
            expected(6),
            &mutation,
            &after_wait,
        )
        .unwrap();
        assert_eq!(
            (
                reissued.fields().file_revision,
                reissued.fields().grant_generation
            ),
            (7, 4)
        );
        *host.clock.0.lock().unwrap() = after_wait.0;
        assert_eq!(
            (host.reader.refresh().await.state, host.fire("data").len()),
            (ReaderState::Applied, 1)
        );
        count += 1;
    }
    assert_eq!(
        count, 2,
        "short and maximum-duration publication cases must run"
    );
}

#[tokio::test]
async fn debug_grant_reader_already_expired_refuses_at_exact_boundary() {
    let fx = Fx::new();
    let g = grant();
    put(&fx, &g);
    let host = Host::new(&fx, token(0x42));
    *host.clock.0.lock().unwrap() = g.fields().expires_at;
    disabled(host.reader.refresh().await.state, Refusal::Expired);
    assert!(host.fire("data").is_empty());
    assert_eq!(host.reader.snapshot().counters.applications, 0);
}

#[tokio::test]
async fn debug_grant_reader_first_seen_expired_tombstone_records_history_before_time_refusal() {
    for revoked in [true, false] {
        let fx = Fx::new();
        let original = grant(); // Issue revision 4, generation 2, expiry 700.
        put(&fx, &original);
        let mut fields = version(&original, 5, 2);
        fields.action = GrantAction::Narrow;
        fields.expires_at.secs = 200;
        let narrowed = changed(fields);
        put(&fx, &narrowed);
        let revision = if revoked {
            let mut fields = version(&narrowed, 6, 2);
            fields.action = GrantAction::Revoke;
            put(&fx, &changed(fields));
            6
        } else {
            5
        };
        let host = Host::new(&fx, token(0x42));
        host.clock.0.lock().unwrap().secs = 201;
        let first = host.reader.refresh().await;
        assert_eq!(
            first.high_revision, revision,
            "expired current-incarnation evidence must record its revision"
        );
        assert_eq!(first.high_generation, 2);
        assert_eq!(first.retired_generation, 2);
        disabled(
            first.state,
            if revoked {
                Refusal::Revoked
            } else {
                Refusal::Expired
            },
        );
        assert!(host.fire("data").is_empty());
        put(&fx, &original);
        let restored = host.reader.refresh().await;
        assert!(
            matches!(
                restored.state,
                ReaderState::Disabled(Refusal::Rollback | Refusal::Retired)
            ),
            "restored pre-narrowing bytes must stay disabled"
        );
        assert!(host.fire("data").is_empty());
        assert_eq!(restored.counters.applications, 0);
        assert_eq!(restored.high_revision, revision);
    }
}

#[tokio::test]
async fn debug_grant_reader_rollback_and_generation_regression_retire() {
    for (revision, generation) in [(3, 2), (5, 1)] {
        let fx = Fx::new();
        let g = grant();
        put(&fx, &g);
        let host = Host::new(&fx, token(0x42));
        assert_eq!(host.reader.refresh().await.state, ReaderState::Applied);
        put(&fx, &changed(version(&g, revision, generation)));
        disabled(host.reader.refresh().await.state, Refusal::Rollback);
        assert!(host.fire("data").is_empty());
        put(&fx, &g);
        assert!(matches!(
            host.reader.refresh().await.state,
            ReaderState::Disabled(Refusal::Retired | Refusal::Rollback)
        ));
    }
}

#[tokio::test]
async fn debug_grant_reader_equal_revision_different_bytes_refuses() {
    let fx = Fx::new();
    let g = grant();
    put(&fx, &g);
    let host = Host::new(&fx, token(0x42));
    assert_eq!(host.reader.refresh().await.state, ReaderState::Applied);
    let mut fields = g.fields().clone();
    fields.reason = Reason::from_bytes(b"other").unwrap();
    put(&fx, &changed(fields));
    disabled(host.reader.refresh().await.state, Refusal::RevisionConflict);
    assert!(host.fire("data").is_empty());
}

#[tokio::test]
async fn debug_grant_reader_every_later_version_must_be_a_subset() {
    for guard in ["scope", "expiry", "lines", "bytes"] {
        let fx = Fx::new();
        let g = grant();
        put(&fx, &g);
        let host = Host::new(&fx, token(0x42));
        assert_eq!(host.reader.refresh().await.state, ReaderState::Applied);
        let mut fields = version(&g, 5, 2);
        fields.action = GrantAction::Narrow;
        match guard {
            "scope" => fields.scope = GrantScope::Volume(volume("other")),
            "expiry" => fields.expires_at.secs += 1,
            "lines" => fields.line_ceiling += 1,
            "bytes" => fields.byte_ceiling += 1,
            _ => unreachable!(),
        }
        put(&fx, &changed(fields));
        disabled(host.reader.refresh().await.state, Refusal::Widening);
        assert!(host.fire("data").is_empty(), "{guard}");
    }
}

#[tokio::test]
async fn debug_grant_reader_first_seen_narrow_and_later_narrow_keep_slot_and_budget() {
    let fx = Fx::new();
    let mut fields = grant().fields().clone();
    fields.action = GrantAction::Narrow;
    let g = changed(fields);
    put(&fx, &g);
    let host = Host::new(&fx, token(0x42));
    let first = host.reader.refresh().await;
    assert_eq!(first.state, ReaderState::Applied);
    assert_eq!(host.fire("data").len(), 1);
    let mut fields = version(&g, 5, 2);
    fields.scope = GrantScope::Conjunction {
        principal: id(1),
        volume: volume("data"),
    };
    fields.line_ceiling = 49;
    fields.byte_ceiling = 49_000;
    fields.expires_at.secs -= 1;
    put(&fx, &changed(fields));
    let second = host.reader.refresh().await;
    assert_eq!(second.state, ReaderState::Applied);
    assert_eq!(second.slot, first.slot);
    assert_eq!(host.capture.snapshot().entries[0].remaining_lines, 49);
    assert_eq!(host.fire("other").len(), 0);
    assert_eq!(host.fire("data").len(), 1);
    assert_eq!(host.capture.snapshot().entries[0].remaining_lines, 48);
    let fields = version(&g, 6, 3);
    put(&fx, &changed(fields));
    let third = host.reader.refresh().await;
    assert_eq!(third.state, ReaderState::Applied);
    assert!(third.slot > second.slot);
    assert_eq!(third.high_revision, 6);
    assert_eq!(third.high_generation, 3);
}

#[tokio::test]
async fn debug_grant_reader_content_evidence_then_restoration_never_resets_budget() {
    for guard in ["corrupt", "missing", "unprotected", "stale", "revoked"] {
        let fx = Fx::new();
        let g = grant();
        put(&fx, &g);
        let host = Host::new(&fx, token(0x42));
        let first = host.reader.refresh().await;
        assert_eq!(first.state, ReaderState::Applied);
        assert_eq!(host.fire("data").len(), 1);
        let refusal = match guard {
            "corrupt" => {
                fx.put_bytes(b"corrupt");
                Refusal::Corrupt
            }
            "missing" => {
                std::fs::remove_file(fx.dir.join(NAME)).unwrap();
                Refusal::Missing
            }
            "unprotected" => {
                chmod(&fx.dir.join(NAME), 0o640);
                Refusal::Unprotected
            }
            "stale" => {
                let mut f = version(&g, 5, 2);
                f.incarnation = Incarnation::from_bytes([9; 16]);
                put(&fx, &changed(f));
                Refusal::StaleIncarnation
            }
            "revoked" => {
                let mut f = version(&g, 5, 2);
                f.action = GrantAction::Revoke;
                put(&fx, &changed(f));
                Refusal::Revoked
            }
            _ => unreachable!(),
        };
        disabled(host.reader.refresh().await.state, refusal);
        assert!(host.fire("data").is_empty(), "{guard}");
        put(&fx, &g);
        let restored = host.reader.refresh().await;
        assert!(
            matches!(
                restored.state,
                ReaderState::Disabled(Refusal::Retired | Refusal::Rollback)
            ),
            "{guard}: {:?}",
            restored.state
        );
        assert!(host.fire("data").is_empty());
        assert_eq!(restored.counters.applications, 1);
        assert_eq!(restored.counters.retirements, 1);
        assert_eq!(restored.retired_generation, 2);
        put(&fx, &changed(version(&g, 6, 3)));
        let recovered = host.reader.refresh().await;
        assert_eq!(recovered.state, ReaderState::Applied);
        assert!(recovered.slot > first.slot);
        assert_eq!(host.fire("data").len(), 1);
    }
}

#[tokio::test]
async fn debug_grant_reader_eio_disables_then_recovers_same_slot_without_retiring() {
    let fx = Fx::new();
    let g = grant();
    put(&fx, &g);
    let host = Host::new(&fx, token(0x42));
    let first = host.reader.refresh().await;
    assert_eq!(first.state, ReaderState::Applied);
    assert_eq!(host.fire("data").len(), 1);
    let budget = host.capture.snapshot().entries[0].remaining_lines;
    put(&fx, &g);
    let fired = AtomicBool::new(false);
    host.ops.set_hook(move |call, phase| {
        if *call == Call::ReadAt && phase == Phase::Before && !fired.swap(true, Ordering::SeqCst) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(())
    });
    let failed = host.reader.refresh().await;
    disabled(failed.state, Refusal::Unreadable);
    assert!(host.fire("data").is_empty());
    assert!(host.capture.snapshot().entries.is_empty());
    assert_eq!(failed.counters.retirements, 0);
    let recovered = host.reader.refresh().await;
    assert_eq!(recovered.state, ReaderState::Applied);
    assert_eq!(recovered.slot, first.slot);
    assert_eq!(recovered.counters.unreadable, 1);
    assert_eq!(host.capture.snapshot().entries[0].remaining_lines, budget);
    assert_eq!(host.fire("data").len(), 1);
    assert_eq!(
        host.capture.snapshot().entries[0].remaining_lines,
        budget - 1
    );
}

#[tokio::test]
async fn debug_grant_reader_expiry_precedes_failed_clock_at_latch_time() {
    struct FailsAfter(Mutex<u64>);
    impl Source for FailsAfter {
        fn read(&self) -> Result<Timestamp, ClockFailure> {
            let mut n = self.0.lock().unwrap();
            *n += 1;
            if *n == 1 {
                Ok(Timestamp {
                    secs: 700,
                    nanos: 123,
                })
            } else {
                Err(ClockFailure::Source)
            }
        }
    }
    let fx = Fx::new();
    put(&fx, &grant());
    let clock = GrantClock::from_source(Box::new(FailsAfter(Mutex::new(0))));
    let _expiry = clock.now();
    let _failure = clock.now();
    assert_eq!(clock.failure(), Some(ClockFailure::Source));
    let (sink, _) = crate::sink::tests::queue();
    let (capture, _) = CaptureHandle::subscriber_with_grant_clock(
        EnvFilter::new("debug"),
        sink,
        true,
        clock.clone(),
    );
    let reader = DebugGrantReader::open(&fx.dir, true, token(0x42), clock, capture).unwrap();
    disabled(reader.refresh().await.state, Refusal::Expired);
}

#[tokio::test]
async fn debug_grant_reader_unsupported_clock_and_host_activation_are_observable() {
    struct Unsupported;
    impl Source for Unsupported {
        fn read(&self) -> Result<Timestamp, ClockFailure> {
            Err(ClockFailure::UnsupportedProfile)
        }
    }
    for unsupported_clock in [true, false] {
        let fx = Fx::new();
        put(&fx, &grant());
        let clock = if unsupported_clock {
            GrantClock::from_source(Box::new(Unsupported))
        } else {
            GrantClock::injected(Arc::new(Fixed(NOW.0)))
        };
        let (sink, _) = crate::sink::tests::queue();
        let ceiling = if unsupported_clock { "debug" } else { "info" };
        let (capture, _) = CaptureHandle::subscriber_with_grant_clock(
            EnvFilter::new(ceiling),
            sink,
            true,
            clock.clone(),
        );
        let reader =
            DebugGrantReader::open(&fx.dir, true, token(0x42), clock, capture.clone()).unwrap();
        let snapshot = reader.refresh().await;
        if unsupported_clock {
            disabled(
                snapshot.state,
                Refusal::Clock(ClockFailure::UnsupportedProfile),
            );
        } else {
            assert!(matches!(
                snapshot.state,
                ReaderState::Disabled(Refusal::Capture(_))
            ));
        }
        assert_eq!(snapshot.counters.applications, 0);
        assert!(capture.snapshot().entries.is_empty());
    }
}

#[tokio::test]
async fn debug_grant_reader_two_second_deadline_suspends_then_resumes_same_slot_and_budget() {
    let fx = Fx::new();
    put(&fx, &grant());
    let host = Host::new(&fx, token(0x42));
    let prior = host.reader.refresh().await;
    assert_eq!(host.fire("data").len(), 1);
    let spent_budget = host.capture.snapshot().entries[0].remaining_lines;
    assert_eq!(spent_budget, 49);
    let pause = Arc::new(Pause::default());
    let hook_pause = pause.clone();
    host.ops.set_hook(move |call, phase| {
        if *call == Call::StatPath && phase == Phase::Before {
            hook_pause.arrive_and_wait();
        }
        Ok(())
    });
    let _release = ReleaseOnDrop(pause.clone());
    host.reader.trigger();
    assert!(pause.wait_arrived(Duration::from_secs(5)));
    // Initial real I/O has completed. The pending refresh is parked before its
    // observation, so virtual time cannot race a slow initial filesystem read.
    tokio::time::pause();
    let reader = host.reader.clone();
    #[expect(
        clippy::disallowed_methods,
        reason = "filesystem deadline fixture runs concurrent waiters on a real runtime, outside simulator execution"
    )]
    let first = tokio::spawn(async move { reader.refresh().await });
    let reader = host.reader.clone();
    #[expect(
        clippy::disallowed_methods,
        reason = "filesystem deadline fixture runs concurrent waiters on a real runtime, outside simulator execution"
    )]
    let second = tokio::spawn(async move { reader.refresh().await });
    tokio::task::yield_now().await;
    assert_eq!(host.reader.joins_in_flight(), Some(2));
    tokio::time::advance(Duration::from_millis(1999)).await;
    assert!(!first.is_finished());
    assert!(!second.is_finished());
    // Tokio rounds timer-wheel wakeups to a millisecond tick.
    tokio::time::advance(Duration::from_millis(2)).await;
    tokio::task::yield_now().await;
    assert!(
        first.is_finished(),
        "first waiter must finish within the deadline tick"
    );
    assert!(
        second.is_finished(),
        "second waiter must finish within the deadline tick"
    );
    let first = first.await.unwrap();
    let second = second.await.unwrap();
    assert_eq!(
        first.state,
        ReaderState::Disabled(Refusal::Stalled),
        "deadline snapshot must report stalled suspension"
    );
    assert_eq!(second.state, first.state);
    assert_eq!(Refusal::Stalled.as_str(), "stalled");
    assert_eq!(second.capture_revision, prior.capture_revision);
    assert_eq!(host.reader.snapshot().counters.stalled, 2);
    assert_eq!(host.reader.snapshot().sequence, prior.sequence);
    assert!(
        host.fire("data").is_empty(),
        "deadline must suspend matching DEBUG capture"
    );
    assert!(host.capture.snapshot().entries.is_empty());
    assert_eq!(first.slot, prior.slot);
    assert_eq!(first.retired_generation, prior.retired_generation);
    assert_eq!(first.counters.retirements, prior.counters.retirements);
    pause.release();
    tokio::time::resume();
    host.ops.set_hook(|_, _| Ok(()));
    // Await the original blocked refresh, without initiating another one that
    // could hide a failure to resume capture on its completion.
    let resumed = completed_after(&host, prior.sequence).await;
    assert_eq!(resumed.state, ReaderState::Applied);
    assert_eq!(resumed.counters.refreshes, prior.counters.refreshes + 1);
    assert_eq!(resumed.slot, prior.slot);
    assert_eq!(resumed.retired_generation, prior.retired_generation);
    assert_eq!(resumed.counters.retirements, prior.counters.retirements);
    assert_eq!(
        host.capture.snapshot().entries[0].remaining_lines,
        spent_budget
    );
    assert_eq!(host.fire("data").len(), 1);
    assert_eq!(
        host.capture.snapshot().entries[0].remaining_lines,
        spent_budget - 1
    );
}

#[tokio::test]
async fn debug_grant_reader_completed_verdict_survives_deadline_before_notifications() {
    let fx = Fx::new();
    put(&fx, &grant());
    let host = Host::new(&fx, token(0x42));
    let pause = Arc::new(Pause::default());
    let release = ReleaseOnDrop(pause.clone());
    host.reader.hold_completion(pause.clone());
    host.reader.trigger();
    assert!(
        pause.wait_arrived(Duration::from_secs(5)),
        "refresh did not reach the applied-verdict notification window"
    );
    let before = host.reader.snapshot();
    let effective = host.reader.observation().effective;
    assert_eq!(
        (before.state, effective.is_some(), host.fire("data").len()),
        (ReaderState::Applied, true, 1),
        "the paused refresh must have applied a real capture before the deadline"
    );
    host.reader.suspend_stalled(before.sequence);
    let after = host.reader.snapshot();
    let effective_after = host.reader.observation().effective;
    assert_eq!(
        (
            after.state,
            effective_after.as_ref().map(|entry| entry.slot),
            after.capture_revision,
            host.fire("data").len()
        ),
        (
            ReaderState::Applied,
            effective.as_ref().map(|entry| entry.slot),
            before.capture_revision,
            1
        ),
        "a late deadline must preserve the completed verdict and effective capture"
    );
    drop(release);
}

#[tokio::test]
async fn debug_grant_reader_concurrent_refresh_awaits_completed_flight_transition_event() {
    let fx = Fx::new();
    put(&fx, &grant());
    let host = Host::new(&fx, token(0x42));
    let pause = Arc::new(Pause::default());
    let release = ReleaseOnDrop(pause.clone());
    host.reader.hold_completion(pause.clone());
    host.reader.trigger();
    assert!(
        pause.wait_arrived(Duration::from_secs(5)),
        "refresh did not reach the applied-verdict notification window"
    );
    let before = host.reader.snapshot();
    let pre_lines = crate::diagnostics::tests::rendered(&host.lines);
    assert_eq!(
        (before.state, before.sequence, pre_lines.len()),
        (ReaderState::Applied, 1, 0),
        "paused flight must have applied its verdict before emitting its transition event: lines={pre_lines:?}"
    );
    let mut refresh = std::pin::pin!(host.reader.refresh());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let done = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(refresh.as_mut().poll(cx).is_ready())
            })
            .await;
            let issue_events = crate::diagnostics::tests::rendered(&host.lines)
                .into_iter()
                .filter(|line| line.contains("\"event\":\"debug_grant_issue\""))
                .count();
            assert_eq!(
                (done, issue_events),
                (false, 0),
                "concurrent refresh must not return before the completed flight emits its transition event"
            );
            if host.reader.joins_in_flight() == Some(1) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("concurrent refresh must join the held flight before release");
    drop(release);
    let after = refresh.await;
    let issue_events = crate::diagnostics::tests::rendered(&host.lines)
        .into_iter()
        .filter(|line| line.contains("\"event\":\"debug_grant_issue\""))
        .count();
    assert_eq!(
        (after.state, after.sequence, issue_events),
        (ReaderState::Applied, 2, 1),
        "concurrent refresh must return only after the first flight's transition event is emitted"
    );
}

#[tokio::test]
async fn debug_grant_reader_obsolete_deadline_cannot_suspend_a_newer_flight() {
    let fx = Fx::new();
    put(&fx, &grant());
    let host = Host::new(&fx, token(0x42));
    let prior = host.reader.refresh().await;
    let (old_pause, _old_release) = block_refresh(&host);
    let old_start = prior.sequence + 1;
    old_pause.release();
    let completed = completed_after(&host, prior.sequence).await;
    assert_eq!(completed.sequence, old_start);
    let (new_pause, _new_release) = block_refresh(&host);
    // Deterministically delay the old waiter's deadline action until a newer
    // flight has registered, after the old flight applied its valid verdict.
    host.reader.suspend_stalled(old_start);
    assert_eq!(
        host.reader.snapshot().state,
        ReaderState::Applied,
        "obsolete deadline must not suspend a newer flight"
    );
    assert_eq!(
        host.fire("data").len(),
        1,
        "obsolete deadline must not suspend a newer flight"
    );
    host.reader.suspend_stalled(completed.sequence + 1);
    disabled(host.reader.snapshot().state, Refusal::Stalled);
    assert!(host.fire("data").is_empty());
    new_pause.release();
    assert_eq!(
        completed_after(&host, completed.sequence).await.state,
        ReaderState::Applied
    );
}

#[tokio::test]
async fn debug_grant_reader_stall_retries_stale_capture_revision_without_retiring() {
    let fx = Fx::new();
    put(&fx, &grant());
    let host = Host::new(&fx, token(0x42));
    let prior = host.reader.refresh().await;
    assert_eq!(host.fire("data").len(), 1);
    let budget = host.capture.snapshot().entries[0].remaining_lines;
    let current = crate::diagnostics::CaptureRevision(prior.capture_revision.0 + 1);
    host.capture.seed_revision(current);
    let (pause, _release) = block_refresh(&host);
    host.reader.suspend_stalled(prior.sequence + 1);
    assert!(
        host.fire("data").is_empty(),
        "stale capture revision must retry suspension"
    );
    let stalled = host.reader.snapshot();
    disabled(stalled.state, Refusal::Stalled);
    assert_eq!(stalled.capture_revision, current);
    assert_eq!(stalled.retired_generation, prior.retired_generation);
    assert_eq!(stalled.counters.retirements, prior.counters.retirements);
    pause.release();
    let resumed = completed_after(&host, prior.sequence).await;
    assert_eq!(resumed.state, ReaderState::Applied);
    assert_eq!(resumed.slot, prior.slot);
    assert_eq!(host.capture.snapshot().entries[0].remaining_lines, budget);
    assert_eq!(host.fire("data").len(), 1);
}

#[tokio::test]
async fn debug_grant_reader_waiter_never_accepts_refresh_started_before_arrival() {
    let fx = Fx::new();
    put(&fx, &grant());
    let host = Host::new(&fx, token(0x42));
    assert_eq!(host.reader.refresh().await.state, ReaderState::Applied);
    let pause = Arc::new(Pause::default());
    let hook_pause = pause.clone();
    let fired = AtomicBool::new(false);
    host.ops.set_hook(move |call, phase| {
        if *call == Call::StatAt(NAME.to_owned())
            && phase == Phase::After
            && !fired.swap(true, Ordering::SeqCst)
        {
            hook_pause.arrive_and_wait();
        }
        Ok(())
    });
    let _release = ReleaseOnDrop(pause.clone());
    host.reader.trigger();
    assert!(pause.wait_arrived(Duration::from_secs(5)));
    std::fs::remove_file(fx.dir.join(NAME)).unwrap();
    let reader = host.reader.clone();
    #[expect(
        clippy::disallowed_methods,
        reason = "filesystem refresh-order fixture requires a late concurrent waiter, outside simulator execution"
    )]
    let late = tokio::spawn(async move { reader.refresh().await });
    tokio::task::yield_now().await;
    assert_eq!(host.reader.joins_in_flight(), Some(1));
    let prior_sequence = host.reader.snapshot().sequence;
    pause.release();
    let snapshot = late.await.unwrap();
    disabled(snapshot.state, Refusal::Missing);
    assert_eq!(
        snapshot.sequence,
        prior_sequence + 2,
        "late waiter must start a subsequent refresh even if the old result also refused"
    );
    assert!(host.fire("data").is_empty());
}

// A failed assertion must release the blocking pool before runtime teardown.
struct ReleaseOnDrop(Arc<Pause>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[tokio::test]
async fn debug_grant_reader_slot_exhaustion_refuses_without_panicking_or_reusing() {
    let fx = Fx::new();
    put(&fx, &grant());
    let host = Host::new(&fx, token(0x42));
    host.reader.seed_last_slot(u64::MAX);
    disabled(host.reader.refresh().await.state, Refusal::SlotOverflow);
    assert!(host.fire("data").is_empty());
    assert_eq!(host.reader.snapshot().counters.applications, 0);
}

#[tokio::test]
async fn debug_grant_reader_clock_rollback_cannot_extend_capture() {
    let fx = Fx::new();
    let g = grant();
    put(&fx, &g);
    let host = Host::new(&fx, token(0x42));
    assert_eq!(host.reader.refresh().await.state, ReaderState::Applied);
    assert_eq!(host.fire("data").len(), 1);
    *host.clock.0.lock().unwrap() = g.fields().expires_at;
    assert!(host.fire("data").is_empty());
    *host.clock.0.lock().unwrap() = NOW.0;
    assert!(
        host.fire("data").is_empty(),
        "a backward step cannot extend the lease"
    );
    assert_eq!(host.capture.snapshot().counters.expired, 1);
    disabled(host.reader.refresh().await.state, Refusal::Expired);
}

#[tokio::test]
async fn debug_grant_reader_first_seen_revocation_retires_unseen_generation() {
    let fx = Fx::new();
    let g = grant();
    let mut fields = g.fields().clone();
    fields.action = GrantAction::Revoke;
    put(&fx, &changed(fields));
    let host = Host::new(&fx, token(0x42));
    disabled(host.reader.refresh().await.state, Refusal::Revoked);
    put(&fx, &g);
    disabled(host.reader.refresh().await.state, Refusal::Retired);
    assert!(host.fire("data").is_empty());
    put(&fx, &changed(version(&g, 5, 3)));
    assert_eq!(host.reader.refresh().await.state, ReaderState::Applied);
    assert_eq!(host.fire("data").len(), 1);
}

#[tokio::test]
async fn debug_grant_reader_directory_replacement_retires_and_latches() {
    let fx = Fx::new();
    put(&fx, &grant());
    let host = Host::new(&fx, token(0x42));
    assert_eq!(host.reader.refresh().await.state, ReaderState::Applied);
    let aside = fx.base.join("aside");
    std::fs::rename(&fx.dir, &aside).unwrap();
    std::fs::create_dir(&fx.dir).unwrap();
    chmod(&fx.dir, 0o700);
    disabled(host.reader.refresh().await.state, Refusal::Directory);
    std::fs::remove_dir(&fx.dir).unwrap();
    std::fs::rename(&aside, &fx.dir).unwrap();
    disabled(host.reader.refresh().await.state, Refusal::Directory);
    assert!(host.fire("data").is_empty());
    assert_eq!(host.reader.snapshot().counters.retirements, 1);
}

#[tokio::test]
async fn debug_grant_reader_directory_stat_eio_is_transient() {
    let fx = Fx::new();
    put(&fx, &grant());
    let host = Host::new(&fx, token(0x42));
    let first = host.reader.refresh().await;
    assert_eq!(first.state, ReaderState::Applied);
    let fired = AtomicBool::new(false);
    host.ops.set_hook(move |call, phase| {
        if *call == Call::StatPath && phase == Phase::Before && !fired.swap(true, Ordering::SeqCst)
        {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(())
    });
    disabled(host.reader.refresh().await.state, Refusal::Directory);
    assert!(host.fire("data").is_empty());
    let recovered = host.reader.refresh().await;
    assert_eq!(recovered.state, ReaderState::Applied);
    assert_eq!(recovered.slot, first.slot);
    assert_eq!(recovered.counters.retirements, 0);
}

#[tokio::test]
async fn debug_grant_reader_new_generation_requires_revision_increase() {
    let fx = Fx::new();
    let g = grant();
    let mut fields = g.fields().clone();
    fields.action = GrantAction::Revoke;
    put(&fx, &changed(fields));
    let host = Host::new(&fx, token(0x42));
    disabled(host.reader.refresh().await.state, Refusal::Revoked);
    put(&fx, &changed(version(&g, 4, 3)));
    disabled(host.reader.refresh().await.state, Refusal::Rollback);
    assert!(host.fire("data").is_empty());
    // The refused generation 3 is now evidence too; recovery uses generation 4.
    put(&fx, &changed(version(&g, 5, 4)));
    assert_eq!(host.reader.refresh().await.state, ReaderState::Applied);
    assert_eq!(host.fire("data").len(), 1);
}

#[tokio::test]
async fn debug_grant_reader_corrupt_verdict_is_cached_until_identity_changes() {
    let fx = Fx::new();
    fx.put_bytes(b"corrupt");
    let host = Host::new(&fx, token(0x42));
    disabled(host.reader.refresh().await.state, Refusal::Corrupt);
    host.ops.clear_calls();
    disabled(host.reader.refresh().await.state, Refusal::Corrupt);
    assert!(
        !host
            .ops
            .calls()
            .iter()
            .any(|call| matches!(call, Call::OpenReadAt(_) | Call::ReadAt))
    );
    assert_eq!(host.reader.snapshot().counters.reloads, 1);
    put(&fx, &grant());
    assert_eq!(host.reader.refresh().await.state, ReaderState::Applied);
    assert_eq!(host.fire("data").len(), 1);
}

#[tokio::test]
async fn debug_grant_reader_content_refusal_disables_even_if_replacement_cannot_advance() {
    let fx = Fx::new();
    put(&fx, &grant());
    let host = Host::new(&fx, token(0x42));
    assert_eq!(host.reader.refresh().await.state, ReaderState::Applied);
    assert_eq!(host.fire("data").len(), 1);
    host.capture
        .seed_revision(crate::diagnostics::CaptureRevision(u64::MAX));
    fx.put_bytes(b"corrupt");
    disabled(
        host.reader.refresh().await.state,
        Refusal::Capture(crate::diagnostics::CaptureError::StaleRevision),
    );
    assert!(host.fire("data").is_empty());
    assert!(host.capture.snapshot().entries.is_empty());
    assert_eq!(host.reader.snapshot().retired_generation, 2);
    put(&fx, &changed(version(&grant(), 6, 3)));
    disabled(
        host.reader.refresh().await.state,
        Refusal::Capture(crate::diagnostics::CaptureError::RevisionOverflow),
    );
    assert!(host.fire("data").is_empty());
}
