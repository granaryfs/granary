// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real serving constructors and protected grant files with controlled startup
//! entropy/time. Requests pass through the same adapter as the shipped host.

use super::*;
use crate::debug_grant::{DebugGrantHost, reader::DebugGrantReader};
use crate::diagnostics::tests::{Observer, rendered};
use crate::diagnostics::{CaptureHandle, subscriber_with_grant_clock_and_observer};
use crate::protected_dir::tests::{Pause, chmod};
use granary_core::clock::Clock;
use granary_core::debug_grant::{
    DebugGrant, GrantAction, GrantFields, GrantScope, Incarnation, Owner, Reason, encode_grant,
};
use granary_core::secure_random::EntropyUnavailable;
use std::sync::{Mutex, mpsc};
use tracing::{Event, Subscriber};
use tracing_subscriber::{EnvFilter, Layer};

const CEILING: &str = "info,granary_server::scoped_capture=debug";
#[derive(Default)]
struct Draw {
    value: u8,
    calls: u8,
}
impl SecureRandom for Draw {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), EntropyUnavailable> {
        assert_eq!(bytes.len(), 16);
        self.calls += 1;
        bytes.fill(self.value);
        Ok(())
    }
}
struct Time(Mutex<Timestamp>);
impl Clock for Time {
    fn now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}
impl Time {
    fn set(&self, secs: i64) {
        *self.0.lock().unwrap() = Timestamp { secs, nanos: 0 };
    }
}

#[derive(Clone, Default)]
struct Guards(
    Arc<Mutex<Option<(CaptureHandle, DebugGrantReader)>>>,
    Arc<std::sync::atomic::AtomicU64>,
);

#[expect(
    clippy::disallowed_methods,
    reason = "a bounded harness probe lets other threads release guards while an emitting-thread guard remains held throughout its callback"
)]
fn guard_released(mut check: impl FnMut() -> bool) -> bool {
    let started = std::time::Instant::now();
    loop {
        if check() {
            return true;
        }
        if started.elapsed() >= Duration::from_secs(1) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

impl<S: Subscriber> Layer<S> for Guards {
    fn on_event(&self, event: &Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().fields().field("phase").is_none() {
            return;
        }
        let handles = self.0.lock().unwrap().clone();
        if let Some((capture, reader)) = handles {
            assert_eq!(
                (
                    guard_released(|| capture.guard_free()),
                    guard_released(|| reader.guard_free())
                ),
                (true, true),
                "lifecycle event held capture/coordinator guard: {}",
                event.metadata().name()
            );
            self.1.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[test]
fn debug_grant_guard_probe_allows_another_threads_capture_read_guard() {
    let (sink, _lines) = crate::sink::tests::queue();
    let (capture, _subscriber) =
        crate::diagnostics::host_subscriber(EnvFilter::new(CEILING), sink, true);
    std::thread::scope(|scope| {
        let (held, arrived) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let held_capture = capture.clone();
        let holder = scope.spawn(move || {
            held_capture.with_read_guard(|| {
                held.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(5)).unwrap();
            });
        });
        arrived.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut attempts = 0;
        let free = guard_released(|| {
            attempts += 1;
            let free = capture.guard_free();
            if attempts == 1 {
                release.send(()).unwrap();
                assert!(
                    !free,
                    "positive fixture must first observe another thread's read guard"
                );
            }
            free
        });
        assert!(
            free,
            "guard probe refused capture guard held by another thread"
        );
        assert!(
            attempts >= 2,
            "guard probe must retry a nonzero contention case"
        );
        holder.join().unwrap();
    });
}

struct Host {
    service: crate::GrainService<Store>,
    reader: DebugGrantReader,
    clock: Arc<Time>,
    grant_clock: crate::debug_grant::clock::GrantClock,
    observer: Observer,
    lines: mpsc::Receiver<Vec<u8>>,
    dispatch: tracing::Dispatch,
    token: Incarnation,
    guard_checks: Arc<std::sync::atomic::AtomicU64>,
}
impl Host {
    fn new(fx: &Fx, draw: &mut Draw, ceiling: &str, producer: bool) -> Self {
        // Startup is deliberately inside the runtime, as is the production root.
        assert!(tokio::runtime::Handle::try_current().is_ok());
        let clock = Arc::new(Time(Mutex::new(Timestamp {
            secs: 100,
            nanos: 0,
        })));
        let startup = DebugGrantHost::injected(draw, clock.clone()).unwrap();
        let observer = Observer::default();
        let guards = Guards::default();
        let (sink, lines) = crate::sink::tests::queue();
        let (capture, subscriber) = subscriber_with_grant_clock_and_observer(
            EnvFilter::new(ceiling),
            sink.clone(),
            sink,
            producer,
            Some(startup.test_clock()),
            observer.clone().and_then(guards.clone()),
        );
        let dispatch = tracing::Dispatch::new(subscriber);
        let service = crate::GrainService::new(Arc::new(fx.store.clone()), "", 4)
            .with_authority_writes(
                fx.reader.clone(),
                fx.controls.clone(),
                fx.service.refusal_counters().unwrap(),
                &fx.config,
                fx.handle.clone(),
            )
            .with_debug_grants(&startup, &fx.config.enrollment_dir, true, capture.clone())
            .unwrap();
        let reader = service.grant_reader().unwrap();
        *guards.0.lock().unwrap() = Some((capture.clone(), reader.clone()));
        tracing::dispatcher::with_default(&dispatch, || {
            startup.ready("127.0.0.1:1234".parse().unwrap());
        });
        let token = service.debug_grant_observation().unwrap().incarnation;
        Self {
            service,
            reader,
            clock,
            grant_clock: startup.test_clock(),
            observer,
            lines,
            dispatch,
            token,
            guard_checks: guards.1.clone(),
        }
    }
    fn fields(&self) -> GrantFields {
        GrantFields {
            incarnation: self.token,
            file_revision: 1,
            grant_generation: 1,
            action: GrantAction::Issue,
            issuer_uid: 1,
            owner: Owner::from_bytes(b"operator").unwrap(),
            reason: Reason::from_bytes(b"incident").unwrap(),
            issued_at: Timestamp {
                secs: 100,
                nanos: 0,
            },
            expires_at: Timestamp {
                secs: 200,
                nanos: 0,
            },
            scope: GrantScope::Principal(PRINCIPAL),
            line_ceiling: 10,
            byte_ceiling: 10_240,
        }
    }
    fn publish(&self, fx: &Fx, fields: GrantFields) {
        assert_eq!(fields.incarnation, self.token, "fixture publication token");
        let next = fx.dir.join("next");
        std::fs::write(
            &next,
            encode_grant(&DebugGrant::new(fields).unwrap()).as_bytes(),
        )
        .unwrap();
        chmod(&next, 0o600);
        std::fs::rename(next, fx.config.enrollment_dir.join("DEBUG-GRANT")).unwrap();
    }
    async fn write(&self, volume: &str) {
        let _default = tracing::dispatcher::set_default(&self.dispatch);
        let response = self
            .service
            .clone()
            .request_for_test(request(
                "PUT",
                &format!("/volume/{volume}/hint"),
                Full::new(Bytes::from_static(b"00000000000000000001")),
            ))
            .await;
        assert_eq!(response.status().as_u16(), 204, "{response:?}");
    }
    async fn fresh(&self) -> crate::Observation {
        self.service.fresh_observation().await.unwrap()
    }
    fn captures(&self) -> Vec<String> {
        rendered(&self.lines)
            .into_iter()
            .filter(|s| s.contains("request_authenticated"))
            .collect()
    }
    fn events(&self, event: &str) -> usize {
        self.observer
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _, fields)| {
                name == event || fields.get("event").is_some_and(|e| e == event)
            })
            .count()
    }
}
fn assert_effective_events(host: &Host) {
    let events = host.observer.events.lock().unwrap();
    let issue = events
        .iter()
        .find(|(_, _, f)| f.get("event").is_some_and(|s| s == "debug_grant_issue"))
        .unwrap();
    let revoke = events
        .iter()
        .find(|(_, _, f)| f.get("event").is_some_and(|s| s == "debug_grant_revoke"))
        .unwrap();
    assert_eq!(
        (
            issue
                .2
                .get("effective_scope")
                .is_some_and(|s| s.contains("Principal")),
            revoke.2.get("effective_scope").map(String::as_str)
        ),
        (true, Some("None")),
        "only an applied live transition carries effective selectors"
    );
}

struct Release(Arc<Pause>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}
async fn completed(reader: &DebugGrantReader, after: u64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while reader.snapshot().sequence <= after {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn debug_grant_composed_write_awaits_post_arrival_refresh_before_capture() {
    let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
    let mut draw = Draw {
        value: 1,
        ..Draw::default()
    };
    let host = Host::new(&fx, &mut draw, CEILING, true);
    host.publish(&fx, host.fields());
    host.write(a().as_str()).await;
    assert_eq!(
        (host.captures().len(), draw.calls),
        (1, 1),
        "matching producer and one secure draw"
    );
    let before = host.reader.snapshot().sequence;
    let pause = Arc::new(Pause::default());
    let release = Release(pause.clone());
    host.reader.hold_refresh(pause.clone());
    host.reader.trigger();
    assert!(pause.wait_arrived(Duration::from_secs(5)));
    let mut fields = host.fields();
    fields.file_revision = 2;
    fields.action = GrantAction::Revoke;
    host.publish(&fx, fields);
    let _default = tracing::dispatcher::set_default(&host.dispatch);
    let volume = a();
    let mut write = std::pin::pin!(host.write(volume.as_str()));
    // Resolution can itself yield; poll until it has joined the held grant read.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            std::future::poll_fn(|cx| {
                assert!(
                    write.as_mut().poll(cx).is_pending(),
                    "write reached capture without grant refresh"
                );
                Poll::Ready(())
            })
            .await;
            if host.reader.joins_in_flight().is_some_and(|joins| joins > 1) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(release);
    write.await;
    assert_eq!(
        (
            host.captures().len(),
            host.fresh().await.debug_grant.unwrap().reason
        ),
        (0, Some("revoked")),
        "revoked scope must not reach DEBUG callsite"
    );
    assert!(
        host.reader.snapshot().sequence > before + 1,
        "must await a refresh begun after joining prior flight"
    );
    // The reader clears its flight before emitting lifecycle events. A later
    // fresh observation can finish before the earlier subscriber's guard probe.
    tokio::time::timeout(Duration::from_secs(5), async {
        while host.guard_checks.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("issue and revoke guard callbacks must complete");
    assert_eq!(
        (
            host.events("debug_grant_issue"),
            host.events("debug_grant_revoke"),
            host.guard_checks.load(Ordering::SeqCst),
        ),
        (1, 1, 2)
    );
    assert_effective_events(&host);
    assert_eq!(
        host.observer
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, _, f)| f.get("message").is_some_and(|m| m == "served"))
            .count(),
        2
    );
}

#[tokio::test]
async fn debug_grant_composed_anonymous_trigger_cached_and_public_status_ignore_stall() {
    let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
    let host = Host::new(
        &fx,
        &mut Draw {
            value: 1,
            ..Draw::default()
        },
        CEILING,
        true,
    );
    let unread = host.service.observation().unwrap().debug_grant.unwrap();
    assert_eq!(
        (unread.state, unread.reason, unread.observed),
        ("unread", None, None)
    );
    host.publish(&fx, host.fields());
    let pause = Arc::new(Pause::default());
    let release = Release(pause.clone());
    host.reader.hold_refresh(pause.clone());
    let mut req = request("GET", "/volume/vol-a/max-seq", Full::new(Bytes::new()));
    req.extensions_mut().clear();
    let response = tokio::time::timeout(
        Duration::from_millis(250),
        host.service.request_for_test(req),
    )
    .await
    .unwrap();
    assert_eq!(
        response.status().as_u16(),
        404,
        "empty volume read positive control"
    );
    assert!(
        pause.wait_arrived(Duration::from_secs(5)),
        "anonymous request did not trigger grant read"
    );
    let count = (host.reader.observations(), host.reader.joins_in_flight());
    for _ in 0..3 {
        assert_eq!(
            host.service
                .observation()
                .unwrap()
                .debug_grant
                .unwrap()
                .state,
            "unread"
        );
        let response = tokio::time::timeout(
            Duration::from_millis(250),
            host.service.request_for_test(request(
                "GET",
                "/volume/vol-a/status",
                Full::new(Bytes::new()),
            )),
        )
        .await
        .unwrap();
        assert_eq!(response.status().as_u16(), 200);
    }
    assert_eq!(
        (host.reader.observations(), host.reader.joins_in_flight()),
        count,
        "cached observation/public status performed I/O"
    );
    let mut fresh = std::pin::pin!(host.fresh());
    std::future::poll_fn(|cx| {
        assert!(
            fresh.as_mut().poll(cx).is_pending(),
            "fresh local status returned without awaiting grant refresh"
        );
        Poll::Ready(())
    })
    .await;
    assert!(host.reader.joins_in_flight().is_some_and(|joins| joins > 0));
    drop(release);
    assert_eq!(fresh.await.debug_grant.unwrap().state, "applied");
    assert!(
        host.reader.snapshot().sequence > 1,
        "fresh status must await a post-arrival refresh"
    );
    assert_eq!(host.events("debug_grant_issue"), 1);
}

#[tokio::test]
async fn debug_grant_composed_snapshot_expiry_narrowing_and_budget_do_not_refresh() {
    let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
    let host = Host::new(
        &fx,
        &mut Draw {
            value: 1,
            ..Draw::default()
        },
        CEILING,
        true,
    );
    host.publish(&fx, host.fields());
    host.write(a().as_str()).await;
    host.write(b().as_str()).await;
    assert_eq!(host.captures().len(), 2);
    let old = host.fresh().await.debug_grant.unwrap();
    let mut fields = host.fields();
    fields.file_revision = 2;
    fields.action = GrantAction::Narrow;
    fields.scope = GrantScope::Conjunction {
        principal: PRINCIPAL,
        volume: a(),
    };
    host.publish(&fx, fields);
    let narrowed = host.fresh().await.debug_grant.unwrap();
    assert_eq!(
        (
            narrowed.slot,
            narrowed.effective.as_ref().unwrap().remaining_lines
        ),
        (old.slot, 8)
    );
    host.write(b().as_str()).await;
    host.write(a().as_str()).await;
    assert_eq!(
        host.captures().len(),
        1,
        "conjunction must exclude b without replenishing budget"
    );
    let before = host.reader.observations();
    host.clock.set(200);
    let _valid_time = host.grant_clock.now();
    *host.clock.0.lock().unwrap() = Timestamp {
        secs: 200,
        nanos: 1_000_000_000,
    };
    let expired = host.service.observation().unwrap().debug_grant.unwrap();
    assert_eq!(
        (
            expired.effective,
            expired.capture_counters.expired,
            expired.reason,
            host.reader.observations()
        ),
        (None, 1, Some("expired"), before),
        "snapshot must observe exact expiry without file refresh; expiry wins at clock failure"
    );
    assert_eq!(
        host.service
            .observation()
            .unwrap()
            .debug_grant
            .unwrap()
            .capture_counters
            .expired,
        1
    );
    assert_eq!(
        (
            host.events("debug_grant_issue"),
            host.events("debug_grant_narrow"),
            host.events("debug_grant_expire")
        ),
        (1, 1, 1)
    );
    // Refresh must observe expiry before retiring and clearing the prior slot.
    let (fx2, _driver2) = Fx::new(false, &[a()], &[]).await;
    let host2 = Host::new(
        &fx2,
        &mut Draw {
            value: 1,
            ..Draw::default()
        },
        CEILING,
        true,
    );
    host2.publish(&fx2, host2.fields());
    host2.write(a().as_str()).await;
    let mut fields = host2.fields();
    fields.file_revision = 2;
    fields.action = GrantAction::Narrow;
    fields.expires_at.secs = 200;
    host2.clock.set(200);
    host2.publish(&fx2, fields);
    assert!(host2.fresh().await.debug_grant.unwrap().effective.is_none());
    assert_eq!(host2.events("debug_grant_expire"), 1);
}

#[tokio::test]
async fn debug_grant_composed_restart_readiness_stale_and_retirement() {
    let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
    let mut draw = Draw {
        value: 1,
        ..Draw::default()
    };
    let first = Host::new(&fx, &mut draw, CEILING, true);
    first.publish(&fx, first.fields());
    first.write(a().as_str()).await;
    assert_eq!(first.captures().len(), 1);
    let bytes = std::fs::read(fx.config.enrollment_dir.join("DEBUG-GRANT")).unwrap();
    draw.value = 2;
    let second = Host::new(&fx, &mut draw, CEILING, true);
    let unread = second.service.observation().unwrap().debug_grant.unwrap();
    assert_eq!(
        (unread.state, unread.effective, draw.calls),
        ("unread", None, 2)
    );
    second.write(a().as_str()).await;
    let stale = second.fresh().await.debug_grant.unwrap();
    assert_eq!(
        (
            stale.incarnation,
            stale.observed.as_ref().unwrap().fields().incarnation,
            stale.reason
        ),
        (second.token, first.token, Some("stale-incarnation"))
    );
    assert!(second.captures().is_empty());
    assert_eq!(second.events("debug_grant_stale"), 1);
    for (host, value) in [(&first, "01"), (&second, "02")] {
        let events = host.observer.events.lock().unwrap();
        let ready = events
            .iter()
            .find(|(_, _, f)| f.get("message").is_some_and(|s| s == "listening"))
            .unwrap();
        assert_eq!(
            (
                ready.2.get("incarnation").unwrap().as_str(),
                ready.2.get("debug_grant_restart").unwrap().as_str()
            ),
            (
                format!("incarnation:{}", value.repeat(16)).as_str(),
                "reset"
            )
        );
    }
    assert_eq!(
        std::fs::read(fx.config.enrollment_dir.join("DEBUG-GRANT")).unwrap(),
        bytes
    );
    std::fs::remove_file(fx.config.enrollment_dir.join("DEBUG-GRANT")).unwrap();
    assert_eq!(
        first.fresh().await.debug_grant.unwrap().reason,
        Some("missing")
    );
    first.publish(&fx, first.fields());
    first.write(a().as_str()).await;
    assert_eq!(
        (
            first.captures().len(),
            first.fresh().await.debug_grant.unwrap().reason
        ),
        (0, Some("retired-generation"))
    );
}

#[tokio::test]
async fn debug_grant_composed_future_issued_requires_higher_generation() {
    let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
    let host = Host::new(
        &fx,
        &mut Draw {
            value: 1,
            ..Draw::default()
        },
        CEILING,
        true,
    );
    let mut fields = host.fields();
    fields.issued_at.secs = 131;
    host.publish(&fx, fields.clone());
    let refused = host.fresh().await.debug_grant.unwrap();
    assert_eq!(
        (refused.reason, refused.future_issued_lead_secs),
        (Some("future-issued"), Some(31))
    );
    host.clock.set(132);
    host.write(a().as_str()).await;
    let retired = host.fresh().await.debug_grant.unwrap();
    assert_eq!(
        (
            host.captures().len(),
            retired.reason,
            retired.future_issued_lead_secs
        ),
        (0, Some("retired-generation"), None),
        "clock catch-up must not activate an unannounced delayed grant"
    );
    fields.file_revision = 2;
    fields.grant_generation = 2;
    fields.issued_at.secs = 132;
    host.publish(&fx, fields);
    host.write(a().as_str()).await;
    assert_eq!(
        (
            host.captures().len(),
            host.fresh().await.debug_grant.unwrap().state
        ),
        (1, "applied")
    );
}

#[tokio::test]
async fn debug_grant_composed_host_capability_refusal_has_no_matching_output() {
    for (ceiling, producer) in [
        ("info", true),
        ("off", true),
        ("info,granary_server::scoped_capture[scope]=debug", true),
        (CEILING, false),
        (CEILING, true),
    ] {
        let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
        let host = Host::new(
            &fx,
            &mut Draw {
                value: 1,
                ..Draw::default()
            },
            ceiling,
            producer,
        );
        host.publish(&fx, host.fields());
        host.write(a().as_str()).await;
        let snapshot = host.fresh().await.debug_grant.unwrap();
        let supported = ceiling == CEILING && producer;
        assert_eq!(
            (snapshot.state, snapshot.reason, host.captures().len()),
            if supported {
                ("applied", None, 1)
            } else {
                (
                    "disabled",
                    Some(if !producer {
                        "unsupported-producer"
                    } else if ceiling.contains('[') {
                        "unsupported-contextual-ceiling"
                    } else {
                        "unsupported-host-ceiling"
                    }),
                    0,
                )
            },
            "ceiling={ceiling} producer={producer}"
        );
        if ceiling != "off" && !supported {
            assert_eq!(host.events("debug_grant_refuse"), 1);
        }
    }
}

#[tokio::test]
async fn debug_grant_composed_deadline_suspends_without_retirement_or_budget_reset() {
    let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
    let host = Host::new(
        &fx,
        &mut Draw {
            value: 1,
            ..Draw::default()
        },
        CEILING,
        true,
    );
    host.publish(&fx, host.fields());
    host.write(a().as_str()).await;
    assert_eq!(host.captures().len(), 1);
    let prior = host.fresh().await.debug_grant.unwrap();
    let pause = Arc::new(Pause::default());
    let release = Release(pause.clone());
    host.reader.hold_refresh(pause.clone());
    let stalled = host.fresh().await.debug_grant.unwrap();
    assert!(pause.wait_arrived(Duration::from_secs(5)));
    assert_eq!(
        (
            stalled.reason,
            stalled.effective,
            stalled.retired_generation,
            stalled.reader_counters.stalled
        ),
        (Some("stalled"), None, 0, 1)
    );
    // Capture itself stays suspended during the filesystem stall.
    let _default = tracing::dispatcher::set_default(&host.dispatch);
    host.service
        .capture_for_test()
        .unwrap()
        .authenticated_request(
            PRINCIPAL,
            &crate::admission::Operation::WriteHint {
                volume: a().as_str(),
            },
        );
    assert!(host.captures().is_empty());
    drop(release);
    completed(&host.reader, prior.reader_counters.refreshes).await;
    let resumed = host.fresh().await.debug_grant.unwrap();
    assert_eq!(
        (
            resumed.state,
            resumed.slot,
            resumed.effective.as_ref().unwrap().remaining_lines
        ),
        ("applied", prior.slot, 9)
    );
}

#[tokio::test]
async fn debug_grant_composed_corrupt_file_clears_and_replay_cannot_replenish() {
    let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
    let host = Host::new(
        &fx,
        &mut Draw {
            value: 1,
            ..Draw::default()
        },
        CEILING,
        true,
    );
    host.publish(&fx, host.fields());
    host.write(a().as_str()).await;
    assert_eq!(host.captures().len(), 1);
    let next = fx.dir.join("next");
    std::fs::write(&next, b"bad").unwrap();
    chmod(&next, 0o600);
    std::fs::rename(next, fx.config.enrollment_dir.join("DEBUG-GRANT")).unwrap();
    host.write(a().as_str()).await;
    let refused = host.fresh().await.debug_grant.unwrap();
    assert_eq!(
        (
            host.captures().len(),
            refused.reason,
            refused.retired_generation,
            refused.effective
        ),
        (0, Some("corrupt"), 1, None)
    );
    host.publish(&fx, host.fields());
    host.write(a().as_str()).await;
    assert_eq!(
        (
            host.captures().len(),
            host.fresh().await.debug_grant.unwrap().reason
        ),
        (0, Some("retired-generation"))
    );
    let mut fields = host.fields();
    fields.file_revision = 2;
    fields.grant_generation = 2;
    host.publish(&fx, fields);
    host.write(a().as_str()).await;
    assert_eq!(host.captures().len(), 1);
}

#[cfg(target_os = "linux")]
fn issue_args(fx: &Fx) -> Vec<std::ffi::OsString> {
    use std::ffi::OsString;
    let mut args: Vec<OsString> = ["debug-grant", "issue", "--dir"]
        .into_iter()
        .map(Into::into)
        .collect();
    args.push(fx.config.enrollment_dir.as_os_str().to_owned());
    args.extend(
        [
            "--incarnation",
            "incarnation:01010101010101010101010101010101",
            "--expected-revision",
            "0",
            "--volume",
            "vol-a",
            "--duration-secs",
            "60",
            "--lines",
            "5",
            "--bytes",
            "5120",
            "--owner",
            "operator",
            "--reason",
            "incident",
        ]
        .into_iter()
        .map(OsString::from),
    );
    args
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn debug_grant_linux_composed_boottime_publication_and_protection() {
    use std::os::unix::fs::PermissionsExt;
    let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
    let startup = DebugGrantHost::new(&mut Draw {
        value: 1,
        ..Draw::default()
    })
    .unwrap();
    let clock = startup.test_clock();
    assert_eq!(clock.failure(), None, "real CLOCK_BOOTTIME startup profile");
    let (sink, lines) = crate::sink::tests::queue();
    let (capture, subscriber) = startup.subscriber(EnvFilter::new(CEILING), sink, true);
    let _default = tracing::subscriber::set_default(subscriber);
    let service = crate::GrainService::new(Arc::new(fx.store.clone()), "", 4)
        .with_authority_writes(
            fx.reader.clone(),
            fx.controls.clone(),
            fx.service.refusal_counters().unwrap(),
            &fx.config,
            fx.handle.clone(),
        )
        .with_debug_grants(&startup, &fx.config.enrollment_dir, false, capture)
        .unwrap();
    let args = issue_args(&fx);
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(
        crate::run_debug_grant_command_line(&args, &clock, &mut out, &mut err),
        0,
        "{}",
        String::from_utf8_lossy(&err)
    );
    assert!(String::from_utf8(out).unwrap().contains("phase=written"));
    let path = fx.config.enrollment_dir.join("DEBUG-GRANT");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        service
            .fresh_observation()
            .await
            .unwrap()
            .debug_grant
            .unwrap()
            .state,
        "applied"
    );
    let response = service
        .request_for_test(request(
            "PUT",
            "/volume/vol-a/hint",
            Full::new(Bytes::from_static(b"00000000000000000001")),
        ))
        .await;
    assert_eq!(response.status().as_u16(), 204);
    assert_eq!(
        rendered(&lines)
            .iter()
            .filter(|s| s.contains("request_authenticated"))
            .count(),
        1
    );
    chmod(&path, 0o640);
    let refusal = service
        .fresh_observation()
        .await
        .unwrap()
        .debug_grant
        .unwrap();
    assert_eq!(
        (refusal.reason, refusal.effective),
        (Some("unprotected"), None)
    );
    chmod(&path, 0o600);
    assert_eq!(
        service
            .fresh_observation()
            .await
            .unwrap()
            .debug_grant
            .unwrap()
            .reason,
        Some("retired-generation")
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn debug_grant_linux_composed_publication_faults_preserve_exit_uncertainty() {
    use crate::protected_dir::tests::{Call, Phase, Recorder};
    let mut cases = 0;
    for failure in ["write", "file-sync", "rename", "directory-sync", "none"] {
        let (fx, _driver) = Fx::new(false, &[a()], &[]).await;
        let host = Host::new(
            &fx,
            &mut Draw {
                value: 1,
                ..Draw::default()
            },
            CEILING,
            true,
        );
        let recorder = Recorder::new();
        recorder.set_hook(move |call, phase| {
            if phase == Phase::Before
                && match failure {
                    "write" => matches!(call, Call::WriteAt),
                    "file-sync" => matches!(call, Call::SyncFile { .. }),
                    "rename" => matches!(call, Call::RenameAt(_, _)),
                    "directory-sync" => matches!(call, Call::SyncDir { .. }),
                    _ => false,
                }
            {
                Err(std::io::Error::other("injected publication failure"))
            } else {
                Ok(())
            }
        });
        let args = issue_args(&fx);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = crate::debug_grant::cli::run_on(
            &recorder,
            &args,
            host.clock.as_ref(),
            &mut out,
            &mut err,
        );
        let (expected, visible) = match failure {
            "none" => (0, true),
            "directory-sync" => (74, true),
            "rename" => (74, false),
            _ => (65, false),
        };
        let refusal = String::from_utf8(err).unwrap();
        assert_eq!(
            (code, fx.config.enrollment_dir.join("DEBUG-GRANT").exists()),
            (expected, visible),
            "{failure}: {refusal}"
        );
        if code == 65 {
            assert!(
                refusal.contains("refused, nothing written")
                    && refusal.contains("injected publication failure"),
                "{refusal}"
            );
        }
        if code == 74 {
            assert!(
                refusal.contains("publication may be visible; run show before retrying"),
                "{refusal}"
            );
        }
        host.write(a().as_str()).await;
        assert_eq!(
            (
                host.fresh().await.debug_grant.unwrap().state,
                host.captures().len()
            ),
            if visible {
                ("applied", 1)
            } else {
                ("disabled", 0)
            },
            "{failure}"
        );
        cases += 1;
    }
    assert_eq!(
        cases, 5,
        "every durability fault plus positive control must run"
    );
}
