// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::Instant;

#[derive(Debug, Default)]
pub(super) struct Probe {
    pub calls: AtomicUsize,
    pub armed: AtomicBool,
    pub entered: AtomicBool,
    pub released: AtomicBool,
    pub synchronous: AtomicBool,
    pub fail: AtomicBool,
}
impl Probe {
    pub(super) fn arm(&self, synchronous: bool) {
        self.entered.store(false, Ordering::SeqCst);
        self.released.store(false, Ordering::SeqCst);
        self.synchronous.store(synchronous, Ordering::SeqCst);
        self.armed.store(true, Ordering::SeqCst);
    }
    fn touched(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "test injects an acknowledged synchronous stall on the dedicated driver thread"
    )]
    async fn append(&self) -> Result<(), LogIoError> {
        self.touched();
        if self.armed.swap(false, Ordering::SeqCst) {
            self.entered.store(true, Ordering::SeqCst);
            if self.synchronous.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_secs(1));
                self.released.store(true, Ordering::SeqCst);
            } else {
                while !self.released.load(Ordering::SeqCst) {
                    yield_once().await;
                }
            }
        }
        if self.fail.load(Ordering::SeqCst) {
            Err(LogIoError::AlreadyExists)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub(super) struct ProbedLog {
    pub inner: Log,
    pub probe: Arc<Probe>,
}
impl DecisionLog for ProbedLog {
    async fn read_marker(&self) -> Result<MarkerRead, LogIoError> {
        self.probe.touched();
        self.inner.read_marker().await
    }
    async fn write_marker(&self, m: &EncodedMarker) -> Result<(), LogIoError> {
        self.probe.touched();
        self.inner.write_marker(m).await
    }
    async fn read(&self, v: &VolumeName) -> Result<Option<Vec<u8>>, LogIoError> {
        self.probe.touched();
        self.inner.read(v).await
    }
    async fn remove_temporary(&self, v: &VolumeName) -> Result<bool, LogIoError> {
        self.probe.touched();
        self.inner.remove_temporary(v).await
    }
    async fn initialise(&self, e: &EncodedEnvelope) -> Result<(), LogIoError> {
        self.probe.touched();
        self.inner.initialise(e).await
    }
    async fn complete_namespace(&self, v: &VolumeName) -> Result<(), LogIoError> {
        self.probe.touched();
        self.inner.complete_namespace(v).await
    }
    async fn append(&self, a: &Append) -> Result<(), LogIoError> {
        self.probe.append().await?;
        self.inner.append(a).await
    }
    async fn truncate(&self, v: &VolumeName, n: u64) -> Result<(), LogIoError> {
        self.probe.touched();
        self.inner.truncate(v, n).await
    }
    async fn resync(&self, v: &VolumeName) -> Result<(), LogIoError> {
        self.probe.touched();
        self.inner.resync(v).await
    }
}

pub(super) fn instrument(
    driver: GatewayDriver,
    probe: Arc<Probe>,
) -> AuthorityDriver<ProbedLog, Store, FixedClock, SimRng, SeededSecureRandom, YieldPause> {
    AuthorityDriver {
        log: ProbedLog {
            inner: driver.log,
            probe,
        },
        store: driver.store,
        clock: driver.clock,
        rng: driver.rng,
        secure_random: driver.secure_random,
        pause: driver.pause,
        gate: driver.gate,
        shared: driver.shared,
        workers: driver.workers,
        end: driver.end,
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "independent harness stopwatch measures status latency, not engine time"
)]
fn stopwatch() -> Instant {
    Instant::now()
}

#[tokio::test]
async fn status_answers_with_driver_blocked() {
    let no_log = vol("no-log");
    let (fx, driver) = Fx::with_inventory(false, &[a(), b()], &[], &[a(), no_log.clone()]).await;
    let probe = Arc::new(Probe::default());
    let driver = instrument(driver, probe.clone());
    let rows = [
        (a(), 200, None),
        (no_log, 404, Some("no-log")),
        (b(), 404, Some("unknown-volume")),
        (c(), 404, Some("unknown-volume")),
    ];
    let run = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(driver.run())
    });
    for (v, s, t) in &rows {
        status_bytes(fx.send(get(v)).await, *s, *t).await;
    }
    probe.arm(true);
    let candidate = good_root(&a(), 1, None, 1);
    let mut submission = pin!(fx.handle.submit(super::super::super::submission(
        &a(),
        1,
        &candidate
    )));
    poll_fn(|cx| {
        assert!(submission.as_mut().poll(cx).is_pending());
        if probe.entered.load(Ordering::SeqCst) {
            Poll::Ready(())
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
    let calls = probe.calls.load(Ordering::SeqCst);
    let store_calls = fx.store.calls.load(Ordering::SeqCst);
    let mut max = Duration::ZERO;
    for n in 0..20 {
        assert!(
            !probe.released.load(Ordering::SeqCst),
            "stall ended before request {n}"
        );
        let (v, s, t) = &rows[n % rows.len()];
        let at = stopwatch();
        let response = tokio::time::timeout(Duration::from_millis(250), fx.send(get(v)))
            .await
            .unwrap();
        let bytes = status_bytes(response, *s, *t).await;
        let elapsed = at.elapsed();
        max = max.max(elapsed);
        assert!(
            elapsed < Duration::from_millis(250),
            "request {n}: {elapsed:?}"
        );
        if *s == 200 {
            let value = codec::decode_status(&bytes).unwrap();
            assert_eq!(value.epoch, Epoch::from_bytes([WORLD_EPOCH; 16]));
            assert_eq!(value.open, None, "decision is still in its log call");
        }
        assert!(
            !probe.released.load(Ordering::SeqCst),
            "request waited on stall"
        );
    }
    assert!(
        max < Duration::from_millis(250),
        "status during an acknowledged 1 s synchronous log stall: N=20, max={max:?}, bound=250 ms, retries=0"
    );
    assert_eq!(probe.calls.load(Ordering::SeqCst), calls);
    assert_eq!(fx.store.calls.load(Ordering::SeqCst), store_calls);
    assert!(matches!(submission.await, Answer::Accepted { .. }));
    fx.handle.stop().await;
    assert_eq!(run.join().unwrap(), RunEnd::Stopped);
}

#[tokio::test]
async fn status_answers_with_store_read_pending() {
    let root = good_root(&a(), 1, None, 1);
    let d = decision_for(&root);
    let (fx, driver) = Fx::with_inventory(
        false,
        &[a()],
        &[d.clone(), attestation(&d)],
        &[a(), vol("no-log")],
    )
    .await;
    fx.log
        .initialise(&encode_envelope(&envelope(&b(), WORLD_EPOCH)))
        .await
        .unwrap();
    fx.store.inner.hold_read(&a(), 1);
    let mut run = spawn_driver(driver);
    while !fx.store.inner.hold_reached() {
        tokio::task::yield_now().await;
    }
    let calls = fx.store.calls.load(Ordering::SeqCst);
    for (v, s, t) in [
        (a(), 200, None),
        (vol("no-log"), 404, Some("no-log")),
        (b(), 404, Some("unknown-volume")),
        (c(), 404, Some("unknown-volume")),
    ] {
        let at = stopwatch();
        let bytes = status_bytes(
            tokio::time::timeout(Duration::from_millis(250), fx.send(get(&v)))
                .await
                .unwrap(),
            s,
            t,
        )
        .await;
        assert!(at.elapsed() < Duration::from_millis(250));
        if s == 200 {
            let value = codec::decode_status(&bytes).unwrap();
            assert!(value.open.is_some());
            assert_eq!(value.head, None, "successful PUT is not head verification");
        }
    }
    assert_eq!(fx.store.calls.load(Ordering::SeqCst), calls);
    fx.handle.inner.shared.stop.request();
    for v in [a(), b()] {
        status_bytes(fx.send(get(&v)).await, 503, Some("stopped")).await;
    }
    fx.store.inner.release();
    fx.handle.stop().await;
    run.join_next().await.unwrap().unwrap();
}
