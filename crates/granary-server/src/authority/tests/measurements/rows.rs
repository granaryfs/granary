// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real log syncs and filesystem reads, with independent client timing.

use super::super::super::file_log::{FileLogOn, StdFileOps};
use super::io::{Call, DiskStore, TimedFileOps, TimedStore, Timings};
use super::output::{distribution, status, write};
use super::*;
use granary_core::binstore::BinStore;
use granary_core::enrollment::{ClientSpkiDigest, EnrollmentSet, TenantName, encode_set};
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, body::Bytes};
use std::fmt::Write as _;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize};

#[derive(Debug, Clone, Copy)]
pub(super) struct WallClock;
impl Clock for WallClock {
    #[expect(
        clippy::disallowed_methods,
        reason = "real runtime traffic buckets and certificate validity use the harness clock seam"
    )]
    fn now(&self) -> Timestamp {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        Timestamp {
            secs: i64::try_from(d.as_secs()).unwrap(),
            nanos: d.subsec_nanos(),
        }
    }
}
#[derive(Debug)]
pub(super) struct TimerPause;
impl Pause for TimerPause {
    #[expect(
        clippy::disallowed_methods,
        reason = "real reissue timers are part of the measurement venue"
    )]
    async fn pause(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}
pub(super) type Driver<S = DiskStore, L = FileLogOn<Arc<TimedFileOps>>> =
    AuthorityDriver<L, TimedStore<S>, WallClock, SimRng, SeededSecureRandom, TimerPause>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LogSetup {
    Initialise,
    Deferred,
}

pub(super) const RAISED: &str = "1000000,1000000,1073741824,1073741824,4";
pub(super) const DEFAULT: &str = "46,5,33554432,268435456,4";
pub(super) const POSITIVE_CONTROL: &str = "4,4,33554432,268435456,4";
pub(super) const DEFAULT_SEED: usize = 8;

pub(super) fn seed() -> u64 {
    u64::try_from(number("GRANARY_MEASURE_SEED", DEFAULT_SEED)).unwrap()
}

pub(super) struct Fixture<S = DiskStore> {
    pub service: crate::GrainService<TimedStore<S>>,
    pub handle: AuthorityHandle,
    pub store: TimedStore<S>,
    pub io: Timings,
    pub dir: PathBuf,
    pub config: crate::config::authority::AuthorityConfig,
    pub stalls: Arc<super::io::Stall>,
}

pub(super) fn get(volume: &VolumeName) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(format!("/volume/{}/status", volume.as_str()))
        .body(Full::new(Bytes::new()))
        .unwrap()
}

pub(super) fn publish(volume: &VolumeName, operation: u64, bytes: Vec<u8>) -> Request<Full<Bytes>> {
    publish_in_epoch(
        volume,
        Epoch::from_bytes([WORLD_EPOCH; 16]),
        operation,
        bytes,
    )
}

pub(super) fn publish_in_epoch(
    volume: &VolumeName,
    epoch: Epoch,
    operation: u64,
    bytes: Vec<u8>,
) -> Request<Full<Bytes>> {
    let mut epoch_hex = String::with_capacity(32);
    for byte in epoch.to_bytes() {
        write!(&mut epoch_hex, "{byte:02x}").unwrap();
    }
    let mut r = Request::builder()
        .method("POST")
        .uri(format!("/volume/{}/publish", volume.as_str()))
        .header("content-type", "application/vnd.granary.root.v1")
        .header("granary-operation", format!("{operation:016x}"))
        .header("granary-epoch", epoch_hex)
        .body(Full::new(Bytes::from(bytes)))
        .unwrap();
    r.extensions_mut()
        .insert(granary_net::identity::ConnectionIdentity::Verified(
            ClientSpkiDigest::from_bytes([1; 32]),
        ));
    r
}
impl<S> Fixture<S>
where
    S: RootStore + BinStore + 'static,
{
    #[expect(
        clippy::too_many_lines,
        clippy::too_many_arguments,
        reason = "a harness-owned process suffix and one fixture compose real I/O before timing"
    )]
    pub(super) async fn new<L>(
        dir: &Path,
        backends: [S; 3],
        mut io: Timings,
        decorate_log: impl FnOnce(FileLogOn<Arc<TimedFileOps>>) -> L,
        volumes: &[VolumeName],
        depth: u64,
        collecting: bool,
        tuple: &str,
        enrollment_set: Option<&EnrollmentSet>,
        log_setup: LogSetup,
        digest: ClientSpkiDigest,
        waiver: bool,
        with_intents: bool,
        dispatch_deadline: Option<Duration>,
    ) -> Result<(Self, Driver<S, L>), String>
    where
        L: DecisionLog + Send + Sync + 'static,
    {
        let state = dir.join("state");
        let enrollment = dir.join("enrollment");
        for path in [&state, &enrollment] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|error| format!("measurement fixture directory failed: {error}"))?;
        }
        io.enabled = collecting;
        let stalls = Arc::new(super::io::Stall::default());
        let ops = Arc::new(TimedFileOps {
            inner: StdFileOps::open(&state, waiver).map_err(|error| error.to_string())?,
            timings: io.clone(),
            stalls: stalls.clone(),
        });
        let intents = with_intents
            .then(|| super::super::super::intent::persistence::FileIntent::store(ops.clone()));
        let log = decorate_log(FileLogOn::with_ops(ops));
        let [engine_backend, service_backend, observer_backend] = backends;
        let engine_store = TimedStore {
            inner: engine_backend,
            timings: io.clone(),
        };
        log.write_marker(&encode_marker(&RunMarker::Clean))
            .await
            .map_err(|error| format!("measurement fixture marker failed: {error:?}"))?;
        for volume in volumes {
            if log_setup == LogSetup::Initialise {
                log.initialise(&encode_envelope(&envelope(volume, WORLD_EPOCH)))
                    .await
                    .map_err(|error| format!("measurement fixture log failed: {error:?}"))?;
            }
            let mut parent = None;
            for seq in 1..if volume == volumes.first().unwrap() {
                depth
            } else {
                1
            } {
                let bytes = good_root(volume, seq, parent, 1);
                parent = Some(GrainId::of(&bytes));
                engine_store
                    .inner
                    .put_root(volume.as_str(), seq, bytes)
                    .await
                    .map_err(|error| format!("measurement fixture root failed: {error}"))?;
            }
        }
        let controls = crate::ControlsConfig::parse(tuple)?;
        let seed = seed();
        if let Some(set) = enrollment_set {
            std::fs::write(
                enrollment.join(crate::enrollment::SET_NAME),
                encode_set(set).as_bytes(),
            )
            .map_err(|error| format!("measurement fixture enrollment failed: {error}"))?;
        } else {
            crate::enrollment::mint(
                &enrollment,
                crate::enrollment::VerbOptions {
                    accept_unsupported_filesystem: waiver,
                },
                &TenantName::parse("measure").map_err(|error| error.to_string())?,
                digest,
                &mut secure(1),
            )
            .map_err(|error| error.to_string())?;
        }
        let reader = crate::enrollment::EnrollmentReader::open(&enrollment, waiver)
            .map_err(|error| error.to_string())?;
        let config = crate::config::authority::AuthorityConfig {
            authority_profile: crate::config::authority::AuthorityProfile::SingleProcess,
            state_dir: state,
            enrollment_dir: enrollment,
            client_ca: dir.join("unused-ca"),
            volumes: volumes
                .iter()
                .map(|v| (v.clone(), vec![*publisher().public_key()]))
                .collect(),
            accept_unsupported_filesystem: waiver,
            controls,
        };
        let volume_configs = configs(volumes);
        let volume_configs = if let Some(intents) = intents {
            volume_configs
                .into_iter()
                .map(|config| config.with_intents(intents.clone()))
                .collect()
        } else {
            volume_configs
        };
        let (handle, driver) = start(
            AuthorityParts {
                admission: crate::Admission::chain_fixture(),
                log,
                store: engine_store,
                clock: WallClock,
                rng: rng(seed),
                secure_random: secure(seed),
                pause: TimerPause,
            },
            boot(1),
            volume_configs,
        )
        .await
        .map_err(|error| format!("measurement fixture start failed: {error:?}"))?;
        let service_store = TimedStore {
            inner: service_backend,
            timings: io.clone(),
        };
        let service =
            crate::GrainService::with_deadline(Arc::new(service_store), "", 2, dispatch_deadline)
                .with_authority_writes(
                    reader,
                    Arc::new(crate::PrincipalControls::new(controls, Arc::new(WallClock))),
                    Arc::new(crate::refusals::RefusalCounters::default()),
                    &config,
                    handle.clone(),
                );
        io.take();
        io.counts();
        io.bytes();
        let store = TimedStore {
            inner: observer_backend,
            timings: io.clone(),
        };
        Ok((
            Self {
                service,
                handle,
                store,
                io,
                dir: dir.to_owned(),
                config,
                stalls,
            },
            driver,
        ))
    }
    pub(super) async fn send(&self, r: Request<Full<Bytes>>) -> hyper::Response<Full<Bytes>> {
        self.service.request_for_test(r).await
    }

    pub(super) async fn complete(
        &self,
        v: &VolumeName,
        expected_epoch: Epoch,
    ) -> Result<(), String> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let value = status(self.send(get(v)).await)
                    .await
                    .map_err(str::to_owned)?;
                if value.epoch != expected_epoch {
                    return Err(format!(
                        "publication completion epoch mismatch: observed={:?}, expected={expected_epoch:?}",
                        value.epoch
                    ));
                }
                if value.open.is_none() {
                    return Ok(());
                }
                // A one-millisecond clock-seam pause avoids spinning on status
                // while keeping the completion bound small beside venue I/O.
                TimerPause.pause(Duration::from_millis(1)).await;
            }
        })
        .await
        .map_err(|_| "publication remained open after its durable decision".to_owned())?
    }
}
impl Fixture<DiskStore> {
    #[expect(
        clippy::disallowed_methods,
        reason = "legacy measurement rows retain their runner-owned directory contract"
    )]
    pub(super) async fn local(
        label: &str,
        volumes: &[VolumeName],
        depth: u64,
        collecting: bool,
        tuple: &str,
        digest: ClientSpkiDigest,
    ) -> (Self, Driver) {
        let base = PathBuf::from(
            std::env::var_os("GRANARY_MEASURE_DIR").expect("runner supplies GRANARY_MEASURE_DIR"),
        );
        let dir = base.join(format!("{label}-{}", std::process::id()));
        let backend = dir.join("backend");
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&backend)
            .unwrap();
        for volume in volumes {
            std::fs::create_dir(backend.join(volume.as_str())).unwrap();
        }
        let waiver = std::env::var("GRANARY_MEASURE_SMOKE").as_deref() == Ok("1");
        Self::new(
            &dir,
            [
                DiskStore(backend.clone()),
                DiskStore(backend.clone()),
                DiskStore(backend),
            ],
            Timings::new(262_144),
            std::convert::identity,
            volumes,
            depth,
            collecting,
            tuple,
            None,
            LogSetup::Initialise,
            digest,
            waiver,
            false,
            None,
        )
        .await
        .unwrap()
    }
}

impl<S> Drop for Fixture<S> {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
pub(super) fn number(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .map_or(default, |s| s.parse().unwrap())
}
pub(super) fn fields(row: &str, tuple: &str, n: usize) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("row".into(), row.into()), ("tuple".into(), tuple.into()), ("samples".into(), n.to_string()),
        ("backend".into(), "filesystem-create-only-sync".into()),
        ("first_durable_decision".into(), "client receives decoded accepted/landed answer after decision append".into()),
        ("completed_publication".into(), "after a durable accepted decision, client observes decoded routed status with no open entry; fixture separately checks exact landed root bytes".into()),
    ])
}
pub(super) fn runtime_thread<F, T>(
    future: F,
    dispatch: tracing::Dispatch,
) -> std::thread::JoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::callsite::rebuild_interest_cache();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(future)
        })
    })
}

#[derive(Debug, Default)]
struct PollStats {
    count: std::sync::atomic::AtomicU64,
    ns: std::sync::atomic::AtomicU64,
}
struct Measured<F> {
    future: std::pin::Pin<Box<F>>,
    stats: Arc<PollStats>,
}
impl<F: Future> Future for Measured<F> {
    type Output = F::Output;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        let at = stopwatch();
        let result = this.future.as_mut().poll(cx);
        let ns = u64::try_from(at.elapsed().as_nanos()).unwrap_or(u64::MAX);
        this.stats.ns.fetch_add(ns, Ordering::Relaxed);
        this.stats.count.fetch_add(1, Ordering::Relaxed);
        result
    }
}
fn measured_driver(
    driver: Driver,
    dispatch: tracing::Dispatch,
    stats: Arc<PollStats>,
) -> std::thread::JoinHandle<RunEnd> {
    runtime_thread(
        Measured {
            future: Box::pin(driver.run()),
            stats,
        },
        dispatch,
    )
}

#[tokio::test]
#[ignore = "real filesystem latency; use the measurement runner"]
#[expect(
    clippy::disallowed_methods,
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    reason = "one wall-clock experiment correlates all phases; displayed rates also retain exact raw counts and nanoseconds"
)]
async fn authority_measurement_mixed_publish() {
    let n = number("GRANARY_MEASURE_SAMPLES", 20);
    let depth = number("GRANARY_MEASURE_DEPTH", 1) as u64;
    let count = number("GRANARY_MEASURE_VOLUMES", 1);
    assert!(n > 0 && (1..=64).contains(&count) && depth > 0);
    let collecting = std::env::var("GRANARY_MEASURE_COLLECT").as_deref() != Ok("off");
    let volumes: Vec<_> = (0..count).map(|i| vol(&format!("v{i:03}"))).collect();
    let busy = volumes.first().unwrap();
    let mut span_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut values: BTreeMap<&str, Vec<u128>> = BTreeMap::new();
    let mut gets = 0;
    let mut listed = 0;
    let mut sync_count = 0;
    let mut gateway_calls = 0;
    let mut lost = 0;
    let mut bytes_read = 0;
    let mut poll_count = 0;
    let mut poll_ns = 0;
    let mut idle_count = 0;
    let mut idle_ns = 0;
    let mut elapsed = Duration::ZERO;
    let mut mixed_gets = 0;
    let mut driver_polls = 0;
    let mut driver_ns = 0;
    for i in 0..n {
        let capture = Capture::new(262_144);
        let dispatch = if collecting {
            tracing::Dispatch::new(capture.clone())
        } else {
            tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default())
        };

        let (fx, driver) = Fixture::local(
            &format!("mixed-{i}"),
            &volumes,
            depth,
            collecting,
            RAISED,
            ClientSpkiDigest::from_bytes([1; 32]),
        )
        .await;
        let manifest = granary_core::manifest::encode_dir_leaf(&[]).unwrap();
        let id = GrainId::of(&manifest);
        fx.store
            .inner
            .put_meta(busy.as_str(), &id, manifest.clone())
            .await
            .unwrap();
        let stats = Arc::new(PollStats::default());
        let running = measured_driver(driver, dispatch.clone(), stats.clone());
        let stop_mix = Arc::new(AtomicBool::new(false));
        let mix_reads = Arc::new(AtomicUsize::new(0));
        let stop = stop_mix.clone();
        let reads = mix_reads.clone();
        let service = fx.service.clone();
        let volume = busy.clone();
        let mix = tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let r = Request::builder()
                    .uri(format!("/volume/{}/meta/{id}", volume.as_str()))
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                let response = service.request_for_test(r).await;
                assert_eq!(response.status(), 200, "mixed GET must reach a real object");
                assert_eq!(
                    response.into_body().collect().await.unwrap().to_bytes(),
                    manifest
                );
                reads.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        let seq = depth;
        let parent = if seq == 1 {
            None
        } else {
            Some(GrainId::of(
                &fx.store
                    .inner
                    .get_root(busy.as_str(), seq - 1)
                    .await
                    .unwrap()
                    .unwrap(),
            ))
        };
        let candidate = good_root(busy, seq, parent, 1);
        let owned =
            granary_client::OwnedCandidate::new(busy.as_str(), Arc::from(candidate.clone()))
                .unwrap();
        let request = granary_client::PublishRequest::new(
            busy.as_str(),
            Epoch::from_bytes([WORLD_EPOCH; 16]),
            &(i as u64 + 1).to_be_bytes(),
            owned.clone(),
            vec![owned],
        )
        .unwrap();
        let at = stopwatch();
        let response = tracing::instrument::WithSubscriber::with_subscriber(
            fx.send(publish(busy, i as u64 + 1, candidate.clone())),
            dispatch.clone(),
        )
        .await;
        let code = response.status().as_u16();
        let token = response
            .headers()
            .get("granary-error")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok()),
            Some("application/vnd.granary.authority-answer.v1")
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let answer =
            granary_client::validate_publish_answer(&request, code, token.as_deref(), &body)
                .unwrap();
        assert!(
            matches!(
                answer,
                granary_client::PublishResponse::Accepted(_)
                    | granary_client::PublishResponse::Landed(_)
            ),
            "publish got {code}/{answer:?}"
        );
        let durable = at.elapsed().as_nanos();
        fx.complete(busy, Epoch::from_bytes([WORLD_EPOCH; 16]))
            .await
            .unwrap();
        let completed_at = stopwatch();
        let completed = completed_at.duration_since(at).as_nanos();
        let counts = fx.io.counts();
        stop_mix.store(true, Ordering::Relaxed);
        mix.await.unwrap();
        mixed_gets += mix_reads.load(Ordering::Relaxed);
        fx.handle.stop().await;
        assert_eq!(running.join().unwrap(), RunEnd::Stopped);
        // The status snapshot can precede the driver's final poll return.
        // Join every producer before taking buffers; retain publication-only
        // I/O and phases by timestamps, excluding orderly-stop log syncs.
        let (spans, span_lost) = capture.take();
        let (io, io_lost) = fx.io.take();
        lost += span_lost + io_lost;
        let io: Vec<_> = io
            .into_iter()
            .filter(|s| s.publication_interval(at, completed_at).is_ok())
            .collect();
        assert_eq!(
            fx.store.inner.get_root(busy.as_str(), seq).await.unwrap(),
            Some(candidate),
            "completed publication must have landed the exact candidate"
        );
        let total = |call| {
            io.iter()
                .filter(|s| s.call == call)
                .map(|s| s.elapsed.as_nanos())
                .sum::<u128>()
        };
        let reads = total(Call::Get) + total(Call::List);
        let stores = total(Call::Put);
        let syncs = total(Call::SyncFile) + total(Call::SyncDir);
        gets += counts.get(Call::Get as usize).copied().unwrap_or(0);
        listed += counts.get(Call::List as usize).copied().unwrap_or(0);
        gateway_calls += counts.get(Call::Gateway as usize).copied().unwrap_or(0);
        bytes_read += io
            .iter()
            .filter(|s| s.call == Call::Get)
            .map(|s| s.bytes)
            .sum::<usize>();
        sync_count += counts.get(Call::SyncFile as usize).copied().unwrap_or(0)
            + counts.get(Call::SyncDir as usize).copied().unwrap_or(0);
        assert!(
            io.iter().all(|s| s.success),
            "failed measured seam call: {io:?}"
        );
        let measured: Vec<_> = spans
            .iter()
            .filter(|s| s.start >= at && s.end <= completed_at)
            .collect();
        for span in spans.iter().filter(|s| {
            s.name == "authority_worker_poll" || (s.start >= at && s.end <= completed_at)
        }) {
            *span_counts.entry(span.name).or_default() += 1;
        }
        let phase = |name| {
            measured
                .iter()
                .filter(|s| s.name == name)
                .map(|s| s.end.duration_since(s.start).as_nanos())
                .sum::<u128>()
        };
        let queue = phase("authority_queue") + phase("authority_log_wait");
        let validation = phase("authority_validation");
        let chain = phase("authority_chain");
        let accounted = queue + validation + chain + stores + syncs;
        for (name, value) in [
            ("decision", durable),
            ("publication", completed),
            ("queue", queue),
            ("validation", validation),
            ("chain_reads", reads),
            ("gateway", total(Call::Gateway)),
            ("chain_phase", chain),
            ("store", stores),
            ("sync", syncs),
            (
                "non_store_non_sync",
                completed.saturating_sub(stores + syncs),
            ),
            ("residual", completed.saturating_sub(accounted)),
            ("phase_overlap", accounted.saturating_sub(completed)),
        ] {
            values.entry(name).or_default().push(value);
        }
        for s in spans.iter().filter(|s| s.name == "authority_worker_poll") {
            let ns = s.end.duration_since(s.start).as_nanos();
            poll_count += 1;
            poll_ns += ns;
            if s.slot != 0 {
                idle_count += 1;
                idle_ns += ns;
            }
        }
        elapsed += Duration::from_nanos(u64::try_from(completed).unwrap());
        driver_polls += stats.count.load(Ordering::Relaxed);
        driver_ns += stats.ns.load(Ordering::Relaxed);
    }
    let mut result = fields("mixed_publish", RAISED, n);
    for (name, v) in &values {
        if collecting || matches!(*name, "decision" | "publication") {
            distribution(&mut result, name, v);
        }
    }
    let sync_total: u128 = values.get("sync").unwrap().iter().sum();
    for (key, value) in [
        ("depth", depth.to_string()), ("last_depth", depth.to_string()), ("volumes", count.to_string()),
        ("collection", if collecting { "on" } else { "off" }.into()), ("sample_loss", lost.to_string()),
        ("actual_gets", gets.to_string()), ("client_verification_gets", n.to_string()), ("actual_lists", listed.to_string()), ("gateway_calls", gateway_calls.to_string()), ("get_bytes", if collecting { bytes_read.to_string() } else { "unmeasured".into() }),
        ("sync_count", sync_count.to_string()), ("sync_total_ns", if collecting { sync_total.to_string() } else { "unmeasured".into() }),
        ("chain_read_total_ns", if collecting { values.get("chain_reads").unwrap().iter().sum::<u128>().to_string() } else { "unmeasured".into() }),
        ("elapsed_ns", elapsed.as_nanos().to_string()), ("throughput_per_s", (n as f64 / elapsed.as_secs_f64()).to_string()),
        ("optimistic_serial_sync_ceiling_per_s", if sync_total == 0 { "unmeasured".into() } else {
            (n as f64 * 1e9 / sync_total as f64).to_string() }),
        ("driver_poll_count", driver_polls.to_string()), ("driver_poll_total_ns", driver_ns.to_string()),
        ("driver_poll_window", "driver lifetime, including initial idle poll and orderly stop".into()),
        ("throughput_window", "sum of independent client publication intervals; fixture construction and teardown excluded".into()),
        ("driver_slot_poll_count", if collecting { poll_count.to_string() } else { "unmeasured".into() }), ("driver_slot_poll_total_ns", if collecting { poll_ns.to_string() } else { "unmeasured".into() }),
        ("idle_slot_poll_count", if collecting { idle_count.to_string() } else { "unmeasured".into() }), ("idle_slot_poll_total_ns", if collecting { idle_ns.to_string() } else { "unmeasured".into() }),
        ("mixed_get_count", mixed_gets.to_string()),
        ("binding_tuple", "false".into()),
    ] { result.insert(key.into(), value); }
    for (name, count) in &span_counts {
        result.insert(format!("span_{name}_count"), count.to_string());
    }
    write("mixed_publish", &result);
    if collecting {
        for name in [
            "authority_queue",
            "authority_validation",
            "authority_chain",
            "authority_log_wait",
            "authority_worker_poll",
        ] {
            assert!(
                span_counts.get(name).copied().unwrap_or(0) > 0,
                "missing phase {name}: {span_counts:?}"
            );
        }
    }
    assert!(mixed_gets > 0, "no mixed load occurred");
    assert_eq!(lost, 0, "sample loss prevents phase conclusions");
    if collecting && depth == 1 && std::env::var("GRANARY_MEASURE_SMOKE").as_deref() != Ok("1") {
        assert!(
            super::output::quantile(values.get("non_store_non_sync").unwrap(), 50).unwrap()
                <= 1_000_000,
            "depth-one non-store, non-sync overhead p50 exceeds 1 ms"
        );
    }
}

async fn stall_deadline(
    phase: &str,
    deadline: Duration,
    wait: impl Future<Output = Result<(), String>>,
) -> Result<(), String> {
    tokio::time::timeout(deadline, wait)
        .await
        .unwrap_or_else(|_| {
            Err(format!(
                "log-sync stall {phase} was not observed within {deadline:?}"
            ))
        })
}

async fn check_publish<T: std::fmt::Debug>(
    reached: &AtomicBool,
    publish: &mut tokio::task::JoinHandle<T>,
    phase: &str,
) -> Result<(), String> {
    // Recheck the flag after task completion to avoid mistaking a crossed
    // boundary for a publish that ended before it.
    if publish.is_finished() && !reached.load(Ordering::SeqCst) {
        Err(format!(
            "publish finished before log-sync stall {phase}: {:?}",
            publish.await
        ))
    } else {
        Ok(())
    }
}

async fn wait_for_stall<T: std::fmt::Debug>(
    entered: &AtomicBool,
    publish: &mut tokio::task::JoinHandle<T>,
    deadline: Duration,
) -> Result<(), String> {
    stall_deadline("entry", deadline, async {
        while !entered.load(Ordering::SeqCst) {
            check_publish(entered, publish, "entry").await?;
            tokio::task::yield_now().await;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "the row's runtime task completion and cancellation are the control's subject"
)]
async fn authority_measurement_finished_publish_is_reported_before_stall() {
    let entered = AtomicBool::new(false);
    let mut publish = tokio::spawn(async { Err::<(), _>("log write refused") });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !publish.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("injected publish did not finish");
    // The watchdog bounds the control, independently of the row's deadline.
    let observed = tokio::time::timeout(
        Duration::from_millis(100),
        wait_for_stall(&entered, &mut publish, Duration::from_secs(10)),
    )
    .await;
    assert_eq!(
        (
            observed.map_err(|error| error.to_string()),
            publish.is_finished()
        ),
        (
            Ok(Err(
                "publish finished before log-sync stall entry: Ok(Err(\"log write refused\"))"
                    .into()
            )),
            true
        ),
        "stall wait must report the finished publish instead of exhausting the control watchdog"
    );
}

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    reason = "the row's runtime task completion and cancellation are the control's subject"
)]
async fn authority_measurement_stall_deadline_and_outcome_controls() {
    let mut cases = 0;
    for phase in ["entry", "release"] {
        let reached = AtomicBool::new(true);
        let mut publish = tokio::spawn(std::future::pending::<()>());
        assert_eq!(check_publish(&reached, &mut publish, phase).await, Ok(()));
        assert_eq!(
            stall_deadline(phase, Duration::from_millis(10), async { Ok(()) }).await,
            Ok(())
        );
        let observed = tokio::time::timeout(
            Duration::from_millis(100),
            stall_deadline(phase, Duration::from_millis(10), std::future::pending()),
        )
        .await;
        assert_eq!(
            observed.map_err(|error| error.to_string()),
            Ok(Err(format!(
                "log-sync stall {phase} was not observed within 10ms"
            )))
        );
        publish.abort();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !publish.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled publish did not finish");
        // A reached flag permits the original outcome to remain unconsumed.
        assert_eq!(check_publish(&reached, &mut publish, phase).await, Ok(()));
        reached.store(false, Ordering::SeqCst);
        let error = check_publish(&reached, &mut publish, phase)
            .await
            .unwrap_err();
        assert!(
            error.starts_with(&format!(
                "publish finished before log-sync stall {phase}: Err("
            )),
            "got {error}"
        );
        assert!(error.contains("Cancelled"), "got {error}");
        cases += 1;
    }
    assert_eq!(cases, 2);
    let entered = AtomicBool::new(false);
    let signal = Arc::new(AtomicBool::new(false));
    let target = signal.clone();
    let mut valid = tokio::spawn(async move {
        target.store(true, Ordering::SeqCst);
        std::future::pending::<()>().await;
    });
    assert_eq!(
        wait_for_stall(&signal, &mut valid, Duration::from_millis(100)).await,
        Ok(())
    );
    let observed = tokio::time::timeout(
        Duration::from_millis(100),
        wait_for_stall(&entered, &mut valid, Duration::from_millis(10)),
    )
    .await;
    assert_eq!(
        observed.map_err(|error| error.to_string()),
        Ok(Err(
            "log-sync stall entry was not observed within 10ms".into()
        ))
    );
    valid.abort();
    assert!(valid.await.unwrap_err().is_cancelled());
}

#[tokio::test]
#[ignore = "repeated one-second synchronous stalls; use the measurement runner"]
#[expect(
    clippy::disallowed_methods,
    reason = "independent runtime publish completion is checked while the driver stalls synchronously"
)]
async fn authority_measurement_stalled_routed_status() {
    let repeats = number("GRANARY_MEASURE_STALLS", 3);
    assert!(repeats > 0);
    let v = vol("v000");
    let (fx, driver) = Fixture::local(
        "stall",
        std::slice::from_ref(&v),
        1,
        false,
        RAISED,
        ClientSpkiDigest::from_bytes([1; 32]),
    )
    .await;
    let run = runtime_thread(
        driver.run(),
        tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
    );
    let mut samples = Vec::with_capacity(repeats * 256);
    let mut errors = 0;
    let mut lost = 0;
    for i in 0..repeats {
        let seq = i as u64 + 1;
        let parent = if seq == 1 {
            None
        } else {
            Some(GrainId::of(
                &fx.store
                    .inner
                    .get_root(v.as_str(), seq - 1)
                    .await
                    .unwrap()
                    .unwrap(),
            ))
        };
        fx.stalls.entered.store(false, Ordering::SeqCst);
        fx.stalls.released.store(false, Ordering::SeqCst);
        fx.stalls.armed.store(true, Ordering::SeqCst);
        let service = fx.service.clone();
        let request = publish(&v, seq, good_root(&v, seq, parent, 1));
        let mut publish = tokio::spawn(async move { service.request_for_test(request).await });
        wait_for_stall(&fx.stalls.entered, &mut publish, Duration::from_secs(10))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let stall_start = stopwatch();
        stall_deadline("release", Duration::from_secs(10), async {
            while !fx.stalls.released.load(Ordering::SeqCst) {
                check_publish(&fx.stalls.released, &mut publish, "release").await?;
                let at = stopwatch();
                let response = fx.send(get(&v)).await;
                let success = status(response).await;
                let ns = at.elapsed().as_nanos();
                if success.is_ok() {
                    if samples.len() < samples.capacity() {
                        samples.push(ns);
                    } else {
                        lost += 1;
                    }
                } else {
                    errors += 1;
                }
                TimerPause.pause(Duration::from_millis(5)).await;
            }
            Ok(())
        })
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            stall_start.elapsed() >= Duration::from_millis(900),
            "stall was not observed throughout"
        );
        assert_eq!(publish.await.unwrap().status(), 202);
        fx.complete(&v, Epoch::from_bytes([WORLD_EPOCH; 16]))
            .await
            .unwrap();
    }
    fx.handle.stop().await;
    assert_eq!(run.join().unwrap(), RunEnd::Stopped);
    let mut result = fields("stalled_status", RAISED, samples.len());
    distribution(&mut result, "status", &samples);
    result.insert("status_errors".into(), errors.to_string());
    result.insert("stall_repetitions".into(), repeats.to_string());
    result.insert("injected_stall_ns".into(), "1000000000".into());
    result.insert("sample_loss".into(), lost.to_string());
    write("stalled_status", &result);
    assert_eq!(lost, 0, "status sample buffer overflow");
    assert_eq!(errors, 0, "only successful decoded routed statuses count");
    assert!(
        super::output::quantile(&samples, 99).unwrap() <= 50_000_000,
        "status p99 exceeds 50 ms"
    );
}
