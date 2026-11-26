// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Competing principals on one routed service, with bounded client populations.

use super::output::{distribution, status, write};
use super::rows::{DEFAULT, Fixture, fields, number, runtime_thread};
use super::*;
use granary_core::enrollment::{ClientSpkiDigest, TenantName};
use hyper::Request;
use hyper::body::{Body, Bytes, Frame};
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::task::{Context, Poll};

#[derive(Default)]
struct StallCoverage {
    target: usize,
    active: usize,
    observed_ns: u128,
    covered_ns: u128,
}
impl StallCoverage {
    fn observe(&mut self, at_ns: u128) {
        if self.active >= self.target {
            self.covered_ns += at_ns - self.observed_ns;
        }
        self.observed_ns = at_ns;
    }
    fn enter(&mut self, at_ns: u128) {
        self.observe(at_ns);
        self.active += 1;
    }
    fn leave(&mut self, at_ns: u128) {
        self.observe(at_ns);
        self.active -= 1;
    }
}
struct StallWindow {
    start: Instant,
    duration_ns: u128,
    coverage: Mutex<StallCoverage>,
}
impl StallWindow {
    fn elapsed(&self) -> u128 {
        self.start.elapsed().as_nanos().min(self.duration_ns)
    }
}
struct StallLease {
    seen: AtomicBool,
    window: Arc<StallWindow>,
}
impl Drop for StallLease {
    fn drop(&mut self) {
        if self.seen.load(Ordering::SeqCst) {
            let mut coverage = self.window.coverage.lock().unwrap();
            coverage.leave(self.window.elapsed());
        }
    }
}
struct Parked(Arc<StallLease>);
impl Body for Parked {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if !self.0.seen.swap(true, Ordering::SeqCst) {
            let mut coverage = self.0.window.coverage.lock().unwrap();
            coverage.enter(self.0.window.elapsed());
        }
        Poll::Pending
    }
}

#[derive(Debug, Default)]
struct StallCounts {
    attempts: usize,
    requests: usize,
    rearms: usize,
    cap_refusals: usize,
    unpolled_endings: usize,
}
impl StallCounts {
    fn record(&mut self, polled: bool, status: Option<u16>) {
        self.attempts += 1;
        if polled {
            self.rearms += usize::from(self.requests > 0);
            self.requests += 1;
        } else if status == Some(429) {
            self.cap_refusals += 1;
        } else {
            self.unpolled_endings += 1;
        }
    }
}

fn checked_stalls(
    counts: &StallCounts,
    target: usize,
    covered_ns: u128,
    window_ns: u128,
) -> Result<(), &'static str> {
    if target == 0 || counts.requests < target || covered_ns == 0 || window_ns == 0 {
        return Err("hostile stalled population missing");
    }
    if counts.attempts != counts.requests + counts.cap_refusals + counts.unpolled_endings
        || counts.rearms != counts.requests - target
        || covered_ns > window_ns
    {
        return Err("hostile stalled population mismatch");
    }
    Ok(())
}

#[test]
fn authority_measurement_stalls_require_polled_bodies() {
    let mut valid = StallCounts::default();
    valid.record(true, Some(408));
    valid.record(false, Some(429));
    valid.record(true, None);
    assert_eq!(
        (valid.requests, valid.rearms, valid.cap_refusals),
        (2, 1, 1)
    );
    assert_eq!(checked_stalls(&valid, 1, 10, 20), Ok(()));
    let mut refused = StallCounts::default();
    refused.record(false, Some(429));
    assert_eq!((refused.requests, refused.cap_refusals), (0, 1));
    assert_eq!(
        checked_stalls(&refused, 1, 10, 20),
        Err("hostile stalled population missing")
    );
}

#[test]
fn authority_measurement_stall_rearms_and_coverage_controls() {
    let mut coverage = StallCoverage {
        target: 2,
        ..StallCoverage::default()
    };
    coverage.enter(10);
    coverage.enter(20);
    coverage.leave(40);
    coverage.enter(50);
    coverage.leave(70);
    coverage.leave(80);
    coverage.observe(100);
    assert_eq!((coverage.active, coverage.covered_ns), (0, 40));
    let valid = StallCounts {
        attempts: 5,
        requests: 3,
        rearms: 1,
        cap_refusals: 2,
        unpolled_endings: 0,
    };
    assert_eq!(checked_stalls(&valid, 2, 40, 100), Ok(()));
    let cases = [
        (
            StallCounts {
                requests: 0,
                ..StallCounts::default()
            },
            40,
            "hostile stalled population missing",
        ),
        (
            StallCounts {
                requests: 5,
                ..StallCounts::default()
            },
            40,
            "hostile stalled population mismatch",
        ),
        (
            StallCounts {
                attempts: 5,
                requests: 3,
                rearms: 0,
                cap_refusals: 2,
                unpolled_endings: 0,
            },
            40,
            "hostile stalled population mismatch",
        ),
        (
            StallCounts {
                attempts: 5,
                requests: 3,
                rearms: 1,
                cap_refusals: 2,
                unpolled_endings: 0,
            },
            101,
            "hostile stalled population mismatch",
        ),
    ];
    assert!(!cases.is_empty());
    for (counts, covered, message) in &cases {
        assert_eq!(checked_stalls(counts, 2, *covered, 100), Err(*message));
    }
    assert!(!cases.is_empty(), "stall named refusal cases");
}
fn identity<B>(request: &mut Request<B>, digest: ClientSpkiDigest) {
    request
        .extensions_mut()
        .insert(granary_net::identity::ConnectionIdentity::Verified(digest));
}

fn checked_population(
    a_attempts: usize,
    b_completed: usize,
    b_429: usize,
    b_failures: usize,
    statuses: usize,
    loss: usize,
) -> Result<(), &'static str> {
    if b_429 != 0 {
        return Err("hostile row B produced 429");
    }
    if b_failures != 0 {
        return Err("hostile row B failed");
    }
    if a_attempts == 0 || b_completed == 0 || statuses == 0 {
        return Err("empty hostile population");
    }
    if loss != 0 {
        return Err("hostile sample loss");
    }
    Ok(())
}

fn export_then_check_population(
    export: impl FnOnce(),
    a_attempts: usize,
    b_completed: usize,
    b_429: usize,
    b_failures: usize,
    statuses: usize,
    loss: usize,
) -> Result<(), &'static str> {
    export();
    checked_population(a_attempts, b_completed, b_429, b_failures, statuses, loss)
}

#[test]
fn authority_measurement_failed_population_exports_counters() {
    let cases = [(0, Ok(())), (1, Err("hostile row B produced 429"))];
    assert!(!cases.is_empty());
    for (refused, expected) in cases {
        let mut exported = None;
        let result = export_then_check_population(
            || exported = Some((1, 1, refused, 0, 1, 0)),
            1,
            1,
            refused,
            0,
            1,
            0,
        );
        assert_eq!(
            (exported, result),
            (Some((1, 1, refused, 0, 1, 0)), expected)
        );
    }
}

#[test]
fn authority_measurement_hostile_population_controls() {
    assert_eq!(checked_population(1, 1, 0, 0, 1, 0), Ok(()));
    let cases = [
        ((1, 1, 1, 0, 1, 0), "hostile row B produced 429"),
        ((1, 1, 0, 1, 1, 0), "hostile row B failed"),
        ((0, 1, 0, 0, 1, 0), "empty hostile population"),
        ((1, 0, 0, 0, 1, 0), "empty hostile population"),
        ((1, 1, 0, 0, 0, 0), "empty hostile population"),
        ((1, 1, 0, 0, 1, 1), "hostile sample loss"),
    ];
    assert!(!cases.is_empty());
    for ((a, b, limited, failed, statuses, loss), message) in cases {
        assert_eq!(
            checked_population(a, b, limited, failed, statuses, loss),
            Err(message)
        );
    }
    assert!(!cases.is_empty(), "hostile population named refusal cases");
}

pub(super) fn checked_publish(
    request: &granary_client::PublishRequest,
    code: u16,
    token: Option<&str>,
    media: Option<&str>,
    bytes: &[u8],
) -> Result<(), &'static str> {
    if media != Some("application/vnd.granary.authority-answer.v1") {
        return Err("hostile B publish media mismatch");
    }
    match granary_client::validate_publish_answer(request, code, token, bytes) {
        Ok(
            granary_client::PublishResponse::Accepted(_)
            | granary_client::PublishResponse::Landed(_),
        ) => Ok(()),
        _ => Err("hostile B publish answer invalid"),
    }
}
#[test]
fn authority_measurement_hostile_publish_answer_controls() {
    use granary_core::authority_answer::{Position, PublishAnswer, encode};
    let v = vol("b");
    let bytes = good_root(&v, 1, None, 1);
    let owned = granary_client::OwnedCandidate::new(v.as_str(), Arc::from(bytes)).unwrap();
    let request = granary_client::PublishRequest::new(
        v.as_str(),
        Epoch::from_bytes([WORLD_EPOCH; 16]),
        &1_u64.to_be_bytes(),
        owned.clone(),
        vec![owned.clone()],
    )
    .unwrap();
    let answer = encode(PublishAnswer::Accepted {
        position: Position {
            epoch: request.epoch(),
            entry_seq: 1,
        },
        candidate_id: owned.id(),
    })
    .unwrap();
    let media = Some("application/vnd.granary.authority-answer.v1");
    assert_eq!(checked_publish(&request, 202, None, media, &answer), Ok(()));
    let foreign = encode(PublishAnswer::Accepted {
        position: Position {
            epoch: request.epoch(),
            entry_seq: 1,
        },
        candidate_id: GrainId::of(b"foreign"),
    })
    .unwrap();
    let cases = [
        (
            202,
            None,
            None,
            answer.as_slice(),
            "hostile B publish media mismatch",
        ),
        (
            202,
            None,
            media,
            &[][..],
            "hostile B publish answer invalid",
        ),
        (
            202,
            None,
            media,
            foreign.as_slice(),
            "hostile B publish answer invalid",
        ),
        (
            500,
            Some("internal"),
            media,
            answer.as_slice(),
            "hostile B publish answer invalid",
        ),
    ];
    assert!(!cases.is_empty());
    for (code, token, media, body, message) in cases {
        assert_eq!(
            checked_publish(&request, code, token, media, body),
            Err(message)
        );
    }
    assert!(
        !cases.is_empty(),
        "hostile publish answer named refusal cases"
    );
}

fn cpu_ticks() -> Option<u64> {
    // /proc/self/stat includes all process threads. Split after comm, whose
    // parentheses and spaces cannot be parsed as fixed whitespace fields.
    let text = std::fs::read_to_string("/proc/self/stat").ok()?;
    let (_, rest) = text.rsplit_once(") ")?;
    let fields: Vec<_> = rest.split_whitespace().collect();
    fields
        .get(11)?
        .parse::<u64>()
        .ok()?
        .checked_add(fields.get(12)?.parse::<u64>().ok()?)
}
fn ticks_per_second() -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let result = std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()?;
    if !result.status.success() {
        return None;
    }
    String::from_utf8(result.stdout).ok()?.trim().parse().ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "hostile load window with two enrolled principals; use the measurement runner"]
#[expect(
    clippy::too_many_lines,
    clippy::disallowed_methods,
    reason = "one bounded load window owns tasks, real timers, populations and shutdown"
)]
async fn authority_measurement_hostile_separation() {
    let seconds = number("GRANARY_MEASURE_SECONDS", 60);
    assert!((1..=60).contains(&seconds));
    let tuple = std::env::var("GRANARY_MEASURE_TUPLE").unwrap_or_else(|_| DEFAULT.into());
    let config = crate::ControlsConfig::parse(&tuple).unwrap();
    let (rate, _, _, _, cap) = config.tuple();
    assert!(
        cap >= 2,
        "hostile stalled uploads require cap >= 2, got {cap}"
    );
    let av = vol("a");
    let bv = vol("b");
    let da = ClientSpkiDigest::from_bytes([1; 32]);
    let db = ClientSpkiDigest::from_bytes([2; 32]);
    let (fx, driver) =
        Fixture::local("hostile", &[av.clone(), bv.clone()], 1, false, &tuple, da).await;
    let opts = crate::enrollment::VerbOptions {
        accept_unsupported_filesystem: std::env::var("GRANARY_MEASURE_SMOKE").as_deref() == Ok("1"),
    };
    let (principal_b, _) = crate::enrollment::mint(
        &fx.config.enrollment_dir,
        opts,
        &TenantName::parse("measure").unwrap(),
        db,
        &mut secure(2),
    )
    .unwrap();
    let run = runtime_thread(
        driver.run(),
        tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
    );
    let duplicate = good_root(&av, 1, None, 1);
    assert_eq!(
        fx.send(super::rows::publish(&av, 1, duplicate.clone()))
            .await
            .status(),
        202
    );
    fx.complete(&av, Epoch::from_bytes([WORLD_EPOCH; 16]))
        .await
        .unwrap();
    assert_eq!(
        fx.store
            .inner
            .get_root(av.as_str(), 1)
            .await
            .unwrap()
            .as_deref(),
        Some(duplicate.as_slice())
    );
    let reader = crate::enrollment::EnrollmentReader::open(
        &fx.config.enrollment_dir,
        opts.accept_unsupported_filesystem,
    )
    .unwrap();
    let enrolled_a = reader.lookup(&da).await;
    let enrolled_b = reader.lookup(&db).await;
    assert!(
        matches!((&enrolled_a, &enrolled_b),
        (crate::enrollment::Lookup::Enrolled { principal: a, .. }, crate::enrollment::Lookup::Enrolled { principal: b, .. })
        if a != b && *b == principal_b),
        "principal separation premise failed: {enrolled_a:?}, {enrolled_b:?}"
    );
    fx.io.counts();
    let hz = ticks_per_second();
    let cpu_start = cpu_ticks();
    let at = stopwatch();
    let deadline = at + Duration::from_secs(seconds as u64);
    let stall_target = cap.saturating_sub(1).min(2);
    let stall_window_ns = Duration::from_secs(seconds as u64).as_nanos();
    let stall_window = Arc::new(StallWindow {
        start: at,
        duration_ns: stall_window_ns,
        coverage: Mutex::new(StallCoverage {
            target: stall_target,
            ..StallCoverage::default()
        }),
    });
    let mut parked = tokio::task::JoinSet::new();
    for _ in 0..stall_target {
        let service = fx.service.clone();
        let window = stall_window.clone();
        parked.spawn(async move {
            let mut counts = StallCounts::default();
            while stopwatch() < deadline {
                let lease = Arc::new(StallLease {
                    seen: AtomicBool::new(false),
                    window: window.clone(),
                });
                let mut request = Request::builder()
                    .method("PUT")
                    .uri("/volume/unknown/root/00000000000000000001")
                    .body(Parked(lease.clone()))
                    .unwrap();
                identity(&mut request, da);
                let response = tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    service.request_for_test(request),
                )
                .await;
                counts.record(
                    lease.seen.load(Ordering::SeqCst),
                    response.ok().map(|response| response.status().as_u16()),
                );
                drop(lease);
                tokio::task::yield_now().await;
            }
            counts
        });
    }
    let initial_stalls_ready = tokio::time::timeout(Duration::from_millis(100), async {
        while stall_window.coverage.lock().unwrap().active < stall_target {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    let mut tasks = tokio::task::JoinSet::new();
    for lane in 0..4 {
        let service = fx.service.clone();
        let av = av.clone();
        let duplicate = duplicate.clone();
        tasks.spawn(async move {
            let unknown = vol("unknown");
            let mut counts = BTreeMap::<u16, usize>::new();
            let mut attempts = 0;
            while stopwatch() < deadline {
                let shape = (attempts + lane) % 4;
                let (v, bytes) = match shape {
                    0 => (&av, duplicate.clone()),
                    1 => (&av, b"invalid root".to_vec()),
                    2 => (&av, vec![0; 65_536]),
                    _ => (&unknown, duplicate.clone()),
                };
                let operation = if shape == 0 {
                    1
                } else {
                    100 + (lane as u64) * 1_000_000_000 + attempts as u64
                };
                let response = service
                    .request_for_test(super::rows::publish(v, operation, bytes))
                    .await;
                *counts.entry(response.status().as_u16()).or_default() += 1;
                attempts += 1;
                tokio::task::yield_now().await;
            }
            (attempts, counts)
        });
    }
    let mut publications = Vec::with_capacity(2048);
    let mut statuses = Vec::with_capacity(2048);
    let mut b_429 = 0;
    let mut failures = 0;
    let mut status_errors = 0;
    let mut reads = 0;
    let mut parent = None;
    // Keep B below its own submission budget so this row isolates competition.
    let spacing = Duration::from_nanos(1_000_000_000_u64.div_ceil(rate).saturating_add(50_000_000));
    while stopwatch() < deadline && publications.len() < publications.capacity() {
        let seq = publications.len() as u64 + 1;
        let bytes = good_root(&bv, seq, parent, 1);
        let id = GrainId::of(&bytes);
        let mut request = super::rows::publish(&bv, seq, bytes.clone());
        identity(&mut request, db);
        let started = stopwatch();
        let response = fx.send(request).await;
        if response.status() == 429 {
            b_429 += 1;
            break;
        }
        let code = response.status().as_u16();
        let token = response
            .headers()
            .get("granary-error")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);
        let media = response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);
        let answer = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap_or_else(|never| match never {})
            .to_bytes();
        let owned =
            granary_client::OwnedCandidate::new(bv.as_str(), Arc::from(bytes.clone())).unwrap();
        let expected = granary_client::PublishRequest::new(
            bv.as_str(),
            Epoch::from_bytes([WORLD_EPOCH; 16]),
            &seq.to_be_bytes(),
            owned.clone(),
            vec![owned],
        )
        .unwrap();
        if checked_publish(&expected, code, token.as_deref(), media.as_deref(), &answer).is_err() {
            failures += 1;
            break;
        }
        fx.complete(&bv, Epoch::from_bytes([WORLD_EPOCH; 16]))
            .await
            .unwrap();
        let mut read = Request::builder()
            .uri(format!("/volume/{}/root/{seq:020}", bv.as_str()))
            .body(http_body_util::Full::new(Bytes::new()))
            .unwrap();
        identity(&mut read, db);
        let response = fx.send(read).await;
        let code = response.status();
        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap_or_else(|never| match never {})
            .to_bytes();
        if code != 200 || body.as_ref() != bytes {
            failures += 1;
            break;
        }
        reads += 1;
        publications.push(started.elapsed().as_nanos());
        parent = Some(id);
        let started = stopwatch();
        if status(fx.send(super::rows::get(&bv)).await).await.is_err() {
            failures += 1;
            status_errors += 1;
            break;
        }
        statuses.push(started.elapsed().as_nanos());
        tokio::time::sleep(spacing.min(deadline.saturating_duration_since(stopwatch()))).await;
    }
    let mut a_attempts = 0;
    let mut a_statuses = BTreeMap::<u16, usize>::new();
    while let Some(result) = tasks.join_next().await {
        let (attempts, counts) = result.unwrap();
        a_attempts += attempts;
        for (status, count) in counts {
            *a_statuses.entry(status).or_default() += count;
        }
    }
    let mut stalls = StallCounts::default();
    while let Some(result) = parked.join_next().await {
        let counts = result.unwrap();
        stalls.attempts += counts.attempts;
        stalls.requests += counts.requests;
        stalls.rearms += counts.rearms;
        stalls.cap_refusals += counts.cap_refusals;
        stalls.unpolled_endings += counts.unpolled_endings;
    }
    let covered_ns = {
        let mut coverage = stall_window.coverage.lock().unwrap();
        coverage.observe(stall_window_ns);
        coverage.covered_ns
    };
    let cpu_end = cpu_ticks();
    let window_ns = at.elapsed().as_nanos();
    let counts = fx.io.counts();
    let loss = usize::from(publications.len() == publications.capacity());
    let admitted = a_statuses
        .iter()
        .filter(|(status, _)| **status != 429)
        .map(|(_, n)| n)
        .sum::<usize>();
    let per_million = admitted as u128 * 1_000_000_000_000_000 / window_ns;
    let mut result = fields("hostile_separation", &tuple, publications.len());
    for (name, samples) in [("b_publication", &publications), ("status", &statuses)] {
        if samples.is_empty() {
            result.insert(format!("{name}_count"), "0".into());
        } else {
            distribution(&mut result, name, samples);
        }
    }
    for (key, value) in [
        ("a_attempts", a_attempts.to_string()),
        ("a_admitted_attempts_lower_bound", admitted.to_string()),
        (
            "a_admitted_attempts_per_s_lower_bound",
            format!("{}.{:06}", per_million / 1_000_000, per_million % 1_000_000),
        ),
        (
            "a_admission_basis",
            "non-429 responses; body-stage 429 admission is unobservable".into(),
        ),
        ("seed", super::rows::seed().to_string()),
        ("b_read_count", reads.to_string()),
        ("b_completed_publications", publications.len().to_string()),
        ("b_429", b_429.to_string()),
        ("b_failures", failures.to_string()),
        ("status_errors", status_errors.to_string()),
        ("b_spacing_ns", spacing.as_nanos().to_string()),
        ("window_ns", window_ns.to_string()),
        ("stall_target", stall_target.to_string()),
        ("stall_attempts", stalls.attempts.to_string()),
        ("stalled_requests", stalls.requests.to_string()),
        ("stall_rearms", stalls.rearms.to_string()),
        ("stall_cap_refusals", stalls.cap_refusals.to_string()),
        ("stall_unpolled_endings", stalls.unpolled_endings.to_string()),
        ("stall_covered_ns", covered_ns.to_string()),
        ("stall_window_ns", stall_window_ns.to_string()),
        ("stall_coverage_fraction", {
            let fraction = covered_ns * 1_000_000_000 / stall_window_ns;
            format!("{}.{:09}", fraction / 1_000_000_000, fraction % 1_000_000_000)
        }),
        ("stall_shape", "one loop per target slot; re-arm after request end; count only bodies polled; occupancy observed from first body poll through request end; coverage excludes re-arm gaps and clips to producer window".into()),
        ("sample_loss", loss.to_string()),
        ("log_appends", "unavailable".into()),
        (
            "log_syncs",
            counts
                .get(super::io::Call::SyncFile as usize)
                .unwrap()
                .to_string(),
        ),
        (
            "server_cpu_ns",
            cpu_start
                .zip(cpu_end)
                .zip(hz)
                .and_then(|((start, end), hz)| {
                    end.checked_sub(start).and_then(|ticks| {
                        if hz == 0 {
                            None
                        } else {
                            Some((u128::from(ticks) * 1_000_000_000 / u128::from(hz)).to_string())
                        }
                    })
                })
                .unwrap_or_else(|| "unavailable".into()),
        ),
    ] {
        result.insert(key.into(), value);
    }
    for (code, count) in a_statuses {
        result.insert(format!("a_status_{code}"), count.to_string());
    }
    let population = export_then_check_population(
        || write("hostile_separation", &result),
        a_attempts,
        publications.len(),
        b_429,
        failures,
        statuses.len(),
        loss,
    );
    fx.handle.stop().await;
    assert_eq!(run.join().unwrap(), RunEnd::Stopped);
    population.unwrap();
    assert!(
        initial_stalls_ready,
        "initial stalled uploads did not hold occupancy before flood"
    );
    checked_stalls(&stalls, stall_target, covered_ns, stall_window_ns).unwrap();
}
