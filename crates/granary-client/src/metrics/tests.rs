// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_core::secure_random::{EntropyUnavailable, SecureRandom};

pub(crate) struct FixedRandom;
impl SecureRandom for FixedRandom {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        for (i, byte) in dest.iter_mut().enumerate() {
            *byte = u8::try_from(i).unwrap();
        }
        Ok(())
    }
}
pub(crate) fn metrics() -> ClientMetrics {
    ClientMetrics::new(&mut FixedRandom)
}
fn active() -> ClientMetrics {
    let m = metrics();
    for group in MetricsGroup::ALL {
        m.set_available(*group, true);
    }
    for result in CommitResult::ALL {
        m.record_commit(*result, Duration::from_millis(5));
    }
    for reason in RetryReason::ALL {
        m.record_retry(*reason);
    }
    m.record_rebase_conflict();
    m.set_contention(true);
    for callback in FuseCallback::ALL {
        for outcome in Outcome::ALL {
            m.record_fuse(*callback, *outcome);
        }
    }
    for outcome in Outcome::ALL {
        m.record_sync(*outcome);
    }
    for result in RegistrationResult::ALL {
        m.record_registration(*result, Duration::from_micros(1_001));
    }
    m.record_uploaded_grains(3);
    m.record_uploaded_bytes(UploadObject::Bin, 7);
    m.record_uploaded_bytes(UploadObject::Meta, 11);
    m.record_rechunk_fallback();
    m.set_view_stale(true);
    for phase in CachePhase::ALL {
        m.record_cache(*phase, CacheResult::Hit);
        m.record_cache(*phase, CacheResult::Miss);
    }
    m.record_transport(ByteDirection::Up, 13);
    m.record_transport(ByteDirection::Down, 17);
    m
}
fn golden(text: &str) -> &str {
    text.splitn(3, '\n').nth(2).unwrap()
}

#[test]
fn renderer_goldens_and_catalogue_census() {
    let active = active().snapshot().unwrap();
    let output = active.render_prometheus().unwrap();
    assert_eq!(output, golden(include_str!("active.prom")));
    assert_eq!(
        metrics().snapshot().unwrap().render_prometheus().unwrap(),
        golden(include_str!("unavailable.prom"))
    );
    let idle = metrics();
    for group in MetricsGroup::ALL {
        idle.set_available(*group, true);
    }
    idle.set_contention(false);
    assert_eq!(
        idle.snapshot().unwrap().render_prometheus().unwrap(),
        golden(include_str!("idle.prom"))
    );
    let samples: Vec<_> = output.lines().filter(|v| !v.starts_with('#')).collect();
    let identities: std::collections::BTreeSet<_> = samples
        .iter()
        .map(|v| v.rsplit_once(' ').unwrap().0)
        .collect();
    assert_eq!((samples.len(), identities.len()), (360, 360));
    assert!(output.len() <= 65_536 && output.lines().all(|v| v.len() < 512));
    assert!(std::mem::size_of::<MetricsSnapshot>() <= 16_384);
    assert_eq!(
        METRICS_CATALOGUE.iter().map(|s| s.code).collect::<Vec<_>>(),
        (1..=22).map(|i| format!("M{i:02}")).collect::<Vec<_>>()
    );
    assert_eq!(escape_help("a\\b\nc"), "a\\\\b\\nc");
    assert!(!output.contains("metrics_listener_up") && !output.contains("metrics_scrapes_total"));
}

fn check_domain<T: Copy + std::fmt::Debug + PartialEq>(
    members: &[T],
    name: fn(T) -> &'static str,
    parse: fn(&str) -> Result<T, MetricsError>,
    attacks: &[&str],
) -> usize {
    let mut cases = 0;
    for valid in members {
        assert_eq!(parse(name(*valid)), Ok(*valid));
        cases += 1;
    }
    for attack in attacks {
        let err = parse(attack).unwrap_err();
        assert_eq!(err.to_string(), "invalid metrics label");
        cases += 1;
    }
    cases
}

#[test]
fn label_domains_refuse_hostile_values() {
    let huge = "x".repeat(100_000);
    let attacks = [
        "../sensitive/file",
        "user=alice",
        "0123456789abcdef",
        "request-123",
        "\"\n",
        "other",
        &huge,
    ];
    for attack in attacks {
        crate::fuzz_probe::metrics_labels_probe(attack.as_bytes());
    }
    crate::fuzz_probe::metrics_labels_probe(b"\xff");
    let mut cases = 0;
    cases += check_domain(
        CommitResult::ALL,
        CommitResult::as_str,
        CommitResult::parse,
        &attacks,
    );
    cases += check_domain(
        RegistrationResult::ALL,
        RegistrationResult::as_str,
        RegistrationResult::parse,
        &attacks,
    );
    cases += check_domain(
        MetricsGroup::ALL,
        MetricsGroup::as_str,
        MetricsGroup::parse,
        &attacks,
    );
    cases += check_domain(
        CachePhase::ALL,
        CachePhase::as_str,
        CachePhase::parse,
        &attacks,
    );
    cases += check_domain(
        CacheResult::ALL,
        CacheResult::as_str,
        CacheResult::parse,
        &attacks,
    );
    cases += check_domain(
        UploadObject::ALL,
        UploadObject::as_str,
        UploadObject::parse,
        &attacks,
    );
    cases += check_domain(
        ByteDirection::ALL,
        ByteDirection::as_str,
        ByteDirection::parse,
        &attacks,
    );
    // Existing logging domains remain closed and are not widened by metrics.
    for attack in attacks {
        assert_eq!(
            (Outcome::parse(attack), RetryReason::parse(attack)),
            (None, None)
        );
        cases += 1;
    }
    assert_eq!(cases, 80);
}

#[test]
fn invalid_cells_are_sticky_and_only_omit_the_affected_group() {
    let m = active();
    m.0.commits[0].0.store(u64::MAX - 2, Ordering::Relaxed);
    m.record_commit(CommitResult::Ok, Duration::ZERO);
    assert_eq!(m.0.commits[0].load(), u64::MAX - 1);
    m.record_commit(CommitResult::Ok, Duration::ZERO);
    m.record_commit(CommitResult::Ok, Duration::ZERO);
    let output = m.snapshot().unwrap().render_prometheus().unwrap();
    assert_eq!(m.0.commits[0].load(), u64::MAX);
    assert!(!output.contains("granary_client_commits_total{result=\"ok\"}"));
    assert!(output.contains("granary_client_commits_total{result=\"conflict\"} 1\n"));
    assert!(output.contains("metrics_overflow{metric=\"M05\"} 1\n"));
    m.0.transport[0].0.store(u64::MAX - 1, Ordering::Relaxed);
    assert!(
        m.snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap()
            .contains("direction=\"up\"} 18446744073709551614\n")
    );
}

#[test]
fn histogram_edges_torn_reads_and_duration_overflow() {
    let m = metrics();
    m.set_available(MetricsGroup::Commit, true);
    for edge in BUCKET_US {
        m.record_commit(CommitResult::Ok, Duration::from_micros(edge));
        m.record_commit(CommitResult::Ok, Duration::from_micros(edge + 1));
    }
    m.record_commit(CommitResult::Ok, Duration::from_nanos(999));
    let mut snapshot = m.snapshot().unwrap();
    assert_eq!(
        snapshot.commit_duration[0].buckets,
        [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1]
    );
    // A bucket visible before its sum is an explicitly supported torn collection.
    snapshot.commit_duration[0].sum = 0;
    let text = snapshot.render_prometheus().unwrap();
    assert_eq!(
        (
            text.contains("result=\"ok\",le=\"+Inf\"} 23\n"),
            text.contains("commit_duration_seconds_count{result=\"ok\"} 23\n")
        ),
        (true, true),
        "{text}"
    );
    assert!(text.contains("commit_duration_seconds_sum{result=\"ok\"} 0.000000\n"));
    m.record_commit(CommitResult::Ok, Duration::MAX);
    let text = m.snapshot().unwrap().render_prometheus().unwrap();
    assert_eq!(
        (
            text.contains("commit_duration_seconds_count{result=\"ok\"}"),
            text.contains("commit_duration_seconds_count{result=\"conflict\"} 0\n"),
            text.contains("metrics_overflow{metric=\"M06\"} 1\n")
        ),
        (false, true, true)
    );
}

#[test]
fn derived_overflow_never_becomes_a_healthy_zero_or_ratio() {
    let m = active();
    m.0.cache[0][0].0.store(u64::MAX - 1, Ordering::Relaxed);
    m.0.cache[0][1].0.store(1, Ordering::Relaxed);
    m.0.registration_duration[0].buckets[0]
        .0
        .store(u64::MAX - 1, Ordering::Relaxed);
    m.0.registration_duration[0].buckets[1]
        .0
        .store(1, Ordering::Relaxed);
    let text = m.snapshot().unwrap().render_prometheus().unwrap();
    assert_eq!(
        (
            text.contains("cache_hit_ratio{phase=\"startup\"}"),
            text.contains("metrics_overflow{metric=\"M17\"} 1\n"),
            text.contains("intent_registration_duration_seconds_count{result=\"ok\"}"),
            text.contains("metrics_overflow{metric=\"M12\"} 1\n")
        ),
        (false, true, false, true)
    );
    assert!(text.contains("cache_hit_ratio{phase=\"read\"} 0.5\n"));
}

#[test]
fn output_limits_fail_the_whole_response() {
    let snapshot = active().snapshot().unwrap();
    let output = snapshot.render_prometheus().unwrap();
    let longest = output.lines().map(|l| l.len() + 1).max().unwrap();
    let count = output.lines().filter(|l| !l.starts_with('#')).count();
    assert_eq!(
        snapshot.render_with_limits(output.len(), longest, count),
        Ok(output.clone())
    );
    for limits in [
        (output.len() - 1, 512, 512),
        (65_536, longest - 1, 512),
        (65_536, 512, count - 1),
    ] {
        assert_eq!(
            snapshot.render_with_limits(limits.0, limits.1, limits.2),
            Err(MetricsError::OutputLimit)
        );
    }
}

#[test]
fn incarnation_failure_and_sequence_exhaustion_refuse_reports() {
    struct Broken;
    impl SecureRandom for Broken {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
            dest.fill(42);
            Err(EntropyUnavailable)
        }
    }
    let m = ClientMetrics::new(&mut Broken);
    m.record_uploaded_grains(3);
    assert_eq!(m.snapshot().unwrap_err(), MetricsError::Unavailable);
    assert_eq!(m.0.grains.load(), 3);
    let m = metrics();
    let first = m.snapshot().unwrap();
    let second = m.snapshot().unwrap();
    assert_eq!(
        (first.incarnation(), first.sequence(), second.sequence()),
        ([66_051, 67_438_087, 134_810_123, 202_182_159], 1, 2)
    );
    m.0.sequence.0.store(u64::MAX - 2, Ordering::Relaxed);
    assert_eq!(m.snapshot().unwrap().sequence(), u64::MAX - 1);
    assert_eq!(m.snapshot().unwrap_err(), MetricsError::SequenceExhausted);
    assert_eq!(m.snapshot().unwrap_err(), MetricsError::SequenceExhausted);
}

#[test]
fn unavailable_idle_and_contention_are_distinct() {
    let m = metrics();
    assert!(
        !m.snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap()
            .contains("contention_flag")
    );
    m.set_contention(false);
    let text = m.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        text.contains("metrics_available{group=\"contention\"} 1\n")
            && text.contains("contention_flag 0\n")
    );
    m.set_contention(true);
    assert!(
        m.snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap()
            .contains("contention_flag 1\n")
    );
    m.set_available(MetricsGroup::Cache, true);
    let text = m.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        text.contains("phase=\"startup\",result=\"miss\"} 0\n")
            && !text.contains("cache_hit_ratio{phase=")
    );
    m.record_cache(CachePhase::Startup, CacheResult::Miss);
    assert!(
        m.snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap()
            .contains("cache_hit_ratio{phase=\"startup\"} 0\n")
    );
}

#[test]
fn stalled_export_and_saturated_histogram_do_not_block_recording() {
    for saturated in [false, true] {
        let m = active();
        if saturated {
            m.0.commit_duration[0].buckets[0]
                .0
                .store(INVALID, Ordering::Relaxed);
        }
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let export = m.clone();
        let worker = std::thread::spawn(move || {
            let snapshot = export.snapshot().unwrap();
            reached_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            snapshot.render_prometheus().unwrap()
        });
        reached_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("export must reach the closed gate");
        let producer = m.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let producer_thread = std::thread::spawn(move || {
            producer.record_commit(CommitResult::Ok, Duration::from_micros(100));
            done_tx
                .send(producer.snapshot().unwrap().commits[0])
                .unwrap();
        });
        let observed = done_rx.recv_timeout(Duration::from_secs(1));
        // Always release before asserting, so a shared-lock mutant fails promptly.
        release_tx.send(()).unwrap();
        let exported = worker.join().unwrap();
        producer_thread.join().unwrap();
        assert!(
            exported.contains("commits_total{result=\"ok\"} 1\n"),
            "{exported}"
        );
        assert_eq!(observed, Ok(2));
    }
}

#[test]
fn stores_are_independent_and_log_filters_do_not_change_observations() {
    use tracing_subscriber::prelude::*;
    for filter in [
        tracing_subscriber::filter::LevelFilter::OFF,
        tracing_subscriber::filter::LevelFilter::TRACE,
    ] {
        let subscriber = tracing_subscriber::registry().with(filter);
        tracing::subscriber::with_default(subscriber, || {
            let a = metrics();
            let b = metrics();
            a.record_transport(ByteDirection::Up, 7);
            b.record_transport(ByteDirection::Up, 11);
            let first = a.snapshot().unwrap();
            let second = a.snapshot().unwrap();
            assert_eq!(
                (
                    first.transport[0],
                    second.transport[0],
                    b.snapshot().unwrap().transport[0]
                ),
                (7, 7, 11)
            );
        });
    }
}

#[test]
fn every_overflow_family_is_marked_and_healthy_siblings_remain() {
    let m = active();
    for cell in [
        &m.0.commits[0],
        &m.0.retries[0],
        &m.0.conflicts,
        &m.0.syncs[0],
        &m.0.registrations[0],
        &m.0.grains,
        &m.0.uploads[0],
        &m.0.rechunks,
        &m.0.cache[0][0],
        &m.0.transport[0],
    ] {
        cell.0.store(INVALID, Ordering::Relaxed);
    }
    m.0.commit_duration[0]
        .sum
        .0
        .store(INVALID, Ordering::Relaxed);
    m.0.registration_duration[0]
        .sum
        .0
        .store(INVALID, Ordering::Relaxed);
    let text = m.snapshot().unwrap().render_prometheus().unwrap();
    let codes = [
        "M05", "M06", "M07", "M08", "M10", "M11", "M12", "M13", "M14", "M15", "M16", "M17", "M18",
    ];
    for code in codes {
        assert!(
            text.contains(&format!("metrics_overflow{{metric=\"{code}\"}} 1\n")),
            "{code}: {text}"
        );
    }
    assert_eq!(codes.len(), 13);
    for healthy in [
        "commits_total{result=\"conflict\"} 1",
        "commit_retries_total{reason=\"conflict\"} 1",
        "syncs_total{outcome=\"failed\"} 1",
        "intent_registrations_total{result=\"failed\"} 1",
        "sync_uploaded_bytes_total{object=\"meta\"} 11",
        "cache_lookups_total{phase=\"read\",result=\"hit\"} 1",
        "transport_body_bytes_total{direction=\"down\"} 17",
    ] {
        assert!(text.contains(healthy), "{healthy}: {text}");
    }
}

#[test]
fn maximum_valid_values_have_a_bounded_exact_golden() {
    let mut snapshot = active().snapshot().unwrap();
    snapshot.commits.fill(u64::MAX - 1);
    snapshot.retries.fill(u64::MAX - 1);
    snapshot.conflicts = u64::MAX - 1;
    snapshot.syncs.fill(u64::MAX - 1);
    snapshot
        .fuse
        .iter_mut()
        .for_each(|row| row.fill(u64::MAX - 1));
    snapshot.registrations.fill(u64::MAX - 1);
    snapshot.grains = u64::MAX - 1;
    snapshot.uploads.fill(u64::MAX - 1);
    snapshot.rechunks = u64::MAX - 1;
    snapshot.cache = [[u64::MAX - 1, 0]; 2];
    snapshot.transport.fill(u64::MAX - 1);
    for hist in snapshot
        .commit_duration
        .iter_mut()
        .chain(&mut snapshot.registration_duration)
    {
        hist.buckets.fill(0);
        hist.buckets[0] = u64::MAX - 1;
        hist.sum = u64::MAX - 1;
    }
    let output = snapshot.render_prometheus().unwrap();
    assert_eq!(output, golden(include_str!("maximum.prom")));
    assert_eq!(
        output.lines().filter(|line| !line.starts_with('#')).count(),
        360
    );
    assert!(output.len() <= 65_536 && output.lines().all(|line| line.len() < 512));
}

#[test]
fn snapshot_completes_while_a_histogram_writer_is_held_between_cells() {
    let m = metrics();
    m.set_available(MetricsGroup::Commit, true);
    m.0.commit_duration[0].pause.store(1, Ordering::Relaxed);
    let writer_metrics = m.clone();
    let writer = std::thread::spawn(move || {
        writer_metrics.record_commit(CommitResult::Ok, Duration::from_millis(1));
    });
    let (gate_tx, gate_rx) = std::sync::mpsc::channel();
    let observer_metrics = m.clone();
    let cancelled = Arc::new(AtomicBool::new(false));
    let stop = cancelled.clone();
    let observer = std::thread::spawn(move || {
        while observer_metrics.0.commit_duration[0]
            .pause
            .load(Ordering::Relaxed)
            != 2
            && !stop.load(Ordering::Relaxed)
        {
            std::thread::yield_now();
        }
        gate_tx
            .send(
                observer_metrics.0.commit_duration[0]
                    .pause
                    .load(Ordering::Relaxed)
                    == 2,
            )
            .unwrap();
    });
    let reached = gate_rx.recv_timeout(Duration::from_secs(1));
    let (copy_tx, copy_rx) = std::sync::mpsc::channel();
    let copy_metrics = m.clone();
    let snapshot_worker =
        std::thread::spawn(move || copy_tx.send(copy_metrics.snapshot()).unwrap());
    let copied = copy_rx.recv_timeout(Duration::from_secs(1));
    let held = m.0.commit_duration[0].pause.load(Ordering::Relaxed);
    // Release before asserting even if a reader-lock mutant made the copy time out.
    cancelled.store(true, Ordering::Relaxed);
    m.0.commit_duration[0].pause.store(3, Ordering::Relaxed);
    writer.join().unwrap();
    observer.join().unwrap();
    snapshot_worker.join().unwrap();
    assert_eq!(
        (reached, copied.is_ok(), held),
        (Ok(true), true, 2),
        "copy result: {copied:?}"
    );
    let report = copied.unwrap().unwrap();
    assert_eq!(
        (
            report.commit_duration[0].buckets[0],
            report.commit_duration[0].sum
        ),
        (1, 0)
    );
    let text = report.render_prometheus().unwrap();
    assert_eq!(
        (
            text.contains("commit_duration_seconds_bucket{result=\"ok\",le=\"+Inf\"} 1\n"),
            text.contains("commit_duration_seconds_count{result=\"ok\"} 1\n")
        ),
        (true, true),
        "{text}"
    );
    assert_eq!(m.snapshot().unwrap().commit_duration[0].sum, 1_000);
    // Disarmed control records the same sample without holding the writer.
    let control = metrics();
    control.record_commit(CommitResult::Ok, Duration::from_millis(1));
    let report = control.snapshot().unwrap();
    assert_eq!(
        (
            report.commit_duration[0].buckets[0],
            report.commit_duration[0].sum,
            control.0.commit_duration[0].pause.load(Ordering::Relaxed)
        ),
        (1, 1_000, 0)
    );
}

#[test]
fn contention_availability_controls_metadata_and_samples() {
    let m = metrics();
    m.set_available(MetricsGroup::Contention, true);
    let text = m.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        text.contains("metrics_available{group=\"contention\"} 0\n"),
        "a decision is required: {text}"
    );
    assert!(
        !text.contains("# HELP granary_client_contention_flag"),
        "{text}"
    );
    m.set_contention(true);
    m.set_available(MetricsGroup::Contention, false);
    let text = m.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        text.contains("metrics_available{group=\"contention\"} 0\n"),
        "{text}"
    );
    assert!(
        !text.contains("# HELP granary_client_contention_flag"),
        "{text}"
    );
    m.set_available(MetricsGroup::Contention, true);
    let text = m.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        text.contains("metrics_available{group=\"contention\"} 1\n"),
        "{text}"
    );
    assert!(text.contains("contention_flag 1\n"), "{text}");
}

#[test]
fn every_catalogue_entry_has_an_explicit_renderer() {
    let snapshot = active().snapshot().unwrap();
    for spec in METRICS_CATALOGUE {
        let mut text = Text {
            output: String::new(),
            series: 0,
            bytes_cap: METRICS_MAX_BYTES,
            line_cap: METRICS_MAX_LINE,
            series_cap: METRICS_MAX_SERIES,
        };
        let mut renamed = *spec;
        renamed.code = "display-only";
        snapshot.render_family(&mut text, &renamed).unwrap();
        assert!(text.series > 0, "missing renderer for {}", spec.code);
        assert!(
            text.output.lines().all(|line| line.starts_with(spec.name)),
            "{}",
            spec.code
        );
    }
}

#[test]
fn each_presence_gate_uses_its_named_group() {
    let families = [
        (MetricsGroup::Cache, vec!["M16", "M17"]),
        (MetricsGroup::Transport, vec!["M18"]),
        (
            MetricsGroup::Sync,
            vec!["M10", "M11", "M12", "M13", "M14", "M15", "M22"],
        ),
        (MetricsGroup::Commit, vec!["M05", "M06", "M07", "M08"]),
        (MetricsGroup::Contention, vec!["M09"]),
    ];
    for (group, expected) in &families {
        let m = metrics();
        m.set_contention(false);
        for other in MetricsGroup::ALL {
            m.set_available(*other, false);
        }
        m.set_available(*group, true);
        let text = m.snapshot().unwrap().render_prometheus().unwrap();
        for spec in METRICS_CATALOGUE.iter().filter(|spec| spec.code >= "M05") {
            assert_eq!(
                text.contains(&format!("# HELP {} ", spec.name)),
                expected.contains(&spec.code),
                "group={group:?}, code={}: {text}",
                spec.code
            );
        }
    }
}

#[test]
fn fuse_completions_are_separate_from_engine_syncs_and_closed() {
    use granary_fuse::{CallbackObserver, CallbackOutcome, MountError};
    let metrics = metrics();
    metrics.set_available(MetricsGroup::Fuse, true);
    let observer = crate::mount::FuseObserver {
        writability: granary_fuse::MountWritability::Writable,
        metrics: Some(metrics.clone()),
    };
    for (callback, result) in [
        (FuseCallback::Fsync, CallbackOutcome::Refused),
        (FuseCallback::Fsyncdir, CallbackOutcome::Refused),
        (FuseCallback::Release, CallbackOutcome::Ok),
        (
            FuseCallback::Release,
            CallbackOutcome::Failed(MountError::Io),
        ),
    ] {
        observer.completed(callback, result);
    }
    let snapshot = metrics.snapshot().unwrap();
    let text = snapshot.render_prometheus().unwrap();
    assert!(text.contains("fuse_requests_total{callback=\"fsync\",outcome=\"refused\"} 1"));
    assert!(text.contains("fuse_requests_total{callback=\"fsyncdir\",outcome=\"refused\"} 1"));
    assert!(text.contains("fuse_requests_total{callback=\"release\",outcome=\"ok\"} 1"));
    assert!(text.contains("fuse_requests_total{callback=\"release\",outcome=\"failed\"} 1"));
    assert_eq!(snapshot.syncs, [0; 4]);
    assert_eq!(snapshot.registrations, [0; 4]);
    assert_eq!(snapshot.uploads, [0; 2]);
    let attacks = ["caller/path", "token=secret", "fsync\nextra", "FSYNC", ""];
    for attack in attacks {
        assert_eq!(FuseCallback::parse(attack), None);
    }
    assert_eq!((attacks.len(), FuseCallback::ALL.len()), (5, 40));
    metrics.0.fuse[24][3]
        .0
        .store(u64::MAX - 1, Ordering::Relaxed);
    metrics.record_fuse(FuseCallback::Fsync, Outcome::Refused);
    let overflow = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(overflow.contains("metrics_overflow{metric=\"M21\"} 1"));
    assert!(!overflow.contains("fuse_requests_total{callback=\"fsync\",outcome=\"refused\"}"));
    assert!(overflow.contains("fuse_requests_total{callback=\"fsyncdir\",outcome=\"refused\"} 1"));
}

#[test]
fn mount_view_stale_gauge_follows_the_state() {
    let m = metrics();
    let absent = m.snapshot().unwrap().render_prometheus().unwrap();
    m.set_available(MetricsGroup::Sync, true);
    let fresh = m.snapshot().unwrap().render_prometheus().unwrap();
    m.set_view_stale(true);
    let stale = m.snapshot().unwrap().render_prometheus().unwrap();
    m.set_view_stale(false);
    let cleared = m.snapshot().unwrap().render_prometheus().unwrap();
    let doc = include_str!("../../../../docs/operating-client-observability.md");
    assert_eq!(
        (
            absent.contains("granary_client_mount_view_stale"),
            fresh.contains("granary_client_mount_view_stale 0\n"),
            stale.contains("granary_client_mount_view_stale 1\n"),
            cleared.contains("granary_client_mount_view_stale 0\n"),
            doc.contains("| M22 | `mount_view_stale` | gauge |"),
        ),
        (false, true, true, true, true)
    );
}

#[test]
fn bundle_projection_preserves_distinct_fields_and_stored_buckets() {
    let histogram = |base| HistogramSnapshot {
        buckets: std::array::from_fn(|i| base + i as u64),
        sum: base + 12,
    };
    let snapshot = MetricsSnapshot {
        incarnation: [11, 12, 13, 14],
        sequence: 15,
        available: [true, false, true, false, true, false],
        commits: [21, 22, 23, 24, 25, u64::MAX],
        commit_duration: std::array::from_fn(|i| histogram(100 + i as u64 * 20)),
        retries: [31, 32, 33],
        conflicts: 34,
        contention: 2,
        syncs: [41, 42, 43, 44],
        fuse: std::array::from_fn(|i| std::array::from_fn(|j| 300 + i as u64 * 4 + j as u64)),
        registrations: [51, 52, 53, 54],
        registration_duration: std::array::from_fn(|i| histogram(500 + i as u64 * 20)),
        grains: 61,
        uploads: [62, 63],
        rechunks: 64,
        view_stale: true,
        cache: [[71, 72], [73, 74]],
        transport: [81, 82],
        listener: 2,
        scrapes: [91, 92, 93, 94],
    };
    let mut expected = Vec::new();
    expected.extend_from_slice(&2u16.to_be_bytes());
    for v in [11u32, 12, 13, 14] {
        expected.extend_from_slice(&v.to_be_bytes());
    }
    expected.extend_from_slice(&15u64.to_be_bytes());
    expected.extend_from_slice(&[1, 0, 1, 0, 1, 0]);
    let words = |bytes: &mut Vec<u8>, values: Vec<u64>| {
        for value in values {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    };
    words(&mut expected, vec![21, 22, 23, 24, 25, u64::MAX]);
    for base in [100, 120, 140, 160, 180, 200] {
        words(&mut expected, (base..=base + 12).collect());
    }
    words(&mut expected, vec![31, 32, 33, 34]);
    expected.push(2);
    words(&mut expected, vec![41, 42, 43, 44]);
    words(&mut expected, (300..460).collect());
    words(&mut expected, vec![51, 52, 53, 54]);
    for base in [500, 520, 540, 560] {
        words(&mut expected, (base..=base + 12).collect());
    }
    words(&mut expected, vec![61, 62, 63, 64, 71, 72, 73, 74, 81, 82]);
    let projection = snapshot.bundle_projection();
    assert!(
        (
            FuseCallback::ALL.len(),
            expected.len(),
            projection.encode().unwrap() == expected
        ) == (40, 2577, true),
        "support metrics projection lost or swapped a field"
    );
    let mut changed = snapshot.clone();
    changed.view_stale = false;
    assert!(
        changed.bundle_projection() == projection,
        "unrepresented metric widened support layout"
    );
}

#[test]
fn configured_listener_metrics_report_health_and_terminal_results() {
    let metrics = active();
    let render = || metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(!render().contains("granary_client_metrics_listener_up"));
    assert!(!render().contains("granary_client_metrics_scrapes_total"));
    metrics.set_metrics_listener_up(false);
    assert!(render().contains("granary_client_metrics_listener_up 0\n"));
    metrics.set_metrics_listener_up(true);
    for result in ScrapeResult::ALL {
        for _ in 0..=result as usize {
            metrics.record_metrics_scrape(result);
        }
    }
    let output = render();
    assert!(output.contains("granary_client_metrics_listener_up 1\n"));
    for (name, count) in [("ok", 1), ("refused", 2), ("limited", 3), ("failed", 4)] {
        assert!(output.contains(&format!(
            "granary_client_metrics_scrapes_total{{result=\"{name}\"}} {count}\n"
        )));
    }
    metrics.set_metrics_listener_up(false);
    assert!(render().contains("granary_client_metrics_listener_up 0\n"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one stalled scrape drives recording, a second snapshot and cancellation in order"
)]
async fn metrics_linux_stalled_snapshot_allows_recording_collection_and_cancellation() {
    use std::net::TcpListener;
    use std::sync::Arc;

    use granary_net::metrics_listener::{self, Configuration, Event, ScrapeResult};
    use rustls::{ClientConfig, RootCertStore};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::{mpsc, oneshot, watch};
    use tokio::time::timeout;
    use tokio_rustls::TlsConnector;

    const WAIT: Duration = Duration::from_secs(2);
    let metrics = metrics();
    metrics.set_available(MetricsGroup::Transport, true);
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let tls = ClientConfig::builder_with_provider(Arc::new(granary_net::crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls));

    for (count, (release, expected)) in
        (1..).zip([(true, ScrapeResult::Ok), (false, ScrapeResult::Cancelled)])
    {
        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = held.local_addr().unwrap();
        let config = Configuration::new(
            addr.to_string().parse().unwrap(),
            &[b'a'; 64],
            cert.cert.pem().as_bytes(),
            cert.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        drop(held);
        let (captured, mut reached) = mpsc::unbounded_channel();
        let (open, gate) = watch::channel(false);
        let (notified, mut events) = mpsc::unbounded_channel();
        let owner = metrics_listener::start(
            config,
            {
                let metrics = metrics.clone();
                move || {
                    let snapshot = metrics.snapshot();
                    let _ = captured.send(());
                    let mut gate = gate.clone();
                    async move {
                        let _ = gate.wait_for(|open| *open).await;
                        snapshot
                            .and_then(|snapshot| snapshot.render_prometheus())
                            .map(String::into_bytes)
                            .map_err(|_| metrics_listener::Failure::Internal)
                    }
                }
            },
            move |event| {
                let _ = notified.send(event);
            },
        )
        .unwrap();
        assert_eq!(
            timeout(WAIT, events.recv()).await.unwrap(),
            Some(Event::Started)
        );
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut stream = connector.connect(addr.ip().into(), stream).await.unwrap();
        let mut request =
            format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer ").into_bytes();
        request.extend_from_slice(&[b'a'; 64]);
        request.extend_from_slice(b"\r\n\r\n");
        stream.write_all(&request).await.unwrap();
        timeout(WAIT, reached.recv()).await.unwrap().unwrap();

        let (done, progress) = oneshot::channel();
        let producer = metrics.clone();
        std::thread::spawn(move || {
            producer.record_transport(ByteDirection::Up, 1);
            let _ = done.send(producer.snapshot());
        });
        let progressed = timeout(WAIT, progress).await;
        if progressed.is_err() {
            open.send_replace(true);
        }
        let newer = progressed
            .unwrap()
            .unwrap()
            .unwrap()
            .render_prometheus()
            .unwrap();
        assert!(newer.contains(&format!(
            "granary_client_transport_body_bytes_total{{direction=\"up\"}} {count}\n"
        )));
        assert!(
            !*open.borrow(),
            "recording and a second snapshot finish while the scrape is held"
        );

        if release {
            open.send_replace(true);
            let mut reply = Vec::new();
            timeout(WAIT, stream.read_to_end(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert!(reply.starts_with(b"HTTP/1.1 200"));
            assert_eq!(
                timeout(WAIT, events.recv()).await.unwrap(),
                Some(Event::Scrape(expected))
            );
            drop(owner);
        } else {
            drop(owner);
            let observed = timeout(WAIT, events.recv()).await;
            if observed.is_err() {
                open.send_replace(true);
            }
            assert_eq!(observed.unwrap(), Some(Event::Scrape(expected)));
            assert!(
                !*open.borrow(),
                "cancellation finishes while the scrape is held"
            );
        }
        assert_eq!(
            timeout(WAIT, events.recv()).await.unwrap(),
            Some(Event::Stopped)
        );
    }
}
