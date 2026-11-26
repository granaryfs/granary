// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
// @file-disposition: STAYS — the populated-occupancy fixture, the pivot drivers that run on it and the exporters of the pivot field set the measurement validator binds are one subject; the unit rows exercise those private exporters directly.

//! Intent-occupancy row arithmetic and the ruled pivot comparison.

use granary_core::authlog::Epoch;
use granary_core::enrollment::{
    ClientSpkiDigest, EnrollmentSet, PrincipalId, PrincipalState, TenantName,
};
use granary_core::hash::GrainId;
use granary_core::intent;
use granary_core::intent::{Ownership, OwnershipMode, Release};
use granary_core::root::{self, RootDoc, RootSig, VolumeName};
use granary_core::sheaf::Timestamp;
use granary_sim::fakes::{Faults, Sim};
use granary_store::crypto::{TrustedKeys, check_signatures};
use http_body_util::{BodyExt as _, Full};
use hyper::{Method, Request, body::Bytes};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

mod cross_volume;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    DurablePrepared,
    Published,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Occupancy {
    Floor,
    Ceiling,
    UpperBound,
}

const MAX_PUBLISH_STREAMS: usize = super::pivot::DENOMINATOR_STREAMS;
const PUBLISH_PILOT_SAMPLES: usize = 32;
const PUBLISH_PILOT_WARMUP: usize = 4;
// At 46/s, 64 requests span about 1.39 s and exercise each of the 16
// numerator writers four times, covering the opening transient seen at the venue.
const PIVOT_WARMUP_REQUESTS: usize = 64;
const PUBLISH_PILOT_TIMEOUT: Duration = Duration::from_secs(2);
const PUBLISH_DIAGNOSTIC_SAMPLES: usize = 368;
const PUBLISH_DIAGNOSTIC_TIMEOUT: Duration = Duration::from_millis(100);
const PUBLISH_DIAGNOSTIC_COMPLETION_TIMEOUT: Duration = Duration::from_secs(2);
const PROGRESS_VOLUME_INTERVAL: usize = 4;
const PROGRESS_INTENT_ROW_INTERVAL: usize = 64;
const PROGRESS_PILOT_INTERVAL: usize = 4;
const PROGRESS_OPEN_LOOP_INTERVAL: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PivotWorkload {
    RegisterOpenLoop {
        count: usize,
        rate: u32,
    },
    PublishOpenLoop {
        count: usize,
        rate: super::pivot::OfferedRate,
        stream_count: usize,
    },
    PublishDiagnostic {
        count: usize,
    },
}

impl PivotWorkload {
    fn count(self) -> usize {
        let measured = match self {
            Self::RegisterOpenLoop { count, .. }
            | Self::PublishOpenLoop { count, .. }
            | Self::PublishDiagnostic { count } => count,
        };
        measured.saturating_add(PIVOT_WARMUP_REQUESTS)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublishPilot {
    sample_count: usize,
    p50: Duration,
    p99: Duration,
    max: Duration,
    stream_count: usize,
}

#[derive(Debug, Default)]
struct DiagnosticRun {
    durations: Vec<Duration>,
    warmup_count: usize,
    warmup_elapsed: Duration,
    publish_censored: usize,
    publish_stalls: Vec<Duration>,
    warmup_publish_stalls: Vec<Duration>,
    completion_stalls: Vec<Duration>,
    stall_index: Option<usize>,
    stall_phase: Option<&'static str>,
}

struct PivotProgress {
    output: Option<super::output::Progress>,
    counts: [usize; 6],
    error: Option<String>,
}

impl PivotProgress {
    fn new(row: Option<&str>) -> Result<Self, String> {
        Ok(Self {
            output: row.map(super::output::Progress::for_row).transpose()?,
            counts: [0; 6],
            error: None,
        })
    }

    fn record(&mut self, phase: &str) {
        if self.error.is_none()
            && let Some(output) = self.output.as_mut()
            && let Err(error) = output.record(phase, self.counts)
        {
            self.error = Some(error);
        }
    }

    fn principals_enrolled(&mut self, principals: usize) {
        self.counts[1] = self.counts[1].saturating_add(principals);
        self.record("principal-enrollment-progress");
    }

    fn intent_row_prepared(&mut self) {
        self.counts[2] = self.counts[2].saturating_add(1);
        if self.counts[2].is_multiple_of(PROGRESS_INTENT_ROW_INTERVAL) {
            self.record("intent-row-progress");
        }
    }

    fn volume_prepared(&mut self) {
        self.counts[0] = self.counts[0].saturating_add(1);
        if self.counts[0].is_multiple_of(PROGRESS_VOLUME_INTERVAL) {
            self.record("occupancy-progress");
        }
    }

    fn pilot_published(&mut self) {
        self.counts[3] = self.counts[3].saturating_add(1);
        if self.counts[3].is_multiple_of(PROGRESS_PILOT_INTERVAL) {
            self.record("pilot-progress");
        }
    }

    fn open_loop_sent(&mut self) {
        self.counts[4] = self.counts[4].saturating_add(1);
        if self.counts[4].is_multiple_of(PROGRESS_OPEN_LOOP_INTERVAL) {
            self.record("open-loop-send-progress");
        }
    }

    fn open_loop_completed(&mut self) {
        self.counts[5] = self.counts[5].saturating_add(1);
        if self.counts[5].is_multiple_of(PROGRESS_OPEN_LOOP_INTERVAL) {
            self.record("open-loop-completion-progress");
        }
    }

    fn finish(&mut self) -> Result<(), String> {
        self.record("row-complete");
        if self.error.is_none()
            && let Some(output) = self.output.as_mut()
            && let Err(error) = output.finish()
        {
            self.error = Some(error);
        }
        self.error.take().map_or(Ok(()), Err)
    }
}

fn progress(
    progress: &Arc<std::sync::Mutex<PivotProgress>>,
    update: impl FnOnce(&mut PivotProgress),
) {
    let mut progress = progress
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    update(&mut progress);
}

#[derive(Debug, Clone, Copy)]
struct RecordedRun<'a> {
    profile: Profile,
    occupancy: Occupancy,
    offered_rate: Option<u32>,
    load_model: &'a str,
    medium: &'a str,
    wrapper: &'a str,
    route: &'a str,
    samples: &'a [Duration],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "the field names are the measurement record's byte metrics"
)]
struct Amplification {
    written_bytes: usize,
    encode_register_bytes: usize,
    full_snapshot_bytes: usize,
}

#[derive(Debug)]
struct OccupancyRow {
    principals: usize,
    row_holders: usize,
    live_roots: usize,
    released_rows: usize,
    root_label: &'static str,
    root_bytes: usize,
    root_size_distribution: BTreeMap<usize, usize>,
    store_kind: String,
    log_filesystem: String,
    amplification: Amplification,
    register_samples: Vec<Duration>,
    pivot_run: Option<super::pivot::OpenLoopRun>,
    diagnostic_run: DiagnosticRun,
    committed_transitions: usize,
    intent_log_bytes: Option<u64>,
    authority_log_wait_samples: Vec<Duration>,
    publish_pilot: Option<PublishPilot>,
    principal_submission_limit: u64,
    principal_in_flight_limit: usize,
    per_stream_offered_rate: Option<f64>,
    denominator_attempts: Vec<DenominatorAttempt>,
}

#[derive(Debug, Clone)]
struct DenominatorAttempt {
    rate: f64,
    achieved_rate: f64,
    sent_count: usize,
    first_refusal: Option<super::pivot::FirstRefusal>,
    conflict_token_counts: BTreeMap<String, usize>,
    rate_limited_count: usize,
    max_outstanding_per_stream: Vec<usize>,
    max_outstanding_overall: usize,
    stream_sample_counts: Vec<usize>,
    durations: Vec<Duration>,
    completion_durations: Vec<Duration>,
    warmup_count: usize,
    warmup_elapsed: Duration,
    authority_log_wait_p99: u128,
    pilot: PublishPilot,
    pilot_p99: Duration,
    cycle_stall_bound: Duration,
    cycle_stalls: Vec<Duration>,
    cycle_ends: String,
    refusal_cycle_duration: Option<Duration>,
    depths: Vec<Option<u64>>,
    drain_timed_out: bool,
}

impl DenominatorAttempt {
    fn from_run(
        run: &super::pivot::OpenLoopRun,
        pilot: PublishPilot,
        authority_log_wait_p99: u128,
    ) -> Result<Self, String> {
        // Ten pilot-p99 cycles distinguish intermittent completion stalls
        // from the ordinary full-cycle distribution without gating the run.
        let cycle_stall_bound = pilot
            .p99
            .checked_mul(10)
            .ok_or_else(|| "pivot cycle stall bound overflow".to_owned())?;
        let stalls = |duration| duration > cycle_stall_bound;
        let cycle_stalls = run
            .cycle_durations
            .iter()
            .filter_map(|&(duration, _)| stalls(duration).then_some(duration))
            .collect();
        let ends = |only_stalls: bool| {
            run.cycle_durations
                .iter()
                .filter(|&&(duration, _)| !only_stalls || stalls(duration))
                .map(|(_, end)| end.as_nanos().to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        Ok(Self {
            rate: run.offered_rate,
            achieved_rate: run.achieved_rate,
            sent_count: run.sent_count,
            first_refusal: run.first_refusal.clone(),
            conflict_token_counts: run.conflict_token_counts.clone(),
            rate_limited_count: run.rate_limited_count,
            max_outstanding_per_stream: run.max_outstanding_per_stream.clone(),
            max_outstanding_overall: run.max_outstanding_overall,
            stream_sample_counts: run.stream_sample_counts.clone(),
            durations: run.durations.clone(),
            completion_durations: run.completion_durations.clone(),
            warmup_count: run.warmup_count,
            warmup_elapsed: run.warmup_elapsed,
            authority_log_wait_p99,
            pilot,
            pilot_p99: pilot.p99,
            cycle_stall_bound,
            cycle_stalls,
            cycle_ends: format!("{};{}", ends(false), ends(true)),
            refusal_cycle_duration: run.refusal_cycle_duration,
            depths: run.observations.clone(),
            drain_timed_out: run.drain_timed_out,
        })
    }

    fn qualifies(&self) -> bool {
        self.first_refusal.is_none() && super::pivot::denominator_is_steady(&self.durations)
    }

    fn outcome(&self) -> &'static str {
        self.first_refusal
            .as_ref()
            .map_or("passed", |refusal| refusal.kind)
    }

    fn first_refusal_ns(&self) -> u128 {
        self.first_refusal
            .as_ref()
            .map_or(0, |refusal| refusal.time.as_nanos())
    }

    fn response_tokens(&self) -> String {
        format_token_counts(&response_token_counts(
            &self.conflict_token_counts,
            self.rate_limited_count,
        ))
    }

    fn maximums(&self) -> String {
        self.max_outstanding_per_stream
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    fn cycle_stalls(&self) -> String {
        if self.cycle_stalls.is_empty() {
            return "none".to_owned();
        }
        self.cycle_stalls
            .iter()
            .map(|duration| duration.as_nanos().to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn refusal_cycle_duration(&self) -> String {
        let mut evidence = self
            .refusal_cycle_duration
            .map_or_else(|| "none".to_owned(), |d| d.as_nanos().to_string());
        if self.drain_timed_out {
            evidence.push_str(",pivot-request-drain-timeout");
        }
        evidence
    }
}

struct PopulatedOccupancy {
    principals: usize,
    row_holders: usize,
    live_roots: usize,
    released_rows: usize,
    root_bytes: usize,
    root_observation: Result<(&'static str, BTreeMap<usize, usize>), &'static str>,
    amplification: Amplification,
    register_samples: Vec<Duration>,
    register_lanes: Vec<(intent::Receipt, ClientSpkiDigest)>,
    publish_principal: PrincipalId,
    publish_digest: ClientSpkiDigest,
}

#[derive(Clone, Copy)]
struct PopulationShape {
    occupancy: Occupancy,
    row_holders: usize,
    live_roots: usize,
    released_rows: usize,
}

fn export_occupancy(name: &str, row: &OccupancyRow) {
    let mut fields = std::collections::BTreeMap::from([
        ("principals".to_owned(), row.principals.to_string()),
        ("row_holders".to_owned(), row.row_holders.to_string()),
        (
            "zero_row_principals".to_owned(),
            row.principals.saturating_sub(row.row_holders).to_string(),
        ),
        ("retired_principals".to_owned(), "0".to_owned()),
        (
            "historical_principals".to_owned(),
            row.principals.to_string(),
        ),
        ("live_roots".to_owned(), row.live_roots.to_string()),
        ("released_rows".to_owned(), row.released_rows.to_string()),
        ("root_label".to_owned(), row.root_label.to_owned()),
        ("root_bytes".to_owned(), row.root_bytes.to_string()),
        (
            "root_size_distribution".to_owned(),
            format_root_size_distribution(&row.root_size_distribution),
        ),
        ("store_kind".to_owned(), row.store_kind.clone()),
        ("log_filesystem".to_owned(), row.log_filesystem.clone()),
        (
            "written_bytes".to_owned(),
            row.amplification.written_bytes.to_string(),
        ),
        (
            "encode_register_bytes".to_owned(),
            row.amplification.encode_register_bytes.to_string(),
        ),
        (
            "full_snapshot_bytes".to_owned(),
            row.amplification.full_snapshot_bytes.to_string(),
        ),
        ("device_bytes".to_owned(), "unmeasured".to_owned()),
        (
            "device_amplification".to_owned(),
            "not-applicable".to_owned(),
        ),
        ("load_model".to_owned(), "closed-loop".to_owned()),
        ("pivot_input".to_owned(), "false".to_owned()),
    ]);
    super::output::distribution(
        &mut fields,
        "register_post",
        &row.register_samples
            .iter()
            .map(Duration::as_nanos)
            .collect::<Vec<_>>(),
    );
    super::output::write(name, &fields);
}

fn pivot_observation_fields(row: &OccupancyRow) -> BTreeMap<String, String> {
    let (warmup_count, warmup_elapsed) = row.pivot_run.as_ref().map_or_else(
        || {
            (
                row.diagnostic_run.warmup_count,
                row.diagnostic_run.warmup_elapsed,
            )
        },
        |run| (run.warmup_count, run.warmup_elapsed),
    );
    BTreeMap::from([
        (
            "pivot_stream_plan".to_owned(),
            "numerator=16;denominator=64@46,64@23,64@11.5".to_owned(),
        ),
        ("pivot_warmup_count".to_owned(), warmup_count.to_string()),
        (
            "pivot_warmup_elapsed_ns".to_owned(),
            warmup_elapsed.as_nanos().to_string(),
        ),
        ("principals".to_owned(), row.principals.to_string()),
        ("row_holders".to_owned(), row.row_holders.to_string()),
        (
            "zero_row_principals".to_owned(),
            row.principals.saturating_sub(row.row_holders).to_string(),
        ),
        ("retired_principals".to_owned(), "0".to_owned()),
        (
            "historical_principals".to_owned(),
            row.principals.to_string(),
        ),
        ("live_roots".to_owned(), row.live_roots.to_string()),
        ("released_rows".to_owned(), row.released_rows.to_string()),
        ("root_label".to_owned(), row.root_label.to_owned()),
        ("root_bytes".to_owned(), row.root_bytes.to_string()),
        (
            "root_size_distribution".to_owned(),
            format_root_size_distribution(&row.root_size_distribution),
        ),
    ])
}

fn format_root_size_distribution(distribution: &BTreeMap<usize, usize>) -> String {
    distribution
        .iter()
        .map(|(size, count)| format!("{size}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_token_counts(counts: &BTreeMap<String, usize>) -> String {
    if counts.is_empty() {
        return "none".to_owned();
    }
    counts
        .iter()
        .map(|(token, count)| format!("{token}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn response_token_counts(
    conflicts: &BTreeMap<String, usize>,
    rate_limited: usize,
) -> BTreeMap<String, usize> {
    let mut counts = conflicts.clone();
    if rate_limited > 0 {
        counts.insert("rate-limited".to_owned(), rate_limited);
    }
    counts
}

fn denominator_depth_fields(attempts: &[DenominatorAttempt]) -> BTreeMap<String, String> {
    let records = attempts
        .iter()
        .map(|attempt| {
            attempt
                .depths
                .iter()
                .enumerate()
                .map(|(index, depth)| {
                    let Some(depth) = depth else {
                        return "none".to_owned();
                    };
                    let phase = if index < PIVOT_WARMUP_REQUESTS {
                        "warmup"
                    } else {
                        "measured"
                    };
                    format!("{index},{},{phase},{depth}", index % MAX_PUBLISH_STREAMS)
                })
                .collect::<Vec<_>>()
                .join(";")
        })
        .collect::<Vec<_>>()
        .join("|");
    let bounds = attempts
        .iter()
        .map(|attempt| observation_range(&attempt.depths))
        .collect::<Vec<_>>()
        .join("|");
    BTreeMap::from([
        ("denominator_attempt_depth_records".to_owned(), records),
        ("denominator_attempt_depth_bounds".to_owned(), bounds),
    ])
}

fn diagnostic_depth_field(start: usize, count: usize) -> [(String, String); 1] {
    let bounds = if count == 0 {
        "none".to_owned()
    } else {
        format!("{start},{}", start + count - 1)
    };
    [("diagnostic_depth_range".to_owned(), bounds)]
}

fn observation_range(values: &[Option<u64>]) -> String {
    let mut observed = values.iter().flatten();
    observed.next().map_or_else(
        || "none".to_owned(),
        |first| {
            let (min, max) = observed.fold((*first, *first), |(min, max), &value| {
                (min.min(value), max.max(value))
            });
            format!("{min},{max}")
        },
    )
}

fn numerator_scope_fields(
    run: &super::pivot::OpenLoopRun,
    intent_log_bytes: u64,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "numerator_generation_range".to_owned(),
            observation_range(&run.observations),
        ),
        (
            "numerator_intent_log_bytes".to_owned(),
            intent_log_bytes.to_string(),
        ),
    ])
}

fn denominator_attempt_fields(attempts: &[DenominatorAttempt]) -> BTreeMap<String, String> {
    let join = |values: Vec<String>| values.join("|");
    let mut fields = BTreeMap::from([
        (
            "denominator_attempt_rates".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| attempt.rate.to_string())
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_warmups".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| {
                        format!(
                            "{},{}",
                            attempt.warmup_count,
                            attempt.warmup_elapsed.as_nanos()
                        )
                    })
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_outcomes".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| attempt.outcome().to_owned())
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_sent_counts".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| attempt.sent_count.to_string())
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_first_refusal_ns".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| attempt.first_refusal_ns().to_string())
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_conflict_tokens".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| format_token_counts(&attempt.conflict_token_counts))
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_response_tokens".to_owned(),
            join(
                attempts
                    .iter()
                    .map(DenominatorAttempt::response_tokens)
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_rate_limited_counts".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| attempt.rate_limited_count.to_string())
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_max_outstanding".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| attempt.max_outstanding_overall.to_string())
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_max_outstanding_per_stream".to_owned(),
            join(attempts.iter().map(DenominatorAttempt::maximums).collect()),
        ),
    ]);
    fields.extend(denominator_cycle_fields(attempts));
    fields.extend(denominator_depth_fields(attempts));
    fields.extend(denominator_sample_fields(attempts));
    fields
}

fn denominator_sample_fields(attempts: &[DenominatorAttempt]) -> BTreeMap<String, String> {
    let join = |values: Vec<String>| values.join("|");
    let samples = |suffix: &str, select: fn(&DenominatorAttempt) -> &[Duration]| {
        attempts
            .iter()
            .enumerate()
            .map(|(index, attempt)| {
                let values: Vec<_> = select(attempt).iter().map(Duration::as_nanos).collect();
                super::output::write_samples(
                    &format!("pivot-denominator-attempt-{index}-{suffix}"),
                    &values,
                )
            })
            .collect()
    };
    BTreeMap::from([
        (
            "denominator_attempt_achieved_rates".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| attempt.achieved_rate.to_string())
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_stream_sample_counts".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| {
                        attempt
                            .stream_sample_counts
                            .iter()
                            .map(usize::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_sample_files".to_owned(),
            join(samples("decision", |attempt| &attempt.durations)),
        ),
        (
            "denominator_attempt_sample_counts".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| attempt.durations.len().to_string())
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_completion_files".to_owned(),
            join(samples("completion", |attempt| {
                &attempt.completion_durations
            })),
        ),
        (
            "denominator_attempt_completion_counts".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| attempt.completion_durations.len().to_string())
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_log_wait_p99_ns".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| attempt.authority_log_wait_p99.to_string())
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_pilot_observations".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| {
                        format!(
                            "{},{},{},{},{}",
                            attempt.pilot.sample_count,
                            attempt.pilot.p50.as_nanos(),
                            attempt.pilot.p99.as_nanos(),
                            attempt.pilot.max.as_nanos(),
                            attempt.pilot.stream_count,
                        )
                    })
                    .collect(),
            ),
        ),
    ])
}

fn denominator_cycle_fields(attempts: &[DenominatorAttempt]) -> BTreeMap<String, String> {
    let join = |values: Vec<String>| values.join("|");
    BTreeMap::from([
        (
            "denominator_attempt_pilot_p99_ns".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| attempt.pilot_p99.as_nanos().to_string())
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_cycle_stall_bound_ns".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| attempt.cycle_stall_bound.as_nanos().to_string())
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_cycle_stall_counts".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| attempt.cycle_stalls.len().to_string())
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_cycle_stall_ns".to_owned(),
            join(
                attempts
                    .iter()
                    .map(|attempt| format!("{};{}", attempt.cycle_stalls(), attempt.cycle_ends))
                    .collect(),
            ),
        ),
        (
            "denominator_attempt_refusal_cycle_ns".to_owned(),
            join(
                attempts
                    .iter()
                    .map(DenominatorAttempt::refusal_cycle_duration)
                    .collect(),
            ),
        ),
    ])
}

fn diagnostic_fields(run: &DiagnosticRun, p99: u128) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "diagnostic_outcome".to_owned(),
            if run.stall_index.is_some() {
                "stalled"
            } else {
                "complete"
            }
            .to_owned(),
        ),
        (
            "diagnostic_completed_count".to_owned(),
            (run.warmup_count + run.durations.len()).to_string(),
        ),
        (
            "diagnostic_stall_index".to_owned(),
            run.stall_index
                .map_or_else(|| "none".to_owned(), |value| value.to_string()),
        ),
        (
            "diagnostic_stall_phase".to_owned(),
            run.stall_phase.unwrap_or("none").to_owned(),
        ),
        (
            "diagnostic_publish_bound_ns".to_owned(),
            PUBLISH_DIAGNOSTIC_TIMEOUT.as_nanos().to_string(),
        ),
        (
            "diagnostic_publish_censored_count".to_owned(),
            run.publish_censored.to_string(),
        ),
        (
            "diagnostic_publish_p99_report".to_owned(),
            if run.stall_index.is_some() {
                "stalled".to_owned()
            } else if !run.durations.is_empty() && run.publish_censored * 100 > run.durations.len()
            {
                format!("> {}", PUBLISH_DIAGNOSTIC_TIMEOUT.as_nanos())
            } else {
                p99.to_string()
            },
        ),
        (
            "diagnostic_publish_stalls".to_owned(),
            run.publish_stalls.len().to_string(),
        ),
        (
            "diagnostic_publish_stall_ns".to_owned(),
            if run.publish_stalls.is_empty() {
                "none".to_owned()
            } else {
                run.publish_stalls
                    .iter()
                    .map(|duration| duration.as_nanos().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            },
        ),
        (
            "diagnostic_warmup_publish_stalls".to_owned(),
            run.warmup_publish_stalls.len().to_string(),
        ),
        (
            "diagnostic_warmup_publish_stall_ns".to_owned(),
            if run.warmup_publish_stalls.is_empty() {
                "none".to_owned()
            } else {
                run.warmup_publish_stalls
                    .iter()
                    .map(|duration| duration.as_nanos().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            },
        ),
        (
            "diagnostic_completion_bound_ns".to_owned(),
            PUBLISH_DIAGNOSTIC_COMPLETION_TIMEOUT.as_nanos().to_string(),
        ),
        (
            "diagnostic_completion_stalls".to_owned(),
            run.completion_stalls.len().to_string(),
        ),
        (
            "diagnostic_completion_stall_ns".to_owned(),
            if run.completion_stalls.is_empty() {
                "none".to_owned()
            } else {
                run.completion_stalls
                    .iter()
                    .map(|duration| duration.as_nanos().to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            },
        ),
        (
            "diagnostic_completion_stall_issue".to_owned(),
            "#832".to_owned(),
        ),
    ])
}

fn pivot_execution_fields(
    diagnostic: bool,
    sample_count: usize,
    run: Option<&super::pivot::OpenLoopRun>,
    principal_submission_limit: u64,
    principal_in_flight_limit: usize,
    per_stream_offered_rate: Option<f64>,
) -> Result<BTreeMap<String, String>, String> {
    if diagnostic {
        return Ok(BTreeMap::from([
            ("pivot_input".to_owned(), "false".to_owned()),
            ("stream_count".to_owned(), "1".to_owned()),
            ("stream_sample_counts".to_owned(), sample_count.to_string()),
            (
                "diagnostic_label".to_owned(),
                "not at the offered rate; diagnostic only; not a comparator input".to_owned(),
            ),
        ]));
    }
    let run = run.ok_or_else(|| "pivot open-loop observation missing".to_owned())?;
    let per_stream_offered_rate = per_stream_offered_rate
        .ok_or_else(|| "pivot per-stream offered rate missing".to_owned())?;
    Ok(BTreeMap::from([
        ("pivot_input".to_owned(), "true".to_owned()),
        ("offered_rate".to_owned(), run.offered_rate.to_string()),
        ("achieved_rate".to_owned(), run.achieved_rate.to_string()),
        (
            "max_send_lateness_ns".to_owned(),
            run.max_send_lateness.as_nanos().to_string(),
        ),
        (
            "late_send_count".to_owned(),
            run.late_send_count.to_string(),
        ),
        (
            "completed_in_window".to_owned(),
            run.completed_in_window.to_string(),
        ),
        ("failure_count".to_owned(), run.failure_count.to_string()),
        ("sent_count".to_owned(), run.sent_count.to_string()),
        (
            "first_refusal".to_owned(),
            run.first_refusal
                .as_ref()
                .map_or("none", |refusal| refusal.kind)
                .to_owned(),
        ),
        (
            "time_to_first_refusal_ns".to_owned(),
            run.first_refusal
                .as_ref()
                .map_or(0, |refusal| refusal.time.as_nanos())
                .to_string(),
        ),
        (
            "conflict_token_counts".to_owned(),
            format_token_counts(&run.conflict_token_counts),
        ),
        (
            "response_token_counts".to_owned(),
            format_token_counts(&response_token_counts(
                &run.conflict_token_counts,
                run.rate_limited_count,
            )),
        ),
        (
            "rate_limited_count".to_owned(),
            run.rate_limited_count.to_string(),
        ),
        (
            "max_outstanding_overall".to_owned(),
            run.max_outstanding_overall.to_string(),
        ),
        (
            "max_outstanding_per_stream".to_owned(),
            run.max_outstanding_per_stream
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ),
        (
            "principal_submission_limit".to_owned(),
            principal_submission_limit.to_string(),
        ),
        (
            "principal_in_flight_limit".to_owned(),
            principal_in_flight_limit.to_string(),
        ),
        (
            "per_stream_offered_rate".to_owned(),
            per_stream_offered_rate.to_string(),
        ),
        (
            "stream_count".to_owned(),
            run.stream_sample_counts.len().to_string(),
        ),
        (
            "stream_sample_counts".to_owned(),
            run.stream_sample_counts
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ),
    ]))
}

fn denominator_result_fields(attempts: &[DenominatorAttempt]) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    fields.extend(denominator_attempt_fields(attempts));
    fields.insert(
        "denominator_cycle_stall_issue".to_owned(),
        "#832".to_owned(),
    );
    fields
}

fn publish_pilot_fields(pilot: Option<PublishPilot>) -> BTreeMap<String, String> {
    pilot.map_or_else(BTreeMap::new, |pilot| {
        BTreeMap::from([
            (
                "pilot_sample_count".to_owned(),
                pilot.sample_count.to_string(),
            ),
            ("pilot_p50_ns".to_owned(), pilot.p50.as_nanos().to_string()),
            ("pilot_p99_ns".to_owned(), pilot.p99.as_nanos().to_string()),
            ("pilot_max_ns".to_owned(), pilot.max.as_nanos().to_string()),
            (
                "pilot_stream_count".to_owned(),
                pilot.stream_count.to_string(),
            ),
            (
                "pilot_sizing_basis".to_owned(),
                "observation-only-fixed-rate-pool".to_owned(),
            ),
        ])
    })
}

fn authority_log_wait_p99(samples: &[Duration]) -> Result<Option<String>, String> {
    if samples.is_empty() {
        return Ok(None);
    }
    let values: Vec<_> = samples.iter().map(Duration::as_nanos).collect();
    super::output::quantile(&values, 99)
        .map(|value| Some(value.to_string()))
        .map_err(str::to_owned)
}

fn write_completion_samples(
    name: &str,
    role: &str,
    terminal: bool,
    run: Option<&super::pivot::OpenLoopRun>,
    duration_count: usize,
) -> Result<Option<(String, usize)>, String> {
    if role != "denominator" || terminal {
        return Ok(None);
    }
    let completion = &run
        .ok_or_else(|| "pivot open-loop observation missing".to_owned())?
        .completion_durations;
    if completion.len() != duration_count {
        return Err("pivot publication completion samples missing".to_owned());
    }
    let values: Vec<_> = completion.iter().map(Duration::as_nanos).collect();
    Ok(Some((
        super::output::write_samples(&format!("{name}-completion"), &values),
        values.len(),
    )))
}

fn export_pivot(
    name: &str,
    profile: Profile,
    occupancy: Occupancy,
    row: &OccupancyRow,
) -> Result<(), String> {
    let role = match (profile, occupancy) {
        (Profile::DurablePrepared, Occupancy::Ceiling) => "numerator",
        (Profile::Published, Occupancy::Floor) => "denominator",
        (Profile::Published, Occupancy::Ceiling) => "diagnostic",
        _ => "non-pivot",
    };
    let diagnostic = role == "diagnostic";
    let terminal = role == "denominator"
        && !row.denominator_attempts.is_empty()
        && row
            .denominator_attempts
            .iter()
            .all(|attempt| !attempt.qualifies());
    let diagnostic_stalled = diagnostic && row.diagnostic_run.stall_index.is_some();
    let run = row.pivot_run.as_ref();
    let durations = if diagnostic {
        &row.diagnostic_run.durations
    } else {
        &run.ok_or_else(|| "pivot open-loop observation missing".to_owned())?
            .durations
    };
    if durations.is_empty() && !terminal && !diagnostic_stalled {
        return Err("pivot sample population missing".to_owned());
    }
    let samples: Vec<_> = durations.iter().map(Duration::as_nanos).collect();
    let sample_file = if terminal {
        "not-applicable".to_owned()
    } else {
        super::output::write_samples(name, &samples)
    };
    let completion_file = write_completion_samples(name, role, terminal, run, durations.len())?;
    let route = if profile == Profile::DurablePrepared {
        "/volume/:volume/intent"
    } else {
        "/volume/:volume/publish"
    };
    let p99 = if terminal || diagnostic_stalled {
        0
    } else {
        super::output::quantile(&samples, 99).map_err(str::to_owned)?
    };
    let mut fields = std::collections::BTreeMap::from([
        ("profile".to_owned(), format!("{profile:?}")),
        ("occupancy".to_owned(), format!("{occupancy:?}")),
        ("pivot_role".to_owned(), role.to_owned()),
        ("route".to_owned(), route.to_owned()),
        (
            "load_model".to_owned(),
            if diagnostic {
                "closed-loop-serial"
            } else {
                "open-loop"
            }
            .to_owned(),
        ),
        ("store_kind".to_owned(), row.store_kind.clone()),
        ("log_filesystem".to_owned(), row.log_filesystem.clone()),
        ("wrapper_layer".to_owned(), "server-service".to_owned()),
        ("sample_count".to_owned(), samples.len().to_string()),
        (
            "committed_transitions".to_owned(),
            row.committed_transitions.to_string(),
        ),
        ("samples_file".to_owned(), sample_file),
        ("p99_ns".to_owned(), p99.to_string()),
    ]);
    if let Some((file, count)) = completion_file {
        fields.insert("completion_samples_file".to_owned(), file);
        fields.insert("completion_sample_count".to_owned(), count.to_string());
    }
    fields.extend(pivot_execution_fields(
        diagnostic,
        samples.len(),
        run,
        row.principal_submission_limit,
        row.principal_in_flight_limit,
        row.per_stream_offered_rate,
    )?);
    fields.extend(pivot_observation_fields(row));
    if diagnostic {
        fields.extend(diagnostic_fields(&row.diagnostic_run, p99));
        fields.extend(diagnostic_depth_field(
            row.diagnostic_run.warmup_count,
            durations.len(),
        ));
    }
    if role == "denominator" {
        fields.extend(denominator_result_fields(&row.denominator_attempts));
    }
    if let (Some(run), Some(bytes)) = (run, row.intent_log_bytes) {
        fields.extend(numerator_scope_fields(run, bytes));
    }
    fields.extend(publish_pilot_fields(row.publish_pilot));
    if let Some(log_wait) = authority_log_wait_p99(&row.authority_log_wait_samples)? {
        fields.insert("authority_log_wait_p99_ns".to_owned(), log_wait);
    }
    super::output::write(name, &fields);
    Ok(())
}

impl Amplification {
    fn from_register(
        written_bytes: usize,
        full_snapshot_bytes: usize,
        receipt: intent::Receipt,
        generation: u64,
        root: &[u8],
    ) -> Result<Self, String> {
        let encoded = intent::encode_register(
            &receipt.writer,
            receipt.epoch,
            &receipt.instance,
            generation,
            root,
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            written_bytes,
            encode_register_bytes: encoded.len(),
            full_snapshot_bytes,
        })
    }

    fn written_ratio(self) -> (usize, usize) {
        (self.written_bytes, self.encode_register_bytes)
    }
}

fn root_label<'a>(
    requested: &'a str,
    roots: &[&[u8]],
    keys: &TrustedKeys,
) -> Result<&'a str, &'static str> {
    if roots.is_empty() {
        return Err("root label requires a nonempty live-root population");
    }
    for bytes in roots {
        let doc = root::decode_root(bytes).map_err(|_| "root label requires accepted v1 roots")?;
        check_signatures(&doc, bytes, keys).map_err(|_| "root label requires accepted v1 roots")?;
    }
    if requested == "707-B"
        && roots
            .iter()
            .any(|root| root.len() != root::ROOT_V1_MAX_ENCODABLE)
    {
        return Err("707-B label requires every live root to be exactly 707 bytes");
    }
    Ok(requested)
}

fn observe_root_population(
    occupancy: Occupancy,
    roots: &[&[u8]],
    keys: &TrustedKeys,
) -> Result<(&'static str, BTreeMap<usize, usize>), &'static str> {
    let requested = if occupancy == Occupancy::Floor {
        "measured length"
    } else {
        "707-B"
    };
    let label = root_label(requested, roots, keys)?;
    let mut distribution = BTreeMap::new();
    for bytes in roots {
        *distribution.entry(bytes.len()).or_default() += 1;
    }
    Ok((label, distribution))
}

fn run_p99(run: RecordedRun<'_>) -> Result<Duration, &'static str> {
    let values: Vec<_> = run.samples.iter().map(Duration::as_nanos).collect();
    let nanos = super::output::quantile(&values, 99).map_err(|_| "pivot row has no samples")?;
    u64::try_from(nanos)
        .map(Duration::from_nanos)
        .map_err(|_| "pivot p99 exceeds the duration range")
}

/// Validate the two inputs before the authoritative Python receipt comparator
/// applies its numeric rule.
fn pivot_inputs(
    register: RecordedRun<'_>,
    publish: RecordedRun<'_>,
) -> Result<(Duration, Duration), &'static str> {
    if register.profile != Profile::DurablePrepared
        || register.occupancy != Occupancy::Ceiling
        || register.route != "/volume/:volume/intent"
        || publish.profile != Profile::Published
        || publish.occupancy != Occupancy::Floor
        || publish.route != "/volume/:volume/publish"
    {
        return Err("pivot roles or occupancy differ from the ruled pair");
    }
    if register.load_model != "open-loop" || publish.load_model != "open-loop" {
        return Err("closed-loop row cannot be a pivot input");
    }
    if register.offered_rate != publish.offered_rate
        || register.medium != publish.medium
        || register.wrapper != publish.wrapper
    {
        return Err("pivot offered load, medium, or wrapper differs");
    }
    Ok((run_p99(register)?, run_p99(publish)?))
}

fn maximal_root(volume: &VolumeName, sequence: u64) -> (Vec<u8>, TrustedKeys) {
    let signer = super::super::publisher();
    let mut doc = RootDoc {
        volume: volume.clone(),
        seq: sequence,
        parent: Some(GrainId::of(b"parent")),
        writer_uuid: [1; 16],
        epoch: 2,
        timestamp: Timestamp { secs: 1, nanos: 0 },
        chunker_spec: "x".repeat(root::CHUNKER_SPEC_MAX),
        manifest_root: GrainId::of(b"manifest"),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![
            RootSig {
                key_id: signer.key_id(),
                sig: [0; 64],
            },
            RootSig {
                key_id: [0x77; 32],
                sig: [0; 64],
            },
        ],
    };
    let unsigned = root::encode_root(&doc).unwrap();
    doc.sigs.first_mut().unwrap().sig = signer.sign(root::signed_prefix(&unsigned).unwrap());
    let encoded = root::encode_root(&doc).unwrap();
    let keys = TrustedKeys::new([*signer.public_key()]).unwrap();
    (encoded, keys)
}

fn observed_filesystem(path: &Path) -> Result<String, String> {
    let output = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "--target"])
        .arg(path)
        .output()
        .map_err(|error| format!("pivot cannot run findmnt: {error}"))?;
    if !output.status.success() {
        return Err("pivot findmnt failed".to_owned());
    }
    let filesystem = String::from_utf8(output.stdout)
        .map_err(|_| "pivot findmnt output is not UTF-8".to_owned())?
        .trim()
        .to_owned();
    if filesystem.is_empty() || filesystem.contains(char::is_whitespace) {
        return Err("pivot findmnt output is invalid".to_owned());
    }
    Ok(filesystem)
}

fn enrollment(offset: u128, count: usize, retired: usize) -> EnrollmentSet {
    assert!(retired <= count);
    let tenant = TenantName::new(b"measure").unwrap();
    let mut set = EnrollmentSet::empty();
    for index in 0..count {
        let ordinal = offset
            .checked_add(u128::try_from(index).expect("measurement principal index fits"))
            .expect("measurement principal ordinal fits");
        let (principal, digest) = identity(ordinal);
        set.mint(principal, tenant.clone(), digest).unwrap();
        if index < retired {
            set.revoke(&digest).unwrap();
            set.retire(&principal).unwrap();
        }
    }
    set
}

fn volume_enrollments(
    principals: usize,
    volume_count: usize,
    distinct_floor_principals: bool,
) -> Result<(EnrollmentSet, Vec<EnrollmentSet>), String> {
    let enrolled_principals = if distinct_floor_principals {
        volume_count
    } else {
        principals
    };
    let enrolled = enrollment(0, enrolled_principals, 0);
    let volumes = if distinct_floor_principals {
        (0..volume_count)
            .map(|index| {
                u128::try_from(index)
                    .map(|offset| enrollment(offset, 1, 0))
                    .map_err(|_| "pivot volume index exceeds u128".to_owned())
            })
            .collect::<Result<_, _>>()?
    } else {
        vec![enrolled.clone(); volume_count]
    };
    Ok((enrolled, volumes))
}

fn identity(ordinal: u128) -> (PrincipalId, ClientSpkiDigest) {
    let bytes = ordinal.to_be_bytes();
    let mut digest = [0_u8; 32];
    digest[16..].copy_from_slice(&bytes);
    (
        PrincipalId::from_bytes(bytes),
        ClientSpkiDigest::from_bytes(digest),
    )
}

async fn intent_post<S>(
    fixture: &super::rows::Fixture<S>,
    volume: &VolumeName,
    digest: ClientSpkiDigest,
    suffix: &str,
    body: Vec<u8>,
) -> (Duration, Vec<u8>)
where
    S: granary_core::rootstore::RootStore + granary_core::binstore::BinStore + 'static,
{
    let request = intent_request(volume, digest, suffix, body);
    let started = super::stopwatch();
    let response = fixture.send(request).await;
    let elapsed = started.elapsed();
    assert_eq!(response.status(), 200);
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|never| match never {})
        .to_bytes()
        .to_vec();
    (elapsed, body)
}

fn intent_request(
    volume: &VolumeName,
    digest: ClientSpkiDigest,
    suffix: &str,
    body: Vec<u8>,
) -> Request<Full<Bytes>> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(format!("/volume/{}/intent{suffix}", volume.as_str()))
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    request
        .extensions_mut()
        .insert(granary_net::identity::ConnectionIdentity::Verified(digest));
    request
}

#[expect(
    clippy::too_many_lines,
    reason = "the occupied volume's HTTP transitions and read-back stay together"
)]
async fn populate_occupancy<S>(
    fixture: &Arc<super::rows::Fixture<S>>,
    progress_record: &Arc<std::sync::Mutex<PivotProgress>>,
    volume: &VolumeName,
    set: &EnrollmentSet,
    shape: PopulationShape,
) -> PopulatedOccupancy
where
    S: granary_core::rootstore::RootStore + granary_core::binstore::BinStore + 'static,
{
    use super::io::Call;

    let (root, keys) = maximal_root(volume, 2);
    assert_eq!(
        fixture
            .handle
            .maintain_intents(volume, set, 0)
            .await
            .status()
            .as_u16(),
        200
    );
    progress(progress_record, |record| {
        record.principals_enrolled(set.principal_count());
    });
    let mut register_samples = Vec::new();
    let mut register_lanes = Vec::with_capacity(shape.row_holders);
    let mut last_register = None;
    let principal_credentials: Vec<_> = set.credentials().collect();
    for principal_ordinal in 0..shape.row_holders {
        let (digest, principal) = *principal_credentials
            .get(principal_ordinal)
            .expect("row holder has an enrolled credential");
        let mut cursor = 0_u64;
        for writer_ordinal in 0..shape.released_rows + shape.live_roots {
            let writer = [u8::try_from(writer_ordinal + 1).unwrap(); 16];
            let ownership = intent::encode_ownership(Ownership {
                writer,
                instance: [3; 16],
                mode: OwnershipMode::Acquire {
                    observed_cursor: cursor,
                },
            })
            .unwrap();
            let (_, grant) = intent_post(fixture, volume, digest, "/ownership", ownership).await;
            let receipt = intent::decode_grant(&grant).unwrap().receipt;
            cursor = receipt.epoch;
            let register = intent::encode_register(
                &receipt.writer,
                receipt.epoch,
                &receipt.instance,
                1,
                &root,
            )
            .unwrap();
            fixture.io.bytes();
            let (elapsed, _) = intent_post(fixture, volume, digest, "", register).await;
            register_samples.push(elapsed);
            let written = fixture.io.bytes()[Call::IntentWrite as usize];
            last_register = Some((written, receipt, principal, digest));
            if writer_ordinal < shape.released_rows {
                let release = intent::encode_release(Release {
                    writer: receipt.writer,
                    epoch: receipt.epoch,
                    instance: receipt.instance,
                    generation: 2,
                })
                .unwrap();
                intent_post(fixture, volume, digest, "/release", release).await;
            } else if writer_ordinal + 1 == shape.released_rows + shape.live_roots {
                register_lanes.push((receipt, digest));
            }
            progress(progress_record, PivotProgress::intent_row_prepared);
        }
    }
    let (snapshot, snapshot_bytes) = committed_snapshot(&fixture.config.state_dir, volume);
    let principals = snapshot.principals.len();
    let observed_row_holders = snapshot
        .principals
        .values()
        .filter(|principal| !principal.rows.is_empty())
        .count();
    let observed_live_roots = snapshot
        .principals
        .values()
        .flat_map(|principal| principal.rows.values())
        .filter(|row| !row.root.is_empty())
        .count();
    let observed_released_rows = snapshot
        .principals
        .values()
        .flat_map(|principal| principal.rows.values())
        .filter(|row| row.root.is_empty())
        .count();
    let roots = fixture.handle.intent_roots(volume).await.unwrap();
    assert_eq!(roots.len(), observed_live_roots);
    let root_observation = observe_root_population(
        shape.occupancy,
        &roots
            .iter()
            .map(|item| item.bytes.as_ref())
            .collect::<Vec<_>>(),
        &keys,
    );
    let (written, receipt, publish_principal, publish_digest) =
        last_register.expect("occupancy row has a register transition");
    let amplification =
        Amplification::from_register(written, snapshot_bytes, receipt, 1, &root).unwrap();
    progress(progress_record, PivotProgress::volume_prepared);
    PopulatedOccupancy {
        principals,
        row_holders: observed_row_holders,
        live_roots: observed_live_roots,
        released_rows: observed_released_rows,
        root_bytes: root.len(),
        root_observation,
        amplification,
        register_samples,
        register_lanes,
        publish_principal,
        publish_digest,
    }
}

async fn stop_occupancy_fixture<S>(
    fixture: &super::rows::Fixture<S>,
    running: std::thread::JoinHandle<super::super::RunEnd>,
) where
    S: granary_core::rootstore::RootStore + granary_core::binstore::BinStore + 'static,
{
    fixture.handle.stop().await;
    assert_eq!(running.join().unwrap(), super::super::RunEnd::Stopped);
}

fn pivot_capture(count: usize) -> Result<super::capture::Capture, String> {
    // A publish can gate at most one decision, one attestation and one
    // terminal outcome; an intent register gates only its snapshot commit.
    // Three log-wait slots per scheduled request therefore bounds both rows.
    // Ten percent spare covers the terminal span racing the last request's
    // receipt without turning capture loss into an accepted measurement.
    let bound = count
        .checked_mul(3)
        .filter(|capacity| *capacity > 0)
        .ok_or_else(|| "pivot span capture capacity invalid".to_owned())?;
    let capacity = bound
        .checked_add(bound.div_ceil(10))
        .ok_or_else(|| "pivot span capture capacity invalid".to_owned())?;
    Ok(super::capture::Capture::authority_log_wait(capacity))
}

fn require_pivot_capture(lost: usize) -> Result<(), String> {
    if lost == 0 {
        Ok(())
    } else {
        Err(format!("pivot-span-capture-lost: {lost}"))
    }
}

fn per_stream_offered_rate(
    offered_rate: f64,
    stream_count: usize,
    principal_limit: u64,
) -> Result<f64, String> {
    let streams = u64::try_from(stream_count)
        .ok()
        .filter(|streams| *streams > 0)
        .ok_or_else(|| "pivot publish stream population missing".to_owned())?;
    let streams_u32 = u32::try_from(streams)
        .map_err(|_| "pivot publish stream population exceeds u32".to_owned())?;
    let principal_limit_u32 = u32::try_from(principal_limit)
        .map_err(|_| "pivot principal limit exceeds u32".to_owned())?;
    if offered_rate > f64::from(principal_limit_u32) * f64::from(streams_u32) {
        return Err(format!(
            "pivot per-stream submission rate exceeds principal limit: offered_rate={offered_rate}, streams={stream_count}, limit={principal_limit}"
        ));
    }
    Ok(offered_rate / f64::from(streams_u32))
}

fn require_distinct_stream_principals(
    targets: &[(VolumeName, Epoch, PrincipalId, ClientSpkiDigest)],
) -> Result<(), String> {
    let distinct: BTreeSet<_> = targets
        .iter()
        .map(|(_, _, principal, _)| *principal)
        .collect();
    if distinct.len() == targets.len() {
        Ok(())
    } else {
        Err(format!(
            "pivot publish stream principals not distinct: streams={}, principals={}",
            targets.len(),
            distinct.len()
        ))
    }
}

fn publish_pilot_summary(
    samples: &[Duration],
    stream_count: usize,
) -> Result<PublishPilot, String> {
    if samples.len() < PUBLISH_PILOT_SAMPLES {
        return Err(format!(
            "pivot publish pilot population insufficient: samples={}, minimum={PUBLISH_PILOT_SAMPLES}",
            samples.len()
        ));
    }
    let nanos: Vec<_> = samples.iter().map(Duration::as_nanos).collect();
    let p50_ns = super::output::quantile(&nanos, 50).map_err(str::to_owned)?;
    // Nearest-rank p99 is an observed order statistic, never interpolation.
    let p99_ns = super::output::quantile(&nanos, 99).map_err(str::to_owned)?;
    let max_ns = nanos
        .iter()
        .copied()
        .max()
        .ok_or_else(|| "pivot publish pilot population missing".to_owned())?;
    Ok(PublishPilot {
        sample_count: samples.len(),
        p50: Duration::from_nanos(
            p50_ns
                .try_into()
                .map_err(|_| "pivot publish pilot p50 exceeds u64")?,
        ),
        p99: Duration::from_nanos(
            p99_ns
                .try_into()
                .map_err(|_| "pivot publish pilot p99 exceeds u64")?,
        ),
        max: Duration::from_nanos(
            max_ns
                .try_into()
                .map_err(|_| "pivot publish pilot maximum exceeds u64")?,
        ),
        // The pilot characterizes the cycle but cannot size the ruled pool.
        stream_count,
    })
}

async fn send_publish<S>(
    fixture: &super::rows::Fixture<S>,
    volume: &VolumeName,
    epoch: Epoch,
    digest: ClientSpkiDigest,
    operation: u64,
    bytes: Vec<u8>,
) -> Result<u64, super::pivot::RequestFailure>
where
    S: granary_core::rootstore::RootStore + granary_core::binstore::BinStore + 'static,
{
    let owned = granary_client::OwnedCandidate::new(volume.as_str(), Arc::from(bytes.clone()))
        .map_err(|_| super::pivot::RequestFailure::Other("pivot publish candidate invalid"))?;
    let expected = granary_client::PublishRequest::new(
        volume.as_str(),
        epoch,
        &operation.to_be_bytes(),
        owned.clone(),
        vec![owned],
    )
    .map_err(|_| super::pivot::RequestFailure::Other("pivot publish request invalid"))?;
    let mut request = super::rows::publish_in_epoch(volume, epoch, operation, bytes);
    request
        .extensions_mut()
        .insert(granary_net::identity::ConnectionIdentity::Verified(digest));
    let response = fixture.send(request).await;
    let token = response
        .headers()
        .get("granary-error")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let code = response.status().as_u16();
    if let Some(refusal) = pivot_publish_refusal(code, token.as_deref()) {
        return Err(refusal);
    }
    let media = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let answer = response
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|never| match never {})
        .to_bytes();
    super::hostile::checked_publish(&expected, code, token.as_deref(), media.as_deref(), &answer)
        .map(|()| expected.candidate().seq())
        .map_err(super::pivot::RequestFailure::Other)
}

async fn publish_stream_cycle<S>(
    fixture: &super::rows::Fixture<S>,
    volume: &VolumeName,
    epoch: Epoch,
    publish: impl Future<Output = Result<u64, super::pivot::RequestFailure>>,
) -> Result<super::pivot::RequestTiming, super::pivot::RequestFailure>
where
    S: granary_core::rootstore::RootStore + granary_core::binstore::BinStore + 'static,
{
    Box::pin(timed_publish_cycle(publish, async {
        fixture
            .complete(volume, epoch)
            .await
            .map_err(|_| super::pivot::RequestFailure::Other("pivot publication completion failed"))
    }))
    .await
}

async fn timed_publish_cycle<P, C>(
    publish: P,
    complete: C,
) -> Result<super::pivot::RequestTiming, super::pivot::RequestFailure>
where
    P: Future<Output = Result<u64, super::pivot::RequestFailure>>,
    C: Future<Output = Result<(), super::pivot::RequestFailure>>,
{
    let decision_started = super::stopwatch();
    publish.await?;
    let decision = decision_started.elapsed();
    let completion_started = super::stopwatch();
    complete.await?;
    Ok(super::pivot::RequestTiming::publish(
        decision,
        completion_started.elapsed(),
    ))
}

fn pivot_publish_refusal(code: u16, token: Option<&str>) -> Option<super::pivot::RequestFailure> {
    match code {
        409 => Some(super::pivot::RequestFailure::Conflict(
            token.unwrap_or("missing").to_owned(),
        )),
        429 => Some(super::pivot::RequestFailure::RateLimited),
        _ => None,
    }
}

async fn serial_publish_pilot<S>(
    fixture: &super::rows::Fixture<S>,
    progress_record: &Arc<std::sync::Mutex<PivotProgress>>,
    targets: &[(VolumeName, Epoch, ClientSpkiDigest)],
) -> Result<Vec<Duration>, String>
where
    S: granary_core::rootstore::RootStore + granary_core::binstore::BinStore + 'static,
{
    let required = PUBLISH_PILOT_WARMUP + PUBLISH_PILOT_SAMPLES;
    if targets.len() < required {
        return Err(format!(
            "pivot publish pilot targets insufficient: targets={}, required={required}",
            targets.len()
        ));
    }
    let mut durations = Vec::with_capacity(PUBLISH_PILOT_SAMPLES);
    for (index, (volume, epoch, digest)) in targets.iter().take(required).enumerate() {
        let started = super::stopwatch();
        tokio::time::timeout(
            PUBLISH_PILOT_TIMEOUT,
            publish_stream_cycle(
                fixture,
                volume,
                *epoch,
                send_publish(
                    fixture,
                    volume,
                    *epoch,
                    *digest,
                    u64::try_from(index + 1).map_err(|_| "pivot pilot operation exceeds u64")?,
                    super::super::good_root(volume, 1, None, 1),
                ),
            ),
        )
        .await
        .map_err(|_| "pivot publish pilot deadline")?
        .map_err(|error| format!("pivot publish pilot failed: {error:?}"))?;
        progress(progress_record, PivotProgress::pilot_published);
        let elapsed = started.elapsed();
        // Four distinct occupied volumes absorb one-time store and worker
        // initialization before the 32-sample sizing population.
        if index >= PUBLISH_PILOT_WARMUP {
            durations.push(elapsed);
        }
    }
    Ok(durations)
}

async fn serial_publish_diagnostic<S>(
    fixture: &super::rows::Fixture<S>,
    progress_record: &Arc<std::sync::Mutex<PivotProgress>>,
    volume: &VolumeName,
    epoch: Epoch,
    digest: ClientSpkiDigest,
    count: usize,
    control: (Duration, Duration, Option<usize>),
) -> Result<DiagnosticRun, String>
where
    S: granary_core::rootstore::RootStore + granary_core::binstore::BinStore + 'static,
{
    let (publish_bound, completion_bound, forced_stall) = control;
    let mut parent = None;
    let warmup_started = super::stopwatch();
    let mut run = DiagnosticRun {
        durations: Vec::with_capacity(count),
        ..DiagnosticRun::default()
    };
    let total = PIVOT_WARMUP_REQUESTS
        .checked_add(count)
        .ok_or_else(|| "pivot diagnostic population exceeds usize".to_owned())?;
    for index in 0..total {
        let measured = index >= PIVOT_WARMUP_REQUESTS;
        if measured && run.warmup_elapsed.is_zero() {
            run.warmup_elapsed = warmup_started.elapsed();
        }
        let sequence = u64::try_from(index + 1)
            .map_err(|_| "pivot diagnostic sequence exceeds u64".to_owned())?;
        let bytes = super::super::good_root(volume, sequence, parent, 1);
        let root_id = GrainId::of(&bytes);
        progress(progress_record, PivotProgress::open_loop_sent);
        let publish_started = super::stopwatch();
        let mut publish: Pin<
            Box<dyn Future<Output = Result<u64, super::pivot::RequestFailure>> + '_>,
        > = if forced_stall == Some(index) {
            Box::pin(std::future::pending())
        } else {
            Box::pin(send_publish(
                fixture, volume, epoch, digest, sequence, bytes,
            ))
        };
        let (duration, committed) = bounded_diagnostic_publish(
            &mut publish,
            publish_started,
            publish_bound,
            completion_bound,
        )
        .await?;
        record_diagnostic_publish_outcome(&mut run, measured, duration, committed);
        if !committed {
            run.stall_index = Some(index);
            run.stall_phase = Some(if measured { "measured" } else { "warmup" });
            progress(progress_record, PivotProgress::open_loop_completed);
            break;
        }
        let completion_started = super::stopwatch();
        match tokio::time::timeout(completion_bound, fixture.complete(volume, epoch)).await {
            Ok(result) => result?,
            Err(_) if measured => run.completion_stalls.push(completion_started.elapsed()),
            Err(_) => {}
        }
        progress(progress_record, PivotProgress::open_loop_completed);
        if measured {
            run.durations.push(duration);
        } else {
            run.warmup_count += 1;
        }
        parent = Some(root_id);
    }
    Ok(run)
}

fn record_diagnostic_publish_outcome(
    run: &mut DiagnosticRun,
    measured: bool,
    duration: Duration,
    committed: bool,
) {
    if duration != PUBLISH_DIAGNOSTIC_TIMEOUT {
        return;
    }
    if measured && committed {
        run.publish_censored += 1;
    }
    if !committed {
        let stalls = if measured {
            &mut run.publish_stalls
        } else {
            &mut run.warmup_publish_stalls
        };
        stalls.push(PUBLISH_DIAGNOSTIC_TIMEOUT + PUBLISH_DIAGNOSTIC_COMPLETION_TIMEOUT);
    }
}

async fn bounded_diagnostic_publish<F>(
    publish: &mut Pin<Box<F>>,
    started: Instant,
    publish_bound: Duration,
    continuation_bound: Duration,
) -> Result<(Duration, bool), String>
where
    F: Future<Output = Result<u64, super::pivot::RequestFailure>> + ?Sized,
{
    match tokio::time::timeout(publish_bound, &mut *publish).await {
        Ok(result) => {
            result.map_err(|error| format!("pivot diagnostic publish failed: {error:?}"))?;
            Ok((started.elapsed(), true))
        }
        Err(_) => match tokio::time::timeout(continuation_bound, &mut *publish).await {
            Ok(result) => {
                result.map_err(|error| format!("pivot diagnostic publish failed: {error:?}"))?;
                Ok((publish_bound, true))
            }
            Err(_) => Ok((publish_bound, false)),
        },
    }
}

async fn publish_open_loop<S>(
    fixture: Arc<super::rows::Fixture<S>>,
    progress_record: Arc<std::sync::Mutex<PivotProgress>>,
    volumes: Arc<Vec<(VolumeName, Epoch, PrincipalId, ClientSpkiDigest)>>,
    count: usize,
    rate: super::pivot::OfferedRate,
) -> Result<super::pivot::OpenLoopRun, String>
where
    S: granary_core::rootstore::RootStore + granary_core::binstore::BinStore + 'static,
{
    if volumes.is_empty() {
        return Err("pivot requires a nonempty volume population".to_owned());
    }
    let mut parents = vec![None; volumes.len()];
    let total = PIVOT_WARMUP_REQUESTS
        .checked_add(count)
        .ok_or_else(|| "pivot publish population exceeds usize".to_owned())?;
    let candidates: Vec<_> = (0..total)
        .map(|index| {
            let lane = index % volumes.len();
            let (volume, _, _, _) = volumes.get(lane).ok_or("pivot volume index missing")?;
            let generation = index / volumes.len() + 1;
            let seq = u64::try_from(generation).map_err(|_| "pivot sequence exceeds u64")?;
            let parent = parents
                .get(lane)
                .copied()
                .ok_or("pivot parent index missing")?;
            let bytes = super::super::good_root(volume, seq, parent, 1);
            *parents.get_mut(lane).ok_or("pivot parent index missing")? = Some(GrainId::of(&bytes));
            Ok((lane, bytes))
        })
        .collect::<Result<_, &'static str>>()
        .map_err(str::to_owned)?;
    let candidates = Arc::new(candidates);
    let stream_count = volumes.len();
    let depths = Arc::new(std::sync::Mutex::new(vec![None; total]));
    let observations = depths.clone();
    let mut run = super::pivot::run_wall_open_loop_phased(
        PIVOT_WARMUP_REQUESTS,
        count,
        rate,
        stream_count,
        move |index| {
            let fixture = fixture.clone();
            let progress_record = progress_record.clone();
            let volume = volumes.clone();
            let candidate = candidates.get(index).cloned();
            let depths = depths.clone();
            async move {
                let (lane, bytes) = candidate.ok_or(super::pivot::RequestFailure::Other(
                    "pivot candidate index missing",
                ))?;
                let (volume, epoch, _, digest) = volume.get(lane).ok_or(
                    super::pivot::RequestFailure::Other("pivot volume index missing"),
                )?;
                let operation = u64::try_from(index + 1).map_err(|_| {
                    super::pivot::RequestFailure::Other("pivot sequence exceeds u64")
                })?;
                progress(&progress_record, PivotProgress::open_loop_sent);
                let publish = async {
                    let result = send_publish(&fixture, volume, *epoch, *digest, operation, bytes).await;
                    if result.is_ok() || matches!(&result, Err(super::pivot::RequestFailure::Conflict(token)) if token == "stale-base") {
                        let Some(crate::authority::VolumeView::Log { head: Some(head), .. }) =
                            fixture.handle.volume_view(volume)
                        else { return Err(super::pivot::RequestFailure::DepthMismatch); };
                        let depth = head.head.map_or(0, |root| root.head_seq);
                        if depth != u64::try_from(index / stream_count).unwrap()
                            || result.as_ref().is_ok_and(|&seq| head.next_seq != Some(seq))
                        {
                            return Err(super::pivot::RequestFailure::DepthMismatch);
                        }
                        depths.lock().unwrap()[index] = Some(depth);
                    }
                    result
                };
                let result = publish_stream_cycle(&fixture, volume, *epoch, publish).await;
                progress(&progress_record, PivotProgress::open_loop_completed);
                result
            }
        },
    )
    .await?;
    run.observations
        .copy_from_slice(&observations.lock().unwrap()[..run.warmup_count + run.sent_count]);
    Ok(run)
}

fn intent_log_length(path: &Path) -> std::io::Result<u64> {
    std::fs::metadata(path).map(|metadata| metadata.len())
}

async fn occupancy_row(
    dir: &Path,
    principals: usize,
    row_holders: usize,
    live_roots: usize,
    released_rows: usize,
    pivot: Option<PivotWorkload>,
    measure_intent_log: fn(&Path) -> std::io::Result<u64>,
) -> Result<OccupancyRow, String> {
    let sim = Sim::new();
    let stores = std::array::from_fn(|node| sim.node(u32::try_from(node).unwrap(), Faults::none()));
    occupancy_row_with_backends(
        dir,
        stores,
        "in-memory-sim".to_owned(),
        false,
        None,
        None,
        Occupancy::Ceiling,
        principals,
        row_holders,
        live_roots,
        released_rows,
        pivot,
        measure_intent_log,
    )
    .await
}

#[expect(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    reason = "one row keeps its HTTP transitions and exact FileOps interval together"
)]
async fn occupancy_row_with_backends<S>(
    dir: &Path,
    stores: [S; 3],
    store_kind: String,
    observe_filesystem: bool,
    progress_name: Option<&str>,
    dispatch_deadline: Option<Duration>,
    occupancy: Occupancy,
    principals: usize,
    row_holders: usize,
    live_roots: usize,
    released_rows: usize,
    pivot: Option<PivotWorkload>,
    measure_intent_log: fn(&Path) -> std::io::Result<u64>,
) -> Result<OccupancyRow, String>
where
    S: granary_core::rootstore::RootStore + granary_core::binstore::BinStore + 'static,
{
    use super::io::{Call, Timings};
    use super::rows::{Fixture, LogSetup, RAISED, runtime_thread};
    let (principal_submission_limit, _, _, _, principal_in_flight_limit) =
        crate::ControlsConfig::parse(RAISED)?.tuple();
    let published_pivot = matches!(pivot, Some(PivotWorkload::PublishOpenLoop { .. }));
    let configured_volumes: Vec<_> = if published_pivot {
        (0..PUBLISH_PILOT_WARMUP + PUBLISH_PILOT_SAMPLES + MAX_PUBLISH_STREAMS)
            .map(|index| {
                let mut name = format!("pivot-{index:02}");
                if occupancy == Occupancy::Ceiling {
                    name.extend(std::iter::repeat_n('v', root::VOLUME_NAME_MAX - name.len()));
                }
                VolumeName::new(name).map_err(|error| format!("pivot volume name invalid: {error}"))
            })
            .collect::<Result<_, _>>()?
    } else {
        vec![
            VolumeName::new("v".repeat(root::VOLUME_NAME_MAX))
                .map_err(|error| format!("pivot volume name invalid: {error}"))?,
        ]
    };
    let distinct_floor_principals =
        published_pivot && occupancy == Occupancy::Floor && principals == 1;
    let (enrolled_set, volume_sets) = volume_enrollments(
        principals,
        configured_volumes.len(),
        distinct_floor_principals,
    )?;
    let timings = Timings::new(16_384);
    let (fixture, driver) = Fixture::new(
        dir,
        stores,
        timings,
        std::convert::identity,
        &configured_volumes,
        1,
        true,
        RAISED,
        Some(&enrolled_set),
        LogSetup::Deferred,
        identity(0).1,
        true,
        true,
        dispatch_deadline,
    )
    .await
    .unwrap();
    let fixture = Arc::new(fixture);
    let progress_record = Arc::new(std::sync::Mutex::new(PivotProgress::new(progress_name)?));
    progress(&progress_record, |record| record.record("row-start"));
    let capture = match pivot {
        Some(workload) => pivot_capture(workload.count())?,
        None => super::capture::Capture::new(16_384),
    };
    let running = runtime_thread(driver.run(), tracing::Dispatch::new(capture.clone()));
    let mut epochs = Vec::with_capacity(configured_volumes.len());
    progress(&progress_record, |record| {
        record.record("volume-initialise-start");
    });
    for volume in &configured_volumes {
        fixture.handle.initialise(volume).await.unwrap();
        let status = super::output::status(fixture.send(super::rows::get(volume)).await)
            .await
            .unwrap();
        epochs.push(status.epoch);
    }
    progress(&progress_record, |record| {
        record.record("volume-initialise-complete");
    });
    let population_shape = PopulationShape {
        occupancy,
        row_holders,
        live_roots,
        released_rows,
    };
    let (observed, pivot_targets, publish_pilot) =
        if let Some(PivotWorkload::PublishOpenLoop { stream_count, .. }) = pivot {
            let pilot_count = PUBLISH_PILOT_WARMUP + PUBLISH_PILOT_SAMPLES;
            let mut pilot_targets = Vec::with_capacity(pilot_count);
            progress(&progress_record, |record| {
                record.record("pilot-occupancy-start");
            });
            for ((volume, epoch), set) in configured_volumes
                .iter()
                .zip(&epochs)
                .zip(&volume_sets)
                .take(pilot_count)
            {
                let population =
                    populate_occupancy(&fixture, &progress_record, volume, set, population_shape)
                        .await;
                pilot_targets.push((volume.clone(), *epoch, population.publish_digest));
            }
            progress(&progress_record, |record| {
                record.record("pilot-occupancy-complete");
                record.record("pilot-publish-start");
            });
            let pilot_samples =
                match serial_publish_pilot(&fixture, &progress_record, &pilot_targets).await {
                    Ok(samples) => samples,
                    Err(reason) => {
                        stop_occupancy_fixture(&fixture, running).await;
                        return Err(reason);
                    }
                };
            progress(&progress_record, |record| {
                record.record("pilot-publish-complete");
            });
            let sizing = match publish_pilot_summary(&pilot_samples, stream_count) {
                Ok(sizing) => sizing,
                Err(reason) => {
                    stop_occupancy_fixture(&fixture, running).await;
                    return Err(reason);
                }
            };
            let stream_count = sizing.stream_count;
            let mut populations = Vec::with_capacity(stream_count);
            progress(&progress_record, |record| {
                record.record("measured-occupancy-start");
            });
            for ((volume, epoch), set) in configured_volumes
                .iter()
                .zip(&epochs)
                .zip(&volume_sets)
                .skip(pilot_count)
                .take(stream_count)
            {
                let population =
                    populate_occupancy(&fixture, &progress_record, volume, set, population_shape)
                        .await;
                populations.push((volume.clone(), *epoch, population));
            }
            progress(&progress_record, |record| {
                record.record("measured-occupancy-complete");
            });
            let targets = populations
                .iter()
                .map(|(volume, epoch, population)| {
                    (
                        volume.clone(),
                        *epoch,
                        population.publish_principal,
                        population.publish_digest,
                    )
                })
                .collect();
            let (_, _, observed) = populations.remove(0);
            assert!(populations.iter().all(|(_, _, population)| {
                (
                    population.principals,
                    population.row_holders,
                    population.live_roots,
                    population.released_rows,
                ) == (
                    observed.principals,
                    observed.row_holders,
                    observed.live_roots,
                    observed.released_rows,
                )
            }));
            (observed, targets, Some(sizing))
        } else {
            progress(&progress_record, |record| {
                record.record("measured-occupancy-start");
            });
            let observed = populate_occupancy(
                &fixture,
                &progress_record,
                configured_volumes
                    .first()
                    .ok_or_else(|| "pivot volume population missing".to_owned())?,
                volume_sets
                    .first()
                    .ok_or_else(|| "pivot enrollment population missing".to_owned())?,
                population_shape,
            )
            .await;
            progress(&progress_record, |record| {
                record.record("measured-occupancy-complete");
            });
            let publish_digest = observed.publish_digest;
            let publish_principal = observed.publish_principal;
            (
                observed,
                vec![(
                    configured_volumes
                        .first()
                        .ok_or_else(|| "pivot volume population missing".to_owned())?
                        .clone(),
                    *epochs
                        .first()
                        .ok_or_else(|| "pivot epoch population missing".to_owned())?,
                    publish_principal,
                    publish_digest,
                )],
                None,
            )
        };
    let per_stream_offered_rate = match pivot {
        Some(PivotWorkload::PublishOpenLoop { rate, .. }) => {
            require_distinct_stream_principals(&pivot_targets)?;
            Some(per_stream_offered_rate(
                rate.as_f64(),
                pivot_targets.len(),
                principal_submission_limit,
            )?)
        }
        Some(PivotWorkload::RegisterOpenLoop { rate, .. }) => Some(per_stream_offered_rate(
            f64::from(rate),
            observed.register_lanes.len(),
            principal_submission_limit,
        )?),
        _ => None,
    };
    let log_filesystem = if observe_filesystem {
        observed_filesystem(&fixture.config.state_dir)
    } else {
        Ok("test-filesystem".to_owned())
    };
    let _ = capture.take();
    fixture.io.counts();
    progress(&progress_record, |record| {
        record.record("request-run-start");
    });
    let measured = match pivot {
        Some(PivotWorkload::RegisterOpenLoop { count, rate }) => {
            let lanes = Arc::new(observed.register_lanes.clone());
            let lane_count = lanes.len();
            let total = PIVOT_WARMUP_REQUESTS
                .checked_add(count)
                .ok_or_else(|| "pivot register population exceeds usize".to_owned())?;
            let registers: Arc<Vec<_>> = Arc::new(
                (0..total)
                    .map(|index| {
                        let lane = index % lane_count;
                        let generation = u64::try_from(index / lane_count + 2).unwrap();
                        let sequence = u64::try_from(index + 3).unwrap();
                        let fresh_root = maximal_root(&configured_volumes[0], sequence).0;
                        assert_eq!(fresh_root.len(), observed.root_bytes);
                        let (receipt, digest) = lanes[lane];
                        let body = intent::encode_register(
                            &receipt.writer,
                            receipt.epoch,
                            &receipt.instance,
                            generation,
                            &fresh_root,
                        )
                        .unwrap();
                        (body, generation, GrainId::of(&fresh_root), digest)
                    })
                    .collect(),
            );
            let register_fixture = fixture.clone();
            let register_volume = configured_volumes[0].clone();
            let register_progress = progress_record.clone();
            let register_run = super::pivot::run_wall_open_loop(
                PIVOT_WARMUP_REQUESTS,
                count,
                super::pivot::OfferedRate::new(rate, 1),
                lane_count,
                Duration::from_secs(30),
                move |index| {
                    let fixture = register_fixture.clone();
                    let progress_record = register_progress.clone();
                    let volume = register_volume.clone();
                    let transition = registers.get(index).cloned();
                    async move {
                        let (register, generation, root_id, digest) =
                            transition.ok_or(super::pivot::RequestFailure::Other(
                                "pivot register transition missing",
                            ))?;
                        progress(&progress_record, PivotProgress::open_loop_sent);
                        let response = fixture
                            .send(intent_request(&volume, digest, "", register))
                            .await;
                        progress(&progress_record, PivotProgress::open_loop_completed);
                        match response.status().as_u16() {
                            200 => {}
                            409 => {
                                return Err(super::pivot::RequestFailure::Conflict(
                                    "intent-conflict".to_owned(),
                                ));
                            }
                            429 => return Err(super::pivot::RequestFailure::RateLimited),
                            _ => {
                                return Err(super::pivot::RequestFailure::Other(
                                    "pivot register request failed",
                                ));
                            }
                        }
                        let answer = response
                            .into_body()
                            .collect()
                            .await
                            .unwrap_or_else(|never| match never {})
                            .to_bytes();
                        let observed = intent::decode_receipt(&answer).map_err(|_| {
                            super::pivot::RequestFailure::Other("pivot register receipt invalid")
                        })?;
                        (observed.generation == generation
                            && matches!(
                                observed.state,
                                intent::ReceiptState::Live { prepared_root_id }
                                    if prepared_root_id == root_id
                            ))
                        .then_some(observed.generation)
                        .ok_or(super::pivot::RequestFailure::Other(
                            "pivot register transition not committed",
                        ))
                    }
                },
            )
            .await;
            register_run.map(|run| (Some(run), DiagnosticRun::default()))
        }
        Some(PivotWorkload::PublishOpenLoop {
            count,
            rate,
            stream_count: _,
        }) => publish_open_loop(
            fixture.clone(),
            progress_record.clone(),
            Arc::new(pivot_targets.clone()),
            count,
            rate,
        )
        .await
        .map(|run| (Some(run), DiagnosticRun::default())),
        Some(PivotWorkload::PublishDiagnostic { count }) => {
            let (volume, epoch, _, digest) = pivot_targets
                .first()
                .ok_or_else(|| "pivot diagnostic target missing".to_owned())?;
            serial_publish_diagnostic(
                &fixture,
                &progress_record,
                volume,
                *epoch,
                *digest,
                count,
                (
                    PUBLISH_DIAGNOSTIC_TIMEOUT,
                    PUBLISH_DIAGNOSTIC_COMPLETION_TIMEOUT,
                    None,
                ),
            )
            .await
            .map(|run| (None, run))
        }
        None => Ok((None, DiagnosticRun::default())),
    };
    progress(&progress_record, |record| {
        record.record("request-run-complete");
        record.record("drain-start");
    });
    let pivot_counts = fixture.io.counts();
    let committed_transitions = pivot_counts[Call::IntentSyncFile as usize];
    stop_occupancy_fixture(&fixture, running).await;
    progress(&progress_record, |record| {
        record.record("drain-complete");
    });
    let (captured, lost_samples) = capture.take();
    if pivot.is_some() {
        require_pivot_capture(lost_samples)?;
    } else {
        assert_eq!(lost_samples, 0, "occupancy span capture lost samples");
    }
    let authority_log_wait_samples = captured
        .into_iter()
        .filter(|sample| sample.name == "authority_log_wait")
        .map(|sample| sample.end.saturating_duration_since(sample.start))
        .collect();
    let (pivot_run, diagnostic_run) = measured?;
    let intent_log_bytes = if matches!(pivot, Some(PivotWorkload::RegisterOpenLoop { .. })) {
        let path = fixture
            .config
            .state_dir
            .join(format!("{}.intent", configured_volumes[0].as_str()));
        Some(
            measure_intent_log(&path)
                .map_err(|error| format!("pivot-intent-log-metadata: {error}"))?,
        )
    } else {
        None
    };
    {
        let mut record = progress_record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        record.finish()?;
    }
    let log_filesystem = log_filesystem?;
    let (root_label, root_size_distribution) = observed.root_observation.map_err(str::to_owned)?;
    if matches!(pivot, Some(PivotWorkload::RegisterOpenLoop { .. }))
        // Every warm-up register commits too: one durable transition per sent
        // request, measured or not.
        && committed_transitions
            != pivot_run
                .as_ref()
                .map_or(0, |run| run.durations.len().saturating_add(run.warmup_count))
    {
        return Err(format!(
            "pivot register transition count mismatch: committed={committed_transitions}, counts={pivot_counts:?}"
        ));
    }
    Ok(OccupancyRow {
        principals: observed.principals,
        row_holders: observed.row_holders,
        live_roots: observed.live_roots,
        released_rows: observed.released_rows,
        root_label,
        root_bytes: observed.root_bytes,
        root_size_distribution,
        store_kind,
        log_filesystem,
        amplification: observed.amplification,
        register_samples: observed.register_samples,
        pivot_run,
        diagnostic_run,
        committed_transitions,
        intent_log_bytes,
        authority_log_wait_samples,
        publish_pilot,
        principal_submission_limit,
        principal_in_flight_limit,
        per_stream_offered_rate,
        denominator_attempts: Vec::new(),
    })
}

async fn venue_occupancy_row(
    pass: &str,
    dir: &Path,
    principals: usize,
    shape: PopulationShape,
    pivot: PivotWorkload,
) -> Result<OccupancyRow, String> {
    let configured = crate::config::store_from_env()
        .map_err(|reason| format!("pivot venue store refused: {reason}"))?;
    let store_kind = configured.store.to_string();
    super::server_child::require_minio(&store_kind)?;
    let (stores, prefixed) =
        super::server_child::measurement_backends(pass, &configured, identity(0).1);
    super::server_child::clear_prefix(&prefixed).await?;
    let row = occupancy_row_with_backends(
        dir,
        stores,
        store_kind,
        true,
        Some(pass),
        configured.dispatch_deadline,
        shape.occupancy,
        principals,
        shape.row_holders,
        shape.live_roots,
        shape.released_rows,
        Some(pivot),
        intent_log_length,
    )
    .await;
    super::server_child::clear_prefix(&prefixed).await?;
    row
}

async fn install(sets: Vec<EnrollmentSet>) -> (usize, usize) {
    use super::super::intents as venue;
    use crate::authority::intent::tests as fixture;

    let path = venue::scratch();
    let (handle, driver) = venue::start(venue::recording(&path), 1).await;
    let running = super::rows::runtime_thread(
        driver,
        tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
    );
    handle.initialise(&fixture::volume()).await.unwrap();
    for set in sets {
        assert_eq!(
            handle
                .maintain_intents(&fixture::volume(), &set, 0)
                .await
                .status()
                .as_u16(),
            200
        );
    }
    let (snapshot, bytes) = committed_snapshot(&path, &fixture::volume());
    handle.stop().await;
    assert_eq!(running.join().unwrap(), super::super::RunEnd::Stopped);
    std::fs::remove_dir_all(path).unwrap();
    (snapshot.principals.len(), bytes)
}

fn committed_snapshot(
    path: &Path,
    volume: &VolumeName,
) -> (crate::authority::intent::Snapshot, usize) {
    let bytes = std::fs::read(path.join(format!("{}.intent", volume.as_str()))).unwrap();
    let snapshot =
        crate::authority::intent::codec::decode_for_rebind(std::io::Cursor::new(&bytes), volume)
            .unwrap();
    (snapshot, bytes.len())
}

fn sample(occupancy: Occupancy, samples: &[Duration]) -> RecordedRun<'_> {
    RecordedRun {
        profile: Profile::DurablePrepared,
        occupancy,
        offered_rate: Some(23),
        load_model: "open-loop",
        medium: "ssd",
        wrapper: "server-service",
        route: "/volume/:volume/intent",
        samples,
    }
}

fn baseline(samples: &[Duration]) -> RecordedRun<'_> {
    RecordedRun {
        profile: Profile::Published,
        occupancy: Occupancy::Floor,
        offered_rate: Some(23),
        load_model: "open-loop",
        medium: "ssd",
        wrapper: "server-service",
        route: "/volume/:volume/publish",
        samples,
    }
}

#[test]
fn authority_measurement_amplification_uses_register_transition_bytes() {
    use crate::authority::intent::tests as fixture;

    let principal = fixture::owned(1);
    let receipt = principal.rows.values().next().unwrap().receipt;
    let root = fixture::root(1, &fixture::volume());
    let encoded =
        intent::encode_register(&receipt.writer, receipt.epoch, &receipt.instance, 1, &root)
            .unwrap();
    let measured = Amplification::from_register(2_000, 1_000, receipt, 1, &root).unwrap();
    assert_eq!(measured.written_ratio(), (2_000, encoded.len()));
    assert_eq!(measured.full_snapshot_bytes, 1_000);
}

#[test]
fn authority_measurement_pivot_uses_only_the_ruled_pair() {
    let ms = |value| [Duration::from_millis(value)];
    assert_eq!(
        pivot_inputs(sample(Occupancy::Ceiling, &ms(81)), baseline(&ms(40))),
        Ok((Duration::from_millis(81), Duration::from_millis(40)))
    );

    let medium_samples = ms(40);
    let mut different_medium = baseline(&medium_samples);
    different_medium.medium = "hdd";
    assert_eq!(
        pivot_inputs(sample(Occupancy::Ceiling, &ms(81)), different_medium),
        Err("pivot offered load, medium, or wrapper differs")
    );
    assert_eq!(
        pivot_inputs(sample(Occupancy::UpperBound, &ms(81)), baseline(&ms(40))),
        Err("pivot roles or occupancy differ from the ruled pair")
    );

    let samples = ms(40);
    let mut different_rate = baseline(&samples);
    different_rate.offered_rate = Some(24);
    assert_eq!(
        pivot_inputs(sample(Occupancy::Ceiling, &ms(81)), different_rate),
        Err("pivot offered load, medium, or wrapper differs")
    );
    let mut different_wrapper = baseline(&samples);
    different_wrapper.wrapper = "client-service";
    assert_eq!(
        pivot_inputs(sample(Occupancy::Ceiling, &ms(81)), different_wrapper),
        Err("pivot offered load, medium, or wrapper differs")
    );
    let mut wrong_floor = baseline(&samples);
    wrong_floor.occupancy = Occupancy::Ceiling;
    assert_eq!(
        pivot_inputs(sample(Occupancy::Ceiling, &ms(81)), wrong_floor),
        Err("pivot roles or occupancy differ from the ruled pair")
    );
    let numerator_samples = ms(81);
    let mut wrong_route = sample(Occupancy::Ceiling, &numerator_samples);
    wrong_route.route = "/volume/:volume/publish";
    assert_eq!(
        pivot_inputs(wrong_route, baseline(&samples)),
        Err("pivot roles or occupancy differ from the ruled pair")
    );
    let mut closed_loop_register = sample(Occupancy::Ceiling, &numerator_samples);
    closed_loop_register.load_model = "closed-loop";
    closed_loop_register.offered_rate = None;
    let mut closed_loop_publish = baseline(&samples);
    closed_loop_publish.load_model = "closed-loop";
    closed_loop_publish.offered_rate = None;
    assert_eq!(
        pivot_inputs(closed_loop_register, closed_loop_publish),
        Err("closed-loop row cannot be a pivot input")
    );
}

fn emit_all_authority_spans() {
    drop([
        tracing::trace_span!("authority_queue"),
        tracing::trace_span!("authority_validation"),
        tracing::trace_span!("authority_chain"),
        tracing::trace_span!("authority_log_wait"),
        tracing::trace_span!("authority_worker_poll"),
    ]);
}

#[test]
fn authority_measurement_publish_pilot_uses_a_population_order_statistic() {
    assert_eq!(
        publish_pilot_summary(&[Duration::from_millis(1)], 64),
        Err("pivot publish pilot population insufficient: samples=1, minimum=32".to_owned())
    );

    let mut samples = vec![Duration::from_millis(20); PUBLISH_PILOT_SAMPLES];
    samples[0] = Duration::from_millis(1);
    for stream_count in [64, 32, 16] {
        let pilot = publish_pilot_summary(&samples, stream_count).unwrap();
        assert_eq!(
            pilot,
            PublishPilot {
                sample_count: 32,
                p50: Duration::from_millis(20),
                p99: Duration::from_millis(20),
                max: Duration::from_millis(20),
                stream_count,
            },
            "the pilot must preserve each ruled rate's pool instead of sizing it"
        );
    }

    let too_slow = vec![Duration::from_millis(65); PUBLISH_PILOT_SAMPLES];
    assert_eq!(
        publish_pilot_summary(&too_slow, 16).unwrap().stream_count,
        16,
        "even a slow pilot only records the fixed pool, never gates it"
    );
}

#[tokio::test]
async fn authority_measurement_denominator_stops_and_exports_the_selected_attempt() {
    let mut run = super::pivot::OpenLoopRun {
        durations: vec![Duration::from_millis(10); 1_000],
        completion_durations: vec![Duration::from_millis(10); 1_000],
        warmup_count: PIVOT_WARMUP_REQUESTS,
        warmup_elapsed: Duration::from_millis(1_392),
        offered_rate: 46.0,
        achieved_rate: 46.0,
        max_send_lateness: Duration::ZERO,
        late_send_count: 0,
        completed_in_window: 1_000,
        failure_count: 0,
        stream_sample_counts: vec![16; MAX_PUBLISH_STREAMS],
        sent_count: 1_000,
        first_refusal: None,
        conflict_token_counts: BTreeMap::new(),
        rate_limited_count: 0,
        max_outstanding_per_stream: vec![1],
        max_outstanding_overall: 1,
        cycle_durations: [20, 250]
            .map(|ms| (Duration::from_millis(ms), Duration::from_millis(ms)))
            .to_vec(),
        refusal_cycle_duration: None,
        observations: (0..1064).map(|index| Some(index / 64)).collect(),
        drain_timed_out: false,
    };
    let attempt = DenominatorAttempt::from_run(
        &run,
        PublishPilot {
            sample_count: 32,
            p50: Duration::from_millis(15),
            p99: Duration::from_millis(20),
            max: Duration::from_millis(20),
            stream_count: 64,
        },
        1_000,
    )
    .unwrap();
    assert_eq!(attempt.cycle_stall_bound, Duration::from_millis(200));
    assert_eq!(attempt.cycle_stalls, [Duration::from_millis(250)]);
    assert_eq!(attempt.refusal_cycle_duration, None);
    let (selected, attempts) = stepped_denominator(|_, rate| {
        let mut attempt = attempt.clone();
        attempt.rate = rate.as_f64();
        if rate == super::pivot::OfferedRate::new(46, 1) {
            attempt.durations[500..].fill(Duration::from_millis(20));
        } else if rate == super::pivot::OfferedRate::new(46, 4) {
            attempt.first_refusal = Some(super::pivot::FirstRefusal {
                kind: "409",
                time: Duration::from_millis(1),
                cycle_index: None,
            });
        }
        std::future::ready(Ok((rate, attempt)))
    })
    .await
    .unwrap();
    assert_eq!(selected, super::pivot::OfferedRate::new(46, 2));
    let depth = denominator_depth_fields(&attempts);
    assert_eq!(depth["denominator_attempt_depth_bounds"], "0,16|0,16");

    let mut exported = denominator_depth_fields(&attempts[1..]);
    run.observations = vec![Some(25), Some(68), Some(2)];
    exported.extend(numerator_scope_fields(&run, 123_456));
    exported.extend(diagnostic_depth_field(64, 368));
    let fixture = include_str!("../../../../../../scripts/test-q3-measurement.py");
    let (_, fixture) = fixture.split_once("PIVOT_DEPTH_EXPORT = \"\"\"").unwrap();
    let (fixture, _) = fixture.split_once("\"\"\"").unwrap();
    let mut expected: BTreeMap<_, _> = fixture
        .lines()
        .map(|line| {
            let (name, value) = line.split_once('\t').unwrap();
            (name.to_owned(), value.to_owned())
        })
        .collect();
    let trace = exported
        .remove("denominator_attempt_depth_records")
        .unwrap();
    let digest = granary_net::crypto_provider()
        .cipher_suites
        .iter()
        .filter(|suite| suite.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
        .find_map(rustls::SupportedCipherSuite::tls13)
        .unwrap()
        .common
        .hash_provider
        .hash(trace.as_bytes());
    assert_eq!(
        digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .concat(),
        expected.remove("depth_trace_sha256").unwrap()
    );
    assert_eq!(exported, expected);
}

#[test]
fn authority_measurement_pivot_publish_streams_have_distinct_principal_budgets() {
    let (_, volume_sets) = volume_enrollments(1, 2, true).unwrap();
    let enrolled_principals: Vec<_> = volume_sets
        .iter()
        .map(|set| set.credentials().next().unwrap().1)
        .collect();
    assert_ne!(enrolled_principals[0], enrolled_principals[1]);

    let volume_a = VolumeName::new("a".to_owned()).unwrap();
    let volume_b = VolumeName::new("b".to_owned()).unwrap();
    let epoch = Epoch::from_bytes([1; 16]);
    let (principal_a, digest_a) = identity(1);
    let (principal_b, digest_b) = identity(2);
    let targets = vec![
        (volume_a.clone(), epoch, principal_a, digest_a),
        (volume_b.clone(), epoch, principal_b, digest_b),
    ];
    assert!(require_distinct_stream_principals(&targets).is_ok());
    assert_eq!(per_stream_offered_rate(46.0, 20, 1_000_000), Ok(2.3));
    assert_eq!(
        per_stream_offered_rate(2_000_001.0, 2, 1_000_000),
        Err("pivot per-stream submission rate exceeds principal limit: offered_rate=2000001, streams=2, limit=1000000".to_owned())
    );

    let shared = vec![
        (volume_a, epoch, principal_a, digest_a),
        (volume_b, epoch, principal_a, digest_b),
    ];
    assert_eq!(
        require_distinct_stream_principals(&shared),
        Err("pivot publish stream principals not distinct: streams=2, principals=1".to_owned())
    );
}

#[test]
fn authority_measurement_pivot_records_publish_conflict_token() {
    assert_eq!(
        pivot_publish_refusal(409, Some("stale-base")),
        Some(super::pivot::RequestFailure::Conflict(
            "stale-base".to_owned()
        ))
    );
    assert_eq!(
        pivot_publish_refusal(429, Some("rate-limited")),
        Some(super::pivot::RequestFailure::RateLimited)
    );
}

#[tokio::test]
async fn authority_measurement_pivot_publish_cycle_requires_completion() {
    let result = timed_publish_cycle(async { Ok(6) }, async {
        Err(super::pivot::RequestFailure::Other(
            "injected incomplete publication",
        ))
    })
    .await;
    assert_eq!(
        result.unwrap_err(),
        super::pivot::RequestFailure::Other("injected incomplete publication")
    );
}

fn assert_stalled_diagnostic_export(run: &DiagnosticRun) {
    assert_eq!(run.stall_phase, Some("warmup"));
    assert!(run.stall_index.is_some_and(|index| index < 64));
    assert_eq!(
        run.warmup_publish_stalls,
        [PUBLISH_DIAGNOSTIC_TIMEOUT + PUBLISH_DIAGNOSTIC_COMPLETION_TIMEOUT]
    );
    let fixture_text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/q3-pivot-stalled-fields.tsv"),
    )
    .unwrap();
    let expected = fixture_text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.split_once('\t').unwrap())
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    assert_eq!(diagnostic_fields(run, 0), expected);
}

#[tokio::test]
async fn authority_measurement_pivot_diagnostic_uses_the_observed_epoch() {
    use super::io::Timings;
    use super::rows::{Fixture, LogSetup, RAISED, runtime_thread};

    let dir = super::super::intents::scratch();
    let sim = Sim::new();
    let stores = std::array::from_fn(|node| sim.node(u32::try_from(node).unwrap(), Faults::none()));
    let volume = VolumeName::new("epoch-control".to_owned()).unwrap();
    let deeper = VolumeName::new("depth-control".to_owned()).unwrap();
    let set = enrollment(0, 1, 0);
    let (fixture, driver) = Fixture::new(
        &dir,
        stores,
        Timings::new(32),
        std::convert::identity,
        &[volume.clone(), deeper.clone()],
        1,
        true,
        RAISED,
        Some(&set),
        LogSetup::Deferred,
        identity(0).1,
        true,
        true,
        None,
    )
    .await
    .unwrap();
    let fixture = Arc::new(fixture);
    let running = runtime_thread(
        driver.run(),
        tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
    );
    fixture.handle.initialise(&volume).await.unwrap();
    let observed_epoch = super::output::status(fixture.send(super::rows::get(&volume)).await)
        .await
        .unwrap()
        .epoch;
    assert_ne!(
        observed_epoch,
        Epoch::from_bytes([crate::authority::tests::WORLD_EPOCH; 16])
    );
    let progress = Arc::new(std::sync::Mutex::new(PivotProgress::new(None).unwrap()));
    let run = serial_publish_diagnostic(
        &fixture,
        &progress,
        &volume,
        observed_epoch,
        identity(0).1,
        1,
        (
            PUBLISH_DIAGNOSTIC_TIMEOUT,
            PUBLISH_DIAGNOSTIC_COMPLETION_TIMEOUT,
            None,
        ),
    )
    .await
    .unwrap();
    assert_eq!((run.warmup_count, run.durations.len()), (64, 1));
    fixture.handle.initialise(&deeper).await.unwrap();
    let Some(crate::authority::VolumeView::Log { epoch, .. }) = fixture.handle.volume_view(&deeper)
    else {
        panic!("depth control volume was not initialized");
    };
    let root = super::super::good_root(&deeper, 1, None, 1);
    send_publish(&fixture, &deeper, epoch, identity(0).1, 1_000, root)
        .await
        .unwrap();
    fixture.complete(&deeper, epoch).await.unwrap();
    let mismatch = publish_open_loop(
        fixture.clone(),
        progress.clone(),
        Arc::new(vec![(deeper, epoch, identity(0).0, identity(0).1)]),
        1,
        super::pivot::OfferedRate::new(46, 1),
    )
    .await
    .unwrap_err();
    assert_eq!(mismatch, "pivot candidate depth mismatch");
    let stalled = serial_publish_diagnostic(
        &fixture,
        &progress,
        &volume,
        observed_epoch,
        identity(0).1,
        1,
        (
            PUBLISH_DIAGNOSTIC_TIMEOUT,
            PUBLISH_DIAGNOSTIC_COMPLETION_TIMEOUT,
            Some(0),
        ),
    )
    .await
    .unwrap();
    assert_stalled_diagnostic_export(&stalled);
    stop_occupancy_fixture(&fixture, running).await;
}

#[test]
fn authority_measurement_pivot_diagnostic_separates_censoring_and_completion_stalls() {
    let run = DiagnosticRun {
        durations: vec![PUBLISH_DIAGNOSTIC_TIMEOUT; 100],
        warmup_count: PIVOT_WARMUP_REQUESTS,
        warmup_elapsed: Duration::from_millis(1_392),
        publish_censored: 2,
        publish_stalls: vec![Duration::from_millis(2_100)],
        warmup_publish_stalls: vec![Duration::from_millis(2_100)],
        completion_stalls: vec![Duration::from_millis(2_001)],
        stall_index: None,
        stall_phase: None,
    };
    let fields = diagnostic_fields(&run, PUBLISH_DIAGNOSTIC_TIMEOUT.as_nanos());
    assert_eq!(
        fields
            .get("diagnostic_publish_p99_report")
            .map(String::as_str),
        Some("> 100000000"),
        "more than one percent censored samples must report a lower bound"
    );
    assert_eq!(
        (
            fields
                .get("diagnostic_publish_censored_count")
                .map(String::as_str),
            fields
                .get("diagnostic_completion_stalls")
                .map(String::as_str),
            fields
                .get("diagnostic_completion_stall_ns")
                .map(String::as_str),
            fields
                .get("diagnostic_warmup_publish_stalls")
                .map(String::as_str),
            fields
                .get("diagnostic_warmup_publish_stall_ns")
                .map(String::as_str),
        ),
        (
            Some("2"),
            Some("1"),
            Some("2001000000"),
            Some("1"),
            Some("2100000000"),
        ),
        "warm-up and measured publish stalls remain separately observable"
    );
}

#[tokio::test]
async fn authority_measurement_pivot_diagnostic_records_a_double_publish_timeout() {
    let mut failed = Box::pin(async {
        Err::<u64, _>(super::pivot::RequestFailure::Other("forced server error"))
    });
    assert_eq!(
        bounded_diagnostic_publish(
            &mut failed,
            super::stopwatch(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err(),
        "pivot diagnostic publish failed: Other(\"forced server error\")"
    );
    let mut publish = Box::pin(std::future::pending());
    let (duration, committed) = bounded_diagnostic_publish(
        &mut publish,
        super::stopwatch(),
        Duration::from_millis(1),
        Duration::from_millis(1),
    )
    .await
    .unwrap();
    assert_eq!(duration, Duration::from_millis(1));
    assert!(
        !committed,
        "an uncommitted root must not become the next parent"
    );
    let mut run = DiagnosticRun::default();
    record_diagnostic_publish_outcome(&mut run, false, PUBLISH_DIAGNOSTIC_TIMEOUT, committed);
    record_diagnostic_publish_outcome(&mut run, true, PUBLISH_DIAGNOSTIC_TIMEOUT, committed);
    assert_eq!(
        (run.warmup_publish_stalls.len(), run.publish_stalls.len()),
        (1, 1),
        "double timeouts are recorded separately in warm-up and measured windows"
    );
    assert!(
        !committed,
        "the path after the timeout helper ends before constructing a stale base"
    );
}

#[test]
fn authority_measurement_pivot_capture_is_bounded_and_drain_scoped() {
    let request_count = 4_097;
    let capture = pivot_capture(request_count).unwrap();
    let dispatch = tracing::Dispatch::new(capture.clone());
    tracing::dispatcher::with_default(&dispatch, || {
        for _ in 0..request_count {
            emit_all_authority_spans();
        }
    });
    let (samples, lost) = capture.take();
    require_pivot_capture(lost).unwrap();
    assert_eq!(samples.len(), request_count);
    assert!(
        samples
            .iter()
            .all(|sample| sample.name == "authority_log_wait")
    );

    let overflow = super::capture::Capture::authority_log_wait(1);
    let dispatch = tracing::Dispatch::new(overflow.clone());
    tracing::dispatcher::with_default(&dispatch, || {
        drop(tracing::trace_span!("authority_log_wait"));
        drop(tracing::trace_span!("authority_log_wait"));
    });
    let (_, lost) = overflow.take();
    assert_eq!(
        require_pivot_capture(lost),
        Err("pivot-span-capture-lost: 1".to_owned())
    );

    let drained = pivot_capture(1).unwrap();
    let dispatch = tracing::Dispatch::new(drained.clone());
    tracing::dispatcher::with_default(&dispatch, emit_all_authority_spans);
    let _ = drained.take();
    tracing::dispatcher::with_default(&dispatch, || {
        drop(tracing::trace_span!("authority_log_wait"));
    });
    let (samples, lost) = drained.take();
    require_pivot_capture(lost).unwrap();
    assert_eq!(
        samples.len(),
        1,
        "setup samples must be removed by the drain"
    );

    let margin = pivot_capture(10).unwrap();
    let dispatch = tracing::Dispatch::new(margin.clone());
    tracing::dispatcher::with_default(&dispatch, || {
        for _ in 0..31 {
            drop(tracing::trace_span!("authority_log_wait"));
        }
    });
    let (samples, lost) = margin.take();
    require_pivot_capture(lost).unwrap();
    assert_eq!(samples.len(), 31, "capture requires spare above 3x count");
}

#[test]
fn authority_measurement_707_label_requires_every_live_root() {
    let volume = VolumeName::new("v".repeat(root::VOLUME_NAME_MAX)).unwrap();
    let (exact, keys) = maximal_root(&volume, 2);
    let short = super::super::good_root(&volume, 1, None, 1);
    assert_eq!(exact.len(), root::ROOT_V1_MAX_ENCODABLE);
    assert_eq!(root_label("707-B", &[&exact], &keys), Ok("707-B"));
    assert_eq!(
        root_label("707-B", &[&exact, &short], &keys),
        Err("707-B label requires every live root to be exactly 707 bytes")
    );
    assert_eq!(
        root_label("measured length", &[&short], &keys),
        Ok("measured length")
    );
    assert_eq!(
        observe_root_population(Occupancy::Floor, &[&short], &keys),
        Ok(("measured length", BTreeMap::from([(short.len(), 1)])))
    );
    assert_eq!(
        observe_root_population(Occupancy::Ceiling, &[&short], &keys),
        Err("707-B label requires every live root to be exactly 707 bytes")
    );
    let arbitrary = [0_u8; root::ROOT_V1_MAX_ENCODABLE];
    assert_eq!(
        root_label("707-B", &[&arbitrary], &keys),
        Err("root label requires accepted v1 roots")
    );
    let mut bad_doc = root::decode_root(&exact).unwrap();
    bad_doc.sigs.first_mut().unwrap().sig[0] ^= 1;
    let bad_signature = root::encode_root(&bad_doc).unwrap();
    assert_eq!(bad_signature.len(), root::ROOT_V1_MAX_ENCODABLE);
    assert_eq!(
        root_label("707-B", &[&bad_signature], &keys),
        Err("root label requires accepted v1 roots")
    );
}

#[test]
fn authority_measurement_historical_sets_are_minted_and_retired_in_memory() {
    let set = enrollment(0, 8, 6);
    let states: Vec<_> = set.principals().map(|(_, state, _)| state).collect();
    assert_eq!(set.principal_count(), 8);
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == PrincipalState::Retired)
            .count(),
        6
    );
    assert_eq!(set.credential_count(), 2);
}

const SMALL_OCCUPANCY_SAMPLES: usize = 4;
const SMALL_OCCUPANCY_LANES: usize = 2;

fn small_occupancy_accepts_run(run: &super::pivot::OpenLoopRun, committed: usize) -> bool {
    if run.failure_count != 0
        || run.rate_limited_count != 0
        || !run.conflict_token_counts.is_empty()
        || run.drain_timed_out
    {
        return false;
    }

    let total = PIVOT_WARMUP_REQUESTS + SMALL_OCCUPANCY_SAMPLES;
    let Some(refusal) = &run.first_refusal else {
        return run.durations.len() == SMALL_OCCUPANCY_SAMPLES
            && committed == total
            && run.stream_sample_counts == [2, 2];
    };

    // Overlap records the preceding cycle on the busy lane. The refused
    // send is one rotation later, after exactly that many successful sends.
    let Some(refused_index) = refusal
        .cycle_index
        .and_then(|index| index.checked_add(SMALL_OCCUPANCY_LANES))
    else {
        return false;
    };
    refusal.kind == "overlap"
        && refused_index < total
        && run.warmup_count == refused_index.min(PIVOT_WARMUP_REQUESTS)
        && run.sent_count == refused_index.saturating_sub(PIVOT_WARMUP_REQUESTS)
        && run.durations.len() == run.sent_count
}

#[test]
fn authority_measurement_small_occupancy_accepts_only_clean_runs_or_overlap() {
    let mut run = super::pivot::OpenLoopRun {
        durations: vec![],
        completion_durations: vec![],
        warmup_count: 16,
        warmup_elapsed: Duration::from_secs(4),
        offered_rate: 4.0,
        achieved_rate: 0.0,
        max_send_lateness: Duration::ZERO,
        late_send_count: 0,
        completed_in_window: 0,
        failure_count: 0,
        stream_sample_counts: vec![0, 0],
        sent_count: 0,
        first_refusal: Some(super::pivot::FirstRefusal {
            kind: "overlap",
            time: Duration::from_secs(4),
            cycle_index: Some(14),
        }),
        conflict_token_counts: BTreeMap::new(),
        rate_limited_count: 0,
        max_outstanding_per_stream: vec![1, 1],
        max_outstanding_overall: 2,
        cycle_durations: vec![],
        refusal_cycle_duration: Some(Duration::from_millis(662)),
        observations: (2..=9)
            .flat_map(|generation| [Some(generation); 2])
            .collect(),
        drain_timed_out: false,
    };
    assert!(small_occupancy_accepts_run(&run, 16));

    run.failure_count = 1;
    assert!(!small_occupancy_accepts_run(&run, 16));
    run.failure_count = 0;

    run.first_refusal.as_mut().unwrap().kind = "deadline";
    assert!(!small_occupancy_accepts_run(&run, 16));
    run.first_refusal = None;
    assert!(!small_occupancy_accepts_run(&run, 16));

    run.warmup_count = PIVOT_WARMUP_REQUESTS;
    run.sent_count = 1;
    run.stream_sample_counts = vec![1, 0];
    run.durations.push(Duration::from_millis(662));
    run.first_refusal = Some(super::pivot::FirstRefusal {
        kind: "overlap",
        time: Duration::from_millis(16_250),
        cycle_index: Some(PIVOT_WARMUP_REQUESTS - 1),
    });
    let committed = PIVOT_WARMUP_REQUESTS + 1;
    assert!(small_occupancy_accepts_run(&run, committed));
    run.sent_count = 2;
    assert!(!small_occupancy_accepts_run(&run, committed));
    run.sent_count = 1;
    run.durations.clear();
    assert!(!small_occupancy_accepts_run(&run, committed));
}

#[tokio::test]
async fn authority_measurement_small_occupancy_uses_http_and_file_ops() {
    use super::super::intents as venue;

    // The lower rate leaves 500 ms per lane so the smoke test has more time
    // to exercise the workload before the driver can refuse an overlap.
    let workload = Some(PivotWorkload::RegisterOpenLoop {
        count: SMALL_OCCUPANCY_SAMPLES,
        rate: 4,
    });
    let dir = venue::scratch();
    let row = occupancy_row(
        &dir,
        2,
        SMALL_OCCUPANCY_LANES,
        1,
        1,
        workload,
        intent_log_length,
    )
    .await
    .unwrap();
    assert_eq!(
        (
            row.principals,
            row.row_holders,
            row.live_roots,
            row.released_rows,
            row.root_label,
        ),
        (2, 2, 2, 2, "707-B")
    );
    assert_eq!(
        row.amplification.written_bytes, row.amplification.full_snapshot_bytes,
        "the injected FileOps counter must observe the full snapshot pwrite"
    );
    assert!(!row.register_samples.is_empty(), "expected HTTP registers");
    assert!(
        run_p99(RecordedRun {
            profile: Profile::DurablePrepared,
            occupancy: Occupancy::Ceiling,
            offered_rate: None,
            load_model: "closed-loop",
            medium: "injected-file-ops",
            wrapper: "server-service",
            route: "/volume/:volume/intent",
            samples: &row.register_samples,
        })
        .is_ok()
    );
    assert!(row.committed_transitions > 0, "expected FileOps commits");
    assert!(row.intent_log_bytes.is_some_and(|bytes| bytes > 0));
    let pivot = row.pivot_run.as_ref().unwrap();
    assert!(
        small_occupancy_accepts_run(pivot, row.committed_transitions),
        "expected a complete HTTP run or an overlap refusal with a clean prefix: {row:?}"
    );
    let exported = pivot_observation_fields(&row);
    assert_eq!(
        (
            exported.get("root_bytes").map(String::as_str),
            exported.get("root_size_distribution").map(String::as_str),
            exported.get("zero_row_principals").map(String::as_str),
            exported.get("retired_principals").map(String::as_str),
            exported.get("historical_principals").map(String::as_str),
        ),
        (Some("707"), Some("707:2"), Some("0"), Some("0"), Some("2"))
    );
    let refused = occupancy_row(&venue::scratch(), 2, 2, 1, 1, workload, |path| {
        std::fs::remove_file(path).unwrap();
        intent_log_length(path)
    })
    .await
    .unwrap_err();
    assert!(
        refused.starts_with("pivot-intent-log-metadata: "),
        "{refused}"
    );
}

#[tokio::test]
#[ignore = "ceiling open-loop register row runs only in the authority venue"]
async fn authority_measurement_pivot_ceiling_register() -> Result<(), String> {
    use super::super::intents as venue;

    let ceiling_dir = venue::scratch();
    let ceiling = venue_occupancy_row(
        "pivot-numerator",
        &ceiling_dir,
        16_384,
        PopulationShape {
            occupancy: Occupancy::Ceiling,
            row_holders: 16,
            live_roots: 16,
            released_rows: 48,
        },
        PivotWorkload::RegisterOpenLoop {
            count: 1_000,
            rate: 46,
        },
    )
    .await?;
    let register = ceiling.pivot_run.as_ref().unwrap();
    assert_eq!(
        (register.failure_count, register.durations.len()),
        (0, 1_000),
        "the ruled pivot numerator requires a complete successful population"
    );
    export_pivot(
        "pivot_numerator",
        Profile::DurablePrepared,
        Occupancy::Ceiling,
        &ceiling,
    )?;
    Ok(())
}

async fn stepped_denominator<T, F, Fut>(
    mut measure: F,
) -> Result<(T, Vec<DenominatorAttempt>), String>
where
    F: FnMut(&'static str, super::pivot::OfferedRate) -> Fut,
    Fut: Future<Output = Result<(T, DenominatorAttempt), String>>,
{
    let rates = [
        ("pivot-denominator", super::pivot::OfferedRate::new(46, 1)),
        (
            "pivot-denominator-rate-23",
            super::pivot::OfferedRate::new(46, 2),
        ),
        (
            "pivot-denominator-rate-11-5",
            super::pivot::OfferedRate::new(46, 4),
        ),
    ];
    let mut attempts = Vec::new();
    let mut last_row = None;
    for (pass, rate) in rates {
        let (row, attempt) = measure(pass, rate).await?;
        let selected = attempt.qualifies();
        attempts.push(attempt);
        last_row = Some(row);
        if selected {
            break;
        }
    }
    Ok((
        last_row.ok_or("pivot denominator attempts missing")?,
        attempts,
    ))
}

#[tokio::test]
#[ignore = "floor open-loop publish row runs only in the authority venue"]
async fn authority_measurement_pivot_floor_publish() -> Result<(), String> {
    use super::super::intents as venue;

    let (mut floor, attempts) = stepped_denominator(|pass, rate| async move {
        let dir = venue::scratch();
        let row = venue_occupancy_row(
            pass,
            &dir,
            1,
            PopulationShape {
                occupancy: Occupancy::Floor,
                row_holders: 1,
                live_roots: 16,
                released_rows: 48,
            },
            PivotWorkload::PublishOpenLoop {
                count: 1_000,
                rate,
                stream_count: MAX_PUBLISH_STREAMS,
            },
        )
        .await?;
        let run = row
            .pivot_run
            .as_ref()
            .ok_or_else(|| "pivot denominator open-loop observation missing".to_owned())?;
        let pilot = row
            .publish_pilot
            .ok_or_else(|| "pivot denominator pilot observation missing".to_owned())?;
        let log_wait: Vec<_> = row
            .authority_log_wait_samples
            .iter()
            .map(Duration::as_nanos)
            .collect();
        let log_wait_p99 = if run.drain_timed_out && log_wait.is_empty() {
            0
        } else {
            super::output::quantile(&log_wait, 99).map_err(str::to_owned)?
        };
        let attempt = DenominatorAttempt::from_run(run, pilot, log_wait_p99)?;
        if run.first_refusal.is_none()
            && (run.failure_count != 0
                || run.durations.len() != 1_000
                || run.achieved_rate < run.offered_rate * 0.95)
        {
            return Err(format!(
                "pivot denominator incomplete: rate={}, samples={}, failures={}, achieved={}",
                run.offered_rate,
                run.durations.len(),
                run.failure_count,
                run.achieved_rate
            ));
        }
        Ok((row, attempt))
    })
    .await?;
    floor.denominator_attempts = attempts;
    export_pivot(
        "pivot_denominator",
        Profile::Published,
        Occupancy::Floor,
        &floor,
    )?;
    Ok(())
}

#[tokio::test]
#[ignore = "ceiling publish diagnostic runs only in the authority venue"]
async fn authority_measurement_pivot_ceiling_publish_diagnostic() -> Result<(), String> {
    use super::super::intents as venue;

    let dir = venue::scratch();
    let ceiling = venue_occupancy_row(
        "pivot-diagnostic",
        &dir,
        16_384,
        PopulationShape {
            occupancy: Occupancy::Ceiling,
            row_holders: 16,
            live_roots: 16,
            released_rows: 48,
        },
        PivotWorkload::PublishDiagnostic {
            count: PUBLISH_DIAGNOSTIC_SAMPLES,
        },
    )
    .await?;
    if ceiling.diagnostic_run.stall_index.is_none()
        && ceiling.diagnostic_run.durations.len() != PUBLISH_DIAGNOSTIC_SAMPLES
    {
        return Err(format!(
            "pivot diagnostic sample population: observed={}, required={PUBLISH_DIAGNOSTIC_SAMPLES}",
            ceiling.diagnostic_run.durations.len()
        ));
    }
    export_pivot(
        "pivot_same_occupancy_publish",
        Profile::Published,
        Occupancy::Ceiling,
        &ceiling,
    )?;
    Ok(())
}

#[tokio::test]
#[ignore = "exact P1/P16/Z16384 occupancy cells run only in the authority venue"]
async fn authority_measurement_full_occupancy_cells() {
    use super::super::intents as venue;

    for holders in [1, 16] {
        let dir = venue::scratch();
        let row = occupancy_row(&dir, holders, holders, 16, 48, None, intent_log_length)
            .await
            .unwrap();
        assert_eq!(row.live_roots, holders * 16);
        assert_eq!(row.released_rows, holders * 48);
        assert_eq!(row.root_label, "707-B");
        export_occupancy(&format!("intent_p{holders}"), &row);
    }
    let zero = install(vec![enrollment(0, 16_384, 0)]).await;
    assert_eq!(zero.0, 16_384);
    super::output::write(
        "intent_z16384",
        &std::collections::BTreeMap::from([
            ("principals".to_owned(), zero.0.to_string()),
            ("full_snapshot_bytes".to_owned(), zero.1.to_string()),
        ]),
    );
    let dir = venue::scratch();
    let ceiling = occupancy_row(&dir, 16_384, 16, 16, 48, None, intent_log_length)
        .await
        .unwrap();
    assert_eq!(
        (ceiling.principals, ceiling.row_holders, ceiling.live_roots),
        (16_384, 16, 256)
    );
    export_occupancy("intent_ceiling", &ceiling);
}

#[tokio::test]
#[ignore = "full 16,384-principal occupancy cells run only in the authority venue"]
async fn authority_measurement_full_historical_series_stops_at_65536() {
    let mut snapshot_sizes = Vec::new();
    for retired in [0, 4_096, 16_368] {
        let set = enrollment(0, 16_384, retired);
        assert_eq!(set.principal_count(), 16_384);
        assert_eq!(set.credential_count(), 16_384 - retired);
        let (principals, bytes) = install(vec![set]).await;
        assert_eq!(principals, 16_384);
        snapshot_sizes.push(bytes);
        super::output::write(
            &format!("intent_h16384_retired_{retired}"),
            &std::collections::BTreeMap::from([
                ("historical_principals".to_owned(), principals.to_string()),
                ("retired_principals".to_owned(), retired.to_string()),
                ("full_snapshot_bytes".to_owned(), bytes.to_string()),
            ]),
        );
    }
    let replacements: Vec<_> = (0..4)
        .map(|batch| enrollment(batch * 16_384, 16_384, 0))
        .collect();
    let upper = install(replacements).await;
    assert_eq!(
        upper.0, 65_536,
        "upper bound; unreachable through enrollment mutations"
    );
    super::output::write(
        "intent_h65536_upper_bound",
        &std::collections::BTreeMap::from([
            ("historical_principals".to_owned(), upper.0.to_string()),
            ("full_snapshot_bytes".to_owned(), upper.1.to_string()),
            (
                "label".to_owned(),
                "upper bound; unreachable through enrollment mutations".to_owned(),
            ),
            ("pivot_input".to_owned(), "false".to_owned()),
        ]),
    );
    let first = snapshot_sizes.first().copied().unwrap();
    assert!(snapshot_sizes.iter().all(|size| *size == first));
}
