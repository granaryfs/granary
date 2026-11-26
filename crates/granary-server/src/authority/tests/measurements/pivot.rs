// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduled open-loop issue times for the ruled pivot pair.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

trait PivotClock: Clone + Send + Sync + 'static {
    fn now(&self) -> Instant;
    fn wait_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
}

#[derive(Clone, Copy)]
struct WallClock;

impl PivotClock for WallClock {
    fn now(&self) -> Instant {
        super::stopwatch()
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the pivot Clock seam's absolute wall-timer implementation"
    )]
    fn wait_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline,
        )))
    }
}

#[derive(Debug)]
pub(super) struct OpenLoopRun {
    pub(super) durations: Vec<Duration>,
    pub(super) completion_durations: Vec<Duration>,
    pub(super) warmup_count: usize,
    pub(super) warmup_elapsed: Duration,
    pub(super) offered_rate: f64,
    pub(super) achieved_rate: f64,
    pub(super) max_send_lateness: Duration,
    pub(super) late_send_count: usize,
    pub(super) completed_in_window: usize,
    pub(super) failure_count: usize,
    pub(super) stream_sample_counts: Vec<usize>,
    pub(super) sent_count: usize,
    pub(super) first_refusal: Option<FirstRefusal>,
    pub(super) conflict_token_counts: BTreeMap<String, usize>,
    pub(super) rate_limited_count: usize,
    pub(super) max_outstanding_per_stream: Vec<usize>,
    pub(super) max_outstanding_overall: usize,
    pub(super) cycle_durations: Vec<(Duration, Duration)>,
    pub(super) refusal_cycle_duration: Option<Duration>,
    pub(super) observations: Vec<Option<u64>>,
    pub(super) drain_timed_out: bool,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RequestTiming {
    decision: Option<Duration>,
    completion: Option<Duration>,
    observed: Option<u64>,
}

impl RequestTiming {
    const fn whole() -> Self {
        Self {
            decision: None,
            completion: None,
            observed: None,
        }
    }

    pub(super) const fn publish(decision: Duration, completion: Duration) -> Self {
        Self {
            decision: Some(decision),
            completion: Some(completion),
            observed: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct OfferedRate {
    numerator: u32,
    divisor: u32,
}

impl OfferedRate {
    pub(super) const fn new(numerator: u32, divisor: u32) -> Self {
        Self { numerator, divisor }
    }

    pub(super) fn as_f64(self) -> f64 {
        f64::from(self.numerator) / f64::from(self.divisor)
    }

    pub(super) fn spacing(self) -> Result<Duration, &'static str> {
        if self.numerator == 0 || self.divisor == 0 {
            return Err("pivot schedule requires a positive rate");
        }
        let nanos = 1_000_000_000_u64
            .checked_mul(u64::from(self.divisor))
            .ok_or("pivot schedule is too large")?
            .div_ceil(u64::from(self.numerator));
        Ok(Duration::from_nanos(nanos))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RequestFailure {
    Conflict(String),
    RateLimited,
    Other(&'static str),
    DepthMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FirstRefusal {
    pub(super) kind: &'static str,
    pub(super) time: Duration,
    pub(super) cycle_index: Option<usize>,
}

fn record_first_refusal(
    target: &Mutex<Option<FirstRefusal>>,
    kind: &'static str,
    time: Duration,
    cycle_index: Option<usize>,
) -> bool {
    let mut refusal = target
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if refusal.is_some() {
        return false;
    }
    *refusal = Some(FirstRefusal {
        kind,
        time,
        cycle_index,
    });
    true
}

fn scheduled_deadlines(count: usize, rate: OfferedRate) -> Result<Vec<Duration>, &'static str> {
    if count == 0 {
        return Err("pivot schedule requires a positive population and rate");
    }
    let spacing = rate.spacing()?;
    (0..count)
        .map(|index| {
            let multiplier = u32::try_from(index).map_err(|_| "pivot schedule is too large")?;
            spacing
                .checked_mul(multiplier)
                .ok_or("pivot schedule is too large")
        })
        .collect()
}

pub(super) const DENOMINATOR_STREAMS: usize = 64;
const DENOMINATOR_SEND_ALLOWANCE: Duration = Duration::from_nanos(1_000_000_000_u64.div_ceil(46));
const DENOMINATOR_CYCLE_LIMIT: Duration = DENOMINATOR_SEND_ALLOWANCE.saturating_mul(64);

// Exact two-sided 5% hypergeometric critical counts for 1,000 samples
// split into two halves, indexed by pooled exceedances above p95 or p99.
const TAIL_CRITICAL_COUNTS: [usize; 51] = [
    1, 2, 3, 4, 5, 6, 6, 7, 8, 8, 9, 10, 10, 11, 12, 12, 13, 13, 14, 15, 15, 16, 16, 17, 18, 18,
    19, 19, 20, 21, 21, 22, 22, 23, 24, 24, 25, 25, 26, 26, 27, 28, 28, 29, 29, 30, 30, 31, 32, 32,
    33,
];

pub(super) fn denominator_is_steady(samples: &[Duration]) -> bool {
    assert_eq!(samples.len(), 1_000);
    let (first, second) = samples.split_at(500);
    let median = |half: &[Duration]| {
        let mut sorted = half.to_vec();
        sorted.sort_unstable();
        let sum = sorted[249].as_nanos() + sorted[250].as_nanos();
        sum / 2 + u128::from(sum % 4 == 3)
    };
    let (a, b) = (median(first), median(second));
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    a.abs_diff(b) * 10 <= a.max(b).max(1)
        && [sorted[949], sorted[989]].into_iter().all(|threshold| {
            let exceedances = |half: &[Duration]| half.iter().filter(|&&d| d > threshold).count();
            let (first, second) = (exceedances(first), exceedances(second));
            first.max(second) < TAIL_CRITICAL_COUNTS[first + second]
        })
}

enum OpenLoopLimits {
    Standard(Duration),
    Publish(Duration),
}

const PUBLISH_LIMITS: OpenLoopLimits = OpenLoopLimits::Publish(Duration::from_secs(30));

#[expect(
    clippy::disallowed_methods,
    reason = "the wall-clock measurement owns concurrent requests issued on an absolute schedule"
)]
#[expect(
    clippy::too_many_lines,
    reason = "the absolute issue schedule and its refusal counts form one measurement"
)]
async fn run_open_loop_timed<C, F, Fut>(
    clock: C,
    warmup_count: usize,
    count: usize,
    rate: OfferedRate,
    stream_count: usize,
    limits: OpenLoopLimits,
    issue: F,
) -> Result<OpenLoopRun, String>
where
    C: PivotClock,
    F: Fn(usize) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<RequestTiming, RequestFailure>> + Send + 'static,
{
    if stream_count == 0 {
        return Err("pivot requires a nonempty stream population".to_owned());
    }
    let total_count = warmup_count
        .checked_add(count)
        .ok_or_else(|| "pivot sample count exceeds usize".to_owned())?;
    let offsets = scheduled_deadlines(total_count, rate).map_err(str::to_owned)?;
    let count_u32 =
        u32::try_from(count).map_err(|_| "pivot sample count exceeds u32".to_owned())?;
    let total_count_u32 =
        u32::try_from(total_count).map_err(|_| "pivot sample count exceeds u32".to_owned())?;
    let spacing = rate.spacing().map_err(str::to_owned)?;
    let (join_timeout, send_allowance, cycle_limit) = match limits {
        OpenLoopLimits::Standard(join) => (join, spacing, None),
        OpenLoopLimits::Publish(join) => (
            join,
            DENOMINATOR_SEND_ALLOWANCE,
            Some(DENOMINATOR_CYCLE_LIMIT),
        ),
    };
    let origin = clock.now();
    let window_end = origin
        .checked_add(
            spacing
                .checked_mul(total_count_u32)
                .ok_or("pivot schedule is too large")?,
        )
        .ok_or("pivot schedule is too large")
        .map_err(str::to_owned)?;
    let mut max_send_lateness = Duration::ZERO;
    let mut late_send_count = 0;
    let mut warmup_late_send_count = 0_usize;
    let mut warmup_sent_count = 0_usize;
    let mut warmup_elapsed = None;
    let mut stream_sample_counts = vec![0; stream_count];
    let active: Arc<Vec<_>> = Arc::new((0..stream_count).map(|_| AtomicUsize::new(0)).collect());
    let maximum_per_stream: Arc<Vec<_>> =
        Arc::new((0..stream_count).map(|_| AtomicUsize::new(0)).collect());
    let active_overall = Arc::new(AtomicUsize::new(0));
    let maximum_overall = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let first_refusal = Arc::new(Mutex::new(None));
    let mut tasks = tokio::task::JoinSet::new();
    for (index, offset) in offsets.into_iter().enumerate() {
        let deadline = origin
            .checked_add(offset)
            .ok_or("pivot schedule is too large")
            .map_err(str::to_owned)?;
        clock.wait_until(deadline).await;
        let sent = clock.now();
        if stop.load(Ordering::Acquire) {
            break;
        }
        let warmup = index < warmup_count;
        if !warmup && warmup_elapsed.is_none() {
            warmup_elapsed = Some(sent.saturating_duration_since(origin));
        }
        let lateness = sent.saturating_duration_since(deadline);
        max_send_lateness = max_send_lateness.max(lateness);
        if lateness > send_allowance {
            if warmup {
                warmup_late_send_count += 1;
            } else {
                late_send_count += 1;
            }
        }
        let stream = index % stream_count;
        if active[stream].fetch_add(1, Ordering::AcqRel) != 0 {
            active[stream].fetch_sub(1, Ordering::AcqRel);
            stop.store(true, Ordering::Release);
            record_first_refusal(
                &first_refusal,
                "overlap",
                sent.saturating_duration_since(origin),
                index.checked_sub(stream_count),
            );
            break;
        }
        if warmup {
            warmup_sent_count += 1;
        } else {
            stream_sample_counts[stream] += 1;
        }
        maximum_per_stream[stream].fetch_max(1, Ordering::AcqRel);
        let outstanding = active_overall.fetch_add(1, Ordering::AcqRel) + 1;
        maximum_overall.fetch_max(outstanding, Ordering::AcqRel);
        let task_clock = clock.clone();
        let task_issue = issue.clone();
        let active = active.clone();
        let active_overall = active_overall.clone();
        let first_refusal = first_refusal.clone();
        let stop = stop.clone();
        tasks.spawn(async move {
            let issued = task_clock.now();
            let cycle = task_issue(index);
            tokio::pin!(cycle);
            let refuse_deadline = |observed: Instant| {
                record_first_refusal(
                    &first_refusal,
                    "cycle-deadline",
                    observed.saturating_duration_since(origin),
                    Some(index),
                );
                stop.store(true, Ordering::Release);
            };
            let result = if let Some(limit) = cycle_limit {
                let mut timer = task_clock.wait_until(deadline + limit + Duration::from_nanos(1));
                let result = poll_fn(|cx| {
                    if let Poll::Ready(result) = cycle.as_mut().poll(cx) {
                        return Poll::Ready(Some(result));
                    }
                    timer.as_mut().poll(cx).map(|()| None)
                })
                .await;
                if let Some(result) = result {
                    result
                } else {
                    refuse_deadline(task_clock.now());
                    cycle.await
                }
            } else {
                cycle.await
            };
            let completed = task_clock.now();
            if cycle_limit
                .is_some_and(|limit| completed.saturating_duration_since(deadline) > limit)
            {
                refuse_deadline(completed);
            }
            // The lane becomes reusable when the request cycle finishes, before
            // result bookkeeping can race the next absolute schedule slot.
            active[stream].fetch_sub(1, Ordering::AcqRel);
            active_overall.fetch_sub(1, Ordering::AcqRel);
            if matches!(
                &result,
                Err(RequestFailure::Conflict(_)
                    | RequestFailure::RateLimited
                    | RequestFailure::DepthMismatch)
            ) {
                let kind = match &result {
                    Err(RequestFailure::Conflict(_)) => "409",
                    Err(RequestFailure::RateLimited) => "429",
                    Err(RequestFailure::DepthMismatch) => "depth-mismatch",
                    _ => unreachable!(),
                };
                if record_first_refusal(
                    &first_refusal,
                    kind,
                    completed.saturating_duration_since(origin),
                    None,
                ) {
                    stop.store(true, Ordering::Release);
                }
            }
            let timing = result.as_ref().ok().copied();
            let duration = timing.and_then(|timing| timing.decision).map_or_else(
                || completed.saturating_duration_since(deadline),
                |decision| issued.saturating_duration_since(deadline) + decision,
            );
            (
                index,
                result,
                duration,
                completed,
                completed.saturating_duration_since(issued),
                completed.saturating_duration_since(deadline),
            )
        });
    }
    let sent_count: usize = stream_sample_counts.iter().sum();
    let on_schedule = sent_count.saturating_sub(late_send_count);
    let on_schedule = u32::try_from(on_schedule).map_err(|_| "pivot sample count exceeds u32")?;
    let achieved_rate = rate.as_f64() * f64::from(on_schedule) / f64::from(count_u32);
    let warmup_on_schedule = warmup_sent_count.saturating_sub(warmup_late_send_count);
    let mut joined = Vec::with_capacity(count);
    let drained = tokio::time::timeout(join_timeout, async {
        while let Some(result) = tasks.join_next().await {
            joined.push(result.map_err(|_| "pivot request task failed".to_owned())?);
        }
        Ok::<_, String>(())
    })
    .await;
    let drain_timed_out = match drained {
        Ok(Ok(())) => false,
        Ok(Err(error)) => return Err(error),
        Err(_) => true,
    };
    let mut completed_in_window = 0;
    let mut failure_count = 0;
    let mut conflict_token_counts = BTreeMap::new();
    let mut rate_limited_count = 0;
    let mut durations = Vec::with_capacity(count);
    let mut completion_durations = Vec::with_capacity(count);
    let first_refusal = first_refusal
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if first_refusal.is_none() && achieved_rate < rate.as_f64() * 0.95 {
        return Err("pivot achieved rate shortfall".to_owned());
    }
    if first_refusal.is_none()
        && (warmup_sent_count != warmup_count
            || warmup_on_schedule.saturating_mul(100) < warmup_count.saturating_mul(95))
    {
        return Err("pivot warmup achieved rate shortfall".to_owned());
    }
    let mut refusal_cycle_duration = None;
    if drain_timed_out {
        let Some(refusal) = &first_refusal else {
            return Err("pivot request completion deadline".to_owned());
        };
        tasks.shutdown().await;
        refusal_cycle_duration = refusal.cycle_index.map(|index| {
            refusal
                .time
                .saturating_sub(spacing * u32::try_from(index).unwrap())
        });
    }
    let mut observations = vec![None; warmup_sent_count + sent_count];
    let mut cycle_durations = Vec::with_capacity(count);
    for (index, result, duration, completed, cycle_duration, scheduled_cycle) in joined {
        let measured = index >= warmup_count;
        if measured && completed <= window_end {
            completed_in_window += 1;
        }
        if let Some(refusal) = &first_refusal
            && refusal.cycle_index == Some(index)
        {
            refusal_cycle_duration = Some(if refusal.kind == "overlap" {
                cycle_duration
            } else {
                scheduled_cycle
            });
        }
        match result {
            Ok(timing) => {
                observations[index] = timing.observed;
                if measured {
                    cycle_durations.push((
                        index,
                        (cycle_duration, completed.saturating_duration_since(origin)),
                    ));
                    durations.push((index, duration));
                    if let Some(completion) = timing.completion {
                        completion_durations.push((index, completion));
                    }
                }
            }
            Err(RequestFailure::Conflict(token)) => {
                *conflict_token_counts.entry(token).or_insert(0) += 1;
            }
            Err(RequestFailure::RateLimited) => rate_limited_count += 1,
            Err(RequestFailure::Other(_)) => failure_count += 1,
            Err(RequestFailure::DepthMismatch) => {
                return Err("pivot candidate depth mismatch".to_owned());
            }
        }
    }
    durations.sort_unstable_by_key(|(index, _)| *index);
    completion_durations.sort_unstable_by_key(|(index, _)| *index);
    cycle_durations.sort_unstable_by_key(|(index, _)| *index);
    let warmup_elapsed = if warmup_count == 0 {
        Duration::ZERO
    } else {
        warmup_elapsed
            .or_else(|| first_refusal.as_ref().map(|refusal| refusal.time))
            .unwrap_or_else(|| clock.now().saturating_duration_since(origin))
    };
    Ok(OpenLoopRun {
        durations: durations
            .into_iter()
            .map(|(_, duration)| duration)
            .collect(),
        completion_durations: completion_durations
            .into_iter()
            .map(|(_, duration)| duration)
            .collect(),
        warmup_count: warmup_sent_count,
        warmup_elapsed,
        offered_rate: rate.as_f64(),
        achieved_rate,
        max_send_lateness,
        late_send_count,
        completed_in_window,
        failure_count,
        stream_sample_counts,
        sent_count,
        first_refusal,
        conflict_token_counts,
        rate_limited_count,
        max_outstanding_per_stream: maximum_per_stream
            .iter()
            .map(|maximum| maximum.load(Ordering::Acquire))
            .collect(),
        max_outstanding_overall: maximum_overall.load(Ordering::Acquire),
        cycle_durations: cycle_durations
            .into_iter()
            .map(|(_, duration)| duration)
            .collect(),
        refusal_cycle_duration,
        observations,
        drain_timed_out,
    })
}

async fn run_open_loop<C, F, Fut>(
    clock: C,
    count: usize,
    rate: OfferedRate,
    stream_count: usize,
    join_timeout: Duration,
    issue: F,
) -> Result<OpenLoopRun, String>
where
    C: PivotClock,
    F: Fn(usize) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<(), RequestFailure>> + Send + 'static,
{
    run_open_loop_timed(
        clock,
        0,
        count,
        rate,
        stream_count,
        OpenLoopLimits::Standard(join_timeout),
        move |index| {
            let issue = issue.clone();
            async move { issue(index).await.map(|()| RequestTiming::whole()) }
        },
    )
    .await
}

pub(super) async fn run_wall_open_loop<F, Fut>(
    warmup_count: usize,
    count: usize,
    rate: OfferedRate,
    stream_count: usize,
    join_timeout: Duration,
    issue: F,
) -> Result<OpenLoopRun, String>
where
    F: Fn(usize) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<u64, RequestFailure>> + Send + 'static,
{
    run_open_loop_timed(
        WallClock,
        warmup_count,
        count,
        rate,
        stream_count,
        OpenLoopLimits::Standard(join_timeout),
        move |index| {
            let issue = issue.clone();
            async move {
                issue(index).await.map(|value| RequestTiming {
                    observed: Some(value),
                    ..RequestTiming::whole()
                })
            }
        },
    )
    .await
}

pub(super) async fn run_wall_open_loop_phased<F, Fut>(
    warmup_count: usize,
    count: usize,
    rate: OfferedRate,
    stream_count: usize,
    issue: F,
) -> Result<OpenLoopRun, String>
where
    F: Fn(usize) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<RequestTiming, RequestFailure>> + Send + 'static,
{
    run_open_loop_timed(
        WallClock,
        warmup_count,
        count,
        rate,
        stream_count,
        PUBLISH_LIMITS,
        issue,
    )
    .await
}

#[derive(Clone)]
struct FakePivotClock {
    origin: Instant,
    elapsed: Arc<Mutex<Duration>>,
    wake_lateness: Arc<Mutex<Vec<Duration>>>,
}

impl FakePivotClock {
    fn new(wake_lateness: Vec<Duration>) -> Self {
        Self {
            origin: super::stopwatch(),
            elapsed: Arc::new(Mutex::new(Duration::ZERO)),
            wake_lateness: Arc::new(Mutex::new(wake_lateness)),
        }
    }
}

impl PivotClock for FakePivotClock {
    fn now(&self) -> Instant {
        self.origin + *self.elapsed.lock().unwrap()
    }

    fn wait_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        let clock = self.clone();
        Box::pin(async move {
            let extra = {
                let mut wake_lateness = clock.wake_lateness.lock().unwrap();
                if wake_lateness.is_empty() {
                    Duration::ZERO
                } else {
                    wake_lateness.remove(0)
                }
            };
            let target = deadline.saturating_duration_since(clock.origin) + extra;
            let mut elapsed = clock.elapsed.lock().unwrap();
            *elapsed = (*elapsed).max(target);
        })
    }
}

#[tokio::test]
async fn authority_measurement_pivot_measures_from_the_scheduled_send_time() {
    let run = run_open_loop(
        FakePivotClock::new(vec![Duration::from_millis(25)]),
        1,
        OfferedRate::new(10, 1),
        1,
        Duration::from_secs(1),
        |_| async { Ok(()) },
    )
    .await
    .unwrap();
    assert_eq!(
        run.durations,
        [Duration::from_millis(25)],
        "measuring from the actual late send would report zero"
    );
    assert_eq!(
        (run.max_send_lateness, run.late_send_count),
        (Duration::from_millis(25), 0)
    );
}

#[tokio::test]
async fn authority_measurement_pivot_applies_the_46_rate_limits_at_23() {
    let rate = OfferedRate::new(46, 2);
    let run = run_wall_open_loop_phased(1, 1, rate, DENOMINATOR_STREAMS, |index| async move {
        if index == 0 {
            WallClock
                .wait_until(super::stopwatch() + Duration::from_millis(1_410))
                .await;
        }
        Ok(RequestTiming::publish(
            Duration::from_millis(1),
            Duration::from_millis(1_409),
        ))
    })
    .await
    .unwrap();
    assert_eq!(run.first_refusal.unwrap().kind, "cycle-deadline");
    assert!(run.refusal_cycle_duration.unwrap() > DENOMINATOR_CYCLE_LIMIT);

    let late = run_open_loop_timed(
        FakePivotClock::new(vec![Duration::from_millis(30)]),
        0,
        1,
        rate,
        DENOMINATOR_STREAMS,
        PUBLISH_LIMITS,
        |_| async { Ok(RequestTiming::whole()) },
    )
    .await
    .unwrap_err();
    assert_eq!(late, "pivot achieved rate shortfall");
}

#[tokio::test]
async fn authority_measurement_pivot_keeps_deadline_refusal_after_drain_timeout() {
    for expected in ["cycle-deadline", "409"] {
        let run = run_open_loop_timed(
            FakePivotClock::new(Vec::new()),
            0,
            2,
            OfferedRate::new(46, 2),
            DENOMINATOR_STREAMS,
            OpenLoopLimits::Publish(Duration::from_millis(20)),
            move |index| async move {
                if index == 1 {
                    std::future::pending().await
                } else if expected == "409" {
                    Err(RequestFailure::Conflict("operation-bound".to_owned()))
                } else {
                    Ok(RequestTiming::whole())
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(run.first_refusal.unwrap().kind, expected);
        assert!(run.drain_timed_out);
        assert_eq!(
            run.durations.len(),
            usize::from(expected == "cycle-deadline")
        );
        if expected == "cycle-deadline" {
            assert!(run.refusal_cycle_duration.unwrap() > DENOMINATOR_CYCLE_LIMIT);
        } else {
            assert_eq!(run.refusal_cycle_duration, None);
            assert_eq!(run.conflict_token_counts.get("operation-bound"), Some(&1));
        }
    }
}

#[tokio::test]
async fn authority_measurement_pivot_records_overlap_at_the_46_rate_deadline() {
    let run = run_open_loop_timed(
        FakePivotClock::new(Vec::new()),
        DENOMINATOR_STREAMS,
        1,
        OfferedRate::new(46, 1),
        DENOMINATOR_STREAMS,
        PUBLISH_LIMITS,
        |_| async { Ok(RequestTiming::whole()) },
    )
    .await
    .unwrap();
    // The lane is reserved until its task runs. The revisit at the exact
    // threshold precedes the timer for a cycle strictly past that threshold.
    let refusal = run.first_refusal.unwrap();
    assert_eq!(
        (refusal.kind, refusal.time),
        ("overlap", DENOMINATOR_CYCLE_LIMIT)
    );
    assert_eq!((run.warmup_count, run.sent_count), (DENOMINATOR_STREAMS, 0));
}

#[tokio::test]
async fn authority_measurement_pivot_records_completion_outside_the_decision_sample() {
    let clock = FakePivotClock::new(Vec::new());
    let issue_clock = clock.clone();
    let run = run_open_loop_timed(
        clock,
        0,
        1,
        OfferedRate::new(10, 1),
        1,
        OpenLoopLimits::Standard(Duration::from_secs(1)),
        move |_| {
            let clock = issue_clock.clone();
            async move {
                let until = clock.now() + Duration::from_millis(30);
                clock.wait_until(until).await;
                Ok(RequestTiming::publish(
                    Duration::from_millis(5),
                    Duration::from_millis(25),
                ))
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(run.durations, [Duration::from_millis(5)]);
    assert_eq!(run.completion_durations, [Duration::from_millis(25)]);
}

#[tokio::test]
async fn authority_measurement_pivot_excludes_the_scheduled_warmup_prefix() {
    let run = run_open_loop_timed(
        FakePivotClock::new(Vec::new()),
        2,
        3,
        OfferedRate::new(10, 1),
        5,
        OpenLoopLimits::Standard(Duration::from_secs(1)),
        |index| async move {
            let duration = Duration::from_millis(u64::try_from(index + 1).unwrap());
            Ok(RequestTiming::publish(duration, duration))
        },
    )
    .await
    .unwrap();
    assert_eq!(
        (
            run.warmup_count,
            run.warmup_elapsed,
            run.durations.len(),
            run.completion_durations,
            run.sent_count,
            run.stream_sample_counts,
        ),
        (
            2,
            Duration::from_millis(200),
            3,
            vec![
                Duration::from_millis(3),
                Duration::from_millis(4),
                Duration::from_millis(5)
            ],
            3,
            vec![0, 0, 1, 1, 1],
        ),
        "warmup requests must keep their guards without entering the measured window"
    );
}

#[tokio::test]
async fn authority_measurement_pivot_refuses_an_overlap_in_the_warmup_prefix() {
    let run = run_open_loop_timed(
        WallClock,
        2,
        3,
        OfferedRate::new(46, 1),
        1,
        OpenLoopLimits::Standard(Duration::from_secs(1)),
        |_| async {
            WallClock
                .wait_until(super::stopwatch() + Duration::from_millis(30))
                .await;
            Ok(RequestTiming::whole())
        },
    )
    .await
    .unwrap();
    assert_eq!(
        (
            run.first_refusal.as_ref().map(|refusal| refusal.kind),
            run.warmup_count,
            run.sent_count,
            run.durations.len(),
        ),
        (Some("overlap"), 1, 0, 0),
    );
}

#[tokio::test]
async fn authority_measurement_pivot_refuses_a_midrun_schedule_shortfall() {
    let result = run_open_loop(
        FakePivotClock::new(vec![
            Duration::ZERO,
            Duration::from_millis(150),
            Duration::ZERO,
            Duration::ZERO,
        ]),
        4,
        OfferedRate::new(10, 1),
        4,
        Duration::from_secs(1),
        |_| async { Ok(()) },
    )
    .await;
    assert_eq!(result.unwrap_err(), "pivot achieved rate shortfall");
}

#[tokio::test]
async fn authority_measurement_pivot_bounds_request_completion() {
    let started = super::stopwatch();
    let result = run_open_loop(
        WallClock,
        1,
        OfferedRate::new(10, 1),
        1,
        Duration::from_millis(10),
        |_| async { std::future::pending::<Result<(), RequestFailure>>().await },
    )
    .await;
    assert_eq!(result.unwrap_err(), "pivot request completion deadline");
    assert!(started.elapsed() < Duration::from_millis(100));
}

#[tokio::test]
async fn authority_measurement_pivot_keeps_slow_requests_in_flight() {
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let run = run_open_loop(
        WallClock,
        4,
        OfferedRate::new(10, 1),
        4,
        Duration::from_secs(2),
        {
            let active = active.clone();
            let maximum = maximum.clone();
            move |_| {
                let active = active.clone();
                let maximum = maximum.clone();
                async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(current, Ordering::SeqCst);
                    WallClock
                        .wait_until(super::stopwatch() + Duration::from_millis(300))
                        .await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                }
            }
        },
    )
    .await
    .unwrap();
    assert_eq!((run.durations.len(), run.offered_rate), (4, 10.0));
    assert!(run.achieved_rate >= 9.5, "{run:?}");
    assert!(
        maximum.load(Ordering::SeqCst) > 1,
        "a slow request did not overlap its next scheduled send"
    );
    assert!(
        run.durations
            .iter()
            .all(|duration| *duration >= Duration::from_millis(300)),
        "durations must start at scheduled send time: {run:?}"
    );
    assert_eq!(run.failure_count, 0);
    assert!(run.completed_in_window > 0, "{run:?}");
}

#[tokio::test]
async fn authority_measurement_pivot_refuses_busy_or_rate_limited_streams() {
    let issue = |_| async {
        WallClock
            .wait_until(super::stopwatch() + Duration::from_millis(30))
            .await;
        Ok(())
    };
    let single = run_open_loop(
        WallClock,
        4,
        OfferedRate::new(46, 1),
        1,
        Duration::from_secs(2),
        issue,
    )
    .await
    .unwrap();
    assert_eq!(
        single.refusal_cycle_duration,
        single
            .cycle_durations
            .first()
            .map(|&(duration, _)| duration),
        "the refusing stall is recorded at its final joined duration"
    );
    assert!(single.refusal_cycle_duration.is_some(), "{single:?}");
    assert_eq!(single.first_refusal.unwrap().kind, "overlap");
    assert_eq!(single.sent_count, 1, "the first overlap must stop the run");
    let rotated = run_open_loop(
        WallClock,
        4,
        OfferedRate::new(46, 1),
        2,
        Duration::from_secs(2),
        issue,
    )
    .await
    .unwrap();
    assert_eq!(
        (rotated.durations.len(), rotated.stream_sample_counts),
        (4, vec![2, 2])
    );

    let limited = run_open_loop(
        WallClock,
        1,
        OfferedRate::new(10, 1),
        1,
        Duration::from_secs(1),
        |_| async { Err(RequestFailure::RateLimited) },
    )
    .await
    .unwrap();
    assert_eq!(limited.first_refusal.unwrap().kind, "429");
    assert_eq!(limited.rate_limited_count, 1);

    let conflicted = run_open_loop(
        WallClock,
        4,
        OfferedRate::new(10, 1),
        4,
        Duration::from_secs(1),
        |_| async { Err(RequestFailure::Conflict("stale-base".to_owned())) },
    )
    .await
    .unwrap();
    assert_eq!(conflicted.first_refusal.unwrap().kind, "409");
    assert_eq!(conflicted.sent_count, 1, "a 409 must stop later slots");
    assert_eq!(
        conflicted.conflict_token_counts,
        BTreeMap::from([("stale-base".to_owned(), 1)]),
        "the 409 token must not be discarded"
    );
}

#[tokio::test]
async fn authority_measurement_pivot_failed_overlap_retains_a_typed_duration() {
    let run = run_open_loop(
        WallClock,
        2,
        OfferedRate::new(46, 1),
        1,
        Duration::from_secs(1),
        |_| async {
            WallClock
                .wait_until(super::stopwatch() + Duration::from_millis(30))
                .await;
            Err(RequestFailure::Other("failed cycle"))
        },
    )
    .await
    .unwrap();
    assert_eq!(
        run.first_refusal.as_ref().map(|item| item.kind),
        Some("overlap")
    );
    assert!(run.refusal_cycle_duration.is_some(), "{run:?}");
    assert_eq!(run.failure_count, 1);
}

#[test]
fn authority_measurement_pivot_first_refusal_is_write_once() {
    let refusal = Mutex::new(None);
    assert!(record_first_refusal(
        &refusal,
        "409",
        Duration::from_millis(1),
        None,
    ));
    assert!(!record_first_refusal(
        &refusal,
        "overlap",
        Duration::from_millis(2),
        None,
    ));
    assert_eq!(
        refusal.into_inner().unwrap(),
        Some(FirstRefusal {
            kind: "409",
            time: Duration::from_millis(1),
            cycle_index: None,
        })
    );
}

#[tokio::test]
async fn authority_measurement_pivot_sorts_samples_and_excludes_failures() {
    let run = run_open_loop(
        WallClock,
        3,
        OfferedRate::new(100, 1),
        3,
        Duration::from_secs(1),
        |index| async move {
            WallClock
                .wait_until(super::stopwatch() + Duration::from_millis((3 - index) as u64 * 20))
                .await;
            if index == 1 {
                Err(RequestFailure::Other("request failed"))
            } else {
                Ok(())
            }
        },
    )
    .await
    .unwrap();
    assert_eq!((run.durations.len(), run.failure_count), (2, 1));
    assert!(
        run.durations[0] > run.durations[1],
        "samples must retain scheduled-send order, not completion order: {run:?}"
    );
}
