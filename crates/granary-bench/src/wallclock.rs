// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `verify-wallclock` — a NON-MINTING verifier for the propagation run
//! artifact.
//!
//! It mints nothing, writes nothing and seals nothing: there is no
//! `ControlsPassed` constructor here and no path that writes a result file.
//! It validates a CLOSED schema, recomputes
//! everything the embedded bytes allow, reads back the handful of
//! harness observations it cannot derive, and emits a consistency
//! report on stdout.
//!
//! **What it can and cannot establish.** An artifact produced by a
//! harness cannot prove the harness performed the events it describes:
//! recomputation establishes internal CONSISTENCY, never OCCURRENCE or
//! PROVENANCE. So the checks split in two and the report says which is
//! which — the RECOMPUTED half is where a DEFECTIVE harness is caught,
//! and the operator-observed half is worth exactly what the harness is
//! worth.
//!
//! **A failing predicate is a RECORD, not a refusal.** Refusal is for
//! INPUTS that cannot be trusted; a pre-registered limit is a predicate and
//! a failed measurement is a measurement. A verb that refused a failing
//! P2 would be a filter on results.
//!
//! Every threshold comparison that decides a verdict is INTEGER
//! arithmetic over the embedded counts. The floating-point ratios exist
//! to be read, never to decide.

use core::fmt;
use std::collections::BTreeSet;

use crate::json::Json;

/// Keys the artifact may not carry, wherever they appear: each is a
/// conclusion the verb computes, so an artifact containing one is a
/// shell handing Rust an answer to seal.
pub const RESERVED_KEYS: [&str; 6] = [
    "p1_verdict",
    "p2_verdict",
    "digest",
    "run_artifact_digest",
    "metadata",
    "controls",
];

/// The eleven snapshot roles, in report order. Five measured, six
/// baseline; the baseline is evidence and gets the same identity
/// discipline as the measurement.
pub const ROLES: [&str; 11] = [
    "server",
    "publisher",
    "client-1",
    "client-2",
    "client-3",
    "warmup-1",
    "warmup-2",
    "warmup-3",
    "warmup-verify-1",
    "warmup-verify-2",
    "warmup-verify-3",
];

/// Harness observations the verb cannot derive and therefore requires
/// by NAME. The list is a MINIMUM: further observations are permitted,
/// and every one of them must carry the label, so a harness cannot
/// smuggle in an unlabelled claim by inventing a name.
pub const REQUIRED_OBSERVATIONS: [&str; 10] = [
    "no_publish",
    "stale_content",
    "wrong_server",
    "no_snapshot",
    "empty_run_id",
    "three_processes",
    "server_killed_before_snapshot",
    "expected_digests_computed_before_publish",
    "warmup_cache_dirs_were_empty",
    "no_cache_client_fails_p2",
];

/// P1, pre-registered: a cacheless `gran cat` reaching the new content.
pub const CLOCK_A_LIMIT_SECONDS: f64 = 30.0;
/// P1, pre-registered: a fresh `gran mount` reaching the new root.
pub const CLOCK_B_LIMIT_SECONDS: f64 = 60.0;
/// The floor below which `clock_a_seconds`/`clock_b_seconds` are
/// refused — see the clock-reading loop's own comments for why `<= 0.0`
/// was not enough. Tied to the report's own precision: `Findings::render` prints
/// both fields as `{:8.3}`, i.e. THREE digits after the point, so
/// `0.001` is one whole unit of the smallest change that render can even
/// show. A control protecting a report must be at least as fine as the
/// report — a floor coarser than the render leaves a gap the render
/// cannot see through, and this is the coarsest floor that has no such
/// gap. It cannot false-refuse a real run: clock A is a cacheless
/// multi-megabyte TLS read, measured at roughly 11 s on the committed
/// artifact.
pub const CLOCK_SECONDS_FLOOR: f64 = 0.001;
/// P2, pre-registered: the multiple of the novel-byte total that bounds
/// the publisher's upload and EACH client's download — never a sum
/// across clients.
pub const P2_MULTIPLE: u64 = 3;
/// A corpus below this cannot discriminate anything.
pub const MIN_CORPUS_BYTES: u64 = 8 * 1024 * 1024;
/// The delta band's lower end, as the rational `1/100`.
pub const DELTA_BAND_LOW: (u64, u64) = (1, 100);
/// The delta band's upper end, as the rational `3/10`.
pub const DELTA_BAND_HIGH: (u64, u64) = (3, 10);
/// The re-run rule's node-CPU mean, in percent.
pub const NODE_CPU_MEAN_LIMIT: f64 = 40.0;
/// The re-run rule's node-CPU maximum, in percent.
pub const NODE_CPU_MAX_LIMIT: f64 = 70.0;
/// No two consecutive node samples may be further apart than this
/// across the run window, or the middle of the run — where a competing
/// workload would show — is unsampled.
pub const SAMPLE_GAP_LIMIT_MS: i64 = 15_000;
/// The in-window count's DENSITY FLOOR, calibrated to a 12 s period.
///
/// It is NOT the sampler's own interval — the sampler's
/// "every 10 s" describes the
/// sampler's INTERVAL and is never a verifier bound: the measured run's
/// largest OBSERVED gap was 11.0 s (the largest one seen once, not an
/// established worst sustainable cadence), and a verifier enforcing
/// 10 s would have REFUSED that good run. A count floor of
/// `floor(D / 10 s)` re-imposed that same 10 s from the other side: the
/// committed run cleared it by exactly one sample (14 in-window against
/// 13 required), and a series at a uniform 11.0 s cadence over the same
/// window yields 12 in-window samples and would have been refused
/// despite passing [`SAMPLE_GAP_LIMIT_MS`].
///
/// It is also NOT a bound on average spacing — phase alignment means a
/// uniform series with a period somewhat above 12 s can still clear
/// `floor(D / 12 s)` at some window lengths, so "density floor" is the
/// honest name, not "average cadence bound".
///
/// 12 s sits strictly above the largest gap observed so far (11.0 s) and
/// strictly below the 15 s hole bound, and it is SCALE-FREE: an 11 s
/// series clears it at any window length, where `floor(D / 10 s) - 1`
/// would silently impose a 10 s interval as the window grows.
/// The floor is not vacuous — coverage plus the 15 s spacing bound alone
/// imply only about `floor(D / 15 s)` in-window samples, which would be
/// a pass about nothing. Spacing bounds the largest HOLE; this bounds
/// the sampling DENSITY.
pub const SAMPLE_DENSITY_PERIOD_SECONDS: i64 = 12;

/// The cold/warm inequality's multiple: a warm re-read must be at least
/// this much smaller than the cold read that filled the cache.
const COLD_WARM_MULTIPLE: u64 = 100;

const TOP_KEYS: [&str; 11] = [
    "artifact_version",
    "run_id",
    "harness",
    "venue",
    "node_cpu_samples",
    "corpus",
    "timeline",
    "clocks",
    "snapshots",
    "observations",
    "per_client",
];

const VENUE_KEYS: [&str; 7] = [
    "node",
    "guest",
    "arch",
    "kernel",
    "os",
    "transport",
    "support_tier",
];

const CORPUS_KEYS: [&str; 6] = [
    "apparent_bytes_v_n",
    "changed_subtree",
    "changed_subtree_bytes",
    "expected_v_n_tree_digest",
    "expected_v_n1_subtree_digest",
    "walker",
];

/// The timeline's stamps IN THE ORDER THE RUN PERFORMS THEM. The
/// ordering check is this array read left to right.
const TIMELINE_KEYS: [&str; 7] = [
    "warmups_ended",
    "delta_generated",
    "publish_started",
    "publish_ended",
    "workloads_started",
    "workloads_ended",
    "server_stopped",
];

const CLOCK_KEYS: [&str; 5] = [
    "client",
    "clock_a_seconds",
    "clock_a_polls",
    "clock_a_poll_bytes",
    "clock_b_seconds",
];

const PER_CLIENT_KEYS: [&str; 7] = [
    "client",
    "observed_subtree_digest",
    "warmup_observed_tree_digest",
    "warmup_verify_observed_tree_digest",
    "exit_codes",
    "endpoint_given",
    "seq_given",
];

/// Every measured exit code the artifact carries, per client.
const EXIT_CODE_KEYS: [&str; 5] = ["warmup", "warmup_verify", "workload", "clock_a", "clock_b"];

const SEQ_GIVEN_KEYS: [&str; 2] = ["warmup", "workload"];

const OBSERVATION_KEYS: [&str; 4] = ["kind", "name", "outcome", "detail"];

/// The publisher's `publish` summary, as the client writer emitted it.
/// Counters are unavailable on retained authority recovery. Parsing accepts
/// null; measurement verification still requires the costs it recomputes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishSummary {
    /// The sequence number this publish produced.
    pub seq: u64,
    /// Objects the remote binmap did not already know.
    pub novel_objects: Option<u64>,
    /// UNCOMPRESSED novel bytes; the wire carries zstd-compressed bins.
    pub novel_bytes: Option<u64>,
    /// Bins uploaded.
    pub bins_uploaded: Option<u64>,
    /// Compressed bin bytes actually uploaded.
    pub bin_bytes_uploaded: Option<u64>,
    /// The manifest root this publish produced.
    pub manifest_root: String,
}

/// One wire snapshot, as `granary-server` or `granary-client` wrote it.
/// Two writers, two shapes, one checker — `writer_kind` is what lets
/// the checker tell them apart.
///
/// Unknown keys are TOLERATED here and refused at the artifact's own
/// level: this object belongs to another crate's versioned format, and
/// a verifier that refused a field a writer added would fail closed on
/// its own dependency's upgrade. What it may never carry is a reserved
/// key or a negative number, and both are refused by the recursive scan
/// that runs before any of this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The snapshot format version.
    pub format_version: u64,
    /// `granary-server` or `granary-client`.
    pub writer_kind: String,
    /// The run this snapshot belongs to.
    pub run_id: String,
    /// The role, from the closed vocabulary.
    pub role: String,
    /// Whether a counter was lost; a poisoned snapshot is not evidence.
    pub poisoned: bool,
    /// Server: request-body bytes for the measured lifetime.
    pub request_bytes: Option<u64>,
    /// Server: requests carrying a body.
    pub requests_with_body: Option<u64>,
    /// Server: response bytes PRODUCED — not necessarily received.
    pub response_bytes_produced: Option<u64>,
    /// Server: how the shutdown ended.
    pub drain_outcome: Option<String>,
    /// Server: the address it bound.
    pub listen_addr: Option<String>,
    /// Client: response bytes counted in this process at the frame.
    pub response_bytes: Option<u64>,
    /// Client: the endpoint it was given; `None` means it bypassed the
    /// measured server entirely (`--direct-s3` stamps null).
    pub endpoint: Option<String>,
    /// Client: the sequence it was pinned to.
    pub pinned_seq: Option<u64>,
    /// Client: present only on a publisher.
    pub publish: Option<PublishSummary>,
}

/// Why an artifact was REFUSED. Every variant means the INPUT cannot be
/// trusted — none of them means "the measurement failed".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The bytes are not JSON this crate's parser accepts.
    Parse(String),
    /// A reserved key, wherever it appeared.
    ReservedKey(String),
    /// The closed schema: an unknown key, a missing key, a wrong type.
    Schema(String),
    /// A numeric field outside its permitted range.
    Range(String),
    /// A required harness observation is missing or unlabelled.
    Observation(String),
    /// The eleven-snapshot identity discipline.
    Identity(String),
    /// The route assertion.
    Route(String),
    /// A content-identity digest does not match the pinned expectation.
    ContentIdentity(String),
    /// A nonzero floor, the under-download floor, or the cold/warm
    /// inequality.
    Floor(String),
    /// The corpus floor or the delta band.
    Corpus(String),
    /// The cross-crate response-byte bound.
    CrossCheck(String),
    /// The timeline ordering.
    Timeline(String),
    /// The node-load samples: coverage, spacing, order or thresholds.
    NodeLoad(String),
    /// A control character in a string or a key. Every artifact string
    /// reaches the report a human reads and every refusal message, so
    /// one is a write primitive on the reader's terminal.
    ControlCharacter(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (tag, detail) = match self {
            Self::Parse(d) => ("parse", d),
            Self::ReservedKey(d) => ("reserved key", d),
            Self::Schema(d) => ("schema", d),
            Self::Range(d) => ("range", d),
            Self::Observation(d) => ("observation", d),
            Self::Identity(d) => ("identity", d),
            Self::Route(d) => ("route", d),
            Self::ContentIdentity(d) => ("content identity", d),
            Self::Floor(d) => ("floor", d),
            Self::Corpus(d) => ("corpus", d),
            Self::CrossCheck(d) => ("cross-check", d),
            Self::Timeline(d) => ("timeline", d),
            Self::NodeLoad(d) => ("node load", d),
            Self::ControlCharacter(d) => ("control character", d),
        };
        write!(f, "{tag}: {detail}")
    }
}

impl core::error::Error for VerifyError {}

/// A pre-registered predicate's answer. Both values are RECORDED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The predicate held.
    Pass,
    /// The predicate did not hold. This is a measurement, not a refusal.
    Fail,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        })
    }
}

/// One client's recomputed numbers.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientFindings {
    /// 1, 2 or 3.
    pub client: u64,
    /// `client-k.response_bytes`.
    pub download_bytes: u64,
    /// `download_bytes / novel_bytes`, for reading only — the verdict
    /// is decided in integer arithmetic.
    pub download_ratio: f64,
    /// Clock A, seconds.
    pub clock_a_seconds: f64,
    /// Clock A's polls. Floored above zero: clock A is cacheless, so a
    /// read that never asked has measured nothing.
    pub clock_a_polls: u64,
    /// Clock A's poll cost in bytes. Floored above zero for the same
    /// reason — a cacheless read cannot be free.
    pub clock_a_poll_bytes: u64,
    /// Clock B, seconds.
    pub clock_b_seconds: f64,
}

/// One harness observation, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedCheck {
    /// The observation's name.
    pub name: String,
    /// `pass` or `fail`, as the harness recorded it.
    pub outcome: String,
    /// The harness's own detail string.
    pub detail: String,
}

/// Everything the verb recomputed, plus what it read back.
#[derive(Debug, Clone, PartialEq)]
pub struct Findings {
    /// The artifact's run id.
    pub run_id: String,
    /// One line of venue, for the report header.
    pub venue: String,
    /// The harness script and its git sha.
    pub harness: String,
    /// `publisher.publish.novel_bytes`.
    pub novel_bytes: u64,
    /// `publisher.publish.bin_bytes_uploaded`.
    pub bin_bytes_uploaded: u64,
    /// `P2_MULTIPLE * novel_bytes`.
    pub p2_budget_bytes: u64,
    /// `server.request_bytes` — a phase total BOUNDING the publisher's
    /// upload, never "the publisher's bytes": there is no client
    /// authentication, so scheduling one publisher is not proof only it
    /// transmitted.
    pub upload_bytes: u64,
    /// `upload_bytes / novel_bytes`, for reading only.
    pub upload_ratio: f64,
    /// `server.requests_with_body`.
    pub requests_with_body: u64,
    /// The three clients.
    pub clients: Vec<ClientFindings>,
    /// Per client, `warmup-k.response_bytes`.
    pub warmup_bytes: Vec<u64>,
    /// Per client, `warmup-verify-k.response_bytes`.
    pub warmup_verify_bytes: Vec<u64>,
    /// `corpus.apparent_bytes_v_n`.
    pub corpus_apparent_bytes: u64,
    /// `corpus.changed_subtree_bytes`.
    pub changed_subtree_bytes: u64,
    /// `novel_bytes / changed_subtree_bytes`.
    pub delta_fraction: f64,
    /// The sum of every client-kind snapshot's `response_bytes`.
    pub client_kind_response_total: u64,
    /// `server.response_bytes_produced`.
    pub server_response_produced: u64,
    /// `https://` + the server's `listen_addr`.
    pub endpoint: String,
    /// `publisher.publish.seq`.
    pub publish_seq: u64,
    /// The run window's first stamp, verbatim.
    pub window_start: String,
    /// The run window's last stamp, verbatim.
    pub window_end: String,
    /// How many node samples the artifact carries.
    pub node_samples_total: usize,
    /// How many of them fall inside the run window.
    pub node_samples_in_window: usize,
    /// The run window's length, seconds.
    pub node_window_seconds: f64,
    /// `floor(window / 12 s)` — the density floor the window demands.
    pub node_samples_required: u64,
    /// The largest consecutive gap across the bracketed window, seconds.
    pub node_max_gap_seconds: f64,
    /// The mean of the samples INSIDE the window, percent.
    pub node_cpu_mean: f64,
    /// The maximum of the samples INSIDE the window, percent.
    pub node_cpu_max: f64,
    /// P1's answer.
    pub p1: Verdict,
    /// P2's answer.
    pub p2: Verdict,
    /// The harness observations, in artifact order.
    pub observed: Vec<ObservedCheck>,
}

// ===========================================================================
// Reading helpers. Every one of them names the SITE in its error, because
// a refusal a reader cannot locate is a refusal a reader will work around.
// ===========================================================================

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

fn fields<'a>(value: &'a Json, at: &str) -> Result<&'a [(String, Json)], VerifyError> {
    match value {
        Json::Obj(f) => Ok(f),
        _ => Err(VerifyError::Schema(format!("`{at}` is not an object"))),
    }
}

fn items<'a>(value: &'a Json, at: &str) -> Result<&'a [Json], VerifyError> {
    match value {
        Json::Arr(v) => Ok(v),
        _ => Err(VerifyError::Schema(format!("`{at}` is not an array"))),
    }
}

/// A CLOSED object: every listed key present, and no key that is not
/// listed. "Keys not listed are refused" is the artifact's contract.
fn closed(value: &Json, at: &str, allowed: &[&str]) -> Result<(), VerifyError> {
    let present = fields(value, at)?;
    for (key, _) in present {
        if !allowed.contains(&key.as_str()) {
            return Err(VerifyError::Schema(format!(
                "unknown key `{key}` in `{at}`"
            )));
        }
    }
    for want in allowed {
        if !present.iter().any(|(k, _)| k == want) {
            return Err(VerifyError::Schema(format!(
                "missing key `{want}` in `{at}`"
            )));
        }
    }
    if present.len() != allowed.len() {
        return Err(VerifyError::Schema(format!("duplicate key in `{at}`")));
    }
    Ok(())
}

fn get<'a>(value: &'a Json, at: &str, key: &str) -> Result<&'a Json, VerifyError> {
    value
        .get(key)
        .ok_or_else(|| VerifyError::Schema(format!("missing key `{key}` in `{at}`")))
}

fn text<'a>(value: &'a Json, at: &str, key: &str) -> Result<&'a str, VerifyError> {
    match get(value, at, key)? {
        Json::Str(s) => Ok(s),
        _ => Err(VerifyError::Schema(format!(
            "`{}` is not a string",
            join(at, key)
        ))),
    }
}

fn nonempty<'a>(value: &'a Json, at: &str, key: &str) -> Result<&'a str, VerifyError> {
    let s = text(value, at, key)?;
    if s.is_empty() {
        return Err(VerifyError::Schema(format!("`{}` is empty", join(at, key))));
    }
    Ok(s)
}

fn uint(value: &Json, at: &str, key: &str) -> Result<u64, VerifyError> {
    match get(value, at, key)? {
        Json::UInt(n) => Ok(*n),
        _ => Err(VerifyError::Schema(format!(
            "`{}` is not an unsigned integer",
            join(at, key)
        ))),
    }
}

fn boolean(value: &Json, at: &str, key: &str) -> Result<bool, VerifyError> {
    match get(value, at, key)? {
        Json::Bool(b) => Ok(*b),
        _ => Err(VerifyError::Schema(format!(
            "`{}` is not a boolean",
            join(at, key)
        ))),
    }
}

/// A count or a duration that reaches floating-point arithmetic. An
/// integer is accepted as itself: JSON writes `36` and `36.0` for the
/// same reading.
fn number(value: &Json, at: &str, key: &str) -> Result<f64, VerifyError> {
    match get(value, at, key)? {
        Json::Num(x) => Ok(*x),
        Json::UInt(n) => Ok(as_f64(*n)),
        _ => Err(VerifyError::Schema(format!(
            "`{}` is not a number",
            join(at, key)
        ))),
    }
}

/// The one lossy conversion in this module, and it is confined here.
/// Every count it sees is a byte total or a sample count from one run —
/// well under 2^53, where an `f64` is still exact. It feeds RATIOS and
/// MEANS that are printed; no verdict is decided from its output.
#[expect(
    clippy::cast_precision_loss,
    reason = "ratios and means are printed, never compared; verdicts use integer arithmetic"
)]
fn as_f64(v: u64) -> f64 {
    v as f64
}

fn hex64<'a>(value: &'a Json, at: &str, key: &str) -> Result<&'a str, VerifyError> {
    let s = text(value, at, key)?;
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(VerifyError::Schema(format!(
            "`{}` is not a 64-character hex digest",
            join(at, key)
        )));
    }
    Ok(s)
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` — MILLISECOND precision, refused
/// otherwise. A second-resolution stamp cannot order two events that
/// complete inside one second, and the ordering check would then pass
/// vacuously on equal values.
fn stamp_millis(s: &str) -> Option<i64> {
    let bytes = s.as_bytes();
    if bytes.len() != 24 {
        return None;
    }
    for (index, want) in [
        (4usize, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
        (23, b'Z'),
    ] {
        if bytes.get(index) != Some(&want) {
            return None;
        }
    }
    let part = |from: usize, to: usize| -> Option<i64> {
        let slice = s.get(from..to)?;
        if !slice.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        slice.parse::<i64>().ok()
    };
    let (year, month, day) = (part(0, 4)?, part(5, 7)?, part(8, 10)?);
    let hour = part(11, 13)?;
    let minute = part(14, 16)?;
    let second = part(17, 19)?;
    let milli = part(20, 23)?;
    if !(1..=12).contains(&month) {
        return None;
    }
    // The day against ITS OWN month, not against 31. `days_from_civil`
    // converts an impossible date happily and NOT monotonically:
    // `2026-02-31` lands on day 20515 while the real, LATER `2026-03-01`
    // lands on 20513. So an impossible stamp sorts AFTER a real one, and
    // the strict timeline ordering that millisecond precision was pinned
    // for is defeated by a date a calendar refuses.
    if !(1..=days_in_month(year, month)).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 || milli > 999 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + milli)
}

/// Days in a proleptic-Gregorian month, including the century rule that
/// makes 1900 a common year and 2000 a leap year. Total: the caller has
/// already bounded the month, and an out-of-range month answers 0, which
/// admits no day at all.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Hinnant's
/// `days_from_civil`). Pure integer arithmetic, no clock, no
/// dependency; the caller has already bounded every field.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn stamp<'a>(value: &'a Json, at: &str, key: &str) -> Result<(&'a str, i64), VerifyError> {
    let s = text(value, at, key)?;
    stamp_millis(s).map(|ms| (s, ms)).ok_or_else(|| {
        VerifyError::Schema(format!(
            "`{}` is not a `YYYY-MM-DDTHH:MM:SS.mmmZ` stamp: `{s}`",
            join(at, key)
        ))
    })
}

fn mul(a: u64, b: u64, what: &str) -> Result<u64, VerifyError> {
    a.checked_mul(b)
        .ok_or_else(|| VerifyError::Range(format!("{what}: {a} x {b} overflows a 64-bit count")))
}

// ===========================================================================
// The recursive scan. It runs FIRST, so a reserved key or an impossible
// number is refused before any check can be computed over it.
// ===========================================================================

fn scan(value: &Json, path: &str) -> Result<(), VerifyError> {
    match value {
        Json::Obj(f) => {
            // A DUPLICATE key is refused everywhere, not only in the
            // closed blocks: `Json::get` answers with the first and a
            // different reader may answer with the last, so one object
            // would carry two values for one field and every check
            // downstream would be reading a choice rather than a fact.
            //
            // The set is what makes that affordable. The `take(index)`
            // rescan it replaces is O(n^2) PER OBJECT over an
            // operator-supplied file: measured 0.60 s at 10k keys, 4.77 s
            // at 30k and 54.1 s at 100k (exponent 1.89 to 2.02), which
            // extrapolates to about 90 minutes at 1M — a HANG, on a verb
            // whose refusal then never arrives. Same rule, same first
            // duplicate, same message.
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            for (key, child) in f {
                // Naming the PARENT rather than the key is the part that
                // carries weight: a refusal that named `join(path, key)`
                // would re-embed the very payload it is refusing.
                // (Measured: the first draft did exactly that, and its
                // own refusal carried the escape sequence and the forged
                // line. A mutant restoring it is killed.)
                //
                // Running FIRST is defence in depth and NOT load-bearing
                // today — said plainly, because the ordering looks like a
                // guard and is not one. `printable` runs on every key, so
                // a key carrying a control character is refused at its
                // FIRST occurrence; the duplicate refusal below can only
                // fire on a SECOND occurrence, whose first must already
                // have passed this check, and no reserved key is
                // spellable with a control character. Moving this call
                // below both of them is an EQUIVALENT mutant and the
                // suite does not kill it. The order is kept so that a
                // refusal added ABOVE it later — which would print the
                // key before anything had vetted it — cannot leak.
                printable(key, owner(path), "key")?;
                if !seen.insert(key.as_str()) {
                    return Err(VerifyError::Schema(format!(
                        "duplicate key `{key}` in `{}`",
                        owner(path)
                    )));
                }
                if RESERVED_KEYS.contains(&key.as_str()) {
                    return Err(VerifyError::ReservedKey(format!(
                        "`{key}` at `{}` — the artifact carries no verdict, no ratio and no \
                         total the verb can compute",
                        join(path, key)
                    )));
                }
                scan(child, &join(path, key))?;
            }
        }
        Json::Arr(v) => {
            for (index, child) in v.iter().enumerate() {
                scan(child, &format!("{path}[{index}]"))?;
            }
        }
        Json::Int(n) => {
            return Err(VerifyError::Range(format!(
                "negative number {n} at `{path}` — every duration, byte count and \
                 percentage in this artifact is non-negative"
            )));
        }
        Json::Num(x) => {
            if !x.is_finite() {
                return Err(VerifyError::Range(format!("non-finite number at `{path}`")));
            }
            if *x < 0.0 {
                return Err(VerifyError::Range(format!(
                    "negative number {x} at `{path}`"
                )));
            }
        }
        Json::Str(s) => printable(s, owner(path), "string")?,
        Json::Null | Json::Bool(_) | Json::UInt(_) => {}
    }
    Ok(())
}

/// The parent this `path` names in a message, or `"the artifact"` at
/// the root — `path` is empty there, and a message built out of the raw
/// (empty) string reads as `` the string at ` ` `` and `` in `` `` ``,
/// which look BROKEN rather than "at the top level". The KEY branch
/// above and the STRING branch and duplicate-key message below all
/// route through this one function so the root-level wording cannot
/// drift between them again.
fn owner(path: &str) -> &str {
    if path.is_empty() {
        "the artifact"
    } else {
        path
    }
}

/// The characters that REORDER a report line rather than write to it:
/// the bidirectional marks, embeddings, overrides and isolates, and the
/// two Unicode line separators. They are Unicode `Cf`/`Zl`/`Zp` rather
/// than `Cc`, so `char::is_control` does not see them — and a
/// right-to-left override inside a venue string makes the rest of that
/// line render backwards, which is the Trojan-Source shape applied to a
/// report a human reads to learn a verdict. None of the artifact's
/// fields — hostnames, paths, shas, an ASCII detail line — has any use
/// for one.
///
/// **This is the COMPLETE Unicode bidirectional control set — verified
/// by enumeration, not by spot check — plus the two line separators:**
/// U+061C (ALM), U+200E/U+200F (LRM/RLM), U+202A–U+202E (LRE, RLE, PDF,
/// LRO, RLO), U+2066–U+2069 (LRI, RLI, FSI, PDI), and U+2028/U+2029 (LS,
/// PS). Fourteen entries, and nothing else is missing.
///
/// **What this table deliberately does NOT carry, said plainly.** The
/// non-reordering invisibles — ZWSP (U+200B), ZWNJ/ZWJ (U+200C/U+200D),
/// word joiner (U+2060), BOM/ZWNBSP (U+FEFF), soft hyphen (U+00AD), and
/// the U+E0000 tag block, which can spell out invisible ASCII — are a
/// different class: they HIDE text rather than reorder or forge a
/// report line, so a table built to close the Trojan-Source shape does
/// not reach them. Closing that class would need structure (the same
/// bound `printable`'s own doc names for misleading but printable
/// text), not a bigger character table.
pub const REORDERING: [char; 14] = [
    '\u{061c}', // ALM
    '\u{200e}', '\u{200f}', // LRM, RLM
    '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', // LRE, RLE, PDF, LRO, RLO
    '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', // LRI, RLI, FSI, PDI
    '\u{2028}', '\u{2029}', // LINE SEPARATOR, PARAGRAPH SEPARATOR
];

/// Refuse a control character in an artifact string or key.
///
/// **The verb's entire product is a report a human reads to learn the
/// verdict**, and every artifact string is interpolated into it — and
/// into every refusal message. A newline FORGES a line: a venue value of
/// `vesta\nP1 VERDICT: fail\nFORGED` puts those two lines on stdout
/// thirty-eight lines above the real `P1 VERDICT: pass`, with the verb
/// exiting 0. An ANSI escape does worse than add: `\x1b[2J\x1b[H`
/// clears the screen and reprints, so the real findings can be replaced
/// rather than merely preceded.
///
/// Refused rather than escaped, and at the DOOR rather than at each
/// print site. An escaping pass has to be complete to be worth anything,
/// and a `writeln!` added later would silently opt out of it; this runs
/// inside the recursive scan, before any check can be computed, so no
/// artifact string reaches any message. Nothing legitimate is lost — a
/// hostname, a role, a git sha, a path and a harness detail line are all
/// printable text, and the committed artifact carries no control
/// character anywhere.
///
/// The class is Unicode `Cc` — C0, DEL and C1, every control a terminal
/// acts on — plus [`REORDERING`], the characters that reorder a line
/// rather than write to it. The message names the SITE and the CODE
/// POINT and never echoes the string, because a refusal that printed the
/// payload would be the injection it exists to refuse.
///
/// **What this does NOT close, said plainly.** A payload of printable
/// characters can still put misleading TEXT on a report line — a venue
/// value of `vesta P1 VERDICT: fail` is accepted, and a row in the
/// suite pins that it is. What the refusal bounds is the artifact's
/// ability to forge a LINE, to drive the terminal, and to reverse one;
/// it cannot bound what a string SAYS. Homoglyphs are in the same
/// unclosed class. Closing that needs structure — machine-readable
/// output, or quoted fixed-width fields — not a bigger character table.
fn printable(s: &str, at: &str, what: &str) -> Result<(), VerifyError> {
    match first_forbidden(s) {
        None => Ok(()),
        Some((c, _)) => Err(VerifyError::ControlCharacter(format!(
            "the {what} at `{at}` carries U+{:04X} — an artifact string is interpolated \
             into the report a human reads and into every refusal, so a control character \
             in one can forge a verdict line or repaint the terminal",
            u32::from(c)
        ))),
    }
}

/// The ONE predicate behind this module's `printable` check, exposed so a caller that has
/// to vet a string BEFORE it ever reaches this module — the CLI's own
/// argv, which is interpolated into this verb's usage errors and into
/// the rendered report before the artifact is even opened — tests
/// against the exact same table rather than a second one that can drift
/// out of sync with it. Returns the first offending character and its
/// 0-based CHARACTER position in `s` (a position for a human to read,
/// not a byte offset into UTF-8).
#[must_use]
pub fn first_forbidden(s: &str) -> Option<(char, usize)> {
    s.chars()
        .enumerate()
        .find(|(_, c)| c.is_control() || REORDERING.contains(c))
        .map(|(index, c)| (c, index))
}

// ===========================================================================
// Snapshots
// ===========================================================================

impl Snapshot {
    /// Read one wire snapshot.
    ///
    /// # Errors
    /// [`VerifyError::Schema`] when a required field of the writer kind
    /// is missing or wrongly typed.
    pub fn from_json(value: &Json) -> Result<Self, VerifyError> {
        let at = "snapshot";
        let writer_kind = nonempty(value, at, "writer_kind")?.to_owned();
        let mut snap = Self {
            format_version: uint(value, at, "format_version")?,
            writer_kind,
            run_id: text(value, at, "run_id")?.to_owned(),
            role: text(value, at, "role")?.to_owned(),
            poisoned: boolean(value, at, "poisoned")?,
            request_bytes: None,
            requests_with_body: None,
            response_bytes_produced: None,
            drain_outcome: None,
            listen_addr: None,
            response_bytes: None,
            endpoint: None,
            pinned_seq: None,
            publish: None,
        };
        match snap.writer_kind.as_str() {
            "granary-server" => {
                snap.request_bytes = optional_uint(value, at, "request_bytes")?;
                snap.requests_with_body = Some(uint(value, at, "requests_with_body")?);
                snap.response_bytes_produced = Some(uint(value, at, "response_bytes_produced")?);
                snap.drain_outcome = Some(nonempty(value, at, "drain_outcome")?.to_owned());
                snap.listen_addr = Some(nonempty(value, at, "listen_addr")?.to_owned());
            }
            "granary-client" => {
                snap.response_bytes = optional_uint(value, at, "response_bytes")?;
                snap.endpoint = optional_text(value, at, "endpoint")?;
                snap.pinned_seq = optional_uint(value, at, "pinned_seq")?;
                snap.publish = match value.get("publish") {
                    Some(Json::Null) | None => None,
                    Some(p) => Some(publish_summary(p)?),
                };
            }
            other => {
                return Err(VerifyError::Schema(format!(
                    "unknown writer kind `{other}`"
                )));
            }
        }
        Ok(snap)
    }
}

fn optional_uint(value: &Json, at: &str, key: &str) -> Result<Option<u64>, VerifyError> {
    match get(value, at, key)? {
        Json::UInt(n) => Ok(Some(*n)),
        Json::Null => Ok(None),
        _ => Err(VerifyError::Schema(format!(
            "`{}` is neither an unsigned integer nor null",
            join(at, key)
        ))),
    }
}

fn optional_text(value: &Json, at: &str, key: &str) -> Result<Option<String>, VerifyError> {
    match get(value, at, key)? {
        Json::Str(s) => Ok(Some(s.clone())),
        Json::Null => Ok(None),
        _ => Err(VerifyError::Schema(format!(
            "`{}` is neither a string nor null",
            join(at, key)
        ))),
    }
}

fn publish_summary(value: &Json) -> Result<PublishSummary, VerifyError> {
    let at = "snapshot.publish";
    Ok(PublishSummary {
        seq: uint(value, at, "seq")?,
        novel_objects: optional_uint(value, at, "novel_objects")?,
        novel_bytes: optional_uint(value, at, "novel_bytes")?,
        bins_uploaded: optional_uint(value, at, "bins_uploaded")?,
        bin_bytes_uploaded: optional_uint(value, at, "bin_bytes_uploaded")?,
        manifest_root: nonempty(value, at, "manifest_root")?.to_owned(),
    })
}

// ===========================================================================
// The blocks
// ===========================================================================

struct Corpus {
    apparent_bytes_v_n: u64,
    changed_subtree_bytes: u64,
    expected_v_n_tree_digest: String,
    expected_v_n1_subtree_digest: String,
}

fn read_corpus(artifact: &Json) -> Result<Corpus, VerifyError> {
    let value = get(artifact, "", "corpus")?;
    closed(value, "corpus", &CORPUS_KEYS)?;
    nonempty(value, "corpus", "changed_subtree")?;
    nonempty(value, "corpus", "walker")?;
    Ok(Corpus {
        apparent_bytes_v_n: uint(value, "corpus", "apparent_bytes_v_n")?,
        changed_subtree_bytes: uint(value, "corpus", "changed_subtree_bytes")?,
        expected_v_n_tree_digest: hex64(value, "corpus", "expected_v_n_tree_digest")?.to_owned(),
        expected_v_n1_subtree_digest: hex64(value, "corpus", "expected_v_n1_subtree_digest")?
            .to_owned(),
    })
}

/// The seven stamps, in the order the run performs them, as
/// `(name, verbatim, millis)`.
fn read_timeline(artifact: &Json) -> Result<Vec<(&'static str, String, i64)>, VerifyError> {
    let value = get(artifact, "", "timeline")?;
    closed(value, "timeline", &TIMELINE_KEYS)?;
    let mut out = Vec::with_capacity(TIMELINE_KEYS.len());
    for key in TIMELINE_KEYS {
        let (verbatim, ms) = stamp(value, "timeline", key)?;
        out.push((key, verbatim.to_owned(), ms));
    }
    Ok(out)
}

#[expect(
    clippy::struct_field_names,
    reason = "the fields carry the artifact's own key names, so the grep from the schema \
              block to the reader that consumes them is one word"
)]
struct Clock {
    clock_a_seconds: f64,
    clock_a_polls: u64,
    clock_a_poll_bytes: u64,
    clock_b_seconds: f64,
}

#[expect(
    clippy::similar_names,
    reason = "`clock_a_seconds`/`clock_b_seconds` are the artifact's own field names \
              (the `Clock` struct's own doc gives the same reason for keeping them) — \
              renaming one to look less like the other would break the schema-to-reader grep"
)]
fn read_clocks(artifact: &Json) -> Result<Vec<Clock>, VerifyError> {
    let value = get(artifact, "", "clocks")?;
    let rows = items(value, "clocks")?;
    if rows.len() != 3 {
        return Err(VerifyError::Schema(format!(
            "`clocks` has {} entries, want 3 (N = 3 is pre-registered)",
            rows.len()
        )));
    }
    let mut out = Vec::with_capacity(3);
    for want in 1..=3u64 {
        let at = format!("clocks[client {want}]");
        let row = rows
            .iter()
            .find(|r| r.get("client") == Some(&Json::UInt(want)))
            .ok_or_else(|| VerifyError::Schema(format!("no `clocks` entry for client {want}")))?;
        closed(row, &at, &CLOCK_KEYS)?;
        // THE TWO CLOCK-A FLOORS. Both fields were read for their TYPE
        // and discarded, and an artifact carrying zeroes reported P1
        // PASSING while carrying the proof that clock A never made its
        // poll: the seconds field alone is satisfied by a loop that
        // measured nothing. Clock A is CACHELESS by construction — it has
        // no cache to be served from — so zero polls is a clock that
        // never asked and zero poll bytes is a counter that was never
        // accumulated, not a poll that was free.
        //
        // The harness floors the poll BYTES in its own K1 row
        // (`scripts/m10-propagate.sh`, "a cacheless gran cat cannot cost
        // zero"); the polls floor is this verb's. Neither is one of the
        // FIVE nonzero floors `check_floors` enumerates by name,
        // so both sit here, in the block that reads the fields, rather
        // than widening that list.
        let clock_a_polls = uint(row, &at, "clock_a_polls")?;
        let clock_a_poll_bytes = uint(row, &at, "clock_a_poll_bytes")?;
        for (field, value) in [
            ("clock_a_polls", clock_a_polls),
            ("clock_a_poll_bytes", clock_a_poll_bytes),
        ] {
            if value == 0 {
                return Err(VerifyError::Floor(format!(
                    "`clocks[client {want}].{field}` is zero; clock A is cacheless by \
                     construction and a read that never asked, or cost nothing, has not \
                     measured the propagation P1 records"
                )));
            }
        }
        // THE FIELDS THE COUNTERS DO NOT REACH. The floor above bounds
        // `clock_a_polls` and `clock_a_poll_bytes` — COUNTS, checked as
        // `u64` — and says nothing about `clock_a_seconds` or
        // `clock_b_seconds`, the DURATIONS, which are the ONLY inputs
        // the P1 verdict and the per-client render actually read. An
        // artifact with both seconds fields at `0.0` and the counters
        // untouched cleared the floor above, was ACCEPTED, and rendered
        // `client k   A    0.000 s   B    0.000 s` directly beneath the
        // line asserting the client "polled at least once and paid for
        // it": the floor checked only the counters, not the duration
        // fields that the verdict decides from. A
        // 0.000 s cacheless read is a measurement that did not happen,
        // counters or no counters, so both seconds fields are floored
        // here too — in their own loop, over `f64` rather than `u64`,
        // because they are read for a different TYPE, not a different
        // concern.
        //
        // `<= 0.0` CLOSED EXACTLY ZERO AND NOTHING ELSE. `clock_a_seconds:
        // 0.0004` cleared that bound, was ACCEPTED, and rendered
        // `A    0.000 s` under `{:8.3}` — verbatim the shape the floor
        // exists to refuse, one line above `P1 VERDICT: pass`. The bound
        // is [`CLOCK_SECONDS_FLOOR`] — one whole unit of the report's own
        // render precision, so nothing that can print as `0.000 s` can
        // clear it — and it is INCLUSIVE: a reading of exactly the floor
        // renders as `0.001 s`, visibly distinct from the refused shape.
        let clock_a_seconds = number(row, &at, "clock_a_seconds")?;
        let clock_b_seconds = number(row, &at, "clock_b_seconds")?;
        for (field, value) in [
            ("clock_a_seconds", clock_a_seconds),
            ("clock_b_seconds", clock_b_seconds),
        ] {
            if value < CLOCK_SECONDS_FLOOR {
                return Err(VerifyError::Floor(format!(
                    "`clocks[client {want}].{field}` is {value}, below the \
                     {CLOCK_SECONDS_FLOOR} s floor — the report renders this field at \
                     `{{:8.3}}` precision, so anything below one whole render unit prints \
                     as `0.000 s`, indistinguishable from a poll that never happened"
                )));
            }
        }
        out.push(Clock {
            clock_a_seconds,
            clock_a_polls,
            clock_a_poll_bytes,
            clock_b_seconds,
        });
    }
    Ok(out)
}

struct PerClient {
    observed_subtree: String,
    warmup_tree: String,
    warmup_verify_tree: String,
    endpoint_given: String,
    seq_given_workload: u64,
    seq_given_warmup: u64,
}

fn read_per_client(artifact: &Json) -> Result<Vec<PerClient>, VerifyError> {
    let value = get(artifact, "", "per_client")?;
    let rows = items(value, "per_client")?;
    if rows.len() != 3 {
        return Err(VerifyError::Schema(format!(
            "`per_client` has {} entries, want 3",
            rows.len()
        )));
    }
    let mut out = Vec::with_capacity(3);
    for want in 1..=3u64 {
        let at = format!("per_client[client {want}]");
        let row = rows
            .iter()
            .find(|r| r.get("client") == Some(&Json::UInt(want)))
            .ok_or_else(|| {
                VerifyError::Schema(format!("no `per_client` entry for client {want}"))
            })?;
        closed(row, &at, &PER_CLIENT_KEYS)?;
        let endpoint_given = nonempty(row, &at, "endpoint_given")?.to_owned();
        let seq_given = get(row, &at, "seq_given")?;
        closed(seq_given, &join(&at, "seq_given"), &SEQ_GIVEN_KEYS)?;
        for key in SEQ_GIVEN_KEYS {
            uint(seq_given, &join(&at, "seq_given"), key)?;
        }
        let seq_given_workload = uint(seq_given, &join(&at, "seq_given"), "workload")?;
        let seq_given_warmup = uint(seq_given, &join(&at, "seq_given"), "warmup")?;
        let exits = get(row, &at, "exit_codes")?;
        let exits_at = join(&at, "exit_codes");
        closed(exits, &exits_at, &EXIT_CODE_KEYS)?;
        for key in EXIT_CODE_KEYS {
            let code = uint(exits, &exits_at, key)?;
            if code != 0 {
                return Err(VerifyError::Identity(format!(
                    "`{}` is {code}; every measured process must have exited 0",
                    join(&exits_at, key)
                )));
            }
        }
        out.push(PerClient {
            observed_subtree: hex64(row, &at, "observed_subtree_digest")?.to_owned(),
            warmup_tree: hex64(row, &at, "warmup_observed_tree_digest")?.to_owned(),
            warmup_verify_tree: hex64(row, &at, "warmup_verify_observed_tree_digest")?.to_owned(),
            endpoint_given,
            seq_given_workload,
            seq_given_warmup,
        });
    }
    Ok(out)
}

fn read_observations(artifact: &Json) -> Result<Vec<ObservedCheck>, VerifyError> {
    let value = get(artifact, "", "observations")?;
    let rows = items(value, "observations")?;
    let mut out: Vec<ObservedCheck> = Vec::with_capacity(rows.len());
    let mut names: BTreeSet<String> = BTreeSet::new();
    for (index, row) in rows.iter().enumerate() {
        let at = format!("observations[{index}]");
        // NOT the generic closed-object check: a missing `kind` is an
        // UNLABELLED observation, which is this block's own refusal
        // rather than a schema nit.
        let present = fields(row, &at)?;
        for (key, _) in present {
            if !OBSERVATION_KEYS.contains(&key.as_str()) {
                return Err(VerifyError::Observation(format!(
                    "unknown key `{key}` in `{at}`"
                )));
            }
        }
        let kind = row.get("kind");
        if kind != Some(&Json::s("observation")) {
            return Err(VerifyError::Observation(format!(
                "`{at}` is not labelled `kind: observation` — every harness \
                 observation carries the label, so an unlabelled claim cannot be \
                 smuggled in beside a recomputed number"
            )));
        }
        let name =
            nonempty(row, &at, "name").map_err(|e| VerifyError::Observation(e.to_string()))?;
        let outcome =
            text(row, &at, "outcome").map_err(|e| VerifyError::Observation(e.to_string()))?;
        if outcome != "pass" && outcome != "fail" {
            return Err(VerifyError::Observation(format!(
                "`{at}` ({name}) has outcome `{outcome}`, want `pass` or `fail`"
            )));
        }
        let detail =
            text(row, &at, "detail").map_err(|e| VerifyError::Observation(e.to_string()))?;
        // A set, for the reason the key scan uses one: `observations` is an
        // unbounded operator-supplied array and a rescan per row is
        // quadratic in it. Same rule, same first duplicate, same message.
        if !names.insert(name.to_owned()) {
            return Err(VerifyError::Observation(format!(
                "observation `{name}` appears twice; two outcomes for one name is not a reading"
            )));
        }
        out.push(ObservedCheck {
            name: name.to_owned(),
            outcome: outcome.to_owned(),
            detail: detail.to_owned(),
        });
    }
    for want in REQUIRED_OBSERVATIONS {
        if !out.iter().any(|o| o.name == want) {
            return Err(VerifyError::Observation(format!(
                "required observation `{want}` is missing; the verb cannot derive it and \
                 will not proceed without it"
            )));
        }
    }
    Ok(out)
}

struct Sample {
    millis: i64,
    cpu: f64,
}

fn read_samples(artifact: &Json) -> Result<Vec<Sample>, VerifyError> {
    let value = get(artifact, "", "node_cpu_samples")?;
    let rows = items(value, "node_cpu_samples")?;
    if rows.is_empty() {
        return Err(VerifyError::NodeLoad(
            "`node_cpu_samples` is empty; a missing measurement of the measurement is not a pass"
                .to_owned(),
        ));
    }
    let mut out = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let at = format!("node_cpu_samples[{index}]");
        closed(row, &at, &["t", "cpu"])?;
        let (_, millis) = stamp(row, &at, "t")?;
        let cpu = number(row, &at, "cpu")?;
        if !(0.0..=100.0).contains(&cpu) {
            return Err(VerifyError::Range(format!(
                "`{}` is {cpu}, outside [0, 100]",
                join(&at, "cpu")
            )));
        }
        out.push(Sample { millis, cpu });
    }
    Ok(out)
}

// ===========================================================================
// Entry points
// ===========================================================================

/// Parse and verify one artifact.
///
/// # Errors
/// [`VerifyError`] naming the first refusal.
pub fn verify(text: &str) -> Result<Findings, VerifyError> {
    let value = Json::parse(text).map_err(|e| VerifyError::Parse(e.to_string()))?;
    verify_json(&value)
}

/// Verify an already-parsed artifact.
///
/// # Errors
/// [`VerifyError`] naming the first refusal.
pub fn verify_json(artifact: &Json) -> Result<Findings, VerifyError> {
    scan(artifact, "")?;
    closed(artifact, "the artifact", &TOP_KEYS)?;
    let version = uint(artifact, "the artifact", "artifact_version")?;
    if version != 1 {
        return Err(VerifyError::Schema(format!(
            "`artifact_version` is {version}, and this verb reads version 1"
        )));
    }
    let run_id = text(artifact, "the artifact", "run_id")?.to_owned();
    let harness = read_harness(artifact)?;
    let venue = read_venue(artifact)?;
    let corpus = read_corpus(artifact)?;
    let timeline = read_timeline(artifact)?;
    let clocks = read_clocks(artifact)?;
    let per_client = read_per_client(artifact)?;
    let samples = read_samples(artifact)?;
    let observed = read_observations(artifact)?;
    let snaps = read_snapshots(artifact, &run_id)?;
    let numbers = recompute(&snaps, &corpus, &per_client)?;
    check_timeline(&timeline)?;
    let load = check_node_load(&samples, &timeline)?;
    Ok(assemble(
        run_id, harness, venue, &corpus, &clocks, numbers, load, observed,
    ))
}

fn read_harness(artifact: &Json) -> Result<String, VerifyError> {
    let value = get(artifact, "", "harness")?;
    closed(value, "harness", &["script", "git_sha"])?;
    let script = nonempty(value, "harness", "script")?;
    let sha = text(value, "harness", "git_sha")?;
    if sha.len() != 40 || !sha.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(VerifyError::Schema(format!(
            "`harness.git_sha` is not a 40-character hex sha: `{sha}`"
        )));
    }
    Ok(format!("{script} @ {sha}"))
}

fn read_venue(artifact: &Json) -> Result<String, VerifyError> {
    let value = get(artifact, "", "venue")?;
    closed(value, "venue", &VENUE_KEYS)?;
    let mut parts = Vec::with_capacity(VENUE_KEYS.len());
    for key in VENUE_KEYS {
        parts.push(format!("{key}={}", nonempty(value, "venue", key)?));
    }
    Ok(parts.join(" "))
}

/// The eleven snapshots, in [`ROLES`] order, with the identity
/// discipline applied. The BASELINE is evidence and gets exactly the
/// same discipline as the measurement — warm-up snapshots from another
/// run, or carrying duplicate roles or the wrong writer kind, could
/// otherwise supply the baseline numbers while the five measured
/// snapshots passed every check.
fn read_snapshots(artifact: &Json, run_id: &str) -> Result<Vec<Snapshot>, VerifyError> {
    if run_id.is_empty() {
        return Err(VerifyError::Identity(
            "the run id is empty; equality among empties is not identity".to_owned(),
        ));
    }
    let value = get(artifact, "", "snapshots")?;
    closed(value, "snapshots", &ROLES)?;
    let mut out = Vec::with_capacity(ROLES.len());
    for role in ROLES {
        let at = join("snapshots", role);
        let raw = get(value, "snapshots", role)?;
        let want_kind = if role == "server" {
            "granary-server"
        } else {
            "granary-client"
        };
        // The writer kind is checked BEFORE the body is read: a
        // client-role file the server kind wrote is two writers and two
        // formats, and this field is what tells them apart.
        let got_kind = text(raw, &at, "writer_kind")?;
        if got_kind != want_kind {
            return Err(VerifyError::Identity(format!(
                "`{at}` was written by `{got_kind}`, want `{want_kind}`"
            )));
        }
        let snap =
            Snapshot::from_json(raw).map_err(|e| VerifyError::Schema(format!("`{at}`: {e}")))?;
        if snap.format_version != 1 {
            return Err(VerifyError::Schema(format!(
                "`{at}.format_version` is {}, and this verb reads version 1",
                snap.format_version
            )));
        }
        if snap.role != role {
            return Err(VerifyError::Identity(format!(
                "`{at}` carries role `{}`; eleven DISTINCT roles from the closed \
                 vocabulary is what makes the set a set",
                snap.role
            )));
        }
        if snap.run_id != run_id {
            return Err(VerifyError::Identity(format!(
                "`{at}` carries run id `{}`, and the artifact's is `{run_id}`",
                snap.run_id
            )));
        }
        if snap.poisoned {
            return Err(VerifyError::Identity(format!(
                "`{at}` is poisoned; a snapshot that lost a counter is not evidence"
            )));
        }
        out.push(snap);
    }
    Ok(out)
}

fn snapshot<'a>(snaps: &'a [Snapshot], role: &str) -> Result<&'a Snapshot, VerifyError> {
    snaps
        .iter()
        .find(|s| s.role == role)
        .ok_or_else(|| VerifyError::Schema(format!("no `{role}` snapshot")))
}

fn count(snap: &Snapshot, field: &str, value: Option<u64>) -> Result<u64, VerifyError> {
    value.ok_or_else(|| {
        VerifyError::Schema(format!(
            "`snapshots.{}.{field}` is null on a snapshot that is not poisoned",
            snap.role
        ))
    })
}

struct Numbers {
    novel_bytes: u64,
    bin_bytes_uploaded: u64,
    upload_bytes: u64,
    requests_with_body: u64,
    downloads: Vec<u64>,
    warmup_bytes: Vec<u64>,
    warmup_verify_bytes: Vec<u64>,
    client_kind_response_total: u64,
    server_response_produced: u64,
    endpoint: String,
    publish_seq: u64,
    delta_fraction: f64,
}

// The recomputation, in the order the partition states it. Each block
// is its own function so a reader can find the check by name.
fn recompute(
    snaps: &[Snapshot],
    corpus: &Corpus,
    per_client: &[PerClient],
) -> Result<Numbers, VerifyError> {
    let server = snapshot(snaps, "server")?;
    let publisher = snapshot(snaps, "publisher")?;
    if server.drain_outcome.as_deref() != Some("drained") {
        return Err(VerifyError::Identity(format!(
            "the server's drain outcome is `{}`, want `drained`; a resident connection \
             means a measured process did not exit",
            server.drain_outcome.as_deref().unwrap_or("(absent)")
        )));
    }
    let listen_addr = server.listen_addr.clone().ok_or_else(|| {
        VerifyError::Schema("the server snapshot has no `listen_addr`".to_owned())
    })?;
    let endpoint = format!("https://{listen_addr}");
    let publish = publisher.publish.as_ref().ok_or_else(|| {
        VerifyError::Schema("the publisher snapshot carries no `publish` summary".to_owned())
    })?;
    // Authority recovery has no historical cost counters. Its snapshot is
    // valid, but cannot substantiate a wallclock measurement of those costs.
    let novel_bytes = count(publisher, "publish.novel_bytes", publish.novel_bytes)?;
    let bin_bytes_uploaded = count(
        publisher,
        "publish.bin_bytes_uploaded",
        publish.bin_bytes_uploaded,
    )?;
    check_route(snaps, &endpoint)?;
    check_seq(snaps, publish.seq)?;
    check_given(snaps, per_client)?;
    check_content_identity(corpus, per_client)?;

    let upload_bytes = count(server, "request_bytes", server.request_bytes)?;
    let requests_with_body = count(server, "requests_with_body", server.requests_with_body)?;
    let server_response_produced = count(
        server,
        "response_bytes_produced",
        server.response_bytes_produced,
    )?;
    let downloads = role_counts(snaps, "client")?;
    let warmup_bytes = role_counts(snaps, "warmup")?;
    let warmup_verify_bytes = role_counts(snaps, "warmup-verify")?;

    check_floors(
        upload_bytes,
        requests_with_body,
        &downloads,
        novel_bytes,
        &warmup_bytes,
    )?;
    check_under_download(&downloads, bin_bytes_uploaded)?;
    check_cold_warm(&warmup_bytes, &warmup_verify_bytes)?;
    check_corpus(corpus, novel_bytes)?;
    let client_kind_response_total = check_cross_bound(snaps, server_response_produced)?;

    Ok(Numbers {
        novel_bytes,
        bin_bytes_uploaded,
        upload_bytes,
        requests_with_body,
        downloads,
        warmup_bytes,
        warmup_verify_bytes,
        client_kind_response_total,
        server_response_produced,
        endpoint,
        publish_seq: publish.seq,
        delta_fraction: as_f64(novel_bytes) / as_f64(corpus.changed_subtree_bytes),
    })
}

/// `client`, `warmup` or `warmup-verify`, in client order.
fn role_counts(snaps: &[Snapshot], prefix: &str) -> Result<Vec<u64>, VerifyError> {
    let mut out = Vec::with_capacity(3);
    for k in 1..=3 {
        let role = format!("{prefix}-{k}");
        let snap = snapshot(snaps, &role)?;
        out.push(count(snap, "response_bytes", snap.response_bytes)?);
    }
    Ok(out)
}

/// Every measured process's endpoint is the MEASURED server's bound
/// address. A publisher on the wrong server leaves the measured request
/// total at zero and would PASS; a `--direct-s3` publish stamps null.
fn check_route(snaps: &[Snapshot], endpoint: &str) -> Result<(), VerifyError> {
    for snap in snaps {
        if snap.writer_kind != "granary-client" {
            continue;
        }
        match snap.endpoint.as_deref() {
            Some(given) if given == endpoint => {}
            Some(given) => {
                return Err(VerifyError::Route(format!(
                    "`snapshots.{}` used endpoint `{given}`, and the measured server bound \
                     `{endpoint}`",
                    snap.role
                )));
            }
            None => {
                return Err(VerifyError::Route(format!(
                    "`snapshots.{}` has a null endpoint — it routed around the measured \
                     server entirely",
                    snap.role
                )));
            }
        }
    }
    Ok(())
}

fn check_seq(snaps: &[Snapshot], publish_seq: u64) -> Result<(), VerifyError> {
    for snap in snaps {
        let want = if snap.role.starts_with("client-") {
            publish_seq
        } else if snap.role.starts_with("warmup-") {
            publish_seq.checked_sub(1).ok_or_else(|| {
                VerifyError::Identity(format!(
                    "the publish seq is {publish_seq}, so no baseline can be pinned one below it"
                ))
            })?
        } else {
            continue;
        };
        if snap.pinned_seq != Some(want) {
            let got = snap
                .pinned_seq
                .map_or_else(|| "null".to_owned(), |n| n.to_string());
            return Err(VerifyError::Identity(format!(
                "`snapshots.{}` is pinned at {got}, want {want} (publish seq {publish_seq})",
                snap.role
            )));
        }
    }
    Ok(())
}

/// What the harness SAYS it gave client k, against what the client SAYS
/// it used. `per_client[k].endpoint_given`, `seq_given.workload` and
/// `seq_given.warmup` were parsed for their SHAPE and then DISCARDED, so
/// an artifact recording client 1 as pointed at an unrelated host, and
/// pinned at `u64::MAX`, passed route, seq, P1 and P2 and exited 0.
///
/// What it is worth, stated rather than implied: all three are written
/// by the same harness, so this catches a harness that RECORDED one
/// thing and DID another — never a consistent lie. That is also why the
/// fields are worth reading at all; before this they were inert.
///
/// `seq_given.warmup` is the SAME GAP one field over. The first
/// fix checked `endpoint_given` and `seq_given.workload` and left
/// this third field of the same block consumed by nothing — a fix that
/// landed on the SITES it was told about rather than the PATTERN they
/// share. Cross-checked here against that client's own
/// `snapshots.warmup-k.pinned_seq`, the same way `seq_given.workload` is
/// checked against `client-k.pinned_seq`.
fn check_given(snaps: &[Snapshot], per_client: &[PerClient]) -> Result<(), VerifyError> {
    for (index, row) in per_client.iter().enumerate() {
        let k = index + 1;
        let role = format!("client-{k}");
        let snap = snapshot(snaps, &role)?;
        match snap.endpoint.as_deref() {
            Some(used) if used == row.endpoint_given => {}
            used => {
                return Err(VerifyError::Route(format!(
                    "`per_client[{k}].endpoint_given` is `{}` and `snapshots.{role}.endpoint` \
                     is `{}`; the harness recorded one endpoint and the client used another",
                    row.endpoint_given,
                    used.unwrap_or("null")
                )));
            }
        }
        let pinned = snap.pinned_seq.ok_or_else(|| {
            VerifyError::Identity(format!("`snapshots.{role}.pinned_seq` is null"))
        })?;
        if row.seq_given_workload != pinned {
            return Err(VerifyError::Identity(format!(
                "`per_client[{k}].seq_given.workload` is {} and `snapshots.{role}.pinned_seq` \
                 is {pinned}; the harness recorded one sequence and the client used another",
                row.seq_given_workload
            )));
        }
        let warmup_role = format!("warmup-{k}");
        let warmup_snap = snapshot(snaps, &warmup_role)?;
        let warmup_pinned = warmup_snap.pinned_seq.ok_or_else(|| {
            VerifyError::Identity(format!("`snapshots.{warmup_role}.pinned_seq` is null"))
        })?;
        if row.seq_given_warmup != warmup_pinned {
            return Err(VerifyError::Identity(format!(
                "`per_client[{k}].seq_given.warmup` is {} and `snapshots.{warmup_role}.pinned_seq` \
                 is {warmup_pinned}; the harness recorded one sequence and the client used another",
                row.seq_given_warmup
            )));
        }
    }
    Ok(())
}

/// The content-identity predicate — the one control whose absence was
/// FAIL-OPEN. A warm client serving `v_n` from cache exits 0 with
/// non-zero bytes and the right run id, and passes every floor having
/// downloaded almost nothing.
fn check_content_identity(corpus: &Corpus, per_client: &[PerClient]) -> Result<(), VerifyError> {
    for (index, row) in per_client.iter().enumerate() {
        let k = index + 1;
        if row.observed_subtree != corpus.expected_v_n1_subtree_digest {
            return Err(VerifyError::ContentIdentity(format!(
                "client {k} read subtree digest {}, and the pinned v_(n+1) digest is {}",
                row.observed_subtree, corpus.expected_v_n1_subtree_digest
            )));
        }
        for (field, got) in [
            ("warmup_observed_tree_digest", &row.warmup_tree),
            (
                "warmup_verify_observed_tree_digest",
                &row.warmup_verify_tree,
            ),
        ] {
            if *got != corpus.expected_v_n_tree_digest {
                return Err(VerifyError::ContentIdentity(format!(
                    "client {k}'s `{field}` is {got}, and the pinned v_n tree digest is {}",
                    corpus.expected_v_n_tree_digest
                )));
            }
        }
    }
    Ok(())
}

/// The FIVE nonzero floors, ENUMERATED. Zero is a legal value in the
/// snapshot schema, so an artifact with positive novel bytes and zero
/// totals otherwise satisfies every upper bound and records P2 as
/// PASSING — every zero numerator sits inside a 3x bound.
fn check_floors(
    upload_bytes: u64,
    requests_with_body: u64,
    downloads: &[u64],
    novel_bytes: u64,
    warmup_bytes: &[u64],
) -> Result<(), VerifyError> {
    let zero = |what: &str| VerifyError::Floor(format!("`{what}` is zero"));
    if upload_bytes == 0 {
        return Err(zero("snapshots.server.request_bytes"));
    }
    if requests_with_body == 0 {
        return Err(zero("snapshots.server.requests_with_body"));
    }
    for (index, bytes) in downloads.iter().enumerate() {
        if *bytes == 0 {
            return Err(zero(&format!(
                "snapshots.client-{}.response_bytes",
                index + 1
            )));
        }
    }
    if novel_bytes == 0 {
        return Err(zero("snapshots.publisher.publish.novel_bytes"));
    }
    for (index, bytes) in warmup_bytes.iter().enumerate() {
        if *bytes == 0 {
            return Err(zero(&format!(
                "snapshots.warmup-{}.response_bytes",
                index + 1
            )));
        }
    }
    Ok(())
}

/// The UNDER-download floor: a client whose cache already holds
/// `v_(n+1)` passes every other check while transferring almost
/// nothing.
fn check_under_download(downloads: &[u64], bin_bytes_uploaded: u64) -> Result<(), VerifyError> {
    // THE FLOOR'S OWN DENOMINATOR — AND ONLY AT ZERO. `x >= 0` is
    // satisfied by every x, so a publisher snapshot carrying
    // `bin_bytes_uploaded: 0` degrades this floor to `client-k >= 0`,
    // which every artifact satisfies, and THAT is the vacuity this guard
    // closes: zero, and only zero.
    //
    // **What this does NOT close, said plainly: a PASS about a client
    // that received ONE byte.** At `bin_bytes_uploaded == 1` the floor
    // below degrades to `client-k >= 1`, which `check_floors`'s own
    // nonzero floor on `client-k.response_bytes` ALREADY guarantees, so
    // this guard adds nothing at 1 that was not already true. VERIFIED:
    // an artifact with `bin_bytes_uploaded = 1` and every
    // `client-k.response_bytes = 1` is ACCEPTED, the report prints
    // `(1, itself > 0)` and ratio `0.0000`, and P2 PASSES. A meaningful
    // lower bound above zero would have to tie `bin_bytes_uploaded` to
    // some OTHER pre-registered quantity; no such tie exists
    // today, and inventing a numeric floor here — a bound this guard
    // alone decided — would not be pre-registered. This guard therefore
    // closes only the zero-denominator case; it does not close the
    // one-byte case.
    //
    // ONE RULE, TWO IMPLEMENTATIONS. The harness applies the same
    // zero-only floor in its own E10 row — see `scripts/m10-propagate.sh`,
    // "THE FLOOR'S OWN DENOMINATOR IS FLOORED HERE" — and its comment
    // states the same one-byte limit. Whoever next touches either guard
    // should go and look at the other one.
    //
    // `bin_bytes_uploaded` is NOT one of the five nonzero floors
    // `check_floors` enumerates by name, so the guard sits inside the
    // check that depends on it rather than widening that list.
    // That is the harness's reasoning too, verbatim.
    if bin_bytes_uploaded == 0 {
        return Err(VerifyError::Floor(
            "`snapshots.publisher.publish.bin_bytes_uploaded` is zero; the under-download \
             floor would then read `client-k >= 0`, which every artifact satisfies"
                .to_owned(),
        ));
    }
    for (index, bytes) in downloads.iter().enumerate() {
        if *bytes < bin_bytes_uploaded {
            return Err(VerifyError::Floor(format!(
                "`snapshots.client-{}.response_bytes` is {bytes}, below \
                 `publisher.publish.bin_bytes_uploaded` {bin_bytes_uploaded}",
                index + 1
            )));
        }
    }
    Ok(())
}

fn check_cold_warm(warmup: &[u64], warmup_verify: &[u64]) -> Result<(), VerifyError> {
    for (index, (cold, warm)) in warmup.iter().zip(warmup_verify.iter()).enumerate() {
        let scaled = mul(COLD_WARM_MULTIPLE, *warm, "the cold/warm inequality")?;
        if scaled > *cold {
            return Err(VerifyError::Floor(format!(
                "`snapshots.warmup-verify-{}.response_bytes` is {warm}; \
                 {COLD_WARM_MULTIPLE} x {warm} = {scaled} exceeds the cold read {cold}, so the \
                 cache was never proven warm",
                index + 1
            )));
        }
    }
    Ok(())
}

fn check_corpus(corpus: &Corpus, novel_bytes: u64) -> Result<(), VerifyError> {
    if corpus.apparent_bytes_v_n < MIN_CORPUS_BYTES {
        return Err(VerifyError::Corpus(format!(
            "`corpus.apparent_bytes_v_n` is {}, below the {MIN_CORPUS_BYTES}-byte floor",
            corpus.apparent_bytes_v_n
        )));
    }
    if corpus.changed_subtree_bytes == 0 {
        return Err(VerifyError::Corpus(
            "`corpus.changed_subtree_bytes` is zero, so the delta fraction is undefined".to_owned(),
        ));
    }
    // The band in exact integer arithmetic: f >= 1/100 and f <= 3/10.
    let subtree = corpus.changed_subtree_bytes;
    let low_ok = mul(novel_bytes, DELTA_BAND_LOW.1, "the delta band")?
        >= mul(subtree, DELTA_BAND_LOW.0, "the delta band")?;
    let high_ok = mul(novel_bytes, DELTA_BAND_HIGH.1, "the delta band")?
        <= mul(subtree, DELTA_BAND_HIGH.0, "the delta band")?;
    if !low_ok || !high_ok {
        return Err(VerifyError::Corpus(format!(
            "the delta fraction {novel_bytes} / {subtree} = {:.6} is outside \
             [{:.2}, {:.2}]: below it the fixed structure cost eats P2's budget, and at or \
             above a third a client that reused NOTHING still passes P2",
            as_f64(novel_bytes) / as_f64(subtree),
            as_f64(DELTA_BAND_LOW.0) / as_f64(DELTA_BAND_LOW.1),
            as_f64(DELTA_BAND_HIGH.0) / as_f64(DELTA_BAND_HIGH.1),
        )));
    }
    Ok(())
}

/// Every client-kind process's counted download, against the server's
/// own produced total. Two crates, two counters, one relation.
fn check_cross_bound(snaps: &[Snapshot], produced: u64) -> Result<u64, VerifyError> {
    let mut total = 0u64;
    for snap in snaps {
        if snap.writer_kind != "granary-client" {
            continue;
        }
        let bytes = count(snap, "response_bytes", snap.response_bytes)?;
        total = total.checked_add(bytes).ok_or_else(|| {
            VerifyError::Range("the client-kind response total overflows a 64-bit count".to_owned())
        })?;
    }
    if total > produced {
        return Err(VerifyError::CrossCheck(format!(
            "the client-kind response total {total} exceeds the server's \
             `response_bytes_produced` {produced}"
        )));
    }
    Ok(total)
}

fn check_timeline(timeline: &[(&'static str, String, i64)]) -> Result<(), VerifyError> {
    for pair in timeline.windows(2) {
        let (Some(before), Some(after)) = (pair.first(), pair.get(1)) else {
            continue;
        };
        if before.2 >= after.2 {
            return Err(VerifyError::Timeline(format!(
                "`{}` ({}) is not strictly before `{}` ({})",
                before.0, before.1, after.0, after.1
            )));
        }
    }
    Ok(())
}

struct Load {
    window_start: String,
    window_end: String,
    window_ms: i64,
    total: usize,
    in_window: usize,
    required_in_window: i64,
    max_gap_ms: i64,
    mean: f64,
    max: f64,
}

/// The re-run rule, CLIPPED to the run window. An honest sampler left
/// running is enough to defeat the unclipped form: a series that
/// BRACKETS the run with idle samples satisfies ordering, spacing and
/// count while pulling the mean below the limit, so a run sustained
/// above it is admitted by the very gate written to reject it.
#[expect(
    clippy::too_many_lines,
    reason = "one gate over one sample series, checked in one fixed order: \
              order, coverage, spacing, count, then the two thresholds"
)]
fn check_node_load(
    samples: &[Sample],
    timeline: &[(&'static str, String, i64)],
) -> Result<Load, VerifyError> {
    let first = timeline
        .iter()
        .min_by_key(|row| row.2)
        .ok_or_else(|| VerifyError::Timeline("the timeline is empty".to_owned()))?;
    let last = timeline
        .iter()
        .max_by_key(|row| row.2)
        .ok_or_else(|| VerifyError::Timeline("the timeline is empty".to_owned()))?;
    for pair in samples.windows(2) {
        let (Some(before), Some(after)) = (pair.first(), pair.get(1)) else {
            continue;
        };
        if before.millis >= after.millis {
            return Err(VerifyError::NodeLoad(
                "the sample timestamps are not strictly increasing".to_owned(),
            ));
        }
    }
    let starts_before = samples.iter().any(|s| s.millis <= first.2);
    let ends_after = samples.iter().any(|s| s.millis >= last.2);
    if !starts_before || !ends_after {
        return Err(VerifyError::NodeLoad(format!(
            "the samples do not cover the run window [{}, {}]: a sample at or before the \
             first stamp and one at or after the last are both required",
            first.1, last.1
        )));
    }
    // The BRACKETED subsequence — every sample inside the window plus
    // the one immediately outside each end — is what the spacing bound
    // applies to, so a hole that straddles a window edge is still a
    // hole. Samples further out are permitted and enter no statistic.
    let lower = samples
        .iter()
        .filter(|s| s.millis <= first.2)
        .map(|s| s.millis)
        .max()
        .unwrap_or(first.2);
    let upper = samples
        .iter()
        .filter(|s| s.millis >= last.2)
        .map(|s| s.millis)
        .min()
        .unwrap_or(last.2);
    let mut max_gap_ms = 0i64;
    let bracketed: Vec<&Sample> = samples
        .iter()
        .filter(|s| s.millis >= lower && s.millis <= upper)
        .collect();
    for pair in bracketed.windows(2) {
        let (Some(before), Some(after)) = (pair.first(), pair.get(1)) else {
            continue;
        };
        let gap = after.millis - before.millis;
        if gap > max_gap_ms {
            max_gap_ms = gap;
        }
    }
    if max_gap_ms > SAMPLE_GAP_LIMIT_MS {
        return Err(VerifyError::NodeLoad(format!(
            "two consecutive samples are {max_gap_ms} ms apart across the run window, and \
             the bound is {SAMPLE_GAP_LIMIT_MS} ms — the middle of a run, where a competing \
             workload would show, must be sampled"
        )));
    }
    let inside: Vec<f64> = samples
        .iter()
        .filter(|s| s.millis >= first.2 && s.millis <= last.2)
        .map(|s| s.cpu)
        .collect();
    let in_window = u32::try_from(inside.len()).map_err(|_| {
        VerifyError::NodeLoad("implausibly many samples inside the run window".to_owned())
    })?;
    if in_window == 0 {
        return Err(VerifyError::NodeLoad(
            "no sample falls inside the run window; the statistic would be computed over \
             nothing"
                .to_owned(),
        ));
    }
    // THE COUNT, which the spacing bound does not imply. Spacing bounds
    // the largest HOLE; it says nothing about how many readings the run
    // was summarised from, and ONE in-window sample satisfied every other
    // check here. `floor(D / SAMPLE_DENSITY_PERIOD_SECONDS)` is a density
    // floor, not a rederivation of the sampler's own interval — see that
    // constant's doc for why 12 s and not the sampler's 10 s. The harness
    // refuses to assemble below the same floor and the verb, which is the
    // half that reads an artifact it did not produce, refuses to report
    // above it.
    let window_ms = last.2.saturating_sub(first.2);
    let required = window_ms / (SAMPLE_DENSITY_PERIOD_SECONDS * 1000);
    if i64::from(in_window) < required {
        return Err(VerifyError::NodeLoad(format!(
            "{in_window} samples fall inside the run window and a {:.3} s window holds \
             {required} at the {SAMPLE_DENSITY_PERIOD_SECONDS} s density floor; the spacing \
             bound bounds the largest HOLE and says nothing about how many readings the mean \
             was computed from",
            as_f64(u64::try_from(window_ms).unwrap_or(0)) / 1000.0
        )));
    }
    let mean = inside.iter().sum::<f64>() / f64::from(in_window);
    let max = inside.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if mean > NODE_CPU_MEAN_LIMIT || max > NODE_CPU_MAX_LIMIT {
        return Err(VerifyError::NodeLoad(format!(
            "the node was at mean {mean:.2} % / max {max:.2} % across the run window, and \
             the re-run rule is mean <= {NODE_CPU_MEAN_LIMIT} % and max <= \
             {NODE_CPU_MAX_LIMIT} %; a rejected run is re-run, not reported"
        )));
    }
    Ok(Load {
        window_start: first.1.clone(),
        window_end: last.1.clone(),
        window_ms,
        total: samples.len(),
        in_window: inside.len(),
        required_in_window: required,
        max_gap_ms,
        mean,
        max,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "the assembly of one report from the blocks that were checked separately; \
              collapsing them into a struct would only rename the same list"
)]
fn assemble(
    run_id: String,
    harness: String,
    venue: String,
    corpus: &Corpus,
    clocks: &[Clock],
    numbers: Numbers,
    load: Load,
    observed: Vec<ObservedCheck>,
) -> Findings {
    let novel = numbers.novel_bytes;
    // Saturating, and it cannot bite: `novel` is bounded by the corpus
    // and the floors have already refused zero. A saturated budget
    // would only make P2 easier, so it is stated rather than left to a
    // reader to wonder about.
    let budget = novel.saturating_mul(P2_MULTIPLE);
    let mut p1 = Verdict::Pass;
    let mut clients = Vec::with_capacity(3);
    for (index, clock) in clocks.iter().enumerate() {
        if clock.clock_a_seconds > CLOCK_A_LIMIT_SECONDS
            || clock.clock_b_seconds > CLOCK_B_LIMIT_SECONDS
        {
            p1 = Verdict::Fail;
        }
        let download = numbers.downloads.get(index).copied().unwrap_or(0);
        clients.push(ClientFindings {
            client: u64::try_from(index + 1).unwrap_or(0),
            download_bytes: download,
            download_ratio: as_f64(download) / as_f64(novel),
            clock_a_seconds: clock.clock_a_seconds,
            clock_a_polls: clock.clock_a_polls,
            clock_a_poll_bytes: clock.clock_a_poll_bytes,
            clock_b_seconds: clock.clock_b_seconds,
        });
    }
    let mut p2 = if numbers.upload_bytes > budget {
        Verdict::Fail
    } else {
        Verdict::Pass
    };
    if numbers.downloads.iter().any(|d| *d > budget) {
        p2 = Verdict::Fail;
    }
    Findings {
        run_id,
        venue,
        harness,
        novel_bytes: novel,
        bin_bytes_uploaded: numbers.bin_bytes_uploaded,
        p2_budget_bytes: budget,
        upload_bytes: numbers.upload_bytes,
        upload_ratio: as_f64(numbers.upload_bytes) / as_f64(novel),
        requests_with_body: numbers.requests_with_body,
        clients,
        warmup_bytes: numbers.warmup_bytes,
        warmup_verify_bytes: numbers.warmup_verify_bytes,
        corpus_apparent_bytes: corpus.apparent_bytes_v_n,
        changed_subtree_bytes: corpus.changed_subtree_bytes,
        delta_fraction: numbers.delta_fraction,
        client_kind_response_total: numbers.client_kind_response_total,
        server_response_produced: numbers.server_response_produced,
        endpoint: numbers.endpoint,
        publish_seq: numbers.publish_seq,
        window_start: load.window_start,
        window_end: load.window_end,
        node_samples_total: load.total,
        node_samples_in_window: load.in_window,
        node_window_seconds: as_f64(u64::try_from(load.window_ms).unwrap_or(0)) / 1000.0,
        node_samples_required: u64::try_from(load.required_in_window).unwrap_or(0),
        node_max_gap_seconds: as_f64(u64::try_from(load.max_gap_ms).unwrap_or(0)) / 1000.0,
        node_cpu_mean: load.mean,
        node_cpu_max: load.max,
        p1,
        p2,
        observed,
    }
}

// ===========================================================================
// The report
// ===========================================================================

impl Findings {
    /// Render the artifact-consistency report.
    ///
    /// The two halves are separated and LABELLED. A check the verb
    /// merely re-reads is worth exactly what the harness is worth, and
    /// saying so is what keeps the record honest.
    #[must_use]
    #[expect(
        clippy::too_many_lines,
        reason = "one report, written in the order it is read; splitting it would hide \
                  the layout in three functions"
    )]
    pub fn render(&self, artifact_path: &str) -> String {
        use fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "granary-bench verify-wallclock — artifact consistency");
        let _ = writeln!(
            out,
            "  NON-MINTING. This verb writes no record, mints no token and creates no\n  \
             file. An artifact cannot prove the harness performed the events it\n  \
             describes, so what follows is CONSISTENCY, never occurrence or provenance."
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "artifact   {artifact_path}");
        let _ = writeln!(out, "run id     {}", self.run_id);
        let _ = writeln!(out, "venue      {}", self.venue);
        let _ = writeln!(out, "harness    {}", self.harness);
        let _ = writeln!(out);

        let _ = writeln!(out, "RECOMPUTED — derived from the embedded bytes");
        let _ = writeln!(
            out,
            "  schema           closed; {} top-level keys, {} reserved keys absent, no \
             negative or non-finite number anywhere",
            TOP_KEYS.len(),
            RESERVED_KEYS.len()
        );
        let _ = writeln!(
            out,
            "  snapshots        {}/{} present, {} distinct roles, one non-empty run id, \
             writer kinds match their roles, none poisoned, server drained",
            ROLES.len(),
            ROLES.len(),
            ROLES.len()
        );
        let _ = writeln!(
            out,
            "  exit codes       15 measured exit codes (5 per client), all 0"
        );
        let _ = writeln!(
            out,
            "  route            every client-kind endpoint == {}, and each \
             `per_client[k].endpoint_given` agrees with it",
            self.endpoint
        );
        let _ = writeln!(
            out,
            "  seq              clients pinned at {} == publish.seq; six baselines pinned \
             one below;\n                   each `per_client[k].seq_given.workload` agrees \
             with its client's pinned seq, and `seq_given.warmup` with its warmup's",
            self.publish_seq
        );
        let _ = writeln!(
            out,
            "  content identity 3 workload subtree digests == corpus.expected_v_n1_subtree_digest"
        );
        let _ = writeln!(
            out,
            "                   6 baseline tree digests == corpus.expected_v_n_tree_digest"
        );
        let _ = writeln!(out, "  nonzero floors   all five, by name:");
        let _ = writeln!(
            out,
            "                     {:<34}{}",
            "server.request_bytes", self.upload_bytes
        );
        let _ = writeln!(
            out,
            "                     {:<34}{}",
            "server.requests_with_body", self.requests_with_body
        );
        for client in &self.clients {
            let _ = writeln!(
                out,
                "                     {:<34}{}",
                format!("client-{}.response_bytes", client.client),
                client.download_bytes
            );
        }
        let _ = writeln!(
            out,
            "                     {:<34}{}",
            "publisher.publish.novel_bytes", self.novel_bytes
        );
        for (index, bytes) in self.warmup_bytes.iter().enumerate() {
            let _ = writeln!(
                out,
                "                     {:<34}{bytes}",
                format!("warmup-{}.response_bytes", index + 1)
            );
        }
        let _ = writeln!(
            out,
            "  clock A polls    every client polled at least once and paid for it (a cacheless \
             read cannot cost nothing):"
        );
        for client in &self.clients {
            let _ = writeln!(
                out,
                "                     {:<34}polls {}, poll bytes {}",
                format!("clocks[client {}]", client.client),
                client.clock_a_polls,
                client.clock_a_poll_bytes
            );
        }
        let _ = writeln!(
            out,
            "  under-download   client-k.response_bytes >= publisher.publish.bin_bytes_uploaded \
             ({}, itself > 0)",
            self.bin_bytes_uploaded
        );
        for (index, (cold, warm)) in self
            .warmup_bytes
            .iter()
            .zip(self.warmup_verify_bytes.iter())
            .enumerate()
        {
            let _ = writeln!(
                out,
                "  cold/warm {}      {COLD_WARM_MULTIPLE} x {warm} <= {cold}",
                index + 1
            );
        }
        let _ = writeln!(
            out,
            "  corpus floor     apparent_bytes_v_n {} >= {MIN_CORPUS_BYTES}",
            self.corpus_apparent_bytes
        );
        let _ = writeln!(
            out,
            "  delta band       f = {} / {} = {:.6}, inside [{:.2}, {:.2}]",
            self.novel_bytes,
            self.changed_subtree_bytes,
            self.delta_fraction,
            as_f64(DELTA_BAND_LOW.0) / as_f64(DELTA_BAND_LOW.1),
            as_f64(DELTA_BAND_HIGH.0) / as_f64(DELTA_BAND_HIGH.1),
        );
        let _ = writeln!(
            out,
            "  cross-crate      sum(client-kind response_bytes) {} <= \
             server.response_bytes_produced {}",
            self.client_kind_response_total, self.server_response_produced
        );
        let _ = writeln!(
            out,
            "  timeline         {} stamps strictly increasing; both warm-ups ended before \
             the publish started",
            TIMELINE_KEYS.len()
        );
        let _ = writeln!(
            out,
            "  node load        window [{}, {}]",
            self.window_start, self.window_end
        );
        let _ = writeln!(
            out,
            "                   {} samples, {} inside the window (the statistic is CLIPPED \
             to it)\n                   >= floor({:.3} s / {SAMPLE_DENSITY_PERIOD_SECONDS} s) \
             = {} required, largest gap {:.1} s <= {} s",
            self.node_samples_total,
            self.node_samples_in_window,
            self.node_window_seconds,
            self.node_samples_required,
            self.node_max_gap_seconds,
            SAMPLE_GAP_LIMIT_MS / 1000
        );
        let _ = writeln!(
            out,
            "                   mean {:.2} % <= {NODE_CPU_MEAN_LIMIT} %, max {:.2} % <= \
             {NODE_CPU_MAX_LIMIT} %",
            self.node_cpu_mean, self.node_cpu_max
        );
        let _ = writeln!(out);

        let _ = writeln!(
            out,
            "P1 — pre-registered: clock A <= {CLOCK_A_LIMIT_SECONDS} s, clock B <= \
             {CLOCK_B_LIMIT_SECONDS} s, N = 3"
        );
        for client in &self.clients {
            let _ = writeln!(
                out,
                "  client {}   A {:8.3} s   B {:8.3} s",
                client.client, client.clock_a_seconds, client.clock_b_seconds
            );
        }
        let _ = writeln!(out, "  P1 VERDICT: {}", self.p1);
        let _ = writeln!(out);

        let _ = writeln!(
            out,
            "P2 — pre-registered: the publisher's upload <= {P2_MULTIPLE}x novel, and EACH \
             client's download <= {P2_MULTIPLE}x novel"
        );
        let _ = writeln!(
            out,
            "  {:<58}{:>12}",
            "novel bytes (publisher.publish.novel_bytes, UNCOMPRESSED)", self.novel_bytes
        );
        let _ = writeln!(
            out,
            "  {:<58}{:>12}",
            format!("budget ({P2_MULTIPLE}x novel)"),
            self.p2_budget_bytes
        );
        let _ = writeln!(
            out,
            "  {:<58}{:>12}   ratio {:.4}",
            "publisher upload, bounded by server.request_bytes",
            self.upload_bytes,
            self.upload_ratio
        );
        for client in &self.clients {
            let _ = writeln!(
                out,
                "  {:<58}{:>12}   ratio {:.4}",
                format!(
                    "client {} download, counted in its own process",
                    client.client
                ),
                client.download_bytes,
                client.download_ratio
            );
        }
        let _ = writeln!(out, "  P2 VERDICT: {}", self.p2);
        let _ = writeln!(out);

        let failing = self.observed.iter().filter(|o| o.outcome != "pass").count();
        let _ = writeln!(out, "operator-observed checks — READ BACK, NOT RECOMPUTED");
        let _ = writeln!(
            out,
            "  These are the harness's own observations. The verb checks that each is\n  \
             present and labelled `kind: observation` and reports its outcome; it cannot\n  \
             derive any of them. The node-CPU samples above are an operator observation\n  \
             too — the verb checks their coverage, spacing and thresholds and cannot\n  \
             verify which machine produced them."
        );
        for check in &self.observed {
            let _ = writeln!(out, "  {:<5} {}", check.outcome, check.name);
            let _ = writeln!(out, "          {}", check.detail);
        }
        let _ = writeln!(
            out,
            "  {} required names present, {} observations total, {failing} failing",
            REQUIRED_OBSERVATIONS.len(),
            self.observed.len()
        );
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "VERDICTS ARE RECORDS, NOT GATES. A failing P1 or P2 is a measurement; this\n\
             verb refuses only inputs it cannot trust, and its exit status reflects the\n\
             artifact's validity rather than the verdicts above."
        );
        out
    }
}
