// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Result records. "A result without its metadata does not exist" —
//! so the metadata is a completeness GATE, not a convention.
//! [`RunMetadata::new`] refuses a missing or empty field, and
//! [`write_record`] cannot be called without a
//! [`crate::control::ControlsPassed`] token.
//!
//! Neither gate can be satisfied by remembering to do the right thing.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

use crate::control::{ControlsPassed, SuiteKind, outcomes_json};
use crate::json::Json;
use crate::sweep::{ArmMetrics, CdcRelevant, ManifestStatus, MaxPolicy};

/// Every field a record must carry, in emitted order. Adding a field
/// here makes every future record carry it; removing one is a
/// deliberate act, visible in review.
pub const REQUIRED_METADATA: [&str; 16] = [
    "record_version",
    "kind",
    "date",
    "granary_git_sha",
    "machine",
    "os",
    "filesystem",
    "support_tier",
    "dataset",
    "version_older",
    "version_newer",
    "chunker_algorithm",
    "chunker_crate_version",
    "zstd_crate_version",
    "zstd_library_version",
    "zstd_level_and_api",
];

/// Field names the record itself owns. A caller-supplied body may not
/// contain them: `write_record` appends the body after the token-derived
/// fields, so a duplicate `controls` key would win in most JSON parsers and
/// the record would show controls that never gated it — with a genuine
/// token — the exact bypass the token binding exists to prevent.
pub const RESERVED_FIELDS: [&str; 2] = ["metadata", "controls"];

/// A validated metadata block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunMetadata {
    fields: Vec<(String, String)>,
}

/// Why a metadata block was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataError {
    /// A required field was absent.
    Missing(&'static str),
    /// A required field was present but empty.
    Empty(&'static str),
    /// A field not in [`REQUIRED_METADATA`] was supplied. Records are
    /// diffed across milestones; a stray key is a silent schema fork.
    Unknown(String),
}

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(k) => write!(f, "missing metadata field `{k}`"),
            Self::Empty(k) => write!(f, "empty metadata field `{k}`"),
            Self::Unknown(k) => write!(f, "unknown metadata field `{k}`"),
        }
    }
}

impl core::error::Error for MetadataError {}

impl RunMetadata {
    /// Validate a metadata block.
    ///
    /// # Errors
    /// [`MetadataError`] if any required field is missing or empty, or
    /// any unknown field is supplied.
    pub fn new(pairs: &[(String, String)]) -> Result<Self, MetadataError> {
        for (k, _) in pairs {
            if !REQUIRED_METADATA.contains(&k.as_str()) {
                return Err(MetadataError::Unknown(k.clone()));
            }
        }
        let mut fields = Vec::with_capacity(REQUIRED_METADATA.len());
        for key in REQUIRED_METADATA {
            let Some((_, v)) = pairs.iter().find(|(k, _)| k == key) else {
                return Err(MetadataError::Missing(key));
            };
            if v.trim().is_empty() {
                return Err(MetadataError::Empty(key));
            }
            fields.push((key.to_owned(), v.clone()));
        }
        Ok(Self { fields })
    }

    /// The record kind — always present ([`REQUIRED_METADATA`] makes it
    /// mandatory and non-empty).
    #[must_use]
    pub fn kind(&self) -> &str {
        self.fields
            .iter()
            .find(|(k, _)| k == "kind")
            .map_or("", |(_, v)| v.as_str())
    }

    /// Render as JSON, in [`REQUIRED_METADATA`] order.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::Obj(
            self.fields
                .iter()
                .map(|(k, v)| (k.clone(), Json::s(v.clone())))
                .collect(),
        )
    }
}

/// Write a result record.
///
/// The `controls` parameter is the point of this signature: a
/// [`ControlsPassed`] token exists only if the FULL production control
/// suite passed in this process, and the recorded `controls` section is
/// read OUT of that token — so the controls a record shows are provably
/// the controls that gated it, not a slice the caller chose.
///
/// The token is taken BY VALUE and consumed: one control run gates one
/// record. Otherwise a single pass could gate arbitrarily many records
/// in the same process, and the prose claim that controls gate each
/// headline run would be true only of the current CLI's shape.
///
/// The required suite is DERIVED FROM THE RECORD'S OWN `kind`, never
/// supplied by the caller: a token is only as meaningful as the suite
/// that minted it, and a caller-supplied requirement let a caller pair
/// factorial metadata with an average-sweep token by simply asking for
/// the weaker suite — the exact bypass the binding exists to prevent.
/// A kind this table does not know is refused outright: an ungated
/// protocol must not be writable.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] if the record kind is unknown, if
/// the token's suite is not the one the kind requires, if the body
/// supplies a reserved field, or if it repeats a key of its own;
/// otherwise propagates the write failure.
pub fn write_record(
    path: &Path,
    meta: &RunMetadata,
    body: Vec<(String, Json)>,
    controls: ControlsPassed,
) -> io::Result<()> {
    reserved_check(&body)?;
    let required_suite = match meta.kind() {
        "m3-grain-sweep" => SuiteKind::AverageSweep,
        "m4-floor-normalization-factorial" => SuiteKind::Factorial,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "record kind `{other}` has no registered control suite — \
                     refusing to write an ungated protocol's record"
                ),
            ));
        }
    };
    if controls.suite() != required_suite {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "the controls token was minted by the `{}` suite, but a \
                 `{}` record requires `{}` — a record must be gated by its \
                 own protocol's controls",
                controls.suite().label(),
                meta.kind(),
                required_suite.label()
            ),
        ));
    }
    let outcomes = controls.into_outcomes();
    let mut fields = vec![
        ("metadata".to_owned(), meta.to_json()),
        ("controls".to_owned(), outcomes_json(&outcomes)),
    ];
    fields.extend(body);
    fs::write(path, Json::Obj(fields).to_pretty())
}

/// Refuse a body that would collide with the record's own fields, or that
/// repeats a key of its own. Extracted so the negative tests exercise the
/// real predicate rather than a copy of it.
fn reserved_check(body: &[(String, Json)]) -> io::Result<()> {
    let mut seen: Vec<&str> = Vec::with_capacity(body.len());
    for (k, _) in body {
        if RESERVED_FIELDS.contains(&k.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("body may not supply the reserved field `{k}`"),
            ));
        }
        if seen.contains(&k.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("body repeats the field `{k}`"),
            ));
        }
        seen.push(k.as_str());
    }
    Ok(())
}

/// Render one arm's record object — THE one renderer: the CLI writes
/// records through it and the reproduction comparator (control 1)
/// renders fresh arms through it, so the two can never drift.
#[must_use]
pub fn arm_json(m: &ArmMetrics) -> Json {
    Json::Obj(vec![
        ("arm".to_owned(), Json::s(m.arm.clone())),
        ("kind".to_owned(), Json::s(m.kind)),
        ("configured_avg".to_owned(), Json::UInt(m.configured_avg)),
        // The swept cell, explicit in every record. `null` for the
        // arms that have no tuple, same rule as max_bytes.
        (
            "configured_min".to_owned(),
            m.configured_min.map_or(Json::Null, Json::UInt),
        ),
        (
            "configured_normalization".to_owned(),
            m.configured_normalization
                .map_or(Json::Null, |v| Json::UInt(u64::from(v))),
        ),
        ("max_clamped".to_owned(), Json::Bool(m.max_clamped())),
        // `max_clamped: false` alone is a trap: at a 1 MiB average
        // `max` is `min(8*avg, ceiling)` = EXACTLY the ceiling with no
        // reduction, so the flag reads false while the cap is binding.
        // These three say which of the two "false"s it is.
        // (At the shipped 256 KiB average, `max` = 2 MiB sits clear of the
        // 8 MiB ceiling, so the shipped tuple does not exhibit the trap —
        // the 1 MiB grid point does, and these fields earn their place.)
        ("max_bytes".to_owned(), max_num(m, |p| p.max)),
        (
            "max_unclamped_bytes".to_owned(),
            max_num(m, |p| p.unclamped),
        ),
        ("max_ceiling_bytes".to_owned(), max_num(m, |p| p.ceiling)),
        (
            "max_at_ceiling".to_owned(),
            m.max_policy
                .map_or(Json::Null, |p| Json::Bool(p.at_ceiling())),
        ),
        ("newer_bytes".to_owned(), Json::UInt(m.newer_bytes)),
        ("novel_raw_bytes".to_owned(), Json::UInt(m.novel_raw_bytes)),
        (
            "novel_stored_bytes".to_owned(),
            Json::UInt(m.novel_stored_bytes),
        ),
        (
            "novel_grain_count".to_owned(),
            Json::UInt(m.novel_grain_count),
        ),
        (
            "novel_manifest_bytes".to_owned(),
            manifest_num(m, m.novel_manifest_bytes),
        ),
        (
            "store_stored_bytes".to_owned(),
            Json::UInt(m.store_stored_bytes),
        ),
        (
            "store_grain_count".to_owned(),
            Json::UInt(m.store_grain_count),
        ),
        (
            "store_manifest_bytes".to_owned(),
            manifest_num(m, m.store_manifest_bytes),
        ),
        (
            "coalesced_ranges".to_owned(),
            Json::UInt(m.coalesced_ranges),
        ),
        (
            "realized_mean_grain".to_owned(),
            Json::Num(m.realized_mean_grain),
        ),
        // Raw-span counterpart of the line above. The external
        // cross-check's mean is over every chunk emitted, so a
        // record that carried only the unique-grain mean could not be
        // compared with it like for like.
        (
            "realized_mean_span".to_owned(),
            Json::Num(m.realized_mean_span),
        ),
        (
            "realized_median_grain".to_owned(),
            Json::UInt(m.realized_median_grain),
        ),
        (
            "novel_pct".to_owned(),
            Json::Num(share(m.novel_raw_bytes, m.newer_bytes) * 100.0),
        ),
        (
            "manifest_status".to_owned(),
            match &m.manifest_status {
                ManifestStatus::Exact => Json::s("exact"),
                ManifestStatus::Unrepresentable(why) => Json::s(format!("unrepresentable: {why}")),
                // NEW arm, not in the frozen text: a HARNESS bug (bad
                // corpus ordering, a size/grain-sum mismatch) must never
                // render as `unrepresentable` (a genuine format finding)
                // or `exact` (a false all-clear) — either would silently
                // narrow the grid or hide a bug in a committed record.
                // `sweep::ManifestStatus::HarnessError` exists precisely
                // so this case is distinguishable; give it its own status
                // string.
                ManifestStatus::HarnessError(why) => Json::s(format!("harness-error: {why}")),
            },
        ),
        (
            "novel_by_class".to_owned(),
            Json::Obj(
                m.novel_by_class
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), Json::UInt(*v)))
                    .collect(),
            ),
        ),
        // The granary side of the designated dedup-bench comparison.
        // Without it the designated comparison — over the files a
        // cutter can actually cut — is not computable from committed
        // artefacts at all.
        (
            "cdc_relevant".to_owned(),
            cdc_relevant_json(&m.cdc_relevant),
        ),
    ])
}

fn cdc_relevant_json(c: &CdcRelevant) -> Json {
    Json::Obj(vec![
        ("min_grain_bytes".to_owned(), Json::UInt(c.min_grain_bytes)),
        ("files".to_owned(), Json::UInt(c.files)),
        ("bytes".to_owned(), Json::UInt(c.bytes)),
        ("raw_chunks".to_owned(), Json::UInt(c.raw_chunks)),
        ("unique_chunks".to_owned(), Json::UInt(c.unique_chunks)),
        (
            "realized_mean_span".to_owned(),
            Json::Num(c.realized_mean_span),
        ),
        (
            "realized_mean_grain".to_owned(),
            Json::Num(c.realized_mean_grain),
        ),
    ])
}

/// `null` for the arms that have no tuple, on the same rule as
/// [`manifest_num`]: an arm with no max policy and an arm whose max
/// happens to be zero must not look alike.
fn max_num(m: &ArmMetrics, f: impl Fn(&MaxPolicy) -> usize) -> Json {
    m.max_policy
        .as_ref()
        .map_or(Json::Null, |p| Json::UInt(f(p) as u64))
}

/// `null`, never `0`, when the manifest could not be measured — a
/// measured zero and an unmeasurable arm must not look alike in a
/// committed record.
fn manifest_num(m: &ArmMetrics, v: u64) -> Json {
    if m.manifest_status == ManifestStatus::Exact {
        Json::UInt(v)
    } else {
        Json::Null
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "byte counts below 2^53; the result is a recorded ratio"
)]
fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    part as f64 / whole as f64
}

#[cfg(test)]
mod tests;
