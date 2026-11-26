// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The seven support-bundle members. Each is a fixed handwritten field walk
//! with no envelope of its own; counts and lengths are bounded before any
//! allocation, and decode requires the exact length.
use super::records;
use crate::support::{Result, SupportError, Tape, require};
use std::ops::RangeInclusive;

/// Version and build identity member cap.
pub const BUNDLE_VERSION_MAX: usize = 64;
/// Redacted configuration member cap.
pub const BUNDLE_CONFIGURATION_MAX: usize = 256;
/// Recent structured logs member cap: 1 MiB of records and 64 KiB of framing.
pub const BUNDLE_LOGS_MAX: usize = 1_114_112;
/// Overlay and journal summary member cap.
pub const BUNDLE_OVERLAY_MAX: usize = 256;
/// Cache summary member cap.
pub const BUNDLE_CACHE_MAX: usize = 64;
/// Last failures member cap.
pub const BUNDLE_FAILURES_MAX: usize = 2048;
/// Metrics snapshot member cap.
pub const BUNDLE_METRICS_MAX: usize = 4096;
/// Most log records one member carries.
pub const BUNDLE_LOG_RECORDS_MAX: usize = 1024;
/// Most bytes one log record may span, newline included.
pub const BUNDLE_LOG_RECORD_MAX: usize = 32_768;
/// Most record bytes one logs member carries in total.
pub const BUNDLE_LOG_BYTES_MAX: usize = 1_048_576;
/// Most failures one failures member carries.
pub const BUNDLE_FAILURES_ENTRIES_MAX: usize = 64;
/// How many operation kinds an `op.failed` failure may name, 1-based: the
/// client's operation kinds, in their declared order.
pub const BUNDLE_OPERATION_KINDS: u8 = 10;
/// Metrics schema version shared by the version and metrics members.
pub const BUNDLE_METRICS_SCHEMA: u16 = 2;
pub(super) const VERSION_LEN: usize = 27;
pub(super) const CONFIGURATION_LEN: usize = 34;
pub(super) const OVERLAY_LEN: usize = 99;
pub(super) const CACHE_WRITER_LEN: usize = 33;
const FAILURE_LEN: usize = 8 + 1 + 1 + 1 + 1 + 8;
const FAILURES_DERIVED_MAX: usize = 2 + BUNDLE_FAILURES_ENTRIES_MAX * FAILURE_LEN;
const LOGS_DERIVED_MAX: usize = 8 + 2 + BUNDLE_LOG_RECORDS_MAX * 2 + BUNDLE_LOG_BYTES_MAX;
pub(super) const METRICS_LEN: usize =
    2 + 16 + 8 + 6 + (6 + 3 + 1 + 4 + 40 * 4 + 4 + 1 + 2 + 1 + 4 + 2) * 8 + 1 + (6 + 4) * 13 * 8;
const _: () = assert!(VERSION_LEN == 27 && VERSION_LEN < BUNDLE_VERSION_MAX);
const _: () = assert!(CONFIGURATION_LEN == 34 && CONFIGURATION_LEN < BUNDLE_CONFIGURATION_MAX);
const _: () = assert!(OVERLAY_LEN == 99 && OVERLAY_LEN < BUNDLE_OVERLAY_MAX);
const _: () = assert!(CACHE_WRITER_LEN == 33 && CACHE_WRITER_LEN < BUNDLE_CACHE_MAX);
const _: () = assert!(FAILURES_DERIVED_MAX == 1282 && FAILURES_DERIVED_MAX < BUNDLE_FAILURES_MAX);
const _: () = assert!(LOGS_DERIVED_MAX == 1_050_634 && LOGS_DERIVED_MAX < BUNDLE_LOGS_MAX);
const _: () = assert!(METRICS_LEN == 2577 && METRICS_LEN < BUNDLE_METRICS_MAX);

fn encode_member(fields: impl FnOnce(&mut Tape<'_>) -> Result<()>) -> Result<Vec<u8>> {
    let mut tape = Tape {
        input: None,
        output: Vec::new(),
    };
    fields(&mut tape)?;
    Ok(tape.output)
}
fn decode_member<T>(
    bytes: &[u8],
    cap: usize,
    fields: impl FnOnce(&mut Tape<'_>) -> Result<T>,
) -> Result<T> {
    require(bytes.len() <= cap, "support size bound")?;
    let mut tape = Tape {
        input: Some(bytes),
        output: Vec::new(),
    };
    let value = fields(&mut tape)?;
    tape.end()?;
    Ok(value)
}
/// A closed tag: any byte outside `allowed` refuses with `reason`.
fn tag_in_range(
    t: &mut Tape<'_>,
    seed: u8,
    allowed: RangeInclusive<u8>,
    reason: &'static str,
) -> Result<u8> {
    let tag = t.u8(seed)?;
    require(allowed.contains(&tag), reason)?;
    Ok(tag)
}
fn nonzero<T: Default + PartialEq>(value: T, reason: &'static str) -> Result<T> {
    require(value != T::default(), reason)?;
    Ok(value)
}
/// Walk a fixed array element by element, in order.
fn each<T: Copy + Default, const N: usize>(
    seed: Option<&[T; N]>,
    mut walk: impl FnMut(T) -> Result<T>,
) -> Result<[T; N]> {
    let mut out = [T::default(); N];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = walk(seed.and_then(|s| s.get(index)).copied().unwrap_or_default())?;
    }
    Ok(out)
}

/// Version and build identity. Tags: `target_os` 1 linux, 2 macos, 3 other;
/// `target_arch` 1 `x86_64`, 2 `aarch64`, 3 other; `features` bits 0
/// `overlay-fault-tests`, 1 `publish-restart-tests`, 2 `conformance-breakage`;
/// `metrics_schema` [`BUNDLE_METRICS_SCHEMA`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleVersion {
    pub package_major: u32,
    pub package_minor: u32,
    pub package_patch: u32,
    pub prerelease: bool,
    pub target_os: u8,
    pub target_arch: u8,
    pub debug_assertions: bool,
    pub features: u8,
    pub metrics_schema: u16,
    pub cache_marker_version: u32,
    pub cache_index_version: u16,
    pub overlay_journal_version: u16,
}
impl BundleVersion {
    /// Canonical fixed-width encoding.
    /// # Errors
    /// Refuses a field outside the documented accept set.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_member(|t| version_fields(t, Some(self)).map(drop))
    }
    /// Decode one complete member.
    /// # Errors
    /// Refuses excessive size, a field outside the accept set and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_member(bytes, BUNDLE_VERSION_MAX, |t| version_fields(t, None))
    }
}
fn version_fields(t: &mut Tape<'_>, s: Option<&BundleVersion>) -> Result<BundleVersion> {
    Ok(BundleVersion {
        package_major: t.u32(s.map_or(0, |s| s.package_major))?,
        package_minor: t.u32(s.map_or(0, |s| s.package_minor))?,
        package_patch: t.u32(s.map_or(0, |s| s.package_patch))?,
        prerelease: t.boolean(s.is_some_and(|s| s.prerelease))?,
        target_os: tag_in_range(t, s.map_or(0, |s| s.target_os), 1..=3, "build target os")?,
        target_arch: tag_in_range(
            t,
            s.map_or(0, |s| s.target_arch),
            1..=3,
            "build target arch",
        )?,
        debug_assertions: t.boolean(s.is_some_and(|s| s.debug_assertions))?,
        features: tag_in_range(t, s.map_or(0, |s| s.features), 0..=7, "build features")?,
        metrics_schema: nonzero(
            t.u16(s.map_or(0, |s| s.metrics_schema))?,
            "build metrics schema",
        )?,
        cache_marker_version: nonzero(
            t.u32(s.map_or(0, |s| s.cache_marker_version))?,
            "build cache marker version",
        )?,
        cache_index_version: nonzero(
            t.u16(s.map_or(0, |s| s.cache_index_version))?,
            "build cache index version",
        )?,
        overlay_journal_version: nonzero(
            t.u16(s.map_or(0, |s| s.overlay_journal_version))?,
            "build journal version",
        )?,
    })
}

/// Redacted configuration: presence, counts and closed classes only.
/// Tags: `mount_mode` 1 read-only, 2 writable; `log_format` 1 text, 2 json;
/// `log_destination` 1 stderr, 2 file; `log_paths` 1 redacted, 2 full;
/// `log_filter_source` 1 default, 2 `RUST_LOG`, 3 flag, 4 environment, 5 file.
/// The threshold is the IEEE-754 binary64 bit pattern of a finite value in
/// (0, 1].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent presence flags, each named 1:1 by an operand or setting the \
              collector reads; they are the encoded fields, so no state machine would \
              reduce the count"
)]
pub struct BundleConfiguration {
    pub mount_mode: u8,
    pub root_key_configured: bool,
    pub manifest_root_pinned: bool,
    pub trust_server: bool,
    pub tls_pin_count: u16,
    pub cache_configured: bool,
    pub seq_pinned: bool,
    pub uid_override: bool,
    pub gid_override: bool,
    pub allow_other: bool,
    pub foreground: bool,
    pub reset_floor: bool,
    pub force: bool,
    pub key_seed_configured: bool,
    pub store_dir_configured: bool,
    pub contention_threshold_bits: u64,
    pub certificate_configured: bool,
    pub key_configured: bool,
    pub credential_context_configured: bool,
    pub publisher_key_count: u16,
    pub wire_snapshot_configured: bool,
    pub log_format: u8,
    pub log_destination: u8,
    pub log_paths: u8,
    pub log_filter_source: u8,
}
impl BundleConfiguration {
    /// Canonical fixed-width encoding.
    /// # Errors
    /// Refuses a field outside the documented accept set.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_member(|t| configuration_fields(t, Some(self)).map(drop))
    }
    /// Decode one complete member.
    /// # Errors
    /// Refuses excessive size, a field outside the accept set and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_member(bytes, BUNDLE_CONFIGURATION_MAX, |t| {
            configuration_fields(t, None)
        })
    }
}
fn configuration_fields(
    t: &mut Tape<'_>,
    s: Option<&BundleConfiguration>,
) -> Result<BundleConfiguration> {
    let flag =
        |t: &mut Tape<'_>, field: fn(&BundleConfiguration) -> bool| t.boolean(s.is_some_and(field));
    Ok(BundleConfiguration {
        mount_mode: tag_in_range(t, s.map_or(0, |s| s.mount_mode), 1..=2, "mount mode")?,
        root_key_configured: flag(t, |s| s.root_key_configured)?,
        manifest_root_pinned: flag(t, |s| s.manifest_root_pinned)?,
        trust_server: flag(t, |s| s.trust_server)?,
        tls_pin_count: t.u16(s.map_or(0, |s| s.tls_pin_count))?,
        cache_configured: flag(t, |s| s.cache_configured)?,
        seq_pinned: flag(t, |s| s.seq_pinned)?,
        uid_override: flag(t, |s| s.uid_override)?,
        gid_override: flag(t, |s| s.gid_override)?,
        allow_other: flag(t, |s| s.allow_other)?,
        foreground: flag(t, |s| s.foreground)?,
        reset_floor: flag(t, |s| s.reset_floor)?,
        force: flag(t, |s| s.force)?,
        key_seed_configured: flag(t, |s| s.key_seed_configured)?,
        store_dir_configured: flag(t, |s| s.store_dir_configured)?,
        contention_threshold_bits: {
            let bits = t.u64(s.map_or(0, |s| s.contention_threshold_bits))?;
            let threshold = f64::from_bits(bits);
            require(threshold > 0.0 && threshold <= 1.0, "contention threshold")?;
            bits
        },
        certificate_configured: flag(t, |s| s.certificate_configured)?,
        key_configured: flag(t, |s| s.key_configured)?,
        credential_context_configured: flag(t, |s| s.credential_context_configured)?,
        publisher_key_count: t.u16(s.map_or(0, |s| s.publisher_key_count))?,
        wire_snapshot_configured: flag(t, |s| s.wire_snapshot_configured)?,
        log_format: tag_in_range(t, s.map_or(0, |s| s.log_format), 1..=2, "log format")?,
        log_destination: tag_in_range(
            t,
            s.map_or(0, |s| s.log_destination),
            1..=2,
            "log destination",
        )?,
        log_paths: tag_in_range(t, s.map_or(0, |s| s.log_paths), 1..=2, "log paths")?,
        log_filter_source: tag_in_range(
            t,
            s.map_or(0, |s| s.log_filter_source),
            1..=5,
            "log filter source",
        )?,
    })
}

/// Recent structured log records, oldest first, each one complete JSON object
/// line. `lost` counts records evicted or refused since the history began.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleLogs {
    pub lost: u64,
    pub records: Vec<String>,
}
impl BundleLogs {
    /// Canonical encoding.
    /// # Errors
    /// Refuses a record outside the grammar or a count, length or total over its bound.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_member(|t| logs_fields(t, Some(self)).map(drop))
    }
    /// Decode one complete member.
    /// # Errors
    /// Refuses excessive size, a record outside the grammar and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_member(bytes, BUNDLE_LOGS_MAX, |t| logs_fields(t, None))
    }
}
fn logs_fields(t: &mut Tape<'_>, s: Option<&BundleLogs>) -> Result<BundleLogs> {
    let lost = t.u64(s.map_or(0, |s| s.lost))?;
    let count = t.count(
        s.map_or(0, |s| s.records.len()),
        BUNDLE_LOG_RECORDS_MAX,
        false,
    )?;
    let mut seeds = s.into_iter().flat_map(|s| &s.records);
    let mut records = Vec::new();
    let mut total = 0_usize;
    for _ in 0..count {
        let seed = seeds.next().map_or("", String::as_str);
        let length = usize::from(t.u16(u16::try_from(seed.len()).unwrap_or(u16::MAX))?);
        require(length != 0, "log record length")?;
        total += length;
        require(total <= BUNDLE_LOG_BYTES_MAX, "support size bound")?;
        let bytes = t.blob(seed.as_bytes(), length, BUNDLE_LOG_RECORD_MAX)?;
        let record = String::from_utf8(bytes).map_err(|_| SupportError("log record text"))?;
        records::check(&record)?;
        records.push(record);
    }
    Ok(BundleLogs { lost, records })
}

/// Overlay and journal summary: counts and closed tags, no identity.
/// Tags: `readiness` 1 pending-reconciliation, 2 pending-recovery, 3 ready,
/// 4 poisoned; `commit_state` 0 none, 1 boundary in doubt, 2 landed with a
/// replacement owed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleOverlay {
    pub readiness: u8,
    pub commit_state: u8,
    pub namespace_entries: u64,
    pub free_entries: u64,
    pub cap: u64,
    pub staged_files: u64,
    pub journal_records: u64,
    pub charged_bytes: u64,
    pub reserved_bytes: u64,
    pub orphan_bytes: u64,
    pub captured_bytes: u64,
    pub swept_files: u64,
    pub swept_bytes: u64,
    pub journal_bytes: u64,
    pub commit_requested: bool,
}
impl BundleOverlay {
    /// Canonical fixed-width encoding.
    /// # Errors
    /// Refuses a field outside the documented accept set.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_member(|t| overlay_fields(t, Some(self)).map(drop))
    }
    /// Decode one complete member.
    /// # Errors
    /// Refuses excessive size, a field outside the accept set and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_member(bytes, BUNDLE_OVERLAY_MAX, |t| overlay_fields(t, None))
    }
}
fn overlay_fields(t: &mut Tape<'_>, s: Option<&BundleOverlay>) -> Result<BundleOverlay> {
    let word = |t: &mut Tape<'_>, field: fn(&BundleOverlay) -> u64| t.u64(s.map_or(0, field));
    Ok(BundleOverlay {
        readiness: tag_in_range(t, s.map_or(0, |s| s.readiness), 1..=4, "overlay readiness")?,
        commit_state: tag_in_range(
            t,
            s.map_or(0, |s| s.commit_state),
            0..=2,
            "overlay commit state",
        )?,
        namespace_entries: word(t, |s| s.namespace_entries)?,
        free_entries: word(t, |s| s.free_entries)?,
        cap: word(t, |s| s.cap)?,
        staged_files: word(t, |s| s.staged_files)?,
        journal_records: word(t, |s| s.journal_records)?,
        charged_bytes: word(t, |s| s.charged_bytes)?,
        reserved_bytes: word(t, |s| s.reserved_bytes)?,
        orphan_bytes: word(t, |s| s.orphan_bytes)?,
        captured_bytes: word(t, |s| s.captured_bytes)?,
        swept_files: word(t, |s| s.swept_files)?,
        swept_bytes: word(t, |s| s.swept_bytes)?,
        journal_bytes: word(t, |s| s.journal_bytes)?,
        commit_requested: t.boolean(s.is_some_and(|s| s.commit_requested))?,
    })
}

/// Cache summary. The writer counters do not exist in degraded mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleCache {
    Writer {
        quota_bytes: u64,
        total_bytes: u64,
        live_objects: u64,
        journal_bytes: u64,
    },
    ReadOnlyDegraded,
}
impl BundleCache {
    /// Canonical encoding: the mode tag, then the writer counters if any.
    /// # Errors
    /// Never for a well-formed value; the signature matches the other members.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_member(|t| cache_fields(t, Some(self)).map(drop))
    }
    /// Decode one complete member.
    /// # Errors
    /// Refuses excessive size, an unknown mode and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_member(bytes, BUNDLE_CACHE_MAX, |t| cache_fields(t, None))
    }
}
fn cache_fields(t: &mut Tape<'_>, s: Option<&BundleCache>) -> Result<BundleCache> {
    let (mode, counters) = match s {
        Some(&BundleCache::Writer {
            quota_bytes,
            total_bytes,
            live_objects,
            journal_bytes,
        }) => (1, [quota_bytes, total_bytes, live_objects, journal_bytes]),
        Some(BundleCache::ReadOnlyDegraded) => (2, [0; 4]),
        None => (0, [0; 4]),
    };
    match t.u8(mode)? {
        1 => {
            let [quota_bytes, total_bytes, live_objects, journal_bytes] =
                each(Some(&counters), |v| t.u64(v))?;
            Ok(BundleCache::Writer {
                quota_bytes,
                total_bytes,
                live_objects,
                journal_bytes,
            })
        }
        2 => Ok(BundleCache::ReadOnlyDegraded),
        _ => Err(SupportError("cache mode")),
    }
}

/// One retained failure. `event` is 1 `op.failed` or 2 `overlay.refused`;
/// `kind` is the operation kind 1..=10 for the first and exactly 0 for the
/// second; `class` is the failure class 1..=6. The correlation id is the
/// random identifier that joins a failure to its log records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleFailure {
    pub ordinal: u64,
    pub event: u8,
    pub kind: u8,
    pub class: u8,
    pub correlation: Option<[u8; 8]>,
}
/// The last failures, oldest first, ordinals strictly increasing and at least
/// 1; a gap means eviction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFailures {
    pub entries: Vec<BundleFailure>,
}
impl BundleFailures {
    /// Canonical encoding.
    /// # Errors
    /// Refuses a count over its bound, a disordered ordinal or a tag outside its set.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_member(|t| failures_fields(t, Some(self)).map(drop))
    }
    /// Decode one complete member.
    /// # Errors
    /// Refuses excessive size, a field outside the accept set and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_member(bytes, BUNDLE_FAILURES_MAX, |t| failures_fields(t, None))
    }
}
fn failures_fields(t: &mut Tape<'_>, s: Option<&BundleFailures>) -> Result<BundleFailures> {
    let count = t.count(
        s.map_or(0, |s| s.entries.len()),
        BUNDLE_FAILURES_ENTRIES_MAX,
        false,
    )?;
    let mut seeds = s.into_iter().flat_map(|s| &s.entries);
    let mut entries: Vec<BundleFailure> = Vec::new();
    for _ in 0..count {
        let seed = seeds.next();
        let ordinal = t.u64(seed.map_or(0, |e| e.ordinal))?;
        require(
            ordinal != 0 && entries.last().is_none_or(|last| last.ordinal < ordinal),
            "failure order",
        )?;
        let event = tag_in_range(t, seed.map_or(0, |e| e.event), 1..=2, "failure event")?;
        let kind = t.u8(seed.map_or(0, |e| e.kind))?;
        require(
            if event == 1 {
                (1..=BUNDLE_OPERATION_KINDS).contains(&kind)
            } else {
                kind == 0
            },
            "failure kind",
        )?;
        let class = tag_in_range(t, seed.map_or(0, |e| e.class), 1..=6, "failure class")?;
        let correlation = t.option(seed.and_then(|e| e.correlation.as_ref()), |t, s| {
            t.fixed(s.copied().unwrap_or([0; 8]))
        })?;
        entries.push(BundleFailure {
            ordinal,
            event,
            kind,
            class,
            correlation,
        });
    }
    Ok(BundleFailures { entries })
}

/// One latency histogram: 12 stored (not cumulative) bucket counts and a sum.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BundleHistogram {
    pub buckets: [u64; 12],
    pub sum: u64,
}
/// The metrics snapshot in the recorder's field order. Every counter admits
/// the whole u64 range; `u64::MAX` is the catalogue's invalidity sentinel and
/// is carried as written. `contention` is 0 no decision, 1 clear, 2 flagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleMetrics {
    pub incarnation: [u32; 4],
    pub sequence: u64,
    pub available: [bool; 6],
    pub commits: [u64; 6],
    pub commit_duration: [BundleHistogram; 6],
    pub retries: [u64; 3],
    pub conflicts: u64,
    pub contention: u8,
    pub syncs: [u64; 4],
    pub fuse: [[u64; 4]; 40],
    pub registrations: [u64; 4],
    pub registration_duration: [BundleHistogram; 4],
    pub grains: u64,
    pub uploads: [u64; 2],
    pub rechunks: u64,
    pub cache: [[u64; 2]; 2],
    pub transport: [u64; 2],
}
impl BundleMetrics {
    /// Canonical fixed-width encoding, schema [`BUNDLE_METRICS_SCHEMA`].
    /// # Errors
    /// Refuses a sequence outside 1..=`u64::MAX - 1` or an unknown contention tag.
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_member(|t| metrics_fields(t, Some(self)).map(drop))
    }
    /// Decode one complete member.
    /// # Errors
    /// Refuses excessive size, a schema other than [`BUNDLE_METRICS_SCHEMA`], a field
    /// outside the accept set and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_member(bytes, BUNDLE_METRICS_MAX, |t| metrics_fields(t, None))
    }
}
fn metrics_fields(t: &mut Tape<'_>, s: Option<&BundleMetrics>) -> Result<BundleMetrics> {
    fn words<const N: usize>(t: &mut Tape<'_>, seed: Option<&[u64; N]>) -> Result<[u64; N]> {
        each(seed, |v| t.u64(v))
    }
    fn histograms<const N: usize>(
        t: &mut Tape<'_>,
        seed: Option<&[BundleHistogram; N]>,
    ) -> Result<[BundleHistogram; N]> {
        each(seed, |h| {
            Ok(BundleHistogram {
                buckets: words(t, Some(&h.buckets))?,
                sum: t.u64(h.sum)?,
            })
        })
    }
    let schema = t.u16(BUNDLE_METRICS_SCHEMA)?;
    require(schema == BUNDLE_METRICS_SCHEMA, "metrics schema")?;
    Ok(BundleMetrics {
        incarnation: each(s.map(|s| &s.incarnation), |v| t.u32(v))?,
        sequence: {
            let sequence = t.u64(s.map_or(0, |s| s.sequence))?;
            require((1..u64::MAX).contains(&sequence), "metrics sequence")?;
            sequence
        },
        available: each(s.map(|s| &s.available), |v| t.boolean(v))?,
        commits: words(t, s.map(|s| &s.commits))?,
        commit_duration: histograms(t, s.map(|s| &s.commit_duration))?,
        retries: words(t, s.map(|s| &s.retries))?,
        conflicts: t.u64(s.map_or(0, |s| s.conflicts))?,
        contention: tag_in_range(
            t,
            s.map_or(0, |s| s.contention),
            0..=2,
            "metrics contention",
        )?,
        syncs: words(t, s.map(|s| &s.syncs))?,
        fuse: each(s.map(|s| &s.fuse), |row| words(t, Some(&row)))?,
        registrations: words(t, s.map(|s| &s.registrations))?,
        registration_duration: histograms(t, s.map(|s| &s.registration_duration))?,
        grains: t.u64(s.map_or(0, |s| s.grains))?,
        uploads: words(t, s.map(|s| &s.uploads))?,
        rechunks: t.u64(s.map_or(0, |s| s.rechunks))?,
        cache: each(s.map(|s| &s.cache), |row| words(t, Some(&row)))?,
        transport: words(t, s.map(|s| &s.transport))?,
    })
}
