// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Canonical client support-bundle manifest, archive and member codecs. The
//! archive depends on the members and never the reverse.
pub(super) mod members;
pub(super) mod records;
#[cfg(test)]
mod tests;

use super::{
    BUNDLE_CACHE_MAX, BUNDLE_CONFIGURATION_MAX, BUNDLE_FAILURES_MAX, BUNDLE_LOGS_MAX,
    BUNDLE_METRICS_MAX, BUNDLE_METRICS_SCHEMA, BUNDLE_OVERLAY_MAX, BUNDLE_VERSION_MAX, BundleCache,
    BundleConfiguration, BundleFailures, BundleLogs, BundleMetrics, BundleOverlay, BundleVersion,
    CHECK_LEN, HEADER_LEN, OVERHEAD, PROFILE_LEN, Result, SupportError, Tape, open, require, seal,
};
use crate::{hash::GrainId, sheaf::Timestamp};
use members::{CACHE_WRITER_LEN, CONFIGURATION_LEN, METRICS_LEN, OVERLAY_LEN, VERSION_LEN};
use std::collections::BTreeMap;

/// Independent full bundle-manifest limit: 4 KiB.
pub const BUNDLE_MANIFEST_MAX: usize = 4096;
/// Full uncompressed bundle-archive limit: 2 MiB.
pub const BUNDLE_ARCHIVE_MAX: usize = 2_097_152;
/// Exactly one manifest entry per bundle member kind.
pub const BUNDLE_MANIFEST_ENTRIES_MAX: usize = 7;
/// Most exported members one bundle archive carries.
pub const BUNDLE_MEMBERS_MAX: usize = 7;
pub(crate) const MANIFEST_HEADER_LEN: usize = 12 + 2;
pub(crate) const MANIFEST_ENTRIES_OFFSET: usize = HEADER_LEN + MANIFEST_HEADER_LEN;
pub(crate) const ENTRY_HEAD_LEN: usize = 1 + 2 + 4 + 1;
pub(crate) const STATUS_EXPORTED: u8 = 1;
pub(crate) const STATUS_REFUSED: u8 = 2;
pub(crate) const MEMBER_LEN_WIDTH: usize = 4;
const ENTRY_EXPORTED_DIGEST_OFFSET: usize = MEMBER_LEN_WIDTH + PROFILE_LEN;
pub(crate) const ENTRY_EXPORTED_TAIL_LEN: usize = ENTRY_EXPORTED_DIGEST_OFFSET + CHECK_LEN;
pub(crate) const ENTRY_REFUSED_TAIL_LEN: usize = 2;
const MANIFEST_ENTRY_MAX_LEN: usize = ENTRY_HEAD_LEN + 1 + 17 + ENTRY_EXPORTED_TAIL_LEN;
pub(crate) const ARCHIVE_MANIFEST_LEN_WIDTH: usize = 4;
pub(crate) const ARCHIVE_MANIFEST_OFFSET: usize = HEADER_LEN + ARCHIVE_MANIFEST_LEN_WIDTH;
pub(crate) const ARCHIVE_MEMBER_COUNT_WIDTH: usize = 2;
const ARCHIVE_MEMBER_FRAMING_LEN: usize = 1 + MEMBER_LEN_WIDTH;
/// Maximum manifest encoding derived from the envelope, timestamp, count and
/// seven 64-byte entries.
pub const BUNDLE_MANIFEST_DERIVED_MAX: usize =
    OVERHEAD + MANIFEST_HEADER_LEN + BUNDLE_MANIFEST_ENTRIES_MAX * MANIFEST_ENTRY_MAX_LEN;
/// Maximum archive encoding derived from the envelope, manifest, member
/// framing, seven member names (79 bytes) and the seven member caps.
pub const BUNDLE_ARCHIVE_DERIVED_MAX: usize = OVERHEAD
    + ARCHIVE_MANIFEST_LEN_WIDTH
    + BUNDLE_MANIFEST_DERIVED_MAX
    + ARCHIVE_MEMBER_COUNT_WIDTH
    + BUNDLE_MEMBERS_MAX * ARCHIVE_MEMBER_FRAMING_LEN
    + 79
    + BUNDLE_VERSION_MAX
    + BUNDLE_CONFIGURATION_MAX
    + BUNDLE_LOGS_MAX
    + BUNDLE_OVERLAY_MAX
    + BUNDLE_CACHE_MAX
    + BUNDLE_FAILURES_MAX
    + BUNDLE_METRICS_MAX;
const _: () = assert!(
    BUNDLE_MANIFEST_DERIVED_MAX == 512 && BUNDLE_MANIFEST_DERIVED_MAX < BUNDLE_MANIFEST_MAX
);
const _: () = assert!(
    BUNDLE_ARCHIVE_DERIVED_MAX == 1_121_578 && BUNDLE_ARCHIVE_DERIVED_MAX < BUNDLE_ARCHIVE_MAX
);
const BUNDLE_MANIFEST_KIND: u16 = 0x0205;
const BUNDLE_ARCHIVE_KIND: u16 = 0x0206;
const fn bytes_lt(mut a: &[u8], mut b: &[u8]) -> bool {
    while let (Some((&av, ar)), Some((&bv, br))) = (a.split_first(), b.split_first()) {
        if av != bv {
            return av < bv;
        }
        a = ar;
        b = br;
    }
    a.is_empty() && !b.is_empty()
}
const MEMBER_NAME_ORDER: [BundleKind; BUNDLE_MEMBERS_MAX] = [
    BundleKind::Cache,
    BundleKind::Configuration,
    BundleKind::Failures,
    BundleKind::Logs,
    BundleKind::Metrics,
    BundleKind::Overlay,
    BundleKind::Version,
];
const _: () = {
    let mut rest: &[BundleKind] = &MEMBER_NAME_ORDER;
    let mut tags = 0u8;
    while let Some((&first, tail)) = rest.split_first() {
        if let Some((&next, _)) = tail.split_first() {
            assert!(bytes_lt(first.member_name(), next.member_name()));
        }
        tags |= 1 << first.tag();
        rest = tail;
    }
    assert!(tags == 0b1111_1110);
};

/// Closed bundle-member registry. Numeric tags, not member-name order, define
/// manifest entry ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BundleKind {
    Version,
    Configuration,
    Logs,
    Overlay,
    Cache,
    Failures,
    Metrics,
}
impl BundleKind {
    /// Canonical bundle-member kind tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Version => 1,
            Self::Configuration => 2,
            Self::Logs => 3,
            Self::Overlay => 4,
            Self::Cache => 5,
            Self::Failures => 6,
            Self::Metrics => 7,
        }
    }
    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Version),
            2 => Ok(Self::Configuration),
            3 => Ok(Self::Logs),
            4 => Ok(Self::Overlay),
            5 => Ok(Self::Cache),
            6 => Ok(Self::Failures),
            7 => Ok(Self::Metrics),
            _ => Err(SupportError("bundle member kind")),
        }
    }
    /// Fixed projection cap for this member kind.
    #[must_use]
    pub const fn cap(self) -> usize {
        match self {
            Self::Version => BUNDLE_VERSION_MAX,
            Self::Configuration => BUNDLE_CONFIGURATION_MAX,
            Self::Logs => BUNDLE_LOGS_MAX,
            Self::Overlay => BUNDLE_OVERLAY_MAX,
            Self::Cache => BUNDLE_CACHE_MAX,
            Self::Failures => BUNDLE_FAILURES_MAX,
            Self::Metrics => BUNDLE_METRICS_MAX,
        }
    }
    /// Fixed archive member name for this kind.
    #[must_use]
    pub const fn member_name(self) -> &'static [u8] {
        match self {
            Self::Version => b"version.bin",
            Self::Configuration => b"configuration.bin",
            Self::Logs => b"logs.bin",
            Self::Overlay => b"overlay.bin",
            Self::Cache => b"cache.bin",
            Self::Failures => b"failures.bin",
            Self::Metrics => b"metrics.bin",
        }
    }
}
/// Fixed refusals: no source-derived text can inhabit a manifest reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleRefusal {
    NotApplicable,
    Unavailable,
    Unreadable,
    Corrupt,
    TimedOut,
    Unencodable,
}
impl BundleRefusal {
    /// Canonical refusal-reason tag.
    #[must_use]
    pub const fn tag(self) -> u16 {
        match self {
            Self::NotApplicable => 1,
            Self::Unavailable => 2,
            Self::Unreadable => 3,
            Self::Corrupt => 4,
            Self::TimedOut => 5,
            Self::Unencodable => 6,
        }
    }
    fn from_tag(tag: u16) -> Result<Self> {
        match tag {
            1 => Ok(Self::NotApplicable),
            2 => Ok(Self::Unavailable),
            3 => Ok(Self::Unreadable),
            4 => Ok(Self::Corrupt),
            5 => Ok(Self::TimedOut),
            6 => Ok(Self::Unencodable),
            _ => Err(SupportError("bundle refusal")),
        }
    }
}
impl std::fmt::Display for BundleRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotApplicable => "not-applicable",
            Self::Unavailable => "unavailable",
            Self::Unreadable => "unreadable",
            Self::Corrupt => "corrupt",
            Self::TimedOut => "timed-out",
            Self::Unencodable => "unencodable",
        })
    }
}
impl std::error::Error for BundleRefusal {}
/// An exported bundle member is always distinct from a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleEntryStatus {
    Exported { length: u32, digest: [u8; 32] },
    Refused(BundleRefusal),
}
/// One bounded bundle-member projection entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleEntry {
    pub kind: BundleKind,
    pub status: BundleEntryStatus,
}
/// Client support-bundle manifest; all fields are checked in both codec directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleManifest {
    pub bundled_at: Timestamp,
    pub entries: Vec<BundleEntry>,
}
impl BundleManifest {
    /// Canonical bounded encoding.
    /// # Errors
    /// Refuses disordered or missing kinds, invalid reasons, profiles or bounds.
    pub fn encode(&self) -> Result<Vec<u8>> {
        seal(BUNDLE_MANIFEST_KIND, BUNDLE_MANIFEST_MAX, |t| {
            manifest_fields(t, Some(self))?;
            Ok(())
        })
    }
    /// Verify exact received bytes and decode within fixed bounds.
    /// # Errors
    /// Refuses invalid envelopes, checksums and noncanonical fields.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut t = open(bytes, BUNDLE_MANIFEST_KIND, BUNDLE_MANIFEST_MAX)?;
        let value = manifest_fields(&mut t, None)?;
        t.end()?;
        Ok(value)
    }
}
fn entry_fields(t: &mut Tape<'_>, s: Option<&BundleEntry>) -> Result<BundleEntry> {
    let kind = BundleKind::from_tag(t.u8(s.map_or(0, |s| s.kind.tag()))?)?;
    let projection_version = t.u16(1)?;
    require(projection_version == 1, "projection version")?;
    let cap_u32 = u32::try_from(kind.cap()).map_err(|_| SupportError("projection cap"))?;
    let cap = t.u32(cap_u32)?;
    require(cap == cap_u32, "projection cap")?;
    let exported = s.and_then(|s| match s.status {
        BundleEntryStatus::Exported { length, digest } => Some((length, digest)),
        BundleEntryStatus::Refused(_) => None,
    });
    let tag = t.u8(s.map_or(0, |s| match s.status {
        BundleEntryStatus::Exported { .. } => STATUS_EXPORTED,
        BundleEntryStatus::Refused(_) => STATUS_REFUSED,
    }))?;
    let status = match tag {
        STATUS_EXPORTED => {
            let member = t.export_name(kind.member_name())?;
            require(member == kind.member_name(), "member name")?;
            let length = t.u32(exported.map_or(0, |(l, _)| l))?;
            let valid_len = usize::try_from(length).is_ok_and(|len| match kind {
                BundleKind::Version => len == VERSION_LEN,
                BundleKind::Configuration => len == CONFIGURATION_LEN,
                BundleKind::Overlay => len == OVERLAY_LEN,
                BundleKind::Cache => matches!(len, 1 | CACHE_WRITER_LEN),
                BundleKind::Metrics => len == METRICS_LEN,
                BundleKind::Logs | BundleKind::Failures => (1..=kind.cap()).contains(&len),
            });
            require(valid_len, "member length")?;
            require(t.u8(1)? == 1 && t.u8(1)? == 1, "member hash profile")?;
            let digest = t.fixed(exported.map_or([0; CHECK_LEN], |(_, d)| d))?;
            BundleEntryStatus::Exported { length, digest }
        }
        STATUS_REFUSED => {
            let reason = BundleRefusal::from_tag(t.u16(s.map_or(0, |s| match s.status {
                BundleEntryStatus::Refused(r) => r.tag(),
                BundleEntryStatus::Exported { .. } => 0,
            }))?)?;
            require(
                match kind {
                    BundleKind::Version => false,
                    BundleKind::Configuration => {
                        matches!(
                            reason,
                            BundleRefusal::Unavailable | BundleRefusal::Unencodable
                        )
                    }
                    BundleKind::Logs | BundleKind::Failures | BundleKind::Metrics => {
                        reason == BundleRefusal::Unavailable
                    }
                    BundleKind::Overlay | BundleKind::Cache => reason != BundleRefusal::Unencodable,
                },
                "member refusal",
            )?;
            BundleEntryStatus::Refused(reason)
        }
        _ => return Err(SupportError("entry status")),
    };
    Ok(BundleEntry { kind, status })
}
fn manifest_fields(t: &mut Tape<'_>, s: Option<&BundleManifest>) -> Result<BundleManifest> {
    let zero = Timestamp { secs: 0, nanos: 0 };
    let bundled_at = t.time(s.map_or(zero, |s| s.bundled_at))?;
    let count = t.count(
        s.map_or(0, |s| s.entries.len()),
        BUNDLE_MANIFEST_ENTRIES_MAX,
        false,
    )?;
    require(count == BUNDLE_MANIFEST_ENTRIES_MAX, "manifest entry count")?;
    let mut seeds = s.into_iter().flat_map(|s| &s.entries);
    let mut entries: Vec<BundleEntry> = Vec::new();
    for _ in 0..count {
        let entry = entry_fields(t, seeds.next())?;
        require(
            entries
                .last()
                .is_none_or(|last| last.kind.tag() < entry.kind.tag()),
            "entry order",
        )?;
        entries.push(entry);
    }
    Ok(BundleManifest {
        bundled_at,
        entries,
    })
}
/// Complete uncompressed support bundle. Members are keyed by [`BundleKind`]
/// and encoded in raw member-name order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleArchive {
    pub manifest: BundleManifest,
    pub members: BTreeMap<BundleKind, Vec<u8>>,
}
impl BundleArchive {
    /// Encode an exact manifest/member agreement, within the whole archive cap.
    /// # Errors
    /// Refuses mismatched or malformed members, hashes, schemas or excessive sizes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let manifest = self.manifest.encode()?;
        seal(BUNDLE_ARCHIVE_KIND, BUNDLE_ARCHIVE_MAX, |t| {
            archive_fields(t, Some((self, &manifest)))?;
            Ok(())
        })
    }
    /// Verify exact archive, manifest and member bytes before decoding.
    /// # Errors
    /// Refuses noncanonical framing, extra/missing or malformed members and digest mismatches.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut t = open(bytes, BUNDLE_ARCHIVE_KIND, BUNDLE_ARCHIVE_MAX)?;
        let value = archive_fields(&mut t, None)?;
        t.end()?;
        Ok(value)
    }
}
fn archive_fields(t: &mut Tape<'_>, s: Option<(&BundleArchive, &[u8])>) -> Result<BundleArchive> {
    let length = usize::try_from(t.u32(s.map_or(0, |(_, bytes)| {
        u32::try_from(bytes.len()).unwrap_or(u32::MAX)
    }))?)
    .map_err(|_| SupportError("support size bound"))?;
    let bytes = t.blob(
        s.map_or(&[], |(_, bytes)| bytes),
        length,
        BUNDLE_MANIFEST_MAX,
    )?;
    let manifest = BundleManifest::decode(&bytes)?;
    let expected: BTreeMap<&'static [u8], (BundleKind, u32, [u8; 32])> = manifest
        .entries
        .iter()
        .filter_map(|e| match e.status {
            BundleEntryStatus::Exported { length, digest } => {
                Some((e.kind.member_name(), (e.kind, length, digest)))
            }
            BundleEntryStatus::Refused(_) => None,
        })
        .collect();
    let count = t.count(
        s.map_or(0, |(a, _)| a.members.len()),
        BUNDLE_MEMBERS_MAX,
        false,
    )?;
    require(count == expected.len(), "archive member count")?;
    let mut seeds = s.into_iter().flat_map(|(a, _)| {
        MEMBER_NAME_ORDER
            .into_iter()
            .filter_map(|kind| a.members.get(&kind).map(|bytes| (kind, bytes.as_slice())))
    });
    let mut members = BTreeMap::new();
    let mut last_name: Option<&'static [u8]> = None;
    let mut version_schema = None;
    let mut has_metrics = false;
    for _ in 0..count {
        let seed = seeds.next();
        let name = t.export_name(seed.map_or(&[], |(kind, _)| kind.member_name()))?;
        require(
            last_name.is_none_or(|last| last < name.as_slice()),
            "archive member order",
        )?;
        let &(kind, expected_len, digest) = expected
            .get(name.as_slice())
            .ok_or(SupportError("archive extra member"))?;
        last_name = Some(kind.member_name());
        let length = t.u32(seed.map_or(0, |(_, b)| u32::try_from(b.len()).unwrap_or(u32::MAX)))?;
        require(length == expected_len, "archive member length")?;
        let member_len = usize::try_from(length).map_err(|_| SupportError("member length"))?;
        // `expected_len` was already bounded by `kind.cap()` in the manifest entry, and
        // `length == expected_len` refuses above as `"archive member length"`, so `blob`'s
        // `"support size bound"` check cannot fire here.
        let owned = if t.input.is_some() {
            Some(t.blob(&[], member_len, kind.cap())?)
        } else {
            let slice = seed.map_or(&[][..], |(_, b)| b);
            t.output.extend_from_slice(slice);
            None
        };
        let bytes = owned
            .as_deref()
            .unwrap_or_else(|| seed.map_or(&[], |(_, b)| b));
        require(
            *GrainId::of(bytes).digest() == digest,
            "archive member checksum",
        )?;
        match kind {
            BundleKind::Version => {
                version_schema = Some(BundleVersion::decode(bytes)?.metrics_schema);
            }
            BundleKind::Configuration => _ = BundleConfiguration::decode(bytes)?,
            BundleKind::Logs => _ = BundleLogs::decode(bytes)?,
            BundleKind::Overlay => _ = BundleOverlay::decode(bytes)?,
            BundleKind::Cache => _ = BundleCache::decode(bytes)?,
            BundleKind::Failures => _ = BundleFailures::decode(bytes)?,
            BundleKind::Metrics => {
                _ = BundleMetrics::decode(bytes)?;
                has_metrics = true;
            }
        }
        if let Some(owned) = owned {
            members.insert(kind, owned);
        }
    }
    if let Some(version_schema) = version_schema
        && has_metrics
    {
        require(
            version_schema == BUNDLE_METRICS_SCHEMA,
            "archive metrics schema",
        )?;
    }
    Ok(BundleArchive { manifest, members })
}
