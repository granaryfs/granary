// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Canonical manifest, uncompressed archive and log metadata projections.
use super::{CONFIGURATION_MAX, Result, SNAPSHOT_MAX, SupportError, Tape, open, require, seal};
use crate::{
    authlog::Epoch, debug_grant::Incarnation, hash::GrainId, root::VolumeName, sheaf::Timestamp,
};
use std::collections::{BTreeMap, BTreeSet};

/// Independent full manifest limit: 1 MiB.
pub const MANIFEST_MAX: usize = 1_048_576;
/// Full uncompressed archive limit: 16 MiB.
pub const ARCHIVE_MAX: usize = 16_777_216;
/// Names examined per source root.
pub const SCAN_NAMES_MAX: usize = 1024;
/// Two required files, 64 logs, two bounded scans and two summaries.
pub const MANIFEST_ENTRIES_MAX: usize = 2 + 64 + 2 * SCAN_NAMES_MAX + 2;
/// Maximum encoding derived from the entry and header widths.
pub const MANIFEST_DERIVED_MAX: usize = MANIFEST_ENTRIES_MAX * 256 + 256;
/// Encoded log metadata limit.
pub const LOG_METADATA_MAX: usize = 1024;
const _: () = assert!(MANIFEST_ENTRIES_MAX == 2116);
const _: () = assert!(MANIFEST_DERIVED_MAX == 541_952);
const _: () = assert!(MANIFEST_DERIVED_MAX < MANIFEST_MAX);
const MANIFEST_KIND: u16 = 0x0203;
const ARCHIVE_KIND: u16 = 0x0204;

/// Disk sampling age; regressed clocks retain the positive lead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgeStatus {
    Fresh,
    StalledWriter,
    ClockRegressed,
}
impl AgeStatus {
    fn tag(self) -> u8 {
        match self {
            Self::Fresh => 1,
            Self::StalledWriter => 2,
            Self::ClockRegressed => 3,
        }
    }
}
/// Exact absolute timestamp difference and its interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotAge {
    pub status: AgeStatus,
    pub seconds: u64,
    pub nanos: u32,
}
impl SnapshotAge {
    /// Compute exact age without clamping a future sample.
    /// # Errors
    /// Invalid nanoseconds or an unrepresentable timestamp difference.
    pub fn between(exported: Timestamp, sampled: Timestamp) -> Result<Self> {
        require(
            exported.is_valid() && sampled.is_valid(),
            "timestamp nanoseconds",
        )?;
        let ticks = |t: Timestamp| {
            i128::from(t.secs)
                .checked_mul(1_000_000_000)
                .and_then(|s| s.checked_add(i128::from(t.nanos)))
        };
        let delta = ticks(exported)
            .and_then(|e| ticks(sampled).and_then(|s| e.checked_sub(s)))
            .ok_or(SupportError("snapshot age overflow"))?;
        let absolute = delta
            .checked_abs()
            .ok_or(SupportError("snapshot age overflow"))?;
        let status = if delta < 0 {
            AgeStatus::ClockRegressed
        } else if delta > 120_000_000_000 {
            AgeStatus::StalledWriter
        } else {
            AgeStatus::Fresh
        };
        Ok(Self {
            status,
            seconds: u64::try_from(absolute / 1_000_000_000)
                .map_err(|_| SupportError("snapshot age overflow"))?,
            nanos: u32::try_from(absolute % 1_000_000_000)
                .map_err(|_| SupportError("snapshot age overflow"))?,
        })
    }
}
/// Closed source registry. Numeric tags, not enum order, define ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Snapshot,
    Configuration,
    Log,
    UnknownSupport,
    UnknownState,
    SupportSummary,
    StateSummary,
}
impl SourceKind {
    /// Canonical source-kind tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Snapshot => 1,
            Self::Configuration => 2,
            Self::Log => 3,
            Self::UnknownSupport => 4,
            Self::UnknownState => 5,
            Self::SupportSummary => 6,
            Self::StateSummary => 7,
        }
    }
    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Snapshot),
            2 => Ok(Self::Configuration),
            3 => Ok(Self::Log),
            4 => Ok(Self::UnknownSupport),
            5 => Ok(Self::UnknownState),
            6 => Ok(Self::SupportSummary),
            7 => Ok(Self::StateSummary),
            _ => Err(SupportError("source kind")),
        }
    }
    /// Fixed projection cap for this source.
    #[must_use]
    pub const fn cap(self) -> usize {
        match self {
            Self::Snapshot => SNAPSHOT_MAX,
            Self::Configuration => CONFIGURATION_MAX,
            Self::Log => LOG_METADATA_MAX,
            _ => 0,
        }
    }
}
/// Fixed refusals: no source-derived text can inhabit a manifest reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportRefusal {
    Missing,
    Unreadable,
    Symlink,
    NonRegular,
    Unprotected,
    Oversize,
    Corrupt,
    OversizeEnvelope,
    ChangedDuringRead,
    NotAllowlisted,
    ScanLimit,
}
impl ExportRefusal {
    fn tag(self) -> u16 {
        match self {
            Self::Missing => 1,
            Self::Unreadable => 2,
            Self::Symlink => 3,
            Self::NonRegular => 4,
            Self::Unprotected => 5,
            Self::Oversize => 6,
            Self::Corrupt => 7,
            Self::OversizeEnvelope => 8,
            Self::ChangedDuringRead => 9,
            Self::NotAllowlisted => 10,
            Self::ScanLimit => 11,
        }
    }
    fn from_tag(tag: u16) -> Result<Self> {
        match tag {
            1 => Ok(Self::Missing),
            2 => Ok(Self::Unreadable),
            3 => Ok(Self::Symlink),
            4 => Ok(Self::NonRegular),
            5 => Ok(Self::Unprotected),
            6 => Ok(Self::Oversize),
            7 => Ok(Self::Corrupt),
            8 => Ok(Self::OversizeEnvelope),
            9 => Ok(Self::ChangedDuringRead),
            10 => Ok(Self::NotAllowlisted),
            11 => Ok(Self::ScanLimit),
            _ => Err(SupportError("export refusal")),
        }
    }
}
impl std::fmt::Display for ExportRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Missing => "missing",
            Self::Unreadable => "unreadable",
            Self::Symlink => "symlink",
            Self::NonRegular => "non-regular",
            Self::Unprotected => "unprotected",
            Self::Oversize => "oversize",
            Self::Corrupt => "corrupt",
            Self::OversizeEnvelope => "oversize-envelope",
            Self::ChangedDuringRead => "changed-during-read",
            Self::NotAllowlisted => "not-allowlisted",
            Self::ScanLimit => "scan-limit",
        })
    }
}
/// An exported member is always distinct from a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryStatus {
    Exported {
        member: Vec<u8>,
        length: u32,
        digest: [u8; 32],
    },
    Refused(ExportRefusal),
}
/// One bounded source projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEntry {
    pub kind: SourceKind,
    pub id: Vec<u8>,
    pub projection_version: u16,
    pub cap: u32,
    pub status: EntryStatus,
}
/// Disk-sampled manifest; all fields are checked in both codec directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportManifest {
    pub exported_at: Timestamp,
    pub incarnation: Incarnation,
    pub expected_incarnation: Option<Incarnation>,
    pub sampled_at: Timestamp,
    pub age: SnapshotAge,
    pub support_truncated: bool,
    pub state_truncated: bool,
    pub entries: Vec<ExportEntry>,
}
impl SupportManifest {
    /// Canonical bounded encoding.
    /// # Errors
    /// Refuses inconsistent ages, inventories, profiles, bounds or ordering.
    pub fn encode(&self) -> Result<Vec<u8>> {
        seal(MANIFEST_KIND, MANIFEST_MAX, |t| {
            manifest_fields(t, Some(self))?;
            Ok(())
        })
    }
    /// Verify exact received bytes and decode within fixed bounds.
    /// # Errors
    /// Refuses invalid envelopes, checksums and noncanonical fields.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut t = open(bytes, MANIFEST_KIND, MANIFEST_MAX)?;
        let value = manifest_fields(&mut t, None)?;
        t.end()?;
        Ok(value)
    }
}
fn expected_member(kind: SourceKind, id: &[u8]) -> Result<Option<Vec<u8>>> {
    let member = match kind {
        SourceKind::Snapshot => {
            require(id == b"SUPPORT-SNAPSHOT", "source id")?;
            Some(b"snapshot.bin".to_vec())
        }
        SourceKind::Configuration => {
            require(id == b"SUPPORT-CONFIGURATION", "source id")?;
            Some(b"configuration.bin".to_vec())
        }
        SourceKind::Log => {
            VolumeName::from_bytes(id).map_err(|_| SupportError("volume name"))?;
            let mut name = id.to_vec();
            name.extend_from_slice(b".logmeta");
            Some(name)
        }
        SourceKind::UnknownSupport | SourceKind::UnknownState => {
            let digits = id
                .strip_prefix(b"unknown-")
                .ok_or(SupportError("synthetic source id"))?;
            require(
                digits.len() == 4 && digits.iter().all(u8::is_ascii_digit),
                "synthetic source id",
            )?;
            let ordinal = digits
                .iter()
                .fold(0_u32, |n, d| n * 10 + u32::from(d.saturating_sub(b'0')));
            require(ordinal < 1024, "synthetic source id")?;
            None
        }
        SourceKind::SupportSummary | SourceKind::StateSummary => {
            require(id == b"inventory", "source id")?;
            None
        }
    };
    Ok(member)
}
fn entry_fields(t: &mut Tape<'_>, s: Option<&ExportEntry>) -> Result<ExportEntry> {
    let kind = SourceKind::from_tag(t.u8(s.map_or(0, |s| s.kind.tag()))?)?;
    let id = t.export_name(s.map_or(&[], |s| s.id.as_slice()))?;
    let projection_version = t.u16(s.map_or(0, |s| s.projection_version))?;
    require(projection_version == 1, "projection version")?;
    let cap = t.u32(s.map_or(0, |s| s.cap))?;
    require(
        usize::try_from(cap).ok() == Some(kind.cap()),
        "projection cap",
    )?;
    let expected = expected_member(kind, &id)?;
    let exported = s.and_then(|s| match &s.status {
        EntryStatus::Exported {
            member,
            length,
            digest,
        } => Some((member, *length, *digest)),
        EntryStatus::Refused(_) => None,
    });
    let tag = t.u8(s.map_or(0, |s| match s.status {
        EntryStatus::Exported { .. } => 1,
        EntryStatus::Refused(_) => 2,
    }))?;
    let status = match tag {
        1 => {
            let member = t.export_name(exported.map_or(&[], |(m, _, _)| m.as_slice()))?;
            require(expected.as_ref() == Some(&member), "member name")?;
            let length = t.u32(exported.map_or(0, |(_, l, _)| l))?;
            require(length > 0 && length <= cap, "member length")?;
            require(t.u8(1)? == 1 && t.u8(1)? == 1, "member hash profile")?;
            let digest = t.fixed(exported.map_or([0; 32], |(_, _, d)| d))?;
            EntryStatus::Exported {
                member,
                length,
                digest,
            }
        }
        2 => {
            let reason = ExportRefusal::from_tag(t.u16(s.map_or(0, |s| match s.status {
                EntryStatus::Refused(r) => r.tag(),
                EntryStatus::Exported { .. } => 0,
            }))?)?;
            require(
                match kind {
                    SourceKind::Log => reason.tag() <= 9,
                    SourceKind::UnknownSupport | SourceKind::UnknownState => {
                        reason == ExportRefusal::NotAllowlisted
                    }
                    SourceKind::SupportSummary | SourceKind::StateSummary => {
                        reason == ExportRefusal::ScanLimit
                    }
                    SourceKind::Snapshot | SourceKind::Configuration => false,
                },
                "source refusal",
            )?;
            EntryStatus::Refused(reason)
        }
        _ => return Err(SupportError("entry status")),
    };
    Ok(ExportEntry {
        kind,
        id,
        projection_version,
        cap,
        status,
    })
}
fn manifest_fields(t: &mut Tape<'_>, s: Option<&SupportManifest>) -> Result<SupportManifest> {
    let zero = Timestamp { secs: 0, nanos: 0 };
    let exported_at = t.time(s.map_or(zero, |s| s.exported_at))?;
    let incarnation =
        Incarnation::from_bytes(t.fixed(s.map_or([0; 16], |s| *s.incarnation.as_bytes()))?);
    let expected_incarnation = t.option(
        s.and_then(|s| s.expected_incarnation.as_ref()),
        |t, seed| {
            Ok(Incarnation::from_bytes(
                t.fixed(seed.map_or([0; 16], |i| *i.as_bytes()))?,
            ))
        },
    )?;
    require(
        expected_incarnation.is_none_or(|i| i == incarnation),
        "expected incarnation",
    )?;
    let sampled_at = t.time(s.map_or(zero, |s| s.sampled_at))?;
    require(t.u8(1)? == 1, "sampling semantics")?;
    let age = SnapshotAge::between(exported_at, sampled_at)?;
    let status = t.u8(s.map_or(0, |s| s.age.status.tag()))?;
    let seconds = t.u64(s.map_or(0, |s| s.age.seconds))?;
    let nanos = t.u32(s.map_or(0, |s| s.age.nanos))?;
    require(
        (status, seconds, nanos) == (age.status.tag(), age.seconds, age.nanos),
        "snapshot age",
    )?;
    let support_truncated = t.boolean(s.is_some_and(|s| s.support_truncated))?;
    let state_truncated = t.boolean(s.is_some_and(|s| s.state_truncated))?;
    let count = t.count(
        s.map_or(0, |s| s.entries.len()),
        MANIFEST_ENTRIES_MAX,
        false,
    )?;
    let mut seeds = s.into_iter().flat_map(|s| &s.entries);
    let mut entries: Vec<ExportEntry> = Vec::new();
    let mut members = BTreeSet::new();
    let mut counts = [0_usize; 7];
    for _ in 0..count {
        let entry = entry_fields(t, seeds.next())?;
        require(
            entries
                .last()
                .is_none_or(|last| (last.kind.tag(), &last.id) < (entry.kind.tag(), &entry.id)),
            "entry order",
        )?;
        let tally = counts
            .get_mut(usize::from(entry.kind.tag() - 1))
            .ok_or(SupportError("source kind"))?;
        *tally += 1;
        require(
            *tally
                <= match entry.kind {
                    SourceKind::Log => 64,
                    SourceKind::UnknownSupport | SourceKind::UnknownState => SCAN_NAMES_MAX,
                    _ => 1,
                },
            "source count",
        )?;
        if let EntryStatus::Exported { ref member, .. } = entry.status {
            require(members.insert(member.clone()), "duplicate member")?;
        }
        entries.push(entry);
    }
    let [snapshot, config, _, _, _, support_summary, state_summary] = counts;
    require(snapshot == 1 && config == 1, "required sources")?;
    require(
        (support_summary == 1, state_summary == 1) == (support_truncated, state_truncated),
        "inventory flags",
    )?;
    Ok(SupportManifest {
        exported_at,
        incarnation,
        expected_incarnation,
        sampled_at,
        age,
        support_truncated,
        state_truncated,
        entries,
    })
}
/// Complete uncompressed archive. Map keys sort by raw member bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportArchive {
    pub manifest: SupportManifest,
    pub members: BTreeMap<Vec<u8>, Vec<u8>>,
}
impl SupportArchive {
    /// Encode an exact manifest/member agreement, within the whole archive cap.
    /// # Errors
    /// Refuses mismatched members, hashes or excessive sizes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let manifest = self.manifest.encode()?;
        let size = self
            .members
            .iter()
            .try_fold(manifest.len() + 6 + 50, |size, (name, bytes)| {
                size.checked_add(5)?
                    .checked_add(name.len())?
                    .checked_add(bytes.len())
            })
            .ok_or(SupportError("support size bound"))?;
        require(size <= ARCHIVE_MAX, "support size bound")?;
        seal(ARCHIVE_KIND, ARCHIVE_MAX, |t| {
            archive_fields(t, Some((self, &manifest)))?;
            Ok(())
        })
    }
    /// Verify exact archive, manifest and member bytes before decoding.
    /// # Errors
    /// Refuses noncanonical framing, extra/missing members and digest mismatches.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut t = open(bytes, ARCHIVE_KIND, ARCHIVE_MAX)?;
        let value = archive_fields(&mut t, None)?;
        t.end()?;
        Ok(value)
    }
}
fn archive_fields(t: &mut Tape<'_>, s: Option<(&SupportArchive, &[u8])>) -> Result<SupportArchive> {
    let length = usize::try_from(t.u32(s.map_or(0, |(_, bytes)| {
        u32::try_from(bytes.len()).unwrap_or(u32::MAX)
    }))?)
    .map_err(|_| SupportError("support size bound"))?;
    let bytes = t.blob(s.map_or(&[], |(_, bytes)| bytes), length, MANIFEST_MAX)?;
    let manifest = SupportManifest::decode(&bytes)?;
    let expected: BTreeMap<_, _> = manifest
        .entries
        .iter()
        .filter_map(|e| match &e.status {
            EntryStatus::Exported {
                member,
                length,
                digest,
            } => Some((member.clone(), (*length, *digest, e.kind.cap()))),
            EntryStatus::Refused(_) => None,
        })
        .collect();
    let count = t.count(s.map_or(0, |(a, _)| a.members.len()), 66, false)?;
    require(count == expected.len(), "archive member count")?;
    let mut seeds = s.into_iter().flat_map(|(a, _)| &a.members);
    let mut members = BTreeMap::new();
    for _ in 0..count {
        let seed = seeds.next();
        let name = t.export_name(seed.map_or(&[], |(name, _)| name.as_slice()))?;
        require(
            members
                .last_key_value()
                .is_none_or(|(last, _)| last < &name),
            "archive member order",
        )?;
        let (expected_len, digest, cap) = expected
            .get(&name)
            .ok_or(SupportError("archive extra member"))?;
        let length = t.u32(seed.map_or(0, |(_, b)| u32::try_from(b.len()).unwrap_or(u32::MAX)))?;
        require(length == *expected_len, "archive member length")?;
        let bytes = t.blob(
            seed.map_or(&[], |(_, b)| b.as_slice()),
            usize::try_from(length).map_err(|_| SupportError("member length"))?,
            *cap,
        )?;
        require(
            GrainId::of(&bytes).digest() == digest,
            "archive member checksum",
        )?;
        members.insert(name, bytes);
    }
    Ok(SupportArchive { manifest, members })
}
/// Secret-free descriptor and validated log-envelope projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportLogMetadata {
    pub volume: VolumeName,
    pub envelope_version: u16,
    pub epoch: Epoch,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub permissions: u32,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
}
impl SupportLogMetadata {
    /// Encode the fixed projection fields, without raw log bytes.
    /// # Errors
    /// Invalid versions, permission bits or timestamps.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut t = Tape {
            input: None,
            output: Vec::new(),
        };
        metadata_fields(&mut t, Some(self))?;
        Ok(t.output)
    }
    /// Decode one complete projection.
    /// # Errors
    /// Invalid fields, excessive size or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        require(bytes.len() <= LOG_METADATA_MAX, "support size bound")?;
        let mut t = Tape {
            input: Some(bytes),
            output: Vec::new(),
        };
        let value = metadata_fields(&mut t, None)?;
        t.end()?;
        Ok(value)
    }
}
fn metadata_fields(t: &mut Tape<'_>, s: Option<&SupportLogMetadata>) -> Result<SupportLogMetadata> {
    let volume = t.name(s.map(|s| &s.volume))?;
    let envelope_version = t.u16(s.map_or(0, |s| s.envelope_version))?;
    require(envelope_version == 1, "log envelope version")?;
    let epoch = Epoch::from_bytes(t.fixed(s.map_or([0; 16], |s| s.epoch.to_bytes()))?);
    let size = t.u64(s.map_or(0, |s| s.size))?;
    let uid = t.u32(s.map_or(0, |s| s.uid))?;
    let gid = t.u32(s.map_or(0, |s| s.gid))?;
    let permissions = t.u32(s.map_or(0, |s| s.permissions))?;
    require(permissions <= 4095, "log permissions")?;
    let zero = Timestamp { secs: 0, nanos: 0 };
    let mtime = t.time(s.map_or(zero, |s| s.mtime))?;
    let ctime = t.time(s.map_or(zero, |s| s.ctime))?;
    Ok(SupportLogMetadata {
        volume,
        envelope_version,
        epoch,
        size,
        uid,
        gid,
        permissions,
        mtime,
        ctime,
    })
}
#[cfg(test)]
mod tests;
