// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline source policy. Only the support pair shares a flock; log reads
//! inspect a bounded envelope, never authority history or a serving guard.
use crate::protected_dir::{
    DirOps, FileRuleBroken, NixOps, ProtectedDir, Stat, is_link_refusal, judge_file,
};
use granary_core::{
    authlog::{self, Classified},
    clock::Clock,
    debug_grant::Incarnation,
    hash::GrainId,
    root::VolumeName,
    sheaf::Timestamp,
    support::{
        self, EntryStatus, ExportEntry, ExportRefusal, SnapshotAge, SourceKind, SupportArchive,
        SupportConfiguration, SupportLogMetadata, SupportManifest, SupportSnapshot,
    },
};
use nix::{fcntl::OFlag, sys::stat::Mode};
use std::{collections::BTreeMap, fs::File, io, path::Path};

/// Failure before publication, or uncertainty after a complete artifact links.
#[derive(Debug)]
pub enum SupportExportError {
    /// A protected walk or filesystem operation failed.
    Io(io::Error),
    /// A source violated a fixed policy rule.
    Refused(&'static str),
    /// A required file failed; no partial archive was produced.
    Required {
        source: &'static str,
        reason: ExportRefusal,
    },
    /// The final name exists; its bytes are complete but durability is uncertain.
    PublicationUncertain(io::Error),
}
impl std::fmt::Display for SupportExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "support export I/O: {e}"),
            Self::Refused(s) => f.write_str(s),
            Self::Required { source, reason } => write!(f, "required {source}: {reason}"),
            Self::PublicationUncertain(e) => {
                write!(f, "support archive publication uncertain: {e}")
            }
        }
    }
}
impl std::error::Error for SupportExportError {}
impl From<io::Error> for SupportExportError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<support::SupportError> for SupportExportError {
    fn from(e: support::SupportError) -> Self {
        Self::Refused(e.0)
    }
}

/// Source paths and the optional operator expectation. No ambient config reads.
#[derive(Debug, Clone, Copy)]
pub struct SupportExportRequest<'a> {
    pub support_dir: &'a Path,
    pub state_dir: &'a Path,
    pub expected_incarnation: Option<Incarnation>,
    pub accept_unsupported_filesystem: bool,
}
/// Construct a bounded archive from held protected source directories.
/// # Errors
/// Refuses unsafe roots, invalid required files or mismatched incarnations/inventories.
pub fn read_support_export(
    request: SupportExportRequest<'_>,
    clock: &dyn Clock,
) -> Result<Vec<u8>, SupportExportError> {
    collect(&NixOps, request, clock).map(|(bytes, _, _)| bytes)
}
/// Read and publish a new private archive outside both source directories.
/// # Errors
/// Source refusals, unsafe output parent, existing destination, I/O or post-link uncertainty.
pub fn publish_support_export(
    request: SupportExportRequest<'_>,
    out: &Path,
    clock: &dyn Clock,
) -> Result<(), SupportExportError> {
    let (bytes, support, state) = collect(&NixOps, request, clock)?;
    super::publish::publish(
        &NixOps,
        &super::publish::PathLinks,
        request,
        out,
        &support,
        &state,
        &bytes,
    )
}
fn walk(ops: &impl DirOps, path: &Path, ack: bool) -> Result<ProtectedDir, SupportExportError> {
    ProtectedDir::for_verb(ops, path, ack).map_err(|e| SupportExportError::Io(io::Error::other(e)))
}
fn collect(
    ops: &impl DirOps,
    request: SupportExportRequest<'_>,
    clock: &dyn Clock,
) -> Result<(Vec<u8>, ProtectedDir, ProtectedDir), SupportExportError> {
    let support = walk(
        ops,
        request.support_dir,
        request.accept_unsupported_filesystem,
    )?;
    let state = walk(
        ops,
        request.state_dir,
        request.accept_unsupported_filesystem,
    )?;
    let lock = ops.lock(&support.dir)?;
    let required = |name, cap| {
        read_required(ops, &support, name, cap).map_err(|reason| SupportExportError::Required {
            source: name,
            reason,
        })
    };
    let snapshot_bytes = required("SUPPORT-SNAPSHOT", support::SNAPSHOT_MAX)?;
    let configuration_bytes = required("SUPPORT-CONFIGURATION", support::CONFIGURATION_MAX)?;
    let snapshot =
        SupportSnapshot::decode(&snapshot_bytes).map_err(|_| SupportExportError::Required {
            source: "SUPPORT-SNAPSHOT",
            reason: ExportRefusal::Corrupt,
        })?;
    let configuration = SupportConfiguration::decode(&configuration_bytes).map_err(|_| {
        SupportExportError::Required {
            source: "SUPPORT-CONFIGURATION",
            reason: ExportRefusal::Corrupt,
        }
    })?;
    validate_pair(&snapshot, &configuration, request.expected_incarnation)?;
    drop(lock);
    let exported_at = clock.now();
    let age = SnapshotAge::between(exported_at, snapshot.sampled_at)?;
    let mut members = BTreeMap::new();
    let mut entries = vec![
        exported(
            SourceKind::Snapshot,
            b"SUPPORT-SNAPSHOT",
            b"snapshot.bin",
            snapshot_bytes,
            &mut members,
        )?,
        exported(
            SourceKind::Configuration,
            b"SUPPORT-CONFIGURATION",
            b"configuration.bin",
            configuration_bytes,
            &mut members,
        )?,
    ];
    for volume in configuration.volumes.keys() {
        let id = volume.as_str().as_bytes();
        match read_log(ops, &state, volume) {
            Ok(bytes) => entries.push(exported(
                SourceKind::Log,
                id,
                format!("{}.logmeta", volume.as_str()).as_bytes(),
                bytes,
                &mut members,
            )?),
            Err(reason) => entries.push(refused(SourceKind::Log, id.to_vec(), reason)),
        }
    }
    let support_truncated = scan(
        &support,
        SourceKind::UnknownSupport,
        &configuration,
        &mut entries,
    )?;
    let state_truncated = scan(
        &state,
        SourceKind::UnknownState,
        &configuration,
        &mut entries,
    )?;
    entries.sort_by(|a, b| (a.kind.tag(), &a.id).cmp(&(b.kind.tag(), &b.id)));
    let manifest = SupportManifest {
        exported_at,
        incarnation: snapshot.incarnation,
        expected_incarnation: request.expected_incarnation,
        sampled_at: snapshot.sampled_at,
        age,
        support_truncated,
        state_truncated,
        entries,
    };
    Ok((
        SupportArchive { manifest, members }.encode()?,
        support,
        state,
    ))
}
fn validate_pair(
    snapshot: &SupportSnapshot,
    config: &SupportConfiguration,
    expected: Option<Incarnation>,
) -> Result<(), SupportExportError> {
    if snapshot.incarnation != config.incarnation {
        return Err(SupportExportError::Refused(
            "support incarnation disagreement",
        ));
    }
    if expected.is_some_and(|i| i != snapshot.incarnation || i != config.incarnation) {
        return Err(SupportExportError::Refused(
            "support expected incarnation mismatch",
        ));
    }
    if !snapshot.volumes.keys().eq(config.volumes.keys()) {
        return Err(SupportExportError::Refused(
            "support inventory disagreement",
        ));
    }
    Ok(())
}
fn file_rule(stat: &Stat, owner: u32) -> Result<(), ExportRefusal> {
    // No-follow metadata sees a planted link before the open. The post-open
    // descriptor check still matters when a regular source is swapped.
    if stat.mode & 0o170_000 == 0o120_000 {
        return Err(ExportRefusal::Symlink);
    }
    judge_file(stat, owner).map_err(|r| match r {
        FileRuleBroken::Link => ExportRefusal::Symlink,
        FileRuleBroken::NotRegular { .. } => ExportRefusal::NonRegular,
        _ => ExportRefusal::Unprotected,
    })
}
fn io_reason(e: &io::Error) -> ExportRefusal {
    if e.kind() == io::ErrorKind::NotFound {
        ExportRefusal::Missing
    } else if is_link_refusal(e) {
        ExportRefusal::Symlink
    } else {
        ExportRefusal::Unreadable
    }
}
fn open_source(
    ops: &impl DirOps,
    root: &ProtectedDir,
    name: &str,
) -> Result<(File, Stat), ExportRefusal> {
    let named = ops.stat_at(&root.dir, name).map_err(|e| io_reason(&e))?;
    file_rule(&named, root.owner())?;
    let file = ops
        .open_read_at(&root.dir, name)
        .map_err(|e| io_reason(&e))?;
    let before = ops.fstat(&file).map_err(|e| io_reason(&e))?;
    file_rule(&before, root.owner())?;
    if named != before {
        return Err(ExportRefusal::ChangedDuringRead);
    }
    Ok((file, before))
}
fn recheck(
    ops: &impl DirOps,
    root: &ProtectedDir,
    name: &str,
    file: &File,
    before: &Stat,
) -> Result<(), ExportRefusal> {
    let after = ops.fstat(file).map_err(|e| io_reason(&e))?;
    let named = ops.stat_at(&root.dir, name).map_err(|e| io_reason(&e))?;
    if before != &after || after != named {
        return Err(ExportRefusal::ChangedDuringRead);
    }
    Ok(())
}
fn read_required(
    ops: &impl DirOps,
    root: &ProtectedDir,
    name: &str,
    cap: usize,
) -> Result<Vec<u8>, ExportRefusal> {
    let (file, before) = open_source(ops, root, name)?;
    let size = usize::try_from(before.size).map_err(|_| ExportRefusal::Oversize)?;
    // Size is checked before allocation or any content read. A separate
    // cap-plus-one bound catches growth beyond the fstat size, even if the
    // writer stops at EOF before our descriptor recheck.
    if size > cap {
        return Err(ExportRefusal::Oversize);
    }
    let mut bytes = Vec::with_capacity(size);
    let mut buffer = [0_u8; 8192];
    while bytes.len() <= cap {
        let remaining = cap
            .saturating_add(1)
            .saturating_sub(bytes.len())
            .min(buffer.len());
        let chunk = buffer.get_mut(..remaining).ok_or(ExportRefusal::Oversize)?;
        let n = ops
            .read_at(
                &file,
                chunk,
                u64::try_from(bytes.len()).map_err(|_| ExportRefusal::Oversize)?,
            )
            .map_err(|e| io_reason(&e))?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(chunk.get(..n).ok_or(ExportRefusal::Unreadable)?);
    }
    if bytes.len() > cap {
        return Err(ExportRefusal::Oversize);
    }
    if bytes.len() != size {
        return Err(ExportRefusal::ChangedDuringRead);
    }
    recheck(ops, root, name, &file, &before)?;
    Ok(bytes)
}
fn read_exact_at(
    ops: &impl DirOps,
    file: &File,
    bytes: &mut [u8],
    offset: usize,
) -> Result<(), ExportRefusal> {
    let mut consumed = 0;
    while consumed < bytes.len() {
        let position = offset
            .checked_add(consumed)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(ExportRefusal::Corrupt)?;
        let chunk = bytes.get_mut(consumed..).ok_or(ExportRefusal::Corrupt)?;
        let n = ops
            .read_at(file, chunk, position)
            .map_err(|e| io_reason(&e))?;
        if n == 0 || n > chunk.len() {
            return Err(ExportRefusal::Corrupt);
        }
        consumed += n;
    }
    Ok(())
}
fn read_log(
    ops: &impl DirOps,
    root: &ProtectedDir,
    volume: &VolumeName,
) -> Result<Vec<u8>, ExportRefusal> {
    let name = format!("{}.log", volume.as_str());
    let (file, before) = open_source(ops, root, &name)?;
    let size = u64::try_from(before.size).map_err(|_| ExportRefusal::Corrupt)?;
    let mut header = [0_u8; 12];
    read_exact_at(ops, &file, &mut header, 0)?;
    let length = u16::from_be_bytes(
        header
            .get(10..12)
            .ok_or(ExportRefusal::Corrupt)?
            .try_into()
            .map_err(|_| ExportRefusal::Corrupt)?,
    );
    if length > 4096 {
        return Err(ExportRefusal::OversizeEnvelope);
    }
    if length < 44 || u64::from(length) > size {
        return Err(ExportRefusal::Corrupt);
    }
    if header.get(..8) != Some(authlog::ENVELOPE_MAGIC.as_slice()) {
        return Err(ExportRefusal::Corrupt);
    }
    let mut bytes = vec![0; usize::from(length)];
    let (start, rest) = bytes
        .split_at_mut_checked(12)
        .ok_or(ExportRefusal::Corrupt)?;
    start.copy_from_slice(&header);
    read_exact_at(ops, &file, rest, 12)?;
    // Classification receives exactly the envelope, never append bytes.
    let envelope = match authlog::classify(&bytes, volume) {
        Ok(Classified::Log {
            envelope,
            committed_len,
            tail_len: 0,
            ..
        }) if committed_len == bytes.len() => envelope,
        _ => return Err(ExportRefusal::Corrupt),
    };
    recheck(ops, root, &name, &file, &before)?;
    let timestamp = |(secs, nanos)| -> Result<Timestamp, ExportRefusal> {
        let t = Timestamp {
            secs,
            nanos: u32::try_from(nanos).map_err(|_| ExportRefusal::Corrupt)?,
        };
        if t.is_valid() {
            Ok(t)
        } else {
            Err(ExportRefusal::Corrupt)
        }
    };
    SupportLogMetadata {
        volume: envelope.volume().clone(),
        envelope_version: envelope.version(),
        epoch: envelope.epoch(),
        size,
        uid: before.uid,
        gid: before.gid,
        permissions: before.perms(),
        mtime: timestamp(before.mtime)?,
        ctime: timestamp(before.ctime)?,
    }
    .encode()
    .map_err(|_| ExportRefusal::Corrupt)
}
fn exported(
    kind: SourceKind,
    id: &[u8],
    member: &[u8],
    bytes: Vec<u8>,
    members: &mut BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<ExportEntry, SupportExportError> {
    let length =
        u32::try_from(bytes.len()).map_err(|_| SupportExportError::Refused("member length"))?;
    let digest = *GrainId::of(&bytes).digest();
    let entry = ExportEntry {
        kind,
        id: id.to_vec(),
        projection_version: 1,
        cap: u32::try_from(kind.cap())
            .map_err(|_| SupportExportError::Refused("projection cap"))?,
        status: EntryStatus::Exported {
            member: member.to_vec(),
            length,
            digest,
        },
    };
    members.insert(member.to_vec(), bytes);
    Ok(entry)
}
fn refused(kind: SourceKind, id: Vec<u8>, reason: ExportRefusal) -> ExportEntry {
    ExportEntry {
        kind,
        id,
        projection_version: 1,
        cap: u32::try_from(kind.cap()).unwrap_or(u32::MAX),
        status: EntryStatus::Refused(reason),
    }
}
fn scan(
    root: &ProtectedDir,
    kind: SourceKind,
    config: &SupportConfiguration,
    entries: &mut Vec<ExportEntry>,
) -> Result<bool, SupportExportError> {
    let mut dir = nix::dir::Dir::openat(
        &root.dir,
        ".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let mut examined = 0;
    for entry in dir.iter() {
        let entry = entry.map_err(io::Error::from)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if examined == support::SCAN_NAMES_MAX {
            let summary = if kind == SourceKind::UnknownSupport {
                SourceKind::SupportSummary
            } else {
                SourceKind::StateSummary
            };
            entries.push(refused(
                summary,
                b"inventory".to_vec(),
                ExportRefusal::ScanLimit,
            ));
            return Ok(true);
        }
        let known = if kind == SourceKind::UnknownSupport {
            [b"SUPPORT-SNAPSHOT".as_slice(), b"SUPPORT-CONFIGURATION"].contains(&name)
        } else {
            config
                .volumes
                .keys()
                .any(|volume| name.strip_suffix(b".log") == Some(volume.as_str().as_bytes()))
        };
        if !known {
            entries.push(refused(
                kind,
                format!("unknown-{examined:04}").into_bytes(),
                ExportRefusal::NotAllowlisted,
            ));
        }
        examined += 1;
    }
    Ok(false)
}
#[cfg(test)]
mod tests;
