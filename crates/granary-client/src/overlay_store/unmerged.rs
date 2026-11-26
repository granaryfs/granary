// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Read-only custody and classification of permanent residual exports.

use super::{
    OverlayDisk, OverlayError, OverlayIo, Record, codec,
    io::{UnmergedEntry, UnmergedInventory},
};
use nix::dir::Dir;
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{FileStat, Mode, SFlag, fstat, fstatat};
use nix::unistd::geteuid;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read as _};
use std::os::fd::AsFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::time::Duration;

const CUSTODY_DEADLINE: Duration = Duration::from_secs(30);
pub(super) const UNMERGED_ENTRY_MAX: usize = 4_096;

#[cfg(test)]
std::thread_local! {
    static SWAP_AFTER_READ: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static GROW_AFTER_READ: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static MAX_READ: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static EXPIRE_AFTER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(super) fn swap_after_read_for_test(enabled: bool) {
    SWAP_AFTER_READ.set(enabled);
}

#[cfg(test)]
pub(super) fn grow_after_read_for_test(enabled: bool) {
    GROW_AFTER_READ.set(enabled);
}

#[cfg(test)]
pub(super) fn reset_max_read_for_test() {
    MAX_READ.set(0);
}

#[cfg(test)]
pub(super) fn max_read_for_test() -> usize {
    MAX_READ.get()
}

#[cfg(test)]
pub(super) fn expire_after_for_test(calls: Option<usize>) {
    EXPIRE_AFTER.set(calls);
}

#[cfg(test)]
fn forced_deadline_expired() -> bool {
    EXPIRE_AFTER.with(|calls| match calls.get() {
        Some(0) => {
            calls.set(None);
            true
        }
        Some(left) => {
            calls.set(Some(left - 1));
            false
        }
        None => false,
    })
}

#[cfg(not(test))]
const fn forced_deadline_expired() -> bool {
    false
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "replace one test-owned leaf between descriptor read and name recheck"
)]
fn swap_after_read(shown: &Path) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    if SWAP_AFTER_READ.replace(false) {
        let replacement = shown.with_extension("replacement");
        let held = shown.with_extension("held");
        std::fs::write(&replacement, b"replacement")?;
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(shown, held)?;
        return std::fs::rename(replacement, shown);
    }
    if GROW_AFTER_READ.replace(false) {
        std::fs::OpenOptions::new()
            .append(true)
            .open(shown)?
            .write_all(b"growth")?;
    }
    Ok(())
}

fn io_error(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn identity(
    stat: &FileStat,
) -> (
    libc::dev_t,
    libc::ino_t,
    libc::mode_t,
    libc::uid_t,
    libc::nlink_t,
) {
    (
        stat.st_dev,
        stat.st_ino,
        stat.st_mode,
        stat.st_uid,
        stat.st_nlink,
    )
}

fn check_directory(dir: &Dir, path: &Path, euid: u32) -> io::Result<FileStat> {
    let stat = fstat(dir).map_err(io_error)?;
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR
        || stat.st_uid != euid
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(io::Error::other("unmerged directory custody refused"));
    }
    crate::custody::refuse_granting_directory_acl_on_fd(
        dir.as_fd(),
        path,
        "overlay unmerged directory",
    )
    .map_err(|_| io::Error::other("unmerged directory custody refused"))?;
    Ok(stat)
}

fn open_directory(parent: &Dir, name: &CStr, path: &Path, euid: u32) -> io::Result<Dir> {
    let fd = openat(
        parent,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io_error)?;
    let dir = Dir::from_fd(fd).map_err(io_error)?;
    check_directory(&dir, path, euid)?;
    Ok(dir)
}

fn component(name: &OsString) -> io::Result<CString> {
    CString::new(name.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("unmerged path component refused"))
}

fn open_leaf(dir: &Dir, name: &CStr, shown: &Path, euid: u32) -> io::Result<(File, FileStat)> {
    let named = fstatat(dir, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(io_error)?;
    let fd = openat(
        dir,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io_error)?;
    let before = fstat(&fd).map_err(io_error)?;
    if identity(&before) != identity(&named)
        || SFlag::from_bits_truncate(before.st_mode) != SFlag::S_IFREG
        || before.st_uid != euid
        || before.st_mode & 0o777 != 0o600
        || !(1..=2).contains(&before.st_nlink)
    {
        return Err(io::Error::other("unmerged leaf custody refused"));
    }
    crate::custody::refuse_granting_acl_on_fd(fd.as_fd(), shown, "overlay unmerged file")
        .map_err(|_| io::Error::other("unmerged leaf custody refused"))?;
    Ok((File::from(fd), before))
}

fn recheck_leaf(dir: &Dir, name: &CStr, file: &File, before: &FileStat) -> io::Result<()> {
    let after = fstat(file).map_err(io_error)?;
    let rebound = fstatat(dir, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(io_error)?;
    if identity(before) != identity(&after)
        || identity(before) != identity(&rebound)
        || before.st_size != after.st_size
    {
        return Err(io::Error::other("unmerged leaf changed during read"));
    }
    Ok(())
}

fn read_leaf(
    file: &mut File,
    buffer: &mut [u8],
    keep: usize,
    descriptor: Option<&codec::ResidualFile>,
    limit: u64,
    mut expired: impl FnMut() -> bool,
) -> io::Result<(Vec<u8>, u64, Option<[u8; 32]>)> {
    let mut kept = Vec::new();
    let mut total = 0_u64;
    let mut hash =
        descriptor.map(|file| codec::ResidualPayloadHasher::new(file.stage_id, file.local_size));
    loop {
        if expired() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "unmerged custody deadline",
            ));
        }
        let count = file.read(buffer)?;
        #[cfg(test)]
        MAX_READ.set(MAX_READ.get().max(count));
        if count == 0 {
            break;
        }
        let before = total;
        total = total
            .checked_add(count as u64)
            .filter(|length| *length <= limit)
            .ok_or_else(|| io::Error::other("unmerged capacity refused"))?;
        let wanted = keep.saturating_sub(kept.len()).min(count);
        kept.extend_from_slice(buffer.get(..wanted).unwrap_or(&[]));
        if let Some(hash) = &mut hash {
            let payload_start =
                usize::try_from((codec::STAGING_HEADER_LEN as u64).saturating_sub(before))
                    .map_or(usize::MAX, |start| start.min(count));
            if let Some(payload) = buffer.get(payload_start..count) {
                hash.update(payload);
            }
        }
    }
    Ok((kept, total, hash.map(|hash| hash.finalize())))
}

fn deadline_expired(elapsed: Option<Duration>) -> bool {
    elapsed.is_some_and(|elapsed| elapsed > CUSTODY_DEADLINE)
}

#[cfg(test)]
pub(super) fn deadline_expired_for_test(elapsed: Option<Duration>) -> bool {
    deadline_expired(elapsed)
}

#[expect(
    clippy::too_many_lines,
    reason = "descriptor custody keeps the held directory and leaf sequence visible in one function"
)]
pub(super) fn disk_inventory(
    disk: &OverlayDisk,
    area: &Path,
    cap: u64,
) -> io::Result<UnmergedInventory> {
    use crate::sync::{InstantClock, MonotonicClock as _};

    let (root, configured_euid) = disk.custody_root();
    let euid = geteuid().as_raw();
    if configured_euid != euid {
        return Err(io::Error::other("unmerged effective uid refused"));
    }
    let relative = area
        .strip_prefix(root)
        .map_err(|_| io::Error::other("unmerged area binding refused"))?;
    let components: Vec<OsString> = relative
        .components()
        .map(|part| match part {
            std::path::Component::Normal(name) => Ok(name.to_owned()),
            _ => Err(io::Error::other("unmerged path component refused")),
        })
        .collect::<io::Result<_>>()?;
    let [overlay_name, scope_name, volume_name] = components.as_slice() else {
        return Err(io::Error::other("unmerged area shape refused"));
    };
    let root_dir = Dir::open(
        root,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io_error)?;
    check_directory(&root_dir, root, euid)?;
    let overlay_name = component(overlay_name)?;
    let scope_name = component(scope_name)?;
    let volume_name = component(volume_name)?;
    let overlay_path = root.join(OsStr::from_bytes(overlay_name.to_bytes()));
    let overlay = open_directory(&root_dir, &overlay_name, &overlay_path, euid)?;
    let scope_path = overlay_path.join(OsStr::from_bytes(scope_name.to_bytes()));
    let scope = open_directory(&overlay, &scope_name, &scope_path, euid)?;
    let area_dir = open_directory(&scope, &volume_name, area, euid)?;
    let staging_path = area.join("staging");
    let staging = open_directory(&area_dir, c"staging", &staging_path, euid)?;
    let unmerged_path = area.join("unmerged");
    let mut unmerged = match open_directory(&area_dir, c"unmerged", &unmerged_path, euid) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(UnmergedInventory {
                present: false,
                entries: Vec::new(),
            });
        }
        Err(error) => return Err(error),
    };
    let listed = check_directory(&unmerged, &unmerged_path, euid)?;
    let clock = InstantClock::default();
    let started = clock.start();
    let expired = || {
        deadline_expired(started.as_ref().and_then(|start| clock.elapsed(start)))
            || forced_deadline_expired()
    };
    let mut names = Vec::new();
    for entry in unmerged.iter() {
        if expired() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "unmerged custody deadline",
            ));
        }
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        if names.len() == UNMERGED_ENTRY_MAX {
            return Err(io::Error::other("unmerged capacity refused"));
        }
        names.push(
            name.to_str()
                .map_err(|_| io::Error::other("unmerged foreign name refused"))?
                .to_owned(),
        );
    }
    if identity(&listed) != identity(&fstat(&unmerged).map_err(io_error)?) {
        return Err(io::Error::other(
            "unmerged directory changed during listing",
        ));
    }
    names.sort_unstable();
    let mut total = 0_u64;
    #[expect(
        clippy::large_stack_arrays,
        reason = "one fixed shared buffer bounds every held-descriptor read"
    )]
    let mut buffer = [0_u8; super::BUFFER];
    let mut inventory = BTreeMap::new();
    let mut descriptors = BTreeMap::new();
    for name in names.iter().filter(|name| name.contains(".path")) {
        let c_name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::other("unmerged foreign name refused"))?;
        let (mut file, stat) = open_leaf(&unmerged, &c_name, &unmerged_path.join(name), euid)?;
        let (bytes, length, _) = read_leaf(
            &mut file,
            &mut buffer,
            codec::UNMERGED_PATH_MAX.saturating_add(1),
            None,
            cap.saturating_sub(total),
            expired,
        )?;
        #[cfg(test)]
        swap_after_read(&unmerged_path.join(name))?;
        recheck_leaf(&unmerged, &c_name, &file, &stat)?;
        if stat.st_nlink != 1 {
            return Err(io::Error::other("unmerged listing custody refused"));
        }
        total = total
            .checked_add(length)
            .ok_or_else(|| io::Error::other("unmerged capacity refused"))?;
        if let (Some((id, _)), Ok(path)) = (entry_name(name), codec::UnmergedPath::decode(&bytes))
            && id == path.file.stage_id
        {
            descriptors.entry(id).or_insert(path.file);
        }
        inventory.insert(
            name.clone(),
            UnmergedEntry {
                name: name.clone(),
                prefix: bytes,
                length,
                links: link_count(stat.st_nlink),
                payload_check: None,
            },
        );
    }
    for name in names.iter().filter(|name| !name.contains(".path")) {
        let c_name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::other("unmerged foreign name refused"))?;
        let (mut file, stat) = open_leaf(&unmerged, &c_name, &unmerged_path.join(name), euid)?;
        if stat.st_nlink == 2 {
            let stage = fstatat(&staging, c_name.as_c_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(io_error)?;
            if identity(&stage) != identity(&stat) {
                return Err(io::Error::other("unmerged pair custody refused"));
            }
        }
        let descriptor = entry_name(name).and_then(|(id, _)| descriptors.get(&id));
        let (header, length, check) = read_leaf(
            &mut file,
            &mut buffer,
            codec::STAGING_HEADER_LEN,
            descriptor,
            cap.saturating_sub(total),
            expired,
        )?;
        #[cfg(test)]
        swap_after_read(&unmerged_path.join(name))?;
        recheck_leaf(&unmerged, &c_name, &file, &stat)?;
        total = total
            .checked_add(length)
            .ok_or_else(|| io::Error::other("unmerged capacity refused"))?;
        inventory.insert(
            name.clone(),
            UnmergedEntry {
                name: name.clone(),
                prefix: header,
                length,
                links: link_count(stat.st_nlink),
                payload_check: check,
            },
        );
    }
    Ok(UnmergedInventory {
        present: true,
        entries: inventory.into_values().collect(),
    })
}

struct JournalFacts {
    scan: codec::JournalScan,
    boundaries: BTreeMap<u64, [u8; 16]>,
    latest_landing: Option<(u64, granary_core::hash::GrainId, u64)>,
    named: BTreeSet<u64>,
}

fn journal_facts(bytes: &[u8]) -> Result<JournalFacts, OverlayError> {
    let mut boundaries = BTreeMap::new();
    let mut latest_landing = None;
    let mut named = BTreeSet::new();
    let scan = codec::scan_journal_with(bytes, |seq, record| {
        match record {
            Record::CommitBoundary { publication_id, .. }
            | Record::ProjectedBoundary { publication_id, .. } => {
                boundaries.insert(seq, *publication_id);
            }
            Record::LandedCommit {
                boundary_seq,
                landed_root,
                landed_seq,
            } => latest_landing = Some((*boundary_seq, *landed_root, *landed_seq)),
            Record::RecreateFile { stage_id, .. } => {
                named.insert(*stage_id);
            }
            _ => {}
        }
        if let Some(id) = super::replacement::reference(record) {
            named.insert(id);
        }
    })
    .map_err(|_| OverlayError::refused("journal fenced"))?;
    Ok(JournalFacts {
        scan,
        boundaries,
        latest_landing,
        named,
    })
}

fn raw_terminal_matches(
    bytes: &[u8],
    facts: &JournalFacts,
    record: &codec::ResidualDisposition,
) -> bool {
    let Some(tail) = bytes.get(facts.scan.valid_len..) else {
        return false;
    };
    let Some((length, body)) = tail.split_first_chunk::<4>() else {
        return false;
    };
    let Some((&kind, body)) = body.split_first() else {
        return false;
    };
    let Some((seq, payload_and_check)) = body.split_first_chunk::<8>() else {
        return false;
    };
    let Ok(payload) = Record::ResidualDisposition(*record).encode_payload() else {
        return false;
    };
    u32::from_be_bytes(*length)
        == codec::LEN_MIN.saturating_add(u32::try_from(payload.len()).unwrap_or(u32::MAX))
        && kind == 17
        && u64::from_be_bytes(*seq) == record.source_end.saturating_add(1)
        && payload_and_check.get(..payload.len()) == Some(payload.as_slice())
}

fn current_record(
    bytes: &[u8],
    facts: &JournalFacts,
    writer: &[u8; 16],
    record: &codec::ResidualDisposition,
) -> bool {
    if &facts.scan.header.writer != writer || record.landed_seq <= facts.scan.header.base_seq {
        return false;
    }
    if facts.scan.state.residual_disposition() == Some(record) {
        return true;
    }
    if record.source_end.checked_add(1) != Some(facts.scan.state.next_seq())
        || !raw_terminal_matches(bytes, facts, record)
    {
        return false;
    }
    let mut state = facts.scan.state.clone();
    state.admit(&Record::ResidualDisposition(*record)).is_ok()
}

fn hostable_torn_disposition(bytes: &[u8], facts: &JournalFacts) -> bool {
    if facts.scan.end == codec::JournalEnd::Clean
        || facts.scan.state.residual_disposition().is_some()
    {
        return false;
    }
    let Some((boundary_seq, landed_root, landed_seq)) = facts.latest_landing else {
        return false;
    };
    let Some(publication_id) = facts.boundaries.get(&boundary_seq).copied() else {
        return false;
    };
    let source_end = facts.scan.state.next_seq().saturating_sub(1);
    let choice = codec::ResidualDisposition {
        boundary_seq,
        publication_id,
        landed_root,
        landed_seq,
        source_end,
        disposition: codec::ResidualMode::KeepRemote,
        collision_count: 1,
        inventory_check: [0; 32],
    };
    let mut state = facts.scan.state.clone();
    let payload_length = Record::ResidualDisposition(choice)
        .encode_payload()
        .ok()
        .and_then(|payload| u32::try_from(payload.len()).ok());
    state.admit(&Record::ResidualDisposition(choice)).is_ok()
        && payload_length.is_some_and(|payload_length| {
            raw_terminal_header(
                bytes,
                facts,
                source_end.saturating_add(1),
                codec::LEN_MIN.saturating_add(payload_length),
            )
        })
}

fn raw_terminal_header(
    bytes: &[u8],
    facts: &JournalFacts,
    expected_seq: u64,
    expected_length: u32,
) -> bool {
    let Some((length, body)) = bytes
        .get(facts.scan.valid_len..)
        .and_then(|tail| tail.split_first_chunk::<4>())
    else {
        return false;
    };
    let Some((&kind, body)) = body.split_first() else {
        return false;
    };
    let Some((seq, _)) = body.split_first_chunk::<8>() else {
        return false;
    };
    u32::from_be_bytes(*length) == expected_length
        && kind == 17
        && u64::from_be_bytes(*seq) == expected_seq
}

#[derive(Clone, Copy)]
enum NameKind {
    Payload,
    Listing,
    Temporary,
}

fn entry_name(name: &str) -> Option<(u64, NameKind)> {
    let (id, kind) = if let Some(id) = name.strip_suffix(".path.next") {
        (id, NameKind::Temporary)
    } else if let Some(id) = name.strip_suffix(".path") {
        (id, NameKind::Listing)
    } else {
        (name, NameKind::Payload)
    };
    if id.len() != 16
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    u64::from_str_radix(id, 16).ok().map(|id| (id, kind))
}

struct Listing {
    path: codec::UnmergedPath,
    bytes: Vec<u8>,
    temporary: bool,
}

pub(crate) fn validate_payload(
    header: &[u8],
    length: u64,
    check: Option<[u8; 32]>,
    listing: &codec::UnmergedPath,
) -> Result<(), OverlayError> {
    let header = header
        .get(..codec::STAGING_HEADER_LEN)
        .ok_or_else(|| OverlayError::refused("unmerged payload header"))?;
    let header = codec::StagingHeader::decode(header)
        .map_err(|_| OverlayError::refused("unmerged payload header"))?;
    header
        .check_binding(&listing.writer, listing.file.stage_id)
        .map_err(|_| OverlayError::refused("unmerged payload binding"))?;
    if length.checked_sub(codec::STAGING_HEADER_LEN as u64) != Some(listing.file.local_size) {
        return Err(OverlayError::refused("unmerged payload length"));
    }
    if check != Some(listing.file.payload_check) {
        return Err(OverlayError::refused("unmerged payload check"));
    }
    Ok(())
}

pub(super) fn inventory(
    io: &mut impl OverlayIo,
    area: &Path,
    cap: u64,
) -> Result<UnmergedInventory, OverlayError> {
    io.unmerged_inventory(area, cap).map_err(|error| {
        let reason = error.to_string();
        if error.kind() == io::ErrorKind::TimedOut {
            OverlayError::refused("unmerged custody deadline")
        } else if reason == "unmerged capacity refused" {
            OverlayError::refused("unmerged capacity")
        } else if error.raw_os_error() == Some(libc::ELOOP)
            || matches!(
                reason.as_str(),
                "unmerged directory custody refused"
                    | "unmerged leaf custody refused"
                    | "unmerged leaf changed during read"
                    | "unmerged effective uid refused"
                    | "unmerged directory changed during listing"
                    | "unmerged listing custody refused"
                    | "unmerged pair custody refused"
            )
        {
            OverlayError::refused("unmerged custody")
        } else {
            OverlayError::Io(error)
        }
    })
}

pub(super) fn lengths(raw: &UnmergedInventory) -> impl Iterator<Item = (String, u64)> + '_ {
    raw.entries
        .iter()
        .map(|entry| (entry.name.clone(), entry.length))
}

#[expect(
    clippy::too_many_lines,
    reason = "classification keeps each refusal adjacent to the custody fact it validates"
)]
pub(super) fn classify(
    raw: UnmergedInventory,
    journal: Option<&[u8]>,
) -> Result<Vec<(String, u64)>, OverlayError> {
    let lengths = raw
        .entries
        .iter()
        .map(|entry| (entry.name.clone(), entry.length))
        .collect();
    let Some(journal) = journal else {
        return Ok(lengths);
    };
    let facts = journal_facts(journal)?;
    let hostable = hostable_torn_disposition(journal, &facts);
    if raw.present && hostable {
        return Err(OverlayError::refused(
            "unmerged current disposition evidence",
        ));
    }
    if raw.entries.is_empty() {
        return Ok(lengths);
    }
    let mut payloads = BTreeMap::new();
    let mut listings = Vec::new();
    for entry in raw.entries {
        let UnmergedEntry {
            name,
            prefix: bytes,
            length,
            links,
            payload_check: check,
        } = entry;
        let (id, kind) =
            entry_name(&name).ok_or_else(|| OverlayError::refused("foreign unmerged name"))?;
        match kind {
            NameKind::Payload => {
                if payloads.insert(id, (bytes, length, links, check)).is_some() {
                    return Err(OverlayError::refused("duplicate unmerged payload"));
                }
            }
            NameKind::Listing | NameKind::Temporary => {
                let path = codec::UnmergedPath::decode(&bytes)
                    .map_err(|_| OverlayError::refused("unmerged listing"))?;
                if id != path.file.stage_id || path.writer != facts.scan.header.writer {
                    return Err(OverlayError::refused("unmerged listing binding"));
                }
                if current_record(journal, &facts, &path.writer, &path.record) {
                    return Err(OverlayError::refused(
                        "unmerged current disposition evidence",
                    ));
                }
                if path.record.landed_seq > facts.scan.header.base_seq {
                    return Err(OverlayError::refused("unmerged unresolved disposition"));
                }
                if id >= facts.scan.state.next_stage_id() {
                    return Err(OverlayError::refused("unmerged installed stage id"));
                }
                if facts.named.contains(&id) {
                    return Err(OverlayError::refused("unmerged installed binding"));
                }
                listings.push(Listing {
                    path,
                    bytes,
                    temporary: matches!(kind, NameKind::Temporary),
                });
            }
        }
    }
    for temporary in listings.iter().filter(|listing| listing.temporary) {
        let Some(final_listing) = listings.iter().find(|listing| {
            !listing.temporary && listing.path.file.stage_id == temporary.path.file.stage_id
        }) else {
            return Err(OverlayError::refused("unmerged temporary missing final"));
        };
        if final_listing.bytes != temporary.bytes {
            return Err(OverlayError::refused("unmerged temporary mismatch"));
        }
    }
    let finals: Vec<_> = listings
        .iter()
        .filter(|listing| !listing.temporary)
        .collect();
    for listing in &finals {
        let id = listing.path.file.stage_id;
        let Some((header, length, links, check)) = payloads.remove(&id) else {
            return Err(OverlayError::refused("unmerged payload missing"));
        };
        validate_payload(&header, length, check, &listing.path)?;
        let group: Vec<_> = finals
            .iter()
            .filter(|other| {
                other.path.writer == listing.path.writer && other.path.record == listing.path.record
            })
            .map(|other| other.path.file.clone())
            .collect();
        if u32::try_from(group.len()).ok() != Some(listing.path.record.collision_count)
            || codec::residual_inventory_check(&group).ok()
                != Some(listing.path.record.inventory_check)
        {
            return Err(OverlayError::refused("unmerged inventory binding"));
        }
        if links == 2 {
            return Err(OverlayError::refused("unmerged pair pending retirement"));
        }
    }
    if !payloads.is_empty() {
        return Err(OverlayError::refused("unmerged listing missing"));
    }
    Ok(lengths)
}

/// `st_nlink` widened to `u64`: `nlink_t` is `u16` on macOS, `u32` on
/// `aarch64` Linux and already `u64` on `x86_64` Linux (glibc and musl).
#[cfg_attr(
    all(target_os = "linux", target_arch = "x86_64"),
    expect(
        clippy::useless_conversion,
        reason = "`nlink_t` is already `u64` on x86_64 Linux and narrower elsewhere"
    )
)]
fn link_count(links: nix::libc::nlink_t) -> u64 {
    u64::from(links)
}
