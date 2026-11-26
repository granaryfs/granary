// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Byte inventory and local admission, independent of replay and authority access.

use super::{DURABILITY, FOREIGN, MISSING, Refusal, disk};
use granary_core::{
    hash::{GrainIdHasher, HashAlgorithm},
    overlay_discard::{InventoryEntry, parse_hex},
    overlay_journal::{self as j, JournalHeader, StagingHeader, UnmergedPath, WriterRecord},
    overlay_ownership as o,
    retained_archive::ArchiveName,
    retained_submission as p,
    root::VolumeName,
};
use nix::fcntl::OFlag;
use std::{
    ffi::OsStr,
    fs::File,
    io::Read as _,
    os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _},
};

#[derive(Default, PartialEq, Eq)]
pub(super) struct Inventory {
    pub entries: Vec<InventoryEntry>,
    pub bytes: u64,
    pub files: u64,
    identities: Vec<(u64, u64)>,
}

pub(crate) fn temporary(name: &str) -> Option<VolumeName> {
    let (volume, counter) = name.split_once(".sub.tmp-")?;
    let count = counter.parse::<u64>().ok()?;
    (count != 0 && count.to_string() == counter)
        .then(|| VolumeName::from_bytes(volume.as_bytes()).ok())
        .flatten()
}

pub(super) type Step<'a> = dyn FnMut(&str, bool) -> Result<(), Refusal> + 'a;

pub(super) fn durable<T>(
    step: &mut Step<'_>,
    label: &str,
    apply: impl FnOnce() -> Result<T, Refusal>,
) -> Result<T, Refusal> {
    step(label, false)?;
    let result = apply()?;
    step(label, true)?;
    Ok(result)
}

pub(super) fn sync(step: &mut Step<'_>, label: &str, file: &File) -> Result<(), Refusal> {
    durable(step, label, || file.sync_all().map_err(|_| DURABILITY))
}

pub(super) struct Walk<'a, 'b> {
    pub mount: u64,
    pub barriers: Option<&'a mut Step<'b>>,
}

/// Ownership is settled after readiness or a completed release, with no fence.
/// Every retained request must be terminal, answered with receipt bytes and
/// free of capture context. The carrier must still have a writable revision
/// and the writer must be able to allocate above its durable ceiling on reopen.
fn carrier_is_settled(carrier: &o::Carrier, writer: &WriterRecord) -> bool {
    carrier.fence == 0
        && matches!(carrier.phase, o::Phase::Serving | o::Phase::Released)
        && carrier.revision < u64::MAX
        && writer.ceiling < j::GENERATION_MAX
        && carrier
            .pending
            .iter()
            .all(|p| p.terminal && p.answered && !p.answer.is_empty() && p.context.is_empty())
}

impl Walk<'_, '_> {
    pub(super) fn bound_file(
        mount: u64,
        dir: &File,
        leaf: &str,
        max: usize,
        inventory: &Inventory,
    ) -> Result<Option<Vec<u8>>, disk::Error> {
        let Ok(index) = inventory
            .entries
            .binary_search_by(|(name, _)| name.as_slice().cmp(leaf.as_bytes()))
        else {
            return Ok(None);
        };
        let mut actual = Inventory::default();
        let bytes = Walk {
            mount,
            barriers: None,
        }
        .file(dir, leaf, leaf.into(), max + 1, &mut actual, None)?;
        if actual.entries.first() != inventory.entries.get(index) {
            return Err(super::CHANGED.into());
        }
        Ok(Some(bytes))
    }

    fn file(
        &mut self,
        directory: &File,
        leaf: &str,
        relative: String,
        keep: usize,
        inventory: &mut Inventory,
        pair: Option<&File>,
    ) -> Result<Vec<u8>, disk::Error> {
        let mut file = disk::at(directory, OsStr::new(leaf), OFlag::empty())
            .map_err(|error| disk::Error::open(&error, MISSING))?;
        let links = disk::protected(&file, self.mount, false)?;
        let inode = disk::identity(&file).map_err(|_| disk::Error::Io)?;
        if links != 1 {
            let other = pair.filter(|_| links == 2).ok_or(FOREIGN)?;
            let other = disk::at(other, OsStr::new(leaf), OFlag::empty())
                .map_err(|error| disk::Error::open(&error, FOREIGN))?;
            if disk::identity(&other).map_err(|_| disk::Error::Io)? != inode {
                return Err(FOREIGN.into());
            }
        }
        let listing = if links == 2 && relative.starts_with("unmerged/") {
            let name = format!("{leaf}.path");
            let file = disk::at(directory, OsStr::new(&name), OFlag::empty())
                .map_err(|error| disk::Error::open(&error, FOREIGN))?;
            if disk::protected(&file, self.mount, false)? != 1 {
                return Err(FOREIGN.into());
            }
            let mut bytes = Vec::new();
            file.take(j::UNMERGED_PATH_MAX as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| disk::Error::Io)?;
            Some(UnmergedPath::decode(&bytes).map_err(|_| FOREIGN)?)
        } else {
            None
        };
        let mut check = listing
            .as_ref()
            .map(|p| j::ResidualPayloadHasher::new(p.file.stage_id, p.file.local_size));
        let mut hasher = GrainIdHasher::new(HashAlgorithm::Blake3);
        let mut prefix = Vec::new();
        let mut length = 0u64;
        let mut buffer = [0; 8192];
        let m = file.metadata().map_err(|_| disk::Error::Io)?;
        loop {
            let count = file.read(&mut buffer).map_err(|_| disk::Error::Io)?;
            let Some(bytes) = buffer.get(..count).filter(|b| !b.is_empty()) else {
                break;
            };
            let skip =
                j::STAGING_HEADER_LEN.saturating_sub(usize::try_from(length).unwrap_or(usize::MAX));
            if let Some(check) = &mut check
                && let Some(payload) = bytes.get(skip..)
            {
                check.update(payload);
            }
            length = length
                .checked_add(count as u64)
                .filter(|n| *n <= m.len())
                .ok_or(FOREIGN)?;
            hasher.update(bytes);
            let needed = keep.saturating_sub(prefix.len()).min(count);
            prefix.extend_from_slice(bytes.get(..needed).ok_or(FOREIGN)?);
        }
        let end = file.metadata().map_err(|_| disk::Error::Io)?;
        if length != m.len()
            || end.len() != length
            || end.nlink() != links
            || (end.ctime(), end.ctime_nsec()) != (m.ctime(), m.ctime_nsec())
        {
            return Err(FOREIGN.into());
        }
        if let Some(listing) = &listing {
            crate::overlay_store::validate_unmerged_payload(
                &prefix,
                length,
                check.as_ref().map(j::ResidualPayloadHasher::finalize),
                listing,
            )
            .map_err(|_| FOREIGN)?;
        }
        if let Some(step) = self.barriers.as_deref_mut() {
            sync(step, &relative, &file)?;
        }
        inventory.bytes = inventory.bytes.checked_add(length).ok_or(FOREIGN)?;
        inventory.files = inventory.files.checked_add(1).ok_or(FOREIGN)?;
        inventory.entries.push((
            relative.into_bytes(),
            Some((length, *hasher.finalize().digest())),
        ));
        inventory.identities.push(inode);
        Ok(prefix)
    }

    pub(super) fn overlay(
        &mut self,
        selected: &File,
        scope: &str,
        volume: &VolumeName,
    ) -> Result<(Inventory, [u8; 16], bool), disk::Error> {
        let mut inventory = Inventory::default();
        let mut leaves = disk::names(selected)?;
        leaves.sort_unstable();
        let writer = self.file(
            selected,
            "writer",
            "writer".into(),
            133,
            &mut inventory,
            None,
        )?;
        let writer = WriterRecord::decode(&writer).map_err(|_| FOREIGN)?;
        if &writer.volume != volume {
            return Err(FOREIGN.into());
        }
        let journal = self.file(
            selected,
            "journal",
            "journal".into(),
            j::JOURNAL_MAX + 1,
            &mut inventory,
            None,
        )?;
        let stage = disk::directory(selected, OsStr::new("staging"), self.mount)?;
        let unmerged = disk::directory(selected, OsStr::new("unmerged"), self.mount)?;
        let mut carrier = None;
        let mut retained = false;
        for leaf in leaves {
            match leaf.to_str().ok_or(FOREIGN)? {
                "writer" | "journal" => {}
                "staging" | "unmerged" => {
                    let (directory, pair) = if leaf == "staging" {
                        (&stage, &unmerged)
                    } else {
                        (&unmerged, &stage)
                    };
                    retained |= self.stages(
                        directory.as_ref().ok_or(FOREIGN)?,
                        pair.as_ref(),
                        leaf.as_bytes(),
                        writer.writer,
                        &mut inventory,
                    )?;
                }
                "writer.tmp" | "journal.next" | "ownership.tmp" => {
                    let name = leaf.to_str().ok_or(FOREIGN)?;
                    self.file(selected, name, name.into(), 0, &mut inventory, None)?;
                }
                "ownership" => {
                    let bytes = self.file(
                        selected,
                        "ownership",
                        "ownership".into(),
                        o::MAX_BYTES + 1,
                        &mut inventory,
                        None,
                    )?;
                    let c = o::decode(&bytes).map_err(|_| FOREIGN)?;
                    if &c.volume != volume
                        || c.scope.digest().map_err(|_| FOREIGN)? != scope
                        || c.writer != writer.writer
                        || writer.ceiling < c.allocated.max(c.sent)
                    {
                        return Err(FOREIGN.into());
                    }
                    retained |= !carrier_is_settled(&c, &writer);
                    carrier = Some(c);
                }
                _ => return Err(FOREIGN.into()),
            }
        }
        match JournalHeader::decode(journal.get(..j::JOURNAL_HEADER_LEN).unwrap_or(&journal)) {
            Ok(h) if h.writer == writer.writer => {}
            Ok(_)
            | Err(j::HeaderError::UnknownVersion { .. } | j::HeaderError::NonZeroFlags { .. }) => {
                return Err(FOREIGN.into());
            }
            Err(_) if carrier.is_some() => {}
            Err(_) => return Err(FOREIGN.into()),
        }
        if journal.starts_with(&j::JOURNAL_MAGIC)
            && journal
                .get(8..10)
                .is_some_and(|n| n != j::VERSION.to_be_bytes())
        {
            return Err(FOREIGN.into());
        }
        let dirty =
            crate::overlay_store::scan_clean(&journal, &writer).is_none_or(|(_, clean)| !clean);
        inventory.entries.sort_unstable();
        Ok((inventory, writer.writer, retained || dirty))
    }

    fn stages(
        &mut self,
        directory: &File,
        pair: Option<&File>,
        area: &[u8],
        writer: [u8; 16],
        inventory: &mut Inventory,
    ) -> Result<bool, disk::Error> {
        let area = std::str::from_utf8(area).map_err(|_| FOREIGN)?;
        inventory.entries.push((area.as_bytes().to_vec(), None));
        inventory
            .identities
            .push(disk::identity(directory).map_err(|_| disk::Error::Io)?);
        let mut leaves = disk::names(directory)?;
        leaves.sort_unstable();
        for leaf in &leaves {
            let leaf = leaf.to_str().ok_or(FOREIGN)?;
            let (stem, suffix) = leaf.split_once('.').unwrap_or((leaf, ""));
            let listing = area == "unmerged" && suffix == "path";
            let temporary = area == "unmerged" && suffix == "path.next";
            if !suffix.is_empty() && !listing && !temporary || leaf.ends_with('.') {
                return Err(FOREIGN.into());
            }
            let id = u64::from_be_bytes(parse_hex(stem).map_err(|_| FOREIGN)?);
            if !(1..=j::STAGE_ID_MAX).contains(&id) {
                return Err(FOREIGN.into());
            }
            let keep = if listing {
                j::UNMERGED_PATH_MAX + 1
            } else if temporary {
                0
            } else {
                j::STAGING_HEADER_LEN
            };
            let bytes = self.file(
                directory,
                leaf,
                format!("{area}/{leaf}"),
                keep,
                inventory,
                if listing || temporary { None } else { pair },
            )?;
            let misbound = if listing {
                UnmergedPath::decode(&bytes)
                    .is_ok_and(|p| p.writer != writer || p.file.stage_id != id)
            } else {
                !temporary
                    && StagingHeader::decode(&bytes)
                        .is_ok_and(|h| h.writer != writer || h.stage_id != id)
            };
            if misbound {
                return Err(FOREIGN.into());
            }
        }
        if let Some(step) = self.barriers.as_deref_mut() {
            sync(step, area, directory)?;
        }
        Ok(!leaves.is_empty())
    }

    pub(super) fn publications(
        &mut self,
        directory: Option<&File>,
        scope: &str,
        volume: &VolumeName,
    ) -> Result<(Inventory, bool), disk::Error> {
        let mut inventory = Inventory::default();
        let mut retained = false;
        let Some(directory) = directory else {
            return Ok((inventory, false));
        };
        let mut leaves = disk::names(directory)?;
        leaves.sort_unstable();
        let live = format!("{}.sub", volume.as_str());
        for leaf in leaves {
            let archive = ArchiveName::parse(leaf.as_bytes()).map_err(|_| FOREIGN)?;
            let Some(leaf) = leaf.to_str() else { continue };
            let canonical = leaf == live || archive.as_ref().is_some_and(|a| &a.volume == volume);
            if !canonical && temporary(leaf).as_ref() != Some(volume) {
                continue;
            }
            let bytes = self.file(
                directory,
                leaf,
                leaf.into(),
                if canonical { p::MAX_BYTES + 1 } else { 0 },
                &mut inventory,
                None,
            )?;
            if canonical {
                let record = p::decode(&bytes).map_err(|_| FOREIGN)?;
                if &record.volume != volume
                    || record.scope.digest().map_err(|_| FOREIGN)? != scope
                    || archive
                        .as_ref()
                        .is_some_and(|a| a.publication_id != record.publication_id)
                {
                    return Err(FOREIGN.into());
                }
                retained |= archive.map_or(!record.is_complete(), |a| !a.settled);
            }
        }
        Ok((inventory, retained))
    }
}
