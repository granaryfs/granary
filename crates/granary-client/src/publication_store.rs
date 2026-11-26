// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Durable publication ownership under the store lock. This module performs no
//! network operations. A successful write has crossed every durability barrier.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Component, Path, PathBuf};

use granary_core::retained_submission::{self as codec, Scope, Submission};
use granary_core::root::VolumeName;

use crate::{custody, fsguard, store::Store};

use self::archive::{archive_read_error, require_settled_archives};

/// A refusal always names the record or path component being inspected.
#[derive(Debug)]
pub struct PublicationStoreError {
    pub path: PathBuf,
    pub reason: String,
    pub kind: PublicationStoreErrorKind,
}
/// Typed publication refusals; validation and persistence errors retain their reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationStoreErrorKind {
    /// Concurrent namespace changes prevent this commit.
    Conflict,
    /// A commit boundary or ownership fence stopped the journal; no namespace
    /// change was observed.
    Fenced,
    /// Remote ancestry or immutable content could not be verified.
    Unavailable,
    /// A local filesystem operation could not complete.
    Io,
    /// Authenticated retained state disagrees with its reconstructed commit.
    Corrupt,
    /// The recovery's remote history or immutable content failed verification.
    RemoteIntegrity,
    Refused,
    Abandoned,
    MissingPublication,
    /// Valid state prevents the requested publication selection.
    Selection,
}
impl std::fmt::Display for PublicationStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.reason)
    }
}
impl std::error::Error for PublicationStoreError {}
fn error(path: &Path, reason: impl std::fmt::Display) -> PublicationStoreError {
    PublicationStoreError {
        path: path.to_owned(),
        reason: reason.to_string(),
        kind: PublicationStoreErrorKind::Refused,
    }
}

/// Classifies a failed read of a record: `retained_read_error` for the paths
/// that retry transient failures, `archive_read_error` for the inspection.
type ReadFailure = fn(&Path, &io::Error) -> PublicationStoreError;

fn retained_read_error(path: &Path, error: &io::Error) -> PublicationStoreError {
    let kind = if error.kind() == io::ErrorKind::InvalidData {
        PublicationStoreErrorKind::Refused
    } else {
        PublicationStoreErrorKind::Io
    };
    PublicationStoreError {
        path: path.to_owned(),
        reason: error.to_string(),
        kind,
    }
}

fn selection_error(path: &Path, reason: &str) -> PublicationStoreError {
    let mut result = error(path, reason);
    result.kind = PublicationStoreErrorKind::Selection;
    result
}

#[derive(Debug, PartialEq, Eq)]
enum Broken {
    RelativePath,
    ParentComponent,
    AncestorOwner,
    AncestorWritable,
    RootOwner,
    RootWritable,
}
impl Broken {
    fn reason(&self, path: &Path) -> String {
        match self {
            Self::RelativePath => "store path must be absolute".to_owned(),
            Self::ParentComponent => "store path contains ..; spell the path without ..".to_owned(),
            Self::AncestorOwner => {
                "store ancestor must be owned by root or the effective uid".to_owned()
            }
            Self::RootOwner => "store root must be owned by the effective uid".to_owned(),
            Self::AncestorWritable => format!(
                "store ancestor is group/other-writable without the sticky bit; chmod go-w {}",
                path.display()
            ),
            Self::RootWritable => format!(
                "store root is group/other-writable; chmod go-w {}",
                path.display()
            ),
        }
    }
}
fn judge_shape(path: &Path) -> Result<(), Broken> {
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(Broken::ParentComponent);
    }
    if !path.is_absolute() {
        return Err(Broken::RelativePath);
    }
    Ok(())
}
fn judge_ancestor(uid: u32, mode: u32, euid: u32) -> Result<(), Broken> {
    if uid != 0 && uid != euid {
        return Err(Broken::AncestorOwner);
    }
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Err(Broken::AncestorWritable);
    }
    Ok(())
}
fn judge_root(uid: u32, mode: u32, euid: u32) -> Result<(), Broken> {
    if uid != euid {
        return Err(Broken::RootOwner);
    }
    if mode & 0o022 != 0 {
        return Err(Broken::RootWritable);
    }
    Ok(())
}

/// A symlink or a non-directory component is custody and says how to fix it;
/// any other failure is classified as a read of an archive is.
fn directory_open_error(path: &Path, err: &io::Error) -> PublicationStoreError {
    match err.raw_os_error() {
        Some(libc::ELOOP) => error(path, format!("{err}; name the symlink target directly")),
        Some(libc::ENOTDIR) => error(path, format!("{err}; component is not a directory")),
        _ => archive_read_error(path, err),
    }
}

/// A validated canonical record with its location, including foreign scopes.
#[derive(Debug, Clone)]
struct LocatedSubmission {
    path: PathBuf,
    submission: Submission,
}

/// Validated selection evidence for a route without an authority scope.
#[derive(Debug, Clone)]
pub struct DirectPublicationSelection {
    /// Completed live records, with their validated canonical locations.
    pub completed: Vec<(PathBuf, Submission)>,
    /// Archives whose full durability barriers have been re-established.
    pub archives: Vec<ArchiveEvidence>,
}

/// Borrowing the Store holds its exclusive lock. Mutating calls require `&mut`
/// and any persistence error disables further writes on this handle.
#[derive(Debug)]
pub struct PublicationStore<'a> {
    store: &'a mut Store,
    disk: Disk,
    poisoned: bool,
}
impl Store {
    /// Access durable publications while borrowing this store's exclusive lock.
    /// `euid` is the effective uid captured by the caller's platform seam.
    /// Walk the absolute path from `/`, refusing parent components, symlinks,
    /// untrusted ancestors and granting ACLs. The effective uid must own the
    /// root, which must not grant group/other write permission, even if sticky.
    /// # Errors
    /// An untrusted path component or root; unprotected publication directories;
    /// or an enumeration or temporary-cleanup failure.
    pub fn publications(
        &mut self,
        euid: u32,
    ) -> Result<PublicationStore<'_>, PublicationStoreError> {
        self.publications_with(euid, true)
    }

    pub(crate) fn publications_read_only(
        &mut self,
        euid: u32,
    ) -> Result<PublicationStore<'_>, PublicationStoreError> {
        self.publications_with(euid, false)
    }

    fn publications_with(
        &mut self,
        euid: u32,
        clean_temporaries: bool,
    ) -> Result<PublicationStore<'_>, PublicationStoreError> {
        let disk = Disk {
            euid,
            temporary: self.publication_temporary,
            #[cfg(test)]
            fail_directory_sync: None,
            #[cfg(test)]
            fail_move: None,
            #[cfg(test)]
            fail_file_sync: self.publication_fail_file_sync,
            #[cfg(test)]
            fail_marker_sync: false,
            #[cfg(test)]
            fail_directory_open: self.publication_fail_directory.open.clone(),
            #[cfg(test)]
            fail_directory_open_after: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fail_directory_read: self.publication_fail_directory.read.clone(),
        };
        disk.walk_root(self.publication_root())?;
        let claims = if clean_temporaries {
            let root = self.publication_root();
            let mut io = crate::OverlayDisk::new(root, euid);
            crate::overlay_discard::claims::scan(&mut io, root)
                .map_err(|e| selection_error(root, &e.to_string()))?
        } else {
            std::collections::BTreeMap::new()
        };
        let publications = self.publication_root().join("publications");
        match disk.directory(&publications, true) {
            Ok(_) => {
                for scope in scope_directories(&disk, &publications)
                    .map_err(|e| archive_read_error(&publications, &e))?
                {
                    disk.directory(&scope, true)
                        .map_err(|e| directory_open_error(&scope, &e))?;
                    if clean_temporaries {
                        remove_temporaries(&disk, &scope, |volume| claims.contains_key(volume))?;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(directory_open_error(&publications, &e)),
        }
        let poisoned = self.publication_poisoned;
        Ok(PublicationStore {
            store: self,
            disk,
            poisoned,
        })
    }
}
impl Drop for PublicationStore<'_> {
    fn drop(&mut self) {
        self.store.publication_poisoned |= self.poisoned;
        self.store.publication_temporary = self.disk.temporary;
    }
}
impl PublicationStore<'_> {
    #[cfg(test)]
    pub(crate) fn inject_selected_for_test(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
        record: Option<&Submission>,
    ) -> Result<(), PublicationStoreError> {
        let path = self.path(scope, volume)?;
        if let Some(record) = record {
            return self.persist(&path, record);
        }
        self.disk.unlink(&path).map_err(|e| error(&path, e))?;
        let parent = path.parent().ok_or_else(|| error(&path, "missing scope"))?;
        self.disk
            .sync_directory(parent)
            .map_err(|e| error(parent, e))
    }

    pub(crate) fn check_generic_resume(
        &mut self,
        record: &Submission,
    ) -> Result<(), PublicationStoreError> {
        use crate::OverlayIo as _;
        use granary_core::overlay_journal as journal;
        self.ready()?;
        self.guard_discard(&record.volume)?;
        let root = self.store.publication_root();
        let area = crate::overlay_store::area_path(root, &record.scope, &record.volume)
            .map_err(|e| error(root, e))?;
        let path = area.join("journal");
        let mut disk = crate::OverlayDisk::new(root, self.disk.euid);
        match disk.directory(&area) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(error(&area, e)),
        }
        crate::overlay_store::settle_area(&mut disk, &crate::FaultControl::default(), &area)
            .map_err(|e| match e {
                crate::OverlayError::Io(e) => retained_read_error(&area, &e),
                e => error(&area, e),
            })?;
        let length = disk
            .length(&path)
            .map_err(|e| error(&path, e))?
            .ok_or_else(|| error(&path, "overlay journal missing from existing area"))?;
        let length = usize::try_from(length)
            .ok()
            .filter(|n| *n <= journal::JOURNAL_MAX)
            .ok_or_else(|| error(&path, "overlay journal exceeds cap"))?;
        let bytes = disk
            .read_at(&path, 0, length)
            .map_err(|e| error(&path, e))?;
        let scan = journal::scan_journal(&bytes).map_err(|e| error(&path, e))?;
        if bytes.len() != length || scan.end != journal::JournalEnd::Clean {
            return Err(error(&path, "overlay journal requires recovery"));
        }
        if let Some(progress) = scan.state.commit_progress(&record.publication_id) {
            if progress.fenced {
                return Err(error(
                    &path,
                    crate::CoordinationError::CommitFenced {
                        publication: record.publication_id,
                    },
                ));
            }
            return Err(error(&path, "publication belongs to an open mount commit"));
        }
        Ok(())
    }
    /// Borrow content access while keeping this publication selection and the
    /// Store's exclusive lock alive through direct harvest and commit.
    #[must_use]
    pub fn content_store(&self) -> &Store {
        self.store
    }

    /// Guard a direct route without inventing an authority scope. Incomplete
    /// live state in any scope refuses; archives require explicit new intent.
    /// The caller must keep this Store's lock through harvest and publication.
    /// # Errors
    /// Invalid custody, corrupt evidence, incomplete live state, unacknowledged
    /// archives or a failed archive durability barrier.
    pub fn select_direct(
        &mut self,
        volume: &VolumeName,
        explicit_new: Option<MayLandAcknowledgement>,
    ) -> Result<DirectPublicationSelection, PublicationStoreError> {
        self.ready()?;
        self.guard_discard(volume)?;
        if let Some(acknowledgement) = explicit_new {
            self.acknowledge(acknowledgement)?;
        }
        let live = self.enumerate(volume, retained_read_error)?;
        let archives = self.selection_archives(volume, None, None)?;
        if let Some(record) = live.iter().find(|r| !r.submission.is_complete()) {
            let mut refusal = error(
                &record.path,
                "incomplete live publication requires authority recovery",
            );
            refusal.kind = PublicationStoreErrorKind::Selection;
            return Err(refusal);
        }
        if explicit_new.is_none()
            && let Some(archive) = archives.iter().find(|a| !a.settled)
        {
            let mut refusal = error(
                &archive.path,
                "abandoned publication; explicit new acknowledgement required",
            );
            refusal.kind = PublicationStoreErrorKind::Abandoned;
            return Err(refusal);
        }
        Ok(DirectPublicationSelection {
            completed: live.into_iter().map(|r| (r.path, r.submission)).collect(),
            archives,
        })
    }
    fn guard_discard(&self, volume: &VolumeName) -> Result<(), PublicationStoreError> {
        let root = self.root();
        self.disk.walk_root(root)?;
        let mut io = crate::OverlayDisk::new(root, self.disk.euid);
        crate::overlay_discard::claims::gate(&mut io, root, volume)
            .map_err(|e| selection_error(root, &e.to_string()))
    }

    fn root(&self) -> &Path {
        self.store.publication_root()
    }
    fn path(&self, scope: &Scope, volume: &VolumeName) -> Result<PathBuf, PublicationStoreError> {
        let digest = scope.digest().map_err(|e| error(self.root(), e))?;
        Ok(self
            .root()
            .join("publications")
            .join(digest)
            .join(format!("{}.sub", volume.as_str())))
    }
    /// Enumerate this volume in every scope, refusing corrupt or foreign files.
    /// Leftover temporaries are never interpreted as canonical records.
    /// # Errors
    /// A protected-directory, read, size, decode or path/scope binding failure.
    fn enumerate(
        &self,
        volume: &VolumeName,
        failure: ReadFailure,
    ) -> Result<Vec<LocatedSubmission>, PublicationStoreError> {
        let publications = self.root().join("publications");
        self.disk.walk_root(self.root())?;
        self.disk
            .directory(self.root(), false)
            .map_err(|e| directory_open_error(self.root(), &e))?;
        match self.disk.directory(&publications, true) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(directory_open_error(&publications, &e)),
        }
        let mut records = Vec::new();
        for directory in scope_directories(&self.disk, &publications)
            .map_err(|e| archive_read_error(&publications, &e))?
        {
            self.disk
                .directory(&directory, true)
                .map_err(|e| directory_open_error(&directory, &e))?;
            let path = directory.join(format!("{}.sub", volume.as_str()));
            if let Some(submission) = self.read(&path, volume, failure)? {
                let expected = self.path(&submission.scope, &submission.volume)?;
                if expected != path || submission.volume != *volume {
                    return Err(error(&path, "record scope or volume disagrees with path"));
                }
                records.push(LocatedSubmission { path, submission });
            }
        }
        records.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(records)
    }
    fn read(
        &self,
        path: &Path,
        volume: &VolumeName,
        failure: ReadFailure,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        let file = match fsguard::open_sole_regular_read(path, "a retained submission") {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return match self.read_archive_duplicate(path, volume) {
                    Ok(Some(record)) => Ok(Some(record)),
                    _ => Err(failure(path, &e)),
                };
            }
        };
        protected(&file, path, self.disk.euid, Some(0o600)).map_err(|e| error(path, e))?;
        let length = file.metadata().map_err(|e| failure(path, &e))?.len();
        let bytes = read_bounded(file, length).map_err(|e| failure(path, &e))?;
        codec::decode(&bytes).map(Some).map_err(|e| error(path, e))
    }
    /// Resume only the exact scope. Any other unresolved scope for this volume
    /// refuses, even if the requested scope has no record. Every returned record
    /// has crossed a fresh full-generation barrier.
    /// # Errors
    /// Enumeration, scope, generation exhaustion or persistence failure.
    pub fn load(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        self.load_selected(scope, volume, false)
    }
    /// Read the exact scope's record without writing: unlike [`Self::load`]
    /// no generation barrier is crossed and no archive is re-established, so
    /// the record must not be acted on before a `load`.
    /// # Errors
    /// Poison, enumeration, scope or an unresolved record under another scope.
    pub fn observe(
        &self,
        scope: &Scope,
        volume: &VolumeName,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        self.ready()?;
        self.inspect(scope, volume, archive_read_error)
    }
    fn load_selected(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
        explicit_new: bool,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        self.ready()?;
        self.guard_discard(volume)?;
        let path = self.path(scope, volume)?;
        let retained = self
            .inspect(scope, volume, retained_read_error)?
            .map(|record| {
                record
                    .generation
                    .checked_add(1)
                    .map(|generation| (record, generation))
                    .ok_or_else(|| error(&path, "generation exhausted"))
            })
            .transpose()?;
        let archives = self.selection_archives(volume, None, None)?;
        let Some((mut record, generation)) = retained else {
            if !explicit_new {
                require_settled_archives(archives.iter().map(|a| (a.path.as_path(), a.settled)))?;
            }
            return Ok(None);
        };
        record.generation = generation;
        #[cfg(feature = "publish-restart-tests")]
        crate::publish_restart::point("load", "before", &record).map_err(|e| error(&path, e))?;
        self.persist(&path, &record)?;
        #[cfg(feature = "publish-restart-tests")]
        crate::publish_restart::point("load", "after", &record).map_err(|e| error(&path, e))?;
        Ok(Some(record))
    }
    /// `load_selected` without the fresh generation: the record and every
    /// archive are validated and re-synced, never rewritten and never cleaned
    /// up after, so a repeated inspection leaves the directory as it found it.
    /// # Errors
    /// The enumeration, selection and archive failures of `load`. Unlike `load`,
    /// a read of the record, an open or listing of a store directory, or a failed
    /// barrier is an I/O failure only when the device, the filesystem or a kernel
    /// resource failed; a custody or shape failure is a refusal. Neither poisons
    /// this handle.
    pub(crate) fn inspect_selected(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        self.ready()?;
        self.guard_discard(volume)?;
        let path = self.path(scope, volume)?;
        let retained = self.inspect(scope, volume, archive_read_error)?;
        if let Some(record) = &retained {
            record
                .generation
                .checked_add(1)
                .ok_or_else(|| error(&path, "generation exhausted"))?;
        }
        let archives = self.inspect_selection_archives(volume, None, None, archive_read_error)?;
        let mut resynced: Vec<&Path> = archives.iter().map(|a| a.path.as_path()).collect();
        resynced.extend(retained.as_ref().map(|_| path.as_path()));
        self.resync_records(&resynced)?;
        if retained.is_none() {
            require_settled_archives(archives.iter().map(|a| (a.path.as_path(), a.settled)))?;
        }
        Ok(retained)
    }
    fn inspect(
        &self,
        scope: &Scope,
        volume: &VolumeName,
        failure: ReadFailure,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        let path = self.path(scope, volume)?;
        let mut found = None;
        for record in self.enumerate(volume, failure)? {
            if record.path == path {
                if record.submission.scope != *scope {
                    return Err(selection_error(&record.path, "requested scope mismatch"));
                }
                found = Some(record.submission);
            } else if !record.submission.is_complete()
                && !crate::sync::terminal_non_landing(&record.submission)
            {
                return Err(selection_error(
                    &record.path,
                    "non-complete publication under another scope",
                ));
            }
        }
        Ok(found)
    }
    /// Begin an explicitly new logical publication. Existing non-complete
    /// publications under any scope refuse; no pending publication is overwritten.
    /// # Errors
    /// Format, scope, generation, ownership or persistence failure.
    pub fn begin(&mut self, record: &Submission) -> Result<(), PublicationStoreError> {
        self.ready()?;
        self.guard_discard(&record.volume)?;
        let path = self.path(&record.scope, &record.volume)?;
        if record.generation != 1 {
            return Err(error(&path, "initial generation must be one"));
        }
        codec::encode(record).map_err(|e| error(&path, e))?;
        let digest = record.scope.digest().map_err(|e| error(&path, e))?;
        for prior in self.enumerate(&record.volume, retained_read_error)? {
            if !prior.submission.is_complete()
                && !crate::sync::terminal_non_landing(&prior.submission)
            {
                return Err(error(&prior.path, "publication is not complete"));
            }
            if prior.submission.publication_id == record.publication_id {
                return Err(error(&prior.path, "publication identity already exists"));
            }
        }
        self.selection_archives(&record.volume, Some(&digest), Some(record.publication_id))?;
        self.persist(&path, record)
    }
    /// Replace a generation of the same publication; preserve frozen intent.
    /// The caller owns candidate release proofs and continuation transitions.
    /// # Errors
    /// Stale generation, changed identity/intent, terminal completion, or I/O.
    pub fn replace(
        &mut self,
        expected_generation: u64,
        record: &Submission,
    ) -> Result<(), PublicationStoreError> {
        self.ready()?;
        self.guard_discard(&record.volume)?;
        let path = self.path(&record.scope, &record.volume)?;
        let old = self
            .inspect(&record.scope, &record.volume, retained_read_error)?
            .ok_or_else(|| error(&path, "no retained publication"))?;
        if old.is_complete() {
            return Err(error(&path, "completion is terminal"));
        }
        if old.generation != expected_generation
            || expected_generation.checked_add(1) != Some(record.generation)
        {
            return Err(error(&path, "stale or exhausted generation"));
        }
        if old.publication_id != record.publication_id || old.frozen != record.frozen {
            return Err(error(
                &path,
                "publication identity or frozen intent changed",
            ));
        }
        codec::encode(record).map_err(|e| error(&path, e))?;
        self.selection_archives(&record.volume, None, None)?;
        self.persist(&path, record)
    }
    /// Revalidate and write a fresh complete generation after restart or an I/O
    /// failure. Poison survives facade recreation for the store lifetime. Even a
    /// completed record crosses a new full barrier before reporting completion.
    /// # Errors
    /// Missing, corrupt or foreign record, generation exhaustion, or persistence.
    pub fn recover(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
    ) -> Result<Submission, PublicationStoreError> {
        let path = self.path(scope, volume)?;
        self.load(scope, volume)?
            .ok_or_else(|| error(&path, "no retained publication"))
    }
    fn persist(&mut self, path: &Path, record: &Submission) -> Result<(), PublicationStoreError> {
        if self.poisoned {
            return Err(error(
                path,
                "persistence failed; reload and write a fresh generation",
            ));
        }
        let bytes = codec::encode(record).map_err(|e| error(path, e))?;
        let root = self.root().to_owned();
        // Set before the first filesystem mutation. No failure path restores it.
        self.poisoned = true;
        durable_replace(&mut self.disk, &root, path, &bytes).map_err(|e| error(path, e))?;
        self.poisoned = false;
        Ok(())
    }
}

impl granary_core::grainsource::GrainSource for PublicationStore<'_> {
    fn get(
        &self,
        id: &granary_core::hash::GrainId,
    ) -> Result<Vec<u8>, granary_core::grainsource::GrainSourceError> {
        granary_core::grainsource::GrainSource::get(self.store, id)
    }
    fn has(&self, id: &granary_core::hash::GrainId) -> bool {
        granary_core::grainsource::GrainSource::has(self.store, id)
    }
}

fn read_bounded(reader: impl Read, length: u64) -> io::Result<Vec<u8>> {
    if length > codec::MAX_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            codec::Error::TooLarge,
        ));
    }
    let mut bytes = Vec::new();
    reader
        .take(codec::MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn protected(file: &File, path: &Path, euid: u32, mode: Option<u32>) -> io::Result<()> {
    let meta = file.metadata()?;
    if meta.uid() != euid {
        return Err(io::Error::other("wrong owner"));
    }
    if mode.map_or(meta.mode() & 0o022 != 0, |mode| meta.mode() & 0o777 != mode) {
        return Err(io::Error::other("unprotected mode"));
    }
    let what = if mode == Some(0o600) {
        "a retained submission record"
    } else {
        "a publication directory"
    };
    custody::refuse_granting_acl_on_fd(file.as_fd(), path, what).map_err(io::Error::other)
}
#[expect(
    clippy::disallowed_methods,
    reason = "enumerate only a guarded owner-controlled publications directory; every child is separately opened O_DIRECTORY|O_NOFOLLOW and checked before any record access"
)]
fn scope_directories(disk: &Disk, path: &Path) -> io::Result<Vec<PathBuf>> {
    #[cfg(test)]
    disk.injected_read_failure(path)?;
    #[cfg(not(test))]
    let _ = disk;
    let mut directories = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(text) = name.to_str() else {
            continue;
        };
        if !granary_core::retained_archive::is_scope_digest(text.as_bytes()) {
            continue;
        }
        directories.push(entry.path());
    }
    Ok(directories)
}

// Only names produced by Disk::create are eligible; neither lookalikes nor
// canonical records are recovery scratch. Unlink never follows a leaf symlink.
#[expect(
    clippy::disallowed_methods,
    reason = "under the exclusive store lock, enumerate a guarded private scope and unlink only exact store temporary names; never follow entries or recurse"
)]
fn remove_temporaries(
    disk: &Disk,
    scope: &Path,
    frozen: impl Fn(&VolumeName) -> bool,
) -> Result<(), PublicationStoreError> {
    let listing = fs::read_dir(scope);
    #[cfg(test)]
    let listing = disk.injected_read_failure(scope).and(listing);
    #[cfg(not(test))]
    let _ = disk;
    for entry in listing.map_err(|e| archive_read_error(scope, &e))? {
        let entry = entry.map_err(|e| archive_read_error(scope, &e))?;
        let name = entry.file_name();
        if let Some(volume) = name.to_str().and_then(crate::overlay_discard::temporary)
            && !frozen(&volume)
        {
            fs::remove_file(entry.path()).map_err(|e| error(scope, e))?;
        }
    }
    Ok(())
}

// Every persistence cut is a seam operation. Tests maintain separate volatile
// data, synced file contents and durable directory entries behind this trait.
trait Persistence {
    type File;
    fn sync_marker(&mut self, root: &Path) -> io::Result<()>;
    fn ensure_directory(&mut self, path: &Path) -> io::Result<()>;
    fn sync_directory(&mut self, path: &Path) -> io::Result<()>;
    fn create(&mut self, canonical: &Path) -> io::Result<(PathBuf, Self::File)>;
    fn write(&mut self, file: &mut Self::File, bytes: &[u8]) -> io::Result<()>;
    fn sync_file(&mut self, file: &Self::File) -> io::Result<()>;
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()>;
    fn open_record(&mut self, path: &Path) -> io::Result<Self::File>;
    fn rename_no_replace(&mut self, from: &Path, to: &Path) -> io::Result<()>;
    fn unlink(&mut self, path: &Path) -> io::Result<()>;
}
fn durable_replace<F: Persistence>(
    fs: &mut F,
    root: &Path,
    path: &Path,
    bytes: &[u8],
) -> io::Result<()> {
    // The validated root is absolute; `/` is its own durability parent.
    let parent = if root == Path::new("/") {
        root
    } else {
        root.parent()
            .ok_or_else(|| io::Error::other("missing store parent"))?
    };
    let publications = root.join("publications");
    let scope = path
        .parent()
        .ok_or_else(|| io::Error::other("missing scope"))?;
    #[cfg(feature = "publish-restart-tests")]
    let record = crate::publish_restart::persistence_record(bytes)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("marker-sync", "before", record.as_ref())?;
    fs.sync_marker(root)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("marker-sync", "after", record.as_ref())?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("root-sync", "before", record.as_ref())?;
    fs.sync_directory(root)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("root-sync", "after", record.as_ref())?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("parent-sync", "before", record.as_ref())?;
    fs.sync_directory(parent)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("parent-sync", "after", record.as_ref())?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("publications-create", "before", record.as_ref())?;
    fs.ensure_directory(&publications)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("publications-create", "after", record.as_ref())?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("publications-root-sync", "before", record.as_ref())?;
    fs.sync_directory(root)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("publications-root-sync", "after", record.as_ref())?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("scope-create", "before", record.as_ref())?;
    fs.ensure_directory(scope)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("scope-create", "after", record.as_ref())?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("publications-sync", "before", record.as_ref())?;
    fs.sync_directory(&publications)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("publications-sync", "after", record.as_ref())?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("temporary-create", "before", record.as_ref())?;
    let (temporary, mut file) = fs.create(path)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("temporary-create", "after", record.as_ref())?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("temporary-write", "before", record.as_ref())?;
    fs.write(&mut file, bytes)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("temporary-write", "after", record.as_ref())?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("temporary-sync", "before", record.as_ref())?;
    fs.sync_file(&file)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("temporary-sync", "after", record.as_ref())?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("temporary-install", "before", record.as_ref())?;
    fs.rename(&temporary, path)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("temporary-install", "after", record.as_ref())?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("scope-sync", "before", record.as_ref())?;
    fs.sync_directory(scope)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("scope-sync", "after", record.as_ref())?;
    Ok(())
}
#[derive(Debug)]
struct Disk {
    euid: u32,
    temporary: u64,
    #[cfg(test)]
    fail_directory_sync: Option<PathBuf>,
    #[cfg(test)]
    fail_move: Option<(i32, bool)>,
    #[cfg(test)]
    fail_file_sync: bool,
    #[cfg(test)]
    fail_marker_sync: bool,
    #[cfg(test)]
    fail_directory_open: Option<PathBuf>,
    // Opens of `fail_directory_open` that succeed before the fault fires, so a
    // path opened twice in one call can fail at its later open.
    #[cfg(test)]
    fail_directory_open_after: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    fail_directory_read: Option<PathBuf>,
}

/// Reuse the publication ancestry guarantee without opening or cleaning publications.
pub(crate) fn check_control_root(root: &Path, euid: u32) -> Result<(), PublicationStoreError> {
    Disk {
        euid,
        temporary: 0,
        #[cfg(test)]
        fail_directory_sync: None,
        #[cfg(test)]
        fail_move: None,
        #[cfg(test)]
        fail_file_sync: false,
        #[cfg(test)]
        fail_marker_sync: false,
        #[cfg(test)]
        fail_directory_open: None,
        #[cfg(test)]
        fail_directory_open_after: std::sync::atomic::AtomicUsize::new(0),
        #[cfg(test)]
        fail_directory_read: None,
    }
    .walk_root(root)
}
impl Disk {
    fn walk_root(&self, root: &Path) -> Result<(), PublicationStoreError> {
        judge_shape(root).map_err(|broken| error(root, broken.reason(root)))?;
        let mut prefix = PathBuf::new();
        for component in root.components() {
            prefix.push(component.as_os_str());
            if prefix == root {
                self.directory(&prefix, false)
                    .map_err(|e| directory_open_error(&prefix, &e))?;
            } else {
                let file = match fsguard::open_directory(&prefix) {
                    Ok(file) => file,
                    Err(e) if e.raw_os_error() == Some(libc::EACCES) => {
                        let meta = fs::symlink_metadata(&prefix).map_err(|e| error(&prefix, e))?;
                        if meta.file_type().is_symlink() {
                            return Err(directory_open_error(
                                &prefix,
                                &io::Error::from_raw_os_error(libc::ELOOP),
                            ));
                        }
                        if !meta.is_dir() {
                            return Err(directory_open_error(
                                &prefix,
                                &io::Error::from_raw_os_error(libc::ENOTDIR),
                            ));
                        }
                        judge_ancestor(meta.uid(), meta.mode(), self.euid)
                            .map_err(|broken| error(&prefix, broken.reason(&prefix)))?;
                        if root.parent() == Some(prefix.as_path()) {
                            return Err(error(
                                &prefix,
                                "the store's parent directory must be readable: every write syncs it",
                            ));
                        }
                        #[cfg(target_vendor = "apple")]
                        return Err(error(
                            &prefix,
                            "an ancestor that cannot be read cannot have its ACL checked",
                        ));
                        #[cfg(not(target_vendor = "apple"))]
                        continue;
                    }
                    Err(e) => return Err(directory_open_error(&prefix, &e)),
                };
                let meta = file.metadata().map_err(|e| error(&prefix, e))?;
                judge_ancestor(meta.uid(), meta.mode(), self.euid)
                    .map_err(|broken| error(&prefix, broken.reason(&prefix)))?;
                custody::refuse_granting_directory_acl_on_fd(
                    file.as_fd(),
                    &prefix,
                    "a store ancestor",
                )
                .map_err(|e| error(&prefix, e))?;
            }
            // Only root or the effective uid can replace a checked component.
            // Dropping its descriptor leaves later path resolution trustworthy.
        }
        Ok(())
    }

    #[cfg(test)]
    fn injected_read_failure(&self, path: &Path) -> io::Result<()> {
        if self.fail_directory_read.as_deref() == Some(path) {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(())
    }

    fn directory(&self, path: &Path, private: bool) -> io::Result<File> {
        #[cfg(test)]
        if self.fail_directory_open.as_deref() == Some(path) {
            use std::sync::atomic::Ordering::Relaxed;
            let passes = self.fail_directory_open_after.load(Relaxed);
            if passes == 0 {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            self.fail_directory_open_after.store(passes - 1, Relaxed);
        }
        let file = fsguard::open_directory(path)?;
        if private {
            protected(&file, path, self.euid, Some(0o700))?;
        } else {
            let meta = file.metadata()?;
            judge_root(meta.uid(), meta.mode(), self.euid)
                .map_err(|broken| io::Error::other(broken.reason(path)))?;
            custody::refuse_granting_directory_acl_on_fd(file.as_fd(), path, "the store root")
                .map_err(io::Error::other)?;
        }
        Ok(file)
    }
}
impl Persistence for Disk {
    type File = File;
    fn sync_marker(&mut self, root: &Path) -> io::Result<()> {
        #[cfg(test)]
        if self.fail_marker_sync {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        self.directory(root, false)?;
        let marker = fsguard::open_sole_regular_read(
            &root.join(crate::store::MARKER_NAME),
            "the store marker",
        )?;
        marker.sync_all()
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "create one private directory beneath the checked store root or validated private publications directory; never recursive or following a final symlink, and validate the opened directory even on AlreadyExists"
    )]
    fn ensure_directory(&mut self, path: &Path) -> io::Result<()> {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        self.directory(path, true)?;
        Ok(())
    }
    fn sync_directory(&mut self, path: &Path) -> io::Result<()> {
        #[cfg(test)]
        if self.fail_directory_sync.as_deref() == Some(path) {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        // Ancestors outside the private subtree may be shared (e.g. /tmp).
        // No writes traverse them here: sync the exact opened descriptor.
        fsguard::open_directory(path)?.sync_all()
    }
    fn create(&mut self, canonical: &Path) -> io::Result<(PathBuf, File)> {
        loop {
            self.temporary = self
                .temporary
                .checked_add(1)
                .ok_or_else(|| io::Error::other("temporary counter exhausted"))?;
            let path = canonical.with_extension(format!("sub.tmp-{}", self.temporary));
            match fsguard::create_regular_exclusive(&path) {
                Ok(file) => {
                    protected(&file, &path, self.euid, Some(0o600))?;
                    return Ok((path, file));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
    }
    fn write(&mut self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
        file.write_all(bytes)
    }
    fn sync_file(&mut self, file: &File) -> io::Result<()> {
        #[cfg(test)]
        if self.fail_file_sync {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        file.sync_all()
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "atomic same-directory replacement under the borrowed exclusive store lock, after guarded exclusive creation, full write and file sync; the private owner-controlled directory excludes other-uid replanting"
    )]
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }
    fn open_record(&mut self, path: &Path) -> io::Result<File> {
        self.open_archive_record(path)
    }
    fn rename_no_replace(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        #[cfg(test)]
        if let Some((errno, after)) = self.fail_move {
            if after {
                self.native_move(from, to)?;
            }
            return Err(io::Error::from_raw_os_error(errno));
        }
        self.native_move(from, to)
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "unlink only the exact duplicate live name under the borrowed lock after archive durability, or the descriptor-checked regular nlink=2 same-inode archive pair after protected custody and requested incomplete content validation; never follow a leaf or recurse"
    )]
    fn unlink(&mut self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
}

#[cfg(test)]
mod tests;

mod archive;
pub(crate) use archive::native_no_replace;
pub use archive::{
    AbandonAcknowledgement, Abandonment, ArchiveEvidence, MayLandAcknowledgement, PinDifference,
};
