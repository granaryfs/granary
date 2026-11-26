// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Archive custody, explicit local abandonment and durable selection evidence.

use std::ffi::CString;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;

use granary_core::retained_archive::{ArchiveName, is_scope_digest};

use super::*;

pub(super) fn require_settled_archives<'a>(
    mut archives: impl Iterator<Item = (&'a Path, bool)>,
) -> Result<(), PublicationStoreError> {
    if let Some((path, _)) = archives.find(|(_, settled)| !settled) {
        let mut e = error(
            path,
            "abandoned publication; explicit new acknowledgement required",
        );
        e.kind = PublicationStoreErrorKind::Abandoned;
        return Err(e);
    }
    Ok(())
}

/// Explicit acknowledgement that local abandonment cannot cancel remote work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MayLandAcknowledgement {
    Acknowledged,
    Unacknowledged,
}
/// Local abandonment consent or evidence that the exact retained work cannot land.
#[derive(Debug)]
pub enum AbandonAcknowledgement<'a> {
    MayLand(MayLandAcknowledgement),
    Proven(&'a crate::RejectionProof, &'a crate::FaultControl),
}
impl From<MayLandAcknowledgement> for AbandonAcknowledgement<'_> {
    fn from(value: MayLandAcknowledgement) -> Self {
        Self::MayLand(value)
    }
}
impl AbandonAcknowledgement<'_> {
    fn check(&self, record: &Submission, path: &Path) -> Result<(), PublicationStoreError> {
        if let Self::Proven(proof, _) = self
            && !proof.matches_submission(record)
        {
            return Err(error(path, "abandonment proof binding"));
        }
        Ok(())
    }
    fn faults(&self) -> Option<&crate::FaultControl> {
        match self {
            Self::Proven(_, faults) => Some(faults),
            Self::MayLand(_) => None,
        }
    }
}
/// Reported pin rotation; retained bytes continue to carry the original pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinDifference {
    pub retained: Vec<[u8; 32]>,
    pub configured: Vec<[u8; 32]>,
}
/// Validated, re-synced archive evidence. This is never a resumable handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEvidence {
    pub path: PathBuf,
    pub submission: Submission,
    pub uncertain: bool,
    pub settled: bool,
}
/// Successful local archival, including any change in configured trust pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abandonment {
    pub archive: ArchiveEvidence,
    pub pin_difference: Option<PinDifference>,
}
#[derive(Debug)]
pub(super) struct ArchiveRecord {
    pub(super) path: PathBuf,
    submission: Submission,
    bytes: Vec<u8>,
    pub(super) settled: bool,
}
impl ArchiveRecord {
    fn evidence(self) -> ArchiveEvidence {
        let uncertain = !self.settled
            && self
                .submission
                .candidates
                .iter()
                .any(|c| !c.evidence.never_decided());
        ArchiveEvidence {
            path: self.path,
            submission: self.submission,
            uncertain,
            settled: self.settled,
        }
    }
}

impl PublicationStore<'_> {
    pub(super) fn ready(&self) -> Result<(), PublicationStoreError> {
        if self.poisoned {
            return Err(error(
                self.root(),
                "persistence failed; reload and write a fresh generation",
            ));
        }
        Ok(())
    }
    fn archive_path(
        &self,
        digest: &str,
        volume: &VolumeName,
        id: [u8; 16],
        settled: bool,
    ) -> Result<PathBuf, PublicationStoreError> {
        if !is_scope_digest(digest.as_bytes()) {
            return Err(error(self.root(), "invalid scope digest"));
        }
        Ok(self.root().join("publications").join(digest).join(
            ArchiveName {
                volume: volume.clone(),
                publication_id: id,
                settled,
            }
            .file_name(),
        ))
    }
    fn read_exact(
        &self,
        path: &Path,
    ) -> Result<Option<(Submission, Vec<u8>)>, PublicationStoreError> {
        let opened = self.disk.open_archive_record(path);
        let file = match opened {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(archive_read_error(path, &e)),
        };
        protected(&file, path, self.disk.euid, Some(0o600)).map_err(|e| error(path, e))?;
        let length = file
            .metadata()
            .map_err(|e| archive_read_error(path, &e))?
            .len();
        let bytes = read_bounded(file, length).map_err(|e| archive_read_error(path, &e))?;
        let submission = codec::decode(&bytes).map_err(|e| error(path, e))?;
        Ok(Some((submission, bytes)))
    }
    fn checked_archive(
        &self,
        path: &Path,
        name: &ArchiveName,
    ) -> Result<ArchiveRecord, PublicationStoreError> {
        let (submission, bytes) = self
            .read_exact(path)?
            .ok_or_else(|| error(path, "archive disappeared"))?;
        let digest = submission.scope.digest().map_err(|e| error(path, e))?;
        if self.archive_path(
            &digest,
            &submission.volume,
            submission.publication_id,
            name.settled,
        )? != path
            || submission.volume != name.volume
            || submission.publication_id != name.publication_id
        {
            return Err(error(
                path,
                "archive scope, volume or identity disagrees with path",
            ));
        }
        if submission.is_complete() {
            return Err(error(path, "complete publication cannot be archived"));
        }
        Ok(ArchiveRecord {
            path: path.to_owned(),
            submission,
            bytes,
            settled: name.settled,
        })
    }
    pub(super) fn read_archive_duplicate(
        &self,
        path: &Path,
        volume: &VolumeName,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        for archive in self.catalogue(volume, None)? {
            if same_inode_pair(path, &archive.path)
                .map_err(|e| error(path, e))?
                .is_some()
            {
                return Ok(Some(archive.submission));
            }
        }
        Ok(None)
    }
    // Parse every name in every scope before filtering: malformed claimants for
    // other volumes must not disappear through a per-volume glob.
    #[expect(
        clippy::disallowed_methods,
        reason = "enumerate a guarded private scope under the borrowed lock; parse all reserved claimants and independently guard every relevant archive leaf"
    )]
    fn catalogue(
        &self,
        volume: &VolumeName,
        include_scope: Option<&str>,
    ) -> Result<Vec<ArchiveRecord>, PublicationStoreError> {
        self.ready()?;
        self.disk.walk_root(self.root())?;
        let publications = self.root().join("publications");
        match self.disk.directory(&publications, true) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(directory_open_error(&publications, &e)),
        }
        let mut archives = Vec::new();
        for scope in scope_directories(&self.disk, &publications)
            .map_err(|e| archive_read_error(&publications, &e))?
        {
            self.disk
                .directory(&scope, true)
                .map_err(|e| directory_open_error(&scope, &e))?;
            let listing = fs::read_dir(&scope);
            #[cfg(test)]
            let listing = self.disk.injected_read_failure(&scope).and(listing);
            for entry in listing.map_err(|e| archive_read_error(&scope, &e))? {
                let entry = entry.map_err(|e| archive_read_error(&scope, &e))?;
                let name = entry.file_name();
                let Some(name) =
                    ArchiveName::parse(name.as_bytes()).map_err(|e| error(&entry.path(), e))?
                else {
                    continue;
                };
                if name.volume == *volume
                    || scope.file_name().and_then(|n| n.to_str()) == include_scope
                {
                    archives.push(self.checked_archive(&entry.path(), &name)?);
                }
            }
        }
        archives.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(archives)
    }
    fn establish_archives(
        &mut self,
        archives: &[ArchiveRecord],
    ) -> Result<(), PublicationStoreError> {
        if archives.is_empty() {
            return Ok(());
        }
        let root = self.root().to_owned();
        self.poisoned = true;
        for archive in archives {
            durable_archive(
                &mut self.disk,
                &root,
                &archive.path,
                Some(&archive.submission),
            )
            .map_err(|e| error(&archive.path, e))?;
        }
        self.poisoned = false;
        Ok(())
    }
    /// Cross the archive barrier without writing; sync proves an earlier rename durable.
    /// A failure does not poison the handle because nothing was written.
    pub(super) fn resync_records(&mut self, paths: &[&Path]) -> Result<(), PublicationStoreError> {
        let root = self.root().to_owned();
        for path in paths {
            durable_archive(&mut self.disk, &root, path, None)
                .map_err(|e| archive_read_error(path, &e))?;
        }
        Ok(())
    }
    pub(super) fn inspect_selection_archives(
        &self,
        volume: &VolumeName,
        include_scope: Option<&str>,
        forbidden_id: Option<[u8; 16]>,
        failure: ReadFailure,
    ) -> Result<Vec<ArchiveRecord>, PublicationStoreError> {
        let archives = self.catalogue(volume, include_scope)?;
        if let Some(archive) = archives
            .iter()
            .find(|a| Some(a.submission.publication_id) == forbidden_id)
        {
            return Err(error(
                &archive.path,
                "archived publication identity already exists",
            ));
        }
        for live in self.enumerate(volume, failure)? {
            if let Some(archive) = archives
                .iter()
                .find(|a| a.submission.publication_id == live.submission.publication_id)
            {
                return Err(error(
                    &archive.path,
                    "archive and live publication share an identity; explicit abandonment retry required",
                ));
            }
        }
        Ok(archives)
    }
    pub(super) fn selection_archives(
        &mut self,
        volume: &VolumeName,
        include_scope: Option<&str>,
        forbidden_id: Option<[u8; 16]>,
    ) -> Result<Vec<ArchiveEvidence>, PublicationStoreError> {
        let archives = self.inspect_selection_archives(
            volume,
            include_scope,
            forbidden_id,
            retained_read_error,
        )?;
        self.establish_archives(&archives)?;
        Ok(archives.into_iter().map(ArchiveRecord::evidence).collect())
    }

    /// Check archived obligations for this scope and volume without re-establishing archives.
    pub(crate) fn require_settled_abandonments(
        &self,
        scope: &Scope,
        volume: &VolumeName,
    ) -> Result<(), PublicationStoreError> {
        let archives = self.inspect_selection_archives(volume, None, None, archive_read_error)?;
        require_settled_archives(
            archives
                .iter()
                .filter(|a| a.submission.scope == *scope)
                .map(|a| (a.path.as_path(), a.settled)),
        )
    }
    /// Select live state for an explicitly new publication after acknowledging
    /// that older archived work may still land. All ordinary live guards apply.
    /// # Errors
    /// Missing acknowledgement, archive/custody conflicts or live-load failure.
    pub fn load_for_new(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
        acknowledgement: MayLandAcknowledgement,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        self.acknowledge(acknowledgement)?;
        self.load_selected(scope, volume, true)
    }
    pub(super) fn acknowledge(
        &self,
        acknowledgement: MayLandAcknowledgement,
    ) -> Result<(), PublicationStoreError> {
        self.ready()?;
        if acknowledgement != MayLandAcknowledgement::Acknowledged {
            return Err(error(
                self.root(),
                "acknowledgement that publication may still land is required",
            ));
        }
        Ok(())
    }
    /// Inspect an exact archive, validating aliases and durability without advancing generation.
    /// # Errors
    /// Invalid digest, missing/corrupt evidence, conflicting aliases or a failed barrier.
    pub fn inspect_archive(
        &mut self,
        scope_digest: &str,
        volume: &VolumeName,
        id: [u8; 16],
    ) -> Result<ArchiveEvidence, PublicationStoreError> {
        let path = self.archive_path(scope_digest, volume, id, false)?;
        let settled = self.archive_path(scope_digest, volume, id, true)?;
        let archives = self.catalogue(volume, None)?;
        if !archives.iter().any(|a| a.path == path || a.path == settled) {
            return Err(missing(&path));
        }
        self.establish_archives(&archives)?;
        archives
            .into_iter()
            .filter(|a| a.path == path || a.path == settled)
            .try_fold(None, |found: Option<ArchiveRecord>, archive| match found {
                Some(found) if found.bytes != archive.bytes => Err(error(
                    &archive.path,
                    "conflicting archive acknowledgement bytes",
                )),
                Some(found) if found.settled => Ok(Some(found)),
                _ => Ok(Some(archive)),
            })?
            .map(ArchiveRecord::evidence)
            .ok_or_else(|| missing(&path))
    }
    /// Check an exact archive after catalogue validation without writing.
    /// # Errors
    /// Invalid digest, poison, or a malformed/corrupt relevant archive.
    pub fn archived(
        &self,
        scope_digest: &str,
        volume: &VolumeName,
        id: [u8; 16],
    ) -> Result<bool, PublicationStoreError> {
        let path = self.archive_path(scope_digest, volume, id, false)?;
        let settled = self.archive_path(scope_digest, volume, id, true)?;
        Ok(self
            .catalogue(volume, None)?
            .iter()
            .any(|a| a.path == path || a.path == settled))
    }
    /// List durable archive evidence for a volume, sorted by complete path.
    /// # Errors
    /// Any malformed claimant, relevant corrupt archive, custody or sync failure.
    pub fn list_archives(
        &mut self,
        volume: &VolumeName,
    ) -> Result<Vec<ArchiveEvidence>, PublicationStoreError> {
        let archives = self.catalogue(volume, None)?;
        for archive in &archives {
            let opened = self.disk.open_checked_record(&archive.path);
            opened.map_err(|e| archive_read_error(&archive.path, &e))?;
        }
        self.establish_archives(&archives)?;
        Ok(archives.into_iter().map(ArchiveRecord::evidence).collect())
    }
    /// Stop local continuation while preserving evidence; report but do not retain pin changes.
    /// # Errors
    /// Missing consent/target, completion, conflict, custody, generation or durability failure.
    #[expect(
        clippy::too_many_lines,
        reason = "one locked abandonment transaction includes observation of fresh generation and archival"
    )]
    pub fn abandon<'a>(
        &mut self,
        requested_scope: &Scope,
        volume: &VolumeName,
        id: [u8; 16],
        acknowledgement: impl Into<AbandonAcknowledgement<'a>>,
    ) -> Result<Abandonment, PublicationStoreError> {
        let acknowledgement = acknowledgement.into();
        self.ready()?;
        self.guard_discard(volume)?;
        if let AbandonAcknowledgement::MayLand(acknowledgement) = acknowledgement {
            self.acknowledge(acknowledgement)?;
        }
        let live = self.path(requested_scope, volume)?;
        let digest = requested_scope.digest().map_err(|e| error(&live, e))?;
        let proven = matches!(acknowledgement, AbandonAcknowledgement::Proven(..));
        let target = self.archive_path(&digest, volume, id, proven)?;
        let other = self.archive_path(&digest, volume, id, !proven)?;
        let mut path = target.clone();
        self.disk.walk_root(self.root())?;
        let publications = self.root().join("publications");
        for directory in [
            &publications,
            live.parent().ok_or_else(|| error(&live, "missing scope"))?,
        ] {
            match self.disk.directory(directory, true) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(missing(&path)),
                Err(e) => return Err(directory_open_error(directory, &e)),
            }
        }
        if self.read_exact(&path)?.is_none() && self.read_exact(&other)?.is_some() {
            path = other;
        }
        // A rename crash may leave the two canonical names on one inode. Prove
        // custody and the requested incomplete content before removing live.
        if let Some((dev, ino)) = same_inode_pair(&live, &path).map_err(|e| error(&path, e))? {
            let file = self
                .disk
                .open_checked_pair_record(&path, dev, ino)
                .map_err(|e| error(&path, e))?;
            let length = file.metadata().map_err(|e| error(&path, e))?.len();
            let bytes = read_bounded(file, length).map_err(|e| error(&path, e))?;
            let record = codec::decode(&bytes).map_err(|e| error(&path, e))?;
            matches_request(&record, requested_scope, volume, id, &path)?;
            acknowledgement.check(&record, &path)?;
            if record.is_complete() {
                return Err(error(&path, "complete publication cannot be archived"));
            }
            self.poisoned = true;
            remove_duplicate(&mut self.disk, &live).map_err(|e| error(&live, e))?;
        }
        let name = ArchiveName {
            volume: volume.clone(),
            publication_id: id,
            settled: path == self.archive_path(&digest, volume, id, true)?,
        };
        let archive = match self.read_exact(&path)? {
            Some(_) => Some(self.checked_archive(&path, &name)?),
            None => None,
        };
        let retained_live = self.read_exact(&live)?;
        if let Some(mut archive) = archive {
            matches_request(&archive.submission, requested_scope, volume, id, &path)?;
            acknowledgement.check(&archive.submission, &path)?;
            let duplicate = if let Some((record, bytes)) = &retained_live {
                if self.path(&record.scope, &record.volume)? != live {
                    return Err(error(&live, "live record disagrees with path"));
                }
                if record.publication_id == id {
                    if record.is_complete() || *bytes != archive.bytes {
                        return Err(error(&live, "conflicting archive and live bytes"));
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            };
            let plain = self.archive_path(&digest, volume, id, false)?;
            let plain_duplicate = if proven
                && plain != archive.path
                && let Some((_, bytes)) = self.read_exact(&plain)?
            {
                if bytes != archive.bytes {
                    return Err(error(&plain, "conflicting archive acknowledgement bytes"));
                }
                true
            } else {
                false
            };
            let root = self.root().to_owned();
            self.poisoned = true;
            durable_archive(&mut self.disk, &root, &path, Some(&archive.submission))
                .map_err(|e| error(&path, e))?;
            if duplicate {
                remove_duplicate(&mut self.disk, &live).map_err(|e| error(&live, e))?;
            }
            if proven && !archive.settled {
                move_archive(
                    &mut self.disk,
                    &path,
                    &target,
                    Some(&archive.submission),
                    acknowledgement.faults(),
                )
                .map_err(|e| error(&path, e))?;
                archive.path = target;
                archive.settled = true;
            }
            if plain_duplicate {
                remove_duplicate(&mut self.disk, &plain).map_err(|e| error(&plain, e))?;
            }
            self.poisoned = false;
            return Ok(abandonment(archive.evidence(), requested_scope));
        }
        let (mut record, _) = retained_live.ok_or_else(|| missing(&live))?;
        matches_request(&record, requested_scope, volume, id, &live)?;
        acknowledgement.check(&record, &live)?;
        if record.is_complete() {
            return Err(error(&live, "complete publication cannot be abandoned"));
        }
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or_else(|| error(&live, "generation exhausted"))?;
        #[cfg(feature = "publish-restart-tests")]
        crate::publish_restart::point("abandon-save", "before", &record)
            .map_err(|e| error(&live, e))?;
        let bytes = codec::encode(&record).map_err(|e| error(&live, e))?;
        let root = self.root().to_owned();
        self.poisoned = true;
        durable_replace(&mut self.disk, &root, &live, &bytes).map_err(|e| error(&live, e))?;
        archive_point(acknowledgement.faults(), "saved").map_err(|e| error(&live, e))?;
        let (reopened, reopened_bytes) = self.read_exact(&live)?.ok_or_else(|| missing(&live))?;
        matches_request(&reopened, requested_scope, volume, id, &live)?;
        if reopened_bytes != bytes {
            return Err(error(&live, "fresh generation changed before archival"));
        }
        #[cfg(feature = "publish-restart-tests")]
        crate::publish_restart::point("abandon-save", "after", &reopened)
            .map_err(|e| error(&live, e))?;
        move_archive(
            &mut self.disk,
            &live,
            &path,
            Some(&reopened),
            acknowledgement.faults(),
        )
        .map_err(|e| error(&path, e))?;
        self.poisoned = false;
        Ok(abandonment(
            ArchiveRecord {
                path,
                submission: reopened,
                bytes,
                settled: proven,
            }
            .evidence(),
            requested_scope,
        ))
    }
}
// Only a failure of the device, the filesystem or a kernel resource is worth a
// retry. Permission, custody and decode failures are the store's own state.
pub(super) fn archive_read_error(path: &Path, cause: &io::Error) -> PublicationStoreError {
    let mut result = error(path, cause);
    if matches!(
        cause.raw_os_error(),
        Some(
            libc::EIO
                | libc::ESTALE
                | libc::ENOMEM
                | libc::ENFILE
                | libc::EMFILE
                | libc::ETIMEDOUT
                | libc::ENOSPC
                | libc::EDQUOT
                | libc::EINTR
                | libc::EAGAIN
        )
    ) {
        result.kind = PublicationStoreErrorKind::Io;
    }
    result
}
fn missing(path: &Path) -> PublicationStoreError {
    let mut e = error(path, "no matching retained publication");
    e.kind = PublicationStoreErrorKind::MissingPublication;
    e
}
fn matches_request(
    record: &Submission,
    scope: &Scope,
    volume: &VolumeName,
    id: [u8; 16],
    path: &Path,
) -> Result<(), PublicationStoreError> {
    if record.scope.digest().map_err(|e| error(path, e))?
        != scope.digest().map_err(|e| error(path, e))?
        || record.scope.authority_base != scope.authority_base
        || record.scope.credential_context != scope.credential_context
        || record.volume != *volume
        || record.publication_id != id
    {
        return Err(error(
            path,
            "requested scope, volume or publication identity mismatch",
        ));
    }
    Ok(())
}
fn abandonment(archive: ArchiveEvidence, requested: &Scope) -> Abandonment {
    let pin_difference = (archive.submission.scope.pins != requested.pins).then(|| PinDifference {
        retained: archive.submission.scope.pins.clone(),
        configured: requested.pins.clone(),
    });
    Abandonment {
        archive,
        pin_difference,
    }
}
fn same_inode_pair(live: &Path, archive: &Path) -> io::Result<Option<(u64, u64)>> {
    let stat = |path| match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    };
    let (Some(l), Some(a)) = (stat(live)?, stat(archive)?) else {
        return Ok(None);
    };
    Ok((l.is_file()
        && a.is_file()
        && l.dev() == a.dev()
        && l.ino() == a.ino()
        && l.nlink() == 2
        && a.nlink() == 2)
        .then_some((a.dev(), a.ino())))
}
pub(super) fn durable_archive<F: Persistence>(
    fs: &mut F,
    root: &Path,
    path: &Path,
    record: Option<&Submission>,
) -> io::Result<()> {
    #[cfg(not(feature = "publish-restart-tests"))]
    let _ = record;
    let scope = path
        .parent()
        .ok_or_else(|| io::Error::other("missing scope"))?;
    let publications = scope
        .parent()
        .ok_or_else(|| io::Error::other("missing publications"))?;
    let parent = root.parent().unwrap_or(root);
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("archive-marker-sync", "before", record)?;
    fs.sync_marker(root)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("archive-marker-sync", "after", record)?;
    for (cut, directory) in [
        ("archive-root-sync", root),
        ("archive-parent-sync", parent),
        ("archive-publications-sync", publications),
        ("archive-scope-sync", scope),
    ] {
        #[cfg(not(feature = "publish-restart-tests"))]
        let _ = cut;
        #[cfg(feature = "publish-restart-tests")]
        crate::publish_restart::persistence_point(cut, "before", record)?;
        fs.sync_directory(directory)?;
        #[cfg(feature = "publish-restart-tests")]
        crate::publish_restart::persistence_point(cut, "after", record)?;
    }
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("archive-open", "before", record)?;
    let file = fs.open_record(path)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("archive-open", "after", record)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("archive-file-sync", "before", record)?;
    fs.sync_file(&file)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("archive-file-sync", "after", record)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("archive-final-sync", "before", record)?;
    fs.sync_directory(scope)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("archive-final-sync", "after", record)?;
    Ok(())
}
pub(super) fn move_archive<F: Persistence>(
    fs: &mut F,
    live: &Path,
    archive: &Path,
    record: Option<&Submission>,
    faults: Option<&crate::FaultControl>,
) -> io::Result<()> {
    #[cfg(not(feature = "publish-restart-tests"))]
    let _ = record;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("archive-rename", "before", record)?;
    fs.rename_no_replace(live, archive)?;
    archive_point(faults, "renamed")?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("archive-rename", "after", record)?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("archive-sync", "before", record)?;
    fs.sync_directory(
        archive
            .parent()
            .ok_or_else(|| io::Error::other("missing scope"))?,
    )?;
    archive_point(faults, "synced")?;
    #[cfg(feature = "publish-restart-tests")]
    crate::publish_restart::persistence_point("archive-sync", "after", record)?;
    Ok(())
}
fn archive_point(faults: Option<&crate::FaultControl>, phase: &'static str) -> io::Result<()> {
    if faults.is_some_and(|f| f.point("recover.archive", phase, 0).is_some()) {
        return Err(io::Error::other("injected archive fault"));
    }
    Ok(())
}
pub(super) fn remove_duplicate<F: Persistence>(fs: &mut F, live: &Path) -> io::Result<()> {
    fs.unlink(live)?;
    fs.sync_directory(
        live.parent()
            .ok_or_else(|| io::Error::other("missing scope"))?,
    )
}

impl Disk {
    fn open_checked_pair_record(&self, path: &Path, dev: u64, ino: u64) -> io::Result<File> {
        let file = fsguard::open_regular_read(path)?;
        let meta = file.metadata()?;
        if meta.nlink() != 2 || meta.dev() != dev || meta.ino() != ino {
            return Err(io::Error::other(
                "archive is no longer the exact two-link inode",
            ));
        }
        protected(&file, path, self.euid, Some(0o600))?;
        Ok(file)
    }
    pub(super) fn open_archive_record(&self, path: &Path) -> io::Result<File> {
        let leaf = path
            .file_name()
            .ok_or_else(|| io::Error::other("archive filename"))?;
        if let Some(name) = ArchiveName::parse(leaf.as_bytes()).map_err(io::Error::other)? {
            let live = path.with_file_name(format!("{}.sub", name.volume.as_str()));
            let other = path.with_file_name(
                ArchiveName {
                    settled: !name.settled,
                    ..name
                }
                .file_name(),
            );
            if let Some((dev, ino)) =
                same_inode_pair(&live, path)?.or(same_inode_pair(&other, path)?)
            {
                return self.open_checked_pair_record(path, dev, ino);
            }
        }
        self.open_checked_record(path)
    }
    pub(super) fn open_checked_record(&self, path: &Path) -> io::Result<File> {
        let file = fsguard::open_sole_regular_read(path, "a retained submission")?;
        protected(&file, path, self.euid, Some(0o600))?;
        Ok(file)
    }
    pub(super) fn native_move(&self, from: &Path, to: &Path) -> io::Result<()> {
        let scope = from
            .parent()
            .ok_or_else(|| io::Error::other("missing scope"))?;
        if to.parent() != Some(scope) {
            return Err(io::Error::other("archive must share live parent"));
        }
        let directory = self.directory(scope, true)?;
        let from = CString::new(
            from.file_name()
                .ok_or_else(|| io::Error::other("missing live name"))?
                .as_bytes(),
        )?;
        let to = CString::new(
            to.file_name()
                .ok_or_else(|| io::Error::other("missing archive name"))?
                .as_bytes(),
        )?;
        // Both leaf names resolve within the opened, validated scope directory.
        native_no_replace(&directory, &from, &to)
    }
}
#[cfg(target_os = "linux")]
#[expect(
    unsafe_code,
    reason = "native descriptor-relative no-replace rename under the borrowed exclusive store lock; validated shared scope descriptor and owned NUL-terminated leaf names"
)]
pub(crate) fn native_no_replace(directory: &File, from: &CString, to: &CString) -> io::Result<()> {
    // SAFETY: directory is an open validated scope; both pointers are owned,
    // NUL-terminated strings alive throughout the syscall. No pointer is retained.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    rename_result(result)
}
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "native descriptor-relative exclusive rename under the borrowed store lock with the validated shared scope descriptor and owned NUL-terminated leaf names"
)]
pub(crate) fn native_no_replace(directory: &File, from: &CString, to: &CString) -> io::Result<()> {
    // SAFETY: directory is an open validated scope; both pointers refer to owned
    // NUL-terminated leaf names alive throughout the call. No pointer is retained.
    let result = unsafe {
        libc::renameatx_np(
            directory.as_raw_fd(),
            from.as_ptr(),
            directory.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    rename_result(result.into())
}
fn rename_result(result: libc::c_long) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
