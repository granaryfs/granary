// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
// @file-disposition: STAYS — Frozen boundary binding, read-only classification and its operator evidence rows.

//! Bind the archived journal and retained publications to the verified authority history.

use super::{Action, DiscardError, Inventory, Refusal, Selection, Tuple, Walk, disk, run_selected};
use crate::{
    HttpStore,
    recovery::{self, AuthorityTransport, NoWriteProof, ProbeOutcome, RecoveryError},
};
use granary_core::{
    hash::GrainId,
    overlay_discard::{DiscardName, hex},
    overlay_journal::{self as j, JournalEnd, Record, WriterRecord},
    retained_archive::{ArchiveName, is_scope_digest},
    retained_submission::{self as p, Scope, Submission},
    root::VolumeName,
};
use granary_store::crypto::TrustedKeys;
use std::{collections::BTreeMap, ffi::OsStr, fmt, os::unix::ffi::OsStrExt as _, path::Path};

use Refusal::{RemoteIntegrity as INTEGRITY, Unresolved as UNRESOLVED};

/// Frozen evidence copied from one exact discard claim under the existing store lock.
#[derive(Debug)]
pub struct ArchiveReconciliation {
    scope: [u8; 32],
    name: DiscardName,
    publications: BTreeMap<[u8; 16], Option<Publication>>,
    publication_scope_absent: bool,
}

#[derive(Debug)]
struct Boundary {
    publication: [u8; 16],
    candidate: GrainId,
    witness: Option<(u64, GrainId)>,
}

#[derive(Debug)]
struct Publication {
    record: Submission,
    attempts: u64,
    witness: Option<(u64, GrainId)>,
    settled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Landed,
    NotLanded,
    Unresolved,
    Integrity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Landing {
    candidate: GrainId,
    seq: u64,
    stored: GrainId,
}

/// A versioned TSV observation about one journal-bound publication.
#[derive(Debug)]
pub struct ReconcileRow {
    scope: [u8; 32],
    name: DiscardName,
    publication: [u8; 16],
    status: Status,
    landing: Option<Landing>,
}

impl ReconcileRow {
    /// The corresponding runtime refusal, if the evidence did not settle.
    #[must_use]
    pub fn refusal(&self) -> Option<&'static str> {
        self.refusal_reason().map(Refusal::as_str)
    }

    /// The closed reason, if the evidence did not settle.
    #[must_use]
    pub const fn refusal_reason(&self) -> Option<Refusal> {
        match self.status {
            Status::Landed | Status::NotLanded => None,
            Status::Unresolved => Some(UNRESOLVED),
            Status::Integrity => Some(INTEGRITY),
        }
    }
}

impl fmt::Display for ReconcileRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = match self.status {
            Status::Landed => "landed",
            Status::NotLanded => "not-landed",
            Status::Unresolved => "unresolved",
            Status::Integrity => "integrity",
        };
        write!(
            f,
            "overlay-reconcile-v1\t{}\t{}\t{}\t{}\t{}\t{status}",
            hex(&self.scope),
            self.name.volume.as_str(),
            hex(&self.name.writer),
            hex(&self.name.incarnation),
            hex(&self.publication),
        )?;
        if let Some(landing) = self.landing {
            writeln!(
                f,
                "\t{}\t{}\t{}",
                landing.candidate, landing.seq, landing.stored
            )
        } else {
            writeln!(f, "\t-\t-\t-")
        }
    }
}

impl ArchiveReconciliation {
    /// Verify the exact claim and read its frozen boundary and retained records.
    ///
    /// # Errors
    /// The selected store is busy or untrusted, the claim is absent, pending or
    /// changed, or the evidence cannot bind the journal or settle an archive
    /// with no publication boundaries.
    pub fn open(
        path: &Path,
        scope: [u8; 32],
        volume: &VolumeName,
        tuple: ([u8; 16], [u8; 32]),
    ) -> Result<Self, DiscardError> {
        let mut publications = BTreeMap::new();
        let mut publication_scope_absent = false;
        let mut read = |selection: &Selection, tree: &Inventory, records: &Inventory| {
            publications = read_publications(selection, tree, records, scope, volume, tuple)?;
            publication_scope_absent =
                publications.is_empty() && selection.publication_scope.is_none();
            Ok(())
        };
        let row = run_selected(
            path,
            scope,
            volume,
            Action::Reconcile(tuple, &mut read),
            &mut |_, _| Err(super::DURABILITY),
            |_, _, _| Err(std::io::Error::other("archive selection is read-only")),
        )
        .map_err(DiscardError)?;
        Ok(Self {
            scope,
            name: row.name,
            publications,
            publication_scope_absent,
        })
    }

    /// The verified archive had no publication boundaries and settled locally.
    #[must_use]
    pub fn is_settled_locally(&self) -> bool {
        self.publications.is_empty()
    }

    /// The archive settled locally while the selected publication scope directory was absent.
    #[must_use]
    pub fn settled_without_publication_scope(&self) -> bool {
        self.publication_scope_absent
    }

    /// Verify the authenticated route and probe each publication's possibly-written slots.
    ///
    /// # Cancellation safety
    /// Cancelling abandons only observations. The evidence and authority are unchanged.
    pub async fn reconcile(
        &self,
        remote: &HttpStore,
        route: &Scope,
        keys: &TrustedKeys,
    ) -> Vec<ReconcileRow> {
        self.probe(
            remote,
            remote.intent_scope_matches(route).then_some(route),
            keys,
        )
        .await
    }

    async fn probe(
        &self,
        remote: &impl AuthorityTransport,
        route: Option<&Scope>,
        keys: &TrustedKeys,
    ) -> Vec<ReconcileRow> {
        let mut rows = Vec::with_capacity(self.publications.len());
        for (&publication, evidence) in &self.publications {
            let (status, landing) = match evidence {
                Some(evidence) if route == Some(&evidence.record.scope) => {
                    evidence.classify(remote, keys).await
                }
                _ => (Status::Unresolved, None),
            };
            rows.push(ReconcileRow {
                scope: self.scope,
                name: self.name.clone(),
                publication,
                status,
                landing,
            });
        }
        rows
    }
}

fn read_publications(
    selection: &Selection,
    tree: &Inventory,
    records: &Inventory,
    scope: [u8; 32],
    volume: &VolumeName,
    tuple: Tuple,
) -> Result<BTreeMap<[u8; 16], Option<Publication>>, Refusal> {
    let read = |leaf, max| {
        Walk::bound_file(selection.mount, &selection.area, leaf, max, tree)?.ok_or(UNRESOLVED)
    };
    let writer = WriterRecord::decode(&read("writer", 133)?).map_err(|_| UNRESOLVED)?;
    let mut boundaries = BTreeMap::<u64, Boundary>::new();
    let scan = j::scan_journal_with(
        &read("journal", j::JOURNAL_MAX)?,
        |index, record| match record {
            Record::CommitBoundary {
                publication_id,
                candidate,
                ..
            }
            | Record::ProjectedBoundary {
                publication_id,
                candidate,
                ..
            } => {
                boundaries.insert(
                    index,
                    Boundary {
                        publication: *publication_id,
                        candidate: *candidate,
                        witness: None,
                    },
                );
            }
            Record::LandedCommit {
                boundary_seq,
                landed_seq,
                landed_root,
            } => {
                if let Some(boundary) = boundaries.get_mut(boundary_seq) {
                    boundary.witness = Some((*landed_seq, *landed_root));
                }
            }
            _ => {}
        },
    )
    .map_err(|_| UNRESOLVED)?;
    if scan.end != JournalEnd::Clean
        || scan.check_writer(&writer).is_err()
        || writer.writer != tuple.0
    {
        return Err(UNRESOLVED);
    }
    if boundaries.is_empty() {
        settle_without_boundaries(selection, records, scope, volume)?;
        return Ok(BTreeMap::new());
    }
    let mut publications = BTreeMap::new();
    for boundary in boundaries.into_values() {
        let id = boundary.publication;
        match publications.entry(id) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                entry.insert(None);
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                let attempts = scan
                    .state
                    .commit_progress(&id)
                    .map_or(0, |progress| progress.attempts);
                entry.insert(bind_publication(
                    selection, records, volume, tuple.0, &boundary, attempts,
                )?);
            }
        }
    }
    Ok(publications)
}

/// After custody, tuple and journal checks pass with no publication boundary,
/// settle only if the selected live record is absent or complete with no
/// possibly written candidate above the winner, every selected archive is
/// settled and consistent, and no other scope retains a record for the volume.
/// Ownership fences and requests do not change this publication proof.
fn settle_without_boundaries(
    selection: &Selection,
    inventory: &Inventory,
    scope: [u8; 32],
    volume: &VolumeName,
) -> Result<(), Refusal> {
    let live = format!("{}.sub", volume.as_str());
    if let Some(dir) = &selection.publication_scope {
        let read = |leaf: &str| {
            Walk::bound_file(selection.mount, dir, leaf, p::MAX_BYTES, inventory)?
                .map(|bytes| p::decode(&bytes).map_err(|_| UNRESOLVED))
                .transpose()
        };
        let record = read(&live)?;
        if let Some(record) = &record {
            let p::Phase::Complete(done) = &record.phase else {
                return Err(UNRESOLVED);
            };
            if record
                .candidates
                .iter()
                .any(|candidate| candidate.seq > done.seq && !candidate.evidence.never_decided())
            {
                return Err(UNRESOLVED);
            }
        }
        for (leaf, _) in &inventory.entries {
            let Some(archive) = ArchiveName::parse(leaf).map_err(|_| UNRESOLVED)? else {
                continue;
            };
            let leaf = std::str::from_utf8(leaf).map_err(|_| UNRESOLVED)?;
            let archived = read(leaf)?.ok_or(UNRESOLVED)?;
            if !archive.settled
                || archived.is_complete()
                || record
                    .as_ref()
                    .is_some_and(|live| live.publication_id == archive.publication_id)
            {
                return Err(UNRESOLVED);
            }
        }
    }
    if let Some(publications) = &selection.publications {
        let selected = hex(&scope);
        for name in disk::names(publications).map_err(|_| UNRESOLVED)? {
            if name == OsStr::new(&selected) || !is_scope_digest(name.as_bytes()) {
                continue;
            }
            let other = disk::directory(publications, &name, selection.mount)
                .map_err(|_| UNRESOLVED)?
                .ok_or(UNRESOLVED)?;
            for leaf in disk::names(&other).map_err(|_| UNRESOLVED)? {
                let archive = ArchiveName::parse(leaf.as_bytes()).map_err(|_| UNRESOLVED)?;
                if leaf == OsStr::new(&live) || archive.is_some_and(|a| &a.volume == volume) {
                    return Err(UNRESOLVED);
                }
            }
        }
    }
    Ok(())
}

fn bind_publication(
    selection: &Selection,
    inventory: &Inventory,
    volume: &VolumeName,
    writer: [u8; 16],
    boundary: &Boundary,
    attempts: u64,
) -> Result<Option<Publication>, Refusal> {
    let Some(dir) = &selection.publication_scope else {
        return Ok(None);
    };
    let read = |leaf: &str| Walk::bound_file(selection.mount, dir, leaf, p::MAX_BYTES, inventory);
    let mut owned = None;
    let mut settled = false;
    for (leaf, archive) in std::iter::once((format!("{}.sub", volume.as_str()), None)).chain(
        [false, true].into_iter().map(|settled| {
            (
                ArchiveName {
                    volume: volume.clone(),
                    publication_id: boundary.publication,
                    settled,
                }
                .file_name(),
                Some(settled),
            )
        }),
    ) {
        let Some(bytes) = read(&leaf)? else { continue };
        let record = p::decode(&bytes).map_err(|_| UNRESOLVED)?;
        if record.publication_id != boundary.publication {
            continue;
        }
        if record.frozen.writer_identity != writer
            || GrainId::of(&record.frozen.initial_root) != boundary.candidate
            || archive.is_some() && record.is_complete()
            || owned.as_ref().is_some_and(|(prior, _)| *prior != bytes)
        {
            return Ok(None);
        }
        settled |= archive == Some(true);
        owned = Some((bytes, record));
    }
    Ok(owned.map(|(_, record)| Publication {
        record,
        attempts,
        witness: boundary.witness,
        settled,
    }))
}

impl Publication {
    async fn classify(
        &self,
        remote: &impl AuthorityTransport,
        keys: &TrustedKeys,
    ) -> (Status, Option<Landing>) {
        let deferred = recovery::deferred_answer_pending(&self.record);
        if NoWriteProof::from_submission(&self.record, self.attempts).is_some() {
            return (
                if deferred || self.witness.is_some() {
                    Status::Unresolved
                } else {
                    Status::NotLanded
                },
                None,
            );
        }
        let outcome = recovery::probe_archive(
            remote,
            &self.record,
            self.attempts,
            self.witness.map(|(seq, _)| seq),
            keys,
        )
        .await;
        match outcome {
            Ok(ProbeOutcome::Landed {
                candidate,
                stored_id,
                ..
            }) => {
                let receipt = match &self.record.phase {
                    p::Phase::Complete(done) => done.receipt,
                    _ => None,
                };
                let status = if self.settled
                    || self
                        .witness
                        .is_some_and(|w| w != (candidate.seq, stored_id))
                    || receipt
                        .is_some_and(|r| (r.root_seq, r.stored_id) != (candidate.seq, stored_id))
                {
                    Status::Integrity
                } else if deferred {
                    Status::Unresolved
                } else {
                    Status::Landed
                };
                (
                    status,
                    Some(Landing {
                        candidate: candidate.id,
                        seq: candidate.seq,
                        stored: stored_id,
                    }),
                )
            }
            Ok(ProbeOutcome::NeverLanded(_))
                if self.record.is_complete() || self.witness.is_some() =>
            {
                (Status::Integrity, None)
            }
            Ok(ProbeOutcome::NeverLanded(_)) if !deferred => (Status::NotLanded, None),
            Err(RecoveryError::RemoteIntegrity(_)) => (Status::Integrity, None),
            _ => (Status::Unresolved, None),
        }
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::{archive_publication_bindings, probe_archive_rows};
