// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Read-only settlement of candidates that may have reached the authority.

use super::{AuthorityTransport, RecoveryError, coordinator::classify_deferred_read};
use granary_core::{
    hash::GrainId,
    retained_submission::{self, Scope, Submission},
    root,
    rootstore::{RootStore, RootStoreError},
};
use granary_store::crypto::{self, TrustedKeys};
use std::collections::{BTreeMap, BTreeSet};

/// Probe-only chain evidence binding the complete possibly-written set and
/// the journal's dispatch count.
#[derive(Debug)]
pub struct NeverLandedProof {
    publication: [u8; 16],
    candidate: GrainId,
    attempts: u64,
    scope: Scope,
    candidates: Vec<(u64, GrainId)>,
}
impl NeverLandedProof {
    pub(crate) fn matches(&self, publication: [u8; 16], candidate: GrainId, attempts: u64) -> bool {
        (self.publication, self.candidate, self.attempts) == (publication, candidate, attempts)
    }
    pub(crate) fn matches_submission(&self, record: &Submission) -> bool {
        !record.is_complete()
            && self.scope == record.scope
            && self.matches(
                record.publication_id,
                GrainId::of(&record.frozen.initial_root),
                self.attempts,
            )
            && self.candidates == possibly_written(record)
    }
}

#[derive(Debug)]
pub enum ProbeOutcome {
    Landed {
        candidate: retained_submission::Candidate,
        stored_root: Vec<u8>,
        stored_id: GrainId,
    },
    NeverLanded(NeverLandedProof),
    Unresolved {
        seq: u64,
    },
}

#[derive(Debug)]
pub(super) struct VerifiedLanding {
    pub(super) candidate: retained_submission::Candidate,
    pub(super) stored_root: Vec<u8>,
    pub(super) stored_id: GrainId,
}

#[derive(Debug)]
pub(super) struct VerifiedChain {
    pub(super) landing: Option<VerifiedLanding>,
    pub(super) occupants: Vec<(u64, GrainId)>,
}

pub(super) enum ChainReadError<E> {
    Missing,
    Read(E),
}

/// Walk the publisher-verified chain for only the possibly-written set.
/// Return the highest matching candidate with its stored envelope after the walk.
/// # Errors
/// Invalid retained input, failed reads or unverifiable chain evidence.
/// # Cancellation safety
/// Dropping abandons reads; the probe has no journal or mutating operation.
pub async fn probe_submission<T: AuthorityTransport>(
    remote: &T,
    record: &Submission,
    attempts: u64,
    keys: &TrustedKeys,
) -> Result<ProbeOutcome, RecoveryError> {
    retained_submission::validate(record)?;
    if possibly_written_candidates(record).next().is_none() {
        return Err(RecoveryError::Invalid(
            "probe has no possibly-written candidates",
        ));
    }
    if record.is_complete() {
        return Err(RecoveryError::Invalid(
            "probe requires incomplete submission",
        ));
    }
    probe_candidates(remote, record, attempts, keys, ProbeMode::Recovery, |seq| {
        remote.probe_root_once(record.volume.as_str(), seq)
    })
    .await
}

/// Recover a terminal candidate's stored envelope without changing Completion.
/// A journalled landing pins the exact stored id; it is never reselected.
/// No envelope is returned while the listing is behind the completed seq.
pub(crate) async fn refetch_landing<T: RootStore>(
    remote: &T,
    record: &Submission,
    expected: Option<(u64, GrainId)>,
    keys: &TrustedKeys,
) -> Result<Option<(Vec<u8>, GrainId)>, RecoveryError> {
    if !record.is_complete() {
        return Err(RecoveryError::Invalid(
            "landing requires complete submission",
        ));
    }
    match probe_candidates(remote, record, 0, keys, ProbeMode::Recovery, |seq| {
        remote.get_root(record.volume.as_str(), seq)
    })
    .await?
    {
        ProbeOutcome::Landed {
            candidate,
            stored_root,
            stored_id,
        } if expected.is_none_or(|expected| expected == (candidate.seq, stored_id)) => {
            Ok(Some((stored_root, stored_id)))
        }
        ProbeOutcome::Unresolved { .. } => Ok(None),
        _ => Err(RecoveryError::RemoteIntegrity("stored landing mismatch")),
    }
}

#[derive(Clone, Copy)]
enum ProbeMode {
    Recovery,
    Archive { witness_seq: Option<u64> },
}

/// Archive reads accept lagging or absent numbered roots as unresolved.
/// # Errors
/// Invalid retained input, unavailable head or contradictory verified evidence.
/// # Cancellation safety
/// Cancelling abandons only reads.
pub(crate) async fn probe_archive(
    remote: &impl AuthorityTransport,
    record: &Submission,
    attempts: u64,
    witness_seq: Option<u64>,
    keys: &TrustedKeys,
) -> Result<ProbeOutcome, RecoveryError> {
    probe_candidates(
        remote,
        record,
        attempts,
        keys,
        ProbeMode::Archive { witness_seq },
        |seq| remote.probe_root_once(record.volume.as_str(), seq),
    )
    .await
}

async fn probe_candidates<T: RootStore, F, Fut>(
    remote: &T,
    record: &Submission,
    attempts: u64,
    keys: &TrustedKeys,
    mode: ProbeMode,
    read: F,
) -> Result<ProbeOutcome, RecoveryError>
where
    F: Fn(u64) -> Fut,
    Fut: std::future::Future<Output = Result<Option<Vec<u8>>, RootStoreError>>,
{
    retained_submission::validate(record)?;
    let deferred = super::deferred_probe(record);
    let selected = selected_candidates(record, false);
    let candidates: Vec<_> = selected.iter().map(|c| (c.seq, c.id)).collect();
    let candidate_floor = candidate_floor(record, false)?;
    let witness_seq = match mode {
        ProbeMode::Archive { witness_seq } => witness_seq,
        ProbeMode::Recovery => None,
    };
    let first = witness_seq.map_or(candidate_floor, |seq| seq.min(candidate_floor));
    let unresolved = deferred.map_or(first, |probe| probe.seq);
    let mut known = BTreeMap::new();
    if deferred.is_some() {
        for seq in candidate_seqs(record) {
            match read(seq).await {
                Ok(Some(bytes))
                    if u64::try_from(bytes.len()).is_ok_and(|len| len <= root::ROOT_MAX_BYTES) =>
                {
                    known.insert(seq, bytes);
                }
                Ok(None) => {}
                Err(error) if let Some(diagnostic) = classify_deferred_read(&error) => {
                    return Err(RecoveryError::RemoteIntegrity(diagnostic));
                }
                Ok(Some(_)) => return Err(RecoveryError::RemoteIntegrity("untrusted probe head")),
                Err(_) => return Ok(ProbeOutcome::Unresolved { seq: unresolved }),
            }
        }
    }
    let head = match remote.max_seq(record.volume.as_str()).await {
        Ok(head) => head,
        Err(_) if deferred.is_some() => return Ok(ProbeOutcome::Unresolved { seq: unresolved }),
        Err(error) => return Err(error.into()),
    };
    let head = known.last_key_value().map_or(head, |(seq, _)| {
        Some(head.map_or(*seq, |head| head.max(*seq)))
    });
    let Some(head) = head else {
        return Ok(ProbeOutcome::Unresolved { seq: unresolved });
    };
    if head < first || witness_seq.is_some_and(|seq| seq > head) {
        return Ok(ProbeOutcome::Unresolved { seq: unresolved });
    }
    let verified = match walk_chain(record, false, head, first, &known, keys, read).await? {
        Ok(verified) => verified,
        Err(ChainReadError::Missing)
            if deferred.is_some() || matches!(mode, ProbeMode::Archive { .. }) =>
        {
            return Ok(ProbeOutcome::Unresolved { seq: unresolved });
        }
        Err(ChainReadError::Read(error))
            if deferred.is_some() || matches!(mode, ProbeMode::Archive { .. }) =>
        {
            if let Some(diagnostic) = classify_deferred_read(&error) {
                return Err(RecoveryError::RemoteIntegrity(diagnostic));
            }
            return Ok(ProbeOutcome::Unresolved { seq: unresolved });
        }
        Err(ChainReadError::Missing) => {
            return Err(RecoveryError::RemoteIntegrity("probe chain root missing"));
        }
        Err(ChainReadError::Read(error)) => return Err(error.into()),
    };
    if let Some(landed) = verified.landing {
        return Ok(ProbeOutcome::Landed {
            candidate: landed.candidate,
            stored_root: landed.stored_root,
            stored_id: landed.stored_id,
        });
    }
    if witness_seq.is_some() {
        return Err(RecoveryError::RemoteIntegrity(
            "journal landing witness mismatch",
        ));
    }
    if let Some(seq) = candidates
        .iter()
        .map(|(seq, _)| *seq)
        .filter(|seq| *seq > head)
        .min()
    {
        return Ok(ProbeOutcome::Unresolved { seq });
    }
    Ok(ProbeOutcome::NeverLanded(NeverLandedProof {
        publication: record.publication_id,
        candidate: GrainId::of(&record.frozen.initial_root),
        attempts,
        scope: record.scope.clone(),
        candidates,
    }))
}

fn selected_candidates(record: &Submission, live: bool) -> Vec<&retained_submission::Candidate> {
    match &record.phase {
        retained_submission::Phase::Complete(done) => record
            .candidates
            .iter()
            .filter(|c| (c.seq, c.id) == (done.seq, done.id))
            .collect(),
        _ if live => record.candidates.iter().collect(),
        _ => possibly_written_candidates(record).collect(),
    }
}

pub(super) fn candidate_seqs(record: &Submission) -> BTreeSet<u64> {
    record
        .candidates
        .iter()
        .map(|candidate| candidate.seq)
        .collect()
}

pub(super) fn candidate_floor(record: &Submission, live: bool) -> Result<u64, RecoveryError> {
    selected_candidates(record, live)
        .into_iter()
        .map(|candidate| candidate.seq)
        .min()
        .ok_or(RecoveryError::Invalid(
            "probe has no possibly-written candidates",
        ))
}

pub(super) async fn walk_chain<F, Fut, E>(
    record: &Submission,
    live: bool,
    head: u64,
    first: u64,
    known: &BTreeMap<u64, Vec<u8>>,
    keys: &TrustedKeys,
    mut read: F,
) -> Result<Result<VerifiedChain, ChainReadError<E>>, RecoveryError>
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Result<Option<Vec<u8>>, E>>,
{
    let selected = selected_candidates(record, live);
    let mut parent = None;
    let mut landing = None;
    let mut occupants = Vec::new();
    for seq in (first..=head).rev() {
        let fetched;
        let bytes = if let Some(bytes) = known.get(&seq) {
            bytes
        } else {
            fetched = match read(seq).await {
                Ok(Some(bytes)) => bytes,
                Ok(None) => return Ok(Err(ChainReadError::Missing)),
                Err(error) => return Ok(Err(ChainReadError::Read(error))),
            };
            &fetched
        };
        if !u64::try_from(bytes.len()).is_ok_and(|len| len <= root::ROOT_MAX_BYTES) {
            return Err(RecoveryError::RemoteIntegrity("untrusted probe head"));
        }
        let doc = if seq == head {
            crypto::check_head(bytes, record.volume.as_str(), seq, keys)
                .map_err(|_| RecoveryError::RemoteIntegrity("untrusted probe head"))?
        } else {
            root::check_link(parent, bytes, record.volume.as_str(), seq)
                .map_err(|_| RecoveryError::RemoteIntegrity("probe ancestry mismatch"))?
        };
        let stored_id = GrainId::of(bytes);
        if landing.is_none()
            && let Some(candidate) =
                matching_candidate(selected.iter().copied(), seq, stored_id, bytes)?
        {
            landing = Some(VerifiedLanding {
                candidate: candidate.clone(),
                stored_root: bytes.clone(),
                stored_id,
            });
        }
        occupants.push((seq, stored_id));
        parent = doc.parent;
    }
    Ok(Ok(VerifiedChain { landing, occupants }))
}

/// Read the exact stored envelope and bind it to a possibly written candidate.
pub(super) async fn read_landing_candidate<'a, T: RootStore>(
    remote: &T,
    record: &'a Submission,
    seq: u64,
    id: GrainId,
    keys: &TrustedKeys,
) -> Result<
    (
        crate::sync::PublishedRoot,
        &'a retained_submission::Candidate,
    ),
    super::RecoveryCommandError,
> {
    let root =
        crate::sync::PublishedRoot::read(remote, &record.volume, seq, Some(id), keys).await?;
    let matched = matching_candidate(
        possibly_written_candidates(record),
        seq,
        root.id(),
        root.bytes(),
    )?
    .ok_or_else(|| crate::sync::refused("SyncCommitLandingBinding"))?;
    Ok((root, matched))
}

pub(super) fn matching_candidate<'a>(
    candidates: impl Iterator<Item = &'a retained_submission::Candidate>,
    seq: u64,
    stored_id: GrainId,
    stored_root: &[u8],
) -> Result<Option<&'a retained_submission::Candidate>, RecoveryError> {
    let matching: Vec<_> = candidates
        .filter(|candidate| candidate.seq == seq && same_landing(&candidate.root, stored_root))
        .collect();
    let exact = matching
        .iter()
        .copied()
        .find(|candidate| candidate.id == stored_id);
    if exact.is_none() && matching.len() > 1 {
        return Err(RecoveryError::RemoteIntegrity("ambiguous probe candidate"));
    }
    Ok(exact.or_else(|| matching.first().copied()))
}

/// Complete envelopes bind the same landing only through their signed prefix.
pub(crate) fn same_landing(candidate: &[u8], stored: &[u8]) -> bool {
    root::signed_prefix(candidate)
        .ok()
        .zip(root::signed_prefix(stored).ok())
        .is_some_and(|(candidate, stored)| candidate == stored)
}

fn possibly_written(record: &Submission) -> Vec<(u64, GrainId)> {
    possibly_written_candidates(record)
        .map(|c| (c.seq, c.id))
        .collect()
}

pub(super) fn possibly_written_candidates(
    record: &Submission,
) -> impl Iterator<Item = &retained_submission::Candidate> {
    record
        .candidates
        .iter()
        .filter(|c| !c.evidence.never_decided())
}
