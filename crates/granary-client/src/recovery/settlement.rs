// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Archive-before-strip settlement under the recovering store's grant.

use super::{
    AuthorityTransport, NoWriteProof, ProbeOutcome, PublicationJournal as _, RecoveryCommandError,
    RejectionProof, deferred_probe, probe_submission,
};
use crate::observe::{RecoverEvent, recover};
use crate::{
    CoordinationError, OverlayIo, RecoveryCommit, RecoveryJournal, RecoveryRule, WritableStore,
};
use granary_core::{
    hash::GrainId, overlay_journal::JournalHeader, retained_submission::Submission,
    root::decode_root,
};
use granary_store::crypto::TrustedKeys;

/// Settle an open boundary on its journal base under this instance's grant.
/// Returns whether conflicting paths were reported.
/// # Errors
/// Ownership, unresolved/landed work, invalid evidence or persistence failure.
/// # Cancellation safety
/// Archival precedes replacement; restart re-derives its proof.
/// Resend reservations precede dispatch and retain the fence.
pub async fn settle_recovery_boundary<P: OverlayIo + Send + Sync, T: AuthorityTransport + Sync>(
    store: &mut WritableStore<P>,
    remote: &T,
    keys: &TrustedKeys,
    acknowledge_resend: Option<[u8; 16]>,
) -> Result<bool, RecoveryCommandError> {
    settle_recovery_boundary_reporting(store, remote, keys, acknowledge_resend, None)
        .await
        .map(|(conflict, _)| conflict)
}

#[expect(
    clippy::too_many_lines,
    reason = "one settlement keeps proof, completion, journal evidence and rejection ordering visible"
)]
pub(crate) async fn settle_recovery_boundary_reporting<
    P: OverlayIo + Send + Sync,
    T: AuthorityTransport + Sync,
>(
    store: &mut WritableStore<P>,
    remote: &T,
    keys: &TrustedKeys,
    acknowledge_resend: Option<[u8; 16]>,
    mut conflict_secure: Option<&mut (dyn granary_core::secure_random::SecureRandom + Send)>,
) -> Result<(bool, Option<String>), RecoveryCommandError> {
    store.check_recovery_owner()?;
    if store.recovery_rule()? == RecoveryRule::BoundaryUnrecorded {
        store.reconcile_unsubmitted_commit()?;
        return Ok((false, None));
    }
    let commits = store.recovery_commits()?;
    let [
        RecoveryCommit::Boundary {
            index,
            candidate,
            publication_id,
            ..
        },
    ] = commits.as_slice()
    else {
        return Err(CoordinationError::Refused("SyncCommitRecoveryRequired").into());
    };
    let progress = store
        .overlay_transaction(|t| t.commit_progress(*publication_id))?
        .ok_or(CoordinationError::Refused("SyncCommitRecoveryRequired"))?;
    let scope = store.snapshot().scope.clone();
    let volume = store.snapshot().volume.clone();
    let digest = scope
        .digest()
        .map_err(|_| CoordinationError::Refused("IntentScope"))?;
    let archived =
        store.publication_transaction(|j| j.archived(&digest, &volume, *publication_id))?;
    let mut archive = None;
    let mut record: Submission = store
        .publication_transaction(|j| {
            if archived {
                let evidence = j.inspect_archive(&digest, &volume, *publication_id)?;
                archive = Some(evidence.settled);
                Ok(Some(evidence.submission))
            } else {
                j.load(&scope, &volume)
            }
        })?
        .ok_or(CoordinationError::Refused("SyncCommitRecoveryRequired"))?;
    if store
        .fault_control()
        .point("recover.boundary", "loaded", 0)
        .is_some()
    {
        return Err(CoordinationError::Refused("SyncInjectedFault").into());
    }
    if record.publication_id != *publication_id
        || GrainId::of(&record.frozen.initial_root) != *candidate
    {
        return Err(CoordinationError::Refused("SyncCommitIdentity").into());
    }
    let admission = if !archived && !record.is_complete() {
        super::coordinator::saved_admission_refusal(&record)
            .map(|(refusal, candidate)| (crate::PublishResponse::Refused(refusal), candidate.seq))
    } else {
        None
    };
    let uncertain = super::probe::possibly_written_candidates(&record)
        .next()
        .is_some();
    let admission_error = |uncertain| {
        admission.and_then(|(answer, _)| {
            CoordinationError::admission_refusal(answer, *publication_id, uncertain)
        })
    };
    let missing = admission.filter(|(answer, _)| {
        *answer == crate::PublishResponse::Refused(crate::PublishRefusal::MissingReference)
    });
    let acknowledged = acknowledge_resend == Some(*publication_id);
    let missing_error = || {
        admission_error(false)
            .unwrap_or(CoordinationError::Refused("missing-reference"))
            .into()
    };
    if let Some((_, seq)) = missing
        && !uncertain
    {
        if !acknowledged {
            return Err(missing_error());
        }
        return resend(store, remote, keys, record, *index, progress.attempts, seq)
            .await
            .map(|()| (false, None));
    }
    let deferred = deferred_probe(&record);
    if archived
        && let Some(probe) = deferred
        && super::probe::possibly_written_candidates(&record)
            .next()
            .is_none()
    {
        return Err(unresolved(probe.seq, true));
    }
    // Possibly-written incomplete records need a read-only proof before live
    // deferred replay or conflict reports. Replay can change the bound evidence.
    let mut never_landed = false;
    let proof = loop {
        let mut deferred_unresolved = None;
        let proof = if let Some(proof) = NoWriteProof::from_submission(&record, progress.attempts) {
            Some(RejectionProof::NoWrite(proof))
        } else {
            let outcome = probe_submission(remote, &record, progress.attempts, keys).await?;
            match outcome {
                ProbeOutcome::NeverLanded(proof) => {
                    if archived && let Some(probe) = deferred {
                        return Err(unresolved(probe.seq, true));
                    }
                    if let Some((_, seq)) = missing {
                        if !acknowledged {
                            return Err(missing_error());
                        }
                        return resend(store, remote, keys, record, *index, progress.attempts, seq)
                            .await
                            .map(|()| (false, None));
                    }
                    never_landed = true;
                    Some(RejectionProof::NeverLanded(proof))
                }
                ProbeOutcome::Unresolved { seq } => {
                    if !archived && deferred_probe(&record).is_some() {
                        deferred_unresolved = Some(seq);
                        None
                    } else {
                        let error = unresolved(seq, archived);
                        if !archived && acknowledged {
                            return resend(
                                store,
                                remote,
                                keys,
                                record,
                                *index,
                                progress.attempts,
                                missing.map_or(seq, |(_, active_seq)| active_seq),
                            )
                            .await
                            .map(|()| (false, None));
                        }
                        let uncertain = super::probe::possibly_written_candidates(&record)
                            .next()
                            .is_some();
                        return Err(admission_error(uncertain).map_or(error, Into::into));
                    }
                }
                ProbeOutcome::Landed {
                    candidate,
                    stored_id,
                    ..
                } => {
                    if let Some(settled) = archive {
                        return Err(archived_landed(candidate.seq, settled));
                    }
                    let generation = record.generation;
                    record.generation = generation
                        .checked_add(1)
                        .ok_or(CoordinationError::Refused("SyncCommitExhausted"))?;
                    record.phase = granary_core::retained_submission::Phase::Complete(
                        granary_core::retained_submission::Completion {
                            seq: candidate.seq,
                            id: candidate.id,
                            root: candidate.root,
                            receipt: None,
                        },
                    );
                    record.current = None;
                    store.publication_transaction(|j| j.replace(generation, &record))?;
                    return finish_landed_boundary(
                        store,
                        *index,
                        candidate.seq,
                        stored_id,
                        archive,
                    )
                    .map(|()| (false, None));
                }
            }
        };
        if let Some(seq) = deferred_probe(&record).map(|probe| probe.seq)
            && !archived
        {
            let replay = {
                let mut journal = RecoveryJournal::new(store, remote, keys);
                if let Some(secure) = conflict_secure.as_mut() {
                    journal = journal.report_conflicts_with(&mut **secure);
                }
                super::coordinator::replay_deferred_answer(remote, &mut journal, &mut record, keys)
                    .await?
            };
            match replay {
                super::coordinator::DeferredReplay::Applied {
                    landing: Some((seq, stored_id)),
                } => {
                    return finish_landed_boundary(store, *index, seq, stored_id, archive)
                        .map(|()| (false, None));
                }
                super::coordinator::DeferredReplay::Applied { landing: None } => continue,
                super::coordinator::DeferredReplay::Unresolved => {
                    return Err(unresolved(seq, false));
                }
                super::coordinator::DeferredReplay::Invalid(error) => return Err(error.into()),
            }
        }
        if let Some(proof) = proof {
            break proof;
        }
        return Err(unresolved(
            deferred_unresolved.ok_or(super::RecoveryError::Invalid("deferred answer absent"))?,
            false,
        ));
    };
    let mut conflict = false;
    if !progress.fenced {
        let head = super::preparation::verify_base(remote, &volume, keys)
            .await?
            .into_state();
        let mut journal = RecoveryJournal::new(store, remote, keys);
        if let Some(secure) = conflict_secure.as_mut() {
            journal = journal.report_conflicts_with(&mut **secure);
        }
        conflict = match journal
            .rebase_manifest(&record.frozen, head.parent, head.seq)
            .await
        {
            Ok(_) => false,
            Err(error) if error.kind == crate::PublicationStoreErrorKind::Conflict => true,
            Err(error) => return Err(super::RecoveryError::Journal(error).into()),
        };
        if !archived && !conflict && !never_landed && admission.is_none() {
            return Ok((false, None));
        }
    }
    store.archive_rejection(&record, &proof)?;
    if progress.fenced {
        store.overlay_transaction(|t| t.replace_rejected_fenced(*index, *publication_id, proof))?;
    } else {
        store.overlay_transaction(|t| {
            t.replace_rejected_with_proof(*index, *publication_id, proof)
        })?;
    }
    recover(RecoverEvent::FenceSettled(
        if progress.fenced || !conflict {
            "released"
        } else {
            "stripped"
        },
    ));
    let uncertain = !never_landed
        && super::probe::possibly_written_candidates(&record)
            .next()
            .is_some();
    Ok((
        conflict,
        admission_error(uncertain).map(|error| error.to_string()),
    ))
}

/// Report settled refusals on the starting journal base after its boundary
/// was stripped. The journal no longer carries the publication identity.
/// # Errors
/// Failure to list the archives after durable completion.
pub(super) fn archived_admission_refusals<P: OverlayIo>(
    store: &mut WritableStore<P>,
    scope: &granary_core::retained_submission::Scope,
    header: &JournalHeader,
) -> Result<impl Iterator<Item = String>, CoordinationError> {
    let volume = store.snapshot().volume.clone();
    let archives = store.publication_transaction(|journal| journal.list_archives(&volume))?;
    let refusals = archives.into_iter().filter_map(move |archive| {
        let record = archive.submission;
        if !archive.settled || record.scope != *scope {
            return None;
        }
        let initial = decode_root(&record.frozen.initial_root).ok()?;
        if initial.writer_uuid != header.writer
            || initial.parent != Some(header.base_root)
            || initial.seq != header.base_seq + 1
        {
            return None;
        }
        let (refusal, _) = super::coordinator::saved_admission_refusal(&record)?;
        if !matches!(
            refusal,
            crate::PublishRefusal::InvalidReference | crate::PublishRefusal::PublishWorkLimit
        ) {
            return None;
        }
        CoordinationError::admission_refusal(
            crate::PublishResponse::Refused(refusal),
            record.publication_id,
            false,
        )
        .map(|error| error.to_string())
    });
    Ok(refusals)
}

fn finish_landed_boundary<P: OverlayIo>(
    store: &mut WritableStore<P>,
    boundary: u64,
    seq: u64,
    stored_id: GrainId,
    archive: Option<bool>,
) -> Result<(), RecoveryCommandError> {
    if let Some(settled) = archive {
        return Err(archived_landed(seq, settled));
    }
    store.overlay_transaction(|transaction| {
        transaction.record_landed(&crate::LandedProof {
            boundary_seq: boundary,
            landed_root: stored_id,
            landed_seq: seq,
            captured_entries: Vec::new(),
            entries: Vec::new(),
        })
    })?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn finish_landed_boundary_for_test<P: OverlayIo>(
    store: &mut WritableStore<P>,
    boundary: u64,
    seq: u64,
    stored_id: GrainId,
    archived: Option<bool>,
) -> Result<(), RecoveryCommandError> {
    finish_landed_boundary(store, boundary, seq, stored_id, archived)
}

fn archived_landed(seq: u64, settled: bool) -> RecoveryCommandError {
    recover(RecoverEvent::ArchivedLanded(seq));
    if settled {
        super::RecoveryError::RemoteIntegrity("archived non-landing contradicted").into()
    } else {
        CoordinationError::Refused("RecoveryArchivedLanded").into()
    }
}

fn unresolved(seq: u64, archived: bool) -> RecoveryCommandError {
    recover(RecoverEvent::Unresolved(seq));
    CoordinationError::Refused(if archived {
        "RecoveryArchivedUnresolved"
    } else {
        "RecoveryUnresolved"
    })
    .into()
}

/// One acknowledged exact attempt. Its reservation is durable before dispatch;
/// even a lost answer leaves the fence and all candidates for the next probe.
async fn resend<P: OverlayIo + Send + Sync, T: AuthorityTransport + Sync>(
    store: &mut WritableStore<P>,
    remote: &T,
    keys: &TrustedKeys,
    mut record: Submission,
    boundary: u64,
    attempts: u64,
    seq: u64,
) -> Result<(), RecoveryCommandError> {
    let missing = super::coordinator::saved_admission_refusal(&record)
        .filter(|(refusal, _)| *refusal == crate::PublishRefusal::MissingReference);
    let candidate = missing
        .map(|(_, candidate)| candidate)
        .filter(|candidate| candidate.seq == seq)
        .or_else(|| {
            super::probe::possibly_written_candidates(&record)
                .find(|c| c.role == granary_core::retained_submission::Role::Active && c.seq == seq)
        })
        .cloned()
        .ok_or(CoordinationError::Refused("RecoveryResendCandidate"))?;
    let next = attempts
        .checked_add(1)
        .ok_or(CoordinationError::Refused("SyncCommitExhausted"))?;
    store
        .overlay_transaction(|t| t.record_commit_attempt(boundary, record.publication_id, next))?;
    let answer = super::coordinator::send_once(
        remote,
        &mut RecoveryJournal::new(store, remote, keys),
        &mut record,
        &candidate,
        None,
        keys,
        |_| {},
        || recover(RecoverEvent::Resent(seq)),
    )
    .await?;
    let refusal = match answer {
        Ok(_) if record.is_complete() => "WritableRecoveryRequired",
        Ok(answer @ crate::PublishResponse::Refused(_)) => {
            let uncertain = super::probe::possibly_written_candidates(&record)
                .next()
                .is_some();
            return Err(CoordinationError::admission_refusal(
                answer,
                record.publication_id,
                uncertain,
            )
            .unwrap_or_else(|| {
                CoordinationError::Refused(
                    answer.identification().1.unwrap_or("RecoveryResendNoWrite"),
                )
            })
            .into());
        }
        Ok(answer) if answer.request_wrote_nothing() => "RecoveryResendNoWrite",
        Ok(_) | Err(super::coordinator::SendFailure::Deferred(_, _)) => "RecoveryResendPending",
        Err(super::coordinator::SendFailure::Authority(_)) => "RecoveryResendUnanswered",
        Err(super::coordinator::SendFailure::Invalid(_)) => "RecoveryResendInvalidAnswer",
    };
    Err(CoordinationError::Refused(refusal).into())
}
