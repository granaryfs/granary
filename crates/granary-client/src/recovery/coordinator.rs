// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::{
    AuthorityTransport, PublicationHandle, PublicationJournal, PublicationOutcome,
    PublicationResult, RecoveryError, RecoveryIntent, RecoveryParts, clear_pruned_response,
    compare, deferred_answer_pending, preparation, probe, retire,
    types::{DISPATCH_ATTEMPTS, MAX_UNAVAILABLE_EXEMPTIONS, charged_attempts},
};
use crate::{
    AuthorityError, CheckedConflict, OwnedCandidate, Policy, PublishRefusal, PublishRequest,
    PublishResponse, ServiceReason, StatusResponse,
    authority_transport::{answer_tuple, check_answer},
    observe::{RecoverEvent, recover},
};
use granary_core::{
    authlog::Epoch,
    authority_answer::{self, Bound, PublishAnswer},
    hash::GrainId,
    identity::WriterIdentity,
    retained_submission::{
        self as retained, Candidate, Completion, Evidence, FrozenIntent, LastResponse, Phase,
        Probe, ProbeReason, RequestIdentity, Role, Scope, Submission,
    },
    root::{self, VolumeName},
    rootstore::{RefusalKind, RootStoreError},
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// Obtain the coordinator's checked bootstrap without creating a publication.
/// A non-observed answer is returned as `RecoveryError::Bootstrap`; no POST or
/// journal mutation is possible. Callers still own route and write admission.
/// # Errors
/// Transport failure or a checked bootstrap refusal/service response.
/// # Cancellation safety
/// Dropping abandons only a read and creates no retained submission.
pub async fn bootstrap_publication<T: AuthorityTransport>(
    transport: &T,
    volume: &VolumeName,
) -> Result<crate::CheckedStatus, RecoveryError> {
    match transport.status_once(volume.as_str()).await? {
        StatusResponse::Observed(status) => Ok(status),
        other => Err(RecoveryError::Bootstrap(Box::new(other))),
    }
}

/// Prepare an explicitly new publication, after acquiring publication access and
/// harvesting into the borrowed journal's store. Existing pending state refuses
/// before bootstrap or uploads; use its handle with `resume_publication`.
/// # Errors
/// Journal refusal, bootstrap failure, unavailable entropy or invalid content/trust.
/// # Cancellation safety
/// Before the initial barrier no POST is eligible. Afterwards the retained phase
/// is authoritative and resuming never harvests source files.
pub async fn begin_publication<T: AuthorityTransport, J: PublicationJournal>(
    mut p: RecoveryParts<'_, T, J>,
    scope: Scope,
    volume: VolumeName,
    manifest: GrainId,
    policy: Policy,
) -> Result<PublicationResult, RecoveryError> {
    scope.digest()?;
    if policy.min_prefix_bits > 12 {
        return Err(RecoveryError::Invalid("invalid preparation policy"));
    }
    let retained_epoch = match p.journal.load(&scope, &volume)? {
        Some(Submission {
            phase: Phase::Complete(done),
            ..
        }) => done.epoch_knowledge(),
        Some(_) => return Err(RecoveryError::Invalid("publication is not complete")),
        None => None,
    };
    let status = bootstrap_publication(p.transport, &volume).await?;
    let epoch = retained_epoch
        .unwrap_or(status.observation().epoch)
        .to_bytes();
    let publication_id = draw(&mut p)?;
    let writer_identity = draw(&mut p)?;
    let operation = draw(&mut p)?;
    let base = preparation::verify_base(p.transport, &volume, p.publisher_keys).await?;
    let objects = preparation::closure(&mut p, &volume, manifest, None).await?;
    let prepared = crate::publish::prepare_from_state(
        p.transport,
        &objects.overlay(&*p.journal),
        manifest,
        crate::HarvestStats::default(),
        &volume,
        p.signer,
        &WriterIdentity::from_bytes(writer_identity),
        p.clock.now(),
        policy,
        base.into_state(),
    )
    .await?;
    let owned = OwnedCandidate::new(volume.as_str(), prepared.root_bytes.clone().into())
        .map_err(|_| RecoveryError::Invalid("prepared candidate"))?;
    let identity = RequestIdentity { epoch, operation };
    let mut record = Submission {
        generation: 1,
        publication_id,
        scope,
        volume,
        frozen: FrozenIntent {
            writer_identity,
            min_prefix_bits: policy.min_prefix_bits,
            initial_root: prepared.root_bytes,
        },
        current: Some(identity),
        candidates: vec![new_candidate(1, identity, &owned)],
        phase: Phase::Ready,
        last_response: None,
        unavailable_exemptions: 0,
    };
    #[cfg(feature = "publish-restart-tests")]
    restart_point("begin", "before", &record)?;
    p.journal.begin(&record)?;
    #[cfg(feature = "publish-restart-tests")]
    restart_point("begin", "after", &record)?;
    drive(&mut p, &mut record, false, None, RecoveryIntent::Continue).await
}

/// Retain and submit an already signed prepared root without constructing a
/// replacement. The caller supplies the adopted store writer; the verified head
/// must still be this root's own parent. Existing unresolved evidence refuses.
/// # Errors
/// Foreign writer/base, invalid signatures or closure, unresolved publication,
/// entropy, transport or persistence failure.
pub async fn begin_exact_publication<T: AuthorityTransport, J: PublicationJournal>(
    mut p: RecoveryParts<'_, T, J>,
    scope: Scope,
    volume: VolumeName,
    writer: [u8; 16],
    bytes: Vec<u8>,
) -> Result<PublicationResult, RecoveryError> {
    scope.digest()?;
    if p.journal
        .load(&scope, &volume)?
        .is_some_and(|r| !r.is_complete())
    {
        return Err(RecoveryError::Invalid("publication is not complete"));
    }
    let doc = granary_core::root::decode_root(&bytes)
        .map_err(|_| RecoveryError::Invalid("exact prepared root"))?;
    granary_store::crypto::check_head(&bytes, volume.as_str(), doc.seq, p.publisher_keys)
        .map_err(|_| RecoveryError::Invalid("exact prepared signature"))?;
    if doc.writer_uuid != writer {
        return Err(RecoveryError::Invalid("exact prepared writer"));
    }
    let status = bootstrap_publication(p.transport, &volume).await?;
    let base = preparation::verify_base(p.transport, &volume, p.publisher_keys)
        .await?
        .into_state();
    if doc.seq != base.seq || doc.parent != base.parent {
        return Err(RecoveryError::Invalid("exact prepared parent changed"));
    }
    let frozen = FrozenIntent {
        writer_identity: writer,
        min_prefix_bits: 0,
        initial_root: bytes.clone(),
    };
    preparation::reconstruct(&mut p, &volume, &frozen).await?;
    let owned = OwnedCandidate::new(volume.as_str(), bytes.into())
        .map_err(|_| RecoveryError::Invalid("exact prepared candidate"))?;
    let identity = RequestIdentity {
        epoch: status.observation().epoch.to_bytes(),
        operation: draw(&mut p)?,
    };
    let mut record = Submission {
        generation: 1,
        publication_id: draw(&mut p)?,
        scope,
        volume,
        frozen,
        current: Some(identity),
        candidates: vec![new_candidate(1, identity, &owned)],
        phase: Phase::Ready,
        last_response: None,
        unavailable_exemptions: 0,
    };
    p.journal.begin(&record)?;
    drive(&mut p, &mut record, true, None, RecoveryIntent::Continue).await
}

/// What an explicit recovery of a selected prepared root found or drove.
#[derive(Debug)]
pub enum SelectedPublication {
    /// The verified chain contains the prepared root or an equal manifest.
    Subsumed { by_seq: u64, by_root: GrainId },
    /// The verified chain does not reach the prepared root's parent.
    Stale,
    /// The prepared root, exact on its parent or merged onto the head.
    Driven(Box<PublicationResult>),
}

/// Classify a selected prepared root against the verified head before any
/// diff, then publish it exactly onto its unchanged parent, or merged against
/// that parent onto the head and signed with `writer`. The journal must hold
/// a recovered set, so no file grain outside the prepared root's delta is read.
/// # Errors
/// A journal without a recovered set, a writer other than the recovering
/// store's own, an unresolved publication, an untrusted or foreign prepared
/// root, a broken remote chain, a merge conflict, entropy, transport or
/// persistence failure.
pub async fn begin_selected_publication<T: AuthorityTransport, J: PublicationJournal>(
    mut p: RecoveryParts<'_, T, J>,
    scope: Scope,
    volume: VolumeName,
    writer: [u8; 16],
    bytes: Vec<u8>,
) -> Result<SelectedPublication, RecoveryError> {
    scope.digest()?;
    let Some(recovered) = p.journal.recovered() else {
        return Err(RecoveryError::Invalid(
            "selected publication needs a recovered set",
        ));
    };
    // Every candidate is signed as `writer`, and only the store's own writer
    // holds the grant its retained writes require.
    if recovered.writer != Some(writer) {
        return Err(RecoveryError::Invalid("selected writer"));
    }
    if p.journal
        .load(&scope, &volume)?
        .is_some_and(|r| !r.is_complete())
    {
        return Err(RecoveryError::Invalid("publication is not complete"));
    }
    let (prepared, head, relation) = selected_relation(
        p.transport,
        &mut *p.journal,
        p.publisher_keys,
        &volume,
        writer,
        &bytes,
    )
    .await?;
    match relation {
        crate::HeadRelation::Subsumed { by_seq, by_root } => {
            recover(subsumed_event(prepared.id(), head, by_seq, by_root));
            Ok(SelectedPublication::Subsumed { by_seq, by_root })
        }
        crate::HeadRelation::Stale => {
            recover(RecoverEvent::Stale);
            Ok(SelectedPublication::Stale)
        }
        crate::HeadRelation::Corrupt => {
            Err(RecoveryError::RemoteIntegrity("prepared root ancestry"))
        }
        crate::HeadRelation::NeedsRebase { chain } if chain.is_empty() => {
            let result = begin_exact_publication(p, scope, volume, writer, bytes).await?;
            report_landing(&result, None);
            Ok(SelectedPublication::Driven(Box::new(result)))
        }
        crate::HeadRelation::NeedsRebase { chain } => {
            // Candidate 1 must carry the frozen manifest, so the exact root
            // is retained unsent and the first drive cycle rebases it, as a
            // stale-base answer would: the merged candidate is the second.
            let status = bootstrap_publication(p.transport, &volume).await?;
            let identity = RequestIdentity {
                epoch: status.observation().epoch.to_bytes(),
                operation: draw(&mut p)?,
            };
            let mut record = Submission {
                generation: 1,
                publication_id: draw(&mut p)?,
                scope,
                volume,
                frozen: FrozenIntent {
                    writer_identity: writer,
                    min_prefix_bits: 0,
                    initial_root: bytes,
                },
                current: Some(identity),
                candidates: vec![new_candidate(1, identity, &prepared)],
                phase: Phase::Rebase,
                last_response: None,
                unavailable_exemptions: 0,
            };
            p.journal.begin(&record)?;
            let result = drive(
                &mut p,
                &mut record,
                false,
                Some(writer),
                RecoveryIntent::ExplicitRecovery,
            )
            .await?;
            report_landing(&result, Some(chain.len()));
            Ok(SelectedPublication::Driven(Box::new(result)))
        }
    }
}

/// Report a selected publication's landing, and the chain it was merged
/// across when it was rebased.
fn report_landing(result: &PublicationResult, chain_len: Option<usize>) {
    let PublicationOutcome::Landed(done) = &result.outcome else {
        return;
    };
    if let Ok(doc) = root::decode_root(&done.root) {
        recover(RecoverEvent::Landed(doc.seq));
    }
    if let Some(len) = chain_len.and_then(|len| u64::try_from(len).ok()) {
        recover(RecoverEvent::Rebased(len));
    }
}

pub(super) fn subsumed_event(
    prepared: GrainId,
    head: Option<u64>,
    by_seq: u64,
    by_root: GrainId,
) -> RecoverEvent {
    let relation = match (by_root == prepared, Some(by_seq) == head) {
        (false, _) => crate::SubsumedRelation::Later,
        (true, true) => crate::SubsumedRelation::Equal,
        (true, false) => crate::SubsumedRelation::Descendant,
    };
    RecoverEvent::Subsumed(relation, by_seq)
}

/// Classify the selected prepared root without creating a publication. The
/// head's structure and ancestor roots share the publication path's verification.
pub(super) async fn selected_relation<T: AuthorityTransport, J: PublicationJournal>(
    transport: &T,
    journal: &mut J,
    keys: &granary_store::crypto::TrustedKeys,
    volume: &VolumeName,
    writer: [u8; 16],
    bytes: &[u8],
) -> Result<(OwnedCandidate, Option<u64>, crate::HeadRelation), RecoveryError> {
    let doc = granary_core::root::decode_root(bytes)
        .map_err(|_| RecoveryError::Invalid("exact prepared root"))?;
    granary_store::crypto::check_head(bytes, volume.as_str(), doc.seq, keys)
        .map_err(|_| RecoveryError::Invalid("exact prepared signature"))?;
    if doc.writer_uuid != writer {
        return Err(RecoveryError::Invalid("exact prepared writer"));
    }
    let prepared = OwnedCandidate::new(volume.as_str(), bytes.to_vec().into())
        .map_err(|_| RecoveryError::Invalid("exact prepared candidate"))?;
    let state = preparation::verify_base(transport, volume, keys)
        .await?
        .into_state();
    let head = state.seq.checked_sub(1);
    let relation = match (state.parent, head) {
        (Some(head_id), Some(head_seq)) => {
            let head = transport
                .probe_root_once(volume.as_str(), head_seq)
                .await?
                .ok_or(RecoveryError::RemoteIntegrity("listed head missing"))?;
            if GrainId::of(&head) != head_id {
                return Err(RecoveryError::RemoteIntegrity("head changed"));
            }
            let manifest = root::decode_root(&head)
                .map_err(|_| RecoveryError::RemoteIntegrity("untrusted head"))?
                .manifest_root;
            preparation::load_structure(transport, journal, &state, manifest).await?;
            let head = crate::VerifiedBase::attach_validated(
                head,
                volume.as_str(),
                keys,
                &*journal,
                state,
            )
            .map_err(|_| RecoveryError::RemoteIntegrity("recovery head"))?;
            for seq in prepared.seq().saturating_sub(1).max(1)..head_seq {
                if let Some(bytes) = transport.probe_root_once(volume.as_str(), seq).await? {
                    journal.put_recovered(&GrainId::of(&bytes), &bytes)?;
                }
            }
            crate::classify_head(&prepared, &head, &*journal, keys)
        }
        _ if doc.seq == 1 && doc.parent.is_none() => {
            crate::HeadRelation::NeedsRebase { chain: vec![] }
        }
        _ => {
            return Err(RecoveryError::RemoteIntegrity(
                "empty authority for parented prepared root",
            ));
        }
    };
    Ok((prepared, head, relation))
}

/// Continue the exact publication selected by its local handle. Completion is
/// terminal. A loaded rebase or failed/interrupted probe requires an explicit
/// recovery invocation, which authorizes a fresh read cycle.
/// # Errors
/// Ownership, identity, format, persistence or entropy failure. No journal error
/// is followed by network work on the failed handle.
/// # Cancellation safety
/// The full-generation barriers record every send and catalogue probe first.
/// Cancellation therefore leaves retained uncertainty or an interrupted probe.
pub async fn resume_publication<T: AuthorityTransport, J: PublicationJournal>(
    p: RecoveryParts<'_, T, J>,
    handle: &PublicationHandle,
    intent: RecoveryIntent,
) -> Result<PublicationResult, RecoveryError> {
    resume_publication_mode(p, handle, intent, false, None).await
}

/// Resume an exact prepared candidate; changed parents require a separate
/// recovery decision. This entry never constructs or signs a replacement.
/// # Errors
/// Invalid retained writer/signatures, ownership, format, transport or persistence.
pub async fn resume_exact_publication<T: AuthorityTransport, J: PublicationJournal>(
    p: RecoveryParts<'_, T, J>,
    handle: &PublicationHandle,
    intent: RecoveryIntent,
) -> Result<PublicationResult, RecoveryError> {
    resume_publication_mode(p, handle, intent, true, None).await
}

pub(crate) async fn resume_store_publication<T: AuthorityTransport, J: PublicationJournal>(
    p: RecoveryParts<'_, T, J>,
    handle: &PublicationHandle,
    intent: RecoveryIntent,
    writer: [u8; 16],
) -> Result<PublicationResult, RecoveryError> {
    resume_publication_mode(p, handle, intent, false, Some(writer)).await
}

async fn resume_publication_mode<T: AuthorityTransport, J: PublicationJournal>(
    mut p: RecoveryParts<'_, T, J>,
    handle: &PublicationHandle,
    intent: RecoveryIntent,
    exact: bool,
    writer: Option<[u8; 16]>,
) -> Result<PublicationResult, RecoveryError> {
    let mut record = p
        .journal
        .load(&handle.scope, &handle.volume)?
        .ok_or(RecoveryError::Invalid("no retained publication"))?;
    retained::validate(&record)?;
    if record.publication_id != handle.publication_id
        || record.scope != handle.scope
        || record.volume != handle.volume
    {
        return Err(RecoveryError::Invalid("publication handle mismatch"));
    }
    if writer.is_none() {
        p.journal.check_generic_resume(&record)?;
        let initial =
            root::decode_root(&record.frozen.initial_root).map_err(retained::Error::from)?;
        for candidate in &record.candidates {
            let doc = root::decode_root(&candidate.root).map_err(retained::Error::from)?;
            if doc.manifest_root != initial.manifest_root {
                return Err(retained::Error::Invalid("frozen manifest").into());
            }
        }
    }
    if exact || writer.is_some() {
        for candidate in &record.candidates {
            let doc = granary_store::crypto::check_head(
                &candidate.root,
                record.volume.as_str(),
                candidate.seq,
                p.publisher_keys,
            )
            .map_err(|_| RecoveryError::Invalid("exact prepared signature"))?;
            if doc.writer_uuid != writer.unwrap_or(record.frozen.writer_identity) {
                return Err(RecoveryError::Invalid("exact prepared writer"));
            }
        }
    }
    if record.is_complete() {
        return Ok(result(&record, PublicationOutcome::Pending, None, None));
    }
    Box::pin(drive(&mut p, &mut record, exact, writer, intent)).await
}

fn draw<T, J>(p: &mut RecoveryParts<'_, T, J>) -> Result<[u8; 16], RecoveryError> {
    let mut bytes = [0; 16];
    p.secure.fill(&mut bytes)?;
    Ok(bytes)
}
fn new_candidate(number: u64, request: RequestIdentity, owned: &OwnedCandidate) -> Candidate {
    Candidate {
        number,
        role: Role::Active,
        request,
        seq: owned.seq(),
        id: owned.id(),
        root: owned.bytes().to_vec(),
        evidence: Evidence::default(),
    }
}
#[cfg(feature = "publish-restart-tests")]
fn restart_point(cut: &str, side: &str, record: &Submission) -> Result<(), RecoveryError> {
    crate::publish_restart::point(cut, side, record).map_err(|e| {
        crate::PublicationStoreError {
            path: std::path::PathBuf::new(),
            reason: e.to_string(),
            kind: crate::PublicationStoreErrorKind::Refused,
        }
        .into()
    })
}

async fn save<J: PublicationJournal>(
    journal: &mut J,
    record: &mut Submission,
) -> Result<(), RecoveryError> {
    let cut = match record.phase {
        Phase::ProbeStarted(_) => Some("probe-save"),
        Phase::AwaitingAnswer { .. } => Some("attempt-save"),
        _ => None,
    };
    save_at(journal, record, cut).await
}

async fn save_at<J: PublicationJournal>(
    journal: &mut J,
    record: &mut Submission,
    cut: Option<&str>,
) -> Result<(), RecoveryError> {
    #[cfg(not(feature = "publish-restart-tests"))]
    let _ = cut;
    let old = record.generation;
    record.generation = old.checked_add(1).ok_or(retained::Error::Exhausted)?;
    retained::validate(record)?;
    #[cfg(feature = "publish-restart-tests")]
    if let Some(cut) = cut {
        restart_point(cut, "before", record)?;
    }
    journal.replace(old, record).await?;
    #[cfg(feature = "publish-restart-tests")]
    if let Some(cut) = cut {
        restart_point(cut, "after", record)?;
    }
    Ok(())
}
async fn save_answer<J: PublicationJournal>(
    journal: &mut J,
    record: &mut Submission,
) -> Result<(), RecoveryError> {
    let cut = match record.phase {
        Phase::Complete(_) => "complete-save",
        Phase::EpochRecovery { .. } => "epoch-save",
        _ => "answer-save",
    };
    save_at(journal, record, Some(cut)).await
}
fn request(record: &Submission, candidate: &Candidate) -> Result<PublishRequest, RecoveryError> {
    let owned = OwnedCandidate::new(record.volume.as_str(), candidate.root.clone().into())
        .map_err(|_| RecoveryError::Invalid("retained candidate"))?;
    let mut ids = BTreeSet::new();
    let mut history = Vec::new();
    for c in record
        .candidates
        .iter()
        .filter(|c| c.request == candidate.request)
    {
        if ids.insert(c.id) {
            history.push(
                OwnedCandidate::new(record.volume.as_str(), c.root.clone().into())
                    .map_err(|_| RecoveryError::Invalid("retained history"))?,
            );
        }
    }
    PublishRequest::new(
        record.volume.as_str(),
        Epoch::from_bytes(candidate.request.epoch),
        &candidate.request.operation,
        owned,
        history,
    )
    .map_err(|_| RecoveryError::Invalid("retained request"))
}

fn result(
    record: &Submission,
    outcome: PublicationOutcome,
    response: Option<PublishResponse>,
    diagnostic: Option<String>,
) -> PublicationResult {
    let outcome = if let Phase::Complete(done) = &record.phase {
        PublicationOutcome::Landed(done.clone())
    } else {
        outcome
    };
    PublicationResult {
        #[cfg(feature = "publish-restart-tests")]
        restart_record: Some(record.clone()),
        handle: PublicationHandle {
            scope: record.scope.clone(),
            volume: record.volume.clone(),
            publication_id: record.publication_id,
        },
        uncertain: !record.is_complete()
            && record
                .candidates
                .iter()
                .any(|c| !c.evidence.never_decided()),
        outcome,
        response,
        diagnostic,
    }
}
fn same_slot(record: &Submission, target: u64) -> bool {
    record
        .candidates
        .iter()
        .filter(|c| c.role == Role::Retired)
        .all(|c| c.seq == target)
}

/// Fresh foreign occupancy for one exact current request. Never persisted.
#[derive(Debug, Clone, Copy)]
pub(super) struct ExactRetry {
    pub(super) number: u64,
    pub(super) request: RequestIdentity,
    pub(super) seq: u64,
    pub(super) id: GrainId,
    pub(super) foreign: GrainId,
}

struct Barrier {
    retry: Option<ExactRetry>,
    landing: Option<(u64, GrainId)>,
}

enum BarrierOutcome {
    Ready(Barrier),
    Unresolved,
    Invalid(RecoveryError),
}

pub(super) enum DeferredReplay {
    Applied { landing: Option<(u64, GrainId)> },
    Unresolved,
    Invalid(RecoveryError),
}

#[derive(Clone, Copy)]
struct DeferredAnswer {
    number: u64,
    answer: PublishResponse,
    claimed: (u64, GrainId),
}

/// Decides whether a read error is integrity for both deferred paths.
pub(super) fn classify_deferred_read(failure: &RootStoreError) -> Option<&'static str> {
    matches!(
        failure,
        RootStoreError::RefusedResponse {
            kind: RefusalKind::OverCap,
            ..
        }
    )
    .then_some("untrusted probe head")
}

fn deferred_occupancy(record: &Submission) -> Result<Option<DeferredAnswer>, RecoveryError> {
    if !deferred_answer_pending(record) {
        return Ok(None);
    }
    let Some(response) = &record.last_response else {
        return Ok(None);
    };
    let Some(active) = record
        .candidates
        .iter()
        .find(|candidate| candidate.role == Role::Active && candidate.number == response.candidate)
    else {
        return Ok(None);
    };
    if response.answer.is_empty() {
        return Ok(None);
    }
    let answer = authority_answer::decode(&response.answer)
        .map_err(|_| RecoveryError::Invalid("checked answer decoding"))?;
    let (status, token) = answer_tuple(answer);
    if response.status != status || response.token != token.unwrap_or("").as_bytes() {
        return Err(RecoveryError::Invalid("checked answer identification"));
    }
    let answer = check_answer(&request(record, active)?, answer)
        .map_err(|_| RecoveryError::Invalid("checked answer identification"))?;
    match answer {
        PublishResponse::Lost(lost) => Ok(Some(DeferredAnswer {
            number: active.number,
            answer,
            claimed: (active.seq, lost.occupant()),
        })),
        PublishResponse::Conflict(CheckedConflict::StaleBase(head)) => {
            Ok(head.root.map(|claimed| DeferredAnswer {
                number: active.number,
                answer,
                claimed,
            }))
        }
        _ => Ok(None),
    }
}

async fn end_deferred_invalid<J: PublicationJournal>(
    journal: &mut J,
    record: &mut Submission,
    answer: Option<PublishResponse>,
    error: RecoveryError,
) -> Result<BarrierOutcome, RecoveryError> {
    if answer.is_some_and(|answer| answer.request_wrote_nothing()) {
        let response = record
            .last_response
            .as_ref()
            .ok_or(RecoveryError::Invalid("deferred answer absent"))?;
        let evidence = &mut record
            .candidates
            .iter_mut()
            .find(|candidate| candidate.number == response.candidate)
            .ok_or(RecoveryError::Invalid("answer candidate absent"))?
            .evidence;
        evidence.proved_no_write = evidence
            .proved_no_write
            .checked_sub(1)
            .ok_or(RecoveryError::Invalid("deferred no-write evidence"))?;
    }
    record.last_response = None;
    record.phase = Phase::Ready;
    save_answer(journal, record).await?;
    Ok(BarrierOutcome::Invalid(error))
}

/// Probe every catalogue slot and the complete current chain in one cycle.
/// Empty observations never release an entry, and classification follows the
/// complete verified walk.
#[expect(
    clippy::too_many_lines,
    reason = "one durable probe cycle keeps every save and read in protocol order"
)]
async fn barrier<T: AuthorityTransport, J: PublicationJournal>(
    transport: &T,
    journal: &mut J,
    publisher_keys: &granary_store::crypto::TrustedKeys,
    record: &mut Submission,
) -> Result<BarrierOutcome, RecoveryError> {
    let seqs = probe::candidate_seqs(record);
    let Some(candidate_first) = seqs.first().copied() else {
        return Ok(BarrierOutcome::Ready(Barrier {
            retry: None,
            landing: None,
        }));
    };
    let last = seqs.last().copied().unwrap_or(candidate_first);
    let pending = deferred_answer_pending(record);
    let deferred = if pending {
        match deferred_occupancy(record) {
            Ok(Some(deferred)) => Some(deferred),
            Ok(None) => {
                return end_deferred_invalid(
                    journal,
                    record,
                    None,
                    RecoveryError::Invalid("checked answer classification"),
                )
                .await;
            }
            Err(error) => return end_deferred_invalid(journal, record, None, error).await,
        }
    } else {
        None
    };
    let first = deferred
        .map(|answer| answer.claimed.0)
        .map_or(candidate_first, |seq| candidate_first.min(seq));
    let destination = record.phase.clone();
    let mut needs_rebase = matches!(destination, Phase::Rebase);
    let mut retry = None;
    let mut roots = BTreeMap::new();
    for &seq in &seqs {
        let probe = Probe {
            cycle: record.generation,
            seq,
            reason: ProbeReason::Started,
        };
        if deferred.is_none() {
            record.phase = Phase::ProbeStarted(probe);
        }
        if deferred.is_some() {
            save_at(journal, record, Some("probe-save")).await?;
        } else {
            save(journal, record).await?;
        }
        let observation = transport.probe_root_once(record.volume.as_str(), seq).await;
        #[cfg(feature = "publish-restart-tests")]
        restart_point("probe-delivered", "after", record)?;
        let bytes = match observation {
            Ok(Some(bytes))
                if u64::try_from(bytes.len())
                    .is_ok_and(|len| len <= granary_core::root::ROOT_MAX_BYTES) =>
            {
                Some(bytes)
            }
            Ok(None) => None,
            Ok(Some(_)) if deferred.is_some() => {
                return end_deferred_invalid(
                    journal,
                    record,
                    deferred.map(|answer| answer.answer),
                    RecoveryError::RemoteIntegrity("untrusted probe head"),
                )
                .await;
            }
            Err(error)
                if deferred.is_some()
                    && let Some(diagnostic) = classify_deferred_read(&error) =>
            {
                return end_deferred_invalid(
                    journal,
                    record,
                    deferred.map(|answer| answer.answer),
                    RecoveryError::RemoteIntegrity(diagnostic),
                )
                .await;
            }
            other => {
                if deferred.is_none() {
                    let reason = if other.is_err() {
                        ProbeReason::Transport
                    } else {
                        ProbeReason::Malformed
                    };
                    record.phase = Phase::Unresolved(Probe { reason, ..probe });
                }
                #[cfg(feature = "publish-restart-tests")]
                restart_point("probe-result", "before", record)?;
                save(journal, record).await?;
                #[cfg(feature = "publish-restart-tests")]
                restart_point("probe-result", "after", record)?;
                return Ok(BarrierOutcome::Unresolved);
            }
        };
        record.phase = destination.clone();
        if let Some(bytes) = bytes {
            roots.insert(seq, bytes);
        }
        if seq != last {
            #[cfg(feature = "publish-restart-tests")]
            restart_point("probe-result", "before", record)?;
            save(journal, record).await?;
            #[cfg(feature = "publish-restart-tests")]
            restart_point("probe-result", "after", record)?;
        }
    }
    let (mut head, head_unavailable) = match transport.max_seq(record.volume.as_str()).await {
        Ok(head) => (head, false),
        Err(_) => (None, true),
    };
    let observed = roots.last_key_value().map(|(seq, _)| *seq);
    if !head_unavailable && let Some(observed) = observed {
        head = Some(head.map_or(observed, |head| head.max(observed)));
    }
    #[expect(
        clippy::nonminimal_bool,
        reason = "the pinned compiler does not provide Option::is_none_or"
    )]
    let listing_unavailable = (head_unavailable && (deferred.is_some() || observed.is_some()))
        || deferred.is_some_and(|answer| !head.is_some_and(|head| head >= answer.claimed.0));
    if listing_unavailable {
        if deferred.is_none() {
            record.phase = Phase::Unresolved(Probe {
                cycle: record.generation,
                seq: last,
                reason: ProbeReason::Transport,
            });
        }
        #[cfg(feature = "publish-restart-tests")]
        restart_point("probe-result", "before", record)?;
        save(journal, record).await?;
        #[cfg(feature = "publish-restart-tests")]
        restart_point("probe-result", "after", record)?;
        return Ok(BarrierOutcome::Unresolved);
    }
    let verified = match head {
        Some(head) if head >= first => {
            let walked =
                probe::walk_chain(record, true, head, first, &roots, publisher_keys, |seq| {
                    transport.probe_root_once(record.volume.as_str(), seq)
                })
                .await;
            match walked {
                Err(error) if deferred.is_some() => {
                    return end_deferred_invalid(
                        journal,
                        record,
                        deferred.map(|answer| answer.answer),
                        error,
                    )
                    .await;
                }
                Err(error) => return Err(error),
                Ok(Ok(verified)) => verified,
                Ok(Err(probe::ChainReadError::Missing)) if deferred.is_none() => {
                    return Err(RecoveryError::RemoteIntegrity("probe chain root missing"));
                }
                Ok(Err(probe::ChainReadError::Read(error)))
                    if deferred.is_some()
                        && let Some(diagnostic) = classify_deferred_read(&error) =>
                {
                    return end_deferred_invalid(
                        journal,
                        record,
                        deferred.map(|answer| answer.answer),
                        RecoveryError::RemoteIntegrity(diagnostic),
                    )
                    .await;
                }
                Ok(Err(probe::ChainReadError::Missing | probe::ChainReadError::Read(_))) => {
                    if deferred.is_none() {
                        record.phase = Phase::Unresolved(Probe {
                            cycle: record.generation,
                            seq: last,
                            reason: ProbeReason::Transport,
                        });
                    }
                    #[cfg(feature = "publish-restart-tests")]
                    restart_point("probe-result", "before", record)?;
                    save(journal, record).await?;
                    #[cfg(feature = "publish-restart-tests")]
                    restart_point("probe-result", "after", record)?;
                    return Ok(BarrierOutcome::Unresolved);
                }
            }
        }
        _ => probe::VerifiedChain {
            landing: None,
            occupants: Vec::new(),
        },
    };
    if let Some(answer) = deferred
        && !verified.occupants.contains(&answer.claimed)
    {
        return end_deferred_invalid(
            journal,
            record,
            Some(answer.answer),
            RecoveryError::RemoteIntegrity("stored landing mismatch"),
        )
        .await;
    }
    let winner = verified.landing.as_ref().map(|landing| &landing.candidate);
    let landing = verified
        .landing
        .as_ref()
        .map(|landing| (landing.candidate.seq, landing.stored_id));
    if winner.is_none() {
        for (seq, id) in &verified.occupants {
            if let Some(active) = record
                .candidates
                .iter()
                .find(|c| c.role == Role::Active && c.seq == *seq && c.id != *id)
            {
                if active.evidence.never_decided() {
                    needs_rebase = true;
                } else {
                    retry = Some(ExactRetry {
                        number: active.number,
                        request: active.request,
                        seq: *seq,
                        id: active.id,
                        foreign: *id,
                    });
                }
            }
        }
    }
    if let Some(deferred) = deferred {
        let candidate = record
            .candidates
            .iter()
            .find(|candidate| candidate.number == deferred.number)
            .cloned()
            .ok_or(RecoveryError::Invalid("answer candidate absent"))?;
        let mut next = record.clone();
        next.phase = Phase::Ready;
        if let Err(error) = apply_answer_classification(
            &mut next,
            &candidate,
            deferred.answer,
            retry.as_ref(),
            &AnswerOccupancy::Verified(Box::new(verified)),
        ) {
            return end_deferred_invalid(journal, record, Some(deferred.answer), error).await;
        }
        *record = next;
    } else {
        compare(record, winner, verified.occupants.iter().copied());
        if !record.is_complete() {
            record.phase = if retry.is_some() {
                Phase::Ready
            } else if needs_rebase && saved_admission_refusal(record).is_none() {
                Phase::Rebase
            } else {
                destination
            };
        }
    }
    #[cfg(feature = "publish-restart-tests")]
    restart_point("probe-result", "before", record)?;
    save(journal, record).await?;
    #[cfg(feature = "publish-restart-tests")]
    restart_point("probe-result", "after", record)?;
    Ok(BarrierOutcome::Ready(Barrier { retry, landing }))
}

pub(super) async fn replay_deferred_answer<T: AuthorityTransport, J: PublicationJournal>(
    transport: &T,
    journal: &mut J,
    record: &mut Submission,
    publisher_keys: &granary_store::crypto::TrustedKeys,
) -> Result<DeferredReplay, RecoveryError> {
    if !deferred_answer_pending(record) {
        return Err(RecoveryError::Invalid("deferred answer absent"));
    }
    match Box::pin(barrier(transport, journal, publisher_keys, record)).await? {
        BarrierOutcome::Ready(Barrier { landing, .. }) => Ok(DeferredReplay::Applied { landing }),
        BarrierOutcome::Unresolved => Ok(DeferredReplay::Unresolved),
        BarrierOutcome::Invalid(error) => Ok(DeferredReplay::Invalid(error)),
    }
}

#[derive(Debug)]
pub(super) enum SendFailure {
    Authority(AuthorityError),
    Invalid(String),
    Deferred(PublishResponse, String),
}

enum AnswerOccupancy {
    NotApplicable,
    Verified(Box<probe::VerifiedChain>),
    Deferred(String),
}

async fn answer_occupancy<T: AuthorityTransport>(
    transport: &T,
    record: &Submission,
    active: &Candidate,
    answer: PublishResponse,
    retry: Option<&ExactRetry>,
    keys: &granary_store::crypto::TrustedKeys,
) -> Result<AnswerOccupancy, RecoveryError> {
    if retry.is_some_and(|witness| match answer {
        PublishResponse::Lost(lost) => lost.occupant() != witness.foreign,
        PublishResponse::Conflict(CheckedConflict::StaleBase(head)) => head
            .root
            .is_some_and(|(seq, id)| seq == witness.seq && id != witness.foreign),
        _ => false,
    }) {
        return Ok(AnswerOccupancy::NotApplicable);
    }
    let claimed = match answer {
        PublishResponse::Lost(lost) => Some((active.seq, lost.occupant())),
        PublishResponse::Conflict(CheckedConflict::StaleBase(head)) => head.root,
        _ => None,
    };
    let Some((claimed_seq, expected_id)) = claimed else {
        return Ok(AnswerOccupancy::NotApplicable);
    };
    let claimed_root = match transport
        .probe_root_once(record.volume.as_str(), claimed_seq)
        .await
    {
        Ok(Some(bytes))
            if u64::try_from(bytes.len())
                .is_ok_and(|len| len <= granary_core::root::ROOT_MAX_BYTES) =>
        {
            bytes
        }
        Ok(Some(_)) => return Err(RecoveryError::RemoteIntegrity("untrusted probe head")),
        Ok(None) => {
            return Ok(AnswerOccupancy::Deferred("probe chain root missing".into()));
        }
        Err(error) if let Some(diagnostic) = classify_deferred_read(&error) => {
            return Err(RecoveryError::RemoteIntegrity(diagnostic));
        }
        Err(error) => return Ok(AnswerOccupancy::Deferred(error.to_string())),
    };
    if GrainId::of(&claimed_root) != expected_id {
        return Err(RecoveryError::RemoteIntegrity("stored landing mismatch"));
    }
    let head = match transport.max_seq(record.volume.as_str()).await {
        Ok(Some(head)) if head >= claimed_seq => head,
        Ok(_) => {
            return Ok(AnswerOccupancy::Deferred("probe chain root missing".into()));
        }
        Err(error) => return Ok(AnswerOccupancy::Deferred(error.to_string())),
    };
    let first = probe::candidate_floor(record, true)?.min(claimed_seq);
    let roots = BTreeMap::from([(claimed_seq, claimed_root)]);
    match probe::walk_chain(record, true, head, first, &roots, keys, |seq| {
        transport.probe_root_once(record.volume.as_str(), seq)
    })
    .await?
    {
        Ok(verified) => Ok(AnswerOccupancy::Verified(Box::new(verified))),
        Err(probe::ChainReadError::Missing) => {
            Ok(AnswerOccupancy::Deferred("probe chain root missing".into()))
        }
        Err(probe::ChainReadError::Read(error))
            if let Some(diagnostic) = classify_deferred_read(&error) =>
        {
            Err(RecoveryError::RemoteIntegrity(diagnostic))
        }
        Err(probe::ChainReadError::Read(error)) => Ok(AnswerOccupancy::Deferred(error.to_string())),
    }
}

async fn save_invalid_answer<J: PublicationJournal>(
    journal: &mut J,
    record: &mut Submission,
    number: u64,
    attempt: u64,
    answer: PublishResponse,
    error: &RecoveryError,
) -> Result<Result<PublishResponse, SendFailure>, RecoveryError> {
    record
        .candidates
        .iter_mut()
        .find(|candidate| candidate.number == number)
        .ok_or(RecoveryError::Invalid("answer candidate absent"))?
        .evidence
        .answer(
            attempt,
            false,
            matches!(
                answer,
                PublishResponse::Landed(_)
                    | PublishResponse::Lost(_)
                    | PublishResponse::Accepted(_)
                    | PublishResponse::Open(_)
                    | PublishResponse::Conflict(CheckedConflict::OperationBound(_))
            ),
        )?;
    record.phase = Phase::Ready;
    save_answer(journal, record).await?;
    let diagnostic = match answer {
        PublishResponse::Conflict(CheckedConflict::EpochMismatch(epoch, _)) => {
            format!("{error}: {epoch:?}")
        }
        _ => error.to_string(),
    };
    Ok(Err(SendFailure::Invalid(diagnostic)))
}

/// One retained attempt, dispatch and saved answer. Hooks preserve the drive's
/// event order; no caller holds a journal transaction across the transport.
#[expect(
    clippy::too_many_arguments,
    reason = "the transport, durable state, witness and two fault hooks are independent seams"
)]
pub(super) async fn send_once<T: AuthorityTransport, J: PublicationJournal>(
    transport: &T,
    journal: &mut J,
    record: &mut Submission,
    active: &Candidate,
    retry: Option<&ExactRetry>,
    keys: &granary_store::crypto::TrustedKeys,
    before_send: impl FnOnce(&mut J) + Send,
    after_send: impl FnOnce() + Send,
) -> Result<Result<PublishResponse, SendFailure>, RecoveryError> {
    let req = request(record, active)?;
    let c = record
        .candidates
        .iter_mut()
        .find(|c| c.number == active.number)
        .ok_or(RecoveryError::Invalid("active candidate absent"))?;
    let attempt = c.evidence.start()?;
    record.phase = Phase::AwaitingAnswer {
        candidate: active.number,
        attempt,
    };
    record.last_response = None;
    save(journal, record).await?;
    #[cfg(feature = "publish-restart-tests")]
    restart_point("dispatch", "before", record)?;
    before_send(journal);
    let answer = transport.publish_once(&req).await;
    #[cfg(feature = "publish-restart-tests")]
    restart_point("dispatch", "after", record)?;
    after_send();
    match answer {
        Ok(answer) => {
            let exempt = answer == PublishResponse::ServiceUnavailable(ServiceReason::Unavailable)
                && record.unavailable_exemptions < MAX_UNAVAILABLE_EXEMPTIONS
                && journal.unavailable_window_open(record);
            let occupancy =
                match answer_occupancy(transport, record, active, answer, retry, keys).await {
                    Ok(occupancy) => occupancy,
                    Err(error) => {
                        return save_invalid_answer(
                            journal,
                            record,
                            active.number,
                            attempt,
                            answer,
                            &error,
                        )
                        .await;
                    }
                };
            let mut next = record.clone();
            if let Err(error) = apply_answer_with_retry(
                &mut next,
                active.number,
                attempt,
                answer,
                retry,
                &occupancy,
                exempt,
            ) {
                // Discard every partial answer transition. An inconsistent
                // checked answer supplies no no-write proof or release.
                // Preserve its decision claim even when validation fails.
                return save_invalid_answer(
                    journal,
                    record,
                    active.number,
                    attempt,
                    answer,
                    &error,
                )
                .await;
            }
            *record = next;
            save_answer(journal, record).await?;
            if let AnswerOccupancy::Deferred(diagnostic) = occupancy {
                Ok(Err(SendFailure::Deferred(answer, diagnostic)))
            } else {
                Ok(Ok(answer))
            }
        }
        Err(error) => {
            record.phase = Phase::Ready;
            save_answer(journal, record).await?;
            Ok(Err(SendFailure::Authority(error)))
        }
    }
}

pub(super) fn saved_admission_refusal(record: &Submission) -> Option<(PublishRefusal, &Candidate)> {
    let answer = record.last_response.as_ref()?;
    let refusal = match (answer.status, answer.token.as_slice()) {
        (400, b"missing-reference") => PublishRefusal::MissingReference,
        (400, b"invalid-reference") => PublishRefusal::InvalidReference,
        (413, b"publish-work-limit") => PublishRefusal::PublishWorkLimit,
        _ => return None,
    };
    let active = record.candidates.iter().find(|candidate| {
        candidate.role == Role::Active
            && candidate.number == answer.candidate
            && candidate.evidence.last_answered_attempt == answer.attempt
    })?;
    Some((refusal, active))
}

#[expect(
    clippy::too_many_lines,
    reason = "one serialized continuation loop exposes every journal-before-network cut"
)]
async fn drive<T: AuthorityTransport, J: PublicationJournal>(
    p: &mut RecoveryParts<'_, T, J>,
    record: &mut Submission,
    exact: bool,
    writer: Option<[u8; 16]>,
    intent: RecoveryIntent,
) -> Result<PublicationResult, RecoveryError> {
    let mut resume = Some(intent);
    let mut sends = 0_u32;
    let mut bound = None;
    let mut response = None;
    let mut retry_reason = crate::RetryReason::Transient;
    let mut attempts_at_start = None;
    loop {
        if record.is_complete() {
            return Ok(result(record, PublicationOutcome::Pending, response, None));
        }
        let classification_owed = deferred_answer_pending(record);
        let saved_refusal =
            saved_admission_refusal(record).map(|(refusal, _)| PublishResponse::Refused(refusal));
        let attempts = p.journal.commit_attempts(record.publication_id)?;
        let attempts_at_start = *attempts_at_start.get_or_insert(attempts.unwrap_or(0));
        let charged = if let Some(attempts) = attempts {
            sends = u32::try_from(attempts).unwrap_or(u32::MAX);
            charged_attempts(attempts, attempts_at_start, record)
        } else {
            u64::from(sends)
        };
        let exhausted = charged >= u64::from(DISPATCH_ATTEMPTS);
        if exhausted && !classification_owed && saved_refusal.is_none() {
            return Ok(result(record, PublicationOutcome::Pending, response, None));
        }
        if let Some(intent) = resume.take() {
            match record.phase {
                Phase::ProbeStarted(_) | Phase::Unresolved(_) | Phase::Rebase
                    if intent == RecoveryIntent::Continue =>
                {
                    return Ok(result(
                        record,
                        PublicationOutcome::Unresolved,
                        saved_refusal,
                        Some(
                            match record.phase {
                                Phase::ProbeStarted(_) => {
                                    "probe interrupted; explicit recovery required"
                                }
                                Phase::Unresolved(_) => {
                                    "probe unresolved; explicit recovery required"
                                }
                                _ => "loaded rebase; explicit recovery required",
                            }
                            .into(),
                        ),
                    ));
                }
                Phase::ProbeStarted(_) | Phase::Unresolved(_) if !classification_owed => {
                    record.phase = if saved_refusal.is_some() {
                        Phase::Ready
                    } else {
                        Phase::Rebase
                    };
                    save(p.journal, record).await?;
                }
                _ => {}
            }
        }
        if matches!(record.phase, Phase::AwaitingAnswer { .. }) {
            record.phase = Phase::Ready;
            save(p.journal, record).await?;
        }
        if exact && matches!(record.phase, Phase::Rebase | Phase::EpochRecovery { .. }) {
            return Ok(result(
                record,
                PublicationOutcome::Unresolved,
                response,
                Some("exact candidate requires unchanged parent".into()),
            ));
        }
        if let Phase::EpochRecovery { epoch } = record.phase {
            let operation = draw(p)?;
            if record
                .candidates
                .iter()
                .any(|c| c.request.operation == operation)
            {
                return Err(RecoveryError::Invalid("operation identity repeated"));
            }
            record.current = Some(RequestIdentity { epoch, operation });
            record.phase = Phase::Rebase;
            save_at(p.journal, record, Some("operation-save")).await?;
        }
        let barrier = Box::pin(barrier(p.transport, p.journal, p.publisher_keys, record)).await?;
        let retry = match barrier {
            BarrierOutcome::Ready(Barrier { retry, .. }) => retry,
            BarrierOutcome::Unresolved => {
                return Ok(result(
                    record,
                    PublicationOutcome::Unresolved,
                    response.or(saved_refusal),
                    Some("probe unresolved".into()),
                ));
            }
            BarrierOutcome::Invalid(error) => {
                return Ok(result(
                    record,
                    PublicationOutcome::BackendError,
                    None,
                    Some(error.to_string()),
                ));
            }
        };
        if record.is_complete() {
            continue;
        }
        if matches!(record.phase, Phase::Ready)
            && let Some((refusal, _)) = saved_admission_refusal(record)
        {
            return Ok(result(
                record,
                PublicationOutcome::Refused,
                Some(PublishResponse::Refused(refusal)),
                None,
            ));
        }
        if classification_owed && retry.is_some() && matches!(record.phase, Phase::Ready) {
            return Ok(result(
                record,
                PublicationOutcome::Unresolved,
                response,
                Some("stale retry release was not proven".into()),
            ));
        }
        if exhausted {
            return Ok(result(record, PublicationOutcome::Pending, response, None));
        }
        if matches!(record.phase, Phase::Rebase) {
            if exact {
                return Ok(result(
                    record,
                    PublicationOutcome::Unresolved,
                    response,
                    Some("exact candidate requires unchanged parent".into()),
                ));
            }
            if record.candidates.len() >= retained::MAX_CANDIDATES {
                return Ok(result(
                    record,
                    PublicationOutcome::Unresolved,
                    response,
                    Some("candidate capacity exhausted".into()),
                ));
            }
            let prepared = async {
                let base =
                    preparation::verify_base(p.transport, &record.volume, p.publisher_keys).await?;
                if !same_slot(record, base.target_seq()) {
                    return Err(RecoveryError::Invalid(
                        "unresolved retired candidate is not at target",
                    ));
                }
                let objects = preparation::reconstruct(p, &record.volume, &record.frozen).await?;
                preparation::prepare(p, &objects, base, &record.frozen, writer).await
            }
            .await;
            let owned = match prepared {
                Ok(c) => c,
                Err(error @ RecoveryError::RemoteIntegrity(_))
                    if p.journal.recovered().is_some() =>
                {
                    return Err(error);
                }
                Err(RecoveryError::Journal(crate::PublicationStoreError {
                    kind: crate::PublicationStoreErrorKind::RemoteIntegrity,
                    ..
                })) => return Err(RecoveryError::RemoteIntegrity("recovery merge")),
                Err(
                    error @ RecoveryError::Journal(crate::PublicationStoreError {
                        kind:
                            crate::PublicationStoreErrorKind::Conflict
                            | crate::PublicationStoreErrorKind::Fenced,
                        ..
                    }),
                ) => return Err(error),
                Err(
                    error @ RecoveryError::Journal(crate::PublicationStoreError {
                        kind: crate::PublicationStoreErrorKind::Corrupt,
                        ..
                    }),
                ) if p.journal.recovered().is_some() => return Err(error),
                Err(error @ RecoveryError::Journal(_)) if attempts.is_some() => return Err(error),
                Err(e) => {
                    return Ok(result(
                        record,
                        PublicationOutcome::Unresolved,
                        response,
                        Some(e.to_string()),
                    ));
                }
            };
            let number = record
                .candidates
                .last()
                .map_or(Some(1), |c| c.number.checked_add(1))
                .ok_or(retained::Error::Exhausted)?;
            let identity = record
                .current
                .ok_or(RecoveryError::Invalid("no current identity"))?;
            for c in &mut record.candidates {
                if c.role == Role::Active {
                    c.role = Role::History;
                }
            }
            record.phase = Phase::Ready;
            record.insert_candidate(new_candidate(number, identity, &owned))?;
            save_at(p.journal, record, Some("replacement-save")).await?;
            // Re-preparation can issue many reads/uploads. Its earlier empty
            // observation is not a substitute for the fresh send barrier.
            continue;
        }
        let active = record
            .candidates
            .iter()
            .find(|c| c.role == Role::Active)
            .cloned()
            .ok_or(RecoveryError::Invalid("no active candidate"))?;
        // Rebase preparation can outlive the response that triggered it. The
        // unsent candidate's sequence still identifies its first dispatch.
        if active.evidence.started == 0
            && root::decode_root(&record.frozen.initial_root)
                .is_ok_and(|initial| active.seq > initial.seq)
        {
            retry_reason = crate::RetryReason::Conflict;
        }
        if !same_slot(record, active.seq) {
            return Ok(result(
                record,
                PublicationOutcome::Unresolved,
                response,
                Some("unresolved retired candidate is not at target".into()),
            ));
        }
        if record.unavailable_exemptions < MAX_UNAVAILABLE_EXEMPTIONS
            || p.journal.check_dispatch_deadline_at_cap()
        {
            p.journal
                .check_dispatch_deadline(active.root.len() as u64)?;
        }
        sends = sends.saturating_add(1);
        let previous_exemptions = record.unavailable_exemptions;
        let answer = send_once(
            p.transport,
            p.journal,
            record,
            &active,
            retry.as_ref(),
            p.publisher_keys,
            |journal| {
                if attempts.is_some() && sends > 1 {
                    journal.retry(sends, retry_reason);
                }
                retry_reason = crate::RetryReason::Transient;
                if bound != Some(active.request.operation) {
                    bound = Some(active.request.operation);
                    crate::observe::publish_bound(
                        crate::observe::PublishOperationId::from_retained(active.request.operation),
                    );
                }
            },
            || {},
        )
        .await?;
        match answer {
            Ok(answer) => {
                response = Some(answer);
                if record.unavailable_exemptions > previous_exemptions {
                    return Ok(result(record, PublicationOutcome::Pending, response, None));
                }
                if matches!(
                    answer,
                    PublishResponse::Conflict(CheckedConflict::StaleBase(_))
                ) {
                    retry_reason = crate::RetryReason::Conflict;
                }
                if retry.is_some()
                    && matches!(
                        answer,
                        PublishResponse::Accepted(_) | PublishResponse::Open(_)
                    )
                {
                    return Ok(result(
                        record,
                        PublicationOutcome::Pending,
                        response,
                        Some("open entry under foreign occupancy: possible wedge, repaired out of band".into()),
                    ));
                }
                if retry.is_some()
                    && matches!(
                        answer,
                        PublishResponse::Conflict(CheckedConflict::StaleBase(_))
                    )
                    && matches!(record.phase, Phase::Ready)
                {
                    return Ok(result(
                        record,
                        PublicationOutcome::Unresolved,
                        response,
                        Some("stale retry release was not proven".into()),
                    ));
                }
                if matches!(
                    answer,
                    PublishResponse::Refused(_)
                        | PublishResponse::Conflict(CheckedConflict::VolumeDamaged)
                ) {
                    return Ok(result(record, PublicationOutcome::Refused, response, None));
                }
            }
            Err(SendFailure::Invalid(diagnostic)) => {
                return Ok(result(
                    record,
                    PublicationOutcome::BackendError,
                    None,
                    Some(diagnostic),
                ));
            }
            Err(SendFailure::Authority(error)) => {
                let transient = matches!(
                    &error,
                    AuthorityError::Transport(_) | AuthorityError::Elapsed
                ) || matches!(&error, AuthorityError::Backend(e)
                        if (e.status() == 429 || (500..600).contains(&e.status())) && e.kind() == crate::ProtocolErrorKind::MissingToken);
                if attempts.is_some() && transient {
                    response = None;
                } else if matches!(
                    error,
                    AuthorityError::Backend(_) | AuthorityError::Request(_)
                ) {
                    return Ok(result(
                        record,
                        PublicationOutcome::BackendError,
                        None,
                        Some(error.to_string()),
                    ));
                } else {
                    return Ok(result(
                        record,
                        PublicationOutcome::Pending,
                        None,
                        Some(error.to_string()),
                    ));
                }
            }
            Err(SendFailure::Deferred(answer, diagnostic)) => {
                return Ok(result(
                    record,
                    PublicationOutcome::Unresolved,
                    Some(answer),
                    Some(diagnostic),
                ));
            }
        }
        let charged = charged + 1;
        if !record.is_complete() && charged < u64::from(DISPATCH_ATTEMPTS) {
            let ceiling = Duration::from_millis(40_u64.saturating_mul(1_u64 << charged.min(7)))
                .min(Duration::from_secs(5));
            let duration = p.delay.jitter(ceiling).min(ceiling);
            p.delay.wait(duration).await;
        }
    }
}

fn complete_receipt(
    record: &mut Submission,
    receipt: granary_core::authority_answer::Receipt,
) -> Result<(), RecoveryError> {
    let c = record
        .candidates
        .iter()
        .find(|c| {
            c.id == receipt.stored_id
                && c.seq == receipt.root_seq
                && c.request.epoch == receipt.position.epoch.to_bytes()
        })
        .ok_or(RecoveryError::Invalid("receipt is not owned"))?;
    record.phase = Phase::Complete(Completion {
        seq: c.seq,
        id: c.id,
        root: c.root.clone(),
        receipt: Some(receipt),
    });
    record.current = None;
    Ok(())
}
fn apply_answer_with_retry(
    record: &mut Submission,
    number: u64,
    attempt: u64,
    answer: PublishResponse,
    retry: Option<&ExactRetry>,
    occupancy: &AnswerOccupancy,
    exempt: bool,
) -> Result<(), RecoveryError> {
    let candidate = {
        let candidate = record
            .candidates
            .iter_mut()
            .find(|c| c.number == number)
            .ok_or(RecoveryError::Invalid("answer candidate absent"))?;
        candidate.evidence.answer(
            attempt,
            answer.request_wrote_nothing(),
            matches!(
                answer,
                PublishResponse::Accepted(_)
                    | PublishResponse::Open(_)
                    | PublishResponse::Lost(_)
                    | PublishResponse::Landed(_)
            ),
        )?;
        candidate.clone()
    };
    let (status, token) = answer.identification();
    let bytes = answer_bytes(answer)?;
    record.last_response = Some(LastResponse {
        candidate: number,
        attempt,
        status,
        token: token.unwrap_or("").as_bytes().to_vec(),
        answer: bytes,
    });
    record.phase = Phase::Ready;
    apply_answer_classification(record, &candidate, answer, retry, occupancy)?;
    if matches!(occupancy, AnswerOccupancy::Deferred(_)) {
        record.phase = Phase::Unresolved(Probe {
            cycle: record.generation,
            seq: candidate.seq,
            reason: ProbeReason::ContentUnavailable,
        });
    }
    if exempt {
        record.unavailable_exemptions += 1;
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one answer successor keeps evidence and destination atomic"
)]
fn apply_answer_classification(
    record: &mut Submission,
    candidate: &Candidate,
    answer: PublishResponse,
    retry: Option<&ExactRetry>,
    occupancy: &AnswerOccupancy,
) -> Result<(), RecoveryError> {
    let seq = candidate.seq;
    let identity = candidate.request;
    let id = candidate.id;
    if let Some(witness) = retry
        && (witness.number != candidate.number
            || witness.request != identity
            || witness.seq != seq
            || witness.id != id
            || record.current != Some(identity))
    {
        return Err(RecoveryError::Invalid(
            "retry witness does not match request",
        ));
    }
    match answer {
        PublishResponse::Landed(landed) => {
            if retry.is_some() {
                return Err(RecoveryError::Invalid(
                    "landed receipt contradicts foreign occupancy",
                ));
            }
            complete_receipt(record, landed.receipt())?;
        }
        PublishResponse::Lost(lost) => {
            if retry.is_some_and(|witness| lost.occupant() != witness.foreign) {
                return Err(RecoveryError::Invalid(
                    "lost occupant contradicts foreign occupancy",
                ));
            }
            let deferred = matches!(occupancy, AnswerOccupancy::Deferred(_));
            if let AnswerOccupancy::Verified(verified) = occupancy {
                compare(
                    record,
                    verified.landing.as_ref().map(|landing| &landing.candidate),
                    verified.occupants.iter().copied(),
                );
            } else if !deferred {
                return Err(RecoveryError::Invalid("answer occupancy missing"));
            }
            if !record.is_complete() && !deferred {
                // A durable lost outcome closes these exact bytes for this
                // epoch and operation, including any unanswered earlier attempt.
                record.candidates.retain(|c| {
                    !(c.id == lost.decision().candidate_id()
                        && Some(c.request) == record.current
                        && c.role != Role::Retired)
                });
                record.phase = Phase::Rebase;
            }
        }
        PublishResponse::Conflict(CheckedConflict::StaleBase(head)) => {
            if let Some(witness) = retry
                && head.root.is_some_and(|(head_seq, head_id)| {
                    head_seq == witness.seq && head_id != witness.foreign
                })
            {
                return Err(RecoveryError::Invalid(
                    "stale head contradicts foreign occupancy",
                ));
            }
            let deferred = matches!(occupancy, AnswerOccupancy::Deferred(_));
            if head.root.is_some() {
                if let AnswerOccupancy::Verified(verified) = occupancy {
                    compare(
                        record,
                        verified.landing.as_ref().map(|landing| &landing.candidate),
                        verified.occupants.iter().copied(),
                    );
                } else if !deferred {
                    return Err(RecoveryError::Invalid("answer occupancy missing"));
                }
            }
            if !record.is_complete() && !deferred {
                if retry.is_some()
                    && record.candidates.iter().any(|c| {
                        c.id == id
                            && c.request == identity
                            && c.role != Role::Retired
                            && c.evidence.decision_seen
                    })
                {
                    return Err(RecoveryError::Invalid(
                        "stale answer contradicts decision evidence",
                    ));
                }
                if let Some(witness) = retry {
                    if head.root.is_some_and(|(head_seq, head_id)| {
                        head_seq >= seq && (head_seq != seq || head_id == witness.foreign)
                    }) {
                        record.candidates.retain(|c| {
                            !(c.id == id && c.request == identity && c.role != Role::Retired)
                        });
                        record.phase = Phase::Rebase;
                    }
                } else {
                    record.phase = Phase::Rebase;
                }
            }
        }
        PublishResponse::Conflict(CheckedConflict::EpochMismatch(epoch, _)) => {
            if record
                .candidates
                .iter()
                .any(|c| c.role == Role::Retired && c.request.epoch == epoch.to_bytes())
            {
                return Err(RecoveryError::Invalid("authority reused a retired epoch"));
            }
            retire(record, epoch.to_bytes());
        }
        PublishResponse::Conflict(CheckedConflict::OperationBound(bound)) => match bound.bound() {
            Bound::Open { candidate_id, .. } => record.activate_bound(candidate_id)?,
            Bound::Landed(receipt) => {
                record.activate_bound(receipt.stored_id)?;
                complete_receipt(record, receipt)?;
            }
        },
        _ => {}
    }
    clear_pruned_response(record);
    Ok(())
}
#[cfg(test)]
pub(super) fn apply_answer(
    record: &mut Submission,
    number: u64,
    attempt: u64,
    answer: PublishResponse,
) -> Result<(), RecoveryError> {
    let claimed = match answer {
        PublishResponse::Lost(lost) => record
            .candidates
            .iter()
            .find(|candidate| candidate.number == number)
            .map(|candidate| (candidate.seq, lost.occupant())),
        PublishResponse::Conflict(CheckedConflict::StaleBase(head)) => head.root,
        _ => None,
    };
    let occupancy = claimed.map_or(AnswerOccupancy::NotApplicable, |(seq, id)| {
        let landing = record
            .candidates
            .iter()
            .find(|candidate| (candidate.seq, candidate.id) == (seq, id))
            .cloned()
            .map(|candidate| probe::VerifiedLanding {
                stored_root: candidate.root.clone(),
                stored_id: id,
                candidate,
            });
        AnswerOccupancy::Verified(Box::new(probe::VerifiedChain {
            landing,
            occupants: vec![(seq, id)],
        }))
    });
    apply_answer_with_retry(record, number, attempt, answer, None, &occupancy, false)
}

fn answer_bytes(answer: PublishResponse) -> Result<Vec<u8>, RecoveryError> {
    let wire = match answer {
        PublishResponse::Landed(l) => PublishAnswer::Landed {
            receipt: l.receipt(),
            head: l.head(),
        },
        PublishResponse::Lost(l) => PublishAnswer::Lost {
            position: l.decision().position(),
            candidate_id: l.decision().candidate_id(),
            occupant: l.occupant(),
            head: l.head(),
        },
        PublishResponse::Accepted(d) => PublishAnswer::Accepted {
            position: d.position(),
            candidate_id: d.candidate_id(),
        },
        PublishResponse::Open(d) => PublishAnswer::Open {
            position: d.position(),
            candidate_id: d.candidate_id(),
        },
        PublishResponse::Conflict(c) => match c {
            CheckedConflict::StaleBase(h) => PublishAnswer::StaleBase(h),
            CheckedConflict::OperationBound(b) => PublishAnswer::OperationBound(b.bound()),
            CheckedConflict::NotDecided(position, candidate_id) => PublishAnswer::NotDecided {
                position,
                candidate_id,
            },
            CheckedConflict::EpochMismatch(epoch, head) => {
                PublishAnswer::EpochMismatch { epoch, head }
            }
            CheckedConflict::VolumeDamaged => PublishAnswer::VolumeDamaged,
        },
        _ => return Ok(Vec::new()),
    };
    authority_answer::encode(wire).map_err(|_| RecoveryError::Invalid("checked answer encoding"))
}
