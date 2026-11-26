// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Journal-bound landing repair, without publication dispatch.

use super::{
    AuthorityTransport, PublicationJournal, RecoveryCommandError, RecoveryJournal, refetch_landing,
};
use crate::sync::refused;
use crate::{OverlayIo, RecoveryCommit, WritableStore};
use granary_core::{
    hash::GrainId,
    retained_submission::{Completion, Phase},
};
use granary_store::crypto::TrustedKeys;

#[cfg(test)]
#[derive(Default)]
pub(crate) struct LandingHooks {
    pub(crate) substitute: Option<Vec<u8>>,
    pub(crate) witness_failure: bool,
    pub(crate) checkpoint_failure: bool,
}

#[cfg(test)]
std::thread_local! {
    static HOOKS: std::cell::RefCell<LandingHooks> = std::cell::RefCell::default();
    static FINISH_SUBSTITUTE: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn landing_hooks_for_test(hooks: LandingHooks) {
    FINISH_SUBSTITUTE.take();
    HOOKS.set(hooks);
}

pub(crate) fn finish_landing_matches(candidate: &[u8], stored: &[u8]) -> bool {
    #[cfg(test)]
    if let Some(substitute) = FINISH_SUBSTITUTE.take() {
        return super::same_landing(candidate, &substitute);
    }
    super::same_landing(candidate, stored)
}

/// Authenticate the retained capture and stored landing before engine attachment.
#[expect(
    clippy::too_many_lines,
    reason = "the evidence gate keeps the retained identity, stored witness and checkpoint reads in order"
)]
pub(super) async fn prepare<P: OverlayIo + Send + Sync, T: AuthorityTransport + Sync>(
    store: &mut WritableStore<P>,
    remote: &T,
    keys: &TrustedKeys,
) -> Result<Vec<u8>, RecoveryCommandError> {
    #[cfg(test)]
    let hooks = HOOKS.take();
    store.check_recovery_owner()?;
    let scope = store.snapshot().scope.clone();
    let volume = store.snapshot().volume.clone();
    let commits = store.recovery_commits()?;
    let (boundary, candidate, publication) = commits
        .iter()
        .find_map(|commit| match commit {
            RecoveryCommit::Boundary {
                index,
                candidate,
                publication_id,
                ..
            } => Some((*index, *candidate, *publication_id)),
            RecoveryCommit::Landed { .. } => None,
        })
        .ok_or_else(|| refused("RecoveryLandedEvidenceMissing"))?;
    let mut record = store
        .publication_transaction(|journal| journal.load(&scope, &volume))?
        .filter(|record| {
            record.publication_id == publication
                && GrainId::of(&record.frozen.initial_root) == candidate
        })
        .ok_or_else(|| refused("RecoveryLandedEvidenceMissing"))?;
    let stored = commits.iter().find_map(|commit| match commit {
        RecoveryCommit::Landed {
            boundary_seq,
            root,
            seq,
            ..
        } if *boundary_seq == boundary => Some((*seq, *root)),
        _ => None,
    });
    #[cfg(test)]
    if hooks.witness_failure {
        return Err(super::RecoveryError::Remote(
            granary_core::rootstore::RootStoreError::Backend(
                "injected landing witness failure".into(),
            ),
        )
        .into());
    }
    let landed = if record.is_complete() {
        refetch_landing(remote, &record, stored, keys)
            .await?
            .ok_or_else(|| refused("SyncCommitLandingBinding"))?
    } else {
        let (seq, id) = stored.ok_or_else(|| refused("SyncCommitLandingBinding"))?;
        let (root, matched) =
            super::probe::read_landing_candidate(remote, &record, seq, id, keys).await?;
        record.phase = Phase::Complete(Completion {
            seq,
            id: matched.id,
            root: matched.root.clone(),
            receipt: None,
        });
        record.current = None;
        let landed = (root.bytes().to_vec(), root.id());
        let generation = record.generation;
        record.generation = generation
            .checked_add(1)
            .ok_or_else(|| refused("SyncCommitExhausted"))?;
        store.publication_transaction(|journal| journal.replace(generation, &record))?;
        landed
    };
    let (bytes, id) = landed;
    let Phase::Complete(done) = &record.phase else {
        return Err(refused("SyncCommitUnresolved").into());
    };
    let initial = granary_core::root::decode_root(&record.frozen.initial_root)
        .map_err(|_| refused("RecoveryLandedEvidenceMissing"))?;
    granary_store::crypto::check_head(
        &record.frozen.initial_root,
        volume.as_str(),
        initial.seq,
        keys,
    )
    .map_err(|_| refused("RecoveryLandedEvidenceMissing"))?;
    #[cfg(test)]
    if hooks.checkpoint_failure {
        return Err(super::RecoveryError::Remote(
            granary_core::rootstore::RootStoreError::Backend(
                "injected checkpoint read failure".into(),
            ),
        )
        .into());
    }
    let objects = super::read_closure(
        remote,
        store.recovery_store(),
        keys,
        &volume,
        initial.manifest_root,
        Some(&record.frozen),
    )
    .await?;
    let mut journal = RecoveryJournal::new(store, remote, keys);
    for (object, bytes) in objects.retained {
        journal
            .put_recovered(&object, &bytes)
            .map_err(super::RecoveryError::Journal)?;
    }
    drop(journal);
    if stored.is_none() {
        store.overlay_transaction(|transaction| {
            transaction.record_landed(&crate::LandedProof {
                boundary_seq: boundary,
                landed_root: id,
                landed_seq: done.seq,
                captured_entries: Vec::new(),
                entries: Vec::new(),
            })
        })?;
    }
    #[cfg(test)]
    FINISH_SUBSTITUTE.set(hooks.substitute);
    Ok(bytes)
}
