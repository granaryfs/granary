// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Bounded finishing of a replayed store on its authenticated recorded base.

use super::{drive, invalid, refusal, unavailable, verifies};
use crate::observe::FailureClass;
use crate::sync::{Cause, CommitDrive, Outcome, RuntimeSeams, refused};
use crate::writable_store::sync_engine::CoalesceState;
use crate::{
    AuthorityTransport, ClientMetrics, CoordinationError, OverlayIo, PublicationOutcome,
    RecoveryCommit, RecoveryIntent, SharedWritableStore, SyncEngine, SyncOptions, SyncRemote,
    SyncRuntime, TokioSyncRuntime, WritableAuthority, WritableStartError, WritableStore,
};
use granary_core::{
    clock::Clock,
    rng::Rng,
    root::{self, RootSig},
    secure_random::SecureRandom,
};
use granary_store::crypto::{SigningKey, TrustedKeys};
use std::sync::Arc;

#[cfg(test)]
std::thread_local! {
    static FINISH_FUTURE_SIZES: std::cell::Cell<(usize, usize, usize, usize)> = const {
        std::cell::Cell::new((0, 0, 0, 0))
    };
}

#[cfg(test)]
pub(crate) fn finish_future_sizes_for_test() -> (usize, usize, usize, usize) {
    FINISH_FUTURE_SIZES.with(|sizes| sizes.replace((0, 0, 0, 0)))
}

/// Inputs independent of a serving session or cache.
pub(crate) struct FinishInputs<'a, R, C> {
    pub(crate) remote: Arc<R>,
    pub(crate) runtime: &'a tokio::runtime::Runtime,
    pub(crate) key: &'a SigningKey,
    pub(crate) spare: SigningKey,
    pub(crate) clock: Arc<C>,
    pub(crate) metrics: ClientMetrics,
    pub(crate) view_mode: crate::ViewMode,
    pub(crate) deadline: tokio::time::Instant,
    /// The mount start's budget for the finishing engine.
    pub(crate) send_budget: Option<std::time::Duration>,
    pub(crate) landing: Option<Vec<u8>>,
    pub(crate) after_landing: fn(),
    pub(crate) keys: TrustedKeys,
    pub(crate) may_publish: bool,
    /// The command's authority is present for explicit recovery.
    pub(crate) selection_transport: Option<&'a R>,
    pub(crate) refuse: fn(CoordinationError, bool) -> WritableStartError,
}

/// Finish retained work and at most one residual commit, then detach the engine.
/// The caller's close runs after reporting and before engine teardown.
#[expect(
    clippy::too_many_lines,
    reason = "one ordered finish with explicit local transactions and engine teardown"
)]
pub(crate) fn finish_bound_store<R, P, C>(
    inputs: FinishInputs<'_, R, C>,
    mut mediator: WritableStore<P>,
    random: &mut (impl SecureRandom + Send),
    rng: &mut impl Rng,
    report: impl Fn(Outcome, &WritableStore<P>, bool, &'static str),
    close: impl FnOnce() -> Result<(), WritableStartError>,
) -> Result<(WritableStore<P>, bool), WritableStartError>
where
    R: WritableAuthority + SyncRemote + AuthorityTransport + Sync + 'static,
    P: OverlayIo + Send + Sync + 'static,
    C: Clock + 'static,
{
    let FinishInputs {
        remote,
        runtime,
        key,
        mut spare,
        clock,
        metrics,
        view_mode,
        deadline,
        send_budget,
        landing,
        after_landing,
        keys,
        may_publish,
        selection_transport,
        refuse,
    } = inputs;
    let settle_prepared = selection_transport.is_some();
    let workspace_bytes = mediator.construction_workspace_bytes;
    let public = *key.public_key();
    let scope = mediator.snapshot().scope.clone();
    let volume = mediator.snapshot().volume.clone();
    let reason = std::cell::Cell::new("obligations");
    let publication_proved = std::cell::Cell::new(false);
    let mut witness_suffix = false;
    #[cfg(test)]
    let hooks = super::finish::finish_hooks_for_engine_test();
    let steps = (|| {
        super::check_deadline(Some(deadline))?;
        let base = mediator.shutdown_base();
        #[cfg(test)]
        let base = (!super::finish::missing_base_for_test())
            .then_some(base)
            .flatten();
        let base = base.ok_or_else(|| refused("SyncBase"))?;
        // Step 3: a context the succession left retired is failed; its
        // network evidence stays.
        for capture in mediator.reopened_captures()? {
            mediator.fail_reopened_capture(&capture)?;
        }
        for request in mediator
            .retained_requests()
            .into_iter()
            .filter(|r| r.operation() == granary_core::overlay_ownership::Operation::Register)
        {
            drive(
                &mut mediator,
                remote.as_ref(),
                runtime,
                &scope,
                &request,
                &public,
                clock.as_ref(),
                rng,
                Some(deadline),
            )?;
        }
        // Step 4: a boundary no publication record names was never sent.
        reason.set("publication");
        let commits = mediator.recovery_commits()?;
        let record = {
            let (scope, volume) = (scope.clone(), volume.clone());
            mediator.publication_transaction(|j| j.load(&scope, &volume))?
        };
        let lane = commits.iter().any(|commit| {
            matches!(commit, RecoveryCommit::Boundary { publication_id, .. }
                if record.as_ref().is_some_and(|record| record.publication_id == *publication_id))
        });
        if !lane && matches!(commits.as_slice(), [RecoveryCommit::Boundary { .. }]) {
            mediator.reconcile_unsubmitted_commit()?;
        }
        Ok::<_, WritableStartError>((base, lane))
    })();
    let (mut base, lane) = match steps {
        Ok(state) => state,
        Err(error) => {
            report(
                super::finish::error_outcome(&error),
                &mediator,
                false,
                reason.get(),
            );
            return Err(finish_step_error(error, refuse));
        }
    };

    // Classify the selection only after settling requests that may change it.
    if let Some(transport) = selection_transport
        && !lane
        && landing.is_none()
        && may_publish
        && !mediator.snapshot().root.is_empty()
        && mediator.recovery_rule()? == crate::RecoveryRule::DirtyJournal
    {
        let mut journal = crate::RecoveryJournal::new(&mut mediator, transport, &keys);
        let witness = super::run_before(runtime, Some(deadline), journal.dirty_witness())
            .and_then(|result| result.map_err(Into::into));
        let witness = match witness {
            Ok(witness) => witness,
            Err(error) => {
                if matches!(
                    error,
                    WritableStartError::Coordination(CoordinationError::Refused(
                        "WritableRecoveryRequired"
                    ))
                ) {
                    reason.set("selected-root-not-proved-published");
                }
                report(
                    super::finish::error_outcome(&error),
                    &mediator,
                    false,
                    reason.get(),
                );
                return Err(error);
            }
        };
        if let Some(witness) = witness {
            super::check_deadline(Some(deadline))?;
            // The whole-tree seal requires serving permission under the closed mutation gate.
            mediator.check_finish_obligations()?;
            mediator.enter_recovery_serving()?;
            let base_bytes = mediator
                .mount_pin()
                .ok_or_else(|| refused("SyncBase"))?
                .base_bytes
                .clone();
            let event = witness.event;
            let shared = SharedWritableStore::new(mediator);
            let content = crate::MountSyncContent::for_recovery(shared.clone(), remote.clone());
            let mut key = Some(spare);
            let sync_runtime = Arc::new(TokioSyncRuntime);
            let comparison = (|| {
                let (engine, _) = super::run_before(
                    runtime,
                    Some(deadline),
                    SyncEngine::attach_with_runtime(
                        shared.as_arc(),
                        remote.clone(),
                        Arc::new(content.clone()),
                        clock.clone(),
                        Arc::new(crate::InstantClock::default()),
                        &mut key,
                        keys.clone(),
                        base_bytes,
                        metrics.clone(),
                        sync_runtime.clone(),
                        None,
                    ),
                )??;
                reason.set("namespace");
                let options = SyncOptions {
                    workspace_bytes,
                    deadline: Some(deadline),
                    ..SyncOptions::default()
                };
                let manifest_matches = witness.selection.is_none()
                    && runtime
                        .block_on(async {
                            tokio::time::timeout_at(deadline, engine.replayed_manifest(options))
                                .await
                        })
                        .map_err(|_| refused("SyncDeadline"))??
                        == witness.tree.manifest;
                super::check_deadline(Some(deadline))?;
                // An earlier publication needs a proved cut and the ordinary
                // suffix lane.
                if !manifest_matches {
                    let key = engine.into_comparison_key().ok_or_else(finish_leaked)?;
                    witness_suffix = true;
                    // On a rerun the authenticated journal base itself proves the empty cut.
                    let installation =
                        if (witness.tree.view.base_id, witness.tree.view.base_seq) == base {
                            None
                        } else {
                            Some(prove_recovered_suffix(
                                &shared,
                                &content,
                                witness,
                                runtime,
                                &sync_runtime,
                                workspace_bytes,
                                deadline,
                            )?)
                        };
                    return Ok(Some((key, installation)));
                }
                reason.set("obligations");
                shared.with(|store| {
                    store.check_recovery_owner()?;
                    store.check_finish_obligations()?;
                    if (witness.tree.view.base_id, witness.tree.view.base_seq) == base
                        && store.check_finish_namespace().is_ok()
                    {
                        store.normalize_finished(true)?;
                    } else {
                        store.overlay_transaction(|overlay| overlay.replace_recovered(witness))?;
                    }
                    store.check_finish_obligations()
                })?;
                Ok::<_, WritableStartError>(None)
            })();
            drop(content);
            match comparison {
                Ok(Some((returned_key, installation))) => {
                    spare = returned_key;
                    mediator = detach_finished(shared)?;
                    if let Some((witness, mut suffix)) = installation {
                        mediator.check_recovery_owner()?;
                        mediator.check_finish_obligations()?;
                        if granary_core::hash::GrainId::of(&mediator.snapshot().root)
                            != witness.selected
                        {
                            return Err(refused("WritableRecoveryRequired").into());
                        }
                        // A clean replacement may discard the selection's registration.
                        // Select the proved, already published witness before switching.
                        if suffix.retires_registration() {
                            let request = mediator.prepare_registration(
                                &witness.tree.view.base_bytes,
                                vec![],
                                clock.as_ref(),
                                |doc, prefix| verifies(&public, doc, prefix),
                            )?;
                            let generation =
                                crate::writable_store::sync_engine::generation(&request)?;
                            suffix.record_handoff(generation)?;
                            drive(
                                &mut mediator,
                                remote.as_ref(),
                                runtime,
                                &scope,
                                &request,
                                &public,
                                clock.as_ref(),
                                rng,
                                Some(deadline),
                            )?;
                        }
                        base = install_recovered_suffix(&mut mediator, witness, suffix)?;
                    }
                }
                Ok(None) => {
                    let store = detach_finished(shared)?;
                    report(Outcome::Clean, &store, false, reason.get());
                    close()?;
                    crate::observe::recover(event);
                    return Ok((store, true));
                }
                Err(error) => {
                    let _ = shared.with(|store| {
                        report(
                            super::finish::error_outcome(&error),
                            store,
                            false,
                            reason.get(),
                        );
                        Ok(())
                    });
                    return Err(error);
                }
            }
        }
    }
    reason.set("publication");
    let steps = (|| {
        // Step 5: what is owed. A lane registers nothing before its own
        // landing's refresh; a journal replay left with nothing owed needs no
        // engine; any other re-registers the carrier's root, never below it.
        if !lane {
            let options = SyncOptions {
                workspace_bytes,
                ..SyncOptions::default()
            };
            if mediator.coalesce_state(&options, TokioSyncRuntime.now())? == CoalesceState::Clean
                || !may_publish
            {
                let proved = finish_clean(
                    &mut mediator,
                    remote.as_ref(),
                    runtime,
                    key,
                    clock.as_ref(),
                    random,
                    deadline,
                    &keys,
                    settle_prepared,
                    may_publish,
                    &reason,
                )?;
                publication_proved.set(proved);
                reason.set("obligations");
                mediator.check_finish_obligations()?;
                return Ok(None);
            }
            if !may_publish {
                return Err(refused("WritableRecoveryRequired").into());
            }
            let registered = mediator.snapshot().root.clone();
            let bytes = if registered.is_empty() {
                base_registration(&mediator, key, clock.as_ref())?
            } else {
                registered
            };
            let request =
                mediator.prepare_registration(&bytes, vec![], clock.as_ref(), |doc, prefix| {
                    verifies(&public, doc, prefix)
                })?;
            drive(
                &mut mediator,
                remote.as_ref(),
                runtime,
                &scope,
                &request,
                &public,
                clock.as_ref(),
                rng,
                Some(deadline),
            )?;
        }
        let view = mediator.mount_pin();
        #[cfg(test)]
        let view = (!super::finish::missing_pin_for_test())
            .then_some(view)
            .flatten();
        let base_bytes = view.ok_or_else(|| refused("SyncBase"))?.base_bytes.clone();
        #[cfg(test)]
        if let Some(delay) = hooks.before_engine_delay {
            crate::overlay_test_support::block_for_test(delay);
        }
        let engine_deadline = if let Some(budget) = send_budget {
            super::check_deadline(Some(deadline))?;
            TokioSyncRuntime
                .now()
                .checked_add(budget)
                .map_or(deadline, |extended| deadline.max(extended))
        } else {
            deadline
        };
        Ok::<_, WritableStartError>(Some((base, base_bytes, engine_deadline)))
    })();
    let (base, base_bytes, engine_deadline) = match steps {
        Ok(Some(engine)) => engine,
        Ok(None) => {
            report(Outcome::Clean, &mediator, false, reason.get());
            close()?;
            return Ok((mediator, publication_proved.get()));
        }
        Err(error) => {
            report(
                super::finish::error_outcome(&error),
                &mediator,
                false,
                reason.get(),
            );
            return Err(finish_step_error(error, refuse));
        }
    };
    // One mount-less engine. Only a mount start gets the publish budget.
    let shared = SharedWritableStore::new(mediator);
    let engine_remote = remote.clone();
    let content = crate::MountSyncContent::for_recovery(shared.clone(), engine_remote.clone());
    let sync_runtime = Arc::new(TokioSyncRuntime);
    reason.set("publication");
    let finish = async {
        let defaults = SyncOptions::default();
        let options = SyncOptions {
            workspace_bytes,
            deadline: Some(engine_deadline),
            resolution_bound: send_budget.unwrap_or(defaults.resolution_bound),
            ..defaults
        };
        let (engine, _) = SyncEngine::attach_with_runtime(
            shared.as_arc(),
            engine_remote.clone(),
            Arc::new(content.clone()),
            clock.clone(),
            Arc::new(crate::InstantClock::default()),
            &mut Some(spare),
            keys,
            base_bytes.clone(),
            metrics.clone(),
            sync_runtime.clone(),
            None,
        )
        .await
        .map_err(|error| (error, true, false))?;
        #[cfg(test)]
        if let Some(floor) = hooks.dispatch_floor {
            engine.set_start_dispatch_floor_for_test(floor);
        }
        let finish_with = finish_with(
            &engine,
            &shared,
            content,
            engine_remote,
            &sync_runtime,
            &volume,
            view_mode,
            clock.clone(),
            metrics,
            engine_deadline,
            options,
            send_budget.is_some(),
            random,
            landing,
            after_landing,
        );
        #[cfg(test)]
        FINISH_FUTURE_SIZES.with(|sizes| {
            let (bound, _, timeout, selected) = sizes.get();
            sizes.set((
                bound,
                std::mem::size_of_val(&finish_with),
                timeout,
                selected,
            ));
        });
        let finished = finish_with.await;
        let conflict = engine.has_commit_conflict();
        finished
            .map(|()| engine)
            .map_err(|error| (error, false, conflict))
    };
    #[cfg(test)]
    FINISH_FUTURE_SIZES.with(|sizes| {
        let (_, inner, timeout, selected) = sizes.get();
        sizes.set((std::mem::size_of_val(&finish), inner, timeout, selected));
    });
    // The start's runtime's own timer cuts the finish: its future borrows
    // the phase's state, so it is not spawned. It is boxed so the timer
    // carries a pointer, not the phase, and drops the phase inside the
    // runtime.
    let finish = Box::pin(finish);
    let bounded = async { tokio::time::timeout_at(engine_deadline, finish).await };
    #[cfg(test)]
    FINISH_FUTURE_SIZES.with(|sizes| {
        let (bound, inner, _, selected) = sizes.get();
        sizes.set((bound, inner, std::mem::size_of_val(&bounded), selected));
    });
    let finished = runtime
        .block_on(bounded)
        .map_err(|_| (crate::sync::refused("SyncDeadline"), false, false))
        .and_then(std::convert::identity);
    let finished = finished.and_then(|engine| {
        reason.set("obligations");
        shared
            .with(WritableStore::check_finish_obligations)
            .map(|()| engine)
            .map_err(|error| (error, false, false))
    });
    let mut conflict = false;
    let (outcome, result) = match finished {
        Ok(engine) => {
            let current = shared.with(|store| Ok(store.shutdown_base()));
            #[cfg(test)]
            let current = current.map(|current| {
                if super::finish::unchanged_base_for_test() {
                    Some(base)
                } else {
                    current
                }
            });
            match current {
                Ok(Some(now)) if now != base => (Outcome::Committed(now.1), Ok(engine)),
                _ => (
                    Outcome::Incomplete(Cause::Failed(FailureClass::Internal)),
                    Err(WritableStartError::Refused(
                        "WritableRecoveryRequired",
                        FailureClass::Internal,
                    )),
                ),
            }
        }
        Err((error, attaching, proved_conflict)) => {
            conflict = proved_conflict;
            let outcome = match &error {
                CoordinationError::Fenced { .. } | CoordinationError::CommitFenced { .. } => {
                    Outcome::Fenced
                }
                CoordinationError::Refused("SyncDeadline") => Outcome::Incomplete(Cause::Deadline),
                error => Outcome::Incomplete(Cause::Failed(crate::sync::failure_class(error))),
            };
            (outcome, Err(refuse(error, attaching)))
        }
    };
    #[cfg(test)]
    if super::finish::poison_before_report_for_test() {
        let shared = shared.as_arc();
        let _ = std::thread::spawn(move || {
            let _store = shared.lock().unwrap();
            panic!("poison the finish reporter's mediator");
        })
        .join();
    }
    let reporting = shared.as_arc();
    let store = reporting
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    report(outcome, &store, conflict, reason.get());
    drop(store);
    drop(reporting);
    let engine = result?;
    #[cfg(test)]
    super::finish::hold_for_test(&engine);
    close()?;
    drop(engine);
    let mut store = detach_finished(shared)?;
    // A suffix counts as published only when its ordinary landing installed
    // the exact root selected by the durable refresh.
    if witness_suffix {
        if !store.finish_publication_proved()? {
            return Err(refused("WritableRecoveryRequired").into());
        }
        publication_proved.set(true);
    }
    Ok((store, publication_proved.get()))
}

// Recovery admits no more mutations between taking the source and installing
// it. Remote range reads run before the install acquisition.
fn prove_recovered_suffix<R, P>(
    shared: &SharedWritableStore<P>,
    content: &crate::MountSyncContent<R, P>,
    witness: crate::recovery::DirtyWitness,
    runtime: &tokio::runtime::Runtime,
    sync_runtime: &Arc<TokioSyncRuntime>,
    workspace: u64,
    deadline: tokio::time::Instant,
) -> Result<
    (
        crate::recovery::DirtyWitness,
        crate::overlay_store::RecoveredSuffix,
    ),
    WritableStartError,
>
where
    R: SyncRemote + 'static,
    P: OverlayIo + Send + Sync + 'static,
{
    #[expect(
        clippy::redundant_closure_for_method_calls,
        reason = "the method item fixes the overlay borrow's lifetime"
    )]
    let prefix = shared.overlay_transaction(|overlay| overlay.recovery_prefix())?;
    let (witness, suffix) = runtime
        .block_on(async {
            let content = content.with_deadline(sync_runtime.clone(), deadline);
            let proof_runtime = sync_runtime.clone();
            sync_runtime
                .blocking(move || {
                    let suffix = prefix.prove(
                        &witness,
                        &content,
                        |tree, id, offset, length| {
                            content.read_content_in(Some(&tree.view), id, offset, length)
                        },
                        workspace,
                        deadline,
                        proof_runtime.as_ref(),
                    )?;
                    Ok::<_, CoordinationError>((witness, suffix))
                })
                .await
        })
        .map_err(|_| refused("SyncMaterializationLost"))?
        .map_err(|error| match error {
            CoordinationError::Refused("SyncWorkspaceExhausted") => {
                crate::OverlayError::no_space().into()
            }
            error => error,
        })?;
    super::check_deadline(Some(deadline))?;
    Ok((witness, suffix))
}

fn install_recovered_suffix<P: OverlayIo>(
    store: &mut WritableStore<P>,
    witness: crate::recovery::DirtyWitness,
    suffix: crate::overlay_store::RecoveredSuffix,
) -> Result<(granary_core::hash::GrainId, u64), CoordinationError> {
    let view = witness.tree.view.clone();
    let change = store
        .overlay_transaction(|overlay| overlay.replace_recovered_suffix(witness, suffix))
        .map_err(|error| match error {
            CoordinationError::Overlay(crate::OverlayError::Refused(
                "WritableRecoveryRequired",
            )) => refused("WritableRecoveryRequired"),
            error => error,
        })?;
    store.replace_leases(&change.retired);
    let base = (view.base_id, view.base_seq);
    store.bind_mount(view);
    Ok(base)
}

fn finish_leaked() -> WritableStartError {
    WritableStartError::Refused("WritableFinishLeaked", FailureClass::Internal)
}

fn finish_step_error(
    error: WritableStartError,
    refuse: fn(CoordinationError, bool) -> WritableStartError,
) -> WritableStartError {
    match error {
        WritableStartError::Coordination(CoordinationError::Refused("SyncDeadline")) => {
            refuse(crate::sync::refused("SyncDeadline"), false)
        }
        error => error,
    }
}

fn detach_finished<P: OverlayIo>(
    shared: SharedWritableStore<P>,
) -> Result<WritableStore<P>, WritableStartError> {
    let leaked = finish_leaked();
    let Some(mut store) = shared.into_inner() else {
        return Err(leaked);
    };
    if !store.detach_sync_engine() {
        return Err(leaked);
    }
    Ok(store)
}

/// Prove P before semantic normalization; recovery also owes this proof
/// after replay leaves an already canonical journal.
#[expect(
    clippy::too_many_arguments,
    reason = "the store, transport and runtime, signing and trust, clock and entropy, and the caller's bound and publication obligation"
)]
fn finish_clean<R, P, C>(
    store: &mut WritableStore<P>,
    remote: &R,
    runtime: &tokio::runtime::Runtime,
    key: &SigningKey,
    clock: &C,
    secure: &mut (impl SecureRandom + Send),
    deadline: tokio::time::Instant,
    keys: &TrustedKeys,
    settle_prepared: bool,
    may_publish: bool,
    reason: &std::cell::Cell<&'static str>,
) -> Result<bool, WritableStartError>
where
    R: WritableAuthority + SyncRemote + AuthorityTransport + Sync + 'static,
    P: OverlayIo + Send + Sync + 'static,
    C: Clock,
{
    reason.set("replay");
    let normalize = store.finish_normalization_required()?;
    if !normalize && !settle_prepared {
        return Ok(true);
    }
    reason.set("namespace");
    if let Err(error) = store.check_finish_namespace() {
        if !may_publish {
            reason.set("publication");
        }
        return Err(error.into());
    }
    reason.set("publication");
    let mut published = store.finish_publication_proved()?;
    if !published {
        if !may_publish {
            return Err(refused("WritableRecoveryRequired").into());
        }
        let scope = store.snapshot().scope.clone();
        let volume = store.snapshot().volume.clone();
        let writer = store.writer_uuid();
        let bytes = store.snapshot().root.clone();
        let record = store.publication_transaction(|j| j.load(&scope, &volume))?;
        // An owed live R is never replaced by classification of P.
        if record.as_ref().is_some_and(|r| !r.is_complete()) {
            return Err(refused("WritableRecoveryRequired").into());
        }
        #[cfg(test)]
        if FINISH_FUTURE_SIZES.with(|sizes| sizes.get().3 == 0) {
            let transport =
                crate::HttpStore::new("https://127.0.0.1:1", vec![[1; 32]], &crate::AmbientNetwork)
                    .unwrap();
            let mut journal = crate::RecoveryJournal::new(store, &transport, keys);
            let mut delay = RuntimeSeams(&TokioSyncRuntime);
            let measured = selected_publication(
                crate::RecoveryParts {
                    transport: &transport,
                    journal: &mut journal,
                    publisher_keys: keys,
                    signer: key,
                    secure,
                    clock,
                    delay: &mut delay,
                },
                scope.clone(),
                volume.clone(),
                writer,
                bytes.clone(),
                deadline,
            );
            FINISH_FUTURE_SIZES.with(|sizes| {
                let (bound, inner, timeout, _) = sizes.get();
                sizes.set((bound, inner, timeout, std::mem::size_of_val(&measured)));
            });
        }
        let mut journal = crate::RecoveryJournal::new(store, remote, keys);
        let mut delay = RuntimeSeams(&TokioSyncRuntime);
        let selected = selected_publication(
            crate::RecoveryParts {
                transport: remote,
                journal: &mut journal,
                publisher_keys: keys,
                signer: key,
                secure,
                clock,
                delay: &mut delay,
            },
            scope,
            volume,
            writer,
            bytes,
            deadline,
        );
        let result = runtime.block_on(selected)?;
        published = match result {
            crate::SelectedPublication::Subsumed { .. } => true,
            crate::SelectedPublication::Stale if settle_prepared => {
                return Err(refused("RecoveryStale").into());
            }
            crate::SelectedPublication::Driven(result)
                if matches!(result.outcome, PublicationOutcome::Landed(_)) =>
            {
                true
            }
            crate::SelectedPublication::Driven(_) if settle_prepared => {
                return Err(refused("RecoveryPublicationUnresolved").into());
            }
            crate::SelectedPublication::Stale | crate::SelectedPublication::Driven(_) => false,
        };
    }
    super::check_deadline(Some(deadline))?;
    reason.set("obligations");
    if normalize {
        store.normalize_finished(published)?;
    } else if !published {
        return Err(refused("WritableRecoveryRequired").into());
    }
    Ok(published)
}

async fn selected_publication<T: AuthorityTransport, J: crate::PublicationJournal>(
    parts: crate::RecoveryParts<'_, T, J>,
    scope: granary_core::retained_submission::Scope,
    volume: root::VolumeName,
    writer: [u8; 16],
    bytes: Vec<u8>,
    deadline: tokio::time::Instant,
) -> Result<crate::SelectedPublication, CoordinationError> {
    tokio::time::timeout_at(
        deadline,
        crate::begin_selected_publication(parts, scope, volume, writer, bytes),
    )
    .await
    .map_err(|_| refused("SyncDeadline"))?
    .map_err(CoordinationError::Recovery)
}

/// The phase's mount-less engine.
type FinishEngine<P, R, C> =
    SyncEngine<P, R, crate::MountSyncContent<R, P>, C, crate::InstantClock>;

/// The finish under the phase's bound: bind the engine's hook over an
/// unattended gate, drive a retained lane to its end or finish its recorded
/// landing, then commit whatever is left once.
#[expect(
    clippy::too_many_arguments,
    reason = "the engine with its store, content, remote and runtime, the inputs and wall clock, metrics, the bound and entropy"
)]
async fn finish_with<R, P, C>(
    engine: &Arc<FinishEngine<P, R, C>>,
    shared: &SharedWritableStore<P>,
    content: crate::MountSyncContent<R, P>,
    remote: Arc<R>,
    sync_runtime: &Arc<TokioSyncRuntime>,
    volume: &granary_core::root::VolumeName,
    view_mode: crate::ViewMode,
    wall: Arc<C>,
    metrics: ClientMetrics,
    deadline: tokio::time::Instant,
    options: SyncOptions,
    start: bool,
    random: &mut (impl SecureRandom + Send),
    landing: Option<Vec<u8>>,
    after_landing: fn(),
) -> Result<(), CoordinationError>
where
    R: WritableAuthority + SyncRemote + AuthorityTransport + Sync + 'static,
    P: OverlayIo + Send + 'static,
    C: Clock + 'static,
{
    let secure: &mut (dyn SecureRandom + Send) = random;
    // The hook's observer is armed and never driven: no boundary runs
    // without an adapter.
    let observer = Arc::new(crate::sync::HeadObserver::new(
        remote,
        sync_runtime.clone(),
        volume.clone(),
        wall,
        view_mode,
        Some(metrics),
    ));
    super::ViewBinding::<R, P>::new(
        engine.clone(),
        content,
        sync_runtime.clone(),
        observer,
        None,
    )
    .bind_gate(
        Arc::new(super::sync::UnattendedGate::default()),
        granary_fuse::kernel_time,
    )?;
    engine.install_locally();
    // Step 6a: a retained lane driven under explicit recovery to its end. A
    // landing it recorded and never installed is finished, not submitted
    // again: the coordinator answers a complete record as landed.
    if let Some(landing) = landing {
        engine.finish_recovered_landing(landing, options).await?;
        after_landing();
    } else {
        let drive = if start {
            CommitDrive::Start(RecoveryIntent::ExplicitRecovery)
        } else {
            CommitDrive::Mount(RecoveryIntent::ExplicitRecovery)
        };
        engine.take_over(options, deadline, drive, secure).await?;
    }
    // Step 6b: one commit of whatever is left.
    let now = sync_runtime.now();
    if shared.with(|store| store.coalesce_state(&options, now))? != CoalesceState::Clean {
        let lane = engine.construct_commit(options, secure).await?;
        let drive = if start {
            CommitDrive::Start(RecoveryIntent::Continue)
        } else {
            CommitDrive::Direct(RecoveryIntent::Continue)
        };
        let result = Box::pin(engine.drive_commit_for(
            &lane,
            secure,
            &mut RuntimeSeams(sync_runtime.as_ref()),
            drive,
            options,
        ))
        .await?;
        if !matches!(result.outcome, PublicationOutcome::Landed(_)) {
            // A proven refusal or an exhausted budget has fenced the
            // store, and that fence is the answer.
            shared.with(|store| store.sync_admission_open())?;
            return Err(crate::sync::refused("SyncCommitUnresolved"));
        }
    }
    Ok(())
}

/// The base's tree re-signed at the base's next seq, as the start registers
/// the head's: the registration a store with no registered root sends.
fn base_registration<P: OverlayIo>(
    mediator: &WritableStore<P>,
    key: &SigningKey,
    clock: &impl Clock,
) -> Result<Vec<u8>, WritableStartError> {
    let view = mediator.mount_pin().ok_or_else(|| refused("SyncBase"))?;
    let mut prepared = root::decode_root(&view.base_bytes).map_err(|_| refused("SyncBase"))?;
    prepared.seq = prepared
        .seq
        .checked_add(1)
        .filter(|seq| *seq < u64::MAX)
        .ok_or_else(|| refusal("WritableRecoveryRequired"))?;
    prepared.parent = Some(view.base_id);
    prepared.writer_uuid = mediator.writer_uuid();
    prepared.timestamp = clock.now();
    prepared.sigs.clear();
    let prefix = root::signing_prefix_of(&prepared).map_err(|_| invalid("IntentPreparedRoot"))?;
    prepared.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&prefix),
    });
    root::encode_root(&prepared).map_err(|_| invalid("IntentPreparedRoot"))
}

/// The start's refusal for a finish that stopped at `error`. A fence keeps
/// its own name; anything a later attempt may clear is the authority's
/// unavailability; every other refusal keeps its own name. An unresolved
/// commit is unavailable once the engine runs, and permanent when the
/// attach meets it: a terminal refusal with no provable non-landing.
pub(super) fn finish_refusal(error: CoordinationError, attaching: bool) -> WritableStartError {
    match error {
        CoordinationError::Fenced { .. } | CoordinationError::CommitFenced { .. } => {
            WritableStartError::Coordination(error)
        }
        CoordinationError::Refused("SyncCommitUnresolved") if attaching => {
            WritableStartError::Coordination(error)
        }
        error if crate::sync::failure_class(&error) == FailureClass::Unavailable => {
            unavailable("WritableAuthorityUnavailable")
        }
        error => WritableStartError::Coordination(error),
    }
}
