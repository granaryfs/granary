// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The start's finishing phase: a store whose journal holds work is finished
//! on the journal's own base, in one commit, before the mount serves.

use super::{
    WritableAuthority, WritableStart, WritableStartError, invalid, overlay_base, pinned_files,
    unavailable,
};
use crate::observe::{self, FailureClass, OperationKind};
use crate::sync::{Cause, Outcome};
use crate::{
    AuthorityTransport, ClientMetrics, CoordinationError, MountSession, OverlayIo, SyncRemote,
    SyncRuntime, TokioSyncRuntime, WritableStore,
};
use granary_core::{
    clock::Clock, hash::GrainId, overlay_journal::JournalHeader, rng::Rng,
    secure_random::SecureRandom,
};
use granary_store::crypto::SigningKey;
use std::sync::Arc;

/// What the start hands the phase, besides the store it finishes.
pub(super) struct Inputs<'a, R, C> {
    pub(super) input: &'a WritableStart<'a>,
    /// The cache directory, which the start has checked.
    pub(super) cache_path: &'a std::path::Path,
    pub(super) remote: &'a R,
    pub(super) runtime: &'a tokio::runtime::Runtime,
    pub(super) public: [u8; 32],
    /// Signs a registration the phase sends itself.
    pub(super) key: &'a SigningKey,
    /// The second key from the same seed, which the phase's engine takes.
    pub(super) spare: SigningKey,
    pub(super) clock: &'a C,
}

/// Finish the shutdown the journal on base `base` was left by, before the
/// start serves: the overlay is opened on that base in a session at its
/// seq, reopened captures are failed, a boundary no record names is
/// stripped, then a mount-less engine drives any retained lane to its end,
/// installs a landing recorded and never installed, and commits the rest in
/// one commit. Every landing installs unattended. The shutdown bound
/// covers the steps before the engine, whose budget allows the authority
/// to answer a publish. The store comes back with the engine detached,
/// on the head the finish produced.
///
/// # Errors
/// The first step's refusal, the store kept as it left it: see the
/// operator page's refusal table.
pub(super) fn finish_interrupted_shutdown<R, P, C>(
    inputs: Inputs<'_, R, C>,
    base: (GrainId, u64),
    mut mediator: WritableStore<P>,
    io: P,
    random: &mut (impl SecureRandom + Send),
    rng: &mut impl Rng,
    sink: &mut dyn crate::LocalReporter,
) -> Result<WritableStore<P>, WritableStartError>
where
    R: WritableAuthority + SyncRemote + AuthorityTransport + Sync + 'static,
    P: OverlayIo + Send + Sync + 'static,
    C: Clock + Clone + 'static,
{
    observe::op_begin(OperationKind::Unmount);
    let started = TokioSyncRuntime.now();
    let Some(deadline) = started.checked_add(phase_bound()) else {
        return Err(ended(
            super::refusal("WritableRecoveryRequired"),
            &mediator,
            started,
        ));
    };

    let Inputs {
        input,
        cache_path,
        remote,
        runtime,
        public,
        key,
        spare,
        clock,
    } = inputs;
    // Step 1: the session at the journal's base, which neither floor binds.
    let opened = MountSession::open(
        remote.read_facade(),
        input.volume.clone(),
        Some(Box::new(public)),
        None,
        false,
        Some(base.1),
        cache_path,
        input.cache_quota,
        &input.cache_origin,
        input.options,
        sink,
    )
    .map_err(WritableStartError::ReadView)
    .and_then(|session| {
        if GrainId::of(&session.pre.root_bytes) == base.0 {
            Ok(session)
        } else {
            Err(invalid("WritableDiscoveryInvalid"))
        }
    });
    #[cfg(test)]
    if let Some(delay) = HOOKS.with_borrow(|hooks| hooks.after_open_delay) {
        crate::overlay_test_support::block_for_test(delay);
    }
    let mut session = match opened {
        Ok(session) => session,
        Err(error) => return Err(ended(error, &mediator, started)),
    };
    if let Err(error) = super::check_deadline(Some(deadline)) {
        report(error_outcome(&error), &mediator, started);
        return Err(unavailable("WritableAuthorityUnavailable"));
    }
    #[cfg(test)]
    if TokioSyncRuntime.now() >= deadline {
        LATE_LOCAL_WORK.set(true);
    }
    if let Err(error) = replay_interrupted_shutdown(&mut session, input, base, &mut mediator, io) {
        return Err(ended(error, &mediator, started));
    }
    let metrics = session
        .metrics()
        .cloned()
        .unwrap_or_else(|| ClientMetrics::new(&mut *random));
    let remote = session.remote_for_sync();
    let send_budget = crate::sync::commit_send_budget();
    #[cfg(test)]
    let send_budget = HOOKS
        .with_borrow(|hooks| hooks.budget)
        .unwrap_or(send_budget);
    super::shared_finish::finish_bound_store(
        super::shared_finish::FinishInputs {
            remote,
            runtime,
            key,
            spare,
            clock: Arc::new(clock.clone()),
            metrics,
            view_mode: input.view,
            deadline,
            send_budget: Some(send_budget),
            refuse: super::shared_finish::finish_refusal,
            may_publish: true,
            selection_transport: None,
            landing: None,
            after_landing: || {},
            keys: granary_store::crypto::TrustedKeys::new([public])
                .map_err(|_| invalid("SyncBase"))?,
        },
        mediator,
        random,
        rng,
        |outcome, store, _, _| report(outcome, store, started),
        || close_session(session),
    )
    .map(|(store, _)| store)
}

/// Replay the interrupted journal on the session opened at its exact base and
/// bind that authenticated view to the mediator.
fn replay_interrupted_shutdown<R, P>(
    session: &mut MountSession<R>,
    input: &WritableStart<'_>,
    base: (GrainId, u64),
    mediator: &mut WritableStore<P>,
    io: P,
) -> Result<(), WritableStartError>
where
    R: WritableAuthority,
    P: OverlayIo,
{
    let pin_nodes = session.pre.nodes.clone();
    let snapshot = session
        .snapshot(input.policy)
        .map_err(|_| invalid("WritableSnapshotRefused"))?;
    let entries = overlay_base(&snapshot)?;
    let pin_files = pinned_files(&snapshot, &entries)?;
    let header = JournalHeader {
        writer: mediator.writer_uuid(),
        base_root: base.0,
        base_seq: base.1,
        next_stage_id: 1,
        receipt_generation: 0,
    };
    #[cfg(test)]
    let mut io = io;
    #[cfg(test)]
    if HOOKS.with_borrow(|hooks| hooks.fault == FinishFault::JournalAbsentWithUnmerged) {
        let root = input
            .store
            .ok_or_else(|| invalid("WritableStoreRequired"))?;
        let scope = input
            .scope
            .as_ref()
            .ok_or_else(|| invalid("WritableScopeRequired"))?;
        let area = crate::overlay_store::area_path(root, scope, &input.volume)
            .map_err(CoordinationError::Overlay)?;
        for name in io
            .entries(&area.join("staging"))
            .map_err(crate::OverlayError::from)
            .map_err(CoordinationError::Overlay)?
        {
            io.remove(&area.join("staging").join(name))
                .map_err(crate::OverlayError::from)
                .map_err(CoordinationError::Overlay)?;
        }
        io.remove(&area.join("journal"))
            .map_err(crate::OverlayError::from)
            .map_err(CoordinationError::Overlay)?;
        io.create_directory(&area.join("unmerged"))
            .map_err(crate::OverlayError::from)
            .map_err(CoordinationError::Overlay)?;
        io.create(&area.join("unmerged/0000000000000001"))
            .map_err(crate::OverlayError::from)
            .map_err(CoordinationError::Overlay)?;
        io.write_at(&area.join("unmerged/0000000000000001"), 0, b"held")
            .map_err(crate::OverlayError::from)
            .map_err(CoordinationError::Overlay)?;
    }
    mediator.open_overlay_local(header, entries, io, false)?;
    let view = session_view(session, pin_nodes, pin_files);
    mediator.bind_mount(Arc::new(view));
    Ok(())
}

/// Report a phase that ended at `error` before its engine ran, and answer it.
fn ended<P: OverlayIo>(
    error: WritableStartError,
    mediator: &WritableStore<P>,
    started: tokio::time::Instant,
) -> WritableStartError {
    report(error_outcome(&error), mediator, started);
    error
}

/// Emit the phase's event for `outcome`, with what `mediator` holds.
fn report<P: OverlayIo>(
    outcome: Outcome,
    mediator: &WritableStore<P>,
    started: tokio::time::Instant,
) {
    let report = crate::sync::report_outcome(
        observe::UnmountTrigger::Start,
        outcome,
        matches!(outcome, Outcome::Incomplete(Cause::Deadline)).then_some(crate::sync::Cut::Bound),
        mediator.shutdown_report().as_ref(),
        mediator.shutdown_base(),
        elapsed(started),
        false,
    );
    #[cfg(test)]
    LAST_REPORT.set(Some(report));
    #[cfg(not(test))]
    let _ = report;
}

/// Milliseconds since `started`.
fn elapsed(started: tokio::time::Instant) -> u64 {
    u64::try_from(
        TokioSyncRuntime
            .now()
            .saturating_duration_since(started)
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

/// Close the phase's session with its own shutdown: the close releases the
/// cache's lock whether or not it succeeds, and a failed one refuses.
pub(super) fn close_session<R>(mut session: MountSession<R>) -> Result<(), WritableStartError>
where
    R: granary_core::rootstore::RootStore + granary_core::binstore::BinStore + Send + 'static,
{
    #[cfg(test)]
    if HOOKS.with_borrow(|hooks| hooks.keep_session) {
        HELD.with_borrow_mut(|held| held.push(Box::new(session)));
        return Ok(());
    }
    granary_fuse::MountBackend::shutdown(&mut session)
        .map_err(|_| WritableStartError::Refused("WritableCacheCloseFailed", FailureClass::Io))
}

/// The start's runtime. When the start returns it shuts down within
/// [`super::RUNTIME_SHUTDOWN_SLACK`], so blocking work a finish cut at its bound
/// left running cannot hold the start; that work dies with the process.
pub(super) struct StartRuntime(Option<tokio::runtime::Runtime>);
impl StartRuntime {
    pub(super) fn new(runtime: tokio::runtime::Runtime) -> Self {
        Self(Some(runtime))
    }
    pub(super) fn get(&self) -> Result<&tokio::runtime::Runtime, WritableStartError> {
        self.0
            .as_ref()
            .ok_or_else(|| unavailable("WritableAuthorityUnavailable"))
    }
}
impl Drop for StartRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_timeout(super::RUNTIME_SHUTDOWN_SLACK);
        }
    }
}

/// The view `session` opened, with its structure nodes `pin_nodes`, which
/// its snapshot takes, and its clean files `pin_files`.
pub(super) fn session_view<R>(
    session: &MountSession<R>,
    pin_nodes: std::collections::BTreeMap<GrainId, Vec<u8>>,
    pin_files: std::collections::BTreeMap<GrainId, (u64, granary_core::manifest::FileGrains)>,
) -> crate::writable_store::ViewContext {
    crate::writable_store::ViewContext {
        base_id: GrainId::of(&session.pre.root_bytes),
        base_seq: session.pre.doc.seq,
        base_bytes: session.pre.root_bytes.clone(),
        bins: std::sync::Arc::from(session.pre.bins.as_slice()),
        entries: session.pre.entries.clone(),
        pin_files,
        pin_nodes,
    }
}

/// The bound on the finish's pre-engine steps.
pub(super) fn phase_bound() -> std::time::Duration {
    #[cfg(test)]
    if let Some(bound) = HOOKS.with_borrow(|hooks| hooks.bound) {
        return bound;
    }
    crate::sync::DEFAULT_SHUTDOWN_BOUND
}

/// What a test changes in the next phases on its thread.
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct FinishHooks {
    /// The bound on pre-engine steps, in place of the default.
    pub(crate) bound: Option<std::time::Duration>,
    /// The finishing engine's budget, in place of the default.
    pub(crate) budget: Option<std::time::Duration>,
    /// The full floor for dispatching a publish, in place of the default.
    pub(crate) dispatch_floor: Option<std::time::Duration>,
    /// Hold the pre-engine steps at the handoff.
    pub(crate) before_engine_delay: Option<std::time::Duration>,
    /// Keep a clone of the engine past the teardown.
    pub(crate) hold_engine: bool,
    /// Keep the phase's session open past the teardown.
    pub(crate) keep_session: bool,
    /// Present the engine's completed base as unchanged to its classifier.
    pub(crate) unchanged_base: bool,
    /// Hold the phase after its session open returns.
    pub(crate) after_open_delay: Option<std::time::Duration>,
    /// The local invariant or reporting fault this phase presents.
    pub(crate) fault: FinishFault,
}

#[cfg(test)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinishFault {
    #[default]
    None,
    MissingBase,
    MissingPin,
    PoisonBeforeReport,
    JournalAbsentWithUnmerged,
}

#[cfg(test)]
std::thread_local! {
    static HOOKS: std::cell::RefCell<FinishHooks> = std::cell::RefCell::default();
    static HELD: std::cell::RefCell<Vec<Box<dyn std::any::Any>>> = std::cell::RefCell::default();
    static LAST_REPORT: std::cell::Cell<Option<crate::sync::ShutdownReport>> = const {
        std::cell::Cell::new(None)
    };
    static LATE_LOCAL_WORK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Set the hooks of every later phase on this thread, and drop whatever an
/// earlier one held.
#[cfg(test)]
pub(crate) fn finish_hooks_for_test(hooks: FinishHooks) {
    HOOKS.set(hooks);
    HELD.with_borrow_mut(Vec::clear);
    LAST_REPORT.set(None);
    LATE_LOCAL_WORK.set(false);
}

#[cfg(test)]
pub(crate) fn finish_report_for_test() -> Option<crate::sync::ShutdownReport> {
    LAST_REPORT.take()
}

#[cfg(test)]
pub(super) fn finish_hooks_for_engine_test() -> FinishHooks {
    HOOKS.with_borrow(|hooks| *hooks)
}

#[cfg(test)]
pub(crate) fn late_local_work_for_test() -> bool {
    LATE_LOCAL_WORK.get()
}

#[cfg(test)]
pub(super) fn hold_for_test<T: Clone + 'static>(engine: &T) {
    if HOOKS.with_borrow(|hooks| hooks.hold_engine) {
        HELD.with_borrow_mut(|held| held.push(Box::new(engine.clone())));
    }
}

#[cfg(test)]
pub(super) fn unchanged_base_for_test() -> bool {
    HOOKS.with_borrow(|hooks| hooks.unchanged_base)
}

#[cfg(test)]
pub(super) fn missing_base_for_test() -> bool {
    HOOKS.with_borrow(|hooks| hooks.fault == FinishFault::MissingBase)
}

#[cfg(test)]
pub(super) fn missing_pin_for_test() -> bool {
    HOOKS.with_borrow(|hooks| hooks.fault == FinishFault::MissingPin)
}

#[cfg(test)]
pub(super) fn poison_before_report_for_test() -> bool {
    HOOKS.with_borrow(|hooks| hooks.fault == FinishFault::PoisonBeforeReport)
}

pub(super) fn error_outcome(error: &WritableStartError) -> Outcome {
    match error {
        WritableStartError::Coordination(
            CoordinationError::Fenced { .. } | CoordinationError::CommitFenced { .. },
        ) => Outcome::Fenced,
        WritableStartError::Coordination(CoordinationError::Refused("SyncDeadline")) => {
            Outcome::Incomplete(Cause::Deadline)
        }
        _ => Outcome::Incomplete(Cause::Failed(error.class())),
    }
}
