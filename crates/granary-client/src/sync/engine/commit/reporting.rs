// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! One process-local terminal observation, independent of retained publication.

use super::super::failure_class;
use super::{
    Arc, Clock, CoordinationError, MonotonicClock, Mutex, OverlayIo, RetainedCommit, RootStore,
    SyncContent, SyncEngine, SyncRemote, SyncRuntime, refused,
};
use crate::{
    CommitResult, CorrelationId, FailureClass, MonotonicToken, OperationKind, Outcome,
    PublicationHandle, PublicationOutcome, PublicationResult,
};
use granary_core::secure_random::SecureRandom;
use std::path::PathBuf;

#[derive(Debug, Default)]
pub(super) struct State {
    started: bool,
    start: Option<Arc<MonotonicToken>>,
    observed: bool,
    pub(super) terminal: Option<CommitResult>,
    pub(super) refusal: Option<FailureClass>,
    pub(super) retry_unavailable: bool,
    pub(super) outage_started: Option<tokio::time::Instant>,
    pub(super) next_poll: Option<(tokio::time::Instant, PublicationHandle)>,
}

/// A blocking merge retains only the reporting slot of its own drive.
#[derive(Debug, Clone, Default)]
pub(super) struct Conflict(Arc<Mutex<Option<PathBuf>>>);
impl Conflict {
    pub(super) fn record(&self, path: PathBuf) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(path);
        }
    }
}

pub(super) struct Observation<'a, P: OverlayIo, R, S, C, M: MonotonicClock, E> {
    engine: &'a SyncEngine<P, R, S, C, M, E>,
    lane: &'a RetainedCommit,
    operation: Option<CorrelationId>,
    span: tracing::Span,
    outcome: Outcome,
    pub(super) conflict: Conflict,
}
impl<'a, P, R, S, C, M, E> Observation<'a, P, R, S, C, M, E>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + RootStore + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
{
    pub(super) fn new(
        engine: &'a SyncEngine<P, R, S, C, M, E>,
        lane: &'a RetainedCommit,
        secure: &mut dyn SecureRandom,
    ) -> Self {
        if let Ok(mut state) = lane.observation.lock()
            && !state.started
        {
            state.started = true;
            // A restart cannot reconstruct the first attempt's process-local token.
            state.start = if lane.recovered {
                None
            } else {
                engine.monotonic.start().map(Arc::new)
            };
        }
        let operation = if lane.recovered {
            if let Ok(id) = CorrelationId::draw(secure) {
                Some(id)
            } else {
                crate::observe::op_failed(OperationKind::Session, FailureClass::Unavailable);
                None
            }
        } else {
            lane.operation_id
        };
        let span = operation.map_or_else(tracing::Span::none, |id| {
            crate::operation_span(OperationKind::Commit, &id)
        });
        span.in_scope(|| crate::observe::op_begin(OperationKind::Commit));
        Self {
            engine,
            lane,
            operation,
            span,
            outcome: Outcome::Cancelled,
            conflict: Conflict::default(),
        }
    }
    pub(super) fn span(&self) -> tracing::Span {
        self.span.clone()
    }
    pub(super) fn finish(
        &mut self,
        result: &Result<(PublicationResult, Option<CommitResult>), CoordinationError>,
    ) {
        let (mut terminal, mut failure, mut fenced) = match result {
            Ok((result, terminal)) => {
                let failure = match result.outcome {
                    PublicationOutcome::Landed(_) => None,
                    PublicationOutcome::Exhausted => {
                        Some(failure_class(&refused("SyncCommitExhausted")))
                    }
                    PublicationOutcome::Refused => Some(FailureClass::Refused),
                    PublicationOutcome::BackendError => Some(FailureClass::Corrupt),
                    PublicationOutcome::Unresolved if result.admission_error().is_some() => {
                        Some(FailureClass::Refused)
                    }
                    PublicationOutcome::Pending | PublicationOutcome::Unresolved => {
                        Some(failure_class(&refused("SyncCommitUnresolved")))
                    }
                };
                (*terminal, failure, terminal.is_some() && failure.is_some())
            }
            Err(error) => {
                let fenced = matches!(
                    error,
                    CoordinationError::Fenced { .. } | CoordinationError::CommitFenced { .. }
                );
                (
                    fenced.then_some(CommitResult::Failed),
                    Some(failure_class(error)),
                    fenced,
                )
            }
        };
        self.outcome = if failure.is_some() {
            Outcome::Failed
        } else {
            Outcome::Ok
        };
        let _entered = self.span.enter();
        let start = match self.lane.observation.lock() {
            Ok(state) => {
                if state.observed {
                    return;
                }
                if let Some(result) = state.terminal {
                    terminal = terminal.map(|_| result);
                }
                if let Some(class) = state.refusal {
                    terminal = Some(CommitResult::Failed);
                    failure = Some(class);
                    fenced = true;
                }
                state.start.clone()
            }
            Err(_) => return,
        };
        if let Some(result) = terminal {
            let duration = start
                .as_ref()
                .and_then(|token| self.engine.monotonic.elapsed(token));
            if let Err(error) = self
                .engine
                .local(|local| local.report_commit_outcome(result, duration, failure, fenced))
            {
                self.outcome = Outcome::Failed;
                crate::observe::op_failed(OperationKind::Commit, failure_class(&error));
                return;
            }
            if let Ok(mut state) = self.lane.observation.lock() {
                state.observed = true;
            }
        } else if let Some(class) = failure {
            crate::observe::op_failed(OperationKind::Commit, class);
        }
        if failure.is_some() && fenced {
            let path = self.conflict.0.lock().ok().and_then(|slot| slot.clone());
            if let Some(path) = &path {
                crate::ClientEvent::conflict_detail().emit_paths(&[
                    crate::observe::PathSlot::Path("path", crate::LogPath::file(path)),
                ]);
                if let Some(id) = self.operation
                    && let Ok(status) = crate::LocalConflictStatus::new(path, id)
                {
                    crate::LocalReport::conflict(status).emit();
                }
            }
        }
    }
}
impl<P: OverlayIo, R, S, C, M: MonotonicClock, E> Drop for Observation<'_, P, R, S, C, M, E> {
    fn drop(&mut self) {
        let _entered = self.span.enter();
        crate::observe::op_end(OperationKind::Commit, self.outcome);
    }
}

impl<P: OverlayIo, R, S, C, M: MonotonicClock, E> SyncEngine<P, R, S, C, M, E> {
    /// Collision classification comes from the merge's terminal observation,
    /// independently of the fence also used for ordinary rejected publications.
    pub(crate) fn has_commit_conflict(&self) -> bool {
        let lane = self
            .state
            .lock()
            .ok()
            .and_then(|state| state.commit.clone());
        lane.is_some_and(|lane| {
            lane.observation
                .lock()
                .is_ok_and(|state| state.terminal == Some(crate::CommitResult::Conflict))
        })
    }
}

#[cfg(test)]
impl<P, R, S, C, M, E> SyncEngine<P, R, S, C, M, E>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + RootStore + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
{
    pub(crate) fn finish_commit_observation_for_test(
        &self,
        lane: &RetainedCommit,
        secure: &mut dyn SecureRandom,
        ownership_fence: bool,
    ) -> bool {
        let mut lane = lane.clone();
        if ownership_fence {
            lane.observation = Arc::default();
        }
        if !ownership_fence {
            lane.observation.lock().unwrap().refusal = Some(FailureClass::Refused);
        }
        let mut observation = Observation::new(self, &lane, secure);
        let result = if ownership_fence {
            Err(self
                .local(|local| local.commit_record(lane.serial, lane.publication))
                .unwrap_err())
        } else {
            Err(CoordinationError::Fenced {
                recorded_generation: None,
            })
        };
        observation.finish(&result);
        lane.observation.lock().unwrap().observed
    }
}
