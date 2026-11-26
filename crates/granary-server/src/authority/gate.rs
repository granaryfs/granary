// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The log token and the fence: how every mutating log call is made.
//!
//! **One mutating log call at a time, engine-wide.** Every
//! `write_marker`, `initialise`, `complete_namespace`, `append`,
//! `truncate` and `resync` runs inside [`LogGate::settling`], which holds
//! the one token for the call's whole duration. An `append` is four steps
//! inside one seam call (record, sync, mark, sync); without the token a
//! second volume's append could write its mark and sync after the first
//! volume's sync failed. The process must write nothing after the failing
//! sync returns. With the token, no other log call is in flight anywhere
//! when a call fails. Initialise's
//! `remove_temporary`, which the seam exempts from the fence, takes it
//! too ([`LogGate::exempt`]), so it never begins after a fence. The
//! start's removals do not take it: the start makes its log calls one at
//! a time and stops at its first fence. Reads and store work never take
//! it.
//!
//! **The fence** is checked after the token is taken and before the call
//! is made, and set by the failing call before its token is released,
//! with no await between the call's return and the set. So once it is
//! set no further log call begins, and none was in flight. A mutating
//! call's future that is dropped before it completes sets it too, from
//! its drop: the seam makes no mutating future cancel-safe. Setting it
//! notifies a host at once (`FenceCell`): every cause reaches the one
//! place the flag is written, and the notification is that write.
//!
//! The token is `tokio::sync::Mutex`, which needs no runtime: its waiters
//! are woken through the task's own waker, so the one `run()` future
//! works the same under tokio and under the simulator's scheduler.

use std::future::Future;

use granary_core::authlog::{EncodeRecordError, SeqZeroError};
use granary_core::decisionlog::LogIoError;
use granary_core::root::VolumeName;
use tokio::sync::watch;

use super::state::ApplyError;

/// Which seam call a [`Fence`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogCall {
    /// An intent snapshot or its startup barrier.
    IntentStore,
    /// `DecisionLog::write_marker`.
    WriteMarker,
    /// `DecisionLog::initialise`.
    Initialise,
    /// `DecisionLog::complete_namespace`.
    CompleteNamespace,
    /// `DecisionLog::append`.
    Append,
    /// `DecisionLog::truncate`.
    Truncate,
    /// `DecisionLog::resync`.
    Resync,
}

impl std::fmt::Display for LogCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::IntentStore => "intent_store",
            Self::WriteMarker => "write_marker",
            Self::Initialise => "initialise",
            Self::CompleteNamespace => "complete_namespace",
            Self::Append => "append",
            Self::Truncate => "truncate",
            Self::Resync => "resync",
        })
    }
}

/// Why a record was not appended: refused before anything was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordRefusal {
    /// The volume has no log to append to.
    NoLog,
    /// The record could not be built.
    Unbuildable(SeqZeroError),
    /// The volume's state refused it: it breaks the committed log's
    /// grammar.
    State(ApplyError),
    /// The codec refused it: it breaks a field rule.
    Codec(EncodeRecordError),
}

impl std::fmt::Display for RecordRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoLog => write!(f, "the volume has no log"),
            Self::Unbuildable(e) => write!(f, "{e}"),
            Self::State(e) => write!(f, "{e}"),
            Self::Codec(e) => write!(f, "{e}"),
        }
    }
}

/// Why the engine fenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceCause {
    /// The call returned this error.
    Failed(LogIoError),
    /// The call's future was dropped before it completed.
    Dropped,
    /// An open entry's owed attestation was refused before its append.
    /// Spec §6.4 owes it before any other action for the entry, so the
    /// engine does not serve without it. Nothing was written.
    AttestationRefused(RecordRefusal),
    /// A record the engine built for a submission (a decision) or for
    /// an outcome (landed or lost) was refused before
    /// its append. The rules that precede it hold every such record to
    /// the grammar and the codec, so a refusal is a broken invariant, and
    /// the engine does not serve past it. Nothing was written.
    RecordRefused(RecordRefusal),
    /// The state refused a record after its append had returned `Ok`:
    /// the log holds a record the engine's state does not.
    CommittedRecordRefused(ApplyError),
}

/// The engine's fence: the mutating log call that raised it. Only a host
/// reboot clears it (spec §6.2); in this process nothing is written,
/// synced or answered after it but `Fenced`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fence {
    /// The call that fenced. For a record refused before or after its
    /// append ([`FenceCause::AttestationRefused`],
    /// [`FenceCause::RecordRefused`],
    /// [`FenceCause::CommittedRecordRefused`]), that append.
    pub call: LogCall,
    /// The volume it addressed; `None` for the run marker.
    pub volume: Option<VolumeName>,
    /// What happened to it.
    pub cause: FenceCause,
}

impl std::fmt::Display for Fence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fenced by {}", self.call)?;
        if let Some(volume) = &self.volume {
            write!(f, " on volume {}", volume.as_str())?;
        }
        match self.cause {
            FenceCause::Failed(e) => write!(f, ": {e}"),
            FenceCause::Dropped => write!(f, ": the call was dropped mid-flight"),
            FenceCause::AttestationRefused(e) => {
                write!(f, ": the owed attestation was refused: {e}")
            }
            FenceCause::RecordRefused(e) => write!(f, ": a record was refused: {e}"),
            FenceCause::CommittedRecordRefused(e) => {
                write!(f, ": the state refused a committed record: {e}")
            }
        }
    }
}

impl std::error::Error for Fence {}

/// The engine-wide fence flag. The first fence set is kept.
///
/// The flag is a `watch` channel's value, so setting it is also its
/// notification: a host holding a receiver learns of the fence when it
/// is set, whatever its cause, without waiting for the workers to stop.
/// [`Self::set`] is the one place the flag changes, and it never clears.
#[derive(Debug, Default)]
pub(crate) struct FenceCell(watch::Sender<Option<Fence>>);

impl FenceCell {
    /// A flag, unset, that publishes through `sender`: the channel a host
    /// made before the start.
    pub(crate) const fn over(sender: watch::Sender<Option<Fence>>) -> Self {
        Self(sender)
    }

    /// The fence, if the engine is fenced.
    pub(crate) fn get(&self) -> Option<Fence> {
        self.0.borrow().clone()
    }

    /// Whether the engine is fenced.
    pub(crate) fn is_set(&self) -> bool {
        self.0.borrow().is_some()
    }

    /// A receiver of the fence. The value is sticky: a receiver made
    /// before the set is notified of it, and one made after reads it at
    /// once (its `wait_for` returns without waiting).
    pub(crate) fn subscribe(&self) -> watch::Receiver<Option<Fence>> {
        self.0.subscribe()
    }

    /// Set the fence to `fence` unless one is set already, and return the
    /// fence the engine now carries. The first set notifies every
    /// receiver; a later one changes nothing and notifies none.
    fn set(&self, fence: Fence) -> Fence {
        let mut kept = fence.clone();
        self.0.send_if_modified(|slot| {
            if let Some(first) = slot {
                kept = first.clone();
                false
            } else {
                *slot = Some(fence);
                true
            }
        });
        kept
    }
}

/// The engine's one log token (module docs).
#[derive(Debug, Default)]
pub(crate) struct LogGate {
    token: tokio::sync::Mutex<()>,
}

/// Fences on drop unless disarmed: a mutating call's future dropped
/// before it completed.
struct Armed<'a> {
    fence: &'a FenceCell,
    call: LogCall,
    volume: Option<&'a VolumeName>,
    live: bool,
}

impl Drop for Armed<'_> {
    fn drop(&mut self) {
        if self.live {
            let _ = self.fence.set(Fence {
                call: self.call,
                volume: self.volume.cloned(),
                cause: FenceCause::Dropped,
            });
        }
    }
}

impl LogGate {
    /// Make one mutating log call under the token: take the token, check
    /// the fence, build and await the call, then hand its result to
    /// `settle`. Where `settle` names a cause, the fence is set to it
    /// before the token is released, with no await between the call's
    /// return and the set (module docs). `settle` is the one place a
    /// caller decides which errors fence and what else the call's
    /// success must be followed by.
    ///
    /// # Cancellation safety
    /// Cancel-safe until the token is taken. After that, dropping this
    /// future fences: the call may already be in flight.
    ///
    /// # Errors
    /// The [`Fence`] the engine carries, if it was fenced before the call
    /// (which was then never made) or by it.
    pub(crate) async fn settling<T, U, F, Fut, S>(
        &self,
        fence: &FenceCell,
        call: LogCall,
        volume: Option<&VolumeName>,
        make: F,
        settle: S,
    ) -> Result<U, Fence>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, LogIoError>>,
        S: FnOnce(Result<T, LogIoError>) -> Result<U, FenceCause>,
    {
        let waiting = self.token.lock();
        #[cfg(test)]
        let waiting =
            tracing::Instrument::instrument(waiting, tracing::trace_span!("authority_log_wait"));
        let _token = waiting.await;
        if let Some(fenced) = fence.get() {
            return Err(fenced);
        }
        let mut armed = Armed {
            fence,
            call,
            volume,
            live: true,
        };
        let result = make().await;
        armed.live = false;
        settle(result).map_err(|cause| {
            fence.set(Fence {
                call,
                volume: volume.cloned(),
                cause,
            })
        })
    }

    /// Make one log call the seam exempts from the fence
    /// (`remove_temporary`) under the token: it begins only while the
    /// engine is unfenced and no other log call is in flight, since it
    /// still writes. Its error and its drop never fence; the error is
    /// the caller's to answer.
    ///
    /// # Cancellation safety
    /// Cancel-safe, as the seam's `remove_temporary` is: re-issuing it
    /// after a drop is always safe.
    ///
    /// # Errors
    /// The [`Fence`] the engine carries, if it was fenced before the
    /// call, which was then never made.
    pub(crate) async fn exempt<T, F, Fut>(
        &self,
        fence: &FenceCell,
        make: F,
    ) -> Result<Result<T, LogIoError>, Fence>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, LogIoError>>,
    {
        let _token = self.token.lock().await;
        if let Some(fenced) = fence.get() {
            return Err(fenced);
        }
        Ok(make().await)
    }

    /// Set the fence to `fenced` under the token, for a cause no log call
    /// returned, so no log call is in flight when it is set. Returns the
    /// fence the engine carries: the first one set.
    ///
    /// # Cancellation safety
    /// Cancel-safe: dropped before the token is taken, it sets nothing.
    pub(crate) async fn fence(&self, fence: &FenceCell, fenced: Fence) -> Fence {
        let _token = self.token.lock().await;
        fence.set(fenced)
    }

    /// [`Self::settling`] where every error of the call fences.
    ///
    /// # Cancellation safety
    /// As [`Self::settling`].
    ///
    /// # Errors
    /// The [`Fence`] the engine carries, if it was fenced before the call
    /// or by it.
    pub(crate) async fn fencing<T, F, Fut>(
        &self,
        fence: &FenceCell,
        call: LogCall,
        volume: Option<&VolumeName>,
        make: F,
    ) -> Result<T, Fence>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, LogIoError>>,
    {
        self.settling(fence, call, volume, make, |result| {
            result.map_err(FenceCause::Failed)
        })
        .await
    }
}
