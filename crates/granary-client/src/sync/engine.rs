// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
// @file-disposition: STAYS — Sync supervision owns admission, construction workspace leases, captured preparation and registration completion; publication lifecycle subjects are children.

//! Mount-less capture, acceptance, registration and ordered acknowledgement.

use super::{
    MonotonicClock, SyncObjectSelection, SyncProjectionQueue, SyncRuntime, TokioSyncRuntime,
    VerifiedBase, accept_sync_projection, rechunk_captured,
};
use crate::{
    CaptureCoverageInput, ClientMetrics, ContentSource, CoordinationError, DurableFile, HttpStore,
    IntentCompletion, IntentReply, IntentTransportError, OverlayError, OverlayIo, PendingIntent,
    Policy, SyncBoundary, SyncTarget, WritableStore,
};
use granary_core::{
    binstore::BinStore,
    clock::Clock,
    grainsource::{GrainSource, GrainSourceError},
    hash::GrainId,
    manifest::FileGrains,
    overlay_ownership::Operation,
    root::VolumeName,
};
use granary_store::crypto::{SigningKey, TrustedKeys};
use std::{
    collections::BTreeMap,
    future::Future,
    ops::ControlFlow::{Break, Continue},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, Notify, oneshot};

pub(crate) fn refused(reason: &'static str) -> CoordinationError {
    CoordinationError::Refused(reason)
}

pub(crate) fn workspace_error(volume: &VolumeName, needed: u64, limit: u64) -> CoordinationError {
    crate::LocalReport::workspace_exhausted(
        crate::local_report::WorkspaceSite::Volume(volume.clone()),
        None,
        needed,
        limit,
    )
    .emit();
    crate::ClientEvent::workspace_exhausted(needed, limit).emit();
    refused("SyncWorkspaceExhausted")
}

struct RuntimeRng<'a, E>(&'a E);
impl<E: SyncRuntime> granary_core::rng::Rng for RuntimeRng<'_, E> {
    fn next_u64(&mut self) -> u64 {
        self.0.random_u64()
    }
}

fn payload_failure(error: CoordinationError) -> CoordinationError {
    if matches!(
        error,
        CoordinationError::Overlay(OverlayError::CaptureCoverageLost)
    ) {
        // Before admission this verifier authenticates our own immutable
        // payload; no covering receipt exists yet to lose a concurrency race.
        refused("SyncRechunkContent")
    } else {
        error
    }
}

pub(crate) fn failure_class(error: &CoordinationError) -> crate::observe::FailureClass {
    use crate::observe::FailureClass as Class;
    match error {
        CoordinationError::SyncRefusal(_) => Class::Refused,
        CoordinationError::Fenced { .. } | CoordinationError::CommitFenced { .. } => {
            Class::Conflict
        }
        CoordinationError::Codec(_) => Class::Corrupt,
        CoordinationError::Overlay(error) => match error {
            OverlayError::Io(_) | OverlayError::Poisoned => Class::Io,
            OverlayError::ContentUnavailable => Class::Unavailable,
            OverlayError::Conflict | OverlayError::CaptureCoverageLost => Class::Conflict,
            OverlayError::Refused(
                "capture extent mismatch" | "short capture extent" | "clean file content",
            ) => Class::Corrupt,
            _ => Class::Refused,
        },
        CoordinationError::Refused(reason) => match *reason {
            "RecoveryResidualWorkspace" => Class::Io,
            "SyncDeadline"
            | "SyncCommitUnresolved"
            | "IntentStartupAttemptsExhausted"
            | "IntentRetryNotEligible"
            | "SyncCommitRebaseUnavailable"
            | "ViewRootUnavailable"
            | "RecoveryResidualUnavailable" => Class::Unavailable,
            "SyncBase"
            | "SyncRechunkContent"
            | "SyncCommitSignature"
            | "SyncCommitManifest"
            | "SyncCommitRebaseManifest"
            | "SyncCommitContainment"
            | "SyncProjectedBinding" => Class::Corrupt,
            #[cfg(any(test, feature = "overlay-fault-tests"))]
            "SyncInjectedFault" => Class::Io,
            "IntentPersistencePoisoned" | "IntentCapExhausted" => Class::Io,
            "SyncCompletionBinding"
            | "SyncSupervisorLost"
            | "SyncMaterializationLost"
            | "SyncLocalTransactionLost"
            | "SyncFaultSupervisorLost" => Class::Internal,
            _ => Class::Refused,
        },
        CoordinationError::Publication(_) => Class::Io,
        CoordinationError::Recovery(error) => match error {
            crate::RecoveryError::Journal(error) => match error.kind {
                crate::PublicationStoreErrorKind::Conflict
                | crate::PublicationStoreErrorKind::Fenced => Class::Conflict,
                crate::PublicationStoreErrorKind::Unavailable => Class::Unavailable,
                crate::PublicationStoreErrorKind::Corrupt => Class::Corrupt,
                _ => Class::Io,
            },
            crate::RecoveryError::RemoteIntegrity(_) | crate::RecoveryError::Record(_) => {
                Class::Corrupt
            }
            crate::RecoveryError::Authority(crate::AuthorityError::Backend(_)) => Class::Corrupt,
            crate::RecoveryError::Authority(_)
            | crate::RecoveryError::Remote(_)
            | crate::RecoveryError::Entropy(_) => Class::Unavailable,
            crate::RecoveryError::Preparation(error) => match error {
                crate::PublishError::Remote(_)
                | crate::PublishError::ProbeUnresolved { .. }
                | crate::PublishError::Unresolved { .. } => Class::Unavailable,
                crate::PublishError::LostRace { .. } => Class::Conflict,
                crate::PublishError::RootTooLarge { .. }
                | crate::PublishError::ReservedVolumeName { .. } => Class::Refused,
                crate::PublishError::BadPlan | crate::PublishError::BinmapConstruction => {
                    Class::Internal
                }
                _ => Class::Corrupt,
            },
            crate::RecoveryError::Bootstrap(_) | crate::RecoveryError::Refused(_) => Class::Refused,
            crate::RecoveryError::Invalid(_) => Class::Internal,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_workspace_defaults_to_one_gib() {
        assert_eq!(SyncOptions::default().workspace_bytes, 1_073_741_824);
    }

    #[test]
    fn workspace_marker_does_not_mask_later_corrupt_metadata() {
        let source = ObjectSink(Vec::new());
        let budget = Budget::new(&source, 0, None);
        assert_eq!(
            budget.charge(1).unwrap_err().to_string(),
            "intent refused: SyncWorkspaceExhausted"
        );
        let id = GrainId::of(b"corrupt metadata");
        let errors = [
            preparation_error(
                crate::PublishError::CorruptMeta { id },
                budget.workspace_refused.load(Ordering::Acquire),
            ),
            budget.payload_error(CoordinationError::Recovery(
                crate::RecoveryError::Preparation(crate::PublishError::CorruptMeta { id }),
            )),
        ];
        for error in errors {
            assert_eq!(
                (
                    failure_class(&error),
                    matches!(error, CoordinationError::Recovery(crate::RecoveryError::Preparation(crate::PublishError::CorruptMeta { id: found })) if found == id)
                ),
                (crate::FailureClass::Corrupt, true),
                "{error:?}"
            );
        }
        let corrupt = preparation_error(
            crate::PublishError::Source(GrainSourceError::Corrupt(id)),
            true,
        );
        assert_eq!(
            failure_class(&corrupt),
            crate::FailureClass::Corrupt,
            "{corrupt:?}"
        );
        let source_error = budget.get(&GrainId::of(&[])).unwrap_err();
        let error = preparation_error(crate::PublishError::Source(source_error), true);
        assert_eq!(
            (error.to_string(), failure_class(&error)),
            (
                "intent refused: SyncWorkspaceExhausted".into(),
                crate::FailureClass::Refused
            )
        );
        let accounting = Budget::<ObjectSink>::refuse(refused("SyncGraphPoisoned"));
        let error = preparation_error(crate::PublishError::Remote(accounting), true);
        assert_eq!(
            failure_class(&error),
            crate::FailureClass::Unavailable,
            "{error:?}"
        );
        for error in [
            refused("SyncGraphPoisoned"),
            CoordinationError::Recovery(crate::RecoveryError::Preparation(
                crate::PublishError::CorruptMeta { id },
            )),
        ] {
            let error = preparation_error(budget.publication_error(error), true);
            assert_eq!(
                (
                    failure_class(&error),
                    matches!(
                        error,
                        CoordinationError::Recovery(crate::RecoveryError::Preparation(
                            crate::PublishError::BadPlan
                        ))
                    )
                ),
                (crate::FailureClass::Internal, true),
                "{error:?}"
            );
        }
    }

    #[test]
    fn workspace_lease_releases_once_and_refuses_ledger_overflow() {
        let ledger = Arc::new(AtomicU64::new(0));
        let lease = Arc::new(WorkspaceLease::new(&ledger, 1024).unwrap());
        let shared = lease.clone();
        drop(lease);
        assert_eq!(ledger.load(Ordering::Acquire), 1024);
        drop(shared);
        assert_eq!(ledger.load(Ordering::Acquire), 0);
        ledger.store(u64::MAX, Ordering::Release);
        let refusal = WorkspaceLease::new(&ledger, 1).err().map(|e| e.to_string());
        assert_eq!(
            (refusal.as_deref(), ledger.load(Ordering::Acquire)),
            (Some("intent refused: SyncGraphOverflow"), u64::MAX)
        );
    }

    #[tokio::test]
    async fn malformed_bin_does_not_set_the_workspace_marker() {
        let (reply, _receiver, metrics) = reply();
        let sink = ObjectSink(vec![]);
        let budget = Budget::new(&sink, 1_073_741_824, None);
        let remote = ObjectRemote {
            remote: &sink,
            budget: &budget,
            reply: &reply,
            deadline: TokioSyncRuntime.now() + Duration::from_secs(1),
            runtime: &TokioSyncRuntime,
            faults: &crate::FaultControl::default(),
            capture: 1,
            metrics: &metrics,
            binmap_get_bytes: &AtomicU64::new(0),
            refused_get_bytes: &AtomicU64::new(0),
            grain_ids: std::collections::BTreeSet::default(),
        };
        let error = remote.put_bin(&[0; 32], vec![]).await.unwrap_err();
        assert_eq!(
            (
                error.to_string(),
                budget.workspace_refused.load(Ordering::Acquire)
            ),
            ("store: sync bin decode".to_owned(), false)
        );
    }

    struct ObjectSink(Vec<u8>);
    impl GrainSource for ObjectSink {
        fn has(&self, _: &GrainId) -> bool {
            true
        }
        fn get(&self, _: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
            Ok(self.0.clone())
        }
    }
    impl SyncContent for ObjectSink {
        fn payload(&self, _: GrainId) -> Result<FileGrains, CoordinationError> {
            Ok(FileGrains::Inline(vec![]))
        }
        fn read_content(&self, _: GrainId, _: u64, _: usize) -> Result<Vec<u8>, OverlayError> {
            Ok(self.0.clone())
        }
        fn put_object(&self, _: GrainId, _: &[u8]) -> Result<(), CoordinationError> {
            Ok(())
        }
        fn remember_payload(
            &self,
            _: GrainId,
            _: u64,
            _: &FileGrains,
        ) -> Result<(), CoordinationError> {
            Ok(())
        }
    }
    impl BinStore for ObjectSink {
        async fn put_bin(
            &self,
            _: &[u8; 32],
            _: Vec<u8>,
        ) -> Result<bool, granary_core::rootstore::RootStoreError> {
            Ok(false)
        }
        async fn put_meta(
            &self,
            _: &str,
            _: &GrainId,
            _: Vec<u8>,
        ) -> Result<bool, granary_core::rootstore::RootStoreError> {
            Ok(false)
        }
        async fn get_meta(
            &self,
            _: &str,
            _: &GrainId,
        ) -> Result<Vec<u8>, granary_core::rootstore::RootStoreError> {
            Ok(self.0.clone())
        }
        async fn get_bin_range(
            &self,
            _: &[u8; 32],
            _: u64,
            _: u32,
        ) -> Result<Vec<u8>, granary_core::rootstore::RootStoreError> {
            Ok(self.0.clone())
        }
    }

    /// A construction's release clears only the projected record its own
    /// lane owns: another lane's, or one with no lane, survives it.
    #[test]
    fn a_construction_release_clears_only_its_own_projected_record() {
        let observed = [Some(7), Some(8), None].map(|owner| {
            let mut state = State {
                constructing_commit: true,
                projected: Some((owner, 0, Arc::new(reply().0))),
                ..State::default()
            };
            state.release_construction(7);
            (state.constructing_commit, state.projected.is_some())
        });
        assert_eq!(observed, [(false, false), (false, true), (false, true)]);
    }

    /// A construction's release clears only the supervised construction
    /// record of its own lane: another lane's survives it.
    #[test]
    fn a_construction_release_clears_only_its_own_construction_record() {
        let observed = [7, 8].map(|serial| {
            let mut state = State {
                constructing_commit: true,
                construction: Some(Construction {
                    owner: [1; 16],
                    serial,
                    charge: 0,
                    snapshot: None,
                }),
                ..State::default()
            };
            state.release_construction(7);
            (state.constructing_commit, state.construction.is_some())
        });
        assert_eq!(observed, [(false, false), (false, true)]);
    }

    /// A lost task's monitor finds a construction only when both its owner
    /// and its serial are the recorded ones: an owner match on another
    /// lane, or a lane match under another owner, finds nothing.
    #[test]
    fn a_lost_construction_is_found_only_by_its_owner_and_serial() {
        let state = State {
            constructing_commit: true,
            construction: Some(Construction {
                owner: [1; 16],
                serial: 7,
                charge: 9,
                snapshot: None,
            }),
            ..State::default()
        };
        let found = [([1; 16], 7), ([1; 16], 8), ([2; 16], 7)].map(|(owner, serial)| {
            state
                .lost_construction(&owner, serial)
                .map(|(_, charge)| charge)
        });
        assert_eq!(found, [Some(9), None, None]);
    }

    #[tokio::test]
    async fn object_put_and_get_workspace_refusals_have_refused_class() {
        let (reply, _receiver, metrics) = reply();
        let tree = granary_core::manifest::build_dir(&[]).unwrap();
        let bytes = tree
            .nodes
            .iter()
            .find(|(id, _)| *id == tree.root)
            .unwrap()
            .1
            .clone();
        let sink = ObjectSink(bytes.clone());
        let budget = Budget::new(&sink, 0, None);
        let remote = ObjectRemote {
            remote: &sink,
            budget: &budget,
            reply: &reply,
            deadline: TokioSyncRuntime.now() + Duration::from_secs(1),
            runtime: &TokioSyncRuntime,
            faults: &crate::FaultControl::default(),
            capture: 1,
            metrics: &metrics,
            binmap_get_bytes: &AtomicU64::new(0),
            refused_get_bytes: &AtomicU64::new(0),
            grain_ids: std::collections::BTreeSet::default(),
        };
        let errors = [
            remote.put_meta("v", &tree.root, bytes).await.unwrap_err(),
            remote.get_meta("v", &tree.root).await.unwrap_err(),
        ];
        assert!(budget.workspace_refused.load(Ordering::Acquire));
        for error in errors {
            // The refusal itself is only a marker; the engine reports the
            // local capacity error when its own workspace set the flag.
            assert!(matches!(
                error,
                granary_core::rootstore::RootStoreError::RefusedResponse { .. }
            ));
        }
        let refusal = || {
            crate::PublishError::Remote(granary_core::rootstore::RootStoreError::RefusedResponse {
                reason: "sync object workspace".into(),
                kind: granary_core::rootstore::RefusalKind::OverCap,
            })
        };
        assert!(matches!(
            preparation_error(refusal(), true),
            CoordinationError::Refused("SyncWorkspaceExhausted")
        ));
        assert_eq!(
            (
                failure_class(&preparation_error(refusal(), true)),
                failure_class(&CoordinationError::Overlay(OverlayError::NoSpace))
            ),
            (crate::FailureClass::Refused, crate::FailureClass::Refused),
        );
        assert!(matches!(
            preparation_error(refusal(), false),
            CoordinationError::Recovery(crate::RecoveryError::Preparation(_))
        ));
        // A remote refusal that merely echoes the workspace text is not local.
        let echoed = CoordinationError::Recovery(crate::RecoveryError::Preparation(
            crate::PublishError::Remote(granary_core::rootstore::RootStoreError::RefusedResponse {
                reason: "sync object workspace".into(),
                kind: granary_core::rootstore::RefusalKind::OverCap,
            }),
        ));
        assert_eq!(
            failure_class(&echoed),
            crate::FailureClass::Unavailable,
            "a wire refusal echoing the workspace text was classified local"
        );
    }

    struct Entropy;
    impl granary_core::secure_random::SecureRandom for Entropy {
        fn fill(
            &mut self,
            bytes: &mut [u8],
        ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
            bytes.fill(7);
            Ok(())
        }
    }

    fn reply() -> (
        Reply,
        oneshot::Receiver<Result<(), CoordinationError>>,
        ClientMetrics,
    ) {
        let metrics = ClientMetrics::new(&mut Entropy);
        metrics.set_available(crate::MetricsGroup::Sync, true);
        let (sender, receiver) = oneshot::channel();
        (
            Reply {
                sender: Mutex::new(Some(sender)),
                cancelled: AtomicBool::new(false),
                cancellation: Notify::new(),
                metrics: metrics.clone(),
                observed: true,
            },
            receiver,
            metrics,
        )
    }

    #[test]
    fn cancellation_and_reply_have_one_delivery_linearization_point() {
        let (reply, mut receiver, metrics) = reply();
        reply.cancel();
        reply.cancel();
        reply.deliver(Ok(()));
        assert!(
            receiver.try_recv().is_err(),
            "cancelled waiter received success"
        );
        let text = metrics.snapshot().unwrap().render_prometheus().unwrap();
        assert!(text.contains("granary_client_syncs_total{outcome=\"cancelled\"} 1\n"));
        assert!(text.contains("granary_client_syncs_total{outcome=\"ok\"} 0\n"));
        let (reply, mut receiver, metrics) = self::reply();
        reply.deliver(Ok(()));
        reply.cancel();
        assert!(receiver.try_recv().unwrap().is_ok());
        let text = metrics.snapshot().unwrap().render_prometheus().unwrap();
        assert!(text.contains("granary_client_syncs_total{outcome=\"ok\"} 1\n"));
        assert!(text.contains("granary_client_syncs_total{outcome=\"cancelled\"} 0\n"));
    }

    #[test]
    fn closed_receiver_is_counted_cancelled_even_before_waiter_drop() {
        let (reply, receiver, metrics) = reply();
        drop(receiver);
        reply.deliver(Ok(()));
        reply.cancel();
        let text = metrics.snapshot().unwrap().render_prometheus().unwrap();
        assert!(
            text.contains("granary_client_syncs_total{outcome=\"cancelled\"} 1\n"),
            "closed receiver was counted as acknowledged"
        );
        assert!(text.contains("granary_client_syncs_total{outcome=\"ok\"} 0\n"));
    }
}

/// Immutable content provider and local object sink. Calls run outside the
/// mediator. Payloads identify canonical file encodings, including inline and
/// empty files; unavailable payloads must be fetched/authenticated, never guessed.
/// Implementations must bound reads and keep inserted objects available through
/// completion and subsequent checkpoint reads, under their own cache policy.
pub trait SyncContent: GrainSource + Send + Sync {
    /// Bind remote reads to the operation's runtime and absolute deadline.
    /// Local providers use the default; remote providers must override it.
    /// The engine calls bound providers only on blocking workers.
    fn with_deadline<E: SyncRuntime + 'static>(
        &self,
        _runtime: Arc<E>,
        _deadline: tokio::time::Instant,
    ) -> impl SyncContent {
        ContentRef(self)
    }
    /// Read locally without starting remote work during recovery polling.
    /// # Errors
    /// Missing, corrupt or unavailable local object.
    fn get_local(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.get(id)
    }
    /// # Errors
    /// Missing, corrupt or unbounded canonical payload/list.
    fn payload(&self, content: GrainId) -> Result<FileGrains, CoordinationError>;
    /// # Errors
    /// Missing or unauthenticated content, invalid range or short read.
    fn read_content(
        &self,
        content: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError>;
    /// # Errors
    /// Hash mismatch, capacity refusal or local sink failure.
    fn put_object(&self, id: GrainId, bytes: &[u8]) -> Result<(), CoordinationError>;
    /// # Errors
    /// Invalid payload, capacity refusal or local retention failure.
    fn remember_payload(
        &self,
        content: GrainId,
        size: u64,
        grains: &FileGrains,
    ) -> Result<(), CoordinationError>;
}

struct ContentRef<'a, S: ?Sized>(&'a S);
impl<S: SyncContent + ?Sized> GrainSource for ContentRef<'_, S> {
    fn has(&self, id: &GrainId) -> bool {
        self.0.has(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.0.get(id)
    }
}
impl<S: SyncContent + ?Sized> SyncContent for ContentRef<'_, S> {
    fn get_local(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.0.get_local(id)
    }
    fn payload(&self, content: GrainId) -> Result<FileGrains, CoordinationError> {
        self.0.payload(content)
    }
    fn read_content(
        &self,
        content: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        self.0.read_content(content, offset, length)
    }
    fn put_object(&self, id: GrainId, bytes: &[u8]) -> Result<(), CoordinationError> {
        self.0.put_object(id, bytes)
    }
    fn remember_payload(
        &self,
        content: GrainId,
        size: u64,
        grains: &FileGrains,
    ) -> Result<(), CoordinationError> {
        self.0.remember_payload(content, size, grains)
    }
}

impl<P, R, S, C, M> SyncEngine<P, R, S, C, M>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
{
    /// Attach a production supervisor using the Tokio scheduling adapter.
    /// # Errors
    /// Duplicate supervisor, readiness, poison or foreign/unverified base.
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit independent storage, timing and signing seams"
    )]
    pub async fn new(
        store: Arc<Mutex<WritableStore<P>>>,
        remote: Arc<R>,
        content: Arc<S>,
        wall: Arc<C>,
        monotonic: Arc<M>,
        key: SigningKey,
        trusted: TrustedKeys,
        base: Vec<u8>,
        metrics: ClientMetrics,
    ) -> Result<Arc<Self>, CoordinationError> {
        Self::with_runtime(
            store,
            remote,
            content,
            wall,
            monotonic,
            key,
            trusted,
            base,
            metrics,
            Arc::new(TokioSyncRuntime),
        )
        .await
    }
}

/// One exact attempt. The engine owns dispatch admission, timing and retries.
pub trait SyncRemote: BinStore {
    fn register_once(
        &self,
        request: &PendingIntent,
        trusted: &TrustedKeys,
    ) -> impl Future<Output = Result<IntentReply, IntentTransportError>> + Send;
    /// Send a retained Release once.
    fn release_once(
        &self,
        request: &PendingIntent,
    ) -> impl Future<Output = Result<IntentReply, IntentTransportError>> + Send;
}
impl SyncRemote for HttpStore {
    async fn register_once(
        &self,
        request: &PendingIntent,
        trusted: &TrustedKeys,
    ) -> Result<IntentReply, IntentTransportError> {
        self.intent_register_once(
            request.scope(),
            request.volume(),
            request.bytes(),
            |doc, prefix| granary_store::crypto::check_signatures(doc, prefix, trusted).is_ok(),
        )
        .await
    }
    async fn release_once(
        &self,
        request: &PendingIntent,
    ) -> Result<IntentReply, IntentTransportError> {
        self.intent_release_once(request.scope(), request.volume(), request.bytes())
            .await
    }
}

/// An enclosing absolute deadline is clamped once, without resetting on retries.
#[derive(Debug, Clone, Copy)]
pub struct SyncOptions {
    pub resolution_bound: Duration,
    pub quiesce_delay: Duration,
    pub max_coalesce_delay: Duration,
    pub deadline: Option<tokio::time::Instant>,
    /// Cumulative work limit for each budget, per engine. Materialisation and
    /// acceptance have separate counters. Lease bookkeeping reserves no memory
    /// and enforces no aggregate memory bound.
    pub workspace_bytes: u64,
}
impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            resolution_bound: crate::DEFAULT_RESOLUTION_BOUND,
            quiesce_delay: crate::DEFAULT_QUIESCE_DELAY,
            max_coalesce_delay: crate::DEFAULT_MAX_COALESCE_DELAY,
            deadline: None,
            workspace_bytes: 1_073_741_824,
        }
    }
}

#[derive(Debug)]
struct Reply {
    sender: Mutex<Option<oneshot::Sender<Result<(), CoordinationError>>>>,
    cancelled: AtomicBool,
    cancellation: Notify,
    metrics: ClientMetrics,
    /// A reply the engine awaits itself records no fsync: only the caller's
    /// own reply observes one.
    observed: bool,
}
impl Reply {
    fn cancel(&self) {
        if let Ok(mut sender) = self.sender.lock()
            && sender.take().is_some()
        {
            self.cancelled.store(true, Ordering::Release);
            self.cancellation.notify_one();
            if self.observed {
                self.metrics.record_sync(crate::observe::Outcome::Cancelled);
                crate::observe::op_end(
                    crate::observe::OperationKind::Fsync,
                    crate::observe::Outcome::Cancelled,
                );
            }
        }
    }
    fn deliver(&self, result: Result<(), CoordinationError>) {
        if let Ok(mut sender) = self.sender.lock()
            && let Some(sender) = sender.take()
        {
            let failure = result.as_ref().err().map(failure_class);
            let mut outcome = if result.is_ok() {
                crate::observe::Outcome::Ok
            } else {
                crate::observe::Outcome::Failed
            };
            if sender.send(result).is_err() {
                self.cancelled.store(true, Ordering::Release);
                self.cancellation.notify_one();
                outcome = crate::observe::Outcome::Cancelled;
            }
            if !self.observed {
                return;
            }
            self.metrics.record_sync(outcome);
            if outcome == crate::observe::Outcome::Failed
                && let Some(class) = failure
            {
                crate::observe::op_failed(crate::observe::OperationKind::Fsync, class);
            }
            crate::observe::op_end(crate::observe::OperationKind::Fsync, outcome);
        }
    }
}

/// Dropping the waiter withdraws reply eligibility; the supervisor keeps owning
/// captures and exact requests. Drop performs no persistence.
#[derive(Debug)]
pub struct SyncWaiter {
    reply: Arc<Reply>,
    receiver: Option<oneshot::Receiver<Result<(), CoordinationError>>>,
}
impl SyncWaiter {
    pub fn cancel(&self) {
        self.reply.cancel();
    }
    /// # Errors
    /// Cancellation, engine failure or a supervisor lost before delivery.
    pub async fn wait(mut self) -> Result<(), CoordinationError> {
        self.receiver
            .take()
            .ok_or_else(|| refused("SyncWaiterConsumed"))?
            .await
            .map_err(|_| refused("SyncCancelled"))?
    }
}
impl Drop for SyncWaiter {
    fn drop(&mut self) {
        self.reply.cancel();
    }
}

struct FloorWake<'a>(&'a Notify);
impl Drop for FloorWake<'_> {
    fn drop(&mut self) {
        self.0.notify_waiters();
    }
}

/// A seal's registration, retained for completion, with what its
/// preparation accepted and signed. `charge` is a projected seal's lane
/// reservation, zero for any other.
struct Prepared {
    request: PendingIntent,
    root: Vec<u8>,
    accepted: Arc<crate::AcceptedSyncProjection>,
    mapped: Option<Arc<std::collections::BTreeSet<GrainId>>>,
    charge: u64,
}

struct Retained {
    input: CaptureCoverageInput,
    reply: Arc<Reply>,
    _workspace: Arc<WorkspaceLease>,
    request: PendingIntent,
    boundary: SyncBoundary,
}
type Preparing = (SyncBoundary, Arc<WorkspaceLease>, Option<u64>, Arc<Reply>);

#[derive(Default)]
struct State {
    queue: SyncProjectionQueue,
    queue_charge: u64,
    retained: BTreeMap<u64, Retained>,
    /// A seal being prepared: its workspace lease, a projected seal's lane
    /// charge, and its caller.
    preparing: Option<Preparing>,
    /// A projected sync's closed lane from its closure until its candidate
    /// is retained or the lane released: the lane's serial, its charge, and
    /// its caller.
    projected: Option<(Option<u64>, u64, Arc<Reply>)>,
    /// Refuse the next failed registration's settlement once its failure
    /// is persisted, as a later local error would.
    #[cfg(test)]
    settle_refusal: bool,
    commit: Option<RetainedCommit>,
    constructing_commit: bool,
    /// A supervised construction's lane from its closure until the
    /// construction ends: what its monitor releases if its task is lost.
    construction: Option<Construction>,
    commit_workspace: Option<WorkspaceLease>,
}

/// Per-engine policy bookkeeping, not a memory reservation or memory bound.
/// Shared seals release once their last preparation/completion owner drops.
struct WorkspaceLease {
    ledger: Arc<AtomicU64>,
    bytes: u64,
}
impl WorkspaceLease {
    fn new(ledger: &Arc<AtomicU64>, bytes: u64) -> Result<Self, CoordinationError> {
        ledger
            .try_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                held.checked_add(bytes)
            })
            .map_err(|_| refused("SyncGraphOverflow"))?;
        Ok(Self {
            ledger: ledger.clone(),
            bytes,
        })
    }
}
impl Drop for WorkspaceLease {
    fn drop(&mut self) {
        self.ledger.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
/// A supervised construction's hold on the commit lane: the operation that
/// opened it, the lane's serial, and once its capture is taken, that
/// capture's graph charge and boundary.
struct Construction {
    owner: [u8; 16],
    serial: u64,
    charge: u64,
    snapshot: Option<Arc<SyncBoundary>>,
}
impl State {
    /// The construction of lane `serial` has ended: only its own projected
    /// and construction records are cleared.
    fn release_construction(&mut self, serial: u64) {
        self.constructing_commit = false;
        self.commit_workspace = None;
        if self
            .projected
            .as_ref()
            .is_some_and(|(owner, _, _)| *owner == Some(serial))
        {
            self.projected = None;
        }
        if self
            .construction
            .as_ref()
            .is_some_and(|construction| construction.serial == serial)
        {
            self.construction = None;
        }
    }

    /// What a lost task's construction of lane `serial` still holds, its
    /// boundary and charge, only while `owner`'s construction of that lane
    /// is the one recorded.
    fn lost_construction(
        &self,
        owner: &[u8; 16],
        serial: u64,
    ) -> Option<(Option<Arc<SyncBoundary>>, u64)> {
        self.construction
            .as_ref()
            .filter(|construction| construction.owner == *owner && construction.serial == serial)
            .map(|construction| (construction.snapshot.clone(), construction.charge))
    }
}

/// Installs a landing, or another writer's published head, as the mount's
/// view. The engine runs each under its admission, inside an operation the
/// sync runtime owns, so a caller that stops waiting stops nothing. The view
/// is rebuilt from `root` alone, and `commit` switches the overlay and binds
/// that view in one mediator acquisition. The returned revocation is sent
/// once admission is released.
pub(crate) trait MountViewHook: Send + Sync {
    fn install(
        &self,
        root: super::PublishedRoot,
        deadline: tokio::time::Instant,
        commit: LandedCommit,
    ) -> ViewInstall<'_>;

    /// Install a landing with the adapter gone: the view is rebuilt from
    /// `root` and `commit` switches the overlay and binds it, with no gate,
    /// re-key or revocation, since nothing serves the view any more. A hook
    /// that cannot rebuild a view refuses and changes nothing.
    fn install_unattended(
        &self,
        root: super::PublishedRoot,
        deadline: tokio::time::Instant,
        commit: LandedCommit,
    ) -> ViewInstall<'_> {
        let _ = (root, deadline, commit);
        Box::pin(async {
            (
                Err(refused("ViewUnattendedUnsupported")),
                Revocation::none(),
            )
        })
    }

    /// Adopt `root`, a head another writer published above the pin, when
    /// the mount holds nothing of its own that the head lacks. Every check
    /// precedes the session's acceptance of `root`, the first write.
    fn adopt(
        &self,
        root: super::PublishedRoot,
        deadline: tokio::time::Instant,
        adoption: AdoptionCommit,
    ) -> ViewInstall<'_, Adopted>;

    /// Close the view over a store that refuses its own reads, and collect
    /// its open inodes to revoke. `Ok` only when the close ran under the
    /// gate; every earlier failure changes nothing.
    fn close(&self, error: CoordinationError, deadline: tokio::time::Instant) -> ViewInstall<'_>;
}

/// An install's outcome, and the revocation to send once admission is
/// released.
pub(crate) type ViewInstall<'a, T = ()> =
    std::pin::Pin<Box<dyn Future<Output = (Result<T, CoordinationError>, Revocation)> + Send + 'a>>;

/// How an adoption that ran to a verdict ended. An `Err` beside it is "no
/// answer yet": nothing changed, and the same head may be tried again.
#[derive(Debug)]
pub(crate) enum Adopted {
    /// The mount now serves the head.
    Installed,
    /// The mount holds work of its own, so it keeps its view.
    Deferred,
    /// The head can never be adopted, and nothing changed.
    Refused {
        #[expect(
            dead_code,
            reason = "the cause is kept for diagnosis; the head observer acts on the refusal alone"
        )]
        cause: CoordinationError,
    },
    /// The view is closed and its held inodes are revoked.
    Closed,
}

/// Whether a head at `seq` can be adopted over a pin at `pin_seq`: above
/// the pin, and at a seq a journal header can carry as its base.
pub(crate) fn head_above_pin(pin_seq: u64, seq: u64) -> bool {
    seq > pin_seq && seq <= u64::MAX - 2
}

/// The engine's half of an adoption: `check` says whether the engine or the
/// mediator holds work an adoption would lose, and `commit` switches to the
/// head.
pub(crate) struct AdoptionCommit {
    pub(crate) check: Box<dyn FnMut() -> Result<bool, CoordinationError> + Send>,
    pub(crate) commit: AdoptedCommit,
}

/// The engine's switch to an adopted head: it replaces the clean overlay
/// with the head's entries and binds the view it is given, returning what
/// the replacement did not carry.
pub(crate) type AdoptedCommit = Box<
    dyn FnOnce(
            Arc<crate::writable_store::ViewContext>,
            crate::writable_start::AdoptionWalk,
            Vec<crate::OverlayEntry>,
        ) -> Result<crate::ViewChange, CoordinationError>
        + Send,
>;

/// The engine as a view boundary drives it, without naming the engine's
/// type parameters: the pin, the advisory precondition, an adoption, and
/// the close of a view whose store refuses its own reads.
pub(crate) trait HeadAdopter: Send + Sync {
    /// The pinned `(id, seq)`, read in one mediator acquisition.
    fn pin(&self) -> Result<(GrainId, u64), CoordinationError>;
    /// Whether the engine or the mediator holds work an adoption would lose.
    fn adoption_blocked(&self) -> Result<bool, CoordinationError>;
    /// Adopt the head published at `seq`.
    fn adopt(&self, seq: u64) -> AdopterFuture<'_, Adopted>;
    /// Close and revoke the view over a store that refuses its own reads.
    fn close(&self, error: CoordinationError) -> AdopterFuture<'_, ()>;
    /// Record that the authority answered with a head sequence.
    fn answered(&self);
}

/// The future a [`HeadAdopter`] call returns.
pub(crate) type AdopterFuture<'a, T> =
    std::pin::Pin<Box<dyn Future<Output = Result<T, CoordinationError>> + Send + 'a>>;

/// The engine's half of an install: it replaces the overlay with the
/// landing and binds the view it is given, returning what the replacement
/// did not carry.
pub(crate) type LandedCommit = Box<
    dyn FnOnce(
            Arc<crate::writable_store::ViewContext>,
        ) -> Result<crate::ViewChange, CoordinationError>
        + Send,
>;

/// What a closed view sends to revoke what it served, once nothing is held.
pub(crate) struct Revocation(Option<Box<dyn FnOnce() + Send>>);
impl Revocation {
    pub(crate) fn none() -> Self {
        Self(None)
    }
    pub(crate) fn new(send: impl FnOnce() + Send + 'static) -> Self {
        Self(Some(Box::new(send)))
    }
    pub(crate) fn send(self) {
        if let Some(send) = self.0 {
            send();
        }
    }
}

/// Engine state a test holds alone, which an adoption waits for.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EngineHold {
    /// A commit lane under construction.
    Construction,
    /// A projected sync's closed lane.
    ProjectedSync,
    /// A registered sync retained for completion.
    RetainedSync,
}

/// Where a test makes a supervised commit construction panic.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetentionPanic {
    /// In the retention closure, before the candidate is checked or its
    /// boundary recorded.
    BeforeRetain,
    /// In the retention closure, once the boundary is durable, before the
    /// state lock is taken.
    AfterRetain,
    /// In the supervised task, once the capture is taken, before its
    /// candidate is constructed.
    Constructing,
    /// In the supervised task, once a lost retention closure's release has
    /// run or been refused.
    AfterLostRetention,
}

/// A single supervisor per mediator. Preparation admits roots in capture order;
/// the admission gate ends before dispatch so registrations can overlap.
pub struct SyncEngine<P: OverlayIo, R, S, C, M, E = TokioSyncRuntime> {
    store: Arc<Mutex<WritableStore<P>>>,
    volume: VolumeName,
    remote: Arc<R>,
    content: Arc<S>,
    wall: Arc<C>,
    monotonic: Arc<M>,
    runtime: Arc<E>,
    key: SigningKey,
    trusted: TrustedKeys,
    base: Mutex<VerifiedBase>,
    metrics: ClientMetrics,
    admission: AsyncMutex<()>,
    faults: crate::FaultControl,
    completion: AsyncMutex<()>,
    floor_changed: Arc<Notify>,
    coalesce_wake: Arc<Notify>,
    /// Holders of the commit driver: a driving caller, and an install that
    /// outlives it.
    commit_driver: Arc<AtomicUsize>,
    workspace_ledger: Arc<AtomicU64>,
    view_hook: OnceLock<Arc<dyn MountViewHook>>,
    /// Install every later landing through the hook's unattended install,
    /// without the adapter's gate: set when a shutdown begins on a mount
    /// whose adapter is gone.
    local_install: AtomicBool,
    /// Set when a head observation receives an authority sequence.
    answered: AtomicBool,
    #[cfg(test)]
    commit_retries: Mutex<Vec<crate::RetryReason>>,
    binmap_get_bytes: AtomicU64,
    refused_get_bytes: AtomicU64,
    state: Mutex<State>,
    /// The last accepted projection's charges, by kind of work.
    #[cfg(test)]
    spend: Mutex<BTreeMap<&'static str, u64>>,
    #[cfg(test)]
    budget_observation: Mutex<Option<BudgetObservation>>,
    #[cfg(test)]
    binmap_work: Mutex<crate::BinmapWork>,
    /// The next commit construction panics at each of these points.
    #[cfg(test)]
    retention_panic: Mutex<Vec<RetentionPanic>>,
    /// Run after the construction state lock and before the mediator closure.
    #[cfg(test)]
    before_close_for_construction: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Run after the live wait subscribes and before it reads state.
    #[cfg(test)]
    before_live_read: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Run after a live-state read, before its subscribed wake is polled.
    #[cfg(test)]
    after_live_read: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Run after takeover recovery fails, before admission is read again.
    #[cfg(test)]
    after_recover_error: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Run after a live pass clears the old answer mark and before takeover.
    #[cfg(test)]
    before_live_drive: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Run after the live loop clears the answer mark, before a drive.
    #[cfg(test)]
    before_live_commit_drive: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Minimum remaining time to dispatch a finishing start's publish.
    #[cfg(test)]
    start_dispatch_floor: OnceLock<Duration>,
    /// Run after the retry wait's first admission read.
    #[cfg(test)]
    after_live_retry_read: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Commit constructions begun by the live loop.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    live_constructions: AtomicU64,
    /// Retry schedule bases and the values drawn from them.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    live_pauses: Mutex<Vec<(Duration, Duration)>>,
}
impl<P: OverlayIo, R, S, C, M, E> std::fmt::Debug for SyncEngine<P, R, S, C, M, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncEngine").finish_non_exhaustive()
    }
}

struct Immutable<'a, S>(&'a S);

impl<S: SyncContent> ContentSource for Immutable<'_, S> {
    fn read_verified(
        &mut self,
        content: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        self.0.read_content(content, offset, length)
    }
}

#[cfg(test)]
#[derive(Clone)]
struct BudgetObservation {
    /// Materialization, then closure acceptance.
    limits: [u64; 2],
    charges: [Arc<Mutex<Vec<u64>>>; 2],
}

// The budget conservatively includes object copies, map nodes, packing/index
// working sets and ref graphs. Repeated fetches consume charge too; exhaustion
// refuses instead of making a whole-file or incomplete-closure substitution.
pub(crate) struct Budget<'a, S> {
    source: &'a S,
    remaining: Mutex<u64>,
    limit: u64,
    boundary: Option<&'a SyncBoundary>,
    file: Option<&'a crate::CapturedFile>,
    // Set only by this engine's own object workspace refusing, so a refusal
    // echoed by the remote is never mistaken for local capacity.
    workspace_refused: AtomicBool,
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    fault_refused: AtomicBool,
    // What was charged, by kind of work, for tests that compare two runs.
    #[cfg(test)]
    spent: Mutex<BTreeMap<&'static str, u64>>,
    #[cfg(test)]
    observed_charges: Option<Arc<Mutex<Vec<u64>>>>,
}

struct ObjectRemote<'a, R, S, E> {
    remote: &'a R,
    budget: &'a Budget<'a, S>,
    reply: &'a Reply,
    deadline: tokio::time::Instant,
    runtime: &'a E,
    faults: &'a crate::FaultControl,
    capture: u64,
    metrics: &'a ClientMetrics,
    binmap_get_bytes: &'a AtomicU64,
    refused_get_bytes: &'a AtomicU64,
    grain_ids: std::collections::BTreeSet<GrainId>,
}
impl<R, S, E: SyncRuntime> ObjectRemote<'_, R, S, E> {
    #[cfg_attr(
        not(any(test, feature = "overlay-fault-tests")),
        expect(
            clippy::unused_async,
            reason = "the hook awaits only when fault points are compiled in; the release build keeps one signature"
        )
    )]
    async fn fault(
        &self,
        name: &'static str,
        phase: &'static str,
        object_kind: &'static str,
    ) -> Result<(), granary_core::rootstore::RootStoreError> {
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        {
            let faults = self.faults.clone();
            let capture = self.capture;
            let action = self
                .runtime
                .blocking(move || faults.sync_point(name, phase, capture, None, object_kind))
                .await
                .map_err(|_| {
                    granary_core::rootstore::RootStoreError::Backend(
                        "sync fault supervisor lost".into(),
                    )
                })?;
            if action.is_some() {
                self.budget.fault_refused.store(true, Ordering::Release);
                return Err(granary_core::rootstore::RootStoreError::Backend(
                    "sync injected fault".into(),
                ));
            }
        }
        #[cfg(not(any(test, feature = "overlay-fault-tests")))]
        {
            let _ = (self.faults, self.capture, name, phase, object_kind);
        }
        Ok(())
    }
    fn check(&self) -> Result<(), granary_core::rootstore::RootStoreError> {
        if self.reply.cancelled.load(Ordering::Acquire) || self.runtime.now() >= self.deadline {
            return Err(granary_core::rootstore::RootStoreError::Backend(
                "sync object attempt stopped".into(),
            ));
        }
        Ok(())
    }
}
impl<R: BinStore, S: SyncContent, E: SyncRuntime> BinStore for ObjectRemote<'_, R, S, E> {
    async fn put_bin(
        &self,
        digest: &[u8; 32],
        bytes: Vec<u8>,
    ) -> Result<bool, granary_core::rootstore::RootStoreError> {
        self.check()?;
        self.budget
            .charge_as("put_bin", bytes.len())
            .map_err(Budget::<S>::refuse)?;
        let entries = granary_core::binfmt::decode_bin(&bytes).map_err(|_| {
            granary_core::rootstore::RootStoreError::Backend("sync bin decode".into())
        })?;
        let grains = entries
            .iter()
            .filter(|entry| self.grain_ids.contains(&entry.id))
            .count() as u64;
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        let kinds = {
            let mut codec = granary_store::codec::GrainCodec::new().map_err(|_| {
                granary_core::rootstore::RootStoreError::Backend("sync codec".into())
            })?;
            entries
                .iter()
                .filter(|entry| !self.grain_ids.contains(&entry.id))
                .map(|entry| {
                    let frame = granary_core::binfmt::frame_bytes(&bytes, entry).map_err(|_| {
                        granary_core::rootstore::RootStoreError::Backend("sync bin frame".into())
                    })?;
                    let payload = codec.decompress_frame(frame).map_err(|_| {
                        granary_core::rootstore::RootStoreError::Backend("sync bin payload".into())
                    })?;
                    object_kind(&payload).ok_or_else(|| {
                        granary_core::rootstore::RootStoreError::Backend("sync object kind".into())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        self.fault("sync.upload", "before", "bin").await?;
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        for kind in &kinds {
            self.fault("sync.node_upload", "before", kind).await?;
        }
        let size = bytes.len() as u64;
        let novel = self.remote.put_bin(digest, bytes).await?;
        if novel {
            self.metrics.record_uploaded_grains(grains);
            self.metrics
                .record_uploaded_bytes(crate::UploadObject::Bin, size);
        }
        self.fault("sync.upload", "accepted", "bin").await?;
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        for kind in &kinds {
            self.fault("sync.node_upload", "accepted", kind).await?;
        }
        Ok(novel)
    }
    async fn put_meta(
        &self,
        volume: &str,
        id: &GrainId,
        bytes: Vec<u8>,
    ) -> Result<bool, granary_core::rootstore::RootStoreError> {
        self.check()?;
        let kind = object_kind(&bytes).ok_or_else(|| {
            granary_core::rootstore::RootStoreError::Backend("sync object kind".into())
        })?;
        self.budget
            .charge_as(
                match kind {
                    "binmap" => "put_binmap",
                    "manifest" => "put_manifest",
                    "grain_list" => "put_grain_list",
                    _ => "put_sheaf",
                },
                bytes.len(),
            )
            .map_err(Budget::<S>::refuse)?;
        self.fault("sync.node_upload", "before", kind).await?;
        let size = bytes.len() as u64;
        let novel = self.remote.put_meta(volume, id, bytes).await?;
        if novel {
            self.metrics
                .record_uploaded_bytes(crate::UploadObject::Meta, size);
        }
        self.fault("sync.node_upload", "accepted", kind).await?;
        Ok(novel)
    }
    async fn get_meta(
        &self,
        volume: &str,
        id: &GrainId,
    ) -> Result<Vec<u8>, granary_core::rootstore::RootStoreError> {
        self.check()?;
        let bytes = self.remote.get_meta(volume, id).await?;
        if object_kind(&bytes) == Some("binmap") {
            self.binmap_get_bytes
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
        if let Err(error) = self
            .budget
            .charge_as(object_kind(&bytes).unwrap_or("other"), bytes.len())
        {
            self.refused_get_bytes
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            return Err(Budget::<S>::refuse(error));
        }
        Ok(bytes)
    }
    async fn get_bin_range(
        &self,
        digest: &[u8; 32],
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, granary_core::rootstore::RootStoreError> {
        self.check()?;
        let bytes = self.remote.get_bin_range(digest, offset, length).await?;
        self.budget
            .charge(bytes.len())
            .map_err(Budget::<S>::refuse)?;
        Ok(bytes)
    }
}

fn object_kind(bytes: &[u8]) -> Option<&'static str> {
    use granary_core::encoding::ObjectType;
    let (kind, _) = granary_core::encoding::open_envelope(bytes).ok()?;
    match kind {
        ObjectType::DirLeaf | ObjectType::DirInterior => Some("manifest"),
        ObjectType::GrainListLeaf | ObjectType::GrainListIndex => Some("grain_list"),
        ObjectType::BinmapIndex | ObjectType::BinTable | ObjectType::BinmapShard => Some("binmap"),
        ObjectType::Sheaf => Some("sheaf"),
        _ => None,
    }
}

// Cancellation may abandon content-addressed attempts before registration. The
// supervisor still explicitly disposes the boundary after this future returns.
async fn before_send<T: Send>(
    runtime: &impl SyncRuntime,
    reply: &Reply,
    deadline: tokio::time::Instant,
    work: impl Future<Output = T> + Send,
) -> Result<T, CoordinationError> {
    let mut work = std::pin::pin!(runtime.timeout_at(deadline, work));
    let mut cancelled = std::pin::pin!(reply.cancellation.notified());
    std::future::poll_fn(|cx| {
        if reply.cancelled.load(Ordering::Acquire) {
            return std::task::Poll::Ready(Err(refused("SyncCancelled")));
        }
        let _ = cancelled.as_mut().poll(cx);
        work.as_mut()
            .poll(cx)
            .map(|result| result.map_err(|_| refused("SyncDeadline")))
    })
    .await
}
// Only this engine's own workspace refusing is local capacity; the same text
// arriving from the remote stays an authority failure.
fn preparation_error(error: crate::PublishError, workspace_refused: bool) -> CoordinationError {
    if workspace_refused
        && matches!(
            &error,
            crate::PublishError::Remote(
                granary_core::rootstore::RootStoreError::RefusedResponse {
                    reason,
                    kind: granary_core::rootstore::RefusalKind::OverCap,
                }
            ) | crate::PublishError::Source(GrainSourceError::Backend(reason))
                if reason == "sync object workspace"
        )
    {
        refused("SyncWorkspaceExhausted")
    } else {
        CoordinationError::Recovery(crate::RecoveryError::Preparation(error))
    }
}

impl<'a, S> Budget<'a, S> {
    pub(crate) fn new(source: &'a S, remaining: u64, boundary: Option<&'a SyncBoundary>) -> Self {
        Self {
            source,
            remaining: Mutex::new(remaining),
            limit: remaining,
            boundary,
            file: boundary.and_then(|boundary| match boundary.files() {
                [file] => Some(file),
                _ => None,
            }),
            workspace_refused: AtomicBool::new(false),
            #[cfg(any(test, feature = "overlay-fault-tests"))]
            fault_refused: AtomicBool::new(false),
            #[cfg(test)]
            spent: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            observed_charges: None,
        }
    }
}
impl<S> Budget<'_, S> {
    fn publication_error(&self, error: CoordinationError) -> crate::PublishError {
        match self.payload_error(error) {
            error @ CoordinationError::Refused("SyncWorkspaceExhausted") => {
                crate::PublishError::Remote(Self::refuse(error))
            }
            _ => crate::PublishError::BadPlan,
        }
    }

    fn payload_error(&self, error: CoordinationError) -> CoordinationError {
        if self.workspace_refused.load(Ordering::Acquire)
            && matches!(
                error,
                CoordinationError::Overlay(OverlayError::CaptureCoverageLost)
            )
        {
            refused("SyncWorkspaceExhausted")
        } else {
            error
        }
    }
    #[expect(
        clippy::needless_pass_by_value,
        reason = "map_err consumes the failed charge's owned error"
    )]
    fn refuse(error: CoordinationError) -> granary_core::rootstore::RootStoreError {
        if !matches!(error, CoordinationError::Refused("SyncWorkspaceExhausted")) {
            return granary_core::rootstore::RootStoreError::Backend(error.to_string());
        }
        granary_core::rootstore::RootStoreError::RefusedResponse {
            reason: "sync object workspace".into(),
            kind: granary_core::rootstore::RefusalKind::OverCap,
        }
    }
    pub(crate) fn charge(&self, bytes: usize) -> Result<(), CoordinationError> {
        self.charge_as("other", bytes)
    }
    /// Charge an allocation whose byte bound is already computed.
    pub(crate) fn charge_reserved(&self, bytes: u64) -> Result<(), CoordinationError> {
        self.spend("other", bytes)
    }
    fn charge_as(&self, kind: &'static str, bytes: usize) -> Result<(), CoordinationError> {
        let charge = (bytes as u64)
            .checked_mul(8)
            .and_then(|n| n.checked_add(1024))
            .ok_or_else(|| refused("SyncGraphOverflow"))?;
        self.spend(kind, charge)
    }
    fn spend(&self, kind: &'static str, charge: u64) -> Result<(), CoordinationError> {
        #[cfg(test)]
        if let Some(charges) = &self.observed_charges {
            // Include the refused charge so the trace identifies its stopping point.
            charges
                .lock()
                .map_err(|_| refused("SyncGraphPoisoned"))?
                .push(charge);
        }
        let mut remaining = self
            .remaining
            .lock()
            .map_err(|_| refused("SyncGraphPoisoned"))?;
        let Some(left) = remaining.checked_sub(charge) else {
            let first = !self.workspace_refused.swap(true, Ordering::AcqRel);
            let needed = self.limit.saturating_sub(*remaining).saturating_add(charge);
            drop(remaining);
            if first {
                if let Some(boundary) = self.boundary {
                    let path = self
                        .file
                        .and_then(crate::CapturedFile::entry)
                        .map(|entry| crate::local_report::namespace_path(&entry.path));
                    crate::LocalReport::workspace_exhausted(
                        crate::local_report::WorkspaceSite::Boundary(boundary.id()),
                        path.as_deref(),
                        needed,
                        self.limit,
                    )
                    .emit();
                }
                crate::ClientEvent::workspace_exhausted(needed, self.limit).emit();
            }
            return Err(refused("SyncWorkspaceExhausted"));
        };
        *remaining = left;
        #[cfg(test)]
        {
            let mut spent = self
                .spent
                .lock()
                .map_err(|_| refused("SyncGraphPoisoned"))?;
            *spent.entry(kind).or_default() += charge;
        }
        #[cfg(not(test))]
        let _ = kind;
        Ok(())
    }
}
impl<S: SyncContent> GrainSource for Budget<'_, S> {
    fn has(&self, id: &GrainId) -> bool {
        self.source.has(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        let bytes = self.source.get(id)?;
        self.charge_as("get", bytes.len()).map_err(|error| {
            GrainSourceError::Backend(match error {
                CoordinationError::Refused("SyncWorkspaceExhausted") => {
                    "sync object workspace".into()
                }
                error => error.to_string(),
            })
        })?;
        Ok(bytes)
    }
}

impl<P, R, S, C, M, E> SyncEngine<P, R, S, C, M, E>
where
    P: OverlayIo + Send + 'static,
    R: SyncRemote + 'static,
    S: SyncContent + 'static,
    C: Clock + 'static,
    M: MonotonicClock + 'static,
    E: SyncRuntime + 'static,
{
    /// Attach once to a ready mediator, using an exact verified captured base.
    /// # Errors
    /// Duplicate supervisor, readiness, poison or foreign/unverified base.
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit independent storage, timing and signing seams"
    )]
    pub async fn with_runtime(
        store: Arc<Mutex<WritableStore<P>>>,
        remote: Arc<R>,
        content: Arc<S>,
        wall: Arc<C>,
        monotonic: Arc<M>,
        key: SigningKey,
        trusted: TrustedKeys,
        base: Vec<u8>,
        metrics: ClientMetrics,
        runtime: Arc<E>,
    ) -> Result<Arc<Self>, CoordinationError> {
        let mut key = Some(key);
        let (engine, _) = Self::attach_with_runtime(
            store, remote, content, wall, monotonic, &mut key, trusted, base, metrics, runtime,
            None,
        )
        .await?;
        Ok(engine)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "explicit independent storage, timing, signing and mount-binding seams"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "attachment validates the base, then initialises every engine field in one place"
    )]
    pub(crate) async fn attach_with_runtime(
        store: Arc<Mutex<WritableStore<P>>>,
        remote: Arc<R>,
        content: Arc<S>,
        wall: Arc<C>,
        monotonic: Arc<M>,
        key: &mut Option<SigningKey>,
        trusted: TrustedKeys,
        base: Vec<u8>,
        metrics: ClientMetrics,
        runtime: Arc<E>,
        mount_binding: Option<([u8; 16], u64, [u8; 16])>,
    ) -> Result<(Arc<Self>, Option<u64>), CoordinationError> {
        if key.is_none() {
            return Err(refused("SyncEngineAlreadyAttached"));
        }
        let volume = {
            let local = store.lock().map_err(|_| refused("SyncMediatorPoisoned"))?;
            let doc = granary_core::root::decode_root(&base).map_err(|_| refused("SyncBase"))?;
            let volume = local.snapshot().volume.clone();
            granary_store::crypto::check_head(&base, volume.as_str(), doc.seq, &trusted)
                .map_err(|_| refused("SyncBase"))?;
            local.check_sync_base(&base, doc.seq)?;
            volume
        };
        let deadline = runtime
            .now()
            .checked_add(crate::DEFAULT_RESOLUTION_BOUND)
            .ok_or_else(|| refused("SyncDeadlineOverflow"))?;
        let map = runtime
            .timeout_at(
                deadline,
                VerifiedBase::attach_map(&base, volume.as_str(), &trusted, remote.as_ref()),
            )
            .await
            .map_err(|_| refused("SyncDeadline"))??;
        let walk_source = content.clone();
        let walk_runtime = runtime.clone();
        let walk_keys = trusted.clone();
        let walk_volume = volume.clone();
        let base = runtime
            .timeout_at(
                deadline,
                runtime.blocking(move || {
                    let source = walk_source.with_deadline(walk_runtime, deadline);
                    VerifiedBase::attach_validated(
                        base,
                        walk_volume.as_str(),
                        &walk_keys,
                        &source,
                        map,
                    )
                }),
            )
            .await
            .map_err(|_| refused("SyncDeadline"))?
            .map_err(|_| refused("SyncBase"))?;
        if runtime.now() >= deadline {
            return Err(refused("SyncDeadline"));
        }
        let base = base?;
        let clock_runtime = runtime.clone();
        let (faults, post_generation, floor_changed, coalesce_wake) = {
            let mut local = store.lock().map_err(|_| refused("SyncMediatorPoisoned"))?;
            local.check_sync_base(base.bytes(), base.seq())?;
            let post_generation = match mount_binding {
                Some(owner) => Some(local.check_mount_binding(owner)?.generation),
                None => None,
            };
            local.attach_sync_engine()?;
            local.set_metrics(metrics.clone());
            let clock = crate::overlay_store::CoalesceClock(Arc::new(move || clock_runtime.now()));
            let coalesce_wake = local.install_coalescer(clock);
            (
                local.fault_control(),
                post_generation,
                local.floor_changed.clone(),
                coalesce_wake,
            )
        };
        let key = key
            .take()
            .ok_or_else(|| refused("SyncEngineAlreadyAttached"))?;
        metrics.set_available(crate::MetricsGroup::Sync, true);
        metrics.set_available(crate::MetricsGroup::Commit, true);
        Ok((
            Arc::new(Self {
                faults,
                store,
                volume,
                remote,
                content,
                wall,
                monotonic,
                runtime,
                key,
                trusted,
                base: Mutex::new(base),
                metrics,
                admission: AsyncMutex::new(()),
                completion: AsyncMutex::new(()),
                floor_changed,
                coalesce_wake,
                commit_driver: Arc::new(AtomicUsize::new(0)),
                workspace_ledger: Arc::new(AtomicU64::new(0)),
                view_hook: OnceLock::new(),
                local_install: AtomicBool::new(false),
                answered: AtomicBool::new(false),
                #[cfg(test)]
                commit_retries: Mutex::new(Vec::new()),
                binmap_get_bytes: AtomicU64::new(0),
                refused_get_bytes: AtomicU64::new(0),
                state: Mutex::new(State::default()),
                #[cfg(test)]
                spend: Mutex::new(BTreeMap::new()),
                #[cfg(test)]
                budget_observation: Mutex::new(None),
                #[cfg(test)]
                binmap_work: Mutex::new(crate::BinmapWork::default()),
                #[cfg(test)]
                retention_panic: Mutex::new(Vec::new()),
                #[cfg(test)]
                before_close_for_construction: Mutex::new(None),
                #[cfg(test)]
                before_live_read: Mutex::new(None),
                #[cfg(test)]
                after_live_read: Mutex::new(None),
                #[cfg(test)]
                after_recover_error: Mutex::new(None),
                #[cfg(test)]
                before_live_drive: Mutex::new(None),
                #[cfg(test)]
                before_live_commit_drive: Mutex::new(None),
                #[cfg(test)]
                start_dispatch_floor: OnceLock::new(),
                #[cfg(test)]
                after_live_retry_read: Mutex::new(None),
                #[cfg(any(test, feature = "overlay-fault-tests"))]
                live_constructions: AtomicU64::new(0),
                #[cfg(any(test, feature = "overlay-fault-tests"))]
                live_pauses: Mutex::new(Vec::new()),
            }),
            post_generation,
        ))
    }

    /// What the last projection attempt charged, including a refused attempt.
    #[cfg(test)]
    pub(crate) fn last_spend(&self) -> BTreeMap<&'static str, u64> {
        self.spend
            .lock()
            .map(|spend| spend.clone())
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn last_binmap_work(&self) -> crate::BinmapWork {
        self.binmap_work
            .lock()
            .map(|work| work.clone())
            .unwrap_or_default()
    }

    /// Binmap bytes returned by preparation GETs, including a GET subsequently
    /// refused by the local workspace. Attach validation is outside this meter.
    #[must_use]
    pub fn binmap_get_bytes(&self) -> u64 {
        self.binmap_get_bytes.load(Ordering::Relaxed)
    }

    /// Metadata response bytes transferred by GETs that the local workspace
    /// subsequently refused, regardless of the response's object type.
    #[must_use]
    pub fn refused_metadata_get_bytes(&self) -> u64 {
        self.refused_get_bytes.load(Ordering::Relaxed)
    }

    /// Fallback triggers and later bypasses for the currently validated base.
    /// # Errors
    /// Refuses a poisoned base lock.
    pub fn binmap_exhaustion_counts(&self) -> Result<(u64, u64), CoordinationError> {
        Ok(self
            .base
            .lock()
            .map_err(|_| refused("SyncBasePoisoned"))?
            .binmap_exhaustion_counts())
    }

    pub(crate) fn runtime_for_mount(&self) -> Arc<E> {
        self.runtime.clone()
    }

    pub(crate) fn take_answered(&self) -> bool {
        self.answered.swap(false, Ordering::AcqRel)
    }

    /// Bind the hook every later landing installs its view through.
    ///
    /// A second binding refuses rather than replacing the first. That arm
    /// is an equivalent mutant, named rather than chased: the one caller
    /// binds once, right after it attaches the engine.
    ///
    /// # Errors
    /// `ViewHookBound` when a hook is already bound.
    pub(crate) fn set_view_hook(
        &self,
        hook: Arc<dyn MountViewHook>,
    ) -> Result<(), CoordinationError> {
        self.view_hook
            .set(hook)
            .map_err(|_| refused("ViewHookBound"))
    }

    /// Install every later landing without the adapter's gate, for a
    /// shutdown whose adapter is gone.
    pub(crate) fn install_locally(&self) {
        self.local_install.store(true, Ordering::Release);
    }

    /// Whether nothing is in flight: no sync admitted at the adapter and
    /// unanswered, none preparing or retained, no projected lane, no
    /// construction, no driver, and admission open. The state lock is taken,
    /// then the mediator, the order a landing's install takes them.
    /// # Errors
    /// A poisoned state lock, or the mediator's own refusal.
    pub(crate) fn quiescent(&self) -> Result<bool, CoordinationError> {
        let state = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?;
        let idle = state.preparing.is_none()
            && state.retained.is_empty()
            && state.projected.is_none()
            && state.construction.is_none()
            && !state.constructing_commit
            && self.commit_driver.load(Ordering::Acquire) == 0;
        let drained =
            self.local(|local| Ok(local.admitted_syncs == 0 && local.sync_admission_open()?))?;
        drop(state);
        Ok(idle && drained)
    }

    /// Whether engine admission is free, for rows that check a revocation
    /// is sent after it is released.
    /// Refuse the next failed registration's settlement after its failure
    /// is persisted and its charge released.
    #[cfg(test)]
    pub(crate) fn refuse_next_settle_for_test(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.settle_refusal = true;
        }
    }

    /// Make the next commit construction panic at `at`, as well as at any
    /// point already armed.
    #[cfg(test)]
    pub(crate) fn panic_retention_for_test(&self, at: RetentionPanic) {
        self.retention_panic
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(at);
    }

    /// Run `hook` after the construction state lock is held and before the
    /// mediator closure that closes the lane.
    #[cfg(test)]
    pub(crate) fn before_close_for_construction_for_test(
        &self,
        hook: impl FnOnce() + Send + 'static,
    ) {
        *self
            .before_close_for_construction
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
    }

    #[cfg(test)]
    pub(crate) fn set_start_dispatch_floor_for_test(&self, floor: Duration) {
        assert!(self.start_dispatch_floor.set(floor).is_ok());
    }

    #[cfg(test)]
    pub(crate) fn workspace_held_for_test(&self) -> u64 {
        self.workspace_ledger.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) async fn accept_boundary_for_test(
        self: &Arc<Self>,
        boundary: &SyncBoundary,
        workspace: u64,
        full: bool,
    ) -> Result<(), CoordinationError> {
        let mut queue = SyncProjectionQueue::default();
        queue.reserve(boundary)?;
        let (reply, _waiter) = self.observed_reply();
        self.accept_boundary(
            boundary,
            workspace,
            &reply,
            self.runtime.now() + Duration::from_secs(30),
            &queue,
            full,
        )
        .await
        .map(|_| ())
    }

    #[cfg(test)]
    fn observed_budget<'a, T>(&self, budget: Budget<'a, T>, phase: usize) -> Budget<'a, T> {
        let Some(observation) = self.budget_observation.lock().unwrap().clone() else {
            return budget;
        };
        let mut budget = Budget::new(budget.source, observation.limits[phase], budget.boundary);
        budget.observed_charges = Some(observation.charges[phase].clone());
        budget
    }

    #[cfg(test)]
    pub(crate) async fn accept_boundary_with_budgets_for_test(
        self: &Arc<Self>,
        boundary: &SyncBoundary,
        limits: [u64; 2],
    ) -> (Result<(), CoordinationError>, [Vec<u64>; 2]) {
        let charges = [Arc::default(), Arc::default()];
        *self.budget_observation.lock().unwrap() = Some(BudgetObservation {
            limits,
            charges: charges.clone(),
        });
        let result = self
            .accept_boundary_for_test(boundary, limits[0].max(limits[1]), false)
            .await;
        *self.budget_observation.lock().unwrap() = None;
        (
            result,
            charges.map(|charges| charges.lock().unwrap().clone()),
        )
    }

    #[cfg(test)]
    pub(crate) fn repeated_workspace_charges_for_test(
        &self,
        boundary: &SyncBoundary,
    ) -> Vec<String> {
        let budget = Budget::new(self.content.as_ref(), 0, Some(boundary));
        (0..2)
            .map(|_| budget.charge(1).unwrap_err().to_string())
            .collect()
    }

    /// Run `hook` after the live wait subscribes and before its first read.
    #[cfg(test)]
    pub(crate) fn before_live_read_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .before_live_read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
    }

    /// Run `hook` after the live wait's first state read.
    #[cfg(test)]
    pub(crate) fn after_live_read_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .after_live_read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
    }

    /// Run `hook` between a failed recovery and takeover's admission re-read.
    #[cfg(test)]
    pub(crate) fn after_recover_error_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .after_recover_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
    }

    /// Run `hook` after a live pass clears the old answer mark.
    #[cfg(test)]
    pub(crate) fn before_live_drive_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .before_live_drive
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
    }

    /// Run `hook` after the live loop clears the answer mark, before a drive.
    #[cfg(test)]
    pub(crate) fn before_live_commit_drive_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .before_live_commit_drive
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
    }

    /// Run `hook` after the retry wait's first admission read.
    #[cfg(test)]
    pub(crate) fn after_live_retry_read_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .after_live_retry_read
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
    }

    /// Commit constructions begun by the live loop.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub fn live_constructions_for_test(&self) -> u64 {
        self.live_constructions.load(Ordering::Relaxed)
    }

    /// Retry schedule bases and their jittered values, in draw order.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub fn live_pauses_for_test(&self) -> Vec<(Duration, Duration)> {
        self.live_pauses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether the mediator still holds a live commit lane.
    ///
    /// # Errors
    /// Returns the mediator's coordination error when its admission cannot be read.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub fn live_lane_held_for_test(&self) -> Result<bool, CoordinationError> {
        self.local(|local| {
            Ok(matches!(
                local.sync_admission()?,
                crate::writable_store::sync_engine::LiveAdmission::Held { .. }
            ))
        })
    }

    /// The floor notification observed by the live wait.
    #[cfg(test)]
    pub(crate) fn floor_changed_for_test(&self) -> Arc<Notify> {
        self.floor_changed.clone()
    }

    /// Whether later landings install without the adapter's gate.
    #[cfg(test)]
    pub(crate) fn installs_locally_for_test(&self) -> bool {
        self.local_install.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn admission_free_for_test(&self) -> bool {
        self.admission.try_lock().is_ok()
    }

    /// Whether the engine's state lock is free, for rows that check an
    /// install waits for the adapter without holding it.
    #[cfg(test)]
    pub(crate) fn state_free_for_test(&self) -> bool {
        self.state.try_lock().is_ok()
    }

    /// What callers' replies still own: whether a seal is being prepared,
    /// how many registrations are retained, and whether a projected lane is
    /// held closed.
    #[cfg(test)]
    pub(crate) fn owned_for_test(&self) -> (bool, usize, bool) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (
            state.preparing.is_some(),
            state.retained.len(),
            state.projected.is_some(),
        )
    }

    /// Whether a commit construction holds admission closed, and whether a
    /// retained lane is held.
    #[cfg(test)]
    pub(crate) fn commit_lane_for_test(&self) -> (bool, bool) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.constructing_commit, state.commit.is_some())
    }

    /// Forget the process-local lane while leaving its durable retention held.
    #[cfg(test)]
    pub(crate) fn forget_commit_for_test(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .commit = None;
    }

    /// The serial of the lane a supervised construction is recorded as
    /// holding, if any.
    #[cfg(test)]
    pub(crate) fn construction_for_test(&self) -> Option<u64> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .construction
            .as_ref()
            .map(|construction| construction.serial)
    }

    /// Start supervised work; callers only own this cancellation-safe waiter.
    #[must_use]
    pub fn sync(self: &Arc<Self>, target: SyncTarget, options: SyncOptions) -> SyncWaiter {
        self.sync_sealed(
            move |local| local.overlay_transaction(|t| t.seal_sync(target)).map(Some),
            options,
        )
    }

    pub(crate) fn sync_sealed(
        self: &Arc<Self>,
        seal: impl FnOnce(&mut WritableStore<P>) -> Result<Option<SyncBoundary>, CoordinationError>
        + Send
        + 'static,
        options: SyncOptions,
    ) -> SyncWaiter {
        let (supervised, waiter) = self.observed_reply();
        let engine = self.clone();
        let runtime = self.runtime.clone();
        drop(runtime.spawn(async move {
            let operation_engine = engine.clone();
            let operation_reply = supervised.clone();
            let operation = engine
                .runtime
                .spawn(async move { operation_engine.run(seal, options, &operation_reply).await });
            match operation.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => supervised.deliver(Err(error)),
                Err(_) => {
                    let failure = engine.fail_supervisor(&supervised).await;
                    supervised.deliver(Err(failure
                        .err()
                        .unwrap_or_else(|| refused("SyncSupervisorLost"))));
                }
            }
        }));
        waiter
    }

    /// One fsync's reply, the only one that records its observation, and
    /// the caller's waiter for it.
    fn observed_reply(&self) -> (Arc<Reply>, SyncWaiter) {
        let (sender, receiver) = oneshot::channel();
        let reply = Arc::new(Reply {
            sender: Mutex::new(Some(sender)),
            cancelled: AtomicBool::new(false),
            cancellation: Notify::new(),
            metrics: self.metrics.clone(),
            observed: true,
        });
        crate::observe::op_begin(crate::observe::OperationKind::Fsync);
        (
            reply.clone(),
            SyncWaiter {
                reply,
                receiver: Some(receiver),
            },
        )
    }

    /// Wait outside the mediator until a retained version permits this shrink.
    /// # Errors
    /// Readiness, poison, missing stage or the original operation deadline.
    /// # Cancellation safety
    /// Dropping this wait changes no stage or retained capture.
    pub fn wait_stage_floor(
        self: &Arc<Self>,
        stage: u64,
        size: u64,
        deadline: tokio::time::Instant,
    ) -> impl Future<Output = Result<(), CoordinationError>> + Send + 'static {
        let engine = self.clone();
        async move {
            loop {
                if engine.runtime.now() >= deadline {
                    return Err(refused("SyncDeadline"));
                }
                let wake = engine.floor_changed.notified();
                tokio::pin!(wake);
                wake.as_mut().enable();
                if engine.local(|local| {
                    local.overlay_transaction(|overlay| overlay.stage_floor_ready(stage, size))
                })? {
                    return Ok(());
                }
                engine
                    .fault("sync.floor", "checked", 0, None, "none")
                    .await?;
                engine
                    .runtime
                    .timeout_at(deadline, wake)
                    .await
                    .map_err(|_| refused("SyncDeadline"))?;
            }
        }
    }
    fn local<T>(
        &self,
        f: impl FnOnce(&mut WritableStore<P>) -> Result<T, CoordinationError>,
    ) -> Result<T, CoordinationError> {
        let mut local = self
            .store
            .lock()
            .map_err(|_| refused("SyncMediatorPoisoned"))?;
        f(&mut local)
    }

    #[cfg_attr(
        not(any(test, feature = "overlay-fault-tests")),
        expect(
            clippy::unused_async,
            reason = "the hook awaits only when fault points are compiled in; the release build keeps one signature"
        )
    )]
    async fn fault(
        &self,
        name: &'static str,
        phase: &'static str,
        capture: u64,
        request: Option<GrainId>,
        object_kind: &'static str,
    ) -> Result<(), CoordinationError> {
        #[cfg(any(test, feature = "overlay-fault-tests"))]
        {
            let faults = self.faults.clone();
            let action = self
                .runtime
                .blocking(move || faults.sync_point(name, phase, capture, request, object_kind))
                .await
                .map_err(|_| refused("SyncFaultSupervisorLost"))?;
            if action.is_some() {
                return Err(refused("SyncInjectedFault"));
            }
        }
        #[cfg(not(any(test, feature = "overlay-fault-tests")))]
        {
            let _ = (self, name, phase, capture, request, object_kind);
        }
        Ok(())
    }

    /// Seal with workspace policy bookkeeping, which only a sealed boundary
    /// keeps. A projected seal reserves its real lane graph charge and
    /// replacement bound, returned with the boundary; a refused seal releases
    /// those overlay reservations and the bookkeeping lease.
    async fn seal_reserved(
        self: &Arc<Self>,
        seal: impl FnOnce(&mut WritableStore<P>) -> Result<Option<SyncBoundary>, CoordinationError>
        + Send
        + 'static,
        workspace: u64,
        projected: bool,
    ) -> Result<Option<(SyncBoundary, u64, Arc<WorkspaceLease>)>, CoordinationError> {
        let lease = Arc::new(WorkspaceLease::new(&self.workspace_ledger, workspace)?);
        self.transaction(move |local| {
            let charge = if projected {
                local.reserve_projected_commit(workspace)?
            } else {
                0
            };
            match seal(local) {
                Ok(Some(boundary)) => Ok(Some((boundary, charge, lease))),
                unsealed => {
                    if projected {
                        local.release_projected_commit(charge)?;
                    }
                    unsealed.map(|_| None)
                }
            }
        })
        .await
    }

    async fn transaction<T: Send + 'static>(
        self: &Arc<Self>,
        action: impl FnOnce(&mut WritableStore<P>) -> Result<T, CoordinationError> + Send + 'static,
    ) -> Result<T, CoordinationError> {
        let engine = self.clone();
        self.runtime
            .blocking(move || engine.local(action))
            .await
            .map_err(|_| refused("SyncLocalTransactionLost"))?
    }

    fn check_waiter(
        &self,
        reply: &Reply,
        deadline: tokio::time::Instant,
    ) -> Result<(), CoordinationError> {
        if reply.cancelled.load(Ordering::Acquire) {
            return Err(refused("SyncCancelled"));
        }
        self.local(|local| local.sync_admission_open().map(|_| ()))?;
        if self.runtime.now() >= deadline {
            return Err(refused("SyncDeadline"));
        }
        Ok(())
    }

    fn deadline(&self, options: SyncOptions) -> Result<tokio::time::Instant, CoordinationError> {
        let deadline = self
            .runtime
            .now()
            .checked_add(options.resolution_bound)
            .ok_or_else(|| refused("SyncDeadlineOverflow"))?;
        Ok(options
            .deadline
            .map_or(deadline, |enclosing| deadline.min(enclosing)))
    }

    async fn run(
        self: &Arc<Self>,
        seal: impl FnOnce(&mut WritableStore<P>) -> Result<Option<SyncBoundary>, CoordinationError>
        + Send
        + 'static,
        options: SyncOptions,
        reply: &Arc<Reply>,
    ) -> Result<(), CoordinationError> {
        let _wake = FloorWake(&self.floor_changed);
        let deadline = self.deadline(options)?;
        let admission = loop {
            let admission = before_send(
                self.runtime.as_ref(),
                reply,
                deadline,
                self.admission.lock(),
            )
            .await?;
            if self.local(|local| local.sync_admission_open())? {
                break admission;
            }
            drop(admission);
            self.wait_for_commit(reply, deadline).await?;
        };
        let Some(prepared) = self
            .seal_prepared(seal, options, reply, deadline, false)
            .await?
        else {
            // The seal found nothing owed: answer without a registration.
            reply.deliver(Ok(()));
            return Ok(());
        };
        drop(admission);
        self.settle(&prepared, reply, deadline).await
    }

    /// Under admission, seal and prepare the registration of what the seal
    /// captured, retained for completion. `None`: the seal found nothing owed.
    async fn seal_prepared(
        self: &Arc<Self>,
        seal: impl FnOnce(&mut WritableStore<P>) -> Result<Option<SyncBoundary>, CoordinationError>
        + Send
        + 'static,
        options: SyncOptions,
        reply: &Arc<Reply>,
        deadline: tokio::time::Instant,
        projected: bool,
    ) -> Result<Option<Prepared>, CoordinationError> {
        self.check_waiter(reply, deadline)?;
        if options.workspace_bytes < 8_388_608 {
            return Err(workspace_error(
                &self.volume,
                8_388_608,
                options.workspace_bytes,
            ));
        }
        // With no in-flight completions, checkpoint marks now carry all admitted
        // payloads, so volatile eligibility may be discarded before the next seal.
        if self.local(|local| Ok(local.sync_queue_empty()))? {
            let mut state = self
                .state
                .lock()
                .map_err(|_| refused("SyncStatePoisoned"))?;
            self.local(|local| local.release_engine_graph(state.queue_charge))?;
            state.queue = SyncProjectionQueue::default();
            state.queue_charge = 0;
        }
        let Some((boundary, charge, workspace)) = self
            .seal_reserved(seal, options.workspace_bytes, projected)
            .await?
        else {
            return Ok(None);
        };
        let reserved = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?
            .queue
            .reserve(&boundary);
        if let Err(error) = reserved {
            self.dispose_unadmitted(&boundary, projected.then_some(charge))?;
            return Err(error.into());
        }
        self.state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?
            .preparing = Some((
            boundary.clone(),
            workspace.clone(),
            projected.then_some(charge),
            reply.clone(),
        ));
        let prepared = match self
            .prepare(&boundary, workspace.clone(), reply, deadline, projected)
            .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| refused("SyncStatePoisoned"))?;
                state.preparing = None;
                state.queue.fail(&boundary)?;
                drop(state);
                self.dispose_unadmitted(&boundary, projected.then_some(charge))?;
                return Err(error);
            }
        };
        self.state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?
            .preparing = None;
        Ok(Some(Prepared { charge, ..prepared }))
    }

    /// Reconcile a prepared registration, without admission. Its completion
    /// alone disposes of the seal: a failure no covering receipt completed
    /// first is persisted and answered here.
    async fn settle(
        self: &Arc<Self>,
        prepared: &Prepared,
        reply: &Arc<Reply>,
        deadline: tokio::time::Instant,
    ) -> Result<(), CoordinationError> {
        let request = &prepared.request;
        let generation = crate::writable_store::sync_engine::generation(request)?;
        let result = self.reconcile(request, reply, deadline).await;
        if let Err(error) = result {
            let _completion = self.completion.lock().await;
            // A concurrent covering receipt may already have completed this call.
            let retained = self
                .state
                .lock()
                .map_err(|_| refused("SyncStatePoisoned"))?
                .retained
                .remove(&generation);
            if let Some(retained) = retained {
                let failure = self.local(|local| {
                    local.fail_sync_registration(request, prepared.accepted.boundary())
                });
                failure?;
                #[cfg(test)]
                if std::mem::take(
                    &mut self
                        .state
                        .lock()
                        .map_err(|_| refused("SyncStatePoisoned"))?
                        .settle_refusal,
                ) {
                    return Err(refused("SyncInjectedFault"));
                }
                retained.reply.deliver(Err(error));
            }
        }
        Ok(())
    }

    /// Dispose of a seal no registration retained, and of a projected seal's
    /// lane reservations with it.
    fn dispose_unadmitted(
        &self,
        boundary: &SyncBoundary,
        projected: Option<u64>,
    ) -> Result<(), CoordinationError> {
        let failure = self.local(|local| local.fail_sync_preparation(boundary));
        if let Some(projected) = projected {
            self.local(|local| local.release_projected_commit(projected))?;
        }
        failure
    }

    /// Accept, sign and retain one seal's registration. A full acceptance
    /// also returns every id its binmap resolves.
    async fn prepare(
        self: &Arc<Self>,
        boundary: &SyncBoundary,
        workspace: Arc<WorkspaceLease>,
        reply: &Arc<Reply>,
        deadline: tokio::time::Instant,
        full: bool,
    ) -> Result<Prepared, CoordinationError> {
        let queue = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?
            .queue
            .clone();
        let (mut accepted, payloads) = self
            .accept_boundary(boundary, workspace.bytes, reply, deadline, &queue, full)
            .await?;
        let mapped = if full {
            let mapped = accepted
                .accepted
                .take_complete()
                .map_err(|_| refused("SyncCommitBinmap"))?;
            Some(Arc::new(mapped))
        } else {
            None
        };
        // Reserve retained carry-forward refs before copying them into the queue.
        let queue_charge = (boundary.files().len() as u64)
            .checked_mul(256)
            .and_then(|n| n.checked_add(512))
            .ok_or_else(|| refused("SyncGraphOverflow"))?;
        self.local(|local| local.reserve_engine_graph(queue_charge))?;
        let accepted = Arc::new(accepted);
        let signing = accepted.clone();
        let engine = self.clone();
        let signed = self
            .transaction(move |local| {
                local.sign_sync_registration(
                    &signing,
                    payloads,
                    &engine.key,
                    &engine.trusted,
                    engine.wall.as_ref(),
                )
            })
            .await;
        let (request, bytes) = match signed {
            Ok(signed) => signed,
            Err(error) => {
                self.local(|local| local.release_engine_graph(queue_charge))?;
                return Err(error);
            }
        };
        let generation = crate::writable_store::sync_engine::generation(&request)?;
        let input = accepted.projection().coverage_input(GrainId::of(&bytes));
        let mut state = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?;
        if let Err(error) = state.queue.admit(&accepted) {
            drop(state);
            self.local(|local| local.release_engine_graph(queue_charge))?;
            return Err(error.into());
        }
        state.queue_charge += queue_charge;
        state.retained.insert(
            generation,
            Retained {
                input,
                reply: reply.clone(),
                _workspace: workspace,
                request: request.clone(),
                boundary: boundary.clone(),
            },
        );
        state.preparing = None;
        Ok(Prepared {
            request,
            root: bytes,
            accepted,
            mapped,
            charge: 0,
        })
    }

    async fn accept_boundary(
        self: &Arc<Self>,
        boundary: &SyncBoundary,
        charge: u64,
        reply: &Arc<Reply>,
        deadline: tokio::time::Instant,
        queue: &SyncProjectionQueue,
        full: bool,
    ) -> Result<
        (
            crate::AcceptedSyncProjection,
            Vec<crate::VerifiedSyncPayload>,
        ),
        CoordinationError,
    > {
        self.fault("sync.capture", "after", boundary.id(), None, "none")
            .await?;
        let engine = self.clone();
        let boundary = boundary.clone();
        let reply = reply.clone();
        let queue = queue.clone();
        #[cfg(test)]
        let injection = crate::publish::shards::injection::capture();
        self.runtime
            .blocking_async(move || async move {
                #[cfg(test)]
                let _injected = injection();
                engine
                    .accept_boundary_inner(&boundary, charge, &reply, deadline, &queue, full)
                    .await
            })
            .await
            .map_err(|_| refused("SyncMaterializationLost"))?
    }

    fn materialized_manifest(
        &self,
        boundary: &SyncBoundary,
        charge: u64,
        reply: &Reply,
        deadline: tokio::time::Instant,
    ) -> Result<GrainId, CoordinationError> {
        let source = self.content.with_deadline(self.runtime.clone(), deadline);
        let (selection, _) = self.materialize(boundary, charge, reply, deadline, &source)?;
        self.check_waiter(reply, deadline)?;
        let budget = Budget::new(&source, charge, Some(boundary));
        budget.charge_as("effects", boundary.effects().len() * 256)?;
        let mut queue = SyncProjectionQueue::default();
        queue.reserve(boundary)?;
        let base = self
            .base
            .lock()
            .map_err(|_| refused("SyncBasePoisoned"))?
            .clone();
        let (manifest, nodes) = super::objects::commit_manifest(
            &queue,
            boundary,
            &selection,
            &base,
            &budget,
            |content| {
                let grains = source
                    .payload(content)
                    .map_err(|_| crate::PublishError::BadPlan)?;
                budget
                    .charge(grains.grain_count() as usize * 128)
                    .map_err(|error| budget.publication_error(error))?;
                Ok(grains)
            },
        )
        .map_err(|error| {
            self.content_error(
                preparation_error(error, budget.workspace_refused.load(Ordering::Acquire)),
                deadline,
            )
        })?;
        for bytes in nodes.values() {
            budget.charge_as("retain", bytes.len())?;
        }
        self.check_waiter(reply, deadline)?;
        Ok(manifest)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "bounded captured object preparation and closure acceptance share one budget"
    )]
    async fn accept_boundary_inner(
        self: &Arc<Self>,
        boundary: &SyncBoundary,
        charge: u64,
        reply: &Arc<Reply>,
        deadline: tokio::time::Instant,
        queue: &SyncProjectionQueue,
        full: bool,
    ) -> Result<
        (
            crate::AcceptedSyncProjection,
            Vec<crate::VerifiedSyncPayload>,
        ),
        CoordinationError,
    > {
        let source = self.content.with_deadline(self.runtime.clone(), deadline);
        let (selection, payloads) = self.materialize(boundary, charge, reply, deadline, &source)?;
        self.check_waiter(reply, deadline)?;
        let budget = Budget::new(&source, charge, Some(boundary));
        #[cfg(test)]
        let budget = self.observed_budget(budget, 1);
        // Charge the journal replayed since the base. The projection's own
        // retention is bounded by the overlay's declared graph charge, not here.
        budget.charge_as("effects", boundary.effects().len() * 256)?;
        let projection = queue.project(boundary, &selection.selected)?;
        if !boundary.complete_tree()
            && selection.selected.iter().any(|file| {
                !projection.entries().iter().any(|entry| {
                    entry.inode == file.inode
                        && entry.size == file.size
                        && entry.kind
                            == crate::OverlayKind::File {
                                content: Some(file.content),
                            }
                })
            })
        {
            return Err(refused("SyncSelectionUnrepresentable"));
        }
        // Authenticate only the payloads that are new since the base. Every
        // other file is a base entry that the verified base already covers.
        let mut grain_ids = std::collections::BTreeSet::new();
        for item in projection
            .changed_payloads()
            .iter()
            .map(|&(content, size)| source.payload(content).map(|grains| (grains, size)))
            .chain(selection.orphaned.iter().map(|(index, grains)| {
                Ok((
                    grains.clone(),
                    boundary
                        .files()
                        .get(*index)
                        .map_or(0, crate::CapturedFile::size),
                ))
            }))
        {
            let (grains, size) = item?;
            budget.charge(grains.grain_count() as usize * 128)?;
            let refs = crate::writable_store::capture::captured_refs(&budget, size, &grains)
                .map_err(|error| payload_failure(budget.payload_error(error)))?;
            grain_ids.extend(refs.into_iter().map(|r| r.id));
        }
        drop(projection);
        let remote = ObjectRemote {
            remote: self.remote.as_ref(),
            budget: &budget,
            reply,
            deadline,
            runtime: self.runtime.as_ref(),
            faults: &self.faults,
            capture: boundary.id(),
            metrics: &self.metrics,
            binmap_get_bytes: &self.binmap_get_bytes,
            refused_get_bytes: &self.refused_get_bytes,
            grain_ids,
        };
        let base = self
            .base
            .lock()
            .map_err(|_| refused("SyncBasePoisoned"))?
            .clone();
        let accepted = before_send(self.runtime.as_ref(), reply, deadline, async {
            if full {
                super::objects::accept_commit_projection(
                    queue,
                    boundary,
                    selection,
                    &base,
                    &self.trusted,
                    &budget,
                    |content| {
                        let grains = source
                            .payload(content)
                            .map_err(|_| crate::PublishError::BadPlan)?;
                        budget
                            .charge(grains.grain_count() as usize * 128)
                            .map_err(|error| budget.publication_error(error))?;
                        Ok(grains)
                    },
                    &remote,
                    self.wall.now(),
                    Policy::default(),
                    |error| budget.publication_error(error),
                )
                .await
            } else {
                accept_sync_projection(
                    queue,
                    boundary,
                    selection,
                    &base,
                    &self.trusted,
                    &budget,
                    |content| {
                        let grains = source
                            .payload(content)
                            .map_err(|_| crate::PublishError::BadPlan)?;
                        budget
                            .charge(grains.grain_count() as usize * 128)
                            .map_err(|error| budget.publication_error(error))?;
                        Ok(grains)
                    },
                    &remote,
                    self.wall.now(),
                    Policy::default(),
                    |error| budget.publication_error(error),
                )
                .await
            }
        })
        .await
        .and_then(|result| match result {
            Ok(accepted) => Ok(accepted),
            Err(error) => Err(self.content_error(
                {
                    #[cfg(any(test, feature = "overlay-fault-tests"))]
                    if budget.fault_refused.load(Ordering::Acquire) {
                        return Err(refused("SyncInjectedFault"));
                    }
                    preparation_error(error, budget.workspace_refused.load(Ordering::Acquire))
                },
                deadline,
            )),
        })
        .and_then(|accepted| {
            self.check_waiter(reply, deadline)?;
            for (id, bytes) in &accepted.nodes {
                budget.charge_as("retain", bytes.len())?;
                source.put_object(*id, bytes)?;
            }
            Ok(accepted)
        });
        #[cfg(test)]
        {
            *self
                .spend
                .lock()
                .map_err(|_| refused("SyncStatePoisoned"))? = budget
                .spent
                .lock()
                .map_err(|_| refused("SyncGraphPoisoned"))?
                .clone();
        }
        let accepted = accepted?;
        #[cfg(test)]
        {
            *self
                .binmap_work
                .lock()
                .map_err(|_| refused("SyncStatePoisoned"))? = accepted.binmap_work().clone();
        }
        Ok((accepted, payloads))
    }

    fn content_error(
        &self,
        error: CoordinationError,
        deadline: tokio::time::Instant,
    ) -> CoordinationError {
        let unavailable = matches!(
            error,
            CoordinationError::Overlay(OverlayError::ContentUnavailable)
                | CoordinationError::Recovery(crate::RecoveryError::Preparation(
                    crate::PublishError::Remote(
                        granary_core::rootstore::RootStoreError::Unavailable { .. }
                            | granary_core::rootstore::RootStoreError::Elapsed { .. }
                    )
                ))
        );
        if unavailable && self.runtime.now() >= deadline {
            refused("SyncDeadline")
        } else {
            error
        }
    }

    fn materialize(
        &self,
        boundary: &SyncBoundary,
        charge: u64,
        reply: &Reply,
        deadline: tokio::time::Instant,
        source: &impl SyncContent,
    ) -> Result<(SyncObjectSelection, Vec<crate::VerifiedSyncPayload>), CoordinationError> {
        let mut selection = SyncObjectSelection::default();
        let mut payloads = Vec::new();
        let mut budget = Budget::new(source, charge, Some(boundary));
        #[cfg(test)]
        {
            budget = self.observed_budget(budget, 0);
        }
        for (index, captured) in boundary.files().iter().enumerate() {
            budget.file = Some(captured);
            self.check_waiter(reply, deadline)?;
            let checkpoint = captured
                .checkpoint()
                .map(|(content, _)| source.payload(content))
                .transpose()?;
            let output = rechunk_captured(
                captured,
                checkpoint.as_ref(),
                &budget,
                |offset, n| {
                    self.check_waiter(reply, deadline)?;
                    self.read_range(boundary, index, offset, n, source)
                },
                |id, bytes| {
                    self.check_waiter(reply, deadline)?;
                    budget.charge(bytes.len())?;
                    source.put_object(id, bytes)
                },
                &self.metrics,
            )
            .map_err(|error| budget.payload_error(error))?;
            source.remember_payload(output.content, captured.size(), &output.grains)?;
            if let Some(entry) = captured.entry() {
                selection.selected.push(DurableFile {
                    inode: entry.inode,
                    size: captured.size(),
                    content: output.content,
                    content_boundary: boundary.through_seq(),
                });
            } else {
                selection.orphaned.insert(index, output.grains.clone());
            }
            let mut verifier =
                self.local(|local| local.begin_sync_payload(boundary, index, output.grains))?;
            let result = (|| {
                verifier.authenticate(source)?;
                let mut offset = 0;
                while offset < captured.size() {
                    self.check_waiter(reply, deadline)?;
                    let range = self.local(|local| {
                        local.overlay_transaction(|t| t.captured_range(boundary, index, offset))
                    })?;
                    verifier.consume(range, source, &mut Immutable(source))?;
                    offset += (captured.size() - offset).min(65_536);
                }
                Ok::<_, CoordinationError>(())
            })();
            if let Err(error) = result {
                self.local(|local| local.abandon_sync_payload(boundary, verifier))?;
                return Err(self.content_error(payload_failure(error), deadline));
            }
            payloads.push(self.local(|local| local.finish_sync_payload(boundary, verifier))?);
        }
        Ok((selection, payloads))
    }

    fn read_range(
        &self,
        boundary: &SyncBoundary,
        index: usize,
        offset: u64,
        length: usize,
        source: &impl SyncContent,
    ) -> Result<Vec<u8>, CoordinationError> {
        let file = boundary
            .files()
            .get(index)
            .ok_or_else(|| refused("SyncFileIndex"))?;
        let mut out = Vec::with_capacity(length);
        let mut at = offset;
        while out.len() < length {
            let aligned = at / 65_536 * 65_536;
            let parts = self.local(|local| {
                local.overlay_transaction(|t| t.captured_parts(boundary, file, aligned))
            })?;
            let mut block = Vec::new();
            for part in parts {
                match part {
                    crate::CapturedPart::Dirty {
                        bytes,
                        start,
                        length,
                    } => block.extend_from_slice(
                        bytes
                            .get(start..start + length)
                            .ok_or_else(|| refused("SyncRange"))?,
                    ),
                    crate::CapturedPart::Zero(n) => block.resize(block.len() + n, 0),
                    crate::CapturedPart::Immutable {
                        content,
                        offset,
                        length,
                    } => {
                        let bytes = match source.read_content(content, offset, length) {
                            Ok(bytes) => bytes,
                            Err(OverlayError::Refused("SyncDeadline")) => {
                                return Err(refused("SyncDeadline"));
                            }
                            Err(error) => return Err(error.into()),
                        };
                        if bytes.len() != length {
                            return Err(refused("SyncRange"));
                        }
                        block.extend(bytes);
                    }
                }
            }
            let start = usize::try_from(at - aligned).map_err(|_| refused("SyncRange"))?;
            let bytes = block.get(start..).ok_or_else(|| refused("SyncRange"))?;
            let n = bytes.len().min(length - out.len());
            if n == 0 {
                return Err(refused("SyncRange"));
            }
            out.extend_from_slice(bytes.get(..n).ok_or_else(|| refused("SyncRange"))?);
            at += n as u64;
        }
        Ok(out)
    }

    /// Wait for dispatch admission. Returns false for an answered registration.
    async fn dispatch_after_backoff(
        self: &Arc<Self>,
        request: &PendingIntent,
        deadline: tokio::time::Instant,
        first_waiter: Option<&Reply>,
    ) -> Result<bool, CoordinationError> {
        let mut delay = self.local(|local| local.retry_delay(request, self.wall.as_ref()))?;
        loop {
            self.runtime
                .timeout_at(deadline, self.runtime.sleep(delay))
                .await
                .map_err(|_| refused("SyncDeadline"))?;
            if self.runtime.now() >= deadline {
                return Err(refused("SyncDeadline"));
            }
            if let Some(reply) = first_waiter {
                self.check_waiter(reply, deadline)?;
            }
            let dispatch = request.clone();
            let engine = self.clone();
            let admission = self
                .transaction(move |local| {
                    if dispatch.operation() == Operation::Register
                        && local.sync_request_answered(&dispatch)?
                    {
                        return Ok(Break(false));
                    }
                    local
                        .dispatch_inner(&dispatch, engine.wall.as_ref(), false)
                        .map(|residual| residual.map_or(Break(true), Continue))
                })
                .await?;
            match admission {
                Break(dispatched) => return Ok(dispatched),
                Continue(residual) => {
                    delay = Duration::from_millis(
                        residual.max(crate::writable_store::MIN_RETRY_WAIT_MS),
                    );
                }
            }
        }
    }

    /// Reconcile a retained registration under the original monotonic deadline.
    /// When admission finds a retry still early, wait at least 10 ms or the
    /// remaining wall-clock delay, whichever is longer, without spending an
    /// attempt. On each wake, check the deadline and the first attempt's waiter.
    async fn reconcile(
        self: &Arc<Self>,
        request: &PendingIntent,
        reply: &Reply,
        deadline: tokio::time::Instant,
    ) -> Result<(), CoordinationError> {
        let capture = self
            .state
            .lock()
            .map_err(|_| refused("SyncStatePoisoned"))?
            .retained
            .get(&crate::writable_store::sync_engine::generation(request)?)
            .map_or(0, |retained| retained.boundary.id());
        for attempt in 0..crate::STARTUP_ATTEMPTS {
            if attempt == 0 {
                self.check_waiter(reply, deadline)?;
            }
            if self.local(|local| local.sync_request_answered(request))?
                || !self
                    .dispatch_after_backoff(request, deadline, (attempt == 0).then_some(reply))
                    .await?
            {
                return self.drain_completions(deadline).await;
            }
            self.fault(
                "sync.registration",
                "before_dispatch",
                capture,
                Some(GrainId::of(request.bytes())),
                "none",
            )
            .await?;
            let start = self.monotonic.start();
            let response = self
                .runtime
                .timeout_at(deadline, self.remote.register_once(request, &self.trusted))
                .await
                .unwrap_or(Err(IntentTransportError::Deadline));
            let elapsed = start
                .as_ref()
                .and_then(|start| self.monotonic.elapsed(start));
            self.fault(
                "sync.registration",
                "after_response",
                capture,
                Some(GrainId::of(request.bytes())),
                "none",
            )
            .await?;
            if elapsed.is_none() {
                crate::observe::OperatorDiagnostic::sync_registration_timing_sample_unavailable()
                    .emit();
            }
            let retry_after = response
                .as_ref()
                .ok()
                .and_then(IntentReply::retry_after)
                .and_then(|value| value.parse::<u64>().ok())
                .and_then(|secs| secs.checked_mul(1000))
                .unwrap_or(0);
            let completing = request.clone();
            let engine = self.clone();
            let completed = self
                .transaction(move |local| {
                    local.complete(
                        &completing,
                        response.as_ref().map_err(|error| *error),
                        engine.wall.as_ref(),
                        &mut RuntimeRng(engine.runtime.as_ref()),
                        retry_after,
                        elapsed,
                    )
                })
                .await?;
            if !matches!(completed, IntentCompletion::Unknown) {
                return self.drain_completions(deadline).await;
            }
        }
        Err(refused("IntentStartupAttemptsExhausted"))
    }

    /// Settle a failed caller's retained registration, with a reply of the
    /// engine's own, under `deadline`.
    /// # Errors
    /// As a registration's reconciliation.
    pub(crate) async fn settle_registration(
        self: &Arc<Self>,
        request: &PendingIntent,
        deadline: tokio::time::Instant,
    ) -> Result<(), CoordinationError> {
        let reply = Reply {
            sender: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            cancellation: Notify::new(),
            metrics: self.metrics.clone(),
            observed: false,
        };
        self.reconcile(request, &reply, deadline).await
    }

    /// Retain this mount's Release, expiring within `bound` and at
    /// `deadline`, the latter as the engine's wall clock reads it now.
    /// # Errors
    /// As [`WritableStore::prepare_release`].
    pub(crate) async fn prepare_release(
        self: &Arc<Self>,
        bound: Duration,
        deadline: tokio::time::Instant,
    ) -> Result<PendingIntent, CoordinationError> {
        let remaining = deadline.saturating_duration_since(self.runtime.now());
        let engine = self.clone();
        self.transaction(move |local| {
            local.prepare_release_within(engine.wall.as_ref(), bound, remaining)
        })
        .await
    }

    /// Send a retained Release until it is answered, under `deadline`.
    /// Unlike a registration's reconciliation there is no attempt cap: the
    /// request's own expiry and `deadline` bound it. If retry admission is
    /// early, wait at least 10 ms or the remaining wall-clock delay, whichever
    /// is longer, without spending an attempt. Check the deadline on wake.
    /// If dispatch or completion finds the retry horizon expired, wait out
    /// `deadline` so a Release never answered ends at the deadline.
    /// # Errors
    /// The deadline, a fence, a refusal or local persistence, paired with
    /// whether [`WritableStore::complete`] emitted its `op.failed` event.
    pub(crate) async fn release(
        self: &Arc<Self>,
        request: &PendingIntent,
        deadline: tokio::time::Instant,
    ) -> Result<(), (CoordinationError, bool)> {
        let expired = loop {
            match self.dispatch_after_backoff(request, deadline, None).await {
                Ok(_) => {}
                Err(error @ CoordinationError::Refused("IntentRetryDeadline")) => {
                    break (error, false);
                }
                Err(error) => return Err((error, false)),
            }
            let response = self
                .runtime
                .timeout_at(deadline, self.remote.release_once(request))
                .await
                .unwrap_or(Err(IntentTransportError::Deadline));
            let retry_after = response
                .as_ref()
                .ok()
                .and_then(IntentReply::retry_after)
                .and_then(|value| value.parse::<u64>().ok())
                .and_then(|secs| secs.checked_mul(1000))
                .unwrap_or(0);
            let completing = request.clone();
            let engine = self.clone();
            let completed = self
                .transaction(move |local| {
                    Ok(local.complete_reported(
                        &completing,
                        response.as_ref().map_err(|error| *error),
                        engine.wall.as_ref(),
                        &mut RuntimeRng(engine.runtime.as_ref()),
                        retry_after,
                        None,
                    ))
                })
                .await
                .map_err(|error| (error, false))?;
            match completed {
                Ok(IntentCompletion::Unknown) => {}
                Ok(_) => return Ok(()),
                Err((error @ CoordinationError::Refused("IntentRetryDeadline"), reported)) => {
                    break (error, reported);
                }
                Err(error) => return Err(error),
            }
        };
        let _ = self
            .runtime
            .timeout_at(deadline, std::future::pending::<()>())
            .await;
        Err(expired)
    }

    async fn drain_completions(
        self: &Arc<Self>,
        deadline: tokio::time::Instant,
    ) -> Result<(), CoordinationError> {
        let _completion = self.completion.lock().await;
        while let Some(work) = self.local(|local| local.capture_completion_work())? {
            let inputs = self
                .state
                .lock()
                .map_err(|_| refused("SyncStatePoisoned"))?
                .retained
                .values()
                .map(|retained| (retained.input.prepared_root, retained.input.clone()))
                .collect();
            let engine = self.clone();
            let plan = self
                .runtime
                .blocking(move || {
                    let content = engine
                        .content
                        .with_deadline(engine.runtime.clone(), deadline);
                    work.validate(&inputs, &content)
                })
                .await
                .map_err(|_| refused("SyncMaterializationLost"))??;
            let completed = self
                .transaction(move |local| local.apply_capture_completions(plan))
                .await?;
            for completion in completed {
                let retained = self
                    .state
                    .lock()
                    .map_err(|_| refused("SyncStatePoisoned"))?
                    .retained
                    .remove(&completion.generation)
                    .ok_or_else(|| refused("SyncCompletionBinding"))?;
                let mut result = completion.result.map_err(CoordinationError::from);
                if let Err(error) = self
                    .fault(
                        "sync.reply",
                        "before",
                        retained.boundary.id(),
                        Some(GrainId::of(retained.request.bytes())),
                        "none",
                    )
                    .await
                {
                    result = Err(error);
                }
                retained.reply.deliver(result);
            }
        }
        Ok(())
    }

    async fn fail_supervisor(&self, reply: &Arc<Reply>) -> Result<(), CoordinationError> {
        let _wake = FloorWake(&self.floor_changed);
        let _completion = self.completion.lock().await;
        let (preparing, retained) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| refused("SyncStatePoisoned"))?;
            let preparing = if state
                .preparing
                .as_ref()
                .is_some_and(|(_, _, _, waiting)| Arc::ptr_eq(reply, waiting))
            {
                state.preparing.take()
            } else {
                None
            };
            let generation = state.retained.iter().find_map(|(generation, retained)| {
                Arc::ptr_eq(&retained.reply, reply).then_some(*generation)
            });
            let retained = generation.and_then(|generation| state.retained.remove(&generation));
            if let Some((boundary, _, _, _)) = &preparing {
                state.queue.fail(boundary)?;
            }
            (preparing, retained)
        };
        if let Some((boundary, _workspace, projected, _)) = preparing {
            self.dispose_unadmitted(&boundary, projected)?;
        }
        if let Some(retained) = retained {
            let failure = self
                .local(|local| local.fail_sync_registration(&retained.request, &retained.boundary));
            failure?;
        }
        Ok(())
    }
}

mod commit;
#[cfg(test)]
pub(crate) use commit::Resumed;
pub(crate) use commit::{
    CommitDrive, RuntimeSeams, build_landed_entries, commit_send_budget, terminal_non_landing,
};
pub use commit::{LiveEnd, RetainedCommit};
