// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Ordered writable admission, with a single owned signer and one-use attachment.

// @file-disposition: STAYS — admission and the writable backend share the owned signer and one-use attachment invariant; shutdown finishing and sync execution live in child modules.

use crate::SyncRuntime as _;
use crate::authority_transport::{AuthorityError, StatusRefusal, StatusResponse};
use crate::mount::MountMetrics;
use crate::observe::{self, FailureClass, OperationKind};
use crate::{
    Cache, CacheOrigin, CoordinationError, FaultControl, HttpStore, IntentCompletion, IntentReply,
    IntentTransportError, MountError, MountOptions, MountSession, OverlayConfig, OverlayEntry,
    OverlayError, OverlayIo, OverlayKind, PendingIntent, SharedWritableStore, Store, WritableStore,
};
use granary_core::{
    binstore::BinStore,
    clock::Clock,
    hash::GrainId,
    intent::{self, Verdict},
    overlay_journal::JournalHeader,
    overlay_ownership::{Operation, Phase},
    retained_submission::Scope,
    rng::Rng,
    root::{self, RootDoc, RootSig, VolumeName},
    rootstore::RootStore,
    secure_random::SecureRandom,
};
use granary_store::crypto::{self, SigningKey};
use std::path::Path;

mod finish;
#[cfg(test)]
pub(crate) use finish::{
    FinishFault, FinishHooks, finish_hooks_for_test, finish_report_for_test,
    late_local_work_for_test,
};
pub(crate) mod shared_finish;
#[cfg(test)]
pub(crate) use shared_finish::finish_future_sizes_for_test;
mod sync;
pub(crate) use sync::AdoptionWalk;
#[cfg(test)]
pub(crate) use sync::{
    GateAction, GateOutcome, KernelTime, Projected, ViewGate, ViewInstallError, adoption_verdict,
    rebuild_verdict, rebuild_view, send_revocation,
};
pub use sync::{MountSyncContent, ViewBinding, ViewMode, sync_mount_error};

/// The caller's one process-credential snapshot; presentation uid/gid are separate.
#[derive(Debug, Clone, Copy)]
pub struct WritableProcess {
    pub ruid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub set_id_tainted: bool,
}

/// What a writable mount's successful file or directory sync, or synchronous
/// write, has made true when it answers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SyncProfile {
    /// The synced bytes are registered with the authority; a later commit
    /// publishes them.
    #[default]
    DurablePrepared,
    /// The sync answers only on its own publication, landed and installed
    /// as the mount's view.
    Published,
}

/// Raw admission operands. The local loader runs only after posture validation.
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent raw trust, foreground, force and floor-reset operands"
)]
pub struct WritableStart<'a> {
    pub volume: VolumeName,
    pub process: WritableProcess,
    pub foreground: bool,
    pub force: bool,
    pub mountpoint: &'a Path,
    pub root_key: Option<[u8; 32]>,
    pub manifest_root: Option<GrainId>,
    pub trust_server: bool,
    pub options: MountOptions,
    pub seq: Option<u64>,
    pub seed: Option<&'a Path>,
    pub certificate: Option<&'a Path>,
    pub credential_key: Option<&'a Path>,
    pub scope: Option<Scope>,
    pub store: Option<&'a Path>,
    pub cache: Option<&'a Path>,
    pub cache_origin: CacheOrigin,
    pub cache_quota: u64,
    pub contention_threshold: crate::ContentionThreshold,
    pub construction_workspace_bytes: u64,
    pub overlay_cap_bytes: u64,
    pub reset_floor: bool,
    pub policy: granary_vfs::AttrPolicy,
    pub euid: u32,
    pub sync_profile: SyncProfile,
    pub view: ViewMode,
}

/// Closed startup diagnostics; no input path, response body or key is formatted.
#[derive(Debug)]
pub enum WritableStartError {
    Refused(&'static str, FailureClass),
    ReadView(MountError),
    Coordination(CoordinationError),
}
impl WritableStartError {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Refused(name, _)
            | Self::Coordination(
                CoordinationError::Refused(name)
                | CoordinationError::Overlay(OverlayError::Refused(name))
                | CoordinationError::Codec(granary_core::overlay_ownership::Error(name)),
            ) => name,
            Self::ReadView(MountError::NoTrustMode) => "NoTrustMode",
            Self::ReadView(MountError::ConflictingTrustModes) => "ConflictingTrustModes",
            Self::ReadView(MountError::StaleHead { .. }) => "StaleHead",
            Self::ReadView(MountError::CachedRootEquivocation { .. }) => "CachedRootEquivocation",
            Self::ReadView(MountError::DegradedCacheRefused) => "DegradedCacheRefused",
            Self::ReadView(MountError::Resolve(crate::ResolveError::NoHead)) => "NoHead",
            Self::ReadView(MountError::Anchor(_)) => "ZeroKey",
            Self::ReadView(MountError::ReservedSeqCandidate { .. }) => "ReservedSeqCandidate",
            Self::ReadView(MountError::FloorNotPersisted { .. }) => "FloorNotPersisted",
            Self::ReadView(MountError::Resolve(crate::ResolveError::BadSignature { .. })) => {
                "BadSignature"
            }
            Self::ReadView(MountError::Resolve(crate::ResolveError::UnknownSigner { .. })) => {
                "UnknownSigner"
            }
            Self::ReadView(_) => "WritableReadViewRefused",
            Self::Coordination(CoordinationError::Fenced { .. }) => "IntentFenced (ESTALE)",
            Self::Coordination(_) => "WritableRecoveryRequired",
        }
    }
    #[must_use]
    pub fn class(&self) -> FailureClass {
        match self {
            Self::Refused(_, class) => *class,
            Self::Coordination(error) => coordination_class(error),
            Self::ReadView(
                MountError::Runtime(_) | MountError::Resolve(crate::ResolveError::Remote(_)),
            ) => FailureClass::Unavailable,
            Self::ReadView(MountError::Cache(_) | MountError::FloorNotPersisted { .. }) => {
                FailureClass::Io
            }
            Self::ReadView(MountError::Resolve(crate::ResolveError::NoHead)) => {
                FailureClass::Refused
            }
            Self::ReadView(MountError::Resolve(_)) => FailureClass::Corrupt,
            Self::ReadView(_) => FailureClass::Refused,
        }
    }
}

/// The closed class a coordination refusal reports under.
#[expect(
    clippy::match_same_arms,
    reason = "recorded refusal names keep their failure-class mappings explicit"
)]
pub(crate) fn coordination_class(error: &CoordinationError) -> FailureClass {
    match error {
        CoordinationError::Refused(
            "IntentRetryDeadline"
            | "IntentRetryNotEligible"
            | "IntentStartupAttemptsExhausted"
            | "IntentEntropyUnavailable"
            | "IntentClockDomainChanged"
            | "RecoveryResidualUnavailable"
            | "SyncDeadline",
        )
        | CoordinationError::Overlay(OverlayError::ContentUnavailable) => FailureClass::Unavailable,
        CoordinationError::Overlay(OverlayError::Io(_) | OverlayError::Poisoned)
        | CoordinationError::Publication(crate::PublicationStoreError {
            kind: crate::PublicationStoreErrorKind::Io,
            ..
        })
        | CoordinationError::Refused(
            "IntentPersistencePoisoned" | "IntentCapExhausted" | "RecoveryResidualWorkspace",
        ) => FailureClass::Io,
        CoordinationError::Fenced { .. }
        | CoordinationError::CommitFenced { .. }
        | CoordinationError::Refused(
            "IntentSelectionChanged" | "IntentCursorChanged" | "IntentTokenDisplaced",
        ) => FailureClass::Conflict,
        CoordinationError::Overlay(
            OverlayError::NoSpace | OverlayError::Refused("OverlayCapacityExhausted"),
        ) => FailureClass::Refused,
        CoordinationError::Overlay(OverlayError::ContentCorrupt)
        | CoordinationError::Codec(_)
        | CoordinationError::Refused(
            "IntentPreparedRoot"
            | "IntentPreparedSignature"
            | "IntentPendingSignature"
            | "IntentCarrierChanged"
            | "IntentLandedReplayInvalid"
            | "WritableIntentDiscoveryInvalid",
        ) => FailureClass::Corrupt,
        CoordinationError::Refused("IntentExpiredRegisterUnresolved") => FailureClass::Refused,
        _ => FailureClass::Refused,
    }
}
impl std::fmt::Display for WritableStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Self::Coordination(error @ CoordinationError::CommitFenced { .. }) = self {
            return error.fmt(f);
        }
        f.write_str(self.name())
    }
}
impl std::error::Error for WritableStartError {}
impl From<CoordinationError> for WritableStartError {
    fn from(error: CoordinationError) -> Self {
        Self::Coordination(error)
    }
}
fn refusal(name: &'static str) -> WritableStartError {
    WritableStartError::Refused(name, FailureClass::Refused)
}
fn invalid(name: &'static str) -> WritableStartError {
    WritableStartError::Refused(name, FailureClass::Corrupt)
}
fn unavailable(name: &'static str) -> WritableStartError {
    WritableStartError::Refused(name, FailureClass::Unavailable)
}

fn check_rails(input: &WritableStart<'_>, linux: bool) -> Result<(), WritableStartError> {
    if input.process.set_id_tainted
        || input.process.ruid != input.euid
        || input.process.rgid != input.process.egid
    {
        return Err(refusal("SetIdExecution"));
    }
    if !input.foreground {
        return Err(refusal("ForegroundRefused"));
    }
    if !linux {
        return Err(refusal("WritablePlatformUnsupported"));
    }
    if input.mountpoint.file_name().is_none() {
        return Err(refusal("MountpointComponentRefused"));
    }
    let metadata = std::fs::symlink_metadata(input.mountpoint).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            refusal("MountpointNotFound")
        } else {
            WritableStartError::Refused("MountpointIo", FailureClass::Io)
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err(refusal("MountpointSymlink"));
    }
    if !metadata.is_dir() {
        return Err(refusal("MountpointNotDirectory"));
    }
    #[cfg(target_os = "linux")]
    check_mount_table(input.mountpoint)?;
    if !input.force {
        check_empty_mountpoint(input.mountpoint)?;
    }
    Ok(())
}
#[expect(
    clippy::disallowed_methods,
    reason = "enumerate only the mountpoint already checked as a real directory, before key or network I/O"
)]
fn check_empty_mountpoint(path: &Path) -> Result<(), WritableStartError> {
    match std::fs::read_dir(path)
        .map_err(|_| WritableStartError::Refused("MountpointIo", FailureClass::Io))?
        .next()
    {
        None => Ok(()),
        Some(Ok(_)) => Err(refusal("MountpointNotEmpty")),
        Some(Err(_)) => Err(WritableStartError::Refused(
            "MountpointIo",
            FailureClass::Io,
        )),
    }
}
#[cfg(target_os = "linux")]
#[expect(
    clippy::disallowed_methods,
    reason = "resolve only the mountpoint's ordinary parent for a bounded mount-table comparison; never traverse the possibly mounted leaf"
)]
fn check_mount_table(path: &Path) -> Result<(), WritableStartError> {
    use std::io::Read as _;
    use std::os::unix::ffi::OsStrExt as _;
    let target = if let Some(name) = path.file_name() {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::canonicalize(parent)
            .map_err(|_| refusal("MountpointIo"))?
            .join(name)
    } else {
        path.to_owned()
    };
    let mut bytes = Vec::new();
    crate::open_regular_read(Path::new("/proc/self/mountinfo"))
        .map_err(|_| refusal("MountTableUnavailable"))?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refusal("MountTableUnavailable"))?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(refusal("MountTableTooLarge"));
    }
    for row in bytes
        .split(|byte| *byte == b'\n')
        .filter(|row| !row.is_empty())
    {
        let field = row
            .split(|byte| *byte == b' ')
            .nth(4)
            .ok_or_else(|| invalid("MountTableInvalid"))?;
        let mut decoded = Vec::new();
        let mut cursor = field.iter().copied();
        while let Some(byte) = cursor.next() {
            if byte == b'\\' {
                let digits = [cursor.next(), cursor.next(), cursor.next()];
                let value = match digits {
                    [Some(b'0'), Some(b'4'), Some(b'0')] => b' ',
                    [Some(b'0'), Some(b'1'), Some(b'1')] => b'\t',
                    [Some(b'0'), Some(b'1'), Some(b'2')] => b'\n',
                    [Some(b'1'), Some(b'3'), Some(b'4')] => b'\\',
                    _ => return Err(invalid("MountTableInvalid")),
                };
                decoded.push(value);
            } else {
                decoded.push(byte);
            }
        }
        if decoded == target.as_os_str().as_bytes() {
            return Err(refusal("MountpointAlreadyMounted"));
        }
    }
    Ok(())
}

impl WritableStart<'_> {
    /// Enforces trust, sharing and selector precedence before any loader or request.
    /// # Errors
    /// The first named admission refusal.
    pub fn check_posture(&self) -> Result<[u8; 32], WritableStartError> {
        let count = [
            self.root_key.is_some(),
            self.manifest_root.is_some(),
            self.trust_server,
        ]
        .into_iter()
        .filter(|given| *given)
        .count();
        if count == 0 {
            return Err(WritableStartError::ReadView(MountError::NoTrustMode));
        }
        if count > 1 {
            return Err(WritableStartError::ReadView(
                MountError::ConflictingTrustModes,
            ));
        }
        if self.trust_server {
            return Err(refusal("WritableTrustServerRefused"));
        }
        if self.manifest_root.is_some() {
            return Err(refusal("WritableManifestRootRefused"));
        }
        if self.options.allow_other {
            return Err(refusal("WritableAllowOtherRefused"));
        }
        if self.options.allow_root {
            return Err(refusal("WritableAllowRootRefused"));
        }
        if self.seq.is_some() {
            return Err(refusal("WritableSeqRefused"));
        }
        self.root_key.ok_or_else(|| refusal("NoTrustMode"))
    }
}

/// Single-attempt authority operations; startup owns retained retries and waits.
#[expect(
    async_fn_in_trait,
    reason = "status is awaited inline; deadline-bounded operations state their Send contract"
)]
pub trait WritableAuthority: RootStore + BinStore + MountMetrics + Send {
    /// A transport facade for a distinct runtime ownership domain.
    #[must_use]
    fn read_facade(&self) -> Self;
    /// # Errors
    /// Checked status or transport failure.
    async fn writable_status(&self, volume: &VolumeName) -> Result<StatusResponse, AuthorityError>;
    /// # Errors
    /// Bounded authenticated readback failure.
    fn writable_readback(
        &self,
        scope: &Scope,
        volume: &VolumeName,
        public: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<IntentReply, IntentTransportError>> + Send;
    /// # Errors
    /// One retained request's uncertain transport outcome.
    fn writable_send(
        &self,
        scope: &Scope,
        request: &PendingIntent,
        public: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<IntentReply, IntentTransportError>> + Send;
    fn writable_wait(&self, milliseconds: u64) -> impl std::future::Future<Output = ()> + Send;
}
fn verifies(public: &[u8; 32], doc: &RootDoc, prefix: &[u8]) -> bool {
    doc.sigs.iter().any(|sig| {
        sig.key_id == crypto::key_id(public) && crypto::verify(public, prefix, &sig.sig).is_ok()
    })
}
impl WritableAuthority for HttpStore {
    fn read_facade(&self) -> Self {
        self.writable_read_facade()
    }
    async fn writable_status(&self, volume: &VolumeName) -> Result<StatusResponse, AuthorityError> {
        self.status_once(volume.as_str()).await
    }
    async fn writable_readback(
        &self,
        scope: &Scope,
        volume: &VolumeName,
        public: &[u8; 32],
    ) -> Result<IntentReply, IntentTransportError> {
        self.intent_readback_once(scope, volume, |doc, prefix| verifies(public, doc, prefix))
            .await
    }
    async fn writable_send(
        &self,
        scope: &Scope,
        request: &PendingIntent,
        public: &[u8; 32],
    ) -> Result<IntentReply, IntentTransportError> {
        match request.operation() {
            Operation::Ownership => {
                let decoded = intent::decode_ownership(request.bytes())
                    .map_err(|_| IntentTransportError::InvalidRequest)?;
                if matches!(decoded.mode, intent::OwnershipMode::Acquire { .. }) {
                    self.intent_acquire_once(scope, request.volume(), request.bytes())
                        .await
                } else {
                    self.intent_takeover_once(scope, request.volume(), request.bytes())
                        .await
                }
            }
            Operation::Register => {
                self.intent_register_once(
                    scope,
                    request.volume(),
                    request.bytes(),
                    |doc, prefix| verifies(public, doc, prefix),
                )
                .await
            }
            Operation::Release => {
                self.intent_release_once(scope, request.volume(), request.bytes())
                    .await
            }
        }
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "production waiting adapter for persisted coordinator eligibility; deterministic authorities advance their supplied Clock instead"
    )]
    async fn writable_wait(&self, milliseconds: u64) {
        tokio::time::sleep(std::time::Duration::from_millis(milliseconds)).await;
    }
}

// This handle deliberately has neither Clone nor Debug. The signer is never reread.
struct CheckedSigner {
    key: Option<SigningKey>,
    public: [u8; 32],
}

/// Opaque admission proof. Moving its mediator seals minting to one store instance.
/// ```compile_fail
/// fn duplicate<R: Clone, P: granary_client::OverlayIo + Clone>(proof: granary_client::WritableReadiness<R, P>) {
///     let _ = proof.clone();
/// }
/// ```
#[expect(
    missing_debug_implementations,
    reason = "readiness owns the private signer; no Debug carriage"
)]
pub struct WritableReadiness<R, P: OverlayIo> {
    mount: WritableMount<R, P>,
    snapshot: granary_vfs::Snapshot,
    base: (VolumeName, u64, GrainId),
    owner: ([u8; 16], u64, [u8; 16]),
    mountpoint: std::path::PathBuf,
}
/// Attached backend retains shared mediator ownership and holds the checked signer
/// until attachment hands the signing key to the engine.
#[expect(
    missing_debug_implementations,
    reason = "backend owns the private signer; no Debug carriage"
)]
pub struct WritableMount<R, P: OverlayIo> {
    session: MountSession<R>,
    mediator: SharedWritableStore<P>,
    signer: CheckedSigner,
    owner: ([u8; 16], u64, [u8; 16]),
    view_state: sync::MountViewState,
    view_binding: Option<ViewBinding<R, P>>,
    /// Where the adapter looks for other writers' heads, once an engine is
    /// attached.
    view_boundary: Option<std::sync::Arc<dyn granary_fuse::ViewBoundary>>,
    sync_profile: SyncProfile,
    view: ViewMode,
    live_driver: bool,
    #[cfg(test)]
    live_options: crate::SyncOptions,
    sync_jobs: Option<sync::SyncJobs<P>>,
    shrink_jobs: Option<sync::ShrinkJobs<P>>,
    /// The attached engine's shutdown, which this backend's own runs.
    shutdown: Option<std::sync::Arc<dyn crate::sync::MountShutdown>>,
    /// The bound the attached engine's shutdown runs under.
    shutdown_bound: std::time::Duration,
    objects: std::collections::BTreeMap<u64, OpenObject>,
    completion_tokens: CompletionTokens,
    #[cfg(test)]
    pub(crate) planning_changes_remaining: usize,
    #[cfg(test)]
    pub(crate) planning_attempts: usize,
    #[cfg(test)]
    pub(crate) materialization_passes: usize,
    #[cfg(test)]
    pub(crate) planning_work_boundaries: Vec<crate::overlay_store::work::QueryWork>,
    #[cfg(test)]
    pub(crate) planning_replace: bool,
    #[cfg(test)]
    pub(crate) planning_move: Option<Vec<granary_core::manifest::Name>>,
    #[cfg(test)]
    pub(crate) setattr_release_after_effect: bool,
    #[cfg(test)]
    #[expect(clippy::type_complexity, reason = "test-only planning hook")]
    pub(crate) planning_hook: Option<Box<dyn FnMut(&SharedWritableStore<P>) + Send>>,
    #[cfg(test)]
    #[expect(
        clippy::type_complexity,
        reason = "test-only landing between view check and effect"
    )]
    pub(crate) after_view_hook: Option<Box<dyn FnMut(&SharedWritableStore<P>) + Send>>,
    #[cfg(test)]
    #[expect(clippy::type_complexity, reason = "test-only pre-materialization hook")]
    pub(crate) before_materialize_hook: Option<Box<dyn FnMut(&SharedWritableStore<P>) + Send>>,
}
const COMPLETION_TOKENS: usize = 1024;

#[cfg(test)]
std::thread_local! {
    static PREPARATION_WORK: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

#[cfg(any(test, feature = "overlay-fault-tests"))]
std::thread_local! {
    static START_FAULTS: std::cell::RefCell<Option<FaultControl>> = const { std::cell::RefCell::new(None) };
}

/// Make the next start on this thread open its store with `faults`.
#[cfg(any(test, feature = "overlay-fault-tests"))]
pub fn start_faults_for_test(faults: FaultControl) {
    START_FAULTS.set(Some(faults));
}

/// The fault control a start opens its store with.
fn start_faults() -> FaultControl {
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    if let Some(faults) = START_FAULTS.take() {
        return faults;
    }
    FaultControl::default()
}

#[cfg(test)]
pub(crate) fn measure_preparation<T>(action: impl FnOnce() -> T) -> (T, (usize, usize)) {
    let before = PREPARATION_WORK.get();
    let answer = action();
    let after = PREPARATION_WORK.get();
    (answer, (after.0 - before.0, after.1 - before.1))
}

/// Completion evidence belongs to the mount's exclusive backend owner,
/// under the adapter gate or its planning ownership transfer.
#[derive(Debug, Default)]
pub(crate) struct CompletionTokens {
    generation: Option<u64>,
    content: std::collections::BTreeSet<GrainId>,
}

impl CompletionTokens {
    #[cfg(test)]
    pub(crate) fn retained_for_test(&self) -> (usize, Option<GrainId>) {
        (self.content.len(), self.content.first().copied())
    }
    #[cfg(test)]
    pub(crate) fn generation_for_test(&self) -> Option<u64> {
        self.generation
    }
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub(crate) fn generation(&self) -> Option<u64> {
        self.generation
    }
    pub(crate) fn clear(&mut self) {
        self.content.clear();
    }
    pub(crate) fn admit_generation(&mut self, generation: u64) {
        if self.generation != Some(generation) {
            self.content.clear();
            self.generation = Some(generation);
        }
    }
    pub(crate) fn contains(&self, content: GrainId) -> bool {
        self.content.contains(&content)
    }
    pub(crate) fn completed(&mut self, content: GrainId) {
        if self.content.contains(&content) {
            return;
        }
        if self.content.len() == COMPLETION_TOKENS {
            self.content.pop_first();
        }
        self.content.insert(content);
    }
    pub(crate) fn remove(&mut self, content: GrainId) {
        self.content.remove(&content);
    }
}

#[derive(Debug, Clone)]
struct OpenObject {
    node: OverlayEntry,
    handles: u64,
    stage_holds: bool,
    attached: bool,
    /// The material of the view this clean object was opened in, once a
    /// landing gave its path another identity: it keeps reading what it
    /// opened, and refuses every change as stale.
    replaced: Option<std::sync::Arc<crate::writable_store::ViewContext>>,
}

/// One consumed proof and the exact owner-only RW attachment configuration.
#[expect(
    missing_debug_implementations,
    reason = "attachment owns the private signer; no Debug carriage"
)]
pub struct WritableAttachment<R, P: OverlayIo> {
    pub backend: WritableMount<R, P>,
    pub snapshot: granary_vfs::Snapshot,
    pub config: granary_fuse::SessionConfig,
    mountpoint: std::path::PathBuf,
}
#[cfg(target_os = "linux")]
impl<R: RootStore + BinStore + Send + 'static, P: OverlayIo + Send + 'static>
    WritableAttachment<R, P>
{
    /// Attach the admitted backend with mediated ordinary write handlers,
    /// and bind an attached engine's landings to the view it serves.
    /// # Errors
    /// Named attachment refusal with a stable session I/O event.
    pub fn mount(
        mut self,
        generation: u64,
    ) -> Result<granary_fuse::BackgroundMount, WritableStartError> {
        let failed = || {
            observe::op_failed(OperationKind::Session, FailureClass::Io);
            WritableStartError::Refused("WritableMountAttachFailed", FailureClass::Io)
        };
        let binding = self.backend.take_view_binding();
        // The engine's landings are bound to the view before the session
        // serves a request, so none is answered without the binding.
        granary_fuse::spawn_writable_session(
            self.snapshot,
            self.backend,
            generation,
            &self.mountpoint,
            &self.config,
            |view| match binding {
                Some(binding) => binding
                    .bind(view, |mount| mount)
                    .map_err(|error| std::io::Error::other(error.to_string())),
                None => Ok(()),
            },
        )
        .map_err(|_| failed())
    }
}
impl<P: OverlayIo> WritableReadiness<HttpStore, P> {
    #[must_use]
    pub fn wire_bytes(&self) -> crate::WireByteHandle {
        self.mount.session.remote_wire_bytes()
    }
}
/// How long a stopped sync executor waits for its blocking work before its
/// worker thread ends anyway.
const RUNTIME_SHUTDOWN_SLACK: std::time::Duration = std::time::Duration::from_secs(1);

/// Keeps the current-thread sync executor driven for the serving mount.
#[derive(Debug)]
#[must_use = "the executor must stay alive while the mount serves"]
pub struct WritableSyncRuntime {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl WritableSyncRuntime {
    /// Drive `runtime` on its own `granary-sync` worker until dropped.
    pub(crate) fn serve(runtime: tokio::runtime::Runtime) -> std::io::Result<Self> {
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let worker = std::thread::Builder::new()
            .name("granary-sync".into())
            .spawn(move || {
                runtime.block_on(async {
                    let _ = stopped.await;
                });
                // Blocking work a shutdown cut runs on until the process
                // exits, so the join does not wait for it.
                runtime.shutdown_timeout(RUNTIME_SHUTDOWN_SLACK);
            })?;
        Ok(Self {
            shutdown: Some(shutdown),
            worker: Some(worker),
        })
    }
}
impl Drop for WritableSyncRuntime {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(worker) = self.worker.take()
            && worker.thread().id() != std::thread::current().id()
        {
            let _ = worker.join();
        }
    }
}

impl<
    R: Send
        + Sync
        + crate::SyncRemote
        + crate::AuthorityTransport
        + crate::WritableAuthority
        + 'static,
    P: OverlayIo + Send + 'static,
> WritableAttachment<R, P>
{
    /// Start the sync supervisor before the daemon can serve requests.
    /// # Errors
    /// Refuses when the executor or admitted engine cannot be installed.
    pub fn start_sync<C: Clock + 'static>(
        &mut self,
        clock: std::sync::Arc<C>,
    ) -> Result<WritableSyncRuntime, WritableStartError> {
        let attach_failed = || {
            observe::op_failed(OperationKind::Session, FailureClass::Io);
            WritableStartError::Refused("WritableSyncAttachFailed", FailureClass::Io)
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| attach_failed())?;
        let remote = self.backend.session.remote_for_sync();
        let content = std::sync::Arc::new(
            self.backend
                .sync_content(remote.clone())
                .map_err(|_| attach_failed())?,
        );
        let metrics = self.backend.session.metrics().cloned().unwrap_or_else(|| {
            crate::ClientMetrics::new(&mut granary_net::secure_random::OsSecureRandom::new())
        });
        runtime
            .block_on(self.backend.attach_live_sync(
                remote,
                content,
                clock,
                std::sync::Arc::new(crate::InstantClock::default()),
                metrics,
                granary_net::secure_random::OsSecureRandom::new(),
            ))
            .map_err(|_| attach_failed())?;
        let runtime = WritableSyncRuntime::serve(runtime).map_err(|_| attach_failed())?;
        self.backend.live_driver = true;
        Ok(runtime)
    }
}
impl<R, P: OverlayIo> WritableAttachment<R, P> {
    /// Clone the lock-free metrics owner and nonblocking overlay owner used by support collection.
    #[must_use]
    pub fn bundle_handles(&self) -> (Option<crate::ClientMetrics>, SharedWritableStore<P>) {
        (
            self.backend.session.metrics().cloned(),
            self.backend.mediator.clone(),
        )
    }

    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Run the engine's shutdown under `bound`; set before
    /// [`WritableAttachment::start_sync`], which attaches the engine.
    pub fn set_shutdown_bound(&mut self, bound: std::time::Duration) {
        self.backend.shutdown_bound = bound;
    }

    /// The attached engine's shutdown, once
    /// [`WritableAttachment::start_sync`] has attached it.
    #[must_use]
    pub fn shutdown_handle(&self) -> Option<crate::ShutdownHandle> {
        self.backend
            .shutdown
            .clone()
            .map(crate::ShutdownHandle::new)
    }

    /// Return a read-only snapshotter for an instrumented integration harness.
    #[cfg(any(test, feature = "overlay-fault-tests"))]
    pub fn metrics_snapshot(
        &self,
    ) -> impl Fn() -> Result<crate::MetricsSnapshot, crate::MetricsError> + Send + Sync + 'static
    {
        let metrics = self.backend.session.metrics().cloned();
        move || {
            metrics
                .as_ref()
                .ok_or(crate::MetricsError::Unavailable)?
                .snapshot()
        }
    }
}

impl<R, P: OverlayIo> WritableMount<R, P> {
    /// Copy the cache's retained counters without filesystem access.
    ///
    /// # Errors
    /// Returns unavailable after shutdown has taken the cache owner.
    pub fn bundle_cache(
        &self,
    ) -> Result<granary_core::support::BundleCache, granary_core::support::BundleRefusal> {
        self.session.bundle_cache()
    }
}
impl<R, P: OverlayIo> WritableReadiness<R, P> {
    #[cfg(test)]
    pub(crate) fn mediator_for_test(&mut self) -> &mut WritableStore<P> {
        self.mount.mediator.get_mut_for_test()
    }

    #[cfg(test)]
    pub(crate) fn snapshot_for_test(&self) -> &granary_vfs::Snapshot {
        &self.snapshot
    }

    #[cfg(test)]
    pub(crate) fn backend_for_test(&mut self) -> &mut WritableMount<R, P> {
        &mut self.mount
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn sync_remote_for_test(&self) -> std::sync::Arc<R>
    where
        R: WritableAuthority,
    {
        self.mount.session.remote_for_sync()
    }

    /// The session's metrics recorder, which an attached engine records into
    /// and the attachment's metrics snapshot reads.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn session_metrics_for_test(&self) -> Option<crate::ClientMetrics> {
        self.mount.session.metrics().cloned()
    }

    #[must_use]
    pub fn verified_base(&self) -> &(VolumeName, u64, GrainId) {
        &self.base
    }
    #[must_use]
    pub fn owner(&self) -> ([u8; 16], u64, [u8; 16]) {
        self.owner
    }
    /// Consume the only admission proof to build the RW session configuration.
    #[must_use]
    pub fn attach(self) -> WritableAttachment<R, P> {
        WritableAttachment {
            backend: self.mount,
            snapshot: self.snapshot,
            config: granary_fuse::writable_session_config(),
            mountpoint: self.mountpoint,
        }
    }
}
impl<R: RootStore + BinStore + Send, P: OverlayIo + Send> granary_vfs::GrainFetch
    for WritableMount<R, P>
{
    fn grain(
        &mut self,
        id: &GrainId,
        length: u32,
    ) -> Result<Vec<u8>, granary_vfs::GrainUnavailable> {
        granary_vfs::GrainFetch::grain(&mut self.session, id, length)
    }
}
impl<R: RootStore + BinStore + Send + 'static, P: OverlayIo + Send + 'static>
    granary_fuse::MountBackend for WritableMount<R, P>
{
    fn callback_observer(&self) -> Option<std::sync::Arc<dyn granary_fuse::CallbackObserver>> {
        let metrics = self.session.metrics().cloned();
        if let Some(metrics) = &metrics {
            metrics.set_available(crate::MetricsGroup::Fuse, true);
        }
        Some(std::sync::Arc::new(crate::mount::FuseObserver {
            metrics,
            writability: granary_fuse::MountWritability::Writable,
        }))
    }

    fn view_boundary(&self) -> Option<std::sync::Arc<dyn granary_fuse::ViewBoundary>> {
        self.view_boundary.clone()
    }

    fn mutation_readiness(&mut self) -> Result<(), granary_fuse::MountError> {
        self.check_mount_view().map_err(mount_error)?;
        if self
            .mediator
            .mutations_closed()
            .map_err(|error| mount_error(write_error(&error)))?
        {
            return Err(granary_fuse::MountError::Closing);
        }
        Ok(())
    }

    type DirectoryCursor = crate::overlay_store::OverlayCursor;

    fn overlay_path(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        self.check_mount_view()?;
        self.mediator
            .overlay_transaction(|o| o.query_path(path))
            .map_err(|e| write_error(&e))
            .and_then(query_value)
            .map(query_metadata)
    }
    fn overlay_lookup(
        &mut self,
        parent: &[granary_core::manifest::Name],
        name: &granary_core::manifest::Name,
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        self.check_mount_view()?;
        self.mediator
            .overlay_transaction(|o| o.query_lookup(parent, name))
            .map_err(|e| write_error(&e))
            .and_then(query_value)
            .map(query_metadata)
    }
    fn overlay_directory(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<granary_fuse::OverlayDirectory<Self::DirectoryCursor>, granary_fuse::WriteError>
    {
        self.check_mount_view()?;
        let result = self
            .mediator
            .overlay_transaction(|o| o.query_directory(path))
            .map_err(|e| write_error(&e))
            .and_then(query_value)?;
        Ok(granary_fuse::OverlayDirectory {
            directory: query_metadata(result.directory),
            parent: query_metadata(result.parent),
            cursor: result.cursor,
        })
    }
    fn overlay_children(
        &mut self,
        cursor: &Self::DirectoryCursor,
    ) -> Result<granary_fuse::OverlayChildren<Self::DirectoryCursor>, granary_fuse::WriteError>
    {
        self.check_mount_view()?;
        let result = self
            .mediator
            .overlay_transaction(|o| o.query_children(cursor))
            .map_err(|e| write_error(&e))
            .and_then(query_value)?;
        Ok(granary_fuse::OverlayChildren {
            entries: result.entries.into_iter().map(query_metadata).collect(),
            next: result.next,
        })
    }

    fn overlay_nodes(
        &mut self,
    ) -> Result<Vec<granary_fuse::OverlayNode>, granary_fuse::WriteError> {
        self.check_mount_view()?;
        let entries = self.nodes()?;
        let mut nodes = vec![granary_fuse::OverlayNode {
            path: Vec::new(),
            kind: granary_vfs::NodeKind::Dir,
            size: 4096,
            exec: false,
            stage: None,
        }];
        nodes.extend(entries.into_iter().map(|entry| granary_fuse::OverlayNode {
            path: entry.path,
            kind: match entry.kind {
                OverlayKind::File { .. } => granary_vfs::NodeKind::File,
                OverlayKind::Directory => granary_vfs::NodeKind::Dir,
                OverlayKind::Symlink { .. } => granary_vfs::NodeKind::Symlink,
            },
            size: match entry.kind {
                OverlayKind::Directory => 4096,
                OverlayKind::Symlink { target } => u64::from(target.wire_len()),
                OverlayKind::File { .. } => entry.size,
            },
            exec: entry.exec,
            stage: entry.stage_id,
        }));
        Ok(nodes)
    }

    fn overlay_capacity(
        &mut self,
    ) -> Result<granary_fuse::OverlayCapacity, granary_fuse::WriteError> {
        self.check_mount_view()?;
        let observation = self
            .mediator
            .overlay_transaction(mediated_capacity)
            .map_err(|error| write_error(&error))?;
        Ok(granary_fuse::OverlayCapacity {
            cap: observation.cap,
            charged: observation.summary.charged_bytes,
            reserved: observation.summary.reserved_bytes,
            captured: observation.summary.captured_bytes,
            files: observation.namespace_len,
            free_entries: observation.free_entries,
        })
    }

    fn overlay_readlink(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<Vec<u8>, granary_fuse::WriteError> {
        self.check_mount_view()?;
        let node = self
            .mediator
            .overlay_transaction(|overlay| overlay.query_path(path))
            .map_err(|error| write_error(&error))?;
        let crate::overlay_store::OverlayQuery::Found(node) = node else {
            return Err(granary_fuse::WriteError::Missing);
        };
        let node = node.entry.ok_or(granary_fuse::WriteError::Missing)?;
        if let OverlayKind::Symlink { target } = node.kind {
            Ok(target.as_bytes().to_vec())
        } else {
            Err(granary_fuse::WriteError::Invalid)
        }
    }

    fn overlay_open(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<Option<u64>, granary_fuse::WriteError> {
        self.check_mount_view()?;
        let node = self.path_entry(path)?;
        if !matches!(node.kind, OverlayKind::File { .. }) {
            return Err(granary_fuse::WriteError::IsDirectory);
        }
        let handles = self
            .objects
            .get(&node.inode)
            .map_or(0, |o| o.handles)
            .checked_add(1)
            .ok_or(granary_fuse::WriteError::Invalid)?;
        if node.stage_id.is_some() {
            let holds = if self
                .objects
                .get(&node.inode)
                .is_some_and(|object| object.stage_holds)
            {
                1
            } else {
                handles
            };
            self.mediator
                .overlay_transaction(|overlay| overlay.open_stage_holds(path, holds))
                .map_err(|error| write_error(&error))?;
        }
        let id = node.inode;
        let stage_holds = node.stage_id.is_some();
        self.objects.insert(
            id,
            OpenObject {
                node,
                handles,
                stage_holds,
                attached: true,
                replaced: None,
            },
        );
        Ok(Some(id))
    }

    fn prepare_shrink_retry(
        &mut self,
        request: granary_fuse::MountShrinkRequest,
    ) -> Result<Box<dyn granary_fuse::MountSyncJob>, granary_fuse::MountSyncError> {
        self.retry_pending_shrink(&request)
    }

    fn prepare_sync(
        &mut self,
        request: granary_fuse::MountSyncRequest,
    ) -> Result<Box<dyn granary_fuse::MountSyncJob>, granary_fuse::MountSyncError> {
        self.prepare_sync_job(request)
    }

    fn overlay_object(
        &mut self,
        object: u64,
    ) -> Result<granary_fuse::OverlayNode, granary_fuse::WriteError> {
        self.check_mount_view()?;
        self.refresh_object(object)?;
        let held = self
            .objects
            .get(&object)
            .ok_or(granary_fuse::WriteError::Missing)?;
        Ok(granary_fuse::OverlayNode {
            path: held.node.path.clone(),
            kind: granary_vfs::NodeKind::File,
            size: held.node.size,
            exec: held.node.exec,
            stage: held.node.stage_id,
        })
    }

    fn overlay_close(&mut self, object: u64) -> Result<(), granary_fuse::WriteError> {
        let held = self
            .objects
            .get_mut(&object)
            .ok_or(granary_fuse::WriteError::Missing)?;
        if held.handles == 0 {
            return Err(granary_fuse::WriteError::Invalid);
        }
        held.handles -= 1;
        let stage = held.node.stage_id.filter(|_| held.stage_holds);
        let last = held.handles == 0;
        let result = if let Some(stage) = stage {
            self.mediator
                .release_stage(stage)
                .map_err(|error| write_error(&error))
        } else {
            Ok(())
        };
        if last {
            self.objects.remove(&object);
        }
        result
    }

    fn prepare_object(&mut self, object: u64) -> Result<(), granary_fuse::WriteError> {
        let view = self.check_mount_view()?;
        self.refresh_bound_object(object)?;
        let held = self
            .objects
            .get(&object)
            .ok_or(granary_fuse::WriteError::Missing)?;
        if held.node.stage_id.is_some() {
            return self.admit_mount_view(view).map(|_| ());
        }
        if let Some(material) = held.replaced.clone() {
            let node = held.node.clone();
            let OverlayKind::File {
                content: Some(content),
            } = node.kind
            else {
                return Err(granary_fuse::WriteError::Invalid);
            };
            if let Err(error) = self.materialize_once(&node, Some(&material)) {
                self.completion_tokens.remove(content);
                return Err(error);
            }
            self.completion_tokens.completed(content);
            return Ok(());
        }
        // Exclusive backend ownership keeps the holds intact across preparation.
        // Restore the object on both success and typed failure.
        let mut held = self
            .objects
            .remove(&object)
            .ok_or(granary_fuse::WriteError::Missing)?;
        let result = self.materialize(&mut held.node);
        self.objects.insert(object, held);
        result
    }

    fn prepare_detach(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<(), granary_fuse::WriteError> {
        self.check_mount_view()?;
        let query = self
            .mediator
            .overlay_transaction(|overlay| overlay.query_path_inode(path))
            .map_err(|error| write_error(&error))?;
        if matches!(query, crate::overlay_store::OverlayQuery::Missing) {
            return Ok(());
        }
        if let Some(inode) = query_value(query)? {
            if self.objects.contains_key(&inode) {
                // The held entry already owns the preparation context. Its refresh
                // still admits readiness and checks the current inverse association.
                self.prepare_object(inode)?;
            } else if self
                .mediator
                .leased(inode)
                .map_err(|error| write_error(&error))?
            {
                self.prepare_overlay(path)?;
            }
        }
        Ok(())
    }

    fn read_object(
        &mut self,
        object: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, granary_fuse::WriteError> {
        if length > granary_vfs::READ_MAX_BYTES as usize {
            return Err(granary_fuse::WriteError::Invalid);
        }
        self.check_mount_view()?;
        self.refresh_object(object)?;
        let held = self
            .objects
            .get(&object)
            .ok_or(granary_fuse::WriteError::Missing)?;
        let node = &held.node;
        let wanted = node.size.saturating_sub(offset).min(length as u64);
        let content = match node.kind {
            OverlayKind::File { content } => content,
            _ => None,
        };
        if held.replaced.is_some() {
            // The opened content is read by its id: the path now names
            // another file, and the base no longer holds this one.
            let content = content.ok_or(granary_fuse::WriteError::Invalid)?;
            let result = self
                .mediator
                .with(|local| {
                    let mut immutable = local.immutable_content()?;
                    Ok(read_chunks(offset, wanted, |at, length| {
                        immutable.read_content(content, at, length)
                    })?)
                })
                .map_err(|error| write_error(&error));
            if matches!(
                result,
                Err(granary_fuse::WriteError::Backend(
                    granary_fuse::MountError::Unavailable | granary_fuse::MountError::Corrupt
                ))
            ) {
                self.completion_tokens.remove(content);
            }
            return result;
        }
        let enforce_base = self.view_state != sync::MountViewState::Direct;
        let result = self
            .mediator
            .with(|local| {
                let pin = sync::pinned(local)?;
                local.guard_view()?;
                local.overlay_transaction(|overlay| {
                    let (_, view) = overlay.preparation_view(node)?;
                    if enforce_base && (view.base_id, view.base_seq) != (pin.base_id, pin.base_seq)
                    {
                        return Ok((view, None));
                    }
                    let bytes = read_chunks(offset, wanted, |at, length| {
                        if let Some(stage) = node.stage_id {
                            overlay.read_stage(stage, at, length)
                        } else {
                            overlay.read_base(&node.path, at, length)
                        }
                    })?;
                    Ok((view, Some(bytes)))
                })
            })
            .map_err(|error| write_error(&error));
        match result {
            Ok((view, Some(bytes))) => {
                self.admit_mount_view(view)?;
                Ok(bytes)
            }
            Ok((view, None)) => {
                self.admit_mount_view(view)?;
                Err(granary_fuse::WriteError::Backend(
                    granary_fuse::MountError::Io,
                ))
            }
            Err(error) => {
                self.admit_mediator_view()?;
                if matches!(
                    error,
                    granary_fuse::WriteError::Backend(
                        granary_fuse::MountError::Unavailable | granary_fuse::MountError::Corrupt
                    )
                ) && let Some(content) = content
                {
                    self.completion_tokens.remove(content);
                }
                Err(error)
            }
        }
    }

    fn prepare_overlay(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<(), granary_fuse::WriteError> {
        self.check_mount_view()?;
        let mut node = self.path_entry(path)?;
        self.materialize(&mut node)
    }

    fn overlay_setattr(
        &mut self,
        path: &[granary_core::manifest::Name],
        size: Option<u64>,
        exec: Option<bool>,
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        use granary_fuse::WriteError as E;
        self.check_mount_view()?;
        let mut node = self.path_entry(path)?;
        if !matches!(node.kind, OverlayKind::File { .. }) {
            return Err(E::IsDirectory);
        }
        if size.is_some_and(|size| size > granary_core::overlay_journal::SIZE_MAX) {
            return Err(E::TooBig);
        }
        let truncation = if let Some(size) = size {
            self.materialize(&mut node)?;
            if node.path != path {
                return Err(E::Missing);
            }
            Some((self.staged(&node)?, size))
        } else {
            None
        };
        let exec = exec.filter(|exec| *exec != node.exec);
        let change = exec
            .map(|exec| journal_location(&node.path).map(|at| (exec, at)))
            .transpose()?;
        let (truncated, result) = set_size_and_exec(&self.mediator, truncation, change);
        if let (Some((stage, size)), true) = (truncation, truncated) {
            node.stage_id = Some(stage);
            node.size = size;
            if let Some(held) = self.objects.get_mut(&node.inode) {
                held.node.size = size;
            }
        }
        result.map_err(|error| write_error(&error))?;
        if let Some(exec) = exec {
            node.exec = exec;
            if let Some(held) = self.objects.get_mut(&node.inode) {
                held.node.exec = exec;
            }
        }
        #[cfg(test)]
        if self.setattr_release_after_effect {
            self.mediator
                .phase_for_test(granary_core::overlay_ownership::Phase::Releasing)
                .map_err(|error| write_error(&error))?;
        }
        // Compare the owned result with authority even after a metadata-only
        // effect; the comparison also admits readiness and index consistency.
        if let Some(current) = self
            .mediator
            .overlay_transaction(|overlay| overlay.query_inode_change(&node))
            .map_err(|error| write_error(&error))
            .and_then(query_value)?
        {
            node = current;
        }
        Ok(query_metadata(crate::overlay_store::OverlayQueryEntry {
            entry: Some(node),
            nlink: 1,
        }))
    }
    fn overlay_mutate(
        &mut self,
        operation: granary_fuse::OverlayMutation<'_>,
    ) -> Result<(), granary_fuse::WriteError> {
        self.mutate(operation)
    }

    fn shutdown(&mut self) -> Result<(), String> {
        if let Some(shutdown) = self.shutdown.clone() {
            // The sequence answers within its bound; the cache closes after
            // it. Its outcome is the handle's to report, so only the cache's
            // result is returned.
            let outcome = shutdown.begin(crate::sync::Trigger::SessionEnd).outcome;
            let cache = granary_fuse::MountBackend::shutdown(&mut self.session);
            if !outcome.released() {
                crate::observe::OperatorDiagnostic::writable_shutdown_coordination_failed(
                    outcome.class(),
                    cache.is_ok(),
                )
                .emit();
            }
            return cache;
        }
        // With no engine attached nothing can be flushed: a store that still
        // owes the authority an answer is reported.
        let coordination = self.mediator.check_quiescent();
        let cache = granary_fuse::MountBackend::shutdown(&mut self.session);
        match (coordination, cache) {
            (Ok(()), result) => result,
            (Err(error), cache) => {
                crate::observe::OperatorDiagnostic::writable_shutdown_coordination_failed(
                    coordination_class(&error),
                    cache.is_ok(),
                )
                .emit();
                Err(format!(
                    "WritableShutdownCoordinationFailed: {error}; cache={}",
                    cache.err().unwrap_or_else(|| "closed".to_owned())
                ))
            }
        }
    }
    fn abandon(&mut self) {
        granary_fuse::MountBackend::abandon(&mut self.session);
    }
}

/// Open a writable mount through every admission gate, including local custody.
/// # Errors
/// The first ordered startup refusal, with its stable session failure event.
pub fn start_writable(
    input: &WritableStart<'_>,
    clock: &(impl Clock + Clone + 'static),
    rng: &mut impl Rng,
    random: &mut (impl SecureRandom + Send),
    sink: &mut dyn crate::LocalReporter,
) -> Result<WritableReadiness<HttpStore, crate::OverlayDisk>, WritableStartError> {
    start_with(
        input,
        cfg!(target_os = "linux"),
        || {
            let (key, spare, credential) = load_local(input)?;
            let scope = input
                .scope
                .as_ref()
                .ok_or_else(|| refusal("WritableCredentialsRequired"))?;
            scope
                .digest()
                .map_err(|_| refusal("WritableCredentialsRequired"))?;
            let base = std::str::from_utf8(&scope.authority_base)
                .map_err(|_| refusal("WritableCredentialsRequired"))?;
            let remote = HttpStore::with_client_credential(
                base,
                scope.pins.clone(),
                &crate::AmbientNetwork,
                Some(credential),
            )
            .map_err(|_| refusal("WritableCredentialInputRefused"))?;
            Ok((key, spare, metered_remote(&remote)))
        },
        |store: &Store| crate::OverlayDisk::new(store.publication_root(), input.euid),
        random,
        clock,
        rng,
        sink,
    )
}

pub(crate) fn metered_remote(remote: &HttpStore) -> HttpStore {
    remote.with_metrics(crate::ClientMetrics::new(
        &mut granary_net::secure_random::OsSecureRandom::new(),
    ))
}

/// The signing key and its spare from the seed, read once, and the client
/// credential.
pub(crate) fn load_local(
    input: &WritableStart<'_>,
) -> Result<(SigningKey, SigningKey, crate::ClientCredential), WritableStartError> {
    let seed = input
        .seed
        .ok_or_else(|| refusal("WritableSigningKeyRequired"))?;
    let store = input
        .store
        .ok_or_else(|| refusal("WritableStoreRequired"))?;
    check_managed_paths(seed, input.credential_key, store, input.cache)?;
    let loaded = crate::load_existing_signing_key_with_spare(seed, input.euid)
        .map_err(|_| refusal("WritableKeyInputRefused"))?;
    let credential = crate::ClientCredential::from_configured(
        input.certificate,
        input.credential_key,
        input.euid,
    )
    .map_err(|_| refusal("WritableCredentialInputRefused"))?
    .ok_or_else(|| refusal("WritableCredentialsRequired"))?;
    if loaded.seed_identity == credential.key_file_identity() {
        return Err(refusal("WritableCredentialInputRefused"));
    }
    let spare = loaded
        .spare
        .ok_or_else(|| refusal("WritableKeyInputRefused"))?;
    Ok((loaded.key, spare, credential))
}

#[expect(
    clippy::disallowed_methods,
    reason = "read-only managed path resolution for support sources and key comparisons before \
              any writable state is created"
)]
/// Resolve a managed input through its real existing ancestors.
///
/// # Errors
///
/// Refuses an unreadable path or a missing leaf below a symlinked ancestor.
#[doc(hidden)]
pub fn managed_path(path: &Path) -> Result<std::path::PathBuf, WritableStartError> {
    match std::fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            for ancestor in path.ancestors() {
                if std::fs::symlink_metadata(ancestor)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
                {
                    return Err(refusal("WritableKeyInputRefused"));
                }
            }
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let leaf = path
                .file_name()
                .ok_or_else(|| refusal("WritableKeyInputRefused"))?;
            Ok(managed_path(parent)?.join(leaf))
        }
        Err(_) => Err(refusal("WritableKeyInputRefused")),
    }
}
fn check_managed_paths(
    seed: &Path,
    tls: Option<&Path>,
    store: &Path,
    cache: Option<&Path>,
) -> Result<(), WritableStartError> {
    let store = managed_path(store)?;
    let cache = cache.map(managed_path).transpose()?;
    if cache
        .as_ref()
        .is_some_and(|cache| cache.starts_with(&store) || store.starts_with(cache))
    {
        return Err(refusal("WritableKeyInputRefused"));
    }
    let mut sidecar = seed.as_os_str().to_owned();
    sidecar.push(".pub");
    for path in [Some(seed), Some(Path::new(&sidecar)), tls]
        .into_iter()
        .flatten()
    {
        let path = managed_path(path)?;
        if std::iter::once(&store)
            .chain(cache.iter())
            .any(|root| path.starts_with(root) || root.starts_with(&path))
        {
            return Err(refusal("WritableKeyInputRefused"));
        }
    }
    Ok(())
}

/// Execute common admission with deterministic custody and transport seams.
/// The loader must use existing-file custody and path separation, and load the
/// credential before constructing the pinned authority pool. It may not create keys.
/// It returns the signing key, its spare from the same seed bytes, and the authority.
/// It receives no serving/ownership permission; equality is checked here before requests.
/// # Errors
/// The first failed gate, with a stable session failure event.
#[expect(
    clippy::too_many_arguments,
    reason = "ordered inputs plus explicit host, custody, storage, entropy, clock, jitter and output seams"
)]
pub(crate) fn start_with<R, P>(
    input: &WritableStart<'_>,
    linux: bool,
    load: impl FnOnce() -> Result<(SigningKey, SigningKey, R), WritableStartError>,
    io: impl FnOnce(&Store) -> P,
    random: &mut (impl SecureRandom + Send),
    clock: &(impl Clock + Clone + 'static),
    rng: &mut impl Rng,
    sink: &mut dyn crate::LocalReporter,
) -> Result<WritableReadiness<R, P>, WritableStartError>
where
    R: WritableAuthority + crate::SyncRemote + crate::AuthorityTransport + Sync + 'static,
    P: OverlayIo + Clone + Send + Sync + 'static,
{
    let result = check_rails(input, linux)
        .and_then(|()| start_inner(input, load, io, random, clock, rng, sink));
    if let Err(error) = &result {
        observe::op_failed(OperationKind::Session, error.class());
    }
    result
}

#[expect(
    clippy::too_many_lines,
    reason = "one visible ordered admission sequence with explicit deterministic seams"
)]
fn start_inner<R, P>(
    input: &WritableStart<'_>,
    load: impl FnOnce() -> Result<(SigningKey, SigningKey, R), WritableStartError>,
    io: impl FnOnce(&Store) -> P,
    random: &mut (impl SecureRandom + Send),
    clock: &(impl Clock + Clone + 'static),
    rng: &mut impl Rng,
    sink: &mut dyn crate::LocalReporter,
) -> Result<WritableReadiness<R, P>, WritableStartError>
where
    R: WritableAuthority + crate::SyncRemote + crate::AuthorityTransport + Sync + 'static,
    P: OverlayIo + Clone + Send + Sync + 'static,
{
    let public = input.check_posture()?;
    input
        .seed
        .ok_or_else(|| refusal("WritableSigningKeyRequired"))?;
    if input.certificate.is_none() || input.credential_key.is_none() || input.scope.is_none() {
        return Err(refusal("WritableCredentialsRequired"));
    }
    let store_path = input
        .store
        .ok_or_else(|| refusal("WritableStoreRequired"))?;
    let cache_path = input.cache.ok_or_else(|| refusal("CacheDirRequired"))?;
    let scope = input
        .scope
        .as_ref()
        .ok_or_else(|| refusal("WritableCredentialsRequired"))?;
    crate::RootVerifier::trusting(public)
        .map_err(|error| WritableStartError::ReadView(MountError::Anchor(error)))?;
    let (key, spare, remote) = load()?;
    if key.public_key() != &public {
        return Err(refusal("WritableKeyMismatch"));
    }
    let start_runtime = finish::StartRuntime::new(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| unavailable("WritableAuthorityUnavailable"))?,
    );
    let runtime = start_runtime.get()?;
    match runtime.block_on(remote.writable_status(&input.volume)) {
        Ok(StatusResponse::Observed(_)) => (),
        Ok(StatusResponse::Refused(StatusRefusal::UnknownTarget)) => {
            return Err(refusal("WritableAuthorityRequired"));
        }
        Ok(StatusResponse::Refused(StatusRefusal::UnknownVolume)) => {
            return Err(refusal("WritableVolumeUnserved"));
        }
        Ok(StatusResponse::Refused(StatusRefusal::NoLog)) => {
            return Err(refusal("WritableAuthorityUninitialised"));
        }
        Ok(StatusResponse::ServiceUnavailable(_) | StatusResponse::Internal)
        | Err(AuthorityError::Transport(_) | AuthorityError::Elapsed) => {
            return Err(unavailable("WritableAuthorityUnavailable"));
        }
        _ => return Err(invalid("WritableDiscoveryInvalid")),
    }
    readback(&remote, runtime, scope, &input.volume, &public, None)?;
    if input.reset_floor {
        let mut cache = Cache::open(cache_path, input.cache_quota, &input.cache_origin)
            .map_err(|error| WritableStartError::ReadView(MountError::Cache(error)))?;
        let reset = cache.reset_mount_anchor(&input.volume);
        let close = Cache::close(cache);
        reset.map_err(|_| refusal("WritableResetFloorRefused"))?;
        close.map_err(|_| refusal("WritableResetFloorRefused"))?;
    }
    // The head and the cache are checked before the authority sees an
    // ownership change.
    let mut session = head_session(&remote, input, public, cache_path, sink)?;
    let store = Store::open(store_path).map_err(|_| refusal("WritableStoreInputRefused"))?;
    let io = io(&store);
    let mut mediator = WritableStore::new(
        store,
        OverlayConfig {
            scope: scope.clone(),
            volume: input.volume.clone(),
            euid: input.euid,
            cap: input.overlay_cap_bytes,
            ownership_completion_reserve: granary_core::overlay_ownership::REPLACEMENT_RESERVE,
            instance: [0; 16],
        },
        io.clone(),
        random,
        start_faults(),
        |doc, prefix| verifies(&public, doc, prefix),
    )?;
    let keys = crypto::TrustedKeys::new([public]).map_err(|_| invalid("SyncBase"))?;
    crate::recovery::preflight_residual(&mut mediator, &remote, &keys, runtime, || {
        crate::TokioSyncRuntime
            .now()
            .checked_add(finish::phase_bound())
            .ok_or_else(|| crate::sync::refused("SyncDeadline"))
    })?;
    mediator.set_contention_threshold(input.contention_threshold);
    mediator.construction_workspace_bytes = input.construction_workspace_bytes;
    if let Some(metrics) = session.metrics() {
        mediator.set_metrics(metrics.clone());
    }
    settle_retained(&mut mediator, clock, |mediator, request, landed_replay| {
        drive_inner(
            mediator,
            &remote,
            runtime,
            scope,
            request,
            &public,
            clock,
            rng,
            landed_replay,
            None,
        )
    })?;
    if mediator.snapshot().phase != Phase::Unowned {
        let request = mediator.prepare_succession(clock)?;
        drive(
            &mut mediator,
            &remote,
            runtime,
            scope,
            &request,
            &public,
            clock,
            rng,
            None,
        )?;
    }
    // A retained or new takeover can settle to Unowned in this invocation.
    if mediator.snapshot().phase == Phase::Unowned {
        let reply = readback(&remote, runtime, scope, &input.volume, &public, None)?;
        if !reply.matches_scope(scope, &input.volume) {
            return Err(invalid("WritableIntentDiscoveryInvalid"));
        }
        let Verdict::Accepted(observed) =
            reply.readback(&input.volume, |doc, prefix| verifies(&public, doc, prefix))
        else {
            return Err(invalid("WritableIntentDiscoveryInvalid"));
        };
        if observed
            .rows
            .iter()
            .any(|row| row.writer == mediator.writer_uuid())
        {
            return Err(refusal("WritableRecoveryRequired"));
        }
        let request = mediator.prepare_acquire(observed.cursor, clock)?;
        drive(
            &mut mediator,
            &remote,
            runtime,
            scope,
            &request,
            &public,
            clock,
            rng,
            None,
        )?;
    }
    // A journal left holding work is finished on its own base before the
    // session the mount serves from opens, on the head finishing produced.
    if let Some(base) = mediator.dirty_journal_base()? {
        // The phase's own session takes the cache, and the serving session
        // opens on the head finishing produced.
        finish::close_session(session)?;
        mediator = finish::finish_interrupted_shutdown(
            finish::Inputs {
                input,
                cache_path,
                remote: &remote,
                runtime,
                public,
                key: &key,
                spare,
                clock,
            },
            base,
            mediator,
            io.clone(),
            random,
            rng,
            sink,
        )?;
        session = head_session(&remote, input, public, cache_path, sink)?;
    }
    let base_id = GrainId::of(&session.pre.root_bytes);
    let mut prepared = session.pre.doc.clone();
    let base_seq = prepared.seq;
    let pin_nodes = session.pre.nodes.clone();
    let snapshot = session
        .snapshot(input.policy)
        .map_err(|_| invalid("WritableSnapshotRefused"))?;
    let base = overlay_base(&snapshot)?;
    let pin_files = pinned_files(&snapshot, &base)?;
    let header = JournalHeader {
        writer: mediator.writer_uuid(),
        base_root: base_id,
        base_seq,
        next_stage_id: 1,
        receipt_generation: 0,
    };
    // The verdict on the registered root precedes the overlay's open, so a
    // start that refuses leaves the journal on its own base.
    let registered = mediator.snapshot().root.clone();
    if !registered.is_empty() {
        let selected = root::decode_root(&registered).map_err(|_| invalid("IntentPreparedRoot"))?;
        if !same_tree(&selected, &prepared)
            && !registered_root_published(
                &remote,
                runtime,
                &input.volume,
                &public,
                &registered,
                &selected,
            )?
        {
            return Err(refusal("WritableRecoveryRequired"));
        }
    }
    let carry_forward = carry_permitted(
        &mediator.retained_requests(),
        mediator.publication_unsettled()?,
    );
    mediator.open_overlay_local(header, base.clone(), io, carry_forward)?;
    for request in mediator.retained_requests() {
        if request.operation() != Operation::Register {
            return Err(refusal("WritableRecoveryRequired"));
        }
        drive(
            &mut mediator,
            &remote,
            runtime,
            scope,
            &request,
            &public,
            clock,
            rng,
            None,
        )?;
    }
    mediator.check_initial_state()?;
    prepared.seq = base_seq
        .checked_add(1)
        .filter(|seq| *seq < u64::MAX)
        .ok_or_else(|| refusal("WritableRecoveryRequired"))?;
    prepared.parent = Some(base_id);
    prepared.writer_uuid = mediator.writer_uuid();
    prepared.timestamp = clock.now();
    prepared.sigs.clear();
    let prefix = root::signing_prefix_of(&prepared).map_err(|_| invalid("IntentPreparedRoot"))?;
    prepared.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&prefix),
    });
    let signer = CheckedSigner {
        key: Some(key),
        public,
    };
    let bytes = root::encode_root(&prepared).map_err(|_| invalid("IntentPreparedRoot"))?;
    let request = mediator.prepare_registration(&bytes, vec![], clock, |doc, prefix| {
        verifies(&signer.public, doc, prefix)
    })?;
    drive(
        &mut mediator,
        &remote,
        runtime,
        scope,
        &request,
        &public,
        clock,
        rng,
        None,
    )?;
    mediator.check_readiness()?;
    let receipt = intent::decode_receipt(&mediator.snapshot().current)
        .map_err(|_| invalid("IntentReceipt"))?;
    let owner = (mediator.writer_uuid(), receipt.epoch, receipt.instance);
    mediator.bind_mount(std::sync::Arc::new(finish::session_view(
        &session, pin_nodes, pin_files,
    )));
    Ok(WritableReadiness {
        mount: WritableMount {
            session,
            mediator: SharedWritableStore::new(mediator),
            signer,
            owner,
            view_state: sync::MountViewState::Direct,
            view_binding: None,
            view_boundary: None,
            sync_profile: input.sync_profile,
            view: input.view,
            live_driver: false,
            #[cfg(test)]
            live_options: crate::SyncOptions::default(),
            sync_jobs: None,
            shrink_jobs: None,
            shutdown: None,
            shutdown_bound: crate::sync::DEFAULT_SHUTDOWN_BOUND,
            objects: std::collections::BTreeMap::new(),
            completion_tokens: CompletionTokens::default(),
            #[cfg(test)]
            planning_changes_remaining: 0,
            #[cfg(test)]
            planning_attempts: 0,
            #[cfg(test)]
            materialization_passes: 0,
            #[cfg(test)]
            planning_work_boundaries: Vec::new(),
            #[cfg(test)]
            planning_replace: false,
            #[cfg(test)]
            planning_move: None,
            #[cfg(test)]
            setattr_release_after_effect: false,
            #[cfg(test)]
            planning_hook: None,
            #[cfg(test)]
            before_materialize_hook: None,
            #[cfg(test)]
            after_view_hook: None,
        },
        snapshot,
        base: (input.volume.clone(), base_seq, base_id),
        owner,
        mountpoint: input.mountpoint.to_owned(),
    })
}

/// A session on the head discovery finds, verified under `public`.
fn head_session<R: WritableAuthority>(
    remote: &R,
    input: &WritableStart<'_>,
    public: [u8; 32],
    cache_path: &Path,
    sink: &mut dyn crate::LocalReporter,
) -> Result<MountSession<R>, WritableStartError> {
    MountSession::open(
        remote.read_facade(),
        input.volume.clone(),
        Some(Box::new(public)),
        None,
        false,
        None,
        cache_path,
        input.cache_quota,
        &input.cache_origin,
        input.options,
        sink,
    )
    .map_err(WritableStartError::ReadView)
}

/// Whether a start may carry a clean journal forward: no request is retained,
/// whose journal record or outcome may still be owed, and no publication is
/// unsettled. Either keeps the journal on its base, where the start's later
/// refusal finds it.
pub(crate) fn carry_permitted(retained: &[PendingIntent], publication_unsettled: bool) -> bool {
    retained.is_empty() && !publication_unsettled
}

/// Whether two roots name the same tree: manifest root, binmap index, sheaf
/// head and chunker spec.
fn same_tree(a: &RootDoc, b: &RootDoc) -> bool {
    a.manifest_root == b.manifest_root
        && a.binmap_index == b.binmap_index
        && a.sheaf_head == b.sheaf_head
        && a.chunker_spec == b.chunker_spec
}

/// Whether every byte acknowledged under the registered prepared root `bytes`
/// is in a root the store has published and verified under `public`: the
/// root itself at its seq, which a landing's refresh registers, or else its
/// parent at the seq below holding the same tree, which a start registers.
/// The parent is tried only when another root, or none, holds the root's seq.
/// # Errors
/// `WritableAuthorityUnavailable` for a read a retry can clear, and
/// `WritableDiscoveryInvalid` for a malformed or refused answer, or a root
/// that does not verify at a published seq.
fn registered_root_published<R: RootStore>(
    remote: &R,
    runtime: &tokio::runtime::Runtime,
    volume: &VolumeName,
    public: &[u8; 32],
    bytes: &[u8],
    doc: &RootDoc,
) -> Result<bool, WritableStartError> {
    let trusted =
        crypto::TrustedKeys::new([*public]).map_err(|_| invalid("WritableDiscoveryInvalid"))?;
    let read = |seq, expected| {
        runtime.block_on(crate::sync::PublishedRoot::read(
            remote,
            volume,
            seq,
            Some(expected),
            &trusted,
        ))
    };
    match read(doc.seq, GrainId::of(bytes)) {
        Ok(_) => return Ok(true),
        Err(CoordinationError::Refused("ViewRootUnpublished" | "ViewRootMismatch")) => {}
        Err(error) => return Err(published_read_refusal(&error)),
    }
    let (Some(parent), Some(seq)) = (doc.parent, doc.seq.checked_sub(1).filter(|seq| *seq > 0))
    else {
        return Ok(false);
    };
    match read(seq, parent) {
        Ok(published) => Ok(same_tree(published.doc(), doc)),
        Err(CoordinationError::Refused("ViewRootUnpublished" | "ViewRootMismatch")) => Ok(false),
        Err(error) => Err(published_read_refusal(&error)),
    }
}

/// The start's refusal for a published-root read that failed other than by
/// naming no root or another root: retryable for a transient store answer,
/// permanent until investigated for every other.
fn published_read_refusal(error: &CoordinationError) -> WritableStartError {
    if matches!(error, CoordinationError::Refused("ViewRootUnavailable")) {
        unavailable("WritableAuthorityUnavailable")
    } else {
        invalid("WritableDiscoveryInvalid")
    }
}

fn readback<R: WritableAuthority>(
    remote: &R,
    runtime: &tokio::runtime::Runtime,
    scope: &Scope,
    volume: &VolumeName,
    public: &[u8; 32],
    deadline: Option<tokio::time::Instant>,
) -> Result<IntentReply, WritableStartError> {
    let reply = run_before(
        runtime,
        deadline,
        remote.writable_readback(scope, volume, public),
    )?
    .map_err(|error| match error {
        IntentTransportError::Backend | IntentTransportError::InvalidRequest => {
            invalid("WritableIntentDiscoveryInvalid")
        }
        _ => unavailable("WritableIntentUnavailable"),
    })?;
    match reply.readback(volume, |doc, prefix| verifies(public, doc, prefix)) {
        Verdict::Accepted(_) => Ok(reply),
        Verdict::NotImplemented => Err(refusal("WritableIntentResourcesMissing")),
        Verdict::Refused(intent::Refusal::UnknownVolume) => Err(refusal("WritableVolumeUnserved")),
        Verdict::Refused(intent::Refusal::NoPrincipal | intent::Refusal::NotEnrolled) => {
            Err(refusal("WritableIntentAccessRefused"))
        }
        Verdict::Backend(_) => Err(invalid("WritableIntentDiscoveryInvalid")),
        _ => Err(unavailable("WritableIntentUnavailable")),
    }
}

pub(crate) fn unique_writer_row<'rows, 'root>(
    rows: &'rows [intent::ReadbackRow<'root>],
    writer: [u8; 16],
) -> Result<Option<&'rows intent::ReadbackRow<'root>>, WritableStartError> {
    let mut matching = rows.iter().filter(|row| row.writer == writer);
    let row = matching.next();
    if matching.next().is_some() {
        return Err(invalid("WritableIntentDiscoveryInvalid"));
    }
    Ok(row)
}
#[expect(
    clippy::too_many_arguments,
    reason = "retained request and deterministic clock/RNG/transport seams"
)]
fn drive<R: WritableAuthority, P: OverlayIo>(
    mediator: &mut WritableStore<P>,
    remote: &R,
    runtime: &tokio::runtime::Runtime,
    scope: &Scope,
    request: &PendingIntent,
    public: &[u8; 32],
    clock: &impl Clock,
    rng: &mut impl Rng,
    deadline: Option<tokio::time::Instant>,
) -> Result<(), WritableStartError> {
    drive_inner(
        mediator, remote, runtime, scope, request, public, clock, rng, false, deadline,
    )
}

/// Settle retained requests before transferring ownership. Resolve Release
/// eligibility, then retire any expired handshake. Stop if expiry restored
/// a fence. Otherwise drive exact handshake and Release bytes, checking local
/// debt before replaying an Acquire, and settle any matched landed refresh.
/// The drive flag marks that refresh.
fn settle_retained<P: OverlayIo>(
    mediator: &mut WritableStore<P>,
    clock: &impl Clock,
    mut drive: impl FnMut(&mut WritableStore<P>, &PendingIntent, bool) -> Result<(), WritableStartError>,
) -> Result<(), WritableStartError> {
    mediator.settle_expired_release(clock)?;
    mediator.settle_expired_handshake(clock)?;
    if mediator.snapshot().phase == Phase::Fenced {
        return Ok(());
    }
    for request in mediator.retained_requests().into_iter().filter(|request| {
        matches!(
            request.operation(),
            Operation::Ownership | Operation::Release
        )
    }) {
        if request.operation() == Operation::Ownership
            && intent::decode_ownership(request.bytes())
                .is_ok_and(|request| matches!(request.mode, intent::OwnershipMode::Acquire { .. }))
        {
            mediator.check_acquisition_debt()?;
        }
        drive(mediator, &request, false)?;
        if mediator.snapshot().phase == Phase::Fenced {
            return Ok(());
        }
    }
    if let Some(replay) = mediator.landed_replay()? {
        drive(mediator, replay.request(), true)?;
    }
    Ok(())
}

/// The prologue of an explicit recovery on a store that holds a carrier: its
/// retained requests settle as a start settles them, so a crash after an
/// adoption resumes the same takeover bytes and a matched landed refresh is
/// answered before any succession. An expired handshake is retired before
/// driving retained requests, and its retained fence stops the drive. A
/// carrier fenced on entry is left as it is, and a settlement answered by a
/// displacement of a release or landed refresh leaves its fenced carrier
/// for classification. A displaced ownership handshake stops the prologue.
/// # Errors
/// As the start's settlement, except a release or landed refresh's persisted
/// displacement.
pub fn recovery_prologue<R: WritableAuthority, P: OverlayIo>(
    mediator: &mut WritableStore<P>,
    remote: &R,
    runtime: &tokio::runtime::Runtime,
    scope: &Scope,
    public: &[u8; 32],
    clock: &impl Clock,
    rng: &mut impl Rng,
) -> Result<(), WritableStartError> {
    settle_recovery(mediator, clock, |mediator, request, landed_replay| {
        drive_inner(
            mediator,
            remote,
            runtime,
            scope,
            request,
            public,
            clock,
            rng,
            landed_replay,
            None,
        )
    })
}

/// [`recovery_prologue`] over any `drive`.
pub(crate) fn settle_recovery<P: OverlayIo>(
    mediator: &mut WritableStore<P>,
    clock: &impl Clock,
    drive: impl FnMut(&mut WritableStore<P>, &PendingIntent, bool) -> Result<(), WritableStartError>,
) -> Result<(), WritableStartError> {
    if mediator.snapshot().phase == Phase::Fenced {
        return Ok(());
    }
    let mut drive = drive;
    settle_retained(
        mediator,
        clock,
        |mediator, request, landed_replay| match drive(mediator, request, landed_replay) {
            Err(WritableStartError::Coordination(CoordinationError::Fenced { .. }))
                if (request.operation() == Operation::Release || landed_replay)
                    && mediator.snapshot().phase == Phase::Fenced =>
            {
                Ok(())
            }
            settled => settled,
        },
    )
}

pub(crate) fn run_before<T: Send>(
    runtime: &tokio::runtime::Runtime,
    deadline: Option<tokio::time::Instant>,
    work: impl std::future::Future<Output = T> + Send,
) -> Result<T, WritableStartError> {
    let Some(deadline) = deadline else {
        return Ok(runtime.block_on(work));
    };
    runtime
        .block_on(crate::TokioSyncRuntime.timeout_at(deadline, work))
        .map_err(|_| crate::sync::refused("SyncDeadline").into())
}

pub(crate) fn check_deadline(
    deadline: Option<tokio::time::Instant>,
) -> Result<(), WritableStartError> {
    if deadline.is_some_and(|deadline| crate::TokioSyncRuntime.now() >= deadline) {
        return Err(crate::sync::refused("SyncDeadline").into());
    }
    Ok(())
}

/// Settle a retained request. Release supplies a fixed monotonic deadline,
/// capped by any enclosing deadline. With a deadline, early dispatch admission
/// waits at least 10 ms or the remaining wall-clock delay, whichever is longer,
/// without spending an attempt. Check the deadline on wake.
/// Without a deadline, dispatch admission is single-pass and an early retry
/// returns `IntentRetryNotEligible`. Landed replay keeps its existing wall-clock
/// retry horizon.
#[expect(
    clippy::too_many_arguments,
    reason = "retained request and deterministic clock/RNG/transport seams"
)]
#[expect(
    clippy::too_many_lines,
    reason = "one retained-request loop keeps the fixed start deadline, expiry readback, wait, send and completion order visible"
)]
pub(crate) fn drive_inner<R: WritableAuthority, P: OverlayIo>(
    mediator: &mut WritableStore<P>,
    remote: &R,
    runtime: &tokio::runtime::Runtime,
    scope: &Scope,
    request: &PendingIntent,
    public: &[u8; 32],
    clock: &impl Clock,
    rng: &mut impl Rng,
    landed_replay: bool,
    deadline: Option<tokio::time::Instant>,
) -> Result<(), WritableStartError> {
    // A carrier has one Release slot. Its retained settlement uses one
    // monotonic budget through all waits and sends, independent of wall ticks.
    let release = request.operation() == Operation::Release;
    let deadline = if release {
        let bound = crate::TokioSyncRuntime
            .now()
            .checked_add(crate::DEFAULT_RESOLUTION_BOUND)
            .ok_or_else(|| refusal("IntentDeadlineOverflow"))?;
        Some(deadline.map_or(bound, |outer| outer.min(bound)))
    } else {
        deadline
    };
    let rewait = deadline.is_some();
    let replay_deadline = if landed_replay {
        let started = clock.now();
        let started = u64::try_from(started.secs)
            .ok()
            .and_then(|secs| secs.checked_mul(1000))
            .and_then(|millis| millis.checked_add(u64::from(started.nanos / 1_000_000)))
            .ok_or_else(|| refusal("IntentClockInvalid"))?;
        Some(
            started
                .checked_add(
                    u64::try_from(crate::DEFAULT_RESOLUTION_BOUND.as_millis())
                        .map_err(|_| refusal("IntentDeadlineOverflow"))?,
                )
                .ok_or_else(|| refusal("IntentDeadlineOverflow"))?,
        )
    } else {
        None
    };
    'settle: loop {
        check_deadline(deadline)?;
        let classification = if landed_replay {
            Some(
                mediator
                    .landed_replay()?
                    .ok_or_else(|| refusal("IntentRequestNotRetained"))?,
            )
        } else {
            None
        };
        let (eligible, pending_expires) = mediator
            .snapshot()
            .pending
            .iter()
            .find(|pending| pending.body == request.bytes())
            .map(|pending| (pending.eligible, pending.expires))
            .ok_or_else(|| refusal("IntentRequestNotRetained"))?;
        let expires = classification.as_ref().map_or(
            pending_expires,
            crate::writable_store::LandedReplay::expires,
        );
        let time = clock.now();
        let now = u64::try_from(time.secs)
            .ok()
            .and_then(|secs| secs.checked_mul(1000))
            .and_then(|millis| millis.checked_add(u64::from(time.nanos / 1_000_000)))
            .ok_or_else(|| refusal("IntentClockInvalid"))?;
        if landed_replay && now >= expires {
            let readback_reply =
                readback(remote, runtime, scope, request.volume(), public, deadline)?;
            let Verdict::Accepted(observed) = readback_reply
                .readback(request.volume(), |doc, prefix| {
                    verifies(public, doc, prefix)
                })
            else {
                return Err(invalid("WritableIntentDiscoveryInvalid"));
            };
            let row = unique_writer_row(&observed.rows, mediator.writer_uuid())?;
            mediator.settle_expired_landed_replay(
                classification
                    .as_ref()
                    .ok_or_else(|| refusal("IntentRequestNotRetained"))?,
                row,
                clock,
            )?;
            return Ok(());
        }
        if let Some(replay_deadline) = replay_deadline {
            if let Some(wait) =
                crate::writable_store::landed_replay_wait(now, eligible, replay_deadline)?
            {
                run_before(runtime, deadline, remote.writable_wait(wait))?;
                continue;
            }
        } else if eligible > now {
            run_before(runtime, deadline, remote.writable_wait(eligible - now))?;
            if release {
                continue;
            }
        }
        check_deadline(deadline)?;
        if rewait {
            while let Some(delay) = mediator.dispatch_inner(request, clock, landed_replay)? {
                let wait = delay.max(crate::writable_store::MIN_RETRY_WAIT_MS);
                run_before(runtime, deadline, remote.writable_wait(wait))?;
                check_deadline(deadline)?;
                if landed_replay {
                    continue 'settle;
                }
            }
        } else if landed_replay {
            mediator.dispatch_landed_replay(request, clock)?;
        } else {
            mediator.dispatch(request, clock)?;
        }
        check_deadline(deadline)?;
        let started = clock.now();
        let answer = run_before(
            runtime,
            deadline,
            remote.writable_send(scope, request, public),
        )?;
        let delay = answer
            .as_ref()
            .ok()
            .and_then(|reply| reply.retry_after())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
            .saturating_mul(1000);
        let completion = if landed_replay {
            mediator.complete_landed_replay(
                request,
                answer.as_ref().map_err(|error| *error),
                clock,
                rng,
                delay,
                elapsed(started, clock.now()),
            )?
        } else {
            mediator.complete(
                request,
                answer.as_ref().map_err(|error| *error),
                clock,
                rng,
                delay,
                elapsed(started, clock.now()),
            )?
        };
        check_deadline(deadline)?;
        match completion {
            IntentCompletion::Accepted(_) | IntentCompletion::TakeoverAbsent => return Ok(()),
            IntentCompletion::Overtaken(_) => return Err(refusal("WritableRecoveryRequired")),
            IntentCompletion::Unknown => (),
        }
    }
}

fn elapsed(start: root::Timestamp, end: root::Timestamp) -> Option<std::time::Duration> {
    let nanos =
        |time: root::Timestamp| i128::from(time.secs) * 1_000_000_000 + i128::from(time.nanos);
    u64::try_from(nanos(end) - nanos(start))
        .ok()
        .map(std::time::Duration::from_nanos)
}
pub(crate) fn overlay_base(
    snapshot: &granary_vfs::Snapshot,
) -> Result<Vec<OverlayEntry>, WritableStartError> {
    use granary_core::manifest::{EntryKind, Name};
    let root = snapshot.manifest_root();
    let mut queue = vec![(root, Vec::new())];
    let mut result = Vec::new();
    while let Some((directory, path)) = queue.pop() {
        let mut entries = Vec::new();
        snapshot
            .readdir(&directory, &directory, 2, |entry| {
                entries.push(entry);
                false
            })
            .map_err(|_| invalid("WritableSnapshotRefused"))?;
        for entry in entries {
            let mut at = path.clone();
            at.push(Name::new(entry.name.clone()).map_err(|_| invalid("WritableSnapshotRefused"))?);
            if let EntryKind::Dir { child } = &entry.kind {
                queue.push((*child, at.clone()));
            }
            let (kind, size, exec) = OverlayKind::from_manifest(entry.kind)
                .ok_or_else(|| invalid("WritableSnapshotRefused"))?;
            let inode = u64::try_from(result.len())
                .ok()
                .and_then(|count| count.checked_add(2))
                .ok_or_else(|| invalid("WritableSnapshotRefused"))?;
            result.push(OverlayEntry {
                path: at,
                inode,
                kind,
                stage_id: None,
                size,
                exec,
            });
        }
    }
    Ok(result)
}

fn mediated_capacity<P: OverlayIo>(
    overlay: &mut crate::WritableOverlay<'_, P>,
) -> Result<crate::OverlayObservation, OverlayError> {
    overlay.observation()
}

fn mediated_entries<P: OverlayIo>(
    overlay: &mut crate::WritableOverlay<'_, P>,
) -> Result<Vec<OverlayEntry>, OverlayError> {
    overlay.entries()
}

pub(crate) fn write_error(error: &CoordinationError) -> granary_fuse::WriteError {
    use granary_fuse::{MountError as E, WriteError};
    let error = match error {
        CoordinationError::Refused("ViewPending") => E::Io,
        CoordinationError::Fenced { .. } | CoordinationError::CommitFenced { .. } => E::Stale,
        CoordinationError::Overlay(OverlayError::PendingShrink) => {
            return WriteError::PendingShrink;
        }
        CoordinationError::Overlay(
            OverlayError::NoSpace | OverlayError::Refused("OverlayCapacityExhausted"),
        ) => E::NoSpace,
        CoordinationError::Overlay(OverlayError::MutationsClosed) => E::Closing,
        CoordinationError::Overlay(OverlayError::ContentCorrupt) => E::Corrupt,
        CoordinationError::Overlay(OverlayError::ContentUnavailable) => E::Unavailable,
        CoordinationError::Overlay(OverlayError::Io(error)) => match error.kind() {
            std::io::ErrorKind::PermissionDenied => E::Access,
            std::io::ErrorKind::StorageFull => E::NoSpace,
            std::io::ErrorKind::QuotaExceeded => E::Quota,
            _ => E::Io,
        },
        _ => match coordination_class(error) {
            FailureClass::Conflict => E::Stale,
            FailureClass::Corrupt => E::Corrupt,
            FailureClass::Unavailable => E::Unavailable,
            FailureClass::Refused => E::Access,
            FailureClass::Io | FailureClass::Internal => E::Io,
        },
    };
    WriteError::Backend(error)
}

pub(crate) fn mount_error(error: granary_fuse::WriteError) -> granary_fuse::MountError {
    match error {
        granary_fuse::WriteError::Backend(mount_error) => mount_error,
        _ => granary_fuse::MountError::Io,
    }
}

/// Read `[offset, offset + wanted)` in chunks no content read refuses for
/// their size; a short chunk is corrupt, as `wanted` never passes the end.
fn read_chunks(
    offset: u64,
    wanted: u64,
    mut chunk: impl FnMut(u64, usize) -> Result<Vec<u8>, OverlayError>,
) -> Result<Vec<u8>, OverlayError> {
    let mut bytes = Vec::new();
    let mut read = 0;
    while read < wanted {
        let length = usize::try_from((wanted - read).min(65536))
            .map_err(|_| OverlayError::ContentCorrupt)?;
        let at = offset
            .checked_add(read)
            .ok_or(OverlayError::ContentCorrupt)?;
        let next = chunk(at, length)?;
        if next.len() != length {
            return Err(OverlayError::ContentCorrupt);
        }
        read += next.len() as u64;
        bytes.extend(next);
    }
    Ok(bytes)
}

fn query_value<T>(
    query: crate::overlay_store::OverlayQuery<T>,
) -> Result<T, granary_fuse::WriteError> {
    use crate::overlay_store::OverlayQuery;
    use granary_fuse::{MountError, WriteError};
    match query {
        OverlayQuery::Found(value) => Ok(value),
        OverlayQuery::Missing => Err(WriteError::Missing),
        OverlayQuery::NotDirectory => Err(WriteError::NotDirectory),
        OverlayQuery::Changed => Err(WriteError::Backend(MountError::PlanningExhausted)),
    }
}

fn query_metadata(query: crate::overlay_store::OverlayQueryEntry) -> granary_fuse::OverlayMetadata {
    let inode = query.entry.as_ref().map_or(0, |entry| entry.inode);
    let node = if let Some(entry) = query.entry {
        overlay_node(entry)
    } else {
        granary_fuse::OverlayNode {
            path: Vec::new(),
            kind: granary_vfs::NodeKind::Dir,
            size: 4096,
            exec: false,
            stage: None,
        }
    };
    granary_fuse::OverlayMetadata {
        inode,
        node,
        nlink: query.nlink,
    }
}

fn overlay_node(entry: OverlayEntry) -> granary_fuse::OverlayNode {
    let (kind, size) = match entry.kind {
        OverlayKind::File { .. } => (granary_vfs::NodeKind::File, entry.size),
        OverlayKind::Directory => (granary_vfs::NodeKind::Dir, 4096),
        OverlayKind::Symlink { target } => {
            (granary_vfs::NodeKind::Symlink, u64::from(target.wire_len()))
        }
    };
    granary_fuse::OverlayNode {
        path: entry.path,
        kind,
        size,
        exec: entry.exec,
        stage: entry.stage_id,
    }
}

/// Truncate a stage and record an exec change in one transaction, so a
/// shutdown's latch finds neither or both, and say whether the truncate
/// landed beside the transaction's result. Nothing to do runs no
/// transaction.
fn set_size_and_exec<P: OverlayIo>(
    mediator: &SharedWritableStore<P>,
    truncation: Option<(u64, u64)>,
    exec: Option<(bool, granary_core::overlay_journal::Location)>,
) -> (bool, Result<(), CoordinationError>) {
    if truncation.is_none() && exec.is_none() {
        return (false, Ok(()));
    }
    let mut truncated = false;
    let result = mediator.overlay_transaction(|overlay| {
        if let Some((stage, size)) = truncation {
            overlay.truncate(stage, size)?;
            truncated = true;
        }
        if let Some((exec, at)) = exec {
            overlay.namespace_record(granary_core::overlay_journal::Record::SetattrExec {
                at,
                exec,
            })?;
        }
        Ok(())
    });
    (truncated, result)
}

fn journal_location(
    path: &[granary_core::manifest::Name],
) -> Result<granary_core::overlay_journal::Location, granary_fuse::WriteError> {
    let (name, parent) = path.split_last().ok_or(granary_fuse::WriteError::Invalid)?;
    Ok(granary_core::overlay_journal::Location {
        name: name.clone(),
        parent: granary_core::overlay_journal::Parent::new(parent.to_vec())
            .map_err(|_| granary_fuse::WriteError::Invalid)?,
    })
}

fn pinned_files(
    snapshot: &granary_vfs::Snapshot,
    base: &[OverlayEntry],
) -> Result<
    std::collections::BTreeMap<GrainId, (u64, granary_core::manifest::FileGrains)>,
    WritableStartError,
> {
    use granary_core::manifest::EntryKind;
    let mut files = std::collections::BTreeMap::new();
    for node in base {
        if let OverlayKind::File { content: Some(id) } = node.kind {
            let mut directory = snapshot.manifest_root();
            let (last, parents) = node
                .path
                .split_last()
                .ok_or_else(|| invalid("WritableSnapshotRefused"))?;
            for parent in parents {
                let entry = snapshot
                    .lookup(&directory, parent.as_bytes())
                    .map_err(|_| invalid("WritableSnapshotRefused"))?;
                let EntryKind::Dir { child } = entry.kind else {
                    return Err(invalid("WritableSnapshotRefused"));
                };
                directory = child;
            }
            let entry = snapshot
                .lookup(&directory, last.as_bytes())
                .map_err(|_| invalid("WritableSnapshotRefused"))?;
            let EntryKind::File { size, grains, .. } = entry.kind else {
                return Err(invalid("WritableSnapshotRefused"));
            };
            files.insert(id, (size, grains));
        }
    }
    Ok(files)
}

impl<R: RootStore + BinStore + Send + 'static, P: OverlayIo + Send + 'static> WritableMount<R, P> {
    #[cfg(test)]
    pub(crate) fn object_attached_for_test(&self, object: u64) -> Option<bool> {
        self.objects.get(&object).map(|held| held.attached)
    }

    fn path_entry(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<OverlayEntry, granary_fuse::WriteError> {
        self.mediator
            .overlay_transaction(|overlay| overlay.query_path(path))
            .map_err(|error| write_error(&error))
            .and_then(query_value)?
            .entry
            .ok_or(granary_fuse::WriteError::Missing)
    }

    fn child_entry(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<
        (
            granary_core::overlay_journal::Location,
            Option<OverlayEntry>,
        ),
        granary_fuse::WriteError,
    > {
        let at = journal_location(path)?;
        let query = self
            .mediator
            .overlay_transaction(|overlay| overlay.query_lookup(at.parent.names(), &at.name))
            .map_err(|error| write_error(&error))?;
        if matches!(query, crate::overlay_store::OverlayQuery::Missing) {
            // Distinguish an absent child from an absent parent before admission.
            self.mediator
                .overlay_transaction(|overlay| overlay.query_has_children(at.parent.names()))
                .map_err(|error| write_error(&error))
                .and_then(query_value)?;
            return Ok((at, None));
        }
        Ok((at, query_value(query)?.entry))
    }

    fn has_children(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<bool, granary_fuse::WriteError> {
        self.mediator
            .overlay_transaction(|overlay| overlay.query_has_children(path))
            .map_err(|error| write_error(&error))
            .and_then(query_value)
    }

    fn refresh_object(&mut self, object: u64) -> Result<(), granary_fuse::WriteError> {
        let query = self
            .mediator
            .overlay_transaction(|overlay| overlay.query_inode(object))
            .map_err(|error| write_error(&error))?;
        let held = self
            .objects
            .get_mut(&object)
            .ok_or(granary_fuse::WriteError::Missing)?;
        if matches!(query, crate::overlay_store::OverlayQuery::Missing) {
            held.attached = false;
        } else if held.attached {
            held.node = query_value(query)?
                .entry
                .ok_or(granary_fuse::WriteError::Missing)?;
        } else {
            // Once detached, a held stage never acquires a namespace occupant.
            query_value(query)?;
        }
        Ok(())
    }

    fn refresh_bound_object(&mut self, object: u64) -> Result<(), granary_fuse::WriteError> {
        let expected = &self
            .objects
            .get(&object)
            .ok_or(granary_fuse::WriteError::Missing)?
            .node;
        let (query, view) = self
            .mediator
            .overlay_transaction(|overlay| overlay.preparation_view(expected))
            .map_err(|error| write_error(&error))?;
        self.admit_mount_view(view)?;
        let held = self
            .objects
            .get_mut(&object)
            .ok_or(granary_fuse::WriteError::Missing)?;
        if matches!(query, crate::overlay_store::OverlayQuery::Missing) {
            held.attached = false;
        } else {
            let changed = query_value(query)?;
            if held.attached
                && let Some(node) = changed
            {
                held.node = node;
            }
        }
        Ok(())
    }

    fn bound_mutate(
        &mut self,
        object: u64,
        size: Option<u64>,
        exec: Option<bool>,
        write: Option<(u64, &[u8], bool)>,
    ) -> Result<(), granary_fuse::WriteError> {
        self.refresh_bound_object(object)?;
        let held = self
            .objects
            .get_mut(&object)
            .ok_or(granary_fuse::WriteError::Missing)?;
        let attached = held.attached;
        let result = Self::bound_file_effect(
            &self.mediator,
            &mut self.completion_tokens,
            held,
            size,
            exec,
            write,
        );
        if attached {
            // Refresh after partial effects and typed refusals too.
            self.refresh_bound_object(object)?;
        }
        result
    }

    fn bound_stage(
        mediator: &SharedWritableStore<P>,
        completions: &mut CompletionTokens,
        held: &mut OpenObject,
    ) -> Result<u64, granary_fuse::WriteError> {
        let stage = if let Some(stage) = held.node.stage_id {
            stage
        } else if held.attached {
            let at = journal_location(&held.node.path)?;
            Self::copy_up(mediator, completions, &held.node, at)?
        } else {
            return Err(granary_fuse::WriteError::Invalid);
        };
        if held.attached && !held.stage_holds {
            // Every handle keeps its hold on the single shared stage.
            mediator
                .promote_holds(&held.node, held.handles)
                .map_err(|error| write_error(&error))?;
            held.node.stage_id = Some(stage);
            held.stage_holds = true;
        }
        Ok(stage)
    }

    fn bound_file_effect(
        mediator: &SharedWritableStore<P>,
        completions: &mut CompletionTokens,
        held: &mut OpenObject,
        size: Option<u64>,
        exec: Option<bool>,
        write: Option<(u64, &[u8], bool)>,
    ) -> Result<(), granary_fuse::WriteError> {
        use granary_fuse::WriteError as E;
        if held.replaced.is_some() {
            return Err(E::Backend(granary_fuse::MountError::Stale));
        }
        if !held.attached && exec.is_some_and(|exec| exec != held.node.exec) {
            return Err(E::Unsupported);
        }
        if held.attached {
            mediator
                .check_readiness()
                .map_err(|error| write_error(&error))?;
            if size.is_some_and(|size| size > granary_core::overlay_journal::SIZE_MAX) {
                return Err(E::TooBig);
            }
        }
        let mut new_size = held.node.size;
        if let Some((offset, bytes, append)) = write {
            let offset = if append { new_size } else { offset };
            if bytes.len() as u64 > granary_core::overlay_journal::EXTENT_LEN_MAX {
                return Err(E::Invalid);
            }
            let end = offset.checked_add(bytes.len() as u64).ok_or(E::Invalid)?;
            if offset > granary_core::overlay_journal::SIZE_MAX
                || end > granary_core::overlay_journal::SIZE_MAX
            {
                return Err(E::TooBig);
            }
            if held.attached && bytes.is_empty() {
                return Ok(());
            }
            let stage = Self::bound_stage(mediator, completions, held)?;
            mediator
                .overlay_transaction(|overlay| overlay.write(stage, offset, bytes))
                .map_err(|error| write_error(&error))?;
            if !bytes.is_empty() {
                new_size = new_size.max(end);
            }
        }
        let truncation = if let Some(size) = size {
            if size > granary_core::overlay_journal::SIZE_MAX {
                return Err(E::TooBig);
            }
            Some((Self::bound_stage(mediator, completions, held)?, size))
        } else {
            None
        };
        let exec = exec.filter(|exec| held.attached && *exec != held.node.exec);
        let change = exec
            .map(|exec| journal_location(&held.node.path).map(|at| (exec, at)))
            .transpose()?;
        let (truncated, result) = set_size_and_exec(mediator, truncation, change);
        if let (Some((_, size)), true) = (truncation, truncated) {
            new_size = size;
        }
        held.node.size = new_size;
        result.map_err(|error| write_error(&error))?;
        if let Some(exec) = exec {
            held.node.exec = exec;
        }
        Ok(())
    }

    fn nodes(&mut self) -> Result<Vec<OverlayEntry>, granary_fuse::WriteError> {
        self.mediator
            .overlay_transaction(mediated_entries)
            .map_err(|error| write_error(&error))
    }

    fn view_error(&mut self, error: &CoordinationError) -> granary_fuse::WriteError {
        if matches!(error, CoordinationError::Refused("ViewPending")) {
            let _ = self.admit_mediator_view();
        }
        write_error(error)
    }

    fn materialize(&mut self, node: &mut OverlayEntry) -> Result<(), granary_fuse::WriteError> {
        self.check_mount_view()?;
        if node.stage_id.is_some() {
            return Ok(());
        }
        for _ in 0..3 {
            #[cfg(test)]
            {
                self.planning_attempts += 1;
                self.planning_work_boundaries
                    .push(crate::overlay_store::work::query_snapshot());
            }
            let (current, view) = self
                .mediator
                .overlay_transaction(|overlay| overlay.preparation_view(node))
                .map_err(|error| self.view_error(&error))?;
            let view = self.admit_mount_view(view)?;
            if let Some(current) = query_value(current)? {
                *node = current;
            }
            if node.stage_id.is_some() {
                return Ok(());
            }
            let OverlayKind::File {
                content: Some(content),
            } = node.kind
            else {
                return Err(granary_fuse::WriteError::Invalid);
            };
            #[cfg(test)]
            if let Some(mut hook) = self.before_materialize_hook.take() {
                hook(&self.mediator);
            }
            if let Err(error) = self.materialize_once(node, None) {
                self.completion_tokens.remove(content);
                return Err(error);
            }
            #[cfg(test)]
            self.change_planning_context(node)?;
            let (current, after_view) = self
                .mediator
                .overlay_transaction(|overlay| overlay.preparation_view(node))
                .map_err(|error| self.view_error(&error))?;
            let after_view = self.admit_mount_view(after_view)?;
            let current = query_value(current)?;
            if after_view.generation != view.generation {
                if let Some(current) = current {
                    *node = current;
                }
                continue;
            }
            let Some(current) = current else {
                self.completion_tokens.completed(content);
                return Ok(());
            };
            *node = current;
        }
        Err(granary_fuse::WriteError::Backend(
            granary_fuse::MountError::PlanningExhausted,
        ))
    }

    #[cfg(test)]
    fn change_planning_context(
        &mut self,
        node: &OverlayEntry,
    ) -> Result<(), granary_fuse::WriteError> {
        if let Some(mut hook) = self.planning_hook.take() {
            hook(&self.mediator);
        }
        if self.planning_replace {
            self.planning_replace = false;
            let at = journal_location(&node.path)?;
            self.mediator
                .overlay_transaction(|overlay| {
                    overlay.namespace_record(granary_core::overlay_journal::Record::Delete {
                        at: at.clone(),
                        kind: granary_core::overlay_journal::DeleteKind::File {
                            stage_id: node.stage_id,
                        },
                    })?;
                    overlay.create_file(at, false)?;
                    Ok(())
                })
                .map_err(|error| write_error(&error))?;
        }
        if let Some(path) = self.planning_move.take() {
            let from = journal_location(&node.path)?;
            let to = journal_location(&path)?;
            self.mediator
                .overlay_transaction(|overlay| {
                    overlay
                        .namespace_record(granary_core::overlay_journal::Record::Move { from, to })
                })
                .map_err(|error| write_error(&error))?;
        }
        if self.planning_changes_remaining > 0 {
            self.planning_changes_remaining -= 1;
            let at = journal_location(&node.path)?;
            self.mediator
                .overlay_transaction(|overlay| {
                    overlay.namespace_record(granary_core::overlay_journal::Record::SetattrExec {
                        at,
                        exec: !node.exec,
                    })
                })
                .map_err(|error| write_error(&error))?;
        }
        Ok(())
    }

    /// Store `node`'s clean content locally from the view's material, or
    /// from `replaced`, the material a replaced object opened in. Each list
    /// node is stored once however many lists name it, and each grain is
    /// probed once however many references repeat it, so the work is bounded
    /// by the file's distinct nodes and grains, not by its references. No
    /// offset is computed here: reads place each reference from the stored
    /// lists.
    #[expect(
        clippy::too_many_lines,
        reason = "one walk from payload to grains, from either material"
    )]
    fn materialize_once(
        &mut self,
        node: &OverlayEntry,
        replaced: Option<&crate::writable_store::ViewContext>,
    ) -> Result<(), granary_fuse::WriteError> {
        use granary_core::encoding::{ObjectType, open_envelope};
        use granary_core::manifest::{FileGrains, decode_grain_list_index, decode_grain_list_leaf};
        use granary_fuse::{MountError, WriteError};
        if node.stage_id.is_some() {
            return Ok(());
        }
        let OverlayKind::File {
            content: Some(content),
        } = node.kind
        else {
            return Err(WriteError::Invalid);
        };
        // The pin is read before admission, so a missing or mismatched file
        // is answered without latching the view or clearing tokens.
        let pinned;
        let pin = if let Some(material) = replaced {
            material
        } else {
            pinned = self
                .mediator
                .with(|local| sync::pinned(local))
                .map_err(|error| write_error(&error))?;
            &*pinned
        };
        let (size, grains) = pin
            .pin_files
            .get(&content)
            .ok_or(WriteError::Backend(MountError::Unavailable))?;
        if *size != node.size {
            return Err(WriteError::Backend(MountError::Corrupt));
        }
        self.admit_mediator_view()?;
        if self.completion_tokens.contains(content) {
            return Ok(());
        }
        let (size, grains) = (*size, grains.clone());
        #[cfg(test)]
        {
            self.materialization_passes += 1;
        }
        let payload = granary_core::manifest::node::file_payload(size, &grains)
            .map_err(|_| WriteError::Backend(MountError::Corrupt))?;
        self.mediator
            .put_immutable(content, &payload)
            .map_err(|error| write_error(&error))?;
        let mut refs = Vec::new();
        let mut grain_ids = std::collections::BTreeSet::new();
        let mut keep = |listed: Vec<granary_core::manifest::GrainRef>| {
            refs.extend(
                listed
                    .into_iter()
                    .filter(|grain| grain_ids.insert(grain.id)),
            );
        };
        let mut lists = Vec::new();
        let mut expanded = std::collections::BTreeSet::new();
        match grains {
            FileGrains::Inline(inline) => keep(inline),
            FileGrains::Spill { root, .. } => lists.push((root, 0u32)),
        }
        while let Some((id, depth)) = lists.pop() {
            if depth > granary_core::manifest::DEPTH_MAX {
                return Err(WriteError::Backend(MountError::Corrupt));
            }
            if !expanded.insert(id) {
                continue;
            }
            #[cfg(test)]
            PREPARATION_WORK.with(|cell| {
                let (lists, probes) = cell.get();
                cell.set((lists + 1, probes));
            });
            let bytes = pin
                .pin_nodes
                .get(&id)
                .ok_or(WriteError::Backend(MountError::Unavailable))?;
            self.mediator
                .put_immutable(id, bytes)
                .map_err(|error| write_error(&error))?;
            let (object_type, body) =
                open_envelope(bytes).map_err(|_| WriteError::Backend(MountError::Corrupt))?;
            match object_type {
                ObjectType::GrainListLeaf => keep(
                    decode_grain_list_leaf(body)
                        .map_err(|_| WriteError::Backend(MountError::Corrupt))?,
                ),
                ObjectType::GrainListIndex => {
                    for child in decode_grain_list_index(body)
                        .map_err(|_| WriteError::Backend(MountError::Corrupt))?
                    {
                        if !expanded.contains(&child.child) {
                            lists.push((child.child, depth + 1));
                        }
                    }
                }
                _ => return Err(WriteError::Backend(MountError::Corrupt)),
            }
        }
        // Grains resolve through the pin's binmap, which a landing moves.
        let binmap = (&pin.entries, &*pin.bins);
        for grain in refs {
            #[cfg(test)]
            PREPARATION_WORK.with(|cell| {
                let (lists, probes) = cell.get();
                cell.set((lists, probes + 1));
            });
            let present = self
                .mediator
                .overlay_transaction(|overlay| Ok(overlay.content_exists(&grain.id)))
                .map_err(|error| write_error(&error))?;
            if !present {
                // Transport and cache access run with no mediator facade alive.
                let bytes = self
                    .session
                    .fetch_mapped_grain(Some(binmap), &grain.id, grain.unpacked_len)
                    .map_err(|_| WriteError::Backend(MountError::Unavailable))?;
                self.mediator
                    .put_immutable(grain.id, &bytes)
                    .map_err(|error| write_error(&error))?;
            }
        }
        Ok(())
    }

    fn copy_up(
        mediator: &SharedWritableStore<P>,
        completions: &mut CompletionTokens,
        node: &OverlayEntry,
        at: granary_core::overlay_journal::Location,
    ) -> Result<u64, granary_fuse::WriteError> {
        let result = mediator.overlay_transaction(|overlay| overlay.copy_up(at));
        if matches!(
            result,
            Err(CoordinationError::Overlay(
                OverlayError::ContentUnavailable | OverlayError::ContentCorrupt
            ))
        ) && let OverlayKind::File {
            content: Some(content),
        } = node.kind
        {
            completions.remove(content);
        }
        result.map_err(|error| write_error(&error))
    }

    fn staged(&mut self, node: &OverlayEntry) -> Result<u64, granary_fuse::WriteError> {
        let stage = if let Some(stage) = node.stage_id {
            stage
        } else {
            let at = journal_location(&node.path)?;
            Self::copy_up(&self.mediator, &mut self.completion_tokens, node, at)?
        };
        let handles = self
            .objects
            .get(&node.inode)
            .filter(|object| !object.stage_holds)
            .map_or(0, |object| object.handles);
        self.mediator
            .promote_holds(node, handles)
            .map_err(|error| write_error(&error))?;
        if let Some(object) = self.objects.get_mut(&node.inode) {
            object.node.stage_id = Some(stage);
            object.stage_holds = true;
        }
        Ok(stage)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "validate each supported operation before its mediated journal effect"
    )]
    fn mutate(
        &mut self,
        operation: granary_fuse::OverlayMutation<'_>,
    ) -> Result<(), granary_fuse::WriteError> {
        use granary_core::overlay_journal::{
            CreateKind, DeleteKind, EXTENT_LEN_MAX, Record, SIZE_MAX,
        };
        use granary_fuse::{OverlayMutation as M, WriteError as E};
        use granary_vfs::NodeKind;
        self.check_mount_view()?;
        match operation {
            M::BoundWrite {
                object,
                offset,
                bytes,
                append,
            } => return self.bound_mutate(object, None, None, Some((offset, bytes, append))),
            M::BoundSetattr { object, size, exec } => {
                return self.bound_mutate(object, size, exec, None);
            }
            M::Symlink { path, target } => {
                let (at, existing) = self.child_entry(path)?;
                if existing.is_some() {
                    return Err(E::Exists);
                }
                if target.as_bytes().len() > 4095 {
                    return Err(E::Invalid);
                }
                self.mediator
                    .overlay_transaction(|overlay| {
                        overlay.namespace_record(Record::Create {
                            at,
                            kind: CreateKind::Symlink {
                                target: target.clone(),
                            },
                        })
                    })
                    .map_err(|error| write_error(&error))?;
            }
            M::Create { path, kind, exec } => {
                if kind == NodeKind::Symlink {
                    return Err(E::Unsupported);
                }
                let (at, existing) = self.child_entry(path)?;
                if existing.is_some() {
                    return Err(E::Exists);
                }
                self.mediator
                    .overlay_transaction(|overlay| match kind {
                        NodeKind::File => overlay.create_file(at, exec).map(|_| ()),
                        NodeKind::Dir => overlay
                            .namespace_record(Record::Create {
                                at,
                                kind: CreateKind::Dir,
                            })
                            .map(|_| ()),
                        NodeKind::Symlink => {
                            Err(OverlayError::refused("unsupported creation kind"))
                        }
                    })
                    .map_err(|error| write_error(&error))?;
            }
            M::Write {
                path,
                offset,
                bytes,
                append,
            } => {
                let node = self.path_entry(path)?;
                if !matches!(node.kind, OverlayKind::File { .. }) {
                    return Err(E::IsDirectory);
                }
                let offset = if append { node.size } else { offset };
                if bytes.len() as u64 > EXTENT_LEN_MAX {
                    return Err(E::Invalid);
                }
                let end = offset.checked_add(bytes.len() as u64).ok_or(E::Invalid)?;
                if offset > SIZE_MAX || end > SIZE_MAX {
                    return Err(E::TooBig);
                }
                if bytes.is_empty() {
                    return Ok(());
                }
                let stage = self.staged(&node)?;
                self.mediator
                    .overlay_transaction(|overlay| overlay.write(stage, offset, bytes).map(|_| ()))
                    .map_err(|error| write_error(&error))?;
            }
            M::Setattr { path, size, exec } => {
                let node = self.path_entry(path)?;
                if !matches!(node.kind, OverlayKind::File { .. }) {
                    return Err(E::IsDirectory);
                }
                if size.is_some_and(|size| size > SIZE_MAX) {
                    return Err(E::TooBig);
                }
                let truncation = size
                    .map(|size| self.staged(&node).map(|stage| (stage, size)))
                    .transpose()?;
                let change = exec
                    .filter(|exec| *exec != node.exec)
                    .map(|exec| journal_location(path).map(|at| (exec, at)))
                    .transpose()?;
                set_size_and_exec(&self.mediator, truncation, change)
                    .1
                    .map_err(|error| write_error(&error))?;
            }
            M::Remove { path, directory } => {
                let (at, node) = self.child_entry(path)?;
                let node = node.ok_or(E::Missing)?;
                let kind = match (&node.kind, directory) {
                    (OverlayKind::Directory, true) => {
                        if self.has_children(path)? {
                            return Err(E::NotEmpty);
                        }
                        DeleteKind::Dir
                    }
                    (OverlayKind::Directory, false) => return Err(E::IsDirectory),
                    (_, true) => return Err(E::NotDirectory),
                    (OverlayKind::File { .. }, false) => DeleteKind::File {
                        stage_id: if self.objects.contains_key(&node.inode)
                            || self
                                .mediator
                                .leased(node.inode)
                                .map_err(|error| write_error(&error))?
                        {
                            Some(self.staged(&node)?)
                        } else {
                            node.stage_id
                        },
                    },
                    (OverlayKind::Symlink { .. }, false) => DeleteKind::Symlink,
                };
                self.mediator
                    .overlay_transaction(|overlay| {
                        overlay
                            .namespace_record(Record::Delete { at, kind })
                            .map(|_| ())
                    })
                    .map_err(|error| write_error(&error))?;
            }
            M::Rename {
                from,
                to,
                no_replace,
            } => {
                let (from_at, source) = self.child_entry(from)?;
                let (to_at, target) = self.child_entry(to)?;
                let source = source.ok_or(E::Missing)?;
                if no_replace && target.is_some() {
                    return Err(E::Exists);
                }
                if from == to {
                    return Ok(());
                }
                if to.starts_with(from) {
                    return Err(E::Invalid);
                }
                if let Some(target) = &target {
                    match (&source.kind, &target.kind) {
                        (OverlayKind::Directory, OverlayKind::Directory) => {
                            if self.has_children(to)? {
                                return Err(E::NotEmpty);
                            }
                        }
                        (OverlayKind::Directory, _) => return Err(E::NotDirectory),
                        (_, OverlayKind::Directory) => return Err(E::IsDirectory),
                        _ => (),
                    }
                }
                if let Some(target) = &target
                    && matches!(target.kind, OverlayKind::File { .. })
                    && (self.objects.contains_key(&target.inode)
                        || self
                            .mediator
                            .leased(target.inode)
                            .map_err(|error| write_error(&error))?)
                {
                    self.staged(target)?;
                }
                let record = if target.is_some() {
                    Record::Replace {
                        from: from_at,
                        to: to_at,
                    }
                } else {
                    Record::Move {
                        from: from_at,
                        to: to_at,
                    }
                };
                self.mediator
                    .overlay_transaction(|overlay| overlay.namespace_record(record).map(|_| ()))
                    .map_err(|error| write_error(&error))?;
            }
        }
        Ok(())
    }
}
