// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use crate::{
    AuthorityError, HttpStore, PublicationStore, PublicationStoreError, PublishRequest,
    PublishResponse, StatusResponse,
};
use granary_core::{
    binstore::BinStore,
    clock::Clock,
    grainsource::GrainSource,
    hash::GrainId,
    retained_submission::{Completion, Scope, Submission},
    root::VolumeName,
    rootstore::{RootStore, RootStoreError},
    secure_random::SecureRandom,
};
use granary_store::crypto::{SigningKey, TrustedKeys};
use std::{collections::BTreeMap, future::Future, pin::Pin, time::Duration};

/// Charged dispatches per ordinary drive, or across the lifetime of one mount commit.
pub(crate) const DISPATCH_ATTEMPTS: u32 = 8;
pub(crate) const MAX_UNAVAILABLE_EXEMPTIONS: u16 = 64;

pub(crate) fn charged_attempts(attempts: u64, attempts_at_start: u64, record: &Submission) -> u64 {
    let credit = u64::from(
        record
            .unavailable_exemptions
            .min(MAX_UNAVAILABLE_EXEMPTIONS),
    )
    .min(attempts_at_start);
    attempts.saturating_sub(credit)
}

/// Evidence that a validated retained generation rules out every candidate write.
#[derive(Debug)]
pub struct NoWriteProof {
    publication: [u8; 16],
    candidate: granary_core::hash::GrainId,
    attempts: u64,
}
impl NoWriteProof {
    /// Derive from a retained submission whose saved answers prove no write.
    /// The caller supplies a freshly loaded generation and the journal attempt
    /// count under the commit lock. Replacement requires that count unchanged.
    #[must_use]
    pub fn from_submission(record: &Submission, attempts: u64) -> Option<Self> {
        granary_core::retained_submission::validate(record).ok()?;
        (!record.is_complete()
            && record
                .candidates
                .iter()
                .all(|candidate| candidate.evidence.never_decided()))
        .then(|| Self {
            publication: record.publication_id,
            candidate: granary_core::hash::GrainId::of(&record.frozen.initial_root),
            attempts,
        })
    }
    pub(crate) fn matches(
        &self,
        publication: [u8; 16],
        candidate: granary_core::hash::GrainId,
        attempts: u64,
    ) -> bool {
        self.publication == publication && self.candidate == candidate && self.attempts == attempts
    }
}

/// Evidence authorizing archival and rejection of an unlanded boundary.
#[derive(Debug)]
pub enum RejectionProof {
    NoWrite(NoWriteProof),
    NeverLanded(super::NeverLandedProof),
}
impl RejectionProof {
    pub(crate) fn matches(&self, publication: [u8; 16], candidate: GrainId, attempts: u64) -> bool {
        match self {
            Self::NoWrite(proof) => proof.matches(publication, candidate, attempts),
            Self::NeverLanded(proof) => proof.matches(publication, candidate, attempts),
        }
    }
    pub(crate) fn matches_submission(&self, record: &Submission) -> bool {
        match self {
            Self::NoWrite(proof) => NoWriteProof::from_submission(record, proof.attempts)
                .is_some_and(|fresh| {
                    fresh.matches(proof.publication, proof.candidate, proof.attempts)
                }),
            Self::NeverLanded(proof) => proof.matches_submission(record),
        }
    }
}

/// Retry-free authority and immutable object operations. Implementations must
/// preserve the checks and whole-call bounds of the HTTP adapter.
pub trait AuthorityTransport: RootStore + BinStore {
    /// Send exactly once; an error supplies no no-write evidence.
    /// # Cancellation safety
    /// Dropping may leave a decided request. The journal must precede this call.
    fn publish_once(
        &self,
        request: &PublishRequest,
    ) -> impl Future<Output = Result<PublishResponse, AuthorityError>> + Send;
    /// Read a diagnostic snapshot, never trusted head or landing evidence.
    /// # Cancellation safety
    /// Dropping abandons this observation and changes no client state.
    fn status_once(
        &self,
        volume: &str,
    ) -> impl Future<Output = Result<StatusResponse, AuthorityError>> + Send;
    /// One bounded root read, with no automatic retry.
    /// # Cancellation safety
    /// Dropping leaves the journal's probe-started marker unresolved.
    fn probe_root_once(
        &self,
        volume: &str,
        seq: u64,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, RootStoreError>> + Send;
}
impl AuthorityTransport for HttpStore {
    async fn publish_once(&self, r: &PublishRequest) -> Result<PublishResponse, AuthorityError> {
        HttpStore::publish_once(self, r).await
    }
    async fn status_once(&self, v: &str) -> Result<StatusResponse, AuthorityError> {
        HttpStore::status_once(self, v).await
    }
    async fn probe_root_once(&self, v: &str, n: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        HttpStore::probe_root_once(self, v, n).await
    }
}

/// Full-generation barriers under one exclusive owner. A failed mutation must
/// poison the handle; only a fresh handle and a synced load may resume it.
pub trait PublicationJournal: GrainSource {
    /// Check the caller's remaining budget before reserving a publish attempt.
    /// # Errors
    /// The remaining drive budget cannot cover the journal's dispatch floor.
    fn check_dispatch_deadline(&self, _root_bytes: u64) -> Result<(), RecoveryError> {
        Ok(())
    }
    /// Keep checking the dispatch deadline once all unavailable exemptions are spent.
    fn check_dispatch_deadline_at_cap(&self) -> bool {
        false
    }
    /// Observe an additional attempt after its durable save, immediately before dispatch.
    fn retry(&mut self, _attempt: u32, _reason: crate::RetryReason) {}
    /// Decide after a checked unavailable answer whether a live drive can
    /// exempt it from the dispatch budget. Ordinary recovery charges every send.
    fn unavailable_window_open(&mut self, _record: &Submission) -> bool {
        false
    }
    /// Refuse generic recovery of a publication owned by an open mount commit.
    /// # Errors
    /// Journal custody, decoding, read failure or mount ownership.
    fn check_generic_resume(&mut self, _record: &Submission) -> Result<(), PublicationStoreError> {
        Ok(())
    }
    /// Durable mount dispatch reservations; ordinary publications have no lifetime cap.
    /// # Errors
    /// Missing boundary, fencing, custody or journal read failure.
    fn commit_attempts(
        &mut self,
        _publication: [u8; 16],
    ) -> Result<Option<u64>, PublicationStoreError> {
        Ok(None)
    }
    /// Load the exact scope, refuse unresolved foreign scopes, and sync a fresh generation.
    /// # Errors
    /// Ownership, decoding or persistence failure.
    fn load(
        &mut self,
        scope: &Scope,
        volume: &VolumeName,
    ) -> Result<Option<Submission>, PublicationStoreError>;
    /// Begin without overwriting an unresolved publication in any scope.
    /// # Errors
    /// Ownership, identity, format or persistence failure.
    fn begin(&mut self, record: &Submission) -> Result<(), PublicationStoreError>;
    /// Select the manifest for a rebase. Store commits recompute their sealed
    /// namespace; whole-tree publications retain their frozen target.
    /// # Errors
    /// Invalid ancestry, conflicting names or unavailable content.
    /// # Cancellation safety
    /// Dropping may leave immutable objects cached; the retained record is unchanged.
    fn rebase_manifest(
        &mut self,
        frozen: &granary_core::retained_submission::FrozenIntent,
        _parent: Option<granary_core::hash::GrainId>,
        _seq: u64,
    ) -> impl Future<Output = Result<granary_core::hash::GrainId, PublicationStoreError>> {
        async {
            granary_core::root::decode_root(&frozen.initial_root)
                .map(|doc| doc.manifest_root)
                .map_err(|error| PublicationStoreError {
                    path: "journal".into(),
                    kind: crate::PublicationStoreErrorKind::Refused,
                    reason: error.to_string(),
                })
        }
    }
    /// Replace atomically, preserving publication identity and frozen intent.
    /// # Errors
    /// Stale generation, terminal completion, format or persistence failure.
    fn replace(
        &mut self,
        generation: u64,
        record: &Submission,
    ) -> impl Future<Output = Result<(), PublicationStoreError>>;
    /// The verified set of a journal that recovers a lost store's content:
    /// reconstruction and a merged candidate's check then read manifest
    /// structure nodes through signed binmaps and never fetch file grains.
    /// `None`, the default, keeps the whole verified closure walk.
    fn recovered(&mut self) -> Option<&mut RecoveredObjects> {
        None
    }
    /// Store one object the recovery verified; only a journal with a
    /// verified set holds a store to receive it.
    /// # Errors
    /// Refused without a verified set; otherwise the store's write failure.
    fn put_recovered(&mut self, _id: &GrainId, _bytes: &[u8]) -> Result<(), PublicationStoreError> {
        Err(PublicationStoreError {
            path: "journal".into(),
            kind: crate::PublicationStoreErrorKind::Refused,
            reason: "no recovered object store".into(),
        })
    }
}

/// The objects a recovery verified itself before storing them: structure
/// nodes found in their own root's signed binmap, the prepared root's novel
/// file grains, and the nodes a merge built from those. An object merely
/// present in the store is never a member. The writer is the recovering
/// store's own, the only one a selected publication may sign as.
#[derive(Debug, Default)]
pub struct RecoveredObjects {
    pub(super) writer: Option<[u8; 16]>,
    pub(super) verified: BTreeMap<GrainId, usize>,
    pub(super) payloads: BTreeMap<GrainId, granary_core::manifest::FileGrains>,
}
impl PublicationJournal for PublicationStore<'_> {
    fn check_generic_resume(&mut self, record: &Submission) -> Result<(), PublicationStoreError> {
        self.check_generic_resume(record)
    }
    fn load(
        &mut self,
        s: &Scope,
        v: &VolumeName,
    ) -> Result<Option<Submission>, PublicationStoreError> {
        self.load(s, v)
    }
    fn begin(&mut self, r: &Submission) -> Result<(), PublicationStoreError> {
        self.begin(r)
    }
    async fn replace(&mut self, g: u64, r: &Submission) -> Result<(), PublicationStoreError> {
        self.replace(g, r)
    }
}

/// Authorizes a new read cycle after an interrupted/failed probe or loaded rebase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryIntent {
    Continue,
    ExplicitRecovery,
}
/// Exact local publication selection; credential continuity is caller-declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationHandle {
    pub scope: Scope,
    pub volume: VolumeName,
    pub publication_id: [u8; 16],
}
/// Retained result of an invocation. No variant except Landed releases content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationOutcome {
    Landed(Completion),
    Pending,
    Refused,
    Unresolved,
    BackendError,
    /// A mount commit consumed its durable dispatch budget.
    Exhausted,
}
/// Durable selection, checked last response and conservative uncertainty.
#[derive(Debug, Clone)]
pub struct PublicationResult {
    /// Nonshipping observation identity, without another mutating journal load.
    #[cfg(feature = "publish-restart-tests")]
    pub restart_record: Option<granary_core::retained_submission::Submission>,
    pub handle: PublicationHandle,
    pub outcome: PublicationOutcome,
    pub response: Option<PublishResponse>,
    /// Whether any surviving candidate can still have an unresolved decision.
    /// A proven-lost candidate is released and contributes no uncertainty.
    pub uncertain: bool,
    pub diagnostic: Option<String>,
}
impl PublicationResult {
    pub(crate) fn admission_error(&self) -> Option<crate::CoordinationError> {
        crate::CoordinationError::admission_refusal(
            self.response?,
            self.handle.publication_id,
            self.uncertain,
        )
    }

    /// Construct a result without a retained observation record.
    #[must_use]
    pub fn new(
        handle: PublicationHandle,
        outcome: PublicationOutcome,
        response: Option<PublishResponse>,
        uncertain: bool,
        diagnostic: Option<String>,
    ) -> Self {
        Self {
            #[cfg(feature = "publish-restart-tests")]
            restart_record: None,
            handle,
            outcome,
            response,
            uncertain,
            diagnostic,
        }
    }
}
/// A local failure or bootstrap refusal. Journal errors stop all network work.
#[derive(Debug)]
pub enum RecoveryError {
    Journal(PublicationStoreError),
    Record(granary_core::retained_submission::Error),
    Authority(AuthorityError),
    Preparation(crate::PublishError),
    Entropy(granary_core::secure_random::EntropyUnavailable),
    Bootstrap(Box<StatusResponse>),
    Invalid(&'static str),
    /// Local policy refused recovery work.
    Refused(&'static str),
    /// The remote history failed verification: an untrusted head, a broken
    /// ancestry, a missing or mismatched sheaf. The rule is a fixed phrase.
    /// Distinct from [`Self::Invalid`], which is a failure of local state.
    RemoteIntegrity(&'static str),
    Remote(RootStoreError),
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Journal(e) => write!(f, "publication journal: {e}"),
            Self::Record(e) => write!(f, "retained publication: {e}"),
            Self::Authority(e) => write!(f, "authority: {e}"),
            Self::Preparation(e) => write!(f, "preparation: {e}"),
            Self::Entropy(e) => e.fmt(f),
            Self::Bootstrap(s) => write!(f, "bootstrap refused: {s:?}"),
            Self::Invalid(s) | Self::Refused(s) | Self::RemoteIntegrity(s) => f.write_str(s),
            Self::Remote(e) => write!(f, "remote: {e}"),
        }
    }
}
impl std::error::Error for RecoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Journal(e) => Some(e),
            Self::Record(e) => Some(e),
            Self::Authority(e) => Some(e),
            Self::Preparation(e) => Some(e),
            Self::Entropy(e) => Some(e),
            Self::Remote(e) => Some(e),
            Self::Bootstrap(_) | Self::Invalid(_) | Self::Refused(_) | Self::RemoteIntegrity(_) => {
                None
            }
        }
    }
}
impl From<PublicationStoreError> for RecoveryError {
    fn from(value: PublicationStoreError) -> Self {
        Self::Journal(value)
    }
}
impl From<granary_core::retained_submission::Error> for RecoveryError {
    fn from(value: granary_core::retained_submission::Error) -> Self {
        Self::Record(value)
    }
}
impl From<AuthorityError> for RecoveryError {
    fn from(value: AuthorityError) -> Self {
        Self::Authority(value)
    }
}
impl From<crate::PublishError> for RecoveryError {
    fn from(value: crate::PublishError) -> Self {
        Self::Preparation(value)
    }
}
impl From<granary_core::secure_random::EntropyUnavailable> for RecoveryError {
    fn from(value: granary_core::secure_random::EntropyUnavailable) -> Self {
        Self::Entropy(value)
    }
}
impl From<RootStoreError> for RecoveryError {
    fn from(value: RootStoreError) -> Self {
        Self::Remote(value)
    }
}

/// Injected jitter and waiting. The coordinator clamps every draw to its ceiling.
pub trait RecoveryDelay {
    fn jitter(&mut self, ceiling: Duration) -> Duration;
    /// # Cancellation safety
    /// Dropping a wait leaves the already journaled continuation unchanged.
    fn wait(&mut self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}
/// Production delay with an explicitly supplied randomness seam.
#[derive(Debug)]
pub struct RecoveryBackoff<R> {
    pub rng: R,
}
impl<R: granary_core::rng::Rng> RecoveryDelay for RecoveryBackoff<R> {
    fn jitter(&mut self, ceiling: Duration) -> Duration {
        let bound = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(self.rng.below(bound.saturating_add(1)))
    }
    fn wait(&mut self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let _ = tokio::time::timeout(duration, std::future::pending::<()>()).await;
        })
    }
}
/// All authority, ownership, trust, identity and time inputs are explicit.
pub struct RecoveryParts<'a, T, J> {
    pub transport: &'a T,
    pub journal: &'a mut J,
    pub publisher_keys: &'a TrustedKeys,
    pub signer: &'a SigningKey,
    pub secure: &'a mut (dyn SecureRandom + Send),
    pub clock: &'a dyn Clock,
    pub delay: &'a mut (dyn RecoveryDelay + Send),
}
impl<T, J> std::fmt::Debug for RecoveryParts<'_, T, J> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryParts").finish_non_exhaustive()
    }
}
