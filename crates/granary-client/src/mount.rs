// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The mount session: what a read-only FUSE mount
//! trusts, and how it resolves its own head once,
//! at open time, rather than on every read.
//!
//! **Scope, expressed in the call graph, not a flag.**
//! `MountSession::open` calls [`crate::resolve::resolve_root`] then
//! [`crate::resolve::preamble`] and stops — it never calls `check_chain`
//! and never writes through `resolve_at_verified_impl`'s cache tail.
//! `cat` validates ancestry; the mount does not.
//! The retained [`crate::resolve::Preamble`] is what lets a long-lived
//! mount answer reads without re-walking the manifest tree on every call.

use std::collections::BTreeMap;
use std::path::Path;

use granary_core::binmap::ShardEntry;
use granary_core::binstore::BinStore;
use granary_core::hash::GrainId;
use granary_core::root::VolumeName;
use granary_core::rootstore::{RootStore, is_reserved_seq};
use granary_fuse::FUSE_SERVE_LIMITS;
use granary_net::config::SIGNING_KEY_LEN;
use granary_vfs::{AttrPolicy, GrainUnavailable, Snapshot, SnapshotError};

use crate::cache::{Cache, CacheError, CacheOrigin};
use crate::fetcher::{FetchState, Fetcher, Want};
use crate::resolve::{
    AnchorError, MetadataBudget, Preamble, ResolveError, RootVerifier, preamble, resolve_root,
};

/// How a mount decides what content to trust. Three modes, no
/// silent default — omitting all three is an error, not a fallback.
/// Verification is opt-in only where the caller NAMES the root
/// (composefs `digest=`, dm-verity, `/ipfs`); wherever the root is
/// discovered over the network and mutable it is mandatory or
/// default-on (CernVM-FS, IPNS, `OSTree`, Nix, stargz-snapshotter).
/// granary's mount discovers its head from the store's hint or
/// `max_seq`, so silent omission is the one shape the field never
/// sanctions.
#[derive(Debug, Clone)]
pub(crate) enum TrustMode {
    /// Publisher authority. The signed root commits the whole tree by
    /// hash. REQUIRED for any machine-wide entry point.
    RootKey(Box<[u8; SIGNING_KEY_LEN]>),
    /// Caller-pinned content. Refuse unless the resolved root's
    /// `manifest_root` equals this id. Needs no key and no distribution
    /// story; gives up FRESHNESS only.
    ManifestRoot(GrainId),
    /// The pinned endpoint is the declared content authority. Named
    /// honestly: a TLS pin does not authenticate a publisher, but
    /// Phase 1's anchor IS a pinned server certificate.
    TrustServer,
}

/// The mount-wide options `MountSession::open`'s trust gate
/// checks against every trust mode, not only `TrustServer`:
/// `allow_other`/`allow_root` are refused in BOTH keyless modes too, or
/// `--manifest-root --allow-other` would expose a keyless mount to
/// every local user while passing any test that only exercises
/// `--trust-server`.
///
/// **What this type does NOT model.** The full set of machine-wide entry points
/// also includes invocation as `mount.gran`, an fstab context and the
/// systemd unit — none of those exist at this layer: they are how a
/// caller ARRIVES at `open` (the CLI's `argv[0]`/fstab dispatch), never
/// a value `open` itself receives, so the CLI refuses them before ever
/// building one of these. Likewise the mount(2) flag set (`ro`,
/// `nosuid`, `nodev`) that keeps write/setuid/setgid/device semantics
/// off the kernel mount is the CLI's own hardcoded `session_config` —
/// this crate has no `fuser` dependency (the CLI adds the
/// `granary-client` → `granary-fuse` path edge, not this crate) and so
/// cannot even name a `fuser::MountOption` to refuse one. Nothing here
/// claims to enforce that half; the CLI is the layer that can.
///
/// ```
/// fn require_copy<T: Copy>() {}
/// require_copy::<granary_client::MountOptions>();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct MountOptions {
    /// `-o allow_other`: any local user, not only the mounting one, may
    /// read the mount.
    pub allow_other: bool,
    /// `-o allow_root`: the root user may read a mount it did not
    /// create.
    pub allow_root: bool,
}

/// The store's session recorder, shared by transport and cache observations.
/// A store without a metrics producer returns `None`.
pub trait MountMetrics {
    fn client_metrics(&self) -> Option<&crate::ClientMetrics>;
}

impl<S: object_store::ObjectStore> MountMetrics for granary_store::backend::GranaryStore<S> {
    fn client_metrics(&self) -> Option<&crate::ClientMetrics> {
        None
    }
}

/// Which floor refused a candidate seq (R3, as narrowed). The refusal
/// must say WHICH ONE blocked, because `--reset-floor` fixes only the
/// mount-private one — see [`MountError::StaleHead`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorKind {
    /// BOTH floors are above the candidate. This case must
    /// be distinguished and both named: naming only the higher one
    /// routes the operator straight to the more dangerous shared-floor
    /// deletion, and the mount then still fails on the other. A tie
    /// counts as both — `--reset-floor` alone would not unblock it.
    Both,
    /// `anchors/<volume>.mount` — `--reset-floor` clears exactly this
    /// one, and only this one.
    MountPrivate,
    /// `anchors/<volume>` — the CLI's own shared rollback defence.
    /// `--reset-floor` does not touch it; clearing it is a separate,
    /// more dangerous, deliberate operator action outside this flag.
    Shared,
}

/// Why `MountSession::open` refused, or could not finish.
#[derive(Debug)]
pub enum MountError {
    /// Zero of `--root-key`/`--manifest-root`/`--trust-server` were
    /// given. Never a fallback.
    NoTrustMode,
    /// More than one of the three was given.
    ConflictingTrustModes,
    /// `allow_other`/`allow_root` was requested outside `--root-key`
    /// — a mount carrying either is machine-wide by
    /// definition, whatever put it there, and the mount requires
    /// `--root-key` for any machine-wide entry point.
    MachineWideRequiresRootKey {
        /// `"allow_other"` or `"allow_root"`.
        option: &'static str,
    },
    /// `Cache::open` itself failed.
    Cache(CacheError),
    /// The cache opened read-only-degraded under a mode that keeps a
    /// floor (`--root-key`/`--trust-server`): a mount
    /// that cannot persist its floor must not pretend to have one.
    DegradedCacheRefused,
    /// The candidate seq (from `max_seq` discovery — never from an
    /// explicit `--seq`, which is an operator COMMAND rather than a
    /// claim the store made) sits below the applicable floor.
    StaleHead {
        /// The seq discovery landed on.
        candidate: u64,
        /// The mount-private floor at `anchors/<volume>.mount`.
        mount_floor: u64,
        /// The shared floor at `anchors/<volume>`.
        shared_floor: u64,
        /// Which floor file is the blocker, or `Both`.
        kind: FloorKind,
        /// Which trust mode is in force. The refusal's basis must
        /// be carried, because a genuine store rollback and a planted-seq
        /// poisoning are observationally identical and the operator has to
        /// deliberate with the numbers in front of them.
        mode: &'static str,
    },
    /// The mount-private freshness floor could not be written.
    FloorNotPersisted {
        /// Why, from the cache layer.
        reason: String,
    },
    /// A candidate seq for head selection is one of the two values that
    /// can never be a real head — the reserved values `0` and
    /// `u64::MAX`. `granary_core::rootstore`'s module doc states
    /// this as a CONTRACT obligation on every `RootStore` implementation
    /// ("[`RootStore::max_seq`] must not return `Some(0)`" / "must not
    /// return `Some(u64::MAX)`"), not an adapter detail — so the two
    /// doors this can arrive through mean different things to an
    /// operator, and this variant distinguishes them.
    ReservedSeqCandidate {
        /// The refused seq: `0` or `u64::MAX`.
        seq: u64,
        /// `true` when `max_seq` DISCOVERY answered this value — the
        /// `RootStore` implementation violated its own trait contract.
        /// `false` when an explicit `--seq` named it — operator error.
        discovered: bool,
    },
    /// `--manifest-root`'s pin did not match the resolved root's
    /// `manifest_root` — checked before the binmap, the
    /// sheaf, the tree walk, or the grain check.
    PinMismatch {
        /// The id the caller pinned.
        expected: GrainId,
        /// The resolved root's own `manifest_root`.
        found: GrainId,
    },
    /// `--root-key`, and a cache-held root at this `(volume, seq)`
    /// ALSO carries a valid signature but different bytes — publisher
    /// equivocation, which is the one case escalated to a refusal.
    CachedRootEquivocation {
        /// The wire root's content id.
        wire: GrainId,
        /// The cached root's content id.
        cached: GrainId,
    },
    /// Whatever `resolve_root` or `preamble` produced. *[Plain code
    /// spans, not intra-doc links: both are private, and this
    /// variant became PUBLIC when `MountError` was promoted for the
    /// daemon's own use — which turned a working private link into a
    /// `private_intra_doc_links` error only the rustdoc lane sees.]*
    Resolve(ResolveError),
    /// `--root-key`'s public key was refused as a trust anchor (the
    /// all-zero fail-open sentinel — see [`AnchorError`]).
    Anchor(AnchorError),
    /// The dedicated `tokio::runtime::Runtime` this session needs could
    /// not be built (OS resource exhaustion; never observed in
    /// practice).
    Runtime(String),
    /// A root published after open cannot be accepted by this session at
    /// all: it has shut down, or it was opened without a root key to check
    /// the root against.
    PublishedRootRefused {
        /// Which of the two.
        reason: &'static str,
    },
}

impl std::fmt::Display for MountError {
    #[expect(
        clippy::too_many_lines,
        reason = "one match arm per MountError variant, and this function is the only \
                  place a MountError is ever worded — splitting it would scatter that \
                  wording across several functions for no gain, because the length is one \
                  arm per variant rather than a tangle"
    )]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTrustMode => write!(
                f,
                "no trust mode given: exactly one of --root-key, --manifest-root or \
                 --trust-server is required — a mount is long-lived and ambient, so it must \
                 not pick a trust posture silently"
            ),
            Self::ConflictingTrustModes => write!(
                f,
                "more than one of --root-key, --manifest-root and --trust-server was given; \
                 exactly one is required"
            ),
            Self::MachineWideRequiresRootKey { option } => write!(
                f,
                "{option} makes this mount readable by every local user, which is a \
                 machine-wide entry point, and --root-key is required for one"
            ),
            Self::Cache(e) => write!(f, "cache: {e}"),
            Self::DegradedCacheRefused => write!(
                f,
                "another process holds the writer lock on this cache directory, so every floor \
                 write would be a silent no-op, and a mount that cannot persist its floor must \
                 not pretend to have one — give the mount its own --cache-dir"
            ),
            Self::StaleHead {
                candidate,
                mount_floor,
                shared_floor,
                kind: FloorKind::MountPrivate,
                mode,
            } => write!(
                f,
                "discovery landed on seq {candidate} in {mode} mode, below the mount-private \
                 freshness floor at seq {mount_floor} (shared floor: {shared_floor}) — refused \
                 as a rollback. Delete anchors/<volume>.mount (gran mount --reset-floor) to \
                 clear it"
            ),
            Self::StaleHead {
                candidate,
                mount_floor,
                shared_floor,
                kind: FloorKind::Shared,
                mode,
            } => write!(
                f,
                "discovery landed on seq {candidate} in {mode} mode, below the SHARED freshness \
                 floor at seq {shared_floor} (mount-private floor: {mount_floor}) — refused as \
                 a rollback. --reset-floor does not touch this file; deleting anchors/<volume> \
                 is a separate, more dangerous action the operator performs deliberately"
            ),
            // BOTH block. Lowest-risk action FIRST, and both named: telling
            // the operator only about the higher one sends them to the more
            // dangerous deletion and the mount still fails on the other.
            Self::StaleHead {
                candidate,
                mount_floor,
                shared_floor,
                kind: FloorKind::Both,
                mode,
            } => write!(
                f,
                "discovery landed on seq {candidate} in {mode} mode, below BOTH freshness \
                 floors — the mount-private one at seq {mount_floor} and the shared one at seq \
                 {shared_floor}. Clearing one is not enough. First: gran mount --reset-floor, \
                 which deletes anchors/<volume>.mount and nothing else. Then, and only if the \
                 mount still refuses: deleting anchors/<volume> is a separate, more dangerous \
                 action the operator performs deliberately, because it is gran cat's own \
                 rollback defence"
            ),
            Self::FloorNotPersisted { reason } => write!(
                f,
                "the mount-private freshness floor could not be persisted ({reason}) — refusing \
                 to serve, because in this mode the floor is the only rollback defence and a \
                 mount that cannot store one must not pretend to have one"
            ),
            Self::ReservedSeqCandidate {
                seq: 0,
                discovered: false,
            } => write!(
                f,
                "--seq: seq 0 is never a head — a root cannot be stored there at all, so the \
                 usable seq range is 1 ..= 18446744073709551614"
            ),
            Self::ReservedSeqCandidate {
                seq: 0,
                discovered: true,
            } => write!(
                f,
                "max_seq discovery answered seq 0, which is never a head — a root cannot be \
                 stored there at all. The RootStore implementation has violated its own \
                 max_seq contract, which requires it never answer Some(0)"
            ),
            Self::ReservedSeqCandidate {
                seq,
                discovered: false,
            } => write!(
                f,
                "--seq: seq {seq} is reserved and can never be a head, so the usable seq \
                 range is 1 ..= 18446744073709551614"
            ),
            Self::ReservedSeqCandidate {
                seq,
                discovered: true,
            } => write!(
                f,
                "max_seq discovery answered seq {seq}, which is reserved and can never be a \
                 head. The RootStore implementation has violated its own max_seq contract, \
                 which requires it never answer Some(u64::MAX)"
            ),
            Self::PinMismatch { expected, found } => write!(
                f,
                "--manifest-root {expected} does not match the resolved root's manifest_root \
                 {found}"
            ),
            Self::CachedRootEquivocation { wire, cached } => write!(
                f,
                "a cached root at this (volume, seq) carries a DIFFERENT, ALSO validly-signed \
                 root than the wire ({wire} vs the cached {cached}) — publisher equivocation, \
                 refusing"
            ),
            Self::Resolve(e) => write!(f, "{e}"),
            Self::Anchor(e) => write!(f, "--root-key: {e}"),
            Self::Runtime(message) => {
                write!(f, "could not build a runtime for this mount: {message}")
            }
            Self::PublishedRootRefused { reason } => {
                write!(
                    f,
                    "a root published after open cannot be accepted: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for MountError {}

impl From<CacheError> for MountError {
    fn from(e: CacheError) -> Self {
        Self::Cache(e)
    }
}

impl From<ResolveError> for MountError {
    fn from(e: ResolveError) -> Self {
        Self::Resolve(e)
    }
}

/// A binmap's entries and its bin table, which the entries index by ordinal.
type Binmap<'a> = (&'a BTreeMap<GrainId, ShardEntry>, &'a [[u8; 32]]);

/// One mount's whole session: what it resolved at open, and what it
/// needs to keep answering `GrainFetch`-shaped reads for as long as it
/// runs. Owns a dedicated current-thread [`tokio::runtime::Runtime`]
/// rather than borrowing one — the eventual FUSE adapter calls a
/// SYNCHRONOUS trait method from its own callback thread, which is not
/// itself a tokio worker, so the runtime this type does its own
/// `block_on` against has to live somewhere, and it lives here rather
/// than in a caller this crate does not control yet.
pub struct MountSession<R> {
    remote: std::sync::Arc<R>,
    volume: VolumeName,
    /// `None` once `shutdown` has taken it. `Cache::close` CONSUMES
    /// `self`, so a value a `&mut self` method must be able to close has
    /// to live behind an `Option` the method can `take()`.
    cache: Option<Cache>,
    /// The mode and verifier this session was opened with. A root accepted
    /// after open is checked against these, never against a key a caller
    /// hands in.
    trust: TrustMode,
    verifier: RootVerifier,
    fetch_state: FetchState,
    runtime: tokio::runtime::Runtime,
    pub(crate) pre: Preamble,
    /// The retained equivocation record. The `writeln!`
    /// to the caller's sink is a one-shot report: a daemonised
    /// mount whose sink is closed loses the only signal that a
    /// cached root and the wire root disagreed, and still serves.
    /// Holding it here means the adapter and the CLI can surface
    /// it on whatever long-lived surface they own, so the record
    /// remains available after the one-shot diagnostic is lost.
    equivocation: Option<crate::EquivocationNotice>,
}

/// The session implements the `granary_vfs::GrainFetch` read seam.
///
/// The path edge lands HERE, not at the CLI: this crate is
/// its first consumer, and `cargo-shear` fails a dependency
/// with no consumer — the same rule that kept it out of this
/// manifest until a consumer existed. Three different homes
/// were proposed; this is the one that convention requires.
impl MountSession<crate::HttpStore> {
    pub(crate) fn remote_wire_bytes(&self) -> crate::WireByteHandle {
        self.remote.wire_bytes()
    }
}
impl<R: RootStore + BinStore + Send> granary_vfs::GrainFetch for MountSession<R> {
    fn grain(&mut self, id: &GrainId, unpacked_len: u32) -> Result<Vec<u8>, GrainUnavailable> {
        self.fetch_grain(id, unpacked_len)
    }
}

/// The FUSE adapter's seam: `granary-fuse`'s `GranaryFs` adapter calls
/// `shutdown` from `Filesystem::destroy`. `MountBackend: 'static` is
/// why this impl needs `R: 'static` on top of `GrainFetch`'s own bounds
/// — `Self` retains `R` through the shared `remote` handle, so
/// `Self: 'static` (what the trait requires) is only satisfiable when
/// `R: 'static` too.
#[derive(Debug)]
pub(crate) struct FuseObserver {
    pub(crate) writability: granary_fuse::MountWritability,
    pub(crate) metrics: Option<crate::ClientMetrics>,
}

impl granary_fuse::CallbackObserver for FuseObserver {
    fn begin(
        &self,
        callback: granary_fuse::Callback,
    ) -> Option<Box<dyn granary_fuse::CallbackScope>> {
        if self.writability == granary_fuse::MountWritability::Writable
            && callback.reports_overlay_operation()
        {
            Some(Box::new(crate::observe::overlay_callback_begin()))
        } else {
            None
        }
    }

    fn captured(
        &self,
        callback: granary_fuse::Callback,
    ) -> Option<Box<dyn granary_fuse::DeferredCallbackScope>> {
        if self.writability == granary_fuse::MountWritability::Writable
            && callback.reports_overlay_operation()
        {
            if callback == granary_fuse::Callback::Write {
                crate::observe::overlay_callback_end(crate::observe::Outcome::Ok, None);
                None
            } else {
                crate::observe::overlay_callback_capture()
            }
        } else {
            None
        }
    }

    fn deferred_completed(
        &self,
        callback: granary_fuse::Callback,
        result: granary_fuse::CallbackOutcome,
    ) {
        self.record_completion(callback, result, false);
    }

    fn completed(&self, callback: granary_fuse::Callback, result: granary_fuse::CallbackOutcome) {
        self.record_completion(callback, result, true);
    }
}
impl FuseObserver {
    fn record_completion(
        &self,
        callback: granary_fuse::Callback,
        result: granary_fuse::CallbackOutcome,
        local: bool,
    ) {
        let (outcome, failure) = callback_outcome(result);
        if let Some(metrics) = &self.metrics {
            metrics.record_fuse(callback, outcome);
        }
        if local
            && self.writability == granary_fuse::MountWritability::Writable
            && callback.reports_overlay_operation()
        {
            crate::observe::overlay_callback_end(outcome, failure);
        }
    }
}

pub(crate) fn callback_outcome(
    result: granary_fuse::CallbackOutcome,
) -> (
    crate::observe::Outcome,
    Option<crate::observe::FailureClass>,
) {
    use crate::observe::{FailureClass, Outcome};
    use granary_fuse::{CallbackOutcome, MountError};
    match result {
        CallbackOutcome::Ok => (Outcome::Ok, None),
        CallbackOutcome::Cancelled => (Outcome::Cancelled, None),
        CallbackOutcome::Refused => (Outcome::Refused, Some(FailureClass::Refused)),
        CallbackOutcome::Failed(error) => (
            Outcome::Failed,
            Some(match error {
                MountError::Stale | MountError::PlanningExhausted => FailureClass::Conflict,
                MountError::Corrupt => FailureClass::Corrupt,
                MountError::Unavailable | MountError::Unreachable => FailureClass::Unavailable,
                MountError::Access | MountError::Closing => FailureClass::Refused,
                MountError::Io | MountError::NoSpace | MountError::Quota => FailureClass::Io,
            }),
        ),
    }
}

impl<R: RootStore + BinStore + Send + 'static> granary_fuse::MountBackend for MountSession<R> {
    type DirectoryCursor = ();
    fn overlay_path(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn overlay_lookup(
        &mut self,
        _parent: &[granary_core::manifest::Name],
        _name: &granary_core::manifest::Name,
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn overlay_directory(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<granary_fuse::OverlayDirectory<()>, granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn overlay_children(
        &mut self,
        _cursor: &(),
    ) -> Result<granary_fuse::OverlayChildren<()>, granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }

    fn overlay_nodes(
        &mut self,
    ) -> Result<Vec<granary_fuse::OverlayNode>, granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn overlay_capacity(
        &mut self,
    ) -> Result<granary_fuse::OverlayCapacity, granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn overlay_readlink(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<Vec<u8>, granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn prepare_shrink_retry(
        &mut self,
        _request: granary_fuse::MountShrinkRequest,
    ) -> Result<Box<dyn granary_fuse::MountSyncJob>, granary_fuse::MountSyncError> {
        Err(granary_fuse::MountSyncError::InvalidRequest)
    }

    fn prepare_sync(
        &mut self,
        _request: granary_fuse::MountSyncRequest,
    ) -> Result<Box<dyn granary_fuse::MountSyncJob>, granary_fuse::MountSyncError> {
        Err(granary_fuse::MountSyncError::InvalidRequest)
    }

    fn overlay_open(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<Option<u64>, granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn overlay_object(
        &mut self,
        _object: u64,
    ) -> Result<granary_fuse::OverlayNode, granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn overlay_close(&mut self, _object: u64) -> Result<(), granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn prepare_object(&mut self, _object: u64) -> Result<(), granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn prepare_detach(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<(), granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn read_object(
        &mut self,
        _object: u64,
        _offset: u64,
        _length: usize,
    ) -> Result<Vec<u8>, granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn prepare_overlay(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<(), granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn overlay_setattr(
        &mut self,
        _path: &[granary_core::manifest::Name],
        _size: Option<u64>,
        _exec: Option<bool>,
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn overlay_mutate(
        &mut self,
        _operation: granary_fuse::OverlayMutation<'_>,
    ) -> Result<(), granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }

    fn callback_observer(&self) -> Option<std::sync::Arc<dyn granary_fuse::CallbackObserver>> {
        let metrics = self.metrics().cloned();
        if let Some(metrics) = &metrics {
            metrics.set_available(crate::MetricsGroup::Fuse, true);
        }
        Some(std::sync::Arc::new(FuseObserver {
            metrics,
            writability: granary_fuse::MountWritability::ReadOnly,
        }))
    }
    fn shutdown(&mut self) -> Result<(), String> {
        // `shutdown` is documented as called ONCE, but must still be
        // IDEMPOTENT: `take()` runs BEFORE `Cache::close` does, on the
        // FIRST call, whether that call's close then succeeds or
        // fails — so every later call finds `cache` already `None` and
        // returns `Ok(())` regardless. That is a no-op, not a claim
        // that the first close succeeded: the first call's `Err`, if
        // any, is the one and only report of that failure, and nothing
        // here remembers it.
        let Some(cache) = self.cache.take() else {
            return Ok(());
        };
        self.report_read_path_instrument(crate::observe::TeardownCause::Shutdown);
        // WARN HERE, not only in `Drop`.
        // `Drop` already warns on a close
        // failure, but `Drop` only reaches the close when `shutdown` was
        // never called — so the SHUTDOWN path had no diagnostic at all,
        // and it is the path a real mount takes. `granary-fuse`'s
        // `Filesystem::destroy` cannot report the `Err` we return: it
        // returns `()`, and that crate depends on neither `tracing` nor
        // the exit slot `source.rs` names for `main.rs`. The failure
        // therefore has to be reported HERE, where it originates and where
        // `tracing` already is, or it is reported nowhere.
        let root = cache.root().to_owned();
        Cache::close(cache).map_err(|e| {
            crate::LocalReport::cache_close_warning(crate::CloseStage::Shutdown, &e).emit();
crate::observe::OperatorDiagnostic::mount_session_shutdown_closing_the_cache_failed_the_crash(e.failure_class()).emit_paths(&[crate::observe::PathSlot::Path("root", crate::LogPath::cache_root(&root))]);
            e.to_string()
        })
    }

    fn abandon(&mut self) {
        // Take it so `Drop` finds nothing to close. `Cache::abandon`
        // consumes the value and performs no close: the crash guard is
        // the point.
        if let Some(cache) = self.cache.take() {
            cache.abandon();
        }
    }
}

impl<R> MountSession<R> {
    /// Copy the cache's retained counters without filesystem access.
    ///
    /// # Errors
    /// Returns unavailable after shutdown has taken the cache owner.
    pub fn bundle_cache(
        &self,
    ) -> Result<granary_core::support::BundleCache, granary_core::support::BundleRefusal> {
        self.cache
            .as_ref()
            .map(Cache::bundle_projection)
            .ok_or(granary_core::support::BundleRefusal::Unavailable)
    }

    /// A transport facade for the sync runtime, separate from this session's
    /// current-thread runtime resources.
    pub(crate) fn remote_for_sync(&self) -> std::sync::Arc<R>
    where
        R: crate::WritableAuthority,
    {
        std::sync::Arc::new(self.remote.read_facade())
    }

    /// The session recorder derived from the remote store.
    #[must_use]
    pub fn metrics(&self) -> Option<&crate::ClientMetrics> {
        self.fetch_state.metrics()
    }

    /// Read-path instrument. ONE line per mount,
    /// at teardown — deliberately not per grain: a per-grain
    /// record is what forced the cold metadata-acquisition benchmark's
    /// counted and timed repetitions apart; the content read is ~100,000 grains.
    ///
    /// **What it is FOR.** The cold whole-tree read measured granary
    /// 3.54x slower than CernVM-FS while moving 0.09%
    /// different bytes, and the reading offered for that gap is that
    /// this path is serial — `fetch_grain` fetches a ONE-element array
    /// per `read`, behind `granary-fuse`'s single-threaded loop. Armed
    /// at the phase boundary in `open`, this should therefore print
    /// `1`. **If a real mount ever prints more, that reading is wrong**
    /// and the counter set built on it is aimed at the wrong layer.
    ///
    /// `window` is the LIVE window, not [`crate::fetcher::FETCH_WINDOW`]:
    /// AIMD drives it toward the floor under shed, and a saturated pass
    /// at a shed window of 4 would otherwise read as an idle one at 32.
    ///
    /// Called from BOTH teardown paths — `shutdown` and `Drop` — each
    /// inside its own `cache.take()` branch, so exactly one of them
    /// reports and neither double-reports. A session torn down by `Drop`
    /// alone (a worker-thread panic never reaches `destroy`) would
    /// otherwise measure and report nothing.
    fn report_read_path_instrument(&self, via: crate::observe::TeardownCause) {
        let c = self.fetch_state.counters();
        crate::observe::OperatorDiagnostic::mount_teardown_read_path_counters_for_the_read_phase(
            via,
            (self.fetch_state.inflight_high_water()) as u64,
            (self.fetch_state.window()) as u64,
            c.origin_requests,
            c.origin_sheds,
            c.origin_requests + c.origin_sheds,
            c.wants_bin,
            c.wants_meta,
            c.wants_bin + c.wants_meta,
            c.cache_hits,
            c.cache_misses,
        )
        .emit();
    }
}

/// A BACKSTOP for
/// the guard file's own error paths and `shutdown` do not cover
/// between them — any exit between `open()` returning `Ok` and
/// `Filesystem::destroy` calling `shutdown` (a daemon's `mount(2)` or
/// mountpoint validation failing, `Session::run` returning `Err`, a
/// panic unwinding a FUSE callback) drops the session without ever
/// reaching `shutdown`, and a merely-dropped `Cache` has no `Drop` of
/// its own to remove the guard it created at open.
///
/// Newly possible because `cache` lives in an `Option`: `Drop::drop`
/// takes `&mut self` and cannot move a bare field out, but it CAN
/// `Option::take` one.
///
/// **`shutdown` stays the primary path and the only path that reports
/// to the CALLER** — `MountBackend::shutdown`'s own doc says a close
/// failure is reported there, and `Drop` cannot reach the caller's
/// `sink`: nothing hands `drop` one (`open`'s `sink` is a borrow that
/// does not outlive that call, and `shutdown`'s own signature has no
/// sink parameter to thread one through). That does NOT leave
/// `Drop` with nowhere
/// to report to at all:
/// `tracing` is a direct
/// dependency of this crate and `cache.rs` already logs through it on
/// exactly this class of failure; `drop` below does the same on a
/// close failure, at `warn`, naming the cache root. That reaches an
/// operator watching logs, which is a real diagnostic — just not the
/// caller-facing report `shutdown` gives a caller with no log
/// subscriber wired up, which is the sense in which `shutdown` is
/// still the only REPORTING path.
///
/// After `shutdown` has run — successfully or not — `self.cache` is
/// already `None` (it takes the cache before calling `Cache::close`,
/// see that impl's own comment), so `Drop` finds nothing and is a
/// no-op. The two compose: neither ever double-closes.
///
/// `Drop::drop` runs BEFORE any of `Self`'s fields drop, so `runtime`
/// is still alive here — moot for `Cache::close` itself, which is pure
/// synchronous `std::fs`, but confirmed rather than assumed because a
/// future change to `close` could start to matter on it.
///
/// **A PANICKING unwind must
/// NOT run the clean-exit close.** The guard file's whole documented
/// contract is "the previous writer did not close cleanly" — the
/// signal the NEXT open reads to detect a crash. A drop that unwinds a
/// panic through this frame would otherwise flush
/// the journal, compact, and REMOVE the guard: the next open would see
/// a clean cache and be told nothing, inverting the one signal that
/// matters most exactly when it matters most. `drop` below checks
/// [`std::thread::panicking`] first and returns without touching the
/// cache when it is true — at the cost of whatever the in-memory
/// journal buffer was still holding unflushed. That cost is accepted:
/// a buffered-but-unflushed journal record is only an INDEX HINT for
/// an object that is already durable on disk (the object itself is
/// written and renamed into `objects/` before any record naming it is
/// ever queued — the same single-object crash window `cache.rs`
/// accepts elsewhere), whereas a guard file removed by mistake is not
/// recoverable after the fact: nothing else on disk says the crash
/// happened. **This is a heuristic, not an airtight one** —
/// `panicking()` is true only while THIS thread is actively unwinding
/// a panic through this exact frame. A panic caught upstream
/// (`catch_unwind`), with the session dropped normally afterward,
/// reads here as an ordinary close. Strictly better than never
/// checking; not a guarantee for every path a panic could take out of
/// a session's lifetime.
///
/// **AND THE FUSE CALLBACK PANIC IS ONE OF THE PATHS IT DOES NOT
/// COVER** — this was observed in
/// `fuser` 0.18.0's `session.rs`:
/// on a worker-thread panic `run()`
/// does NOT reach its own `filesystem.destroy()` call: `thread::join`
/// returns `Err` and `run()` returns `io::Error::other("event loop
/// thread panicked")` early. The teardown instead happens through
/// `FilesystemHolder`'s own `Drop`, **on the `Session::run` thread,
/// which is not panicking** — so `panicking()` is FALSE there, and the
/// adapter's `destroy` calls one of `MountBackend::shutdown` or (on a
/// poisoned lock — see below) `abandon` deliberately, rather than
/// reaching this backstop at all. This guard therefore
/// covers DIRECT drops (tests, and any composition that owns a session
/// without a `fuser` session around it); it does not cover the FUSE
/// crash lifecycle on its own. **That lifecycle is closed by
/// [`granary_fuse::MountBackend::abandon`], not by this backstop** —
/// discharging the adapter's crash-lifecycle obligation.
/// `GranaryFs::destroy` detects mutex poisoning and selects
/// `abandon` INSTEAD of `shutdown`
/// on a poisoned lock, and `abandon`'s own impl above `take()`s
/// `self.cache` exactly the way `shutdown` does — so by the time this
/// `Drop` runs (immediately afterward, since `destroy` already
/// released `MountInner`), `cache` is already `None` and there is
/// nothing here for the panicking()-blind backstop to undo. The
/// backstop above still matters on its own two paths (a direct drop
/// with no `destroy` ever called, and a panic caught upstream via
/// `catch_unwind` with the session then dropped normally) — it was
/// simply never the FUSE crash path's own answer, which is `abandon`.
impl<R> Drop for MountSession<R> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // See this impl's own doc comment: treated as an
            // unclean exit on purpose. The guard stays on disk, and
            // `self.cache` — still `Some` unless `shutdown` already
            // ran — is left for its own (no-op; `Cache` has no `Drop`)
            // drop. Nothing here talks to `Cache` during an unwind.
            return;
        }
        if let Some(cache) = self.cache.take() {
            // Reported here as well as in `shutdown`, and for the same
            // reason the close warning below is: this is the path a
            // session takes when `shutdown` was never called, and it
            // would otherwise measure the read phase and tell nobody.
            self.report_read_path_instrument(crate::observe::TeardownCause::Drop);
            // A close failure is never silently discarded here
            // (`let _ = ...`). In `open`'s error path, the corresponding
            // cleanup failure is reported on `sink` while the caller
            // still receives the original mount error. A daemon that never
            // calls `shutdown` cannot provide that sink to THIS backstop,
            // so `Drop` reports genuine close failures (ENOSPC, EACCES)
            // through `tracing`; otherwise the guard could remain with no
            // diagnostic anywhere.
            let root = cache.root().to_owned();
            if let Err(e) = Cache::close(cache) {
                crate::LocalReport::cache_close_warning(crate::CloseStage::Drop, &e).emit();
                crate::observe::OperatorDiagnostic::mount_session_drop_closing_the_cache_failed_the_crash(e.failure_class()).emit_paths(&[crate::observe::PathSlot::Path("root", crate::LogPath::cache_root(&root))]);
            }
        }
    }
}

impl<R> std::fmt::Debug for MountSession<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountSession")
            .field("volume", &self.volume)
            .finish_non_exhaustive()
    }
}

impl TrustMode {
    /// The flag that selected this mode, for a refusal that has to carry
    /// which mode is in force.
    const fn name(&self) -> &'static str {
        match self {
            Self::RootKey(_) => "--root-key",
            Self::ManifestRoot(_) => "--manifest-root",
            Self::TrustServer => "--trust-server",
        }
    }
}

/// Everything [`open_with_cache`] hands back to [`MountSession::open`]
/// on success, besides `cache` itself — `open` keeps `cache` owned for
/// its own whole call so it can decide what happens to it: closed on
/// any `Err` this function returns, kept (and only then wrapped in
/// `Some`) on `Ok`.
struct OpenResult {
    fetch_state: FetchState,
    runtime: tokio::runtime::Runtime,
    candidate_seq: u64,
    pub(crate) pre: Preamble,
    equivocation: Option<crate::EquivocationNotice>,
}

/// The degraded-cache check through the floor raise —
/// every fallible step that runs with the cache already open,
/// pulled out of `open` for exactly one reason: it lets `open` close
/// `cache` on ANY of their error paths through ONE boundary instead of
/// nine. `Cache` has no `Drop` impl. The writer creates `guard` on open
/// and removes it on a CLEAN close only, so a `cache` that is merely dropped on one of
/// these paths — each of which would otherwise have to close it itself —
/// leaves the crash guard in place, and the NEXT open reports "the
/// previous writer did not close cleanly" about a writer that never
/// crashed at all.
///
/// Order and logic are UNCHANGED from `open`'s own historical body —
/// this is a relocation, not a rewrite, and the comments below name
/// each operation in that same order. `cache` is
/// taken as `&mut Cache`, never consumed: this function only ever
/// borrows it, so the caller — never this function — decides its fate.
#[expect(
    clippy::too_many_lines,
    reason = "The degraded-cache check through the floor raise form one auditable, ORDERED flow (every \
              local refusal before anything that needs a server) — splitting it further would \
              scatter the security-sensitive order across functions, exactly \
              the reasoning `open` itself already carries for the same lint"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "the per-session observation handle is independent of the trust, head, cache and destination inputs"
)]
fn open_with_cache<R: RootStore + BinStore>(
    remote: &R,
    volume: &VolumeName,
    trust: &TrustMode,
    verifier: &RootVerifier,
    seq: Option<u64>,
    cache: &mut Cache,
    sink: &mut dyn crate::LocalReporter,
    metrics: Option<crate::ClientMetrics>,
) -> Result<OpenResult, MountError> {
    // The response to a degraded open is per
    // mode — only the two modes that keep a floor
    // refuse; `--manifest-root` keeps none, so a degraded cache there
    // costs only performance.
    if cache.is_read_only_degraded() {
        match trust {
            TrustMode::RootKey(_) | TrustMode::TrustServer => {
                return Err(MountError::DegradedCacheRefused);
            }
            TrustMode::ManifestRoot(_) => {
                sink.report(&crate::LocalReport::cache_degraded());
            }
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| MountError::Runtime(e.to_string()))?;

    // Head selection. `Some(n)` names `n` exactly;
    // `None` discovers via `max_seq`, taken DIRECTLY — never
    // through `resolve_head_verified`, which would raise the
    // SHARED anchor unconditionally.
    //
    // **The floor binds DISCOVERY'S OWN ANSWER, never a
    // user-commanded `--seq`**. As `ResolveError::StaleHead` records, an
    // explicit seq is a user command.
    // The threat the floor answers is a STORE lying about where the
    // head is; an operator naming a seq is not that. Binding an
    // explicit `--seq` would also destroy the documented escape
    // hatch from a poisoned floor, leaving
    // `--reset-floor` as the only route out of an attack any
    // stranger can mount.
    let discovered = seq.is_none();
    let candidate_seq = match seq {
        Some(n) => n,
        None => runtime
            .block_on(remote.max_seq(volume.as_str()))
            .map_err(ResolveError::from)?
            .ok_or(ResolveError::NoHead)?,
    };

    // Neither reserved seq can ever be a real head (0 or
    // u64::MAX) — checked here, before anything
    // else uses `candidate_seq`, because this IS head selection and
    // the CLI has since added a caller that trusts this function to
    // have already ruled both out, the way `main.rs`'s own `--seq`
    // parser and `HttpStore::max_seq` already do. `discovered`
    // distinguishes an operator's mistake from a `RootStore`
    // implementation violating its own `max_seq` contract.
    if is_reserved_seq(candidate_seq) {
        return Err(MountError::ReservedSeqCandidate {
            seq: candidate_seq,
            discovered,
        });
    }

    if discovered {
        match trust {
            TrustMode::RootKey(_) | TrustMode::TrustServer => {
                // R3 as narrowed: the effective lower bound is
                // max(shared_floor, mount_private_floor).
                let mount_floor = cache.read_mount_anchor(volume).unwrap_or(0);
                let shared_floor = cache.read_anchor(volume).map_or(0, |a| a.seq);
                let effective = mount_floor.max(shared_floor);
                if candidate_seq < effective {
                    // Say WHICH floor blocked, and when both
                    // do, say BOTH — `--reset-floor` fixes only the
                    // mount-private one, so naming the higher alone
                    // routes the operator to the dangerous deletion and
                    // the mount then still refuses. A TIE is `Both`:
                    // clearing the private floor leaves the shared one
                    // at the same seq, still blocking.
                    let mount_blocks = candidate_seq < mount_floor;
                    let shared_blocks = candidate_seq < shared_floor;
                    let kind = match (mount_blocks, shared_blocks) {
                        (true, true) => FloorKind::Both,
                        (true, false) => FloorKind::MountPrivate,
                        (false, _) => FloorKind::Shared,
                    };
                    return Err(MountError::StaleHead {
                        candidate: candidate_seq,
                        mount_floor,
                        shared_floor,
                        kind,
                        mode: trust.name(),
                    });
                }
            }
            // --manifest-root: read no floor and write none — its
            // acceptance predicate is seq-independent, so a floor
            // refuses nothing the mode cares about and can only
            // brick it.
            TrustMode::ManifestRoot(_) => {}
        }
    }

    // Root acquisition, its own function. Returns
    // before anything is fetched on the strength of `doc`'s
    // contents. `degraded: None`, always — never `Some`, and never
    // through any retry path that could produce one: this call can
    // structurally never take `read_root_bytes`'s cache-fallback
    // branch, which is what makes a transport-down start refuse
    // rather than silently serve a cache replay; the test
    // `a_transport_down_start_is_refused_rather_than_served_from_cache` checks this.
    let (root_bytes, doc) = runtime.block_on(resolve_root(
        remote,
        Some(&*cache),
        None,
        volume.as_str(),
        candidate_seq,
        verifier,
    ))?;

    // `--manifest-root`'s pin, HERE — before the
    // binmap, the sheaf, the tree walk or the grain check. The
    // ordering is expressed in the call graph (this line sits
    // between `resolve_root` and `preamble`), not a flag.
    if let TrustMode::ManifestRoot(expected) = trust
        && doc.manifest_root != *expected
    {
        return Err(MountError::PinMismatch {
            expected: *expected,
            found: doc.manifest_root,
        });
    }

    // Fetch and validate the preamble after accepting the root and any pin.
    let mut fetch_state = FetchState::new().map_err(|e| ResolveError::Fetch {
        what: "fetcher init",
        message: e.to_string(),
    })?;
    fetch_state.set_metrics(metrics);
    let mut budget = MetadataBudget::default();
    let pre = runtime.block_on(async {
        let mut fetcher = Fetcher::new(remote, &mut fetch_state);
        preamble(
            &mut fetcher,
            Some(&mut *cache),
            volume.as_str(),
            root_bytes,
            doc,
            &mut budget,
        )
        .await
    })?;

    // The same-seq comparison and the floor raise, shared with a re-pin.
    let equivocation_finding = accept_into_cache(
        cache,
        volume,
        trust,
        verifier,
        candidate_seq,
        &pre.root_bytes,
        sink,
    )?;

    Ok(OpenResult {
        fetch_state,
        runtime,
        candidate_seq,
        pre,
        equivocation: equivocation_finding,
    })
}

/// Accept a verified root at `seq` into the cache: the same-seq comparison
/// against a cached copy, then the floor raise. `root_bytes` has already
/// passed `verifier` for `volume` at `seq`. The order is the security
/// property, as `open_with_cache`'s is: every refusal comes before the two
/// cache writes, and the eviction (an idempotent corruption repair) precedes
/// the floor raise, which is not best-effort.
///
/// Returns the equivocation finding the keyless modes record and report
/// rather than refuse.
fn accept_into_cache(
    cache: &mut Cache,
    volume: &VolumeName,
    trust: &TrustMode,
    verifier: &RootVerifier,
    seq: u64,
    root_bytes: &[u8],
    sink: &mut dyn crate::LocalReporter,
) -> Result<Option<crate::EquivocationNotice>, MountError> {
    // The same-seq comparison. A WARNING except
    // under --root-key, where a cached copy that ALSO verifies is
    // publisher equivocation rather than local corruption.
    let mut equivocation_finding: Option<crate::EquivocationNotice> = None;
    if let Some(cached_bytes) = cache.get_root_bytes(volume, seq)
        && cached_bytes != root_bytes
    {
        match trust {
            TrustMode::RootKey(_) => {
                let cached_verifies = verifier
                    .check_head(volume.as_str(), seq, &cached_bytes)
                    .is_ok();
                if cached_verifies {
                    // 6b: two different, both validly-signed
                    // roots at one seq — publisher equivocation.
                    return Err(MountError::CachedRootEquivocation {
                        wire: GrainId::of(root_bytes),
                        cached: GrainId::of(&cached_bytes),
                    });
                }
                // 6c: local corruption — `Cache::get_root_bytes`
                // performs no signature and no hash check of
                // its own, so a cached entry that fails the
                // SAME check the wire root just passed is
                // corruption, not a second publisher. Evict and
                // proceed on the verified wire bytes.
                cache.evict_root_bytes(volume, seq);
                sink.report(&crate::LocalReport::cache_unverified(volume.clone(), seq));
            }
            TrustMode::ManifestRoot(_) | TrustMode::TrustServer => {
                // 6a: treat the cached copy as untrusted, warn
                // with both digests, proceed on the WIRE bytes,
                // and record the finding on the SAME surface as
                // the `gran mount: pinned …` line below — never
                // only a typed warning.
                let finding = crate::EquivocationNotice::new(
                    volume.clone(),
                    seq,
                    GrainId::of(root_bytes),
                    GrainId::of(&cached_bytes),
                );
                sink.report(&crate::LocalReport::equivocation(finding.clone()));
                equivocation_finding = Some(finding);
            }
        }
    }

    // The floor raise. RootKey and TrustServer
    // raise the MOUNT-PRIVATE floor to the accepted seq —
    // unconditionally on every accepted seq, explicit or
    // discovered, mirroring `resolve_at_verified`'s own unconditional
    // `raise_floor: true`. Note this is DELIBERATELY not symmetric with
    // head selection's read side, which is discovery-only: raising takes the
    // monotonic max, so an explicit `--seq` below the floor moves
    // nothing, while an explicit seq ABOVE it is a seq this mount
    // genuinely accepted and the floor should remember.
    // ManifestRoot raises nothing. Never the shared anchor — that
    // is `cat`'s own rollback defence.
    match trust {
        TrustMode::RootKey(_) | TrustMode::TrustServer => {
            // NOT best-effort. In these two modes the floor is the only
            // rollback defence there is, and a mount that accepted seq N
            // while silently storing nothing leaves the next DISCOVERY
            // free to accept an authentic older seq — the protection is
            // gone and nobody is told. The same requirement governs
            // both a degraded cache and a failed floor write:
            // a mount that cannot persist its floor
            // must not pretend to have one.
            cache
                .raise_mount_anchor(volume, seq)
                .map_err(|reason| MountError::FloorNotPersisted { reason })?;
        }
        TrustMode::ManifestRoot(_) => {}
    }

    Ok(equivocation_finding)
}

impl<R: RootStore + BinStore> MountSession<R> {
    /// `MountSession::open`. The order below is normative and
    /// is the security property: every local refusal comes before
    /// anything that needs a server.
    ///
    /// `root_key`/`manifest_root`/`trust_server` are the raw,
    /// possibly-conflicting trust-mode inputs (the trust gate lives
    /// here, not in a caller that might get it wrong): a caller hands
    /// over exactly what `--root-key`/`--manifest-root`/`--trust-server`
    /// named, and this function is the one place that decides whether
    /// that was a legal combination.
    ///
    /// `seq`: `Some(n)` names `n` exactly; `None` discovers via
    /// `max_seq`, taken DIRECTLY (never through `resolve_head_verified`,
    /// which would raise the SHARED anchor unconditionally).
    ///
    /// **The floor is READ only when the seq was DISCOVERED.**
    /// The floor binds DISCOVERY'S OWN ANSWER, never a user-commanded
    /// `--seq`; see `ResolveError::StaleHead`. The floor
    /// answers a STORE lying about where the head is; an operator naming a
    /// seq is not that, and the explicit `--seq` route around a
    /// poisoned floor would be worthless if the defence it routes around
    /// also refused it. The RAISE is unconditional, which is safe because
    /// it takes the monotonic max.
    ///
    /// # Errors
    /// See [`MountError`].
    #[expect(
        clippy::too_many_arguments,
        reason = "the raw trust-mode triple (3), the head selector, the cache's own three \
                  open parameters, the machine-wide option gate and the sink are each \
                  independently load-bearing inputs to this function; bundling any subset \
                  into a struct here would just move the same count behind one more name"
    )]
    pub fn open(
        remote: R,
        volume: VolumeName,
        root_key: Option<Box<[u8; SIGNING_KEY_LEN]>>,
        manifest_root: Option<GrainId>,
        trust_server: bool,
        seq: Option<u64>,
        cache_dir: &Path,
        cache_quota_bytes: u64,
        cache_origin: &CacheOrigin,
        options: MountOptions,
        sink: &mut dyn crate::LocalReporter,
    ) -> Result<Self, MountError>
    where
        R: MountMetrics,
    {
        // The trust gate. Exactly one of the three; zero
        // is an error naming all three.
        let given_count = [root_key.is_some(), manifest_root.is_some(), trust_server]
            .into_iter()
            .filter(|given| *given)
            .count();
        if given_count == 0 {
            return Err(MountError::NoTrustMode);
        }
        if given_count > 1 {
            return Err(MountError::ConflictingTrustModes);
        }
        let trust = if let Some(key) = root_key {
            TrustMode::RootKey(key)
        } else if let Some(id) = manifest_root {
            TrustMode::ManifestRoot(id)
        } else {
            TrustMode::TrustServer
        };

        // The machine-wide set (`allow_other`, `allow_root`, invocation
        // as `mount.gran`, an fstab context, the systemd unit) requires
        // `--root-key` under EVERY member — checked on "not RootKey",
        // never on "is TrustServer": the narrower check passes
        // `--manifest-root --allow-other`, exposing a keyless mount to
        // every local user while passing any test that only exercises
        // `--trust-server`; tests must exercise BOTH keyless modes
        // to catch the narrower form.
        if !matches!(trust, TrustMode::RootKey(_)) {
            if options.allow_other {
                return Err(MountError::MachineWideRequiresRootKey {
                    option: "allow_other",
                });
            }
            if options.allow_root {
                return Err(MountError::MachineWideRequiresRootKey {
                    option: "allow_root",
                });
            }
        }

        // The verifier. Both keyless modes state, on the
        // sink passed in (never an ambient `eprintln!` — `reader_verifier`'s
        // own precedent), what is and is not checked.
        let verifier = match &trust {
            TrustMode::RootKey(key) => RootVerifier::trusting(**key).map_err(MountError::Anchor)?,
            TrustMode::ManifestRoot(_) | TrustMode::TrustServer => {
                sink.report(&crate::LocalReport::signature_unchecked());
                RootVerifier::unverified()
            }
        };

        // Open the cache after selecting the verifier.
        let mut cache = Cache::open(cache_dir, cache_quota_bytes, cache_origin)?;

        // The degraded-cache check through the floor raise —
        // pulled into `open_with_cache` so every one of their
        // error paths can close `cache` through ONE boundary, right
        // below, rather than each dropping it in place. `cache` is only
        // ever BORROWED by this call; ownership stays here so this
        // match — and only this match — decides its fate.
        let opened = open_with_cache(
            &remote,
            &volume,
            &trust,
            &verifier,
            seq,
            &mut cache,
            sink,
            remote.client_metrics().cloned(),
        );
        let OpenResult {
            fetch_state,
            runtime,
            candidate_seq,
            pre,
            equivocation: equivocation_finding,
        } = match opened {
            Ok(v) => v,
            Err(e) => {
                // The ORIGINAL error `e` is always what is returned,
                // whether or not the close itself succeeds — that part
                // is not negotiable. `Cache` has no `Drop` impl, so a
                // cache merely dropped here — rather than closed
                // below — leaves the crash guard
                // file in place, which the NEXT open reports as an
                // unclean exit that never happened.
                //
                // A close failure is never silently discarded:
                // `let _ = Cache::close(cache);` would hide
                // a genuine flush, compaction, or guard-removal failure
                // behind an unrelated mount refusal, with no diagnostic
                // that cleanup itself also failed. Report it on `sink`
                // — the caller still gets `e`, never this one.
                if let Err(close_err) = Cache::close(cache) {
                    sink.report(&crate::LocalReport::cache_close_warning(
                        crate::CloseStage::RefusedMount,
                        &close_err,
                    ));
                }
                return Err(e);
            }
        };

        // Report what was pinned, plus the explicit
        // "history: not checked" line — the diagnostic substitute for
        // the dropped chain walk, never a replacement for it.
        sink.report(&crate::LocalReport::pinned(
            volume.clone(),
            candidate_seq,
            GrainId::of(&pre.root_bytes),
            pre.doc.manifest_root,
        ));
        sink.report(&crate::LocalReport::history());

        // A long-lived writer must call `Cache::maintain()`. Do so once
        // before returning the session.
        // `append_journal_record`'s inline compaction only fires
        // on an append THIS session makes; it can never see a journal
        // that was ALREADY over threshold when `Cache::open` above found
        // it (an earlier compaction the free-space watermark declined,
        // since cleared, or simply a mount that goes on to serve nothing
        // but misses). Once, here — after the cache is open and
        // everything above has already decided this mount proceeds,
        // before the session reaches a caller that might read for a long
        // time before its own first write ever appends anything.
        cache.maintain();

        // THE PHASE BOUNDARY for the read-path instrument. Everything
        // above this line is the preamble — including a structure-node
        // prefetch that submits a MULTI-want batch (`resolve.rs`'s
        // `prefetch_structure_nodes`) — and everything below it is
        // serving reads. Arming here is what makes the high-water mark
        // reported at teardown a statement about the CONTENT read path
        // rather than about the preamble's width.
        let mut fetch_state = fetch_state;
        fetch_state.arm_read_phase();

        Ok(Self {
            remote: std::sync::Arc::new(remote),
            volume,
            cache: Some(cache),
            trust,
            verifier,
            fetch_state,
            runtime,
            pre,
            equivocation: equivocation_finding,
        })
    }

    /// Accept a root the store published after this session opened, under
    /// the key and mode the session was opened with: the same-seq comparison
    /// and the mount-private floor raise `open` performs, on a root read back
    /// from the store. Every precondition is checked before anything is
    /// written, and the floor raise comes last and is not best-effort.
    ///
    /// # Errors
    /// `PublishedRootRefused` when the session has shut down or was not
    /// opened with a root key; the verifier's refusal when `root` is not this
    /// volume's root at its seq under this session's key;
    /// `ReservedSeqCandidate` when `root`'s seq is reserved; `StaleHead` when
    /// it is below the mount-private floor; `CachedRootEquivocation` when a
    /// cached root at the same seq also verifies; `FloorNotPersisted` when
    /// the floor cannot be written.
    pub(crate) fn accept_published(
        &mut self,
        root: &crate::sync::PublishedRoot,
        sink: &mut dyn crate::LocalReporter,
    ) -> Result<(), MountError> {
        self.accept_above(root, false, sink)
    }

    /// [`Self::accept_published`] for a root another writer published, which
    /// this session discovered: a seq below either floor is refused, as
    /// `open_with_cache` refuses a discovered head.
    ///
    /// # Errors
    /// [`Self::accept_published`]'s, and `StaleHead` when the seq is below
    /// the shared floor too.
    pub(crate) fn accept_discovered(
        &mut self,
        root: &crate::sync::PublishedRoot,
        sink: &mut dyn crate::LocalReporter,
    ) -> Result<(), MountError> {
        self.accept_above(root, true, sink)
    }

    /// Accept `root` above the mount-private floor, and above the shared one
    /// too when it was `discovered`. Each anchor is read at most once, and
    /// the shared one only when it can decide or name the refusal.
    fn accept_above(
        &mut self,
        root: &crate::sync::PublishedRoot,
        discovered: bool,
        sink: &mut dyn crate::LocalReporter,
    ) -> Result<(), MountError> {
        // `shutdown` takes the cache (`Cache::close` consumes it), as
        // `fetch_grain` notes: a root accepted after shutdown has nowhere to
        // persist its floor, so it is refused rather than silently kept.
        let cache = self
            .cache
            .as_mut()
            .ok_or(MountError::PublishedRootRefused {
                reason: "the mount session has already shut down",
            })?;
        // `--manifest-root` keeps no floor and `--trust-server` has no key
        // to check a re-pin against; under either the verifier below is
        // `RootVerifier::unverified()` and the accept would succeed having
        // checked nothing. The degraded-cache refusal needs no counterpart
        // here: `open_with_cache` already refuses a degraded cache under
        // `--root-key`, and cache mode is fixed at open.
        let TrustMode::RootKey(_) = &self.trust else {
            return Err(MountError::PublishedRootRefused {
                reason: "a re-pin needs a session opened with a root key",
            });
        };
        // Bind the root to THIS session's volume, seq and key before any
        // cache write: a root read for another volume, or under another
        // key, cannot raise this volume's floor.
        self.verifier
            .check_head(self.volume.as_str(), root.seq(), root.bytes())?;
        // Neither reserved seq can ever be a head, and the floor raise
        // persists nothing for one, so accepting it would claim a raise that
        // never happened. `open_with_cache` refuses the same candidate class;
        // a store holding a root there has broken its own contract.
        if is_reserved_seq(root.seq()) {
            return Err(MountError::ReservedSeqCandidate {
                seq: root.seq(),
                discovered: true,
            });
        }
        // A seq below the floor this session already raised is a rollback,
        // refused as `open_with_cache` refuses a discovered one, before the
        // same-seq comparison could evict or report anything at it. A
        // discovered root must reach the shared floor as well.
        let mount_floor = cache.read_mount_anchor(&self.volume).unwrap_or(0);
        let mount_blocks = root.seq() < mount_floor;
        if mount_blocks || discovered {
            let shared_floor = cache.read_anchor(&self.volume).map_or(0, |a| a.seq);
            let shared_blocks = root.seq() < shared_floor;
            if mount_blocks || shared_blocks {
                return Err(MountError::StaleHead {
                    candidate: root.seq(),
                    mount_floor,
                    shared_floor,
                    kind: match (mount_blocks, shared_blocks) {
                        (true, true) => FloorKind::Both,
                        (true, false) => FloorKind::MountPrivate,
                        (false, _) => FloorKind::Shared,
                    },
                    mode: self.trust.name(),
                });
            }
        }
        // Under `--root-key` the comparison refuses, so it records no finding.
        accept_into_cache(
            cache,
            &self.volume,
            &self.trust,
            &self.verifier,
            root.seq(),
            root.bytes(),
            sink,
        )?;
        Ok(())
    }

    /// The `GrainFetch`-shaped fetch: cache first, then the wire
    /// through a [`Fetcher`] built from `self.remote.as_ref()` and
    /// `&mut self.fetch_state`, `block_on`'d on `self.runtime`. Owns
    /// nothing new — every piece it touches is a field this session
    /// already holds.
    ///
    /// The inherent method the `GrainFetch` impl delegates to. Inherent
    /// rather than written directly in the impl so this module's own tests
    /// can call it without importing the trait.
    pub(crate) fn fetch_grain(
        &mut self,
        id: &GrainId,
        unpacked_len: u32,
    ) -> Result<Vec<u8>, GrainUnavailable> {
        self.fetch_mapped_grain(None, id, unpacked_len)
    }

    /// [`Self::fetch_grain`] with `id` looked up in `mapping`, a binmap's
    /// entries and bin table, in place of the binmap this session opened
    /// with. A writable mount passes the view it serves, which a landing
    /// can move past the session's own.
    pub(crate) fn fetch_mapped_grain(
        &mut self,
        mapping: Option<Binmap<'_>>,
        id: &GrainId,
        unpacked_len: u32,
    ) -> Result<Vec<u8>, GrainUnavailable> {
        let (entries, bins) = mapping.unwrap_or((&self.pre.entries, self.pre.bins.as_slice()));
        let entry = *entries
            .get(id)
            .ok_or_else(|| GrainUnavailable::new(format!("{id} is not in the resolved binmap")))?;
        let ordinal = usize::try_from(entry.bin_ordinal).map_err(|_| {
            GrainUnavailable::new(format!(
                "{id} names bin ordinal {}, past what this platform can index",
                entry.bin_ordinal
            ))
        })?;
        let digest = *bins.get(ordinal).ok_or_else(|| {
            GrainUnavailable::new(format!(
                "{id} names bin ordinal {ordinal}, past the bin table"
            ))
        })?;
        let want = Want::BinRange {
            id: *id,
            digest,
            offset: entry.offset,
            comp_len: entry.comp_len,
            unpacked_len,
        };

        // `shutdown` takes the cache (`Cache::close` consumes it), so a
        // read that arrives after shutdown finds `None` here. This must
        // REFUSE rather than hand `None` down to `Fetcher::fetch`:
        // `fetch(None, ..)` is a SUPPORTED, silent cacheless path — it
        // goes straight to the wire and still succeeds — so passing it
        // unconditionally would make a use-after-shutdown invisible. A
        // read after `destroy` is a bug in the caller, and this seam
        // says so rather than serving it.
        let cache = self
            .cache
            .as_mut()
            .ok_or_else(|| GrainUnavailable::new("mount session has already shut down"))?;

        // Cache first, then the wire — both inside `Fetcher::fetch`
        // itself (its own admission loop checks the cache before ever
        // seating a wire slot, and `finish` inserts on a wire hit), so
        // this call site does not duplicate that lookaside.
        let mut fetcher = Fetcher::new(self.remote.as_ref(), &mut self.fetch_state);
        let mut results = self
            .runtime
            .block_on(fetcher.fetch(Some(cache), [want]))
            .map_err(|e| GrainUnavailable::new(e.to_string()))?;
        let outcome = results
            .remove(id)
            .ok_or_else(|| GrainUnavailable::new(format!("{id}: the fetch produced no outcome")))?;
        let bytes = outcome.map_err(|e| GrainUnavailable::new(e.to_string()))?;

        // Verify the returned bytes hash to the id before returning
        // them — the fetcher already does this on BOTH delivery paths
        // (`finish`'s own hash check on the wire; `Cache::get`'s, which
        // is what makes a hit's id honest, on a cache hit), and doing it
        // again here is the seam's stated
        // contract: one hash on a path that just did a network round
        // trip, in exchange for never trusting a borrowed invariant
        // across a crate boundary this method is the edge of.
        if GrainId::of(&bytes) != *id {
            return Err(GrainUnavailable::new(format!(
                "{id}: fetched bytes do not hash to the id that named them"
            )));
        }
        // The contract names TWO things: the bytes hash to `id`, AND their
        // length is what the manifest declared. The fetcher rejects a grain
        // LONGER than declared but not a SHORT one, and the mount skips
        // `emit_target`, which is where `gran cat`'s own exact length check
        // (`GrainLenMismatch`) lives — so dropping the chain walk silently
        // dropped this too. The reader catches a short grain downstream as
        // EIO, but a seam answers for its own contract.
        if bytes.len() != unpacked_len as usize {
            return Err(GrainUnavailable::new(format!(
                "{id}: fetched {} bytes where the manifest declares {unpacked_len}",
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    /// The equivocation record, if this mount saw one — the cached
    /// root at the accepted seq disagreed with the wire root, the mount
    /// proceeded on the WIRE bytes, and this is the durable record of it.
    /// `None` on every ordinary mount.
    pub fn equivocation(&self) -> Option<&crate::EquivocationNotice> {
        self.equivocation.as_ref()
    }

    /// This method is the bridge: `open`'s resolved `Preamble` was
    /// never needed until now — `granary-fuse`'s [`Snapshot`] indexes
    /// the SAME resident structure map (`pre.nodes`) this session
    /// already proved resolves and holds from `open()` until
    /// `snapshot()` consumes it (`resolve.rs`'s own doc: "`nodes` is
    /// carried out, not dropped"). It lives here, not in `granary-fuse`
    /// or in the CLI, because `Preamble` is `pub(crate)` to THIS crate
    /// and never crosses it — only the
    /// already-public `Snapshot` this method returns does.
    ///
    /// `policy` (uid/gid) is presentation-only and carries no
    /// trust decision of its own (`MOUNT_HELP`'s own words:
    /// "PRESENTATION, not confidentiality") — the CLI resolves
    /// it from `--uid`/`--gid` or the mounting process's own
    /// credentials and hands it in here un-interpreted.
    ///
    /// Consumes the structure map: a second call builds a `Snapshot`
    /// over an empty map and fails naming the root as absent, and a
    /// FAILING first call has already moved the map into
    /// `Snapshot::new`, so the session cannot retry. Called exactly
    /// once per mount. `structure_node` returns `None` for everything
    /// after it.
    ///
    /// THIS METHOD is public surface (`gran` calls it through
    /// `granary_client::`) — `structure_node`, named just above, is
    /// not; it is `#[cfg(test)]`. And note what a second call LOOKS
    /// like: the failure is the ordinary missing-node error, which
    /// reads as a corrupt volume rather than as "already consumed".
    /// Nothing represents the consumed state, so a caller added later
    /// would be told the wrong thing. One caller exists and calls once.
    ///
    /// # Errors
    /// Whatever [`Snapshot::new`] reports: a reachable node absent from
    /// `pre.nodes`, one that fails to decode as a directory node, a tree
    /// exceeding the depth bound, a `subtree_entry_count` or `first_key`
    /// mismatch, a node repeated inside one directory's B-tree, a
    /// publish timestamp with invalid nanoseconds (`nanos` not strictly
    /// under one second — `SnapshotError::InvalidTimestamp`), a directory
    /// entry declaring the reserved `Fifo` or `Socket` kind, or a symlink
    /// target longer than this mount's FUSE `readlink` reply can carry.
    /// (Representability against the KERNEL's timestamp type is a
    /// different, later refusal — `granary_fuse::MountRefused`, at mount
    /// time — and not one [`Snapshot::new`] itself can return.)
    ///
    /// Most of these should not be reachable in production: `open`'s
    /// `preamble` call already proved the same tree resolves before
    /// `open` ever returns `Ok`, so a failure of one of THOSE kinds here
    /// would mean the two checks disagree, not that either is optional.
    /// The last two are the exception, not a disagreement between checks:
    /// `validate_dir_tree` (core's own preamble walk) passes a `Fifo`,
    /// `Socket`, or over-long-but-format-valid symlink target through
    /// untouched — `1..=4096` bytes is the FORMAT bound a target is
    /// validated against, unrelated to the FUSE `readlink` reply's own,
    /// smaller SERVE-layer bound — so a node carrying either reaches this
    /// call resolving cleanly, and is refused ONLY here, by design: the
    /// preamble intentionally admits what the format allows, and this
    /// mount intentionally refuses what it cannot represent or has no
    /// handler for. Both are reachable in production.
    pub fn snapshot(&mut self, policy: AttrPolicy) -> Result<Snapshot, SnapshotError> {
        // The limits are named directly rather than threaded as a parameter
        // (unlike `policy`): `policy` varies genuinely per mount (the real
        // process credentials the caller resolves), while every mount this
        // crate builds goes through the same `fuser` adapter and so always
        // wants the identical bound `granary_fuse` itself serves — a
        // parameter every caller passes the same constant for would add
        // coupling with no caller ever exercising a different value.
        Snapshot::new(
            std::mem::take(&mut self.pre.nodes),
            self.pre.doc.manifest_root,
            self.pre.doc.timestamp,
            self.pre.tree,
            policy,
            FUSE_SERVE_LIMITS,
        )
    }

    /// Test/diagnostic-only accessor into the in-memory map the mount
    /// holds, never a store call. `Some` proves [`Preamble::nodes`] is
    /// retained rather than re-derived; after `snapshot()` moves the
    /// map out, every id returns `None`.
    #[cfg(test)]
    pub(crate) fn structure_node(&self, id: &GrainId) -> Option<&[u8]> {
        self.pre.nodes.get(id).map(Vec::as_slice)
    }

    /// How many structure nodes the SESSION still holds.
    ///
    /// Asking by ID cannot establish a MOVE at all, on any fixture: a
    /// walk that cloned the map and removed exactly the id being asked
    /// about answers `None` to that question while every other node
    /// stays resident. The COUNT can — but only on a tree with more
    /// than one structure node, because emptying a one-node map and
    /// deleting its only entry are the same observation. That is why
    /// the row using this asserts the fixture's SHAPE before it
    /// asserts the count: both halves were measured, and the
    /// single-node form of this assertion passed the very mutant it
    /// was written to kill.
    #[cfg(test)]
    pub(crate) fn structure_node_count(&self) -> usize {
        self.pre.nodes.len()
    }
}

#[cfg(test)]
mod tests;
