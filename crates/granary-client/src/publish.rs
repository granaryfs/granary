// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `gran publish` — the client publish path (frozen):
//! harvest into the local store, compute novelty against the REMOTE
//! binmap, pack the novel objects into bins, upload bins then binmap,
//! write the commit record, CAS the signed root at `seq + 1`, repair the
//! advisory hint.
//!
//! ```text
//! harvest ─► local CAS ─► novelty vs remote binmap ─► bins ─► binmap ─► sheaf ─► root CAS ─► hint
//! ```
//!
//! **Sheaves are DIRECTLY-ADDRESSED meta objects**: a sheaf is
//! uploaded with `put_meta` under `meta/{volume}/` and read back with
//! `get_meta(volume, sheaf_head)`, exactly like the binmap index and the
//! bin table — the objects the ROOT layer resolves directly. It is never
//! packed into a bin and never gets a binmap entry. Grounds: it makes
//! the dedup-only-publish property literally true (sheaf + root are the
//! only uploads); it removes what would otherwise be per-publish binmap
//! churn (one new object forces a bin, a bin-table row, a shard rewrite
//! and a new index — on EVERY publish, including ones that change
//! nothing); sheaf cardinality is one per publish, the same as roots, so
//! there is no small-objects concern; and readers already fetch it at
//! refresh cadence alongside the binmap index.
//!
//! **`sheaf_head` is the one meta reference `remote_state` copies
//! forward WITHOUT content verification.** `remote_state` fetches and
//! content-address-checks the binmap index, the bin table, and every
//! shard (`fetch_meta` — every one of those bytes is re-hashed against
//! the id that named it before this code trusts it); the head root's
//! `sheaf_head` id, by contrast, is taken from the decoded — and
//! signature-verified — root and carried into the new sheaf's `parent`
//! link untouched, with no `get_meta` round trip to confirm the sheaf it
//! names still exists or still hashes to that id. This is deliberate,
//! not an oversight: the signature
//! covers the id, so a forged sheaf reference is already excluded, and
//! `remote_state`'s own novelty computation and this publish's uploads
//! never need the PRIOR sheaf's bytes, only its id. The consequence a
//! reader should know: a missing prior sheaf (its object deleted out of
//! band) is NOT caught here — the next publish still succeeds, and the
//! new sheaf's `parent` extends the chain to an id that will not
//! resolve, a permanently unresolvable link one hop back, with the
//! deletion itself invisible at publish time. This does not corrupt
//! history — a broken chain link fails a reader's walk rather than
//! resetting anything, and the root's own `parent` chain is independent
//! of it — so no fetch-and-verify round trip has been added for it; the
//! cost of one is a `get_meta` on every publish for a link this code
//! never otherwise needs, to guard a deletion that is already visible
//! (loudly, to whoever tries to walk past it) the moment a reader
//! reaches it.
//!
//! **Novelty is computed against the remote binmap, never against the
//! local store.** The local store is monotone — it still holds every
//! object of every prior harvest — so "is this object new to me" and "is
//! this object new to the VOLUME" are different questions, and only the
//! second one decides what gets uploaded. The remote known-id set comes
//! from the head root's binmap shards, which is also what makes a
//! republish upload a delta rather than a tree.
//!
//! **The publish set is the manifest closure**, walked from the harvest's
//! root through the local store: every manifest node and every grain the
//! tree references, and nothing else. Unreachable objects left in the
//! local store by an earlier harvest of a different tree are NOT
//! published (they would be pure chaff in the volume).
//!
//! **Locality order (v0 policy, `binfmt::plan_bins` doc):** manifest
//! traversal order — a directory node, then each entry in canonical name
//! order, a file's grains consecutively in file order, subdirectories
//! depth-first. Split points are the planner's; the order is ours, and
//! it puts the bytes of one file next to each other inside one bin.
//!
//! **Dedup-only publish**: seq and the sheaf chain
//! advance, `manifest_root` does not, and the binmap is not rebuilt —
//! the new root carries the PREVIOUS root's `binmap_index` id byte for
//! byte, so the only two objects written are the sheaf and the root.
//!
//! **Lost CAS race: loud failure, no automatic rebase.** v1 volumes are
//! single-writer by distribution default; an automatic rebase-and-retry
//! loop was never built: a lost CAS race may rebase and retry or fail
//! loudly, and this implementation satisfies that contract by failing loudly.
//! The error names the attempted seq plus a listing-derived head that
//! is an UNVERIFIED diagnostic (see `LostRace`'s field doc), and
//! nothing is written at `seq + 1`. Whether a re-run's uploaded bins
//! are pure reuse depends on the loser's novel set: when it is DISJOINT
//! from the winner's, the bins ARE content-addressed reuse and only the
//! orphaned binmap objects are chaff for winnow — but a lost race,
//! by definition, means a second writer existed, and if the two
//! writers' novel sets PARTIALLY OVERLAP, the re-run's own novel set
//! shrinks (the winner already covered part of it), `plan_bins`
//! regroups the remainder differently, and the re-run uploads FRESH bin
//! bytes for content the loser's first attempt already uploaded under a
//! now-orphaned bin — measured at 200,349 bytes of fresh bin from one
//! partially-overlapping re-run. The disjoint case is the common one
//! (v1 volumes are single-writer by default, so a race is already the
//! uncommon path), but the claim above is not universal — state it only
//! for the disjoint case.
//!
//! **The hint is advisory**: a failed hint write is a
//! WARNING on a successful publish, never a failure — readers
//! forward-probe and the next publish repairs it.
//!
//! Split into [`prepare`] (everything up to and including the uploads)
//! and [`commit`] (the CAS + hint) because the CAS is the commit point:
//! the split is what lets a test interleave a racing writer exactly
//! where a real race happens, and it costs the caller one extra line.
//!
//! **HARVEST IS HOISTED OUT OF THE GENERIC PATH.** The flow reads the
//! remote through [`RootStore`] + [`BinStore`] and the local store
//! through [`GrainSource`] — all three pure, none naming an
//! `object_store` type — so the simulator can drive it against fakes.
//! Harvest cannot join that: it WRITES the local store, and
//! `GrainSource` is read-only by design. So the entry point that is
//! generic in the local store is [`prepare_from_manifest`], which takes
//! the manifest root a harvest already produced; [`prepare`] is the
//! CLI's convenience wrapper that harvests into a concrete [`Store`] and
//! then calls it. The consequence worth stating: the SIMULATED path
//! genuinely only reads the local store, which is what lets the sim
//! need no filesystem.
//!
//! **v1 limits, stated rather than discovered later.** (a) The novel
//! frames are compressed into memory before any bin is written, so peak
//! RSS scales with the NOVEL set of one publish — fine for a delta,
//! coarse for a first publish of a large tree; streaming the packer is
//! future work, and `plan_bins` is already the pure seam it needs.
//! (b) The bin table is scanned linearly to place each new bin's
//! ordinal (bins per publish × table size). (c) The binmap is rewritten
//! whole-shard: every shard is re-encoded and re-hashed in memory, but
//! only shards whose BYTES CHANGED are uploaded — the wire cost is
//! proportional to the TOUCHED shards, the CPU cost to all of them.
//! That distinction is load-bearing: `put_meta` is `PutMode::Create`,
//! and S3 streams a full body before answering 412, so a rebuild that
//! put every bucket unconditionally would send 256 full shards for a
//! one-grain delta at `prefix_bits = 8` and 4096 at the max width.
//! Delta/log binmap formats are deferred to Phase 2+.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use granary_core::binfmt::{self, PackedFrame};
use granary_core::binmap::{self, SHARD_ENTRY_LEN, SHARD_TARGET_BYTES, ShardEntry};
use granary_core::binstore::BinStore;
use granary_core::encoding::{self, DecodeError, ObjectType};
use granary_core::grainsource::{GrainSource, GrainSourceError};
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_core::identity::WriterIdentity;
use granary_core::manifest::{self, EntryKind, FileGrains};
use granary_core::root::{
    self, RootDoc, RootIdentityError, RootSig, Timestamp, VolumeName, WRITER_UUID_LEN,
};
use granary_core::rootstore::{RefusalKind, RootStore, RootStoreError};
use granary_core::sheaf::{self, SheafDoc, SheafOp};
use granary_core::thresh::CHUNKER_SPEC;
use granary_store::bounds::ROOT_MAX_BYTES;
use granary_store::codec::{CodecError, GrainCodec};
use granary_store::crypto::{self, HeadError, SigningKey, TrustedKeys};

use crate::harvest::{self, FileIdentity, HarvestError, HarvestStats};
use crate::store::Store;

pub(crate) mod shards;
pub use shards::Work as BinmapWork;

/// Publisher policy knobs. Not format: every value here is a choice a
/// later publish may revise (within the monotonicity rule below).
#[derive(Debug, Default, Clone, Copy)]
pub struct Policy {
    /// Floor on the binmap's routing width. The width is otherwise
    /// derived from the entry count and [`SHARD_TARGET_BYTES`]; a
    /// publisher that knows a volume is about to grow can pre-split
    /// rather than pay the whole-map rewrite later. NEVER a ceiling:
    /// `prefix_bits` is monotonic per volume, so the
    /// effective floor is `max(prior root's bits, this)`.
    pub min_prefix_bits: u8,
}

/// What one publish did — the summary the CLI prints and the tests
/// assert on.
#[derive(Debug, Clone, Copy)]
pub struct PublishSummary {
    pub seq: u64,
    pub epoch: u64,
    /// Objects (grains + manifest nodes) the remote binmap did not
    /// already know. The sheaf is NOT one of them — it is meta.
    pub novel_objects: u64,
    /// Uncompressed bytes of those objects.
    pub novel_bytes: u64,
    /// Bins the packer produced for them.
    pub bins_planned: u64,
    /// Bins whose bytes were actually new to the bucket (a bin that was
    /// already there — a crashed earlier publish — is not re-uploaded).
    pub bins_uploaded: u64,
    /// Bin bytes written (0 for the bins that deduped).
    pub bin_bytes_uploaded: u64,
    /// `1 << prefix_bits` — the dense shard count of the new binmap.
    pub shards_total: u64,
    /// Shards whose bytes changed. The rest are content-identical to the
    /// previous publish's and dedup on `put_meta`. ZERO when the publish
    /// mapped nothing new: the binmap is then reused wholesale, not
    /// rebuilt (see step 6 of `prepare_from_manifest`).
    pub shards_rewritten: u64,
    /// Whether the sheaf object's bytes were new to the bucket. The
    /// sheaf is a directly-addressed meta object, never binned.
    pub sheaf_uploaded: bool,
    pub prefix_bits: u8,
    pub manifest_root: GrainId,
    pub binmap_index: GrainId,
    pub sheaf_head: GrainId,
    /// False when the advisory hint write failed — the publish still
    /// SUCCEEDED. It is the ONLY report of that failure:
    /// [`commit`] does not print, so warning the operator is the
    /// caller's job.
    pub hint_written: bool,
    pub harvest: HarvestStats,
}

/// A publish that has uploaded everything and not yet claimed its seq.
/// The root bytes are signed and final; [`commit`] is one put-if-absent
/// away from making them the volume's head.
#[derive(Debug)]
pub struct Prepared {
    volume: VolumeName,
    /// The seq this publish will attempt to claim.
    ///
    /// **PRIVATE, so the seq reservation is enforced
    /// structurally.** [`remote_state`] is the only thing that sets this
    /// field, and it refuses a next seq of `u64::MAX`; a `pub` field
    /// would let any holder of a `Prepared` write `prepared.seq =
    /// u64::MAX` and hand [`commit`] a seq reserved from head selection —
    /// which `commit` would then claim, report as a success, and leave
    /// invisible to every reader. Read it through [`Prepared::seq`].
    /// (Its sibling `root_bytes` stays public for a reason this field
    /// has none of; see below.)
    seq: u64,
    /// The exact root bytes [`commit`] will attempt to claim — public
    /// so a caller can pre-place them, which is how the ambiguous-retry
    /// case proves read-after-write self-identification. Being public
    /// also means [`commit`] cannot trust its length: it re-checks
    /// against [`granary_store::bounds::ROOT_MAX_BYTES`] itself, before
    /// any `PUT`, rather than relying on whatever [`prepare`] originally
    /// produced here.
    pub root_bytes: Vec<u8>,
    summary: PublishSummary,
}

impl Prepared {
    /// The seq this publish will attempt to claim.
    ///
    /// Read-only by design; see the field's own note.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }
}

// There is no whole-publish deadline: instead of a fixed total over the
// whole flow, every seam call carries its own deadline — `crate::http_store`
// (`SEAM_DEADLINE_BASE`/`seam_deadline`) for the `PublishRoute::Server`
// route, `crate::direct_deadline` (`DirectStoreDeadline`) for the
// `PublishRoute::DirectS3` one. A wedged peer is cut at its own
// call — see each module's own doc for its derivation — rather than at
// the end of an arbitrary total, and an operation is a finite sequence of
// individually bounded calls plus bounded local work: a long chain walk
// whose every call finishes inside its own bound completes, which no
// finite whole-flow total would admit.
//
// THE TRADE, STATED WITH ITS COST. A flow is a finite sequence of
// individually bounded calls, so what bounds the FLOW is the SUM of
// those bounds, not any one of them. On the `PublishRoute::DirectS3`
// route every call carries the same flat `DIRECT_STORE_CALL_DEADLINE`
// (15 minutes), and a call that takes almost all of it and then SUCCEEDS
// is not an error anywhere — it is admitted, and the next call starts a
// fresh deadline. The root path alone chains four such calls in one
// invocation: `prepare`'s `max_seq`, `prepare`'s `get_root` of the head,
// `commit`'s `put_root`, and — on the ambiguous-PUT path — the one probe
// `get_root` that resolves it. That is roughly SIXTY minutes of blocking,
// and it is the FLOOR rather than the worst case: every `put_bin` and `put_meta`
// this publish uploads carries its own deadline too, so the sum grows
// with the volume and has no finite bound at all.
//
// That is the deliberate deadline trade, not an oversight. A whole-flow
// total would cut an HONEST long publish (many bins, a deep chain) that was
// making progress the whole time, and admit a wedged call whenever an
// earlier call had not yet spent the budget. The per-call regime admits
// the honest publish and cuts the wedged call; what it gives up is any
// bound on the sum.

#[derive(Debug)]
pub enum PublishError {
    Harvest(HarvestError),
    /// A failure of the local object surface, through the pure seam.
    /// This is what the whole publish flow — CLI and simulated alike —
    /// produces for a missing, corrupt or unreadable local object.
    Source(GrainSourceError),
    Remote(RootStoreError),
    /// A stored object failed to decode, named by what was being read.
    Decode {
        what: &'static str,
        source: DecodeError,
    },
    Codec(CodecError),
    EncodeBin(binfmt::EncodeBinError),
    EncodeBinmap(binmap::EncodeBinmapError),
    EncodeSheaf(sheaf::EncodeSheafError),
    EncodeRoot(root::EncodeRootError),
    /// `max_seq` named a root that `get_root` could not produce.
    MissingRoot {
        seq: u64,
    },
    /// The head root at `seq` names a binmap object (`what`: "binmap
    /// index", "bin table", or "binmap shard") that `get_meta` could
    /// not produce — the meta-object analogue of `MissingRoot`, named
    /// the same way rather than surfacing as a bare `Remote(NotFound)`.
    MissingMeta {
        what: &'static str,
        id: GrainId,
        volume: String,
        seq: u64,
    },
    /// The head root's embedded name is not the volume it was fetched
    /// from — the cross-volume replay check.
    VolumeMismatch {
        want: String,
        got: String,
    },
    /// The head root's `seq` field disagrees with the key it lives at.
    SeqMismatch {
        key_seq: u64,
        doc_seq: u64,
    },
    /// The head root carries no signature by the
    /// publishing key (the trust model is self-publish,
    /// the publisher extends only a chain it signed).
    UnknownSigner {
        seq: u64,
    },
    BadSignature {
        seq: u64,
    },
    /// A metadata object's bytes do not hash to the id that named them.
    CorruptMeta {
        id: GrainId,
    },
    /// The manifest closure reached an object that is not a manifest
    /// node — a store that has been tampered with.
    NotAManifestNode {
        id: GrainId,
    },
    /// A novel object is missing from the local store: refused BEFORE
    /// any upload, so a broken store cannot half-publish a volume.
    MissingObject {
        id: GrainId,
    },
    /// Put-if-absent lost: another writer holds this seq. `head` is
    /// DIAGNOSTIC ONLY — a raw listing maximum, neither decoded nor
    /// signature-verified (an attacker who can write the bucket can
    /// list any key); nothing trusts it — the re-run's `remote_state`
    /// does the verified head resolution.
    LostRace {
        volume: String,
        attempted: u64,
        head: u64,
    },
    /// The ONE-PROBE RULE's fourth outcome:
    /// `put_root` failed, and the single `get_root` that would have
    /// resolved it ALSO failed or was itself refused for a reason that
    /// proves nothing about the occupant. Neither error alone tells the
    /// story — `put_error` is what the write reported, `probe_error` is
    /// what the read that would have settled it reported — so both are
    /// carried rather than discarding one. The outcome is
    /// genuinely UNKNOWN: the write may have landed, and a re-run
    /// resolves it from the chain rather than from this error.
    ProbeUnresolved {
        put_error: RootStoreError,
        probe_error: RootStoreError,
    },
    /// The ONE-PROBE RULE's other unresolved outcome: `put_root` failed
    /// and the probe ANSWERED — nothing is at the attempted seq. That is
    /// NOT the same as "the PUT genuinely failed": surfacing it as the
    /// plain original error is sound only when the failed PUT's own
    /// answer was TERMINAL and known to be the only attempt sent, and no
    /// adapter this client uses can prove that (the module doc on the
    /// ONE-PROBE RULE, `granary_core::rootstore`, states why —
    /// `object_store`'s own internal retries, on both routes). So a
    /// probe finding nothing carries the PUT's own error without
    /// promoting it to a terminal fact: the write MAY still land, and a
    /// re-run resolves it from the chain.
    Unresolved {
        put_error: RootStoreError,
    },
    /// The signed candidate is larger than [`ROOT_MAX_BYTES`], the read
    /// cap the ONE-PROBE RULE's own settling probe uses — refused BEFORE
    /// any root `PUT`, never after: the chain is unchanged, though
    /// [`prepare`] has already uploaded the content objects this root
    /// would have named (harvest and upload happen before `commit` ever
    /// runs). `Prepared::root_bytes` is public so a caller can pre-place
    /// bytes for the ambiguous-retry case (read-after-write
    /// self-identification), which means `commit` cannot trust that a
    /// `Prepared` it receives still carries what `prepare` produced.
    /// Without this guard an oversized candidate that somehow landed
    /// would make the probe's own `OverCap` refusal (a bound meant to
    /// prove FOREIGNNESS) misreport this writer's own bytes as a lost
    /// race.
    RootTooLarge {
        len: usize,
        cap: u64,
    },
    /// A frame length that `plan_bins` accepted no longer fits `u32` —
    /// unreachable (the codec caps frames far below), checked anyway.
    FrameTooLong {
        len: usize,
    },
    /// A counter reached the top of the range it may take.
    ///
    /// **`root epoch` is unreachable, `root seq` is not.** The epoch limb
    /// is `u64::MAX` and checked anyway. The seq limb fires ONE SEQ
    /// EARLIER than the arithmetic would, and by design: head selection
    /// reserves seq `u64::MAX` as a value that can never be a head, so
    /// the usable space is `1 ..= u64::MAX - 1` and a publisher whose
    /// head is `u64::MAX - 1` is REFUSED. That is seq-space exhaustion
    /// reported honestly — the alternative is a root written at the
    /// reserved seq, reported as a success, and then hidden from every
    /// reader by the very rule that reserves it. Unreachable without
    /// ~1.8 × 10^19 publishes or an operator planting their own signed
    /// root at the top of the range.
    CounterOverflow {
        what: &'static str,
    },
    /// Internal invariant: the packer produced a bin range the frame
    /// list does not cover.
    BadPlan,
    /// Final encoded binmap disagrees with its authenticated base and plan.
    BinmapConstruction,
    /// The volume does not exist yet and its name is in the reserved
    /// registry. Admission only: an already-existing reserved volume
    /// publishes normally.
    ///
    /// **Remote-clean, not side-effect-free.** The check lives at the
    /// publish flow's first remote call, so nothing is uploaded — but
    /// [`prepare`] harvests the source tree into the LOCAL store before
    /// it, so the CLI path leaves that tree in the local CAS. The
    /// `Display` text says so; a caller reading the variant rather than
    /// the message needs it here too.
    ReservedVolumeName {
        volume: String,
    },
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Harvest(e) => write!(f, "harvest: {e}"),
            // No prefix: `GrainSourceError`'s own rendering already
            // names the local store where that is the failing layer, and
            // a second "local store:" in front of it would read as two.
            Self::Source(e) => write!(f, "{e}"),
            Self::Remote(e) => write!(f, "remote: {e}"),
            Self::Decode { what, source } => write!(f, "decode {what}: {source}"),
            Self::Codec(e) => write!(f, "codec: {e}"),
            Self::EncodeBin(e) => write!(f, "encode bin: {e}"),
            Self::EncodeBinmap(e) => write!(f, "encode binmap: {e}"),
            Self::EncodeSheaf(e) => write!(f, "encode sheaf: {e}"),
            Self::EncodeRoot(e) => write!(f, "encode root: {e}"),
            Self::MissingRoot { seq } => {
                write!(f, "root {seq} is listed but missing (concurrent delete?)")
            }
            Self::MissingMeta {
                what,
                id,
                volume,
                seq,
            } => write!(
                f,
                "{what} {id}, named by volume {volume:?} root {seq}, is missing (concurrent delete?)"
            ),
            Self::VolumeMismatch { want, got } => write!(
                f,
                "head root names volume {got:?} but was fetched from {want:?} (cross-volume replay)"
            ),
            Self::SeqMismatch { key_seq, doc_seq } => {
                write!(f, "root at key seq {key_seq} carries seq {doc_seq}")
            }
            Self::UnknownSigner { seq } => write!(
                f,
                "root {seq} carries no signature by this key — a publisher extends its own chain"
            ),
            Self::BadSignature { seq } => write!(f, "root {seq}: signature verification failed"),
            Self::CorruptMeta { id } => write!(f, "metadata object {id} does not hash to its id"),
            Self::NotAManifestNode { id } => write!(f, "object {id} is not a manifest node"),
            Self::MissingObject { id } => {
                write!(
                    f,
                    "object {id} is not in the local store — nothing uploaded"
                )
            }
            Self::LostRace {
                volume,
                attempted,
                head,
            } => write!(
                f,
                "lost the CAS race on volume {volume}: seq {attempted} is held by another \
                 writer (listing suggests head ~{head}, unverified). Nothing was committed; \
                 a re-run resolves the verified head — or fails loudly if the occupant does \
                 not decode and verify"
            ),
            Self::ProbeUnresolved {
                put_error,
                probe_error,
            } => write!(
                f,
                "put failed ({put_error}) and the settling probe also failed ({probe_error}) — \
                 the outcome is UNKNOWN: the publish may have landed; a re-run resolves it from \
                 the chain"
            ),
            Self::Unresolved { put_error } => write!(
                f,
                "put failed ({put_error}) and the settling probe found nothing at the attempted \
                 seq — the outcome is still UNKNOWN, because nothing here can prove that failed \
                 attempt was the only one sent: the publish may nonetheless have landed; a \
                 re-run resolves it from the chain"
            ),
            Self::RootTooLarge { len, cap } => write!(
                f,
                "root candidate is {len} bytes, over the {cap}-byte cap the settling probe reads \
                 under — no root PUT was sent, so the chain is unchanged"
            ),
            Self::FrameTooLong { len } => write!(f, "frame of {len} bytes exceeds u32"),
            // NOT "would overflow u64": true of the epoch limb, false of
            // the seq one: `u64::MAX` is reserved. A head of `u64::MAX - 1` gives
            // `checked_add` a perfectly good `Some(u64::MAX)` — nothing
            // overflows, the value is simply RESERVED — and the failure
            // must be reported as seq-space exhaustion rather
            // than as a false arithmetic claim. One wording covers both:
            // the epoch at `u64::MAX` and the seq at `u64::MAX - 1` alike
            // have no next value they are allowed to take.
            Self::CounterOverflow { what } => write!(f, "{what} has no usable next value"),
            Self::BinmapConstruction => write!(f, "binmap construction integrity failure"),
            Self::BadPlan => write!(f, "internal: bin plan does not cover its frames"),
            Self::ReservedVolumeName { volume } => write!(
                f,
                "volume {volume:?} does not exist and its name is reserved — pick another name. \
                 Nothing was uploaded; the local store may already hold this tree, because the \
                 harvest runs before this check"
            ),
        }
    }
}

impl std::error::Error for PublishError {}

impl From<HarvestError> for PublishError {
    fn from(e: HarvestError) -> Self {
        Self::Harvest(e)
    }
}
impl From<GrainSourceError> for PublishError {
    fn from(e: GrainSourceError) -> Self {
        Self::Source(e)
    }
}
impl From<RootStoreError> for PublishError {
    fn from(e: RootStoreError) -> Self {
        Self::Remote(e)
    }
}
impl From<CodecError> for PublishError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}
impl From<binfmt::EncodeBinError> for PublishError {
    fn from(e: binfmt::EncodeBinError) -> Self {
        Self::EncodeBin(e)
    }
}
impl From<binmap::EncodeBinmapError> for PublishError {
    fn from(e: binmap::EncodeBinmapError) -> Self {
        Self::EncodeBinmap(e)
    }
}
impl From<sheaf::EncodeSheafError> for PublishError {
    fn from(e: sheaf::EncodeSheafError) -> Self {
        Self::EncodeSheaf(e)
    }
}
impl From<root::EncodeRootError> for PublishError {
    fn from(e: root::EncodeRootError) -> Self {
        Self::EncodeRoot(e)
    }
}

fn decode_err(what: &'static str) -> impl FnOnce(DecodeError) -> PublishError {
    move |source| PublishError::Decode { what, source }
}

/// Map a refused head root at `head` onto the publisher's own errors.
fn head_err(head: u64, e: HeadError) -> PublishError {
    match e {
        HeadError::Identity(RootIdentityError::Decode(source)) => PublishError::Decode {
            what: "head root",
            source,
        },
        HeadError::Identity(RootIdentityError::VolumeMismatch { expected, found }) => {
            PublishError::VolumeMismatch {
                want: expected,
                got: found,
            }
        }
        HeadError::Identity(RootIdentityError::SeqMismatch { expected, found }) => {
            PublishError::SeqMismatch {
                key_seq: expected,
                doc_seq: found,
            }
        }
        HeadError::NoTrustedSlot => PublishError::UnknownSigner { seq: head },
        HeadError::BadSignature { .. } => PublishError::BadSignature { seq: head },
    }
}

// ------------------------------------------------------------ remote state

/// The volume as the remote store has it, reduced to what a publish
/// needs: where the chain is, and which ids the binmap already covers.
#[derive(Debug, Default)]
pub(crate) struct RemoteState {
    /// Seq this publish will claim (1 for a volume with no roots).
    pub(crate) seq: u64,
    /// Id of the head root's BYTES — the new root's parent (`None` iff
    /// `seq == 1`).
    pub(crate) parent: Option<GrainId>,
    epoch: u64,
    /// Head root's `sheaf_head` — the new sheaf's parent.
    sheaf_parent: Option<GrainId>,
    /// Every id the published binmap resolves, with its extent. Extents
    /// are carried unchanged into the new binmap: bin ordinals stay
    /// meaningful because the bin table is APPEND-ONLY.
    pub(crate) known: BTreeMap<GrainId, ShardEntry>,
    /// The bin table, positionally numbered — appended to, never
    /// reordered.
    pub(crate) bins: Vec<[u8; DIGEST_LEN]>,
    /// The head's routing width. `prefix_bits` never narrows.
    prefix_bits: u8,
    /// The head root's `binmap_index` — reused verbatim when this
    /// publish maps nothing new.
    binmap_index: Option<GrainId>,
    /// The head binmap's shard ids, positionally. Carried so a rebuild
    /// can skip re-uploading a shard whose bytes did not change:
    /// `put_meta` is `PutMode::Create`, which on S3 STREAMS THE WHOLE
    /// BODY before the 412, so an unconditional loop over
    /// `1 << prefix_bits` buckets would send every shard in full on
    /// every mapping publish — 256 full-body PUTs for a one-grain delta
    /// at `prefix_bits = 8`, 4096 at the max width — and the wire cost
    /// would stop being proportional to the TOUCHED shards the module
    /// doc promises. `remote_state` decodes these and
    /// keeps them here. Positional correspondence is only
    /// meaningful at an UNCHANGED width, and the skip is gated on that.
    prior_shards: Vec<GrainId>,
    prior_table: Option<(GrainId, Vec<u8>)>,
    prior_index: Option<Vec<u8>>,
}

impl RemoteState {
    /// A volume with no roots at all: seq 1, epoch 1, nothing known.
    pub(crate) const fn empty() -> Self {
        Self {
            seq: 1,
            parent: None,
            epoch: 1,
            sheaf_parent: None,
            known: BTreeMap::new(),
            bins: Vec::new(),
            prefix_bits: 0,
            binmap_index: None,
            prior_shards: Vec::new(),
            prior_table: None,
            prior_index: None,
        }
    }
}

/// Fetch and fully validate the head of `volume`: strict root decode,
/// the cross-volume replay check, signature verification under the
/// publishing key (self-publish trust model), then the binmap index,
/// bin table and every shard, content-address-checked on the way in.
///
/// **This is also the reserved-volume-name admission point.** It is the
/// publish flow's first remote call, and `max_seq` returning nothing is
/// the observed fact "this volume does not exist yet" — so the branch
/// below is exactly where a publish brings a volume into existence.
/// Every public entry point reaches it: `prepare` delegates to
/// `prepare_from_manifest`, which is this function's only caller, and
/// `commit` cannot create a volume because it only consumes a
/// [`Prepared`] this flow minted.
async fn remote_state<R: RootStore + BinStore>(
    remote: &R,
    volume: &VolumeName,
    key: &SigningKey,
) -> Result<RemoteState, PublishError> {
    let vol = volume.as_str();
    let Some(head) = remote.max_seq(vol).await? else {
        // Gated on the NEW-VOLUME condition, never on the name alone: a
        // reserved name must stay mintable by granary and extendable
        // afterwards, so a refusal at the top of the flow would break
        // the very volumes the registry exists to hold.
        if root::is_reserved_volume_name(volume) {
            return Err(PublishError::ReservedVolumeName {
                volume: vol.to_owned(),
            });
        }
        return Ok(RemoteState::empty());
    };
    let bytes = remote
        .get_root(vol, head)
        .await?
        .ok_or(PublishError::MissingRoot { seq: head })?;
    // The signature proves a writer we trust produced this root; it does
    // NOT prove which volume it was for. The check
    // verifies over the RECEIVED bytes' prefix, never a re-encoding.
    let trusted = TrustedKeys::new([*key.public_key()]).map_err(|_refused| {
        // Refused only for the all-zero key, which no signing key holds: a
        // pair the backend accepts is never all zero. It stays a refusal of
        // this root's signer rather than a panic.
        PublishError::UnknownSigner { seq: head }
    })?;
    state_from_head(remote, volume, head, &bytes, &trusted).await
}

pub(crate) async fn state_from_head<R: BinStore>(
    remote: &R,
    volume: &VolumeName,
    head: u64,
    bytes: &[u8],
    trusted: &TrustedKeys,
) -> Result<RemoteState, PublishError> {
    let vol = volume.as_str();
    let doc = crypto::check_head(bytes, vol, head, trusted).map_err(|e| head_err(head, e))?;
    let state = state_from_doc(remote, volume, head, bytes, &doc).await?;
    Ok(RemoteState {
        // ENFORCE THE SEQ RESERVATION ON WRITES, and it is not a nicety. Seq
        // `u64::MAX` is reserved and can never be a head, so the next seq
        // must land in `1 ..= u64::MAX - 1` — which makes `u64::MAX - 1` a
        // TERMINAL head rather than an ordinary one.
        //
        // Without the `filter`, a head of `u64::MAX - 1` — which the READ
        // side positively requires to stay valid — gives `checked_add` a
        // `Some(u64::MAX)`, `commit` writes a root there, and the publish
        // REPORTS SUCCESS. `max_seq` then hides that root from every
        // reader, the next publish selects `u64::MAX` again, gets
        // `AlreadyExists`, and the one-probe finds its own foreign bytes:
        // `LostRace`, which this module's docs call deliberately terminal.
        // Forever. Refusing here is strictly better than a success that
        // silently loses the volume. (Seq 0 needed no write-side rule
        // because it is unselectable by construction — `RemoteState::empty`
        // is seq 1 and `head + 1` is at least 2 — and `u64::MAX` gets no
        // such freebie.)
        seq: head
            .checked_add(1)
            .filter(|&next| next != u64::MAX)
            .ok_or(PublishError::CounterOverflow { what: "root seq" })?,
        epoch: doc
            .epoch
            .checked_add(1)
            .ok_or(PublishError::CounterOverflow { what: "root epoch" })?,
        ..state
    })
}

/// The binmap of a root read back from the store: every id it resolves and
/// the bin table. Only a read side holds one; it carries nothing a publish
/// could claim a successor from.
#[derive(Debug)]
pub(crate) struct PublishedBinmap {
    /// Every id the binmap resolves, with its extent.
    pub(crate) known: BTreeMap<GrainId, ShardEntry>,
    /// The bin table, positionally numbered.
    pub(crate) bins: Vec<[u8; DIGEST_LEN]>,
}

/// The binmap of a root read back from the store, without reserving a
/// successor: a read has no next seq or epoch, so a head at `u64::MAX - 1`
/// or an epoch at `u64::MAX` stays readable. The root's signature was checked
/// when it was read, and is not checked again.
pub(crate) async fn state_from_published<R: BinStore>(
    remote: &R,
    root: &crate::sync::PublishedRoot,
) -> Result<PublishedBinmap, PublishError> {
    let state = state_from_doc(remote, root.volume(), root.seq(), root.bytes(), root.doc()).await?;
    Ok(PublishedBinmap {
        known: state.known,
        bins: state.bins,
    })
}

/// The metadata reads behind a checked head: the binmap index, bin table and
/// every shard, validated on the way in. `doc` is the document `check_head`
/// returned for `bytes`, so every caller has checked the bytes first. The
/// counters describe the root read; `state_from_head` replaces them with the
/// next write's reservations.
async fn state_from_doc<R: BinStore>(
    remote: &R,
    volume: &VolumeName,
    head: u64,
    bytes: &[u8],
    doc: &root::RootDoc,
) -> Result<RemoteState, PublishError> {
    let vol = volume.as_str();
    let index_bytes = fetch_meta(remote, vol, head, "binmap index", &doc.binmap_index).await?;
    let index = binmap::decode_binmap_index(&index_bytes).map_err(decode_err("binmap index"))?;
    let table_bytes = fetch_meta(remote, vol, head, "bin table", &index.bin_table).await?;
    let bins = binmap::decode_bin_table(&table_bytes).map_err(decode_err("bin table"))?;
    let bin_count = u32::try_from(bins.len()).unwrap_or(u32::MAX);
    let mut known = BTreeMap::new();
    for (shard_index, shard_id) in index.shards.iter().enumerate() {
        let shard_bytes = fetch_meta(remote, vol, head, "binmap shard", shard_id).await?;
        let entries = binmap::decode_shard(&shard_bytes).map_err(decode_err("binmap shard"))?;
        // The bounds a shard cannot check alone: ordinals against the
        // table, ROUTING against its own position, and id uniqueness
        // ACROSS shards — a signed but misrouted/duplicated binmap is
        // refused as remote state, not silently accepted (these once
        // lived only in test helpers).
        binmap::validate_ordinals(&entries, bin_count).map_err(decode_err("binmap shard"))?;
        binmap::validate_routing(&entries, index.prefix_bits, shard_index)
            .map_err(decode_err("binmap shard"))?;
        for e in entries {
            if known.insert(e.id, e).is_some() {
                return Err(decode_err("binmap shard")(
                    granary_core::encoding::DecodeError::Invalid {
                        what: "duplicate grain id across binmap shards",
                    },
                ));
            }
        }
    }
    Ok(RemoteState {
        seq: head,
        parent: Some(GrainId::of(bytes)),
        epoch: doc.epoch,
        sheaf_parent: Some(doc.sheaf_head),
        known,
        bins,
        prefix_bits: index.prefix_bits,
        binmap_index: Some(doc.binmap_index),
        prior_shards: index.shards,
        prior_table: Some((index.bin_table, table_bytes)),
        prior_index: Some(index_bytes),
    })
}

/// Fetch a metadata object and check it against the id that named it —
/// content addressing is only a guarantee if someone checks it. `what`
/// names the object's role and `seq` the root that pointed at it, so a
/// missing one is refused BY NAME (`MissingMeta`) rather than surfacing
/// as a bare `Remote(NotFound)` that names neither the volume, the head
/// seq, nor which object.
async fn fetch_meta<R: BinStore>(
    remote: &R,
    volume: &str,
    seq: u64,
    what: &'static str,
    id: &GrainId,
) -> Result<Vec<u8>, PublishError> {
    let bytes = match remote.get_meta(volume, id).await {
        Ok(bytes) => bytes,
        Err(RootStoreError::NotFound) => {
            return Err(PublishError::MissingMeta {
                what,
                id: *id,
                volume: volume.to_owned(),
                seq,
            });
        }
        Err(e) => return Err(PublishError::Remote(e)),
    };
    if GrainId::of(&bytes) != *id {
        return Err(PublishError::CorruptMeta { id: *id });
    }
    Ok(bytes)
}

// ------------------------------------------------------------ publish set

/// The manifest closure of `root`, in traversal order (see the module
/// doc's locality note). Ids are unique and every one of them is an
/// object the volume must be able to resolve.
pub(crate) fn collect_objects<G: GrainSource + ?Sized>(
    store: &G,
    root: &GrainId,
) -> Result<Vec<GrainId>, PublishError> {
    collect_objects_pruned(store, root, &BTreeSet::new())
}

/// [`collect_objects`] that records the ids in `reuse` but never opens them.
/// The caller vouches that everything beneath a reused id is already mapped, so
/// the full walk would emit those ids and every one would be filtered out as
/// known: the ids this returns that are not mapped equal the full walk's, in
/// the same order.
pub(crate) fn collect_objects_pruned<G: GrainSource + ?Sized>(
    store: &G,
    root: &GrainId,
    reuse: &BTreeSet<GrainId>,
) -> Result<Vec<GrainId>, PublishError> {
    let mut out = Vec::new();
    // TWO sets, two questions: `emitted` answers "is this
    // id already in `out`" for BOTH roles — a grain and a node can
    // share an id when a file's bytes are a node's encoding, so `out`
    // is deduplicated over the union. The walk is what guarantees that:
    // `encode_bin` refuses a duplicate grain id only WITHIN one bin, so
    // a duplicate split across a `plan_bins` boundary would pass it.
    // Expansion is not gated on `emitted` AT ALL, because an id first
    // met as a grain must still be opened
    // when it is later met as a node, or its subtree is silently absent
    // from the signed set. `expanded` answers a DIFFERENT question —
    // "have this node's children been discovered" — and is what keeps a
    // shared node read ONCE rather than once per path reaching it.
    // Dropping it leaves the emitted set and its order identical and
    // makes reads exponential in sharing depth, which is why a read
    // COUNTER pins it and no output check can. It is also what bounds
    // the walk without leaning on that: `GrainSource::get` is
    // contractually hash-verified, so a cycle needs a preimage
    // cycle and cannot be built — and `expanded` makes termination hold
    // anyway, for an id met twice by any route.
    let mut emitted: BTreeSet<GrainId> = BTreeSet::new();
    let mut expanded: BTreeSet<GrainId> = BTreeSet::new();
    let mut work: Vec<Item> = vec![Item::Node(*root)];
    while let Some(item) = work.pop() {
        match item {
            Item::Grain(id) => push_grain(&id, &mut out, &mut emitted),
            Item::Node(id) => {
                if emitted.insert(id) {
                    out.push(id);
                }
                if expanded.insert(id) && !reuse.contains(&id) {
                    let mut items = expand(store, &id)?;
                    items.reverse();
                    work.extend(items);
                }
            }
        }
    }
    Ok(out)
}

/// One entry on the publish-set worklist: a manifest node to open, or
/// a grain to record. Grains are items rather than emitted inline
/// because a directory leaf interleaves them with subdirectories, and
/// the emission ORDER between the two is the locality order.
enum Item {
    Node(GrainId),
    Grain(GrainId),
}

/// Read one manifest node and return what it references, in manifest
/// order.
fn expand<G: GrainSource + ?Sized>(store: &G, id: &GrainId) -> Result<Vec<Item>, PublishError> {
    // Read-verified: `Store::get` hashes what it read.
    let bytes = store.get(id)?;
    let (ty, cursor) = encoding::open_envelope(&bytes).map_err(decode_err("manifest node"))?;
    let mut items = Vec::new();
    match ty {
        ObjectType::DirLeaf => {
            for entry in manifest::decode_dir_leaf(cursor).map_err(decode_err("dir leaf"))? {
                match entry.kind {
                    EntryKind::Dir { child } => items.push(Item::Node(child)),
                    EntryKind::File { grains, .. } => match grains {
                        FileGrains::Inline(refs) => {
                            items.extend(refs.into_iter().map(|r| Item::Grain(r.id)));
                        }
                        FileGrains::Spill { root, .. } => items.push(Item::Node(root)),
                    },
                    EntryKind::Symlink { .. } | EntryKind::Fifo | EntryKind::Socket => {}
                }
            }
        }
        ObjectType::DirInterior => {
            for child in
                manifest::decode_dir_interior(cursor).map_err(decode_err("dir interior"))?
            {
                items.push(Item::Node(child.child));
            }
        }
        ObjectType::GrainListLeaf => {
            for r in
                manifest::decode_grain_list_leaf(cursor).map_err(decode_err("grain-list leaf"))?
            {
                items.push(Item::Grain(r.id));
            }
        }
        ObjectType::GrainListIndex => {
            for child in
                manifest::decode_grain_list_index(cursor).map_err(decode_err("grain-list index"))?
            {
                items.push(Item::Node(child.child));
            }
        }
        ObjectType::Bin
        | ObjectType::BinmapIndex
        | ObjectType::BinTable
        | ObjectType::BinmapShard
        | ObjectType::Root
        | ObjectType::Sheaf => return Err(PublishError::NotAManifestNode { id: *id }),
    }
    Ok(items)
}

/// A grain is a leaf: recorded, never opened here (its bytes are read
/// only if it turns out to be novel).
fn push_grain(id: &GrainId, out: &mut Vec<GrainId>, emitted: &mut BTreeSet<GrainId>) {
    if emitted.insert(*id) {
        out.push(*id);
    }
}

// ------------------------------------------------------------ binmap width

/// The narrowest routing width whose EXPECTED shard lands inside
/// [`SHARD_TARGET_BYTES`], never narrower than `floor` (monotonic per
/// volume) and never wider than [`binmap::PREFIX_BITS_MAX`]
/// (which is a refuse cap, not a target: a volume past the target at the
/// widest legal routing keeps publishing, with bigger shards).
fn choose_prefix_bits(entries: u64, floor: u8) -> u8 {
    let floor = floor.min(binmap::PREFIX_BITS_MAX);
    let entry_bytes = entries.saturating_mul(SHARD_ENTRY_LEN as u64);
    for bits in floor..=binmap::PREFIX_BITS_MAX {
        if entry_bytes / (1u64 << bits) <= SHARD_TARGET_BYTES {
            return bits;
        }
    }
    binmap::PREFIX_BITS_MAX
}

// ------------------------------------------------------------ the flow

/// Harvest into `store`, then upload and sign — everything except
/// claiming the seq. The CLI's convenience wrapper over
/// [`harvest::harvest`] + [`prepare_from_manifest`].
///
/// `store` is the CONCRETE local store, not a [`GrainSource`], because
/// harvest WRITES it. The simulator drives [`prepare_from_manifest`]
/// instead — see the module doc's note on the split. The two must not
/// drift: this function's whole body after the harvest is one delegated
/// call, so there is no second copy of the flow to keep in step.
///
/// # Errors
/// Any [`PublishError`]; nothing has been committed when this fails,
/// though bins/binmap objects may already be in the bucket (they are
/// content-addressed and unreferenced until a root names them).
#[expect(
    clippy::too_many_arguments,
    reason = "the wrapper takes exactly what `prepare_from_manifest` takes, with the harvest's \
              two inputs in place of its two outputs — see the reason there"
)]
pub async fn prepare<R: RootStore + BinStore>(
    remote: &R,
    store: &Store,
    source: &Path,
    volume: &VolumeName,
    key: &SigningKey,
    identity: &WriterIdentity,
    now: Timestamp,
    policy: Policy,
) -> Result<Prepared, PublishError> {
    // 1. Harvest into the local store.
    let (manifest_root, harvest_stats) = harvest::harvest(source, store)?;
    prepare_from_manifest(
        remote,
        store,
        manifest_root,
        harvest_stats,
        volume,
        key,
        identity,
        now,
        policy,
    )
    .await
}

/// [`prepare`] with one descriptor-derived file identity that the
/// harvest must refuse. The CLI uses this for the private key seed; the
/// ordinary public API remains available to callers that have no secret
/// file to exclude.
///
/// # Errors
/// Any [`PublishError`], including a harvest refusal when `refused`
/// appears under any name in `source`.
#[doc(hidden)]
#[expect(
    clippy::too_many_arguments,
    reason = "the protected-file wrapper takes exactly what `prepare` takes plus the identity \
              captured from the seed descriptor"
)]
pub async fn prepare_excluding_file<R: RootStore + BinStore>(
    remote: &R,
    store: &Store,
    source: &Path,
    refused: FileIdentity,
    volume: &VolumeName,
    key: &SigningKey,
    identity: &WriterIdentity,
    now: Timestamp,
    policy: Policy,
) -> Result<Prepared, PublishError> {
    prepare_excluding_files(
        remote,
        store,
        source,
        &[refused],
        volume,
        key,
        identity,
        now,
        policy,
    )
    .await
}

/// Protect several descriptor identities during harvest, before any remote call.
///
/// # Errors
/// Any [`PublishError`], including refusal of any protected file alias.
#[expect(
    clippy::too_many_arguments,
    reason = "the protected harvest wrapper preserves the preparation inputs"
)]
pub async fn prepare_excluding_files<R: RootStore + BinStore>(
    remote: &R,
    store: &Store,
    source: &Path,
    refused: &[FileIdentity],
    volume: &VolumeName,
    key: &SigningKey,
    identity: &WriterIdentity,
    now: Timestamp,
    policy: Policy,
) -> Result<Prepared, PublishError> {
    let (manifest_root, harvest_stats) = harvest::harvest_excluding_files(source, store, refused)?;
    prepare_from_manifest(
        remote,
        store,
        manifest_root,
        harvest_stats,
        volume,
        key,
        identity,
        now,
        policy,
    )
    .await
}

/// Upload and sign a tree that is ALREADY in the local store —
/// everything from novelty computation to the signed root bytes, with no
/// filesystem walk and no local write.
///
/// This is the generic entry point: `remote` is any [`RootStore`] +
/// [`BinStore`] and `store` any [`GrainSource`], so the whole flow runs
/// against fakes with no bucket and no filesystem. `manifest_root` and
/// `harvest_stats` are what a harvest produced; the simulator supplies
/// them from a synthetic tree, the CLI from [`prepare`].
///
/// `harvest_stats` is carried into the summary unchanged — nothing here
/// re-derives it, and no field of it enters the root's preimage, so it
/// is reporting only.
///
/// # Errors
/// Any [`PublishError`]; nothing has been committed when this fails,
/// though bins/binmap objects may already be in the bucket (they are
/// content-addressed and unreferenced until a root names them).
#[expect(
    clippy::too_many_arguments,
    reason = "every argument is an input the CALLER owns, and two of them — the writer \
              identity and the timestamp — are seam values that exist precisely so the \
              caller supplies them explicitly; bagging them into a struct would re-hide the \
              inputs this signature makes visible"
)]
pub async fn prepare_from_manifest<R: RootStore + BinStore, G: GrainSource + ?Sized>(
    remote: &R,
    store: &G,
    manifest_root: GrainId,
    harvest_stats: HarvestStats,
    volume: &VolumeName,
    key: &SigningKey,
    identity: &WriterIdentity,
    now: Timestamp,
    policy: Policy,
) -> Result<Prepared, PublishError> {
    // 2. What the volume already has — and, when it has nothing, the
    //    reserved-name admission check (see `remote_state`).
    let state = remote_state(remote, volume, key).await?;

    prepare_from_state(
        remote,
        store,
        manifest_root,
        harvest_stats,
        volume,
        key,
        identity,
        now,
        policy,
        state,
    )
    .await
}

/// Closure whose bins and metadata have all completed acceptance barriers.
/// It grants no root-store or cache admission capability.
#[derive(Debug)]
pub(crate) struct AcceptedManifest {
    pub(crate) doc: RootDoc,
    pub(crate) summary: PublishSummary,
    /// Every id the new binmap resolves: the head's entries plus this call's.
    pub(crate) mapped: BTreeMap<GrainId, ShardEntry>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit construction inputs shared with recovery"
)]
pub(crate) async fn prepare_from_state<R: BinStore, G: GrainSource + ?Sized>(
    remote: &R,
    store: &G,
    manifest_root: GrainId,
    harvest_stats: HarvestStats,
    volume: &VolumeName,
    key: &SigningKey,
    identity: &WriterIdentity,
    now: Timestamp,
    policy: Policy,
    state: RemoteState,
) -> Result<Prepared, PublishError> {
    let accepted = accept_from_state(
        remote,
        store,
        manifest_root,
        harvest_stats,
        volume,
        now,
        policy,
        state,
    )
    .await?;
    drop(accepted.mapped);
    let mut doc = accepted.doc;
    doc.writer_uuid = writer_uuid(now, identity, doc.seq, volume, &manifest_root);
    let prefix = root::signing_prefix_of(&doc)?;
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&prefix),
    });
    Ok(Prepared {
        volume: volume.clone(),
        seq: doc.seq,
        root_bytes: root::encode_root(&doc)?,
        summary: accepted.summary,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "explicit captured object construction inputs"
)]
pub(crate) async fn accept_from_state<R: BinStore, G: GrainSource + ?Sized>(
    remote: &R,
    store: &G,
    manifest_root: GrainId,
    harvest_stats: HarvestStats,
    volume: &VolumeName,
    now: Timestamp,
    policy: Policy,
    state: RemoteState,
) -> Result<AcceptedManifest, PublishError> {
    accept_objects_from_state(
        remote,
        store,
        manifest_root,
        harvest_stats,
        volume,
        now,
        policy,
        state,
        &[],
        &BTreeSet::new(),
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "ordered preparation shared by direct publication and verified recovery"
)]
pub(crate) async fn accept_objects_from_state<R: BinStore, G: GrainSource + ?Sized>(
    remote: &R,
    store: &G,
    manifest_root: GrainId,
    harvest_stats: HarvestStats,
    volume: &VolumeName,
    now: Timestamp,
    policy: Policy,
    state: RemoteState,
    extra: &[GrainId],
    reuse: &BTreeSet<GrainId>,
) -> Result<AcceptedManifest, PublishError> {
    let accepted = accept_loaded_objects(
        remote,
        store,
        manifest_root,
        harvest_stats,
        volume,
        now,
        policy,
        shards::State::from_full(state),
        extra,
        reuse,
    )
    .await?;
    Ok(AcceptedManifest {
        doc: accepted.doc,
        summary: accepted.summary,
        mapped: accepted.complete.ok_or(PublishError::BinmapConstruction)?,
    })
}

/// A sync result makes no complete-map claim. Only full loading can fill the
/// private complete set consumed by commit construction.
#[derive(Debug)]
pub(crate) struct AcceptedObjects {
    pub(crate) doc: RootDoc,
    pub(crate) summary: PublishSummary,
    complete: Option<BTreeMap<GrainId, ShardEntry>>,
    pub(crate) work: shards::Work,
}
impl AcceptedObjects {
    pub(crate) fn take_complete(&mut self) -> Result<BTreeSet<GrainId>, PublishError> {
        self.complete
            .take()
            .map(|map| map.into_keys().collect())
            .ok_or(PublishError::BinmapConstruction)
    }
}

#[expect(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    reason = "ordered captured closure packing shares one acceptance barrier"
)]
pub(crate) async fn accept_loaded_objects<R: BinStore, G: GrainSource + ?Sized>(
    remote: &R,
    store: &G,
    manifest_root: GrainId,
    harvest_stats: HarvestStats,
    volume: &VolumeName,
    now: Timestamp,
    policy: Policy,
    mut state: shards::State,
    extra: &[GrainId],
    reuse: &BTreeSet<GrainId>,
) -> Result<AcceptedObjects, PublishError> {
    let vol = volume.as_str();
    // 3. Novelty: the manifest closure minus what the binmap covers.
    let mut publish_set = collect_objects_pruned(store, &manifest_root, reuse)?;
    publish_set.retain(|id| !reuse.contains(id));
    let mut emitted: BTreeSet<_> = publish_set.iter().copied().collect();
    publish_set.extend(extra.iter().copied().filter(|id| emitted.insert(*id)));
    let novel = state.select(remote, vol, &publish_set).await?;

    // This publish's commit record. It is NOT part of the pack set: a
    // sheaf is a directly-addressed meta object (see the module doc),
    // so it never enters a bin and never gets a binmap entry, and a
    // publish that changes nothing else therefore touches nothing else.
    let sheaf_doc = SheafDoc {
        parent: state.sheaf_parent,
        manifest_root,
        timestamp: now,
        ops: vec![SheafOp::PublishTree],
    };
    let sheaf_bytes = sheaf::encode_sheaf(&sheaf_doc)?;
    let sheaf_head = GrainId::of(&sheaf_bytes);

    // 4. Pack. Refuse a missing object BEFORE the first upload: a
    // half-published volume is worse than a refused one.
    for id in &novel {
        if !store.has(id) {
            return Err(PublishError::MissingObject { id: *id });
        }
    }
    let mut codec = GrainCodec::new()?;
    let mut frames: Vec<PackedFrame> = Vec::with_capacity(novel.len());
    // The planner's input, pushed in the SAME iteration as the frame it
    // describes: `FramePlan` carries both lengths, so the compressed
    // length and the declared decompressed length of one grain cannot
    // come to be paired with another's.
    let mut planned: Vec<binfmt::FramePlan> = Vec::with_capacity(novel.len());
    let mut novel_bytes: u64 = 0;
    for id in &novel {
        let bytes = store.get(id)?;
        if GrainId::of(&bytes) != *id {
            return Err(PublishError::CorruptMeta { id: *id });
        }
        novel_bytes = novel_bytes.saturating_add(bytes.len() as u64);
        // The grain's own length is what the frame header will declare
        // (the codec writes it), so it is read here rather than decoded
        // back out of the frame.
        let unpacked_len = u32::try_from(bytes.len())
            .map_err(|_| PublishError::FrameTooLong { len: bytes.len() })?;
        let frame = codec.compress_grain(&bytes)?;
        let comp_len = u32::try_from(frame.len())
            .map_err(|_| PublishError::FrameTooLong { len: frame.len() })?;
        planned.push(binfmt::FramePlan {
            comp_len,
            unpacked_len,
        });
        frames.push(PackedFrame { id: *id, frame });
    }
    let plans = binfmt::plan_bins(&planned)?;

    // 5. Upload bins, appending to the bin table as they land.
    let mut bins = state.bins.clone();
    let mut new_entries: Vec<ShardEntry> = Vec::with_capacity(novel.len());
    let mut bins_uploaded: u64 = 0;
    let mut bin_bytes_uploaded: u64 = 0;
    for plan in &plans {
        let group = frames.get(plan.clone()).ok_or(PublishError::BadPlan)?;
        let bin = binfmt::encode_bin(group)?;
        let digest = *GrainId::of(&bin).digest();
        // Ordinals are positions in an APPEND-ONLY table: an existing
        // digest keeps the position it already has.
        let ordinal = if let Some(at) = bins.iter().position(|d| *d == digest) {
            at
        } else {
            bins.push(digest);
            bins.len().saturating_sub(1)
        };
        let ordinal = u32::try_from(ordinal).map_err(|_| PublishError::BadPlan)?;
        // The bin's OWN index is the extent authority — decoded back out
        // of the bytes that are about to be uploaded, not recomputed.
        let index = binfmt::decode_bin(&bin).map_err(decode_err("freshly encoded bin"))?;
        for e in index {
            new_entries.push(ShardEntry {
                id: e.id,
                bin_ordinal: ordinal,
                offset: e.offset,
                comp_len: e.comp_len,
            });
        }
        let len = bin.len() as u64;
        if remote.put_bin(&digest, bin).await? {
            bins_uploaded = bins_uploaded.saturating_add(1);
            bin_bytes_uploaded = bin_bytes_uploaded.saturating_add(len);
        }
    }

    // Only verified final bytes may cross the metadata acceptance barrier.
    #[cfg_attr(
        not(test),
        expect(
            unused_mut,
            reason = "test-only bound corruption edits final bytes before verification"
        )
    )]
    let mut built = shards::build(&state, &bins, &new_entries, policy)?;
    #[cfg(test)]
    shards::injection::apply(&state, &mut built)?;
    let verified = shards::verify(&state, &bins, &new_entries, &publish_set, policy, built)?;
    let prefix_bits = verified.prefix_bits();
    let shard_count = 1usize << prefix_bits;
    let binmap_index = verified.index_id();
    let (shards_rewritten, complete, work) = verified.upload(remote, vol).await?;

    // 7. The sheaf: a DIRECTLY-ADDRESSED meta object, like the binmap
    // index and the bin table (see the module doc).
    // One per publish, resolved by `get_meta(volume, sheaf_head)`.
    let sheaf_uploaded = remote.put_meta(vol, &sheaf_head, sheaf_bytes).await?;

    Ok(AcceptedObjects {
        doc: RootDoc {
            volume: volume.clone(),
            seq: state.seq,
            parent: state.parent,
            writer_uuid: [0; 16],
            epoch: state.epoch,
            timestamp: now,
            chunker_spec: CHUNKER_SPEC.to_string(),
            manifest_root,
            binmap_index,
            sheaf_head,
            sigs: Vec::new(),
        },
        summary: PublishSummary {
            seq: state.seq,
            epoch: state.epoch,
            novel_objects: novel.len() as u64,
            novel_bytes,
            bins_planned: plans.len() as u64,
            bins_uploaded,
            bin_bytes_uploaded,
            shards_total: shard_count as u64,
            shards_rewritten,
            sheaf_uploaded,
            prefix_bits,
            manifest_root,
            binmap_index,
            sheaf_head,
            hint_written: false,
            harvest: harvest_stats,
        },
        complete,
        work,
    })
}

/// Claim the seq (put-if-absent) and repair the hint.
///
/// # Errors
/// [`PublishError::RootTooLarge`] when the candidate is over the
/// settling probe's own read cap, refused before any `PUT`;
/// [`PublishError::LostRace`] when another writer took the seq —
/// deliberately terminal (see the module doc); [`PublishError::Unresolved`]
/// or [`PublishError::ProbeUnresolved`] when a failed `PUT`'s outcome
/// cannot be settled (the ONE-PROBE RULE, `granary_core::rootstore`). This
/// function never returns [`PublishError::Remote`]: every `put_root`
/// failure is resolved by the one probe into one of the variants above.
pub async fn commit<R: RootStore>(
    remote: &R,
    prepared: Prepared,
) -> Result<PublishSummary, PublishError> {
    let Prepared {
        volume,
        seq,
        root_bytes,
        mut summary,
    } = prepared;
    // REFUSED BEFORE ANY PUT, never after. `root_bytes` is public on
    // `Prepared` (read-after-write self-identification needs a caller
    // able to pre-place bytes), so this function cannot trust that what
    // it received is what `prepare` produced. Without this guard an
    // oversized candidate that somehow landed would make the settling
    // probe's own `OverCap` refusal — built to prove an occupant is
    // FOREIGN — misreport this writer's own bytes as a lost race.
    let candidate_len = root_bytes.len();
    if u64::try_from(candidate_len).unwrap_or(u64::MAX) > ROOT_MAX_BYTES {
        return Err(PublishError::RootTooLarge {
            len: candidate_len,
            cap: ROOT_MAX_BYTES,
        });
    }
    let vol = volume.as_str();
    match remote.put_root(vol, seq, root_bytes.clone()).await {
        Ok(()) => {}
        Err(first) => {
            // Read-after-write self-identification (the
            // decision-validation RootStore shape): a retried or
            // transport-ambiguous PUT whose FIRST attempt landed is
            // indistinguishable from a lost race by the error alone —
            // object_store's own retry can surface AlreadyExists for
            // our own committed bytes. One probe settles it: if the
            // object at our seq IS byte-identical to what we tried to
            // write, we won.
            //
            // The arms below read the ONE-PROBE RULE's table
            // (`granary_core::rootstore` module doc) in order: ours
            // lands; foreign bytes or an `OverCap` refusal are a lost
            // race; any OTHER refusal proves nothing about the occupant
            // and is unresolved; absent is unresolved too, because
            // nothing here can prove the failed PUT's own attempt was
            // the only one sent; and a probe that itself errors carries
            // both errors.
            match remote.get_root(vol, seq).await {
                Ok(Some(present)) if present == root_bytes => {
                    // Our publish landed; fall through to the hint.
                }
                // `OverCap` is an ANSWER, not a failure to get one:
                // `get_root` bounds what it reads, and an object too
                // large to be a legal root is one no publish here could
                // have written, so it is foreign by the same reasoning
                // as bytes that simply differ. Folded into this arm
                // rather than given its own, because what the probe
                // established is identical and the outcome must be too.
                //
                // Routed here explicitly because it would otherwise fall
                // to the probe-failed catch-all below and become a
                // generic `ProbeUnresolved`, discarding the one thing
                // the probe proved — that the seq is DEFINITELY occupied
                // by someone else, not merely that something went wrong
                // reading it.
                Ok(Some(_))
                | Err(RootStoreError::RefusedResponse {
                    kind: RefusalKind::OverCap,
                    ..
                }) => {
                    // FOREIGN bytes at our seq: a lost race however the
                    // first error was spelled (a timeout can race too) —
                    // report the contested seq + a diagnostic head.
                    // And once foreignness is ESTABLISHED, a failing
                    // listing must not demote this to a bare transport
                    // error: best-effort head, floor = the contested
                    // seq itself.
                    // Clamped: get_root already PROVED seq occupied, so
                    // a listing that omits it (incomplete or adversarial)
                    // must not report head < seq.
                    let head = remote
                        .max_seq(vol)
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or(seq)
                        .max(seq);
                    return Err(PublishError::LostRace {
                        volume: vol.to_owned(),
                        attempted: seq,
                        head,
                    });
                }
                Ok(None) => {
                    // The probe ANSWERED: nothing is at our seq. That is
                    // NOT the same as "the PUT genuinely failed" — this
                    // client has no carrier proving the failed PUT's own
                    // attempt was the only one sent (the module doc's
                    // reason), so the outcome stays unresolved rather
                    // than being promoted to the plain original error.
                    return Err(PublishError::Unresolved { put_error: first });
                }
                // Reached both by the probe itself failing, and by a
                // refusal of any kind OTHER than `OverCap` — a framing
                // fault, a work limit — which is an answer about the
                // TRANSPORT, not about what occupies the seq: it proves
                // nothing an `OverCap` proves, so it settles nothing and
                // is treated exactly like any other probe error.
                Err(probe_error) => {
                    // Whether the PUT landed is now UNKNOWN, not "no" —
                    // carry BOTH errors rather than silently keeping only
                    // the PUT's error.
                    return Err(PublishError::ProbeUnresolved {
                        put_error: first,
                        probe_error,
                    });
                }
            }
        }
    }
    // Advisory only: a lost hint is a designed state.
    //
    // The failure is REPORTED, not printed: this is library code with a
    // sim caller, so a `gran publish:`-branded line would be wrong in
    // half its callers, and `eprintln!` panics on a closed stderr —
    // which is exactly why `sim-replay` writes its own output without
    // the macro. `hint_written` carries it to whoever is the operator's
    // voice.
    summary.hint_written = remote.write_hint(vol, seq).await.is_ok();
    Ok(summary)
}

/// [`prepare`] then [`commit`] — what the CLI runs.
///
/// # Errors
/// Any [`PublishError`].
#[expect(
    clippy::too_many_arguments,
    reason = "the wrapper takes exactly what `prepare` takes — see the reason there"
)]
pub async fn publish<R: RootStore + BinStore>(
    remote: &R,
    store: &Store,
    source: &Path,
    volume: &VolumeName,
    key: &SigningKey,
    identity: &WriterIdentity,
    now: Timestamp,
    policy: Policy,
) -> Result<PublishSummary, PublishError> {
    let prepared = prepare(remote, store, source, volume, key, identity, now, policy).await?;
    commit(remote, prepared).await
}

/// [`publish`] with the private seed's descriptor identity excluded from
/// the source harvest. Kept as the exact combined-flow counterpart of
/// [`prepare_excluding_file`] for callers and end-to-end tests that use
/// the convenience wrapper.
///
/// # Errors
/// Any [`PublishError`].
#[doc(hidden)]
#[expect(
    clippy::too_many_arguments,
    reason = "the wrapper takes exactly what `prepare_excluding_file` takes"
)]
pub async fn publish_excluding_file<R: RootStore + BinStore>(
    remote: &R,
    store: &Store,
    source: &Path,
    refused: FileIdentity,
    volume: &VolumeName,
    key: &SigningKey,
    identity: &WriterIdentity,
    now: Timestamp,
    policy: Policy,
) -> Result<PublishSummary, PublishError> {
    publish_excluding_files(
        remote,
        store,
        source,
        &[refused],
        volume,
        key,
        identity,
        now,
        policy,
    )
    .await
}

/// Protect several descriptor identities during harvest, before any remote call.
///
/// # Errors
/// Any [`PublishError`], including refusal of any protected file alias.
#[expect(
    clippy::too_many_arguments,
    reason = "the protected harvest wrapper preserves the preparation inputs"
)]
pub async fn publish_excluding_files<R: RootStore + BinStore>(
    remote: &R,
    store: &Store,
    source: &Path,
    refused: &[FileIdentity],
    volume: &VolumeName,
    key: &SigningKey,
    identity: &WriterIdentity,
    now: Timestamp,
    policy: Policy,
) -> Result<PublishSummary, PublishError> {
    let prepared = prepare_excluding_files(
        remote, store, source, refused, volume, key, identity, now, policy,
    )
    .await?;
    commit(remote, prepared).await
}

/// v1 `writer_uuid`: 16 bytes of a blake3 digest over
/// this invocation's timestamp, writer identity, seq, volume and
/// manifest root. It is an IDENTITY, not a secret and not a fencing
/// token — fencing semantics sharpen in Phase 2; what v1 needs is
/// that two concurrent publishes can tell their own root from the
/// other's after an ambiguous retry, which this gives
/// without pulling an rng or a uuid crate into the client.
///
/// **PURE: every byte of the preimage is an argument.** Mixing
/// `std::process::id()` in here would make three processes given
/// identical inputs mint three different SIGNED roots and so make
/// replay impossible. Who the writer is arrives as a
/// [`WriterIdentity`] the caller built, so
/// freshness is the caller's contract.
///
/// **The domain separator is `v2`, and it moves with the layout.**
/// Re-deriving a different value from a changed preimage under an
/// unchanged separator is precisely the silent drift the golden pin
/// test exists to catch.
fn writer_uuid(
    now: Timestamp,
    identity: &WriterIdentity,
    seq: u64,
    volume: &VolumeName,
    manifest_root: &GrainId,
) -> [u8; WRITER_UUID_LEN] {
    let mut seed = Vec::new();
    seed.extend_from_slice(b"granary-writer-uuid-v2");
    seed.extend_from_slice(&now.secs.to_be_bytes());
    seed.extend_from_slice(&now.nanos.to_be_bytes());
    seed.extend_from_slice(identity.as_bytes());
    seed.extend_from_slice(&seq.to_be_bytes());
    seed.extend_from_slice(volume.as_str().as_bytes());
    seed.extend_from_slice(&manifest_root.to_bytes());
    let digest = *GrainId::of(&seed).digest();
    let mut out = [0u8; WRITER_UUID_LEN];
    for (slot, b) in out.iter_mut().zip(digest.iter()) {
        *slot = *b;
    }
    out
}

#[cfg(test)]
mod tests;
