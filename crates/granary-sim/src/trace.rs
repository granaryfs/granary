// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The sim owns its replay artifact: a structured
//! operation log the fakes append to, rendered by the formatter below.
//!
//! **Not `tracing`.** The meta-test compares one seed's artifact across
//! two processes byte for byte, and `tracing` cannot be that artifact:
//!
//! - **There is nothing to compare.** `tracing` is not a dependency of
//!   granary-client, and the whole workspace holds exactly ONE `tracing::`
//!   call — in a server scaffold the sim never runs. A meta-test against
//!   tracing output would compare empty to empty: vacuously green
//!   forever, whatever the defect.
//! - **The subscriber stamps wall time from inside the dependency.**
//!   `tracing_subscriber::fmt()`'s default timer calls
//!   `std::time::SystemTime::now()` in a foreign crate, where clippy's
//!   `disallowed_methods` cannot see it and where no clock seam
//!   virtualizes it.
//! - **ANSI is on by default**, even when stdout is not a tty.
//! - **Span ids come from a thread-keyed slab**: the same span renders
//!   `Some(274877906945)` under `cargo test` and `Some(1)` under
//!   `cargo nextest`.
//!
//! `tracing` may still be emitted alongside for humans. It is never the
//! compared artifact.
//!
//! # The five rules this module exists to enforce
//!
//! 1. **Every writing variant records the full content it wrote.** Not
//!    decoration: `writer_uuid` affects exactly one thing — the bytes of
//!    the signed root — so an artifact of operation-kind + volume + seq
//!    would be byte-identical with and without an ambient pid in the
//!    preimage, and the negative proof that the pid is gone would pass
//!    while proving nothing. Concretely: the three object PUTs carry a
//!    non-optional [`Address`], and the whole 32 bytes reach the
//!    rendering — a truncated address would let two distinct objects
//!    render the same. [`Op::WriteHint`] carries no address because it
//!    writes no object: a hint's entire written content is
//!    `(volume, seq)`, and both are recorded.
//! 2. **Errors render from the fixed vocabulary in [`TraceError`]**, and
//!    an `io::Error` contributes its [`io::ErrorKind`] and nothing else.
//!    `io::Error`'s own `Display` is locale-sensitive under glibc's
//!    `strerror_r`, and two of the three CI platforms are glibc.
//!    granary-client's `io_kind_name` is the existing precedent, and so
//!    is its reasoning: `ErrorKind`'s `Debug` is NOT a fixed vocabulary
//!    — `Uncategorized` is std's unstable catch-all, its membership
//!    shrinks as std names new kinds, and rendering it would make the
//!    artifact toolchain-version-dependent. The conversion is
//!    `From<io::ErrorKind>`, so there is no constructor an `io::Error`
//!    can reach at all.
//! 3. **No absolute paths and no ambient ids** — no pids, no fds, no
//!    temp paths. Note the scope: a content address is not ambient, and
//!    rule 1 requires it. There are exactly two ways ambient text could
//!    reach the artifact, and both are closed by type: the free-text
//!    half of a backend error, so [`TraceError::Backend`] carries none;
//!    and the volume name, so it is a [`Volume`] and not a `String` —
//!    an unconstrained volume puts a temp path in `vol=…` with nothing
//!    to stop it.
//! 4. **[`Trace::is_empty`] exists so the meta-test can refuse a vacuous
//!    artifact.** Two empty renderings compare equal; a comparison that
//!    does not first assert the artifact recorded something is a check
//!    that cannot fail.
//! 5. **The rendering is INJECTIVE: runs that did different things
//!    render different bytes.** [`Trace::render`] IS the artifact the
//!    cross-process meta-test compares, so a genuine divergence that
//!    rendered equal would be a green test over a broken replay.
//!    Injectivity is not a property of the format alone — it holds only
//!    while no field's alphabet contains the separators the format uses.
//!    A free-text volume carrying `"demo -> ok\nn0 read-hint vol=evil"`
//!    makes a ONE-entry trace render byte-identically to a TWO-entry
//!    one; [`Volume`]'s closed alphabet is what removes that, and
//!    `structurally_different_traces_never_render_identically` is the
//!    property test.
//!
//! # Why an address here is a bare `[u8; 32]`
//!
//! The artifact names an object by the digest it renders and needs
//! nothing else of it: rule 1 wants all 32 bytes to reach the
//! rendering, and `GrainId::digest()` is already exactly those bytes,
//! so the fakes' conversion is a copy. A volume name is the opposite
//! case — its ACCEPT-SET is load-bearing for rules 3 and 5 — so
//! [`Volume`] delegates to `granary_core::root::VolumeName` instead of
//! restating the rules here.
//!
//! **What the bare digest COSTS, which is not a rendering question.** A
//! `GrainId` is `{algorithm, digest}`; an `Address` is the digest half,
//! so this artifact is ALGORITHM-BLIND. Two objects under different hash
//! algorithms that share digest bytes render the same trace line and
//! compare equal in every address-based assertion, which makes a replay
//! divergence consisting ONLY of an algorithm change invisible to the
//! cross-process meta-test — and rule 5's injectivity holds over what is
//! recorded, so it cannot see that either. This is empty while
//! `HashAlgorithm::ALL` has one member and stops being empty the moment
//! a second is registered, which is already a tracked event: that
//! registration must re-prove that `GrainId`'s derived `Ord` still
//! equals its encoded memcmp order across tags. Whether the artifact
//! should then key on the tagged id is a DECISION and not recorded here
//! — bin digests are deliberately stored untagged; the artifact's choice
//! with a second hash algorithm is undecided.

use std::fmt;
use std::io;

use granary_core::root::VolumeName;

/// A content address — the 32-byte digest of the object an operation
/// read or wrote.
///
/// A bare digest rather than `granary_core::hash::GrainId`: the
/// artifact renders the bytes and needs nothing else of the type — see
/// the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; 32]);

impl Address {
    /// Wrap a 32-byte digest.
    #[must_use]
    pub const fn new(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// The digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Address {
    /// All 64 hex digits, lowercase.
    ///
    /// Not truncated for readability. The artifact's whole job is to
    /// differ when the bytes differ, and a 16-digit prefix would render
    /// two distinct objects identically for any collision an
    /// implementation bug produced in the ignored half.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A volume name as the artifact may carry it: a DNS-1123 label —
/// 1..=63 bytes of `[a-z0-9-]`, no leading or trailing dash.
///
/// **Why a type and not a `String`.** This is the only free-text field
/// that reaches the rendering, and unconstrained it is two defects at
/// once. It is an ambient-data channel straight through rule 3 — a temp
/// path arrives as `vol=/var/folders/t/…/vol` with nothing to stop it —
/// and it is a hole in rule 5, because a name containing `\n` or the
/// outcome separator lets one entry render exactly like two. Both close
/// at the point of record, by construction rather than by discipline:
/// there is no way to name a volume in an [`Op`] except through
/// [`Volume::new`], [`Volume::from_checked`] — which takes a name
/// already validated by the same rules — or [`Volume::rejected`].
///
/// **ONE accept-set, not two that agree.** The rules are
/// `granary_core::root::VolumeName`'s, and [`Volume::new`] gets them by
/// calling it rather than by restating them: the sim records exactly
/// the names production accepts because it asks production's validator.
/// A hand-copied second opinion about what a volume is would be an
/// accept-set divergence waiting to happen — the class this project has
/// been bitten by before — and it would break more than the sim's
/// vocabulary: [`Volume::from_checked`] and every fake that pairs a
/// refusal with [`Volume::rejected`] assume a name `VolumeName` accepts
/// is a name this type accepts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Volume(String);

impl Volume {
    /// What a name that is NOT a DNS-1123 label records as.
    ///
    /// **Unforgeable**: it starts with `-`, which the DNS-1123 label
    /// rule refuses outright, so neither [`Volume::new`] nor
    /// [`Volume::from_checked`] can produce it and no accepted volume
    /// collides with it.
    ///
    /// The cost is stated rather than hidden: two distinct rejected
    /// names record identically, so the artifact does not tell them
    /// apart. That is the deliberate trade — the alternative is echoing
    /// arbitrary bytes, which is the channel this type exists to close —
    /// and it is narrow, because a name a fake refuses came from the
    /// scenario's own fixture, not from the environment.
    pub const REJECTED: &'static str = "-rejected-";

    /// The label, or `None` if `granary_core::root::VolumeName` does not
    /// accept `name`.
    ///
    /// Callers that must record the operation anyway — a fake whose
    /// volume check just refused the name — pair this with
    /// [`Volume::rejected`].
    #[must_use]
    pub fn new(name: &str) -> Option<Self> {
        // `from_bytes` and not `VolumeName::new`: it validates a borrow,
        // so a name the rules refuse costs no allocation at all.
        Some(Self::from_checked(
            &VolumeName::from_bytes(name.as_bytes()).ok()?,
        ))
    }

    /// The artifact's rendering of an ALREADY-validated name.
    ///
    /// Infallible by construction, and the reason a fake that has just
    /// built a `VolumeName` needs no second opinion — nor a fallback
    /// whose unreachability rests on two checks agreeing. The sentinel
    /// stays unforgeable through this path for the same reason it does
    /// through [`Volume::new`]: a `VolumeName` cannot lead with `-`.
    #[must_use]
    pub fn from_checked(name: &VolumeName) -> Self {
        Self(name.as_str().to_owned())
    }

    /// The sentinel of [`Volume::REJECTED`].
    #[must_use]
    pub fn rejected() -> Self {
        Self(Self::REJECTED.to_owned())
    }

    /// The label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the sentinel rather than a name.
    #[must_use]
    pub fn is_rejected(&self) -> bool {
        self.0 == Self::REJECTED
    }
}

impl fmt::Display for Volume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The io kinds the artifact names, as an IN-CRATE vocabulary.
///
/// Everything std has not named — and everything this list has not
/// adopted — collapses into [`IoKind::Other`]. That is the point: see
/// rule 2 in the module doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoKind {
    /// `io::ErrorKind::PermissionDenied`.
    PermissionDenied,
    /// `io::ErrorKind::NotFound`.
    NotFound,
    /// `io::ErrorKind::IsADirectory`.
    IsADirectory,
    /// `io::ErrorKind::NotADirectory`.
    NotADirectory,
    /// `io::ErrorKind::InvalidData`.
    InvalidData,
    /// `io::ErrorKind::UnexpectedEof`.
    UnexpectedEof,
    /// Every other kind, including std's unstable catch-all.
    Other,
}

impl From<io::ErrorKind> for IoKind {
    fn from(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::IsADirectory => Self::IsADirectory,
            io::ErrorKind::NotADirectory => Self::NotADirectory,
            io::ErrorKind::InvalidData => Self::InvalidData,
            io::ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            _ => Self::Other,
        }
    }
}

impl fmt::Display for IoKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let word = match self {
            Self::PermissionDenied => "permission-denied",
            Self::NotFound => "not-found",
            Self::IsADirectory => "is-a-directory",
            Self::NotADirectory => "not-a-directory",
            Self::InvalidData => "invalid-data",
            Self::UnexpectedEof => "unexpected-eof",
            Self::Other => "other",
        };
        f.write_str(word)
    }
}

/// The fixed error vocabulary of the artifact (module doc, rule 2).
///
/// Every variant renders as a constant. None carries free text, which is
/// what keeps rule 3 true: a backend error's message is the usual way an
/// absolute path escapes into a log.
///
/// This is a rendering VOCABULARY, not an error type: nothing returns it
/// in a `Result`, it deliberately carries no source and no payload, and
/// it does not implement `std::error::Error`. The fakes map the seams'
/// real error types into it precisely to drop everything that would not
/// be stable across two processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceError {
    /// The object or head does not exist.
    NotFound,
    /// A create-if-absent write lost to an object already there.
    AlreadyExists,
    /// The volume name is not DNS-1123.
    InvalidVolume,
    /// `offset + len` overflowed.
    RangeOverflow,
    /// Stored bytes did not match the address they were stored under.
    Corrupt,
    /// The fault schedule made this operation fail.
    Injected,
    /// The fault schedule told the caller this `put_root` failed and
    /// HELD the write for a later release — distinct from
    /// [`TraceError::Injected`], because a held write may still land.
    Deferred,
    /// An io failure, named by its KIND alone.
    Io(IoKind),
    /// A sync returned failure (the decision-log fake's
    /// `LogIoError::SyncFailed`).
    SyncFailed,
    /// A truncation past the file's end (the decision-log fake's
    /// `LogIoError::OutOfRange`).
    OutOfRange,
    /// Everything else, as one stable word.
    Backend,
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("not-found"),
            Self::AlreadyExists => f.write_str("already-exists"),
            Self::InvalidVolume => f.write_str("invalid-volume"),
            Self::RangeOverflow => f.write_str("range-overflow"),
            Self::Corrupt => f.write_str("corrupt"),
            Self::Injected => f.write_str("injected"),
            Self::Deferred => f.write_str("deferred"),
            Self::Io(kind) => write!(f, "io:{kind}"),
            Self::SyncFailed => f.write_str("sync-failed"),
            Self::OutOfRange => f.write_str("out-of-range"),
            Self::Backend => f.write_str("backend"),
        }
    }
}

/// One operation against one seam.
///
/// The three object PUTs each carry a mandatory [`Address`], and
/// [`Op::WriteHint`] carries the `(volume, seq)` pair that is a hint's
/// whole written content: that is how rule 1 is enforced by the type
/// rather than by discipline — no writing variant can be recorded
/// without saying what it wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// `BinStore::put_bin`.
    PutBin {
        /// Address of the bin written.
        addr: Address,
    },
    /// `BinStore::put_meta`.
    PutMeta {
        /// Volume namespace.
        volume: Volume,
        /// Address of the object written.
        addr: Address,
    },
    /// `RootStore::put_root`.
    PutRoot {
        /// Volume namespace.
        volume: Volume,
        /// Sequence number claimed.
        seq: u64,
        /// Address of the signed root BYTES written — the field the
        /// writer identity reaches, and the reason rule 1 exists.
        addr: Address,
    },
    /// `RootStore::write_hint`. The hint is a pointer, not an object, so
    /// it has no content address of its own.
    WriteHint {
        /// Volume namespace.
        volume: Volume,
        /// Sequence number hinted.
        seq: u64,
    },
    /// `BinStore::get_bin_range`.
    GetBinRange {
        /// Address of the bin read.
        addr: Address,
        /// Range start.
        offset: u64,
        /// Range length requested.
        len: u32,
    },
    /// `BinStore::get_meta`.
    GetMeta {
        /// Volume namespace.
        volume: Volume,
        /// Address requested.
        addr: Address,
    },
    /// `RootStore::get_root`.
    GetRoot {
        /// Volume namespace.
        volume: Volume,
        /// Sequence number requested.
        seq: u64,
    },
    /// `RootStore::read_hint`.
    ReadHint {
        /// Volume namespace.
        volume: Volume,
    },
    /// `RootStore::max_seq`.
    MaxSeq {
        /// Volume namespace.
        volume: Volume,
    },
    /// `GrainSource::get`.
    GetGrain {
        /// Address requested.
        addr: Address,
    },
    /// `GrainSource::has`.
    HasGrain {
        /// Address requested.
        addr: Address,
    },
    /// A deferred `put_root` reaching its release point: the held write
    /// applied create-only, recorded under the node that issued it. Not
    /// an operation any node issued at that point, so it carries no
    /// operation index.
    ReleaseRoot {
        /// Volume namespace.
        volume: Volume,
        /// Sequence number the held write claims.
        seq: u64,
        /// Address of the held root bytes.
        addr: Address,
    },
    /// The out-of-band admin handle planting a root.
    AdminPlantRoot {
        /// Volume namespace.
        volume: Volume,
        /// Sequence number planted at — any `u64`, 0 and `u64::MAX`
        /// included.
        seq: u64,
        /// Address of the planted bytes.
        addr: Address,
    },
    /// The out-of-band admin handle deleting a root. A delete writes no
    /// object, so `(volume, seq)` is its whole content.
    AdminDeleteRoot {
        /// Volume namespace.
        volume: Volume,
        /// Sequence number deleted.
        seq: u64,
    },
    /// The out-of-band admin handle listing a volume's root seqs.
    AdminListRoots {
        /// Volume namespace.
        volume: Volume,
    },
    /// One entry of the decision-log fake ([`crate::decision_log`]).
    Log(LogOp),
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PutBin { addr } => write!(f, "put-bin addr={addr}"),
            Self::PutMeta { volume, addr } => write!(f, "put-meta vol={volume} addr={addr}"),
            Self::PutRoot { volume, seq, addr } => {
                write!(f, "put-root vol={volume} seq={seq} addr={addr}")
            }
            Self::WriteHint { volume, seq } => write!(f, "write-hint vol={volume} seq={seq}"),
            Self::GetBinRange { addr, offset, len } => {
                write!(f, "get-bin-range addr={addr} off={offset} len={len}")
            }
            Self::GetMeta { volume, addr } => write!(f, "get-meta vol={volume} addr={addr}"),
            Self::GetRoot { volume, seq } => write!(f, "get-root vol={volume} seq={seq}"),
            Self::ReadHint { volume } => write!(f, "read-hint vol={volume}"),
            Self::MaxSeq { volume } => write!(f, "max-seq vol={volume}"),
            Self::GetGrain { addr } => write!(f, "get-grain addr={addr}"),
            Self::HasGrain { addr } => write!(f, "has-grain addr={addr}"),
            Self::ReleaseRoot { volume, seq, addr } => {
                write!(f, "release-root vol={volume} seq={seq} addr={addr}")
            }
            Self::AdminPlantRoot { volume, seq, addr } => {
                write!(f, "admin-plant-root vol={volume} seq={seq} addr={addr}")
            }
            Self::AdminDeleteRoot { volume, seq } => {
                write!(f, "admin-delete-root vol={volume} seq={seq}")
            }
            Self::AdminListRoots { volume } => write!(f, "admin-list-roots vol={volume}"),
            Self::Log(op) => op.fmt(f),
        }
    }
}

// ------------------------------------------------ the decision-log fake

/// A name in the decision-log fake's filesystem
/// ([`crate::decision_log`]): the pre-existing anchor, the state
/// directory inside it, and the files inside that.
///
/// Rendered from a closed vocabulary plus a [`Volume`], so it carries
/// no ambient path (rule 3); the `:` after `log` and `tmp` cannot occur
/// in a volume, so two paths never render alike (rule 5).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogPath {
    /// The pre-existing directory that holds the state directory.
    Anchor,
    /// The state directory.
    StateDir,
    /// The run marker.
    Marker,
    /// The run marker's temporary.
    MarkerTemp,
    /// A volume's log.
    Log(Volume),
    /// A volume's log temporary.
    Temp(Volume),
}

impl fmt::Display for LogPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anchor => f.write_str("anchor"),
            Self::StateDir => f.write_str("state"),
            Self::Marker => f.write_str("marker"),
            Self::MarkerTemp => f.write_str("marker-tmp"),
            Self::Log(volume) => write!(f, "log:{volume}"),
            Self::Temp(volume) => write!(f, "tmp:{volume}"),
        }
    }
}

/// Which `DecisionLog` method a [`LogOp::Call`] entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogCall {
    /// `read_marker`.
    ReadMarker,
    /// `write_marker`.
    WriteMarker,
    /// `read`.
    Read,
    /// `remove_temporary`.
    RemoveTemporary,
    /// `initialise`.
    Initialise,
    /// `complete_namespace`.
    CompleteNamespace,
    /// `append`.
    Append,
    /// `truncate`.
    Truncate,
    /// `resync`.
    Resync,
}

impl fmt::Display for LogCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReadMarker => "read-marker",
            Self::WriteMarker => "write-marker",
            Self::Read => "read",
            Self::RemoveTemporary => "remove-temporary",
            Self::Initialise => "initialise",
            Self::CompleteNamespace => "complete-namespace",
            Self::Append => "append",
            Self::Truncate => "truncate",
            Self::Resync => "resync",
        })
    }
}

/// What a host crash did to one file's unsynced truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncationDraw {
    /// No truncation was pending.
    None,
    /// The pending truncation reached the medium.
    Kept,
    /// The pending truncation was undone: the discarded bytes are back.
    Undone,
}

impl fmt::Display for TruncationDraw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Kept => "kept",
            Self::Undone => "undone",
        })
    }
}

/// What a host crash wrote after a file's surviving unsynced bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fill {
    /// Nothing: no garbage follows the kept prefix.
    None,
    /// Zero bytes.
    Zero,
    /// Bytes drawn from the run's seeded generator.
    Seeded,
}

impl fmt::Display for Fill {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Zero => "zero",
            Self::Seeded => "seeded",
        })
    }
}

/// What a host crash left of one unacknowledged append. Recovery
/// discards the first four as an interrupted append and adopts the
/// last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DrawRow {
    /// The record's bytes are absent.
    RecordAbsent,
    /// The record is torn — a proper prefix, or garbage in its tail —
    /// and no mark follows it.
    RecordTorn,
    /// The record was never synced, yet every byte of it reached the
    /// medium; no mark follows it, since a mark is written only after
    /// the record's sync returns.
    RecordWholeUnsynced,
    /// The record is intact and was synced; its mark is absent or
    /// torn.
    MarkAbsentOrTorn,
    /// The record was synced and its mark reached the medium whole
    /// before the mark's sync returned: committed, never acknowledged.
    Survivor,
    /// The append was written after a truncation whose sync never
    /// returned, and the crash undid the truncation: the file is back
    /// to its bytes from before the truncation, and the append is gone.
    LostWithUndoneTruncation,
}

impl fmt::Display for DrawRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RecordAbsent => "record-absent",
            Self::RecordTorn => "record-torn",
            Self::RecordWholeUnsynced => "record-whole-unsynced",
            Self::MarkAbsentOrTorn => "mark-absent-or-torn",
            Self::Survivor => "survivor",
            Self::LostWithUndoneTruncation => "lost-truncation-undone",
        })
    }
}

/// A durable step a log write must wait for (the decision-log fake's
/// ordering checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Barrier {
    /// This process's run-marker write: the temporary synced, renamed
    /// over the marker, the state directory synced, and — when the
    /// write created the state directory — the anchor synced.
    Marker,
    /// A log this process initialised: the state directory and the
    /// anchor synced after the link.
    Initialise,
    /// An adopted log holding no records: that log's own
    /// `complete_namespace` must have seen the state directory's and
    /// the anchor's syncs return in this process.
    CompleteNamespace,
    /// A truncation whose sync has not returned.
    Truncation,
    /// An adopted log holding records that this process has not
    /// re-synced, or any log with bytes whose sync never returned.
    SurvivorResync,
}

impl fmt::Display for Barrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Marker => "marker",
            Self::Initialise => "initialise",
            Self::CompleteNamespace => "complete-namespace",
            Self::Truncation => "truncation",
            Self::SurvivorResync => "survivor-resync",
        })
    }
}

/// An ordering violation the decision-log fake observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogViolation {
    /// A mark was written before its record's sync had returned.
    MarkBeforeRecordSync,
    /// A log write began while a barrier was incomplete.
    WriteBeforeBarrier(Barrier),
    /// A mutating call after this process was fenced: a sync failed, or
    /// a mutating call failed after it had begun.
    AfterFence,
    /// A mutating call by a later process in the same boot as a fence:
    /// only a host crash clears it.
    SameBootAfterFence,
    /// An append to a log whose bytes run past its committed prefix: a
    /// tail recovery never truncated.
    TailNotTruncated,
    /// A mutating call on a volume's log (or on the marker) while
    /// another is in flight on it: one writer, one call at a time.
    ConcurrentCall,
    /// An append whose epoch is not its log's, or to a log with no
    /// envelope to have one.
    EpochMismatch,
    /// A mutating call covered by the engine's one log token begun while
    /// another is in flight on a different log (or on the marker): no two
    /// such calls overlap anywhere in the process.
    OverlappingCall,
    /// A step of a mutating call begun before this process was fenced,
    /// applied after it: the fence stops a call already in flight too.
    StepAfterFence,
}

impl fmt::Display for LogViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MarkBeforeRecordSync => f.write_str("mark-before-record-sync"),
            Self::WriteBeforeBarrier(barrier) => write!(f, "write-before-barrier:{barrier}"),
            Self::AfterFence => f.write_str("after-fence"),
            Self::SameBootAfterFence => f.write_str("same-boot-after-fence"),
            Self::TailNotTruncated => f.write_str("tail-not-truncated"),
            Self::ConcurrentCall => f.write_str("concurrent-call"),
            Self::EpochMismatch => f.write_str("epoch-mismatch"),
            Self::OverlappingCall => f.write_str("overlapping-call"),
            Self::StepAfterFence => f.write_str("step-after-fence"),
        }
    }
}

/// Which injected media fault a [`LogOp::Damage`] entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Damage {
    /// Bytes flipped inside a committed record, a valid mark left at or
    /// after them: recovery must refuse.
    Detectable,
    /// Damage confined to the end of the file that starts at a committed
    /// record's mark and destroys the mark of every committed record it
    /// touches, so a whole record leads the tail: recovery discards
    /// them while the tail is no longer than that record plus a mark.
    Residual,
    /// The same damage, starting inside the first record it touches, so
    /// no whole record leads the tail: recovery discards them while the
    /// tail is no longer than the largest record.
    ResidualIntoRecord,
    /// A mark-free tail that begins with the first half of a record and
    /// runs on as filler to one byte past the largest record: recovery
    /// must refuse. The traced start is where the committed prefix ends,
    /// which is where the tail begins.
    Oversize,
    /// The same tail at exactly the largest record's length: recovery
    /// discards it.
    AtBound,
    /// A whole, check-valid record of the log's epoch that is not the
    /// legal next record leads a mark-free tail: recovery must refuse.
    ForeignRecord,
    /// The legal next record, re-encoded under the wrong entry sequence
    /// number, leads a mark-free tail: recovery must refuse.
    WrongSeqRecord,
    /// A whole record of another epoch, one that would break the grammar
    /// if it were this epoch's, leads a short mark-free tail: recovery
    /// discards it.
    OtherEpochRecord,
}

impl fmt::Display for Damage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Detectable => "detectable",
            Self::Residual => "residual",
            Self::ResidualIntoRecord => "residual-into-record",
            Self::Oversize => "oversize",
            Self::AtBound => "at-bound",
            Self::ForeignRecord => "foreign-record",
            Self::WrongSeqRecord => "wrong-seq-record",
            Self::OtherEpochRecord => "other-epoch-record",
        })
    }
}

/// Why recovery's classification refused a log, in the artifact's fixed
/// vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A whole envelope named an unknown version.
    UnknownVersion,
    /// The envelope's body did not decode strictly.
    EnvelopeMalformed,
    /// The envelope names a different volume.
    WrongVolume,
    /// Committed history is damaged, or the tail is beyond what one
    /// interrupted append can leave.
    DamagedHistory,
    /// The committed log broke this grammar rule (1 to 7).
    Grammar(u8),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVersion => f.write_str("unknown-version"),
            Self::EnvelopeMalformed => f.write_str("envelope-malformed"),
            Self::WrongVolume => f.write_str("wrong-volume"),
            Self::DamagedHistory => f.write_str("damaged-history"),
            Self::Grammar(rule) => write!(f, "grammar-rule-{rule}"),
        }
    }
}

/// What recovery's classification said of a volume's log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The volume has no log.
    Absent,
    /// A file too short to hold an envelope and no mark.
    NoEnvelope,
    /// A log: `records` committed records ending at byte `committed`,
    /// and `tail` bytes to discard.
    Log {
        /// Committed records.
        records: u64,
        /// The committed prefix's length.
        committed: u64,
        /// The bytes past it.
        tail: u64,
    },
    /// Refused, at this byte offset.
    Refused {
        /// Why.
        reason: Refusal,
        /// Where.
        offset: u64,
    },
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("absent"),
            Self::NoEnvelope => f.write_str("no-envelope"),
            Self::Log {
                records,
                committed,
                tail,
            } => write!(f, "log records={records} committed={committed} tail={tail}"),
            Self::Refused { reason, offset } => {
                write!(f, "refused reason={reason} offset={offset}")
            }
        }
    }
}

/// One entry of the decision-log fake. Each internal step is its own
/// entry, and each step that writes bytes carries their [`Address`]
/// (rule 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogOp {
    /// A `DecisionLog` method returned. `volume` is `None` for the two
    /// marker methods, which name none.
    Call {
        /// The method.
        call: LogCall,
        /// The volume it addressed.
        volume: Option<Volume>,
    },
    /// Bytes appended to a file.
    Write {
        /// The file.
        path: LogPath,
        /// How many bytes.
        len: u64,
        /// The digest of exactly those bytes.
        addr: Address,
    },
    /// A file sync.
    FileSync {
        /// The file.
        path: LogPath,
    },
    /// A directory sync.
    DirSync {
        /// The directory.
        path: LogPath,
    },
    /// A file created.
    Create {
        /// The new name.
        path: LogPath,
        /// Whether the create refuses an existing name (`O_EXCL`); if
        /// not, it replaces the name's old binding.
        exclusive: bool,
    },
    /// A directory created.
    Mkdir {
        /// The new directory.
        path: LogPath,
    },
    /// A hard link that never replaces an existing name.
    Link {
        /// The existing name.
        from: LogPath,
        /// The new name.
        to: LogPath,
    },
    /// A name removed.
    Unlink {
        /// The name.
        path: LogPath,
    },
    /// A rename over whatever `to` named.
    Rename {
        /// The old name.
        from: LogPath,
        /// The new name.
        to: LogPath,
    },
    /// A file truncated.
    Truncate {
        /// The file.
        path: LogPath,
        /// Its new length.
        len: u64,
    },
    /// A file read whole.
    Read {
        /// The file.
        path: LogPath,
    },
    /// A process restart: the page cache survives, nothing is drawn.
    Restart,
    /// A host crash: `kept` of the `pending` namespace operations, in
    /// issue order, reached the medium.
    Crash {
        /// Namespace operations not yet covered by a directory sync.
        pending: u64,
        /// How many of them, from the first, survived.
        kept: u64,
    },
    /// One file's draw at a host crash: of `written` bytes past the
    /// synced `base`, the first `kept` survived, followed by `garbage`
    /// bytes of `fill`.
    Draw {
        /// The file, by the first name the drawn namespace gives it.
        path: LogPath,
        /// What became of an unsynced truncation.
        truncation: TruncationDraw,
        /// The length known to be on the medium.
        base: u64,
        /// Bytes written past `base` with no returned sync.
        written: u64,
        /// How many of them survived, from the first.
        kept: u64,
        /// Garbage bytes after the kept ones.
        garbage: u64,
        /// What the garbage is.
        fill: Fill,
    },
    /// Where one unacknowledged append landed at a host crash.
    Row {
        /// The log.
        path: LogPath,
        /// The record's offset in the log.
        at: u64,
        /// The row.
        row: DrawRow,
    },
    /// A file the medium holds after a host crash: its whole bytes'
    /// digest, so any drawn byte or boundary changes the artifact.
    File {
        /// The name.
        path: LogPath,
        /// Its length.
        len: u64,
        /// The digest of its whole content.
        addr: Address,
    },
    /// Whether the state directory exists after a host crash.
    StateDir {
        /// Whether it does.
        present: bool,
    },
    /// An injected media fault applied at a host crash, flipping
    /// `start..end`; recorded `absent` when the log held too few
    /// committed records for it to fire.
    Damage {
        /// The log.
        path: LogPath,
        /// Which fault.
        damage: Damage,
        /// The first byte flipped.
        start: u64,
        /// One past the last byte flipped.
        end: u64,
    },
    /// An ordering violation the fake observed.
    Violation(LogViolation),
    /// What recovery's classification said of a log, recorded by the
    /// driver that ran it.
    Verdict {
        /// The log.
        path: LogPath,
        /// The verdict.
        verdict: Verdict,
    },
    /// The test harness planting a file's bytes directly.
    Seed {
        /// The file.
        path: LogPath,
        /// Its length.
        len: u64,
        /// The digest of its content.
        addr: Address,
    },
    /// The test harness emptying the state directory.
    SeedEmptyStateDir,
    /// The test harness returning the filesystem to empty.
    Reset,
}

impl fmt::Display for LogOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Call { call, volume } => {
                write!(f, "log-call call={call}")?;
                if let Some(volume) = volume {
                    write!(f, " vol={volume}")?;
                }
                Ok(())
            }
            Self::Write { path, len, addr } => {
                write!(f, "log-write path={path} len={len} addr={addr}")
            }
            Self::FileSync { path } => write!(f, "log-file-sync path={path}"),
            Self::DirSync { path } => write!(f, "log-dir-sync path={path}"),
            Self::Create { path, exclusive } => write!(
                f,
                "log-create path={path} excl={}",
                if *exclusive { "yes" } else { "no" }
            ),
            Self::Mkdir { path } => write!(f, "log-mkdir path={path}"),
            Self::Link { from, to } => write!(f, "log-link from={from} to={to}"),
            Self::Unlink { path } => write!(f, "log-unlink path={path}"),
            Self::Rename { from, to } => write!(f, "log-rename from={from} to={to}"),
            Self::Truncate { path, len } => write!(f, "log-truncate path={path} len={len}"),
            Self::Read { path } => write!(f, "log-read path={path}"),
            Self::Restart => f.write_str("log-restart"),
            Self::Crash { pending, kept } => {
                write!(f, "log-crash ns-pending={pending} ns-kept={kept}")
            }
            Self::Draw {
                path,
                truncation,
                base,
                written,
                kept,
                garbage,
                fill,
            } => write!(
                f,
                "log-draw path={path} trunc={truncation} base={base} written={written} \
                 kept={kept} garbage={garbage} fill={fill}"
            ),
            Self::Row { path, at, row } => write!(f, "log-row path={path} at={at} row={row}"),
            Self::File { path, len, addr } => {
                write!(f, "log-file path={path} len={len} addr={addr}")
            }
            Self::StateDir { present } => {
                write!(
                    f,
                    "log-state-dir present={}",
                    if *present { "yes" } else { "no" }
                )
            }
            Self::Damage {
                path,
                damage,
                start,
                end,
            } => write!(
                f,
                "log-damage path={path} kind={damage} start={start} end={end}"
            ),
            Self::Violation(violation) => write!(f, "log-violation kind={violation}"),
            Self::Verdict { path, verdict } => {
                write!(f, "log-verdict path={path} result={verdict}")
            }
            Self::Seed { path, len, addr } => {
                write!(f, "log-seed path={path} len={len} addr={addr}")
            }
            Self::SeedEmptyStateDir => f.write_str("log-seed-empty-state-dir"),
            Self::Reset => f.write_str("log-reset"),
        }
    }
}

/// What the operation answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Succeeded.
    Ok,
    /// A content-addressed write that stored new bytes.
    Novel,
    /// A content-addressed write whose bytes were already present —
    /// success, not a conflict.
    Unchanged,
    /// A read that succeeded and found nothing.
    Absent,
    /// Failed, from the fixed vocabulary.
    Failed(TraceError),
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => f.write_str("ok"),
            Self::Novel => f.write_str("novel"),
            Self::Unchanged => f.write_str("unchanged"),
            Self::Absent => f.write_str("absent"),
            Self::Failed(err) => write!(f, "failed({err})"),
        }
    }
}

/// One recorded operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Which sim node issued it. A harness-assigned index, not an
    /// ambient id (module doc, rule 3).
    pub node: u32,
    /// What it did.
    pub op: Op,
    /// What it answered.
    pub outcome: Outcome,
}

/// The replay artifact: the ordered operation log of one run.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Trace {
    entries: Vec<Entry>,
}

impl Trace {
    /// An empty trace.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an operation.
    pub fn record(&mut self, node: u32, op: Op, outcome: Outcome) {
        self.entries.push(Entry { node, op, outcome });
    }

    /// The entries, in the order they happened.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Whether the run recorded nothing.
    ///
    /// The meta-test's guard (module doc, rule 4): two empty artifacts
    /// compare equal, so a cross-process comparison that does not first
    /// establish the artifact is non-empty is a check that cannot fail.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Render the artifact: one `\n`-terminated line per operation, in
    /// order, fields in a fixed order.
    ///
    /// Nothing here reads the environment, the clock or the process, so
    /// two runs that record equal entries render equal bytes on any
    /// machine — which is the property the meta-test rests on.
    #[must_use]
    pub fn render(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for Trace {
    /// The artifact itself. [`Trace::render`] is the name the scenarios
    /// use; this is where the bytes are decided.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for entry in &self.entries {
            writeln!(f, "n{} {} -> {}", entry.node, entry.op, entry.outcome)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
