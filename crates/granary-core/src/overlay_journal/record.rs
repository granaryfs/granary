// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The journal's eighteen record kinds and their payload codec.
//! A payload is strict: every field is
//! range checked, nothing trails it, and a kind whose fields do not apply
//! (the stage id of a directory) carries them as zero. Rules that need
//! earlier records (the next stage id, a bound stage) are the scan's, in
//! [`super::JournalState`].

use super::{
    CHECK_LEN, EXTENT_LEN_MAX, GENERATION_MAX, PATH_BYTES_MAX, PATH_DEPTH_MAX, Reader, SIZE_MAX,
    STAGE_ID_MAX,
};
use crate::hash::{GRAIN_ID_BINARY_LEN, GrainId};
use crate::manifest::name::SYMLINK_TARGET_MAX;
use crate::manifest::{Name, NameError, SymlinkTarget, SymlinkTargetError};

pub(super) const KIND_CREATE: u8 = 1;
pub(super) const KIND_STAGE_BIND: u8 = 2;
pub(super) const KIND_WRITE_EXTENT: u8 = 3;
pub(super) const KIND_TRUNCATE: u8 = 4;
pub(super) const KIND_MOVE: u8 = 5;
pub(super) const KIND_REPLACE: u8 = 6;
pub(super) const KIND_DELETE: u8 = 7;
pub(super) const KIND_SETATTR_EXEC: u8 = 8;
pub(super) const KIND_FILE_SYNCED: u8 = 9;
pub(super) const KIND_INTENT_REGISTERED: u8 = 10;
pub(super) const KIND_COMMIT_BOUNDARY: u8 = 11;
pub(super) const KIND_LANDED_COMMIT: u8 = 12;
pub(super) const KIND_COMMIT_ATTEMPT: u8 = 13;
pub(super) const KIND_COMMIT_FENCE: u8 = 14;
pub(super) const KIND_PROJECTED_BOUNDARY: u8 = 15;
pub(super) const KIND_RECREATE_FILE: u8 = 16;
pub(super) const KIND_RESIDUAL_DISPOSITION: u8 = 17;
pub(super) const KIND_STAGE_ROLLBACK: u8 = 18;

const TYPE_FILE: u8 = 1;
const TYPE_DIR: u8 = 2;
const TYPE_SYMLINK: u8 = 3;

const SELECTION_NONE: u8 = 0;
const SELECTION_FILE: u8 = 1;

const ABSENT: u8 = 0;
const PRESENT: u8 = 1;

/// A path from the root to a directory, in the overlay tree as it stands
/// when the record applies: at most [`PATH_DEPTH_MAX`] names and
/// [`PATH_BYTES_MAX`] name bytes in all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parent(Vec<Name>);

impl Parent {
    /// The root directory.
    #[must_use]
    pub const fn root() -> Self {
        Self(Vec::new())
    }

    /// A parent path.
    ///
    /// # Errors
    /// [`RecordError::PathTooDeep`] and [`RecordError::PathTooLong`].
    pub fn new(names: Vec<Name>) -> Result<Self, RecordError> {
        if names.len() > PATH_DEPTH_MAX {
            return Err(RecordError::PathTooDeep { depth: names.len() });
        }
        let bytes = names
            .iter()
            .fold(0usize, |sum, n| sum.saturating_add(n.as_bytes().len()));
        if bytes > PATH_BYTES_MAX {
            return Err(RecordError::PathTooLong { bytes });
        }
        Ok(Self(names))
    }

    /// The names, outermost first.
    #[must_use]
    pub fn names(&self) -> &[Name] {
        &self.0
    }
}

/// A directory entry named by its parent and its own name: how every
/// namespace record addresses an entry, a move included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// The containing directory.
    pub parent: Parent,
    /// The entry's name.
    pub name: Name,
}

/// What a `create` record makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateKind {
    /// A file with its executable bit and the staging file that backs it,
    /// whose id is the journal's running next id.
    File { exec: bool, stage_id: u64 },
    /// A directory.
    Dir,
    /// A symbolic link.
    Symlink { target: SymlinkTarget },
}

/// What a `delete` record removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteKind {
    /// A file; `stage_id` is its staging file, or `None` for a clean file
    /// that was never staged.
    File { stage_id: Option<u64> },
    /// A directory.
    Dir,
    /// A symbolic link.
    Symlink,
}

/// Why a `stage-bind` record exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindCause {
    /// The first write to a clean file: a new staging file with the next
    /// id, which advances the counter.
    CopyUp = 1,
    /// A continuing file carried across a journal replacement: an id already
    /// issued, below the running next id; the counter does not advance and
    /// the physical file is unchanged.
    Rebind = 2,
}

/// Why an `intent-registered` record exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentCause {
    /// A directory sync registered the prepared root.
    DirectorySync = 1,
    /// The landed root was registered after a commit.
    LandedRefresh = 2,
}

/// The file a `projected-boundary` selected: its stage, as the replay through
/// the boundary resolves it, and the content id and size of its captured
/// payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectedSelection {
    /// The selected file's staging file, bound in this journal.
    pub stage_id: u64,
    /// The captured payload's content id.
    pub content: GrainId,
    /// The captured payload's size.
    pub size: u64,
}

/// The authenticated payload a stage starts from after recreation or rollback.
/// Its content id is encoded as for `file-synced`; its size bounds the byte source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecreateAnchor {
    /// The payload's content id.
    pub content: GrainId,
    /// The payload's size.
    pub size: u64,
}

/// Which whole-file version a residual choice preserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidualMode {
    /// Preserve the staged whole-file version.
    KeepLocal = 1,
    /// Preserve the landed file and export the staged version.
    KeepRemote = 2,
}

/// A terminal durable choice over a landing's complete colliding residual.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidualDisposition {
    /// The answered boundary's journal seq.
    pub boundary_seq: u64,
    /// That boundary's opaque publication identity.
    pub publication_id: [u8; 16],
    /// The exact stored landing.
    pub landed_root: GrainId,
    /// The stored landing's chain seq.
    pub landed_seq: u64,
    /// The last journal seq before this record.
    pub source_end: u64,
    /// The immutable choice over every collision.
    pub disposition: ResidualMode,
    /// Number of descriptors in the complete inventory.
    pub collision_count: u32,
    /// Check of the ordered descriptors, including full payload checks.
    pub inventory_check: [u8; CHECK_LEN],
}

/// A named stage's descriptor in a residual inventory or unmerged listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidualFile {
    /// The original stage identity.
    pub stage_id: u64,
    /// Its final local namespace location.
    pub at: Location,
    /// The full local file's executable bit.
    pub exec: bool,
    /// Logical payload length, excluding the staging header.
    pub local_size: u64,
    /// Check over the stage identity, size and full logical payload.
    pub payload_check: [u8; CHECK_LEN],
}

impl ResidualFile {
    /// Encode one canonical inventory descriptor.
    ///
    /// # Errors
    /// The [`RecordError`] the decoder would report for these fields.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.stage_id.to_be_bytes());
        put_location(&mut out, &self.at);
        out.push(u8::from(self.exec));
        out.extend_from_slice(&self.local_size.to_be_bytes());
        out.extend_from_slice(&self.payload_check);
        Self::decode(&out)?;
        Ok(out)
    }

    /// Decode exactly one descriptor, with no trailing bytes.
    ///
    /// # Errors
    /// The [`RecordError`] naming the first invalid field.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut r = Reader::new(bytes);
        let file = Self {
            stage_id: get_stage_id(&mut r)?,
            at: get_location(&mut r)?,
            exec: get_exec(get_u8(&mut r)?)?,
            local_size: get_size(&mut r)?,
            payload_check: r.array().ok_or(RecordError::Truncated)?,
        };
        if !r.is_empty() {
            return Err(RecordError::TrailingBytes);
        }
        Ok(file)
    }
}

/// Check the complete, strictly stage-ordered residual inventory.
///
/// # Errors
/// An empty inventory or a malformed or out-of-order descriptor.
pub fn residual_inventory_check(files: &[ResidualFile]) -> Result<[u8; CHECK_LEN], RecordError> {
    if files.is_empty() {
        return Err(RecordError::EmptyInventory);
    }
    let mut hasher = blake3::Hasher::new_derive_key("granary residual inventory v1");
    let mut previous = 0;
    for file in files {
        if file.stage_id <= previous {
            return Err(RecordError::InventoryOrder);
        }
        hasher.update(&file.encode()?);
        previous = file.stage_id;
    }
    Ok(*hasher.finalize().as_bytes())
}

/// One journal record. A record's `seq` is its place in the journal and is
/// not part of the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// Kind 1: a new entry.
    Create { at: Location, kind: CreateKind },
    /// Kind 2: bind an existing file to a staging file.
    StageBind {
        at: Location,
        cause: BindCause,
        stage_id: u64,
        staged_size: u64,
        base_content: GrainId,
    },
    /// Kind 3: bytes written to a staging file, with their check.
    WriteExtent {
        stage_id: u64,
        offset: u64,
        length: u64,
        check: [u8; CHECK_LEN],
    },
    /// Kind 4: a file's size set; an extension zero-fills.
    Truncate { stage_id: u64, new_size: u64 },
    /// Kind 5: a rename onto a name that did not exist.
    Move { from: Location, to: Location },
    /// Kind 6: a rename over an existing entry, which is displaced.
    Replace { from: Location, to: Location },
    /// Kind 7: an entry removed.
    Delete { at: Location, kind: DeleteKind },
    /// Kind 8: the executable bit set.
    SetattrExec { at: Location, exec: bool },
    /// Kind 9 (sync-class): a file's prefix is durable on the authority.
    FileSynced {
        stage_id: u64,
        synced_size: u64,
        content: GrainId,
        generation: u64,
        prepared_root: GrainId,
    },
    /// Kind 10 (sync-class): a prepared root was registered.
    IntentRegistered {
        generation: u64,
        prepared_root: GrainId,
        cause: IntentCause,
    },
    /// Kind 11 (sync-class): the records up to `through_seq` went into a
    /// candidate root.
    CommitBoundary {
        candidate: GrainId,
        through_seq: u64,
        publication_id: [u8; 16],
    },
    /// Kind 12 (sync-class): the commit answered by an earlier boundary
    /// landed.
    LandedCommit {
        boundary_seq: u64,
        landed_root: GrainId,
        landed_seq: u64,
    },
    /// Kind 13 (sync-class): one durable dispatch reservation for a boundary.
    CommitAttempt {
        boundary_seq: u64,
        publication_id: [u8; 16],
        attempt: u64,
    },
    /// Kind 14 (sync-class): a boundary's publication is persistently fenced.
    CommitFence {
        boundary_seq: u64,
        publication_id: [u8; 16],
    },
    /// Kind 15 (sync-class): the records up to `through_seq` went into a
    /// candidate that projects one sync's selection, or none, rather than
    /// the whole tree.
    ProjectedBoundary {
        candidate: GrainId,
        through_seq: u64,
        publication_id: [u8; 16],
        selection: Option<ProjectedSelection>,
    },
    /// Kind 16: a file stage carried across a journal replacement under its
    /// issued id, named at `at` or detached with no entry, starting from
    /// `anchor`'s bytes or from none.
    RecreateFile {
        at: Option<Location>,
        exec: bool,
        stage_id: u64,
        anchor: Option<RecreateAnchor>,
    },
    /// Kind 17 (sync-class): a terminal residual choice.
    ResidualDisposition(ResidualDisposition),
    /// Kind 18 (sync-class): restore a bound stage to an authenticated anchor
    /// or to empty, recording the size and live bytes discarded by replay.
    StageRollback {
        stage_id: u64,
        old_size: u64,
        anchor: Option<RecreateAnchor>,
        discarded_bytes: u64,
    },
}

/// Why a payload is not a record. Both directions use it: the decoder reports
/// it for a malformed payload and the encoder for a record the decoder would
/// reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// Inventory descriptors must have strictly increasing stage ids.
    InventoryOrder,
    /// The residual choice is neither keep-local nor keep-remote.
    BadDisposition { byte: u8 },
    /// A disposition must enumerate at least one collision.
    EmptyInventory,
    /// A kind this version does not define.
    UnknownKind { kind: u8 },
    /// The payload ends inside a field.
    Truncated,
    /// Bytes remain after the last field.
    TrailingBytes,
    /// The payload is above the record bound.
    PayloadTooLarge { len: usize },
    /// A parent path deeper than 128 names.
    PathTooDeep { depth: usize },
    /// A parent path with more than 4096 name bytes.
    PathTooLong { bytes: usize },
    /// A name the manifest rules refuse.
    BadName(NameError),
    /// A symlink target the manifest rules refuse.
    BadSymlinkTarget(SymlinkTargetError),
    /// An entry type byte that is not file, directory or symlink.
    BadEntryType { tag: u8 },
    /// An exec byte other than 0 or 1.
    BadExec { byte: u8 },
    /// A cause byte this kind does not define.
    BadCause { byte: u8 },
    /// A content or root id with an unregistered algorithm tag.
    BadGrainId,
    /// A field that does not apply to this variant is not zero.
    MustBeZero { field: &'static str },
    /// A stage id of 0 or above 2^63 - 1 where one is required.
    StageIdOutOfRange { stage_id: u64 },
    /// A size or offset above 2^63 - 1.
    SizeOutOfRange { value: u64 },
    /// An extent of zero bytes.
    ExtentEmpty,
    /// An extent above the grain size.
    ExtentTooLong { length: u64 },
    /// An extent whose end passes 2^63 - 1.
    ExtentOverflow { offset: u64, length: u64 },
    /// A generation of 0 or `u64::MAX`.
    GenerationOutOfRange { generation: u64 },
    /// A sequence number outside its range.
    SeqOutOfRange { field: &'static str, value: u64 },
    /// An attempt reservation numbered zero.
    AttemptZero,
    /// A projected boundary's selection tag other than none or a file.
    BadSelectionTag { tag: u8 },
    /// An optional field's tag other than absent or present.
    BadPresenceTag { field: &'static str, tag: u8 },
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadDisposition { byte } => {
                write!(f, "journal residual disposition {byte} is invalid")
            }
            Self::EmptyInventory => write!(f, "journal residual inventory is empty"),
            Self::InventoryOrder => write!(f, "journal residual inventory is not in stage order"),
            Self::UnknownKind { kind } => write!(f, "unknown journal record kind {kind}"),
            Self::Truncated => write!(f, "journal record payload ends inside a field"),
            Self::TrailingBytes => write!(f, "journal record payload has trailing bytes"),
            Self::PayloadTooLarge { len } => {
                write!(f, "journal record payload of {len} bytes is too large")
            }
            Self::PathTooDeep { depth } => write!(f, "journal path of {depth} names is too deep"),
            Self::PathTooLong { bytes } => {
                write!(f, "journal path of {bytes} name bytes is too long")
            }
            Self::BadName(e) => write!(f, "journal name: {e}"),
            Self::BadSymlinkTarget(e) => write!(f, "journal symlink target: {e}"),
            Self::BadEntryType { tag } => write!(f, "journal entry type {tag} is invalid"),
            Self::BadExec { byte } => write!(f, "journal exec byte {byte} is not 0 or 1"),
            Self::BadCause { byte } => write!(f, "journal cause byte {byte} is invalid"),
            Self::BadGrainId => write!(f, "journal id has an unregistered algorithm"),
            Self::MustBeZero { field } => write!(f, "journal field {field} must be zero here"),
            Self::StageIdOutOfRange { stage_id } => {
                write!(f, "journal stage id {stage_id} is out of range")
            }
            Self::SizeOutOfRange { value } => write!(f, "journal size {value} is out of range"),
            Self::ExtentEmpty => write!(f, "journal extent has no bytes"),
            Self::ExtentTooLong { length } => {
                write!(f, "journal extent of {length} bytes is too long")
            }
            Self::ExtentOverflow { offset, length } => {
                write!(f, "journal extent at {offset} of {length} bytes overflows")
            }
            Self::GenerationOutOfRange { generation } => {
                write!(f, "journal generation {generation} is out of range")
            }
            Self::SeqOutOfRange { field, value } => {
                write!(f, "journal {field} {value} is out of range")
            }
            Self::AttemptZero => write!(f, "journal commit attempt is zero"),
            Self::BadSelectionTag { tag } => {
                write!(f, "journal projected selection tag {tag} is invalid")
            }
            Self::BadPresenceTag { field, tag } => {
                write!(f, "journal {field} tag {tag} is invalid")
            }
        }
    }
}

impl std::error::Error for RecordError {}

impl Record {
    /// Whether a later admitted record retires this extent's whole check.
    /// Replay checks only extents that no later record supersedes, and
    /// restores unchecked surviving fragments from the base or synced mark.
    #[must_use]
    pub fn extent_superseded_by(&self, later: &Self) -> bool {
        let Self::WriteExtent {
            stage_id,
            offset,
            length,
            ..
        } = self
        else {
            return false;
        };
        let end = offset.saturating_add(*length);
        match later {
            Self::WriteExtent {
                stage_id: other,
                offset: start,
                length: len,
                ..
            } => stage_id == other && *offset < start.saturating_add(*len) && *start < end,
            Self::Truncate {
                stage_id: other,
                new_size,
            } => stage_id == other && *new_size < end,
            Self::StageRollback {
                stage_id: other, ..
            } => stage_id == other,
            _ => false,
        }
    }

    /// The record's kind byte.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Create { .. } => KIND_CREATE,
            Self::StageBind { .. } => KIND_STAGE_BIND,
            Self::WriteExtent { .. } => KIND_WRITE_EXTENT,
            Self::Truncate { .. } => KIND_TRUNCATE,
            Self::Move { .. } => KIND_MOVE,
            Self::Replace { .. } => KIND_REPLACE,
            Self::Delete { .. } => KIND_DELETE,
            Self::SetattrExec { .. } => KIND_SETATTR_EXEC,
            Self::FileSynced { .. } => KIND_FILE_SYNCED,
            Self::IntentRegistered { .. } => KIND_INTENT_REGISTERED,
            Self::CommitBoundary { .. } => KIND_COMMIT_BOUNDARY,
            Self::LandedCommit { .. } => KIND_LANDED_COMMIT,
            Self::CommitAttempt { .. } => KIND_COMMIT_ATTEMPT,
            Self::CommitFence { .. } => KIND_COMMIT_FENCE,
            Self::ProjectedBoundary { .. } => KIND_PROJECTED_BOUNDARY,
            Self::RecreateFile { .. } => KIND_RECREATE_FILE,
            Self::ResidualDisposition(_) => KIND_RESIDUAL_DISPOSITION,
            Self::StageRollback { .. } => KIND_STAGE_ROLLBACK,
        }
    }

    /// Whether the record is sync-class: appended only after a completed
    /// fsync of the journal or installed in a synced image, so its existence
    /// proves every earlier byte was durable.
    #[must_use]
    pub const fn is_sync_class(&self) -> bool {
        is_sync_class_kind(self.kind())
    }

    /// The payload bytes, refusing any record [`Record::decode_payload`]
    /// would reject (the encoder decodes what it wrote to validate the fields).
    ///
    /// # Errors
    /// The [`RecordError`] the decoder would report.
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per journal record keeps the canonical field order explicit"
    )]
    pub fn encode_payload(&self) -> Result<Vec<u8>, RecordError> {
        let mut out = Vec::new();
        match self {
            Self::ResidualDisposition(choice) => {
                out.extend_from_slice(&choice.boundary_seq.to_be_bytes());
                out.extend_from_slice(&choice.publication_id);
                out.extend_from_slice(&choice.landed_root.to_bytes());
                out.extend_from_slice(&choice.landed_seq.to_be_bytes());
                out.extend_from_slice(&choice.source_end.to_be_bytes());
                out.push(choice.disposition as u8);
                out.extend_from_slice(&choice.collision_count.to_be_bytes());
                out.extend_from_slice(&choice.inventory_check);
            }
            Self::Create { at, kind } => put_create(&mut out, at, kind),
            Self::StageBind {
                at,
                cause,
                stage_id,
                staged_size,
                base_content,
            } => {
                put_location(&mut out, at);
                out.push(*cause as u8);
                out.extend_from_slice(&stage_id.to_be_bytes());
                out.extend_from_slice(&staged_size.to_be_bytes());
                out.extend_from_slice(&base_content.to_bytes());
            }
            Self::WriteExtent {
                stage_id,
                offset,
                length,
                check,
            } => {
                out.extend_from_slice(&stage_id.to_be_bytes());
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(&length.to_be_bytes());
                out.extend_from_slice(check);
            }
            Self::Truncate { stage_id, new_size } => {
                out.extend_from_slice(&stage_id.to_be_bytes());
                out.extend_from_slice(&new_size.to_be_bytes());
            }
            Self::Move { from, to } | Self::Replace { from, to } => {
                put_location(&mut out, from);
                put_location(&mut out, to);
            }
            Self::Delete { at, kind } => {
                if let DeleteKind::File { stage_id: Some(0) } = kind {
                    return Err(RecordError::StageIdOutOfRange { stage_id: 0 });
                }
                put_delete(&mut out, at, kind);
            }
            Self::SetattrExec { at, exec } => {
                put_location(&mut out, at);
                out.push(u8::from(*exec));
            }
            Self::FileSynced {
                stage_id,
                synced_size,
                content,
                generation,
                prepared_root,
            } => {
                out.extend_from_slice(&stage_id.to_be_bytes());
                out.extend_from_slice(&synced_size.to_be_bytes());
                out.extend_from_slice(&content.to_bytes());
                out.extend_from_slice(&generation.to_be_bytes());
                out.extend_from_slice(&prepared_root.to_bytes());
            }
            Self::IntentRegistered {
                generation,
                prepared_root,
                cause,
            } => {
                out.extend_from_slice(&generation.to_be_bytes());
                out.extend_from_slice(&prepared_root.to_bytes());
                out.push(*cause as u8);
            }
            Self::CommitBoundary {
                candidate,
                through_seq,
                publication_id,
            } => {
                out.extend_from_slice(&candidate.to_bytes());
                out.extend_from_slice(&through_seq.to_be_bytes());
                out.extend_from_slice(publication_id);
            }
            Self::ProjectedBoundary {
                candidate,
                through_seq,
                publication_id,
                selection,
            } => {
                out.extend_from_slice(&candidate.to_bytes());
                out.extend_from_slice(&through_seq.to_be_bytes());
                out.extend_from_slice(publication_id);
                put_selection(&mut out, selection.as_ref());
            }
            Self::RecreateFile {
                at,
                exec,
                stage_id,
                anchor,
            } => put_recreate(&mut out, at.as_ref(), *exec, *stage_id, anchor.as_ref()),
            Self::StageRollback {
                stage_id,
                old_size,
                anchor,
                discarded_bytes,
            } => {
                out.extend_from_slice(&stage_id.to_be_bytes());
                out.extend_from_slice(&old_size.to_be_bytes());
                put_anchor(&mut out, anchor.as_ref());
                out.extend_from_slice(&discarded_bytes.to_be_bytes());
            }
            Self::CommitAttempt {
                boundary_seq,
                publication_id,
                attempt,
            } => {
                out.extend_from_slice(&boundary_seq.to_be_bytes());
                out.extend_from_slice(publication_id);
                out.extend_from_slice(&attempt.to_be_bytes());
            }
            Self::CommitFence {
                boundary_seq,
                publication_id,
            } => {
                out.extend_from_slice(&boundary_seq.to_be_bytes());
                out.extend_from_slice(publication_id);
            }
            Self::LandedCommit {
                boundary_seq,
                landed_root,
                landed_seq,
            } => {
                out.extend_from_slice(&boundary_seq.to_be_bytes());
                out.extend_from_slice(&landed_root.to_bytes());
                out.extend_from_slice(&landed_seq.to_be_bytes());
            }
        }
        if out.len() > super::PAYLOAD_MAX {
            return Err(RecordError::PayloadTooLarge { len: out.len() });
        }
        // All lossy representations (notably Some(0) in a file delete)
        // are refused above; the remaining fields encode canonically.
        Self::decode_payload(self.kind(), &out)?;
        Ok(out)
    }

    /// Decode a payload of the given kind, strictly.
    ///
    /// # Errors
    /// The [`RecordError`] naming the first field the payload fails.
    pub fn decode_payload(kind: u8, payload: &[u8]) -> Result<Self, RecordError> {
        let mut r = Reader::new(payload);
        let record = match kind {
            KIND_RESIDUAL_DISPOSITION => get_residual_disposition(&mut r)?,
            KIND_CREATE => get_create(&mut r)?,
            KIND_STAGE_BIND => get_stage_bind(&mut r)?,
            KIND_WRITE_EXTENT => get_extent(&mut r)?,
            KIND_TRUNCATE => {
                let stage_id = get_stage_id(&mut r)?;
                let new_size = get_size(&mut r)?;
                Self::Truncate { stage_id, new_size }
            }
            KIND_MOVE | KIND_REPLACE => {
                let from = get_location(&mut r)?;
                let to = get_location(&mut r)?;
                if kind == KIND_MOVE {
                    Self::Move { from, to }
                } else {
                    Self::Replace { from, to }
                }
            }
            KIND_DELETE => get_delete(&mut r)?,
            KIND_SETATTR_EXEC => {
                let at = get_location(&mut r)?;
                let exec = get_exec(get_u8(&mut r)?)?;
                Self::SetattrExec { at, exec }
            }
            KIND_FILE_SYNCED => {
                let stage_id = get_stage_id(&mut r)?;
                let synced_size = get_size(&mut r)?;
                let content = get_grain_id(&mut r)?;
                let generation = get_generation(&mut r)?;
                let prepared_root = get_grain_id(&mut r)?;
                Self::FileSynced {
                    stage_id,
                    synced_size,
                    content,
                    generation,
                    prepared_root,
                }
            }
            KIND_INTENT_REGISTERED => {
                let generation = get_generation(&mut r)?;
                let prepared_root = get_grain_id(&mut r)?;
                let cause = match get_u8(&mut r)? {
                    1 => IntentCause::DirectorySync,
                    2 => IntentCause::LandedRefresh,
                    byte => return Err(RecordError::BadCause { byte }),
                };
                Self::IntentRegistered {
                    generation,
                    prepared_root,
                    cause,
                }
            }
            KIND_COMMIT_BOUNDARY => get_commit_boundary(&mut r)?,
            KIND_PROJECTED_BOUNDARY => get_projected_boundary(&mut r)?,
            KIND_RECREATE_FILE => get_recreate(&mut r)?,
            KIND_STAGE_ROLLBACK => Self::StageRollback {
                stage_id: get_stage_id(&mut r)?,
                old_size: get_size(&mut r)?,
                anchor: get_anchor(&mut r)?,
                discarded_bytes: get_u64(&mut r)?,
            },
            KIND_LANDED_COMMIT => get_landed(&mut r)?,
            KIND_COMMIT_ATTEMPT | KIND_COMMIT_FENCE => {
                let boundary_seq = get_u64(&mut r)?;
                if boundary_seq == 0 {
                    return Err(RecordError::SeqOutOfRange {
                        field: "boundary seq",
                        value: 0,
                    });
                }
                let publication_id = r.array().ok_or(RecordError::Truncated)?;
                if kind == KIND_COMMIT_ATTEMPT {
                    let attempt = get_u64(&mut r)?;
                    if attempt == 0 {
                        return Err(RecordError::AttemptZero);
                    }
                    Self::CommitAttempt {
                        boundary_seq,
                        publication_id,
                        attempt,
                    }
                } else {
                    Self::CommitFence {
                        boundary_seq,
                        publication_id,
                    }
                }
            }
            kind => return Err(RecordError::UnknownKind { kind }),
        };
        if !r.is_empty() {
            return Err(RecordError::TrailingBytes);
        }
        Ok(record)
    }
}

/// Whether `kind` is one of the sync-class kinds (9 to 15, 17 and 18).
#[must_use]
pub(super) const fn is_sync_class_kind(kind: u8) -> bool {
    matches!(
        kind,
        KIND_RESIDUAL_DISPOSITION
            | KIND_FILE_SYNCED
            | KIND_INTENT_REGISTERED
            | KIND_COMMIT_BOUNDARY
            | KIND_LANDED_COMMIT
            | KIND_COMMIT_ATTEMPT
            | KIND_COMMIT_FENCE
            | KIND_PROJECTED_BOUNDARY
            | KIND_STAGE_ROLLBACK
    )
}

/// The fixed payload length of a sync-class kind, or `None` for any other.
pub(super) const fn sync_payload_len(kind: u8) -> Option<usize> {
    match kind {
        KIND_RESIDUAL_DISPOSITION => Some(110),
        KIND_FILE_SYNCED => Some(8 + 8 + GRAIN_ID_BINARY_LEN + 8 + GRAIN_ID_BINARY_LEN),
        KIND_INTENT_REGISTERED => Some(8 + GRAIN_ID_BINARY_LEN + 1),
        KIND_COMMIT_BOUNDARY => Some(GRAIN_ID_BINARY_LEN + 8 + 16),
        KIND_LANDED_COMMIT => Some(8 + GRAIN_ID_BINARY_LEN + 8),
        KIND_COMMIT_ATTEMPT => Some(32),
        KIND_COMMIT_FENCE => Some(24),
        KIND_PROJECTED_BOUNDARY => Some(GRAIN_ID_BINARY_LEN + 8 + 16 + SELECTION_LEN),
        KIND_STAGE_ROLLBACK => Some(66),
        _ => None,
    }
}

fn put_create(out: &mut Vec<u8>, at: &Location, kind: &CreateKind) {
    put_location(out, at);
    match kind {
        CreateKind::File { exec, stage_id } => {
            out.push(TYPE_FILE);
            out.push(u8::from(*exec));
            out.extend_from_slice(&stage_id.to_be_bytes());
        }
        CreateKind::Dir => {
            out.push(TYPE_DIR);
            out.push(0);
            out.extend_from_slice(&0u64.to_be_bytes());
        }
        CreateKind::Symlink { target } => {
            out.push(TYPE_SYMLINK);
            out.push(0);
            out.extend_from_slice(&0u64.to_be_bytes());
            out.extend_from_slice(&target.wire_len().to_be_bytes());
            out.extend_from_slice(target.as_bytes());
        }
    }
}

fn put_delete(out: &mut Vec<u8>, at: &Location, kind: &DeleteKind) {
    put_location(out, at);
    let (tag, stage_id) = match kind {
        DeleteKind::File { stage_id } => (TYPE_FILE, stage_id.unwrap_or(0)),
        DeleteKind::Dir => (TYPE_DIR, 0),
        DeleteKind::Symlink => (TYPE_SYMLINK, 0),
    };
    out.push(tag);
    out.extend_from_slice(&stage_id.to_be_bytes());
}

fn get_create(r: &mut Reader<'_>) -> Result<Record, RecordError> {
    let at = get_location(r)?;
    let tag = get_u8(r)?;
    let exec = get_u8(r)?;
    let stage_id = get_u64(r)?;
    let kind = match tag {
        TYPE_FILE => {
            let exec = get_exec(exec)?;
            check_stage_id(stage_id)?;
            CreateKind::File { exec, stage_id }
        }
        TYPE_DIR | TYPE_SYMLINK => {
            must_be_zero(exec.into(), "exec")?;
            must_be_zero(stage_id, "stage id")?;
            if tag == TYPE_DIR {
                CreateKind::Dir
            } else {
                CreateKind::Symlink {
                    target: get_symlink_target(r)?,
                }
            }
        }
        tag => return Err(RecordError::BadEntryType { tag }),
    };
    Ok(Record::Create { at, kind })
}

fn get_delete(r: &mut Reader<'_>) -> Result<Record, RecordError> {
    let at = get_location(r)?;
    let tag = get_u8(r)?;
    let stage_id = get_u64(r)?;
    let kind = match tag {
        TYPE_FILE if stage_id == 0 => DeleteKind::File { stage_id: None },
        TYPE_FILE => {
            check_stage_id(stage_id)?;
            DeleteKind::File {
                stage_id: Some(stage_id),
            }
        }
        TYPE_DIR | TYPE_SYMLINK => {
            must_be_zero(stage_id, "stage id")?;
            if tag == TYPE_DIR {
                DeleteKind::Dir
            } else {
                DeleteKind::Symlink
            }
        }
        tag => return Err(RecordError::BadEntryType { tag }),
    };
    Ok(Record::Delete { at, kind })
}

fn get_stage_bind(r: &mut Reader<'_>) -> Result<Record, RecordError> {
    let at = get_location(r)?;
    let cause = match get_u8(r)? {
        1 => BindCause::CopyUp,
        2 => BindCause::Rebind,
        byte => return Err(RecordError::BadCause { byte }),
    };
    let stage_id = get_stage_id(r)?;
    let staged_size = get_size(r)?;
    let base_content = get_grain_id(r)?;
    Ok(Record::StageBind {
        at,
        cause,
        stage_id,
        staged_size,
        base_content,
    })
}

fn get_commit_boundary(r: &mut Reader<'_>) -> Result<Record, RecordError> {
    let candidate = get_grain_id(r)?;
    let through_seq = get_u64(r)?;
    let publication_id = r.array().ok_or(RecordError::Truncated)?;
    Ok(Record::CommitBoundary {
        candidate,
        through_seq,
        publication_id,
    })
}

/// A selection's tag, stage id, content id and size: always this long, so the
/// boundary's payload length is fixed and it can witness a hole.
const SELECTION_LEN: usize = 1 + 8 + GRAIN_ID_BINARY_LEN + 8;

/// No selection is one encoding only: the tag and every field zero.
fn put_selection(out: &mut Vec<u8>, selection: Option<&ProjectedSelection>) {
    match selection {
        None => {
            out.push(SELECTION_NONE);
            out.extend_from_slice(&[0; SELECTION_LEN - 1]);
        }
        Some(selection) => {
            out.push(SELECTION_FILE);
            out.extend_from_slice(&selection.stage_id.to_be_bytes());
            out.extend_from_slice(&selection.content.to_bytes());
            out.extend_from_slice(&selection.size.to_be_bytes());
        }
    }
}

fn get_projected_boundary(r: &mut Reader<'_>) -> Result<Record, RecordError> {
    let candidate = get_grain_id(r)?;
    let through_seq = get_u64(r)?;
    let publication_id = r.array().ok_or(RecordError::Truncated)?;
    let selection = match get_u8(r)? {
        SELECTION_NONE => {
            must_be_zero(get_u64(r)?, "selected stage id")?;
            let content: [u8; GRAIN_ID_BINARY_LEN] = r.array().ok_or(RecordError::Truncated)?;
            if content != [0; GRAIN_ID_BINARY_LEN] {
                return Err(RecordError::MustBeZero {
                    field: "selected content",
                });
            }
            must_be_zero(get_u64(r)?, "selected size")?;
            None
        }
        SELECTION_FILE => Some(ProjectedSelection {
            stage_id: get_stage_id(r)?,
            content: get_grain_id(r)?,
            size: get_size(r)?,
        }),
        tag => return Err(RecordError::BadSelectionTag { tag }),
    };
    Ok(Record::ProjectedBoundary {
        candidate,
        through_seq,
        publication_id,
        selection,
    })
}

/// An absent location is its tag alone; an absent anchor is its tag and zero
/// fields, and a detached stage's exec byte is zero: one encoding each.
fn put_recreate(
    out: &mut Vec<u8>,
    at: Option<&Location>,
    exec: bool,
    stage_id: u64,
    anchor: Option<&RecreateAnchor>,
) {
    match at {
        None => out.push(ABSENT),
        Some(at) => {
            out.push(PRESENT);
            put_location(out, at);
        }
    }
    out.push(u8::from(exec));
    out.extend_from_slice(&stage_id.to_be_bytes());
    put_anchor(out, anchor);
}

fn put_anchor(out: &mut Vec<u8>, anchor: Option<&RecreateAnchor>) {
    match anchor {
        None => {
            out.push(ABSENT);
            out.extend_from_slice(&[0; GRAIN_ID_BINARY_LEN + 8]);
        }
        Some(anchor) => {
            out.push(PRESENT);
            out.extend_from_slice(&anchor.content.to_bytes());
            out.extend_from_slice(&anchor.size.to_be_bytes());
        }
    }
}

fn get_recreate(r: &mut Reader<'_>) -> Result<Record, RecordError> {
    let at = match get_u8(r)? {
        ABSENT => None,
        PRESENT => Some(get_location(r)?),
        tag => {
            return Err(RecordError::BadPresenceTag {
                field: "location",
                tag,
            });
        }
    };
    let exec = get_exec(get_u8(r)?)?;
    if at.is_none() {
        must_be_zero(exec.into(), "exec")?;
    }
    let stage_id = get_stage_id(r)?;
    Ok(Record::RecreateFile {
        at,
        exec,
        stage_id,
        anchor: get_anchor(r)?,
    })
}

fn get_anchor(r: &mut Reader<'_>) -> Result<Option<RecreateAnchor>, RecordError> {
    match get_u8(r)? {
        ABSENT => {
            let content: [u8; GRAIN_ID_BINARY_LEN] = r.array().ok_or(RecordError::Truncated)?;
            if content != [0; GRAIN_ID_BINARY_LEN] {
                return Err(RecordError::MustBeZero {
                    field: "anchor content",
                });
            }
            must_be_zero(get_u64(r)?, "anchor size")?;
            Ok(None)
        }
        PRESENT => Ok(Some(RecreateAnchor {
            content: get_grain_id(r)?,
            size: get_size(r)?,
        })),
        tag => Err(RecordError::BadPresenceTag {
            field: "anchor",
            tag,
        }),
    }
}

fn get_landed(r: &mut Reader<'_>) -> Result<Record, RecordError> {
    let boundary_seq = get_u64(r)?;
    if boundary_seq == 0 {
        return Err(RecordError::SeqOutOfRange {
            field: "boundary seq",
            value: 0,
        });
    }
    let landed_root = get_grain_id(r)?;
    let landed_seq = get_u64(r)?;
    if !(2..=GENERATION_MAX).contains(&landed_seq) {
        return Err(RecordError::SeqOutOfRange {
            field: "landed seq",
            value: landed_seq,
        });
    }
    Ok(Record::LandedCommit {
        boundary_seq,
        landed_root,
        landed_seq,
    })
}

fn get_extent(r: &mut Reader<'_>) -> Result<Record, RecordError> {
    let stage_id = get_stage_id(r)?;
    let offset = get_size(r)?;
    let length = get_u64(r)?;
    if length == 0 {
        return Err(RecordError::ExtentEmpty);
    }
    if length > EXTENT_LEN_MAX {
        return Err(RecordError::ExtentTooLong { length });
    }
    if offset.checked_add(length).is_none_or(|end| end > SIZE_MAX) {
        return Err(RecordError::ExtentOverflow { offset, length });
    }
    let check = r.array().ok_or(RecordError::Truncated)?;
    Ok(Record::WriteExtent {
        stage_id,
        offset,
        length,
        check,
    })
}

fn get_stage_id(r: &mut Reader<'_>) -> Result<u64, RecordError> {
    let stage_id = get_u64(r)?;
    check_stage_id(stage_id)?;
    Ok(stage_id)
}

fn put_location(out: &mut Vec<u8>, at: &Location) {
    // A parent holds at most `PATH_DEPTH_MAX` names, so the depth fits u16.
    let depth = u16::try_from(at.parent.0.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&depth.to_be_bytes());
    for name in &at.parent.0 {
        out.push(name.wire_len());
        out.extend_from_slice(name.as_bytes());
    }
    out.push(at.name.wire_len());
    out.extend_from_slice(at.name.as_bytes());
}

fn get_u8(r: &mut Reader<'_>) -> Result<u8, RecordError> {
    r.u8().ok_or(RecordError::Truncated)
}

fn get_u64(r: &mut Reader<'_>) -> Result<u64, RecordError> {
    r.u64().ok_or(RecordError::Truncated)
}

fn get_size(r: &mut Reader<'_>) -> Result<u64, RecordError> {
    let value = get_u64(r)?;
    if value > SIZE_MAX {
        return Err(RecordError::SizeOutOfRange { value });
    }
    Ok(value)
}

fn get_generation(r: &mut Reader<'_>) -> Result<u64, RecordError> {
    let generation = get_u64(r)?;
    if generation == 0 || generation > GENERATION_MAX {
        return Err(RecordError::GenerationOutOfRange { generation });
    }
    Ok(generation)
}

fn get_grain_id(r: &mut Reader<'_>) -> Result<GrainId, RecordError> {
    r.grain_id()
        .ok_or(RecordError::Truncated)?
        .map_err(|()| RecordError::BadGrainId)
}

fn get_exec(byte: u8) -> Result<bool, RecordError> {
    match byte {
        0 => Ok(false),
        1 => Ok(true),
        byte => Err(RecordError::BadExec { byte }),
    }
}

fn check_stage_id(stage_id: u64) -> Result<(), RecordError> {
    if stage_id == 0 || stage_id > STAGE_ID_MAX {
        return Err(RecordError::StageIdOutOfRange { stage_id });
    }
    Ok(())
}

fn must_be_zero(value: u64, field: &'static str) -> Result<(), RecordError> {
    if value != 0 {
        return Err(RecordError::MustBeZero { field });
    }
    Ok(())
}

fn get_name(r: &mut Reader<'_>) -> Result<Name, RecordError> {
    let len = usize::from(get_u8(r)?);
    let bytes = r.take(len).ok_or(RecordError::Truncated)?;
    Name::new(bytes.to_vec()).map_err(RecordError::BadName)
}

fn get_parent(r: &mut Reader<'_>) -> Result<Parent, RecordError> {
    let depth = usize::from(r.u16().ok_or(RecordError::Truncated)?);
    if depth > PATH_DEPTH_MAX {
        return Err(RecordError::PathTooDeep { depth });
    }
    let mut names = Vec::with_capacity(depth);
    let mut bytes = 0usize;
    for _ in 0..depth {
        let name = get_name(r)?;
        bytes = bytes.saturating_add(name.as_bytes().len());
        if bytes > PATH_BYTES_MAX {
            return Err(RecordError::PathTooLong { bytes });
        }
        names.push(name);
    }
    Ok(Parent(names))
}

fn get_location(r: &mut Reader<'_>) -> Result<Location, RecordError> {
    let parent = get_parent(r)?;
    let name = get_name(r)?;
    Ok(Location { parent, name })
}

fn get_symlink_target(r: &mut Reader<'_>) -> Result<SymlinkTarget, RecordError> {
    let len = usize::from(r.u16().ok_or(RecordError::Truncated)?);
    if len > SYMLINK_TARGET_MAX {
        return Err(RecordError::BadSymlinkTarget(SymlinkTargetError::TooLong {
            len,
        }));
    }
    let bytes = r.take(len).ok_or(RecordError::Truncated)?;
    SymlinkTarget::new(bytes.to_vec()).map_err(RecordError::BadSymlinkTarget)
}

fn get_residual_disposition(r: &mut Reader<'_>) -> Result<Record, RecordError> {
    let boundary_seq = get_u64(r)?;
    if boundary_seq == 0 {
        return Err(RecordError::SeqOutOfRange {
            field: "boundary seq",
            value: 0,
        });
    }
    let publication_id = r.array().ok_or(RecordError::Truncated)?;
    let landed_root = get_grain_id(r)?;
    let landed_seq = get_u64(r)?;
    if landed_seq == 0 || landed_seq == u64::MAX {
        return Err(RecordError::SeqOutOfRange {
            field: "landed seq",
            value: landed_seq,
        });
    }
    let source_end = get_u64(r)?;
    let disposition = match get_u8(r)? {
        1 => ResidualMode::KeepLocal,
        2 => ResidualMode::KeepRemote,
        byte => return Err(RecordError::BadDisposition { byte }),
    };
    let collision_count = u32::from_be_bytes(r.array().ok_or(RecordError::Truncated)?);
    if collision_count == 0 {
        return Err(RecordError::EmptyInventory);
    }
    let inventory_check = r.array().ok_or(RecordError::Truncated)?;
    Ok(Record::ResidualDisposition(ResidualDisposition {
        boundary_seq,
        publication_id,
        landed_root,
        landed_seq,
        source_end,
        disposition,
        collision_count,
        inventory_check,
    }))
}
