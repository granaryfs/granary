// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The journal header, the record frame, the value rules that need earlier
//! records, and the scan that classifies a journal's bytes as clean, torn or
//! fenced.

use std::collections::BTreeMap;

use super::record::{
    BindCause, CreateKind, DeleteKind, Record, RecordError, is_sync_class_kind, sync_payload_len,
};
use super::{
    BindingError, CHECK_LEN, GENERATION_MAX, HEADER_CONTEXT, JOURNAL_HEADER_LEN, JOURNAL_MAGIC,
    JOURNAL_MAX, LEN_MAX, LEN_MIN, MarkState, PAYLOAD_MAX, RECORD_CONTEXT, Reader, STAGE_ID_MAX,
    StagingHeader, VERSION, WRITER_ID_LEN, WriterRecord,
};
use crate::hash::{GRAIN_ID_BINARY_LEN, GrainId};

/// The journal's header: which writer owns the journal, which root it was
/// built on, and the counters that carry across a replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalHeader {
    /// The writer identity; equals the writer file's.
    pub writer: [u8; WRITER_ID_LEN],
    /// The root this overlay was built on.
    pub base_root: GrainId,
    /// The base root's seq, 1..=`u64::MAX - 2` so a successor head exists.
    pub base_seq: u64,
    /// The id the first stage-introducing record must take, 1..=2^63.
    pub next_stage_id: u64,
    /// 0, or the highest generation for which a receipt is held.
    pub receipt_generation: u64,
}

/// Why a byte string is not a journal header. [`JournalHeader::decode`]
/// reports the first of these, in declaration order, that the input fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// The first eight bytes are not the journal magic.
    BadMagic,
    /// Not exactly 117 bytes.
    BadLength { len: usize },
    /// The check does not match the bytes before it.
    BadCheck,
    /// A version other than 1.
    UnknownVersion { version: u16 },
    /// The reserved flags are not zero.
    NonZeroFlags { flags: u16 },
    /// The base root id has an unregistered algorithm.
    BadGrainId,
    /// A base seq of 0 or above `u64::MAX - 2`.
    BaseSeqOutOfRange { base_seq: u64 },
    /// A next stage id of 0 or above 2^63.
    NextStageIdOutOfRange { next_stage_id: u64 },
    /// A receipt generation of `u64::MAX`.
    ReceiptGenerationOutOfRange { generation: u64 },
}

impl std::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "bad journal magic"),
            Self::BadLength { len } => write!(f, "journal header has a bad length of {len}"),
            Self::BadCheck => write!(f, "journal header check does not match"),
            Self::UnknownVersion { version } => write!(f, "unknown journal version {version}"),
            Self::NonZeroFlags { flags } => {
                write!(f, "journal flags 0x{flags:04x} are reserved")
            }
            Self::BadGrainId => write!(f, "journal base root has an unregistered algorithm"),
            Self::BaseSeqOutOfRange { base_seq } => {
                write!(f, "journal base seq {base_seq} is out of range")
            }
            Self::NextStageIdOutOfRange { next_stage_id } => {
                write!(f, "journal next stage id {next_stage_id} is out of range")
            }
            Self::ReceiptGenerationOutOfRange { generation } => {
                write!(f, "journal receipt generation {generation} is out of range")
            }
        }
    }
}

impl std::error::Error for HeaderError {}

impl JournalHeader {
    /// Everything the header's check covers: the first 85 bytes.
    fn preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(JOURNAL_HEADER_LEN);
        out.extend_from_slice(&JOURNAL_MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.writer);
        out.extend_from_slice(&self.base_root.to_bytes());
        out.extend_from_slice(&self.base_seq.to_be_bytes());
        out.extend_from_slice(&self.next_stage_id.to_be_bytes());
        out.extend_from_slice(&self.receipt_generation.to_be_bytes());
        out
    }

    /// The header's check, which every record's check also covers.
    #[must_use]
    pub fn check(&self) -> [u8; CHECK_LEN] {
        blake3::derive_key(HEADER_CONTEXT, &self.preimage())
    }

    fn validate(&self) -> Result<(), HeaderError> {
        if self.base_seq == 0 || self.base_seq > u64::MAX - 2 {
            return Err(HeaderError::BaseSeqOutOfRange {
                base_seq: self.base_seq,
            });
        }
        if self.next_stage_id == 0 || self.next_stage_id > STAGE_ID_MAX + 1 {
            return Err(HeaderError::NextStageIdOutOfRange {
                next_stage_id: self.next_stage_id,
            });
        }
        if self.receipt_generation > GENERATION_MAX {
            return Err(HeaderError::ReceiptGenerationOutOfRange {
                generation: self.receipt_generation,
            });
        }
        Ok(())
    }

    /// The header's canonical bytes, 117 of them.
    ///
    /// # Errors
    /// The [`HeaderError`] the decoder would report for these fields.
    pub fn encode(&self) -> Result<Vec<u8>, HeaderError> {
        self.validate()?;
        let mut out = self.preimage();
        out.extend_from_slice(&self.check());
        Ok(out)
    }

    /// Decode a header from exactly 117 bytes.
    ///
    /// The checks run in this order and the first failure is the error:
    /// magic, length, the check, version, flags, the base root's algorithm,
    /// base seq, next stage id, receipt generation.
    ///
    /// # Errors
    /// [`HeaderError`] naming the first check the input fails.
    pub fn decode(bytes: &[u8]) -> Result<Self, HeaderError> {
        if bytes
            .get(..JOURNAL_MAGIC.len())
            .is_some_and(|magic| magic != JOURNAL_MAGIC)
        {
            return Err(HeaderError::BadMagic);
        }
        let bad_length = HeaderError::BadLength { len: bytes.len() };
        if bytes.len() != JOURNAL_HEADER_LEN {
            return Err(bad_length);
        }
        let (covered, check) = bytes.split_last_chunk::<CHECK_LEN>().ok_or(bad_length)?;
        if *check != blake3::derive_key(HEADER_CONTEXT, covered) {
            return Err(HeaderError::BadCheck);
        }
        let mut r = Reader::new(covered);
        let (
            Some(_),
            Some(version),
            Some(flags),
            Some(writer),
            Some(base_root),
            Some(base_seq),
            Some(next_stage_id),
            Some(receipt_generation),
        ) = (
            r.take(JOURNAL_MAGIC.len()),
            r.u16(),
            r.u16(),
            r.array(),
            r.grain_id(),
            r.u64(),
            r.u64(),
            r.u64(),
        )
        else {
            return Err(bad_length);
        };
        if version != VERSION {
            return Err(HeaderError::UnknownVersion { version });
        }
        if flags != 0 {
            return Err(HeaderError::NonZeroFlags { flags });
        }
        let base_root = base_root.map_err(|()| HeaderError::BadGrainId)?;
        let header = Self {
            writer,
            base_root,
            base_seq,
            next_stage_id,
            receipt_generation,
        };
        header.validate()?;
        Ok(header)
    }
}

/// A value rule that needs earlier records: the record decoded and its check
/// held, but it is impossible given what precedes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueError {
    /// A disposition does not bind the sealed source and refreshed landing.
    ResidualSourceMismatch,
    /// A disposition seals the journal against every subsequent append.
    AfterResidualDisposition,
    /// A new stage id that is not the running next id.
    StageIdNotNext { expected: u64, found: u64 },
    /// A re-bind of an id that was never issued (not below the running next
    /// id).
    RebindNotIssued { stage_id: u64, next: u64 },
    /// A recreate of an id that was never issued (not below the running next
    /// id).
    RecreateNotIssued { stage_id: u64, next: u64 },
    /// A bind of an id already bound in this journal.
    StageAlreadyBound { stage_id: u64 },
    /// A record names a stage id that no record in this journal bound.
    UnknownStage { stage_id: u64 },
    /// A synced size above the stage's accounted size.
    SyncedExceedsStaged { synced_size: u64, staged_size: u64 },
    /// A generation not above the header's receipt generation.
    GenerationNotAboveReceipt { generation: u64, receipt: u64 },
    /// A generation below the one before it.
    GenerationDecreased { generation: u64, previous: u64 },
    /// Equal generations must identify the same prepared root.
    GenerationRootMismatch { generation: u64 },
    /// A commit boundary whose through seq is not below its own seq.
    BoundaryThroughNotBelowSeq { through_seq: u64, seq: u64 },
    /// A projected boundary selects a stage bound after its through seq.
    SelectionAfterThrough {
        stage_id: u64,
        bound_at: u64,
        through_seq: u64,
    },
    /// A projected boundary whose prefix ends before an open boundary.
    ThroughBelowOpenBoundary { through_seq: u64, boundary_seq: u64 },
    /// A landed commit that names no unanswered commit boundary.
    NoOpenBoundary { boundary_seq: u64 },
    /// Commit evidence must identify an open boundary's publication.
    CommitBinding { boundary_seq: u64 },
    /// Each charge reserves exactly the next attempt.
    AttemptNotNext { previous: u64, attempt: u64 },
    /// A landed seq not above the header's base seq.
    LandedSeqNotAboveBase { landed_seq: u64, base_seq: u64 },
}

impl std::fmt::Display for ValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResidualSourceMismatch => {
                write!(f, "journal residual disposition source mismatch")
            }
            Self::AfterResidualDisposition => {
                write!(f, "journal record follows residual disposition")
            }
            Self::StageIdNotNext { expected, found } => {
                write!(f, "journal stage id {found} is not the next id {expected}")
            }
            Self::RebindNotIssued { stage_id, next } => write!(
                f,
                "journal re-bind of stage id {stage_id} which was not issued (next id {next})"
            ),
            Self::RecreateNotIssued { stage_id, next } => write!(
                f,
                "journal recreate of stage id {stage_id} which was not issued (next id {next})"
            ),
            Self::StageAlreadyBound { stage_id } => {
                write!(f, "journal stage id {stage_id} is already bound")
            }
            Self::UnknownStage { stage_id } => {
                write!(f, "journal record names unbound stage id {stage_id}")
            }
            Self::SyncedExceedsStaged {
                synced_size,
                staged_size,
            } => write!(
                f,
                "journal synced size {synced_size} exceeds staged size {staged_size}"
            ),
            Self::GenerationNotAboveReceipt {
                generation,
                receipt,
            } => write!(
                f,
                "journal generation {generation} is not above receipt generation {receipt}"
            ),
            Self::GenerationDecreased {
                generation,
                previous,
            } => write!(
                f,
                "journal generation {generation} is below the previous {previous}"
            ),
            Self::GenerationRootMismatch { generation } => write!(
                f,
                "journal generation {generation} names different prepared roots"
            ),
            Self::BoundaryThroughNotBelowSeq { through_seq, seq } => write!(
                f,
                "journal commit boundary through seq {through_seq} is not below its seq {seq}"
            ),
            Self::SelectionAfterThrough {
                stage_id,
                bound_at,
                through_seq,
            } => write!(
                f,
                "journal projected selection of stage id {stage_id} bound at seq {bound_at} is after through seq {through_seq}"
            ),
            Self::ThroughBelowOpenBoundary {
                through_seq,
                boundary_seq,
            } => write!(
                f,
                "journal projected through seq {through_seq} is below open boundary {boundary_seq}"
            ),
            Self::NoOpenBoundary { boundary_seq } => {
                write!(
                    f,
                    "journal landed commit names no open boundary {boundary_seq}"
                )
            }
            Self::CommitBinding { boundary_seq } => write!(
                f,
                "journal commit evidence names no matching open boundary {boundary_seq}"
            ),
            Self::AttemptNotNext { previous, attempt } => write!(
                f,
                "journal commit attempt {attempt} does not follow {previous}"
            ),
            Self::LandedSeqNotAboveBase {
                landed_seq,
                base_seq,
            } => write!(
                f,
                "journal landed seq {landed_seq} is not above base seq {base_seq}"
            ),
        }
    }
}

impl std::error::Error for ValueError {}

/// What the scan keeps about one bound stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StageState {
    /// The accounted size: the bind's staged size, raised by an extent's end
    /// and set by a truncate.
    pub size: u64,
    /// The synced size of the last `file-synced` for this stage.
    pub synced_size: Option<u64>,
    /// The seq of the record that bound it in this journal.
    pub bound_at: u64,
}

/// Durable dispatch reservations and the sticky fence for an open publication.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommitProgress {
    /// Number of durable dispatch reservations.
    pub attempts: u64,
    /// Whether an admitted fence record exists.
    pub fenced: bool,
}

/// The state the value rules need, folded record by record: the stage table,
/// the running next id, the generation cursor, unanswered boundaries and
/// the latest landing needed to bind a residual choice. No paths and no tree.
#[derive(Debug, Clone)]
pub struct JournalState {
    landed: Option<(u64, [u8; 16], GrainId, u64, bool)>,
    disposition: Option<super::ResidualDisposition>,
    base_seq: u64,
    receipt_generation: u64,
    next_seq: u64,
    next_stage_id: u64,
    last_generation: u64,
    last_prepared_root: Option<GrainId>,
    highest_generation: u64,
    stages: BTreeMap<u64, StageState>,
    open_boundaries: BTreeMap<u64, ([u8; 16], CommitProgress)>,
}

impl JournalState {
    /// The state of an empty journal with this header.
    #[must_use]
    pub fn new(header: &JournalHeader) -> Self {
        Self {
            landed: None,
            disposition: None,
            base_seq: header.base_seq,
            receipt_generation: header.receipt_generation,
            next_seq: 1,
            next_stage_id: header.next_stage_id,
            last_generation: header.receipt_generation,
            last_prepared_root: None,
            highest_generation: header.receipt_generation,
            stages: BTreeMap::new(),
            open_boundaries: BTreeMap::new(),
        }
    }

    /// The terminal choice; its inventory still requires consumer validation.
    #[must_use]
    pub const fn residual_disposition(&self) -> Option<&super::ResidualDisposition> {
        self.disposition.as_ref()
    }

    /// The seq the next record takes.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The id the next stage-introducing record takes.
    #[must_use]
    pub const fn next_stage_id(&self) -> u64 {
        self.next_stage_id
    }

    /// The highest generation in the header's receipt or any record.
    #[must_use]
    pub const fn highest_generation(&self) -> u64 {
        self.highest_generation
    }

    /// What the scan keeps about `stage_id`, if a record bound it.
    #[must_use]
    pub fn stage(&self, stage_id: u64) -> Option<&StageState> {
        self.stages.get(&stage_id)
    }

    /// The seqs of commit boundaries no landed commit has answered.
    pub fn open_boundaries(&self) -> impl Iterator<Item = u64> + '_ {
        self.open_boundaries.keys().copied()
    }

    /// Aggregate admitted evidence for this publication, excluding landed boundaries.
    #[must_use]
    pub fn commit_progress(&self, publication: &[u8; 16]) -> Option<CommitProgress> {
        self.open_boundaries
            .values()
            .filter(|(id, _)| id == publication)
            .fold(None, |total, (_, progress)| {
                let total = total.unwrap_or_default();
                Some(CommitProgress {
                    attempts: total.attempts.saturating_add(progress.attempts),
                    fenced: total.fenced || progress.fenced,
                })
            })
    }

    fn stage_mut(&mut self, stage_id: u64) -> Result<&mut StageState, ValueError> {
        self.stages
            .get_mut(&stage_id)
            .ok_or(ValueError::UnknownStage { stage_id })
    }

    fn new_stage(&mut self, stage_id: u64, size: u64) -> Result<(), ValueError> {
        if stage_id != self.next_stage_id {
            return Err(ValueError::StageIdNotNext {
                expected: self.next_stage_id,
                found: stage_id,
            });
        }
        self.stages.insert(
            stage_id,
            StageState {
                size,
                synced_size: None,
                bound_at: self.next_seq,
            },
        );
        self.next_stage_id = stage_id.saturating_add(1);
        Ok(())
    }

    fn admit_bind(
        &mut self,
        cause: BindCause,
        stage_id: u64,
        staged_size: u64,
    ) -> Result<(), ValueError> {
        match cause {
            BindCause::CopyUp => self.new_stage(stage_id, staged_size),
            BindCause::Rebind => {
                if stage_id >= self.next_stage_id {
                    return Err(ValueError::RebindNotIssued {
                        stage_id,
                        next: self.next_stage_id,
                    });
                }
                self.carry_stage(stage_id, staged_size)
            }
        }
    }

    /// Bind an issued id again without advancing the counter: a re-bind or a
    /// recreate, each of which checks the id was issued first.
    fn carry_stage(&mut self, stage_id: u64, size: u64) -> Result<(), ValueError> {
        if self.stages.contains_key(&stage_id) {
            return Err(ValueError::StageAlreadyBound { stage_id });
        }
        self.stages.insert(
            stage_id,
            StageState {
                size,
                synced_size: None,
                bound_at: self.next_seq,
            },
        );
        Ok(())
    }

    fn admit_generation(
        &mut self,
        generation: u64,
        prepared_root: GrainId,
    ) -> Result<(), ValueError> {
        if generation <= self.receipt_generation {
            return Err(ValueError::GenerationNotAboveReceipt {
                generation,
                receipt: self.receipt_generation,
            });
        }
        if generation < self.last_generation {
            return Err(ValueError::GenerationDecreased {
                generation,
                previous: self.last_generation,
            });
        }
        if generation == self.last_generation && self.last_prepared_root != Some(prepared_root) {
            return Err(ValueError::GenerationRootMismatch { generation });
        }
        self.last_prepared_root = Some(prepared_root);
        self.last_generation = generation;
        self.highest_generation = self.highest_generation.max(generation);
        Ok(())
    }

    /// Apply the value rules for `record` at the next seq and fold it in.
    /// On an error the state is unchanged.
    ///
    /// # Errors
    /// The [`ValueError`] naming the rule the record breaks.
    #[expect(
        clippy::too_many_lines,
        reason = "one atomic record fold keeps cross-record value rules together"
    )]
    pub fn admit(&mut self, record: &Record) -> Result<(), ValueError> {
        let seq = self.next_seq;
        if self.disposition.is_some() {
            return Err(ValueError::AfterResidualDisposition);
        }
        match record {
            Record::ResidualDisposition(choice) => {
                if self.landed
                    != Some((
                        choice.boundary_seq,
                        choice.publication_id,
                        choice.landed_root,
                        choice.landed_seq,
                        true,
                    ))
                    || !self.open_boundaries.is_empty()
                    || choice.source_end.checked_add(1) != Some(seq)
                    || usize::try_from(choice.collision_count)
                        .map_or(true, |count| count > self.stages.len())
                {
                    return Err(ValueError::ResidualSourceMismatch);
                }
                self.disposition = Some(*choice);
            }
            Record::Create { kind, .. } => {
                if let CreateKind::File { stage_id, .. } = kind {
                    self.new_stage(*stage_id, 0)?;
                }
            }
            Record::StageBind {
                cause,
                stage_id,
                staged_size,
                ..
            } => self.admit_bind(*cause, *stage_id, *staged_size)?,
            Record::RecreateFile {
                stage_id, anchor, ..
            } => {
                if *stage_id >= self.next_stage_id {
                    return Err(ValueError::RecreateNotIssued {
                        stage_id: *stage_id,
                        next: self.next_stage_id,
                    });
                }
                self.carry_stage(*stage_id, anchor.map_or(0, |anchor| anchor.size))?;
            }
            Record::WriteExtent {
                stage_id,
                offset,
                length,
                ..
            } => {
                let stage = self.stage_mut(*stage_id)?;
                // The decoder bounded both, so the sum cannot overflow.
                stage.size = stage.size.max(offset.saturating_add(*length));
            }
            Record::Truncate { stage_id, new_size } => {
                self.stage_mut(*stage_id)?.size = *new_size;
            }
            Record::StageRollback {
                stage_id, anchor, ..
            } => {
                self.stage_mut(*stage_id)?.size = anchor.map_or(0, |anchor| anchor.size);
            }
            Record::Delete { kind, .. } => {
                if let DeleteKind::File {
                    stage_id: Some(stage_id),
                } = kind
                {
                    self.stage_mut(*stage_id)?;
                }
            }
            Record::Move { .. } | Record::Replace { .. } | Record::SetattrExec { .. } => {}
            Record::FileSynced {
                stage_id,
                synced_size,
                generation,
                prepared_root,
                ..
            } => {
                let staged_size = self.stage_mut(*stage_id)?.size;
                if *synced_size > staged_size {
                    return Err(ValueError::SyncedExceedsStaged {
                        synced_size: *synced_size,
                        staged_size,
                    });
                }
                self.admit_generation(*generation, *prepared_root)?;
                self.stage_mut(*stage_id)?.synced_size = Some(*synced_size);
            }
            Record::IntentRegistered {
                generation,
                prepared_root,
                cause,
            } => {
                self.admit_generation(*generation, *prepared_root)?;
                if *cause == super::IntentCause::LandedRefresh
                    && let Some((_, _, root, _, refreshed)) = &mut self.landed
                    && root == prepared_root
                {
                    *refreshed = true;
                }
            }
            Record::CommitBoundary {
                through_seq,
                publication_id,
                ..
            }
            | Record::ProjectedBoundary {
                through_seq,
                publication_id,
                ..
            } => {
                if let Record::ProjectedBoundary {
                    selection: Some(selection),
                    ..
                } = record
                {
                    let bound_at = self.stage_mut(selection.stage_id)?.bound_at;
                    if bound_at > *through_seq {
                        return Err(ValueError::SelectionAfterThrough {
                            stage_id: selection.stage_id,
                            bound_at,
                            through_seq: *through_seq,
                        });
                    }
                }
                if let Record::ProjectedBoundary { .. } = record
                    && let Some(&boundary_seq) = self.open_boundaries.keys().next_back()
                    && *through_seq < boundary_seq
                {
                    return Err(ValueError::ThroughBelowOpenBoundary {
                        through_seq: *through_seq,
                        boundary_seq,
                    });
                }
                if *through_seq >= seq {
                    return Err(ValueError::BoundaryThroughNotBelowSeq {
                        through_seq: *through_seq,
                        seq,
                    });
                }
                self.open_boundaries
                    .insert(seq, (*publication_id, CommitProgress::default()));
            }
            Record::CommitAttempt {
                boundary_seq,
                publication_id,
                ..
            }
            | Record::CommitFence {
                boundary_seq,
                publication_id,
            } => {
                let (_, progress) = self
                    .open_boundaries
                    .get_mut(boundary_seq)
                    .filter(|(id, _)| id == publication_id)
                    .ok_or(ValueError::CommitBinding {
                        boundary_seq: *boundary_seq,
                    })?;
                if let Record::CommitAttempt { attempt, .. } = record {
                    if progress.attempts.checked_add(1) != Some(*attempt) {
                        return Err(ValueError::AttemptNotNext {
                            previous: progress.attempts,
                            attempt: *attempt,
                        });
                    }
                    progress.attempts = *attempt;
                } else {
                    progress.fenced = true;
                }
            }
            Record::LandedCommit {
                boundary_seq,
                landed_seq,
                landed_root,
            } => {
                if !self.open_boundaries.contains_key(boundary_seq) {
                    return Err(ValueError::NoOpenBoundary {
                        boundary_seq: *boundary_seq,
                    });
                }
                if *landed_seq <= self.base_seq {
                    return Err(ValueError::LandedSeqNotAboveBase {
                        landed_seq: *landed_seq,
                        base_seq: self.base_seq,
                    });
                }
                if let Some((publication, _)) = self.open_boundaries.remove(boundary_seq) {
                    self.landed =
                        Some((*boundary_seq, publication, *landed_root, *landed_seq, false));
                }
            }
        }
        self.next_seq = seq.saturating_add(1);
        Ok(())
    }
}

/// Why a journal could not be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The header is out of range.
    Header(HeaderError),
    /// Record `index` is malformed.
    Record { index: usize, error: RecordError },
    /// Record `index` breaks a value rule.
    Value { index: usize, error: ValueError },
    /// The journal would exceed the journal bound.
    TooLarge { len: usize },
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header(e) => write!(f, "{e}"),
            Self::Record { index, error } => write!(f, "record {index}: {error}"),
            Self::Value { index, error } => write!(f, "record {index}: {error}"),
            Self::TooLarge { len } => write!(f, "journal of {len} bytes is too large"),
        }
    }
}

impl std::error::Error for EncodeError {}

pub(super) fn record_check(
    header_check: &[u8; CHECK_LEN],
    len: u32,
    kind: u8,
    seq: u64,
    payload: &[u8],
) -> [u8; CHECK_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(RECORD_CONTEXT);
    hasher.update(header_check);
    hasher.update(&len.to_be_bytes());
    hasher.update(&[kind]);
    hasher.update(&seq.to_be_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

/// Recompute the check of a plausibly framed record in place; used by the
/// fuzz probe so mutated bytes reach the payload decoder. Returns the frame's
/// total length, or `None` when `frame` does not start with a bounded frame.
pub(crate) fn refresh_frame_check(
    header_check: &[u8; CHECK_LEN],
    frame: &mut [u8],
) -> Option<usize> {
    let len = u32::from_be_bytes(*frame.first_chunk::<4>()?);
    if !(LEN_MIN..=LEN_MAX).contains(&len) {
        return None;
    }
    let total = 4usize.checked_add(usize::try_from(len).ok()?)?;
    let frame = frame.get_mut(..total)?;
    let (covered, check) = frame.split_last_chunk_mut::<CHECK_LEN>()?;
    let (_, body) = covered.split_first_chunk::<4>()?;
    let (&kind, rest) = body.split_first()?;
    let (seq, payload) = rest.split_first_chunk::<8>()?;
    *check = record_check(header_check, len, kind, u64::from_be_bytes(*seq), payload);
    Some(total)
}

/// One record's frame: `len`, `kind`, `seq`, the payload, and the check.
///
/// # Errors
/// The [`RecordError`] of a malformed record, or
/// [`RecordError::SeqOutOfRange`] for a seq of 0.
pub fn encode_record(
    header: &JournalHeader,
    seq: u64,
    record: &Record,
) -> Result<Vec<u8>, RecordError> {
    if seq == 0 {
        return Err(RecordError::SeqOutOfRange {
            field: "seq",
            value: 0,
        });
    }
    encode_record_checked(&header.check(), seq, record)
}

pub(crate) fn encode_record_checked(
    header_check: &[u8; CHECK_LEN],
    seq: u64,
    record: &Record,
) -> Result<Vec<u8>, RecordError> {
    let payload = record.encode_payload()?;
    let len = u32::try_from(payload.len() + LEN_MIN as usize)
        .map_err(|_| RecordError::PayloadTooLarge { len: payload.len() })?;
    let mut out = Vec::with_capacity(4 + len as usize);
    out.extend_from_slice(&len.to_be_bytes());
    out.push(record.kind());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&payload);
    out.extend_from_slice(&record_check(
        header_check,
        len,
        record.kind(),
        seq,
        &payload,
    ));
    Ok(out)
}

/// A whole journal: the header and every record, framed with seqs from 1.
/// The records go through the same value rules the scan applies.
///
/// # Errors
/// [`EncodeError`] for the first thing the scan would refuse.
pub fn encode_journal(header: &JournalHeader, records: &[Record]) -> Result<Vec<u8>, EncodeError> {
    let mut out = header.encode().map_err(EncodeError::Header)?;
    let header_check = header.check();
    let mut state = JournalState::new(header);
    for (index, record) in records.iter().enumerate() {
        let frame = encode_record_checked(&header_check, state.next_seq(), record)
            .map_err(|error| EncodeError::Record { index, error })?;
        state
            .admit(record)
            .map_err(|error| EncodeError::Value { index, error })?;
        out.extend_from_slice(&frame);
        if out.len() > JOURNAL_MAX {
            return Err(EncodeError::TooLarge { len: out.len() });
        }
    }
    Ok(out)
}

/// Why the scan stopped before the end of the file without a record to
/// believe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TornCause {
    /// Fewer than 4 bytes left for a `len` field.
    ShortLength,
    /// A `len` outside 41..=16425.
    LengthOutOfRange { len: u32 },
    /// A `len` in range but running past the end of the file.
    ShortFrame { len: u32 },
    /// A complete frame whose check does not match.
    BadCheck,
}

/// How a scanned journal ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalEnd {
    /// Every byte after the header is a record that stands.
    Clean,
    /// No journal witness follows the bad frame. This is provisional until
    /// replay checks staging headers, including unnamed files, for synced
    /// recovery evidence. Only then may the writer cut at `valid_len`.
    Torn(TornCause),
}

/// Why the journal must not be read further or repaired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceReason {
    /// The file is above the journal bound.
    TooLarge { len: usize },
    /// The header is short, invalid, or fails a range.
    Header(HeaderError),
    /// A bad frame at the fence offset with a check-valid sync-class frame
    /// at `witness` beyond it: the damage was durable, not a tear.
    MidFileDamage { cause: TornCause, witness: usize },
    /// A check-valid frame of an undefined kind.
    UnknownKind { kind: u8 },
    /// A check-valid frame whose seq skips ahead of the expected one.
    SeqGap { expected: u64, found: u64 },
    /// A check-valid frame whose seq repeats or falls behind the expected one.
    SeqRepeat { expected: u64, found: u64 },
    /// A check-valid frame with an impossible payload.
    Payload(RecordError),
    /// A check-valid record that breaks a value rule.
    Value(ValueError),
}

impl std::fmt::Display for FenceReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { len } => write!(f, "journal of {len} bytes is above its bound"),
            Self::Header(e) => write!(f, "{e}"),
            Self::MidFileDamage { cause, witness } => write!(
                f,
                "journal damage ({cause:?}) precedes a valid sync record at {witness}"
            ),
            Self::UnknownKind { kind } => write!(f, "journal record of unknown kind {kind}"),
            Self::SeqGap { expected, found } => {
                write!(f, "journal seq gap: expected {expected}, found {found}")
            }
            Self::SeqRepeat { expected, found } => {
                write!(f, "journal seq repeat: expected {expected}, found {found}")
            }
            Self::Payload(e) => write!(f, "{e}"),
            Self::Value(e) => write!(f, "{e}"),
        }
    }
}

/// The scan's refusal: where in the file, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fence {
    /// The byte offset of the frame (or of the file, for a header or size
    /// refusal) the fence is about.
    pub offset: usize,
    /// Why.
    pub reason: FenceReason,
}

impl std::fmt::Display for Fence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "journal fenced at byte {}: {}", self.offset, self.reason)
    }
}

impl std::error::Error for Fence {}

/// What a scan returns for a journal that is not fenced.
#[derive(Debug, Clone)]
pub struct JournalScan {
    /// The header.
    pub header: JournalHeader,
    /// The length of the header and every record that stands: where a torn
    /// tail is cut.
    pub valid_len: usize,
    /// Clean, or torn at `valid_len`.
    pub end: JournalEnd,
    /// The state after the last record: stage table, next ids, generations.
    pub state: JournalState,
}

/// Why a scanned journal does not belong with this writer file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriterBindError {
    /// The journal's writer is not the writer file's.
    WriterMismatch,
    /// The journal holds a generation above the writer file's ceiling: the
    /// writer file was rolled back or restored.
    CeilingBelowGeneration { highest: u64, ceiling: u64 },
}

impl std::fmt::Display for WriterBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WriterMismatch => write!(f, "journal names another writer"),
            Self::CeilingBelowGeneration { highest, ceiling } => write!(
                f,
                "journal generation {highest} is above the writer ceiling {ceiling}"
            ),
        }
    }
}

impl std::error::Error for WriterBindError {}

/// Replay's disposition of a custody-checked, decoded staging header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingDisposition {
    /// The valid journal prefix binds this file.
    Named,
    /// Unnamed and without a valid synced mark; eligible for the sweep.
    Sweep,
    /// An unnamed synced mark proves journal damage. Keep all evidence;
    /// refuse replay before cutting a provisional torn tail or sweeping.
    RecoveryEvidence,
}

impl JournalScan {
    /// Classify a staging header before any recovery mutations. The caller
    /// must check custody and decode the header even for an unnamed file.
    ///
    /// # Errors
    /// [`BindingError`] if the writer or canonical filename's id differs.
    pub fn classify_staging(
        &self,
        filename_id: u64,
        header: &StagingHeader,
    ) -> Result<StagingDisposition, BindingError> {
        header.check_binding(&self.header.writer, filename_id)?;
        if self.state.stage(filename_id).is_some() {
            Ok(StagingDisposition::Named)
        } else if matches!(header.mark, MarkState::Present(_)) {
            Ok(StagingDisposition::RecoveryEvidence)
        } else {
            Ok(StagingDisposition::Sweep)
        }
    }

    /// Check the journal against the writer file: the same writer, and every
    /// generation (the receipt's included) at most the ceiling.
    ///
    /// # Errors
    /// [`WriterBindError`] naming which differs.
    pub fn check_writer(&self, writer: &WriterRecord) -> Result<(), WriterBindError> {
        if self.header.writer != writer.writer {
            return Err(WriterBindError::WriterMismatch);
        }
        let highest = self.state.highest_generation();
        if highest > writer.ceiling {
            return Err(WriterBindError::CeilingBelowGeneration {
                highest,
                ceiling: writer.ceiling,
            });
        }
        Ok(())
    }
}

enum Frame {
    /// A believable frame: its total length and its record.
    Record(usize, Record),
    /// A frame that cannot be believed yet: a tear unless a witness follows.
    Torn(TornCause),
    /// A check-valid frame that is impossible.
    Impossible(FenceReason),
}

fn read_frame(header_check: &[u8; CHECK_LEN], rest: &[u8], expected_seq: u64) -> Frame {
    let Some(len_bytes) = rest.first_chunk::<4>() else {
        return Frame::Torn(TornCause::ShortLength);
    };
    let len = u32::from_be_bytes(*len_bytes);
    if !(LEN_MIN..=LEN_MAX).contains(&len) {
        return Frame::Torn(TornCause::LengthOutOfRange { len });
    }
    let Some(total) = usize::try_from(len).ok().and_then(|len| len.checked_add(4)) else {
        return Frame::Torn(TornCause::LengthOutOfRange { len });
    };
    let Some(frame) = rest.get(..total) else {
        return Frame::Torn(TornCause::ShortFrame { len });
    };
    let parts = frame.split_first_chunk::<4>().and_then(|(_, body)| {
        let (body, check) = body.split_last_chunk::<CHECK_LEN>()?;
        let (&kind, rest) = body.split_first()?;
        let (seq, payload) = rest.split_first_chunk::<8>()?;
        Some((kind, u64::from_be_bytes(*seq), payload, check))
    });
    let Some((kind, seq, payload, check)) = parts else {
        return Frame::Torn(TornCause::ShortFrame { len });
    };
    if *check != record_check(header_check, len, kind, seq, payload) {
        return Frame::Torn(TornCause::BadCheck);
    }
    if seq != expected_seq {
        return Frame::Impossible(if seq > expected_seq {
            FenceReason::SeqGap {
                expected: expected_seq,
                found: seq,
            }
        } else {
            FenceReason::SeqRepeat {
                expected: expected_seq,
                found: seq,
            }
        });
    }
    match Record::decode_payload(kind, payload) {
        Ok(record) => Frame::Record(total, record),
        Err(RecordError::UnknownKind { kind }) => {
            Frame::Impossible(FenceReason::UnknownKind { kind })
        }
        Err(e) => Frame::Impossible(FenceReason::Payload(e)),
    }
}

/// Whether `rest` starts with a check-valid sync-class frame whose seq is
/// above `last_good_seq`: proof that every byte before it was durable when it
/// was appended. A candidate is rejected by its `len` (exactly the kind's
/// fixed length), its registered kind and its seq before a hash is spent on
/// it. Payload semantics deliberately do not weaken this evidence: even an
/// impossible check-valid sync frame must fence a hole before it.
fn is_witness(header_check: &[u8; CHECK_LEN], rest: &[u8], last_good_seq: u64) -> bool {
    let Some(&kind) = rest.get(4) else {
        return false;
    };
    if !is_sync_class_kind(kind) {
        return false;
    }
    let Some(payload_len) = sync_payload_len(kind) else {
        return false;
    };
    let Some(len_bytes) = rest.first_chunk::<4>() else {
        return false;
    };
    let len = u32::from_be_bytes(*len_bytes);
    let Some(total) = payload_len.checked_add(LEN_MIN as usize + 4) else {
        return false;
    };
    if usize::try_from(len).ok() != total.checked_sub(4) {
        return false;
    }
    let Some(frame) = rest.get(..total) else {
        return false;
    };
    let Some(seq) = frame
        .get(5..)
        .and_then(|r| r.first_chunk::<8>())
        .map(|s| u64::from_be_bytes(*s))
    else {
        return false;
    };
    if seq <= last_good_seq {
        return false;
    }
    let Some((covered, check)) = frame.split_last_chunk::<CHECK_LEN>() else {
        return false;
    };
    let payload = covered.get(13..).unwrap_or(&[]);
    *check == record_check(header_check, len, kind, seq, payload)
}

fn find_witness(
    header_check: &[u8; CHECK_LEN],
    bytes: &[u8],
    from: usize,
    last_good_seq: u64,
) -> Option<usize> {
    (from..bytes.len()).find(|&p| {
        bytes
            .get(p..)
            .is_some_and(|rest| is_witness(header_check, rest, last_good_seq))
    })
}

/// Scan a journal's bytes.
///
/// The header must be valid and the file at most [`JOURNAL_MAX`]; otherwise
/// the result is a [`Fence`] at byte 0. Frames are then read in order while
/// they are bounded, check-valid, gapless and strictly decodable. A frame
/// whose check is valid but which is impossible (an undefined kind, a wrong
/// seq, a bad payload, a broken value rule) is a [`Fence`] at its offset. At
/// the first frame that cannot be believed (short, `len` out of range,
/// running past the end, a bad check), the rest of the file is probed for a
/// check-valid sync-class frame with a later seq: one proves the damage was
/// durable, so the result is a [`Fence`]; none means a tear, and the records
/// that stand have been visited and the provisional cut is `valid_len`.
/// Replay must check staging headers before cutting or sweeping.
///
/// # Errors
/// [`Fence`] as above. A tear is not an error.
pub fn scan_journal(bytes: &[u8]) -> Result<JournalScan, Fence> {
    scan_journal_with(bytes, |_, _| {})
}

/// Scan while visiting each admitted record at its frame seq. The codec
/// retains only the fixed-size stage and boundary state, and drops each
/// record after the visit. The visitor must fold into provisional state:
/// discard its effects on a fence, and inspect staging evidence before
/// applying a torn-tail repair. It must not acknowledge or mutate files.
///
/// # Errors
/// The same [`Fence`] as [`scan_journal`].
pub fn scan_journal_with(
    bytes: &[u8],
    mut visit: impl FnMut(u64, &Record),
) -> Result<JournalScan, Fence> {
    if bytes.len() > JOURNAL_MAX {
        return Err(Fence {
            offset: 0,
            reason: FenceReason::TooLarge { len: bytes.len() },
        });
    }
    let header =
        JournalHeader::decode(bytes.get(..JOURNAL_HEADER_LEN).unwrap_or(bytes)).map_err(|e| {
            Fence {
                offset: 0,
                reason: FenceReason::Header(e),
            }
        })?;
    let header_check = header.check();
    let mut state = JournalState::new(&header);
    let mut offset = JOURNAL_HEADER_LEN;
    loop {
        let rest = bytes.get(offset..).unwrap_or(&[]);
        if rest.is_empty() {
            return Ok(JournalScan {
                header,
                valid_len: offset,
                end: JournalEnd::Clean,
                state,
            });
        }
        match read_frame(&header_check, rest, state.next_seq()) {
            Frame::Record(total, record) => {
                state.admit(&record).map_err(|e| Fence {
                    offset,
                    reason: FenceReason::Value(e),
                })?;
                visit(state.next_seq().saturating_sub(1), &record);
                offset = offset.saturating_add(total);
            }
            Frame::Impossible(reason) => return Err(Fence { offset, reason }),
            Frame::Torn(cause) => {
                let last_good = state.next_seq().saturating_sub(1);
                if let Some(witness) =
                    find_witness(&header_check, bytes, offset.saturating_add(1), last_good)
                {
                    return Err(Fence {
                        offset,
                        reason: FenceReason::MidFileDamage { cause, witness },
                    });
                }
                return Ok(JournalScan {
                    header,
                    valid_len: offset,
                    end: JournalEnd::Torn(cause),
                    state,
                });
            }
        }
    }
}

const _: () = assert!(PAYLOAD_MAX == 16384);
const _: () = assert!(GRAIN_ID_BINARY_LEN == 33);
