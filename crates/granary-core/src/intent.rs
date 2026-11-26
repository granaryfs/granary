// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Writer-intent wire bodies: ownership, grant, registration, release, receipt
//! and readback. A pure codec shared by the client
//! that sends and reads them and the server that reads and sends them. It
//! holds no policy: which status answers which request is the agreement function's
//! classification and the server's record, and a prepared root's signature is
//! checked by a step the caller supplies, because core holds no cryptography.
//!
//! A writer identity names a client store's writing of one volume and lasts as
//! long as the store; an instance token names one process of that store and is
//! used with the authority-issued epoch to fence displaced ownership. Both are 16 opaque bytes.

mod judge;

pub use judge::{
    Disagreement, RESEND_AFTER_TRANSPORT_FAILURE, Refusal, RegisterRequest, ReleaseRequest, Reply,
    Resend, UnknownCause, Verdict, judge_ownership, judge_readback, judge_register, judge_release,
};

use crate::encoding::{Cursor, DecodeError};
use crate::hash::{GRAIN_ID_BINARY_LEN, GrainId};
use crate::root::{self, RootDoc, VolumeName};

/// Registration body magic.
pub const REGISTER_MAGIC: [u8; 8] = *b"GRNINTRG";
/// Release body magic.
pub const RELEASE_MAGIC: [u8; 8] = *b"GRNINTRL";
/// Receipt body magic.
pub const RECEIPT_MAGIC: [u8; 8] = *b"GRNINTRC";
/// Readback body magic.
pub const READBACK_MAGIC: [u8; 8] = *b"GRNINTRB";
/// Ownership request magic.
pub const OWNERSHIP_MAGIC: [u8; 8] = *b"GRNINTOW";
/// Ownership grant magic.
pub const GRANT_MAGIC: [u8; 8] = *b"GRNINTGR";
/// Ownership request media type.
pub const MEDIA_OWNERSHIP: &str = "application/vnd.granary.intent-ownership.v1";
/// Ownership grant media type.
pub const MEDIA_GRANT: &str = "application/vnd.granary.intent-grant.v1";
/// Exact acquire length.
pub const ACQUIRE_BYTES: usize = 10 + 1 + WRITER_LEN + INSTANCE_LEN + 8;
/// Released takeover length.
pub const TAKEOVER_RELEASED_BYTES: usize = 10 + 1 + WRITER_LEN + INSTANCE_LEN + 8 + 8 + 1 + 1;
/// Largest ownership request.
pub const OWNERSHIP_MAX_BYTES: usize = TAKEOVER_RELEASED_BYTES + GRAIN_ID_BINARY_LEN;
/// Released grant length.
pub const GRANT_RELEASED_BYTES: usize = RECEIPT_RELEASED_BYTES + GRAIN_ID_BINARY_LEN;
/// Largest grant.
pub const GRANT_MAX_BYTES: usize = GRANT_RELEASED_BYTES + GRAIN_ID_BINARY_LEN;
/// The wire version of every body.
pub const VERSION: u16 = 1;

/// Media type of the registration request.
pub const MEDIA_REGISTER: &str = "application/vnd.granary.intent-register.v1";
/// Media type of the release request.
pub const MEDIA_RELEASE: &str = "application/vnd.granary.intent-release.v1";
/// Media type of the receipt.
pub const MEDIA_RECEIPT: &str = "application/vnd.granary.intent-receipt.v1";
/// Media type of the readback.
pub const MEDIA_READBACK: &str = "application/vnd.granary.intent-readback.v1";

/// Length of a writer identity.
pub const WRITER_LEN: usize = 16;
/// Length of an instance token.
pub const INSTANCE_LEN: usize = 16;

/// The root format's cap on one prepared root's bytes.
#[expect(
    clippy::cast_possible_truncation,
    reason = "const context has no try_from; the assertion below proves the value survives"
)]
const ROOT_CAP: usize = root::ROOT_MAX_BYTES as usize;
const _: () = assert!(ROOT_CAP as u64 == root::ROOT_MAX_BYTES);

/// Magic, version, writer, epoch, instance and generation: the registration without
/// its root, and the whole release.
pub const ENVELOPE_LEN: usize = 8 + 2 + WRITER_LEN + 8 + INSTANCE_LEN + 8;
/// Largest registration: the envelope and a root at the root format's cap.
pub const REGISTER_MAX_BYTES: usize = ENVELOPE_LEN + ROOT_CAP;
/// Exactly the size of a release.
pub const RELEASE_BYTES: usize = ENVELOPE_LEN;
/// Size of a released receipt.
pub const RECEIPT_RELEASED_BYTES: usize = 8 + 2 + 1 + WRITER_LEN + 8 + INSTANCE_LEN + 8;
/// Size of a live receipt, which also carries the prepared root's id.
pub const RECEIPT_LIVE_BYTES: usize = RECEIPT_RELEASED_BYTES + GRAIN_ID_BINARY_LEN;
/// Largest receipt.
pub const RECEIPT_MAX_BYTES: usize = RECEIPT_LIVE_BYTES;

/// Most live rows one principal holds for one volume, and so the most rows a
/// readback carries.
pub const MAX_LIVE_ROWS: usize = 16;
/// Most rows one principal holds for one volume, live and released together.
pub const MAX_TOTAL_ROWS: usize = 64;
/// Most root bytes a readback carries: the live ceiling at the root cap.
pub const MAX_ROOT_BYTES: usize = MAX_LIVE_ROWS * ROOT_CAP;
/// Readback header: magic, version, principal/volume allocator cursor and count.
pub const READBACK_HEADER_LEN: usize = 8 + 2 + 8 + 2;
/// Readback row overhead: writer, epoch, generation and root length.
pub const READBACK_ROW_OVERHEAD: usize = WRITER_LEN + 8 + 8 + 4;
/// Largest readback.
pub const READBACK_MAX_BYTES: usize =
    READBACK_HEADER_LEN + MAX_LIVE_ROWS * READBACK_ROW_OVERHEAD + MAX_ROOT_BYTES;

const _: () = assert!(REGISTER_MAX_BYTES == 65_594);
const _: () = assert!(RELEASE_BYTES == 58);
const _: () = assert!(RECEIPT_RELEASED_BYTES == 59);
const _: () = assert!(RECEIPT_MAX_BYTES == 92);
const _: () = assert!(MAX_ROOT_BYTES == 1_048_576);
const _: () = assert!(READBACK_MAX_BYTES == 1_049_172);

/// How long a conforming client keeps resending a registration or release
/// unchanged before it stops and surfaces the unknown outcome: 24 hours.
pub const RETRANSMIT_HORIZON_SECS: u64 = 24 * 60 * 60;

/// How long a released row is kept before the server may evict it, given the
/// configured grace period of the collector: the longer of the grace and the
/// retransmit horizon without a successful mutation. Refusals/replays do not
/// renew age. Absence refuses delayed mutation; eviction never resets H.
#[must_use]
pub const fn released_row_retention_secs(grace_secs: u64) -> u64 {
    if grace_secs < RETRANSMIT_HORIZON_SECS {
        RETRANSMIT_HORIZON_SECS
    } else {
        grace_secs
    }
}

/// A strict decode or encode refusal. Each variant is one named rule of the
/// format and has one stable [`name`](Error::name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The body is longer than its kind's maximum.
    OverBound,
    /// Fewer than eight bytes: no magic to compare.
    ShortInput,
    /// The magic is not this body's.
    BadMagic,
    /// A version other than 1.
    UnknownVersion(u16),
    /// A field's bytes are not all present.
    Truncated,
    /// Bytes follow the last field.
    TrailingBytes,
    /// A generation of 0, which means no generation.
    GenerationZero,
    /// A generation of `u64::MAX`, which would have no successor.
    GenerationMax,
    /// Epoch zero is never ownership.
    EpochZero,
    /// A live readback epoch exceeds its allocator cursor.
    EpochPastCursor,
    /// Invalid ownership mode.
    BadOwnershipMode(u8),
    /// Recovery acknowledgement is neither zero nor one.
    BadRecoveryAck(u8),
    /// Zero in a live snapshot, or MAX in any snapshot.
    BadSnapshotGeneration,
    /// A receipt state other than live or released.
    BadState(u8),
    /// A grain id whose algorithm tag is not registered.
    BadGrainIdTag,
    /// A prepared root that is not a strictly valid root v1.
    RootInvalid(DecodeError),
    /// A readback row's root longer than the root cap.
    RootTooLong,
    /// A prepared root of no bytes.
    RootEmpty,
    /// A readback declaring more rows than the ceiling.
    CountOverCeiling,
    /// A readback that ends cleanly before its declared rows.
    CountMismatch,
    /// A readback row ordered before the one above it.
    RowsUnsorted,
    /// A readback row for the writer of the one above it.
    RowsDuplicate,
    /// A prepared root naming another volume than the requested one.
    RootWrongVolume,
    /// A prepared root the caller's signature step refused.
    RootBadSignature,
}

impl Error {
    /// The stable refusal name used by the reject vectors.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::OverBound => "over-bound",
            Self::ShortInput => "short-input",
            Self::BadMagic => "bad-magic",
            Self::UnknownVersion(_) => "unknown-version",
            Self::Truncated => "truncated",
            Self::TrailingBytes => "trailing-bytes",
            Self::GenerationZero => "generation-zero",
            Self::GenerationMax => "generation-max",
            Self::EpochZero => "epoch-zero",
            Self::EpochPastCursor => "epoch-past-cursor",
            Self::BadOwnershipMode(_) => "bad-ownership-mode",
            Self::BadRecoveryAck(_) => "bad-recovery-ack",
            Self::BadSnapshotGeneration => "bad-snapshot-generation",
            Self::BadState(_) => "bad-state",
            Self::BadGrainIdTag => "bad-grain-id-tag",
            Self::RootInvalid(_) => "root-invalid",
            Self::RootTooLong => "root-too-long",
            Self::RootEmpty => "root-empty",
            Self::CountOverCeiling => "count-over-ceiling",
            Self::CountMismatch => "count-mismatch",
            Self::RowsUnsorted => "rows-unsorted",
            Self::RowsDuplicate => "rows-duplicate",
            Self::RootWrongVolume => "root-wrong-volume",
            Self::RootBadSignature => "root-bad-signature",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownVersion(v) => write!(f, "intent body: unknown version {v}"),
            Self::BadState(s) => write!(f, "intent body: bad receipt state 0x{s:02x}"),
            Self::RootInvalid(e) => write!(f, "intent body: root-invalid: {e}"),
            other => write!(f, "intent body: {}", other.name()),
        }
    }
}

impl std::error::Error for Error {}

/// The checked ceiling on generation: `1..=u64::MAX - 1`.
fn generation_ok(generation: u64) -> Result<u64, Error> {
    match generation {
        0 => Err(Error::GenerationZero),
        u64::MAX => Err(Error::GenerationMax),
        g => Ok(g),
    }
}

fn epoch_ok(epoch: u64) -> Result<u64, Error> {
    if epoch == 0 {
        Err(Error::EpochZero)
    } else {
        Ok(epoch)
    }
}

fn snapshot_generation(generation: u64, live: bool) -> Result<u64, Error> {
    if generation == u64::MAX || (live && generation == 0) {
        Err(Error::BadSnapshotGeneration)
    } else {
        Ok(generation)
    }
}

/// A cursor read can fail only by running out of bytes.
fn short(_: DecodeError) -> Error {
    Error::Truncated
}

fn array_of<const N: usize>(c: &mut Cursor<'_>) -> Result<[u8; N], Error> {
    c.take(N)
        .map_err(short)?
        .try_into()
        .map_err(|_| Error::Truncated)
}

/// Bound, magic and version, in that order; the cursor is left on the first
/// field. `max` is the kind's largest body.
fn open(bytes: &[u8], magic: [u8; 8], max: usize) -> Result<Cursor<'_>, Error> {
    if bytes.len() > max {
        return Err(Error::OverBound);
    }
    if bytes.len() < magic.len() {
        return Err(Error::ShortInput);
    }
    let mut c = Cursor::new(bytes);
    if c.take(magic.len()).map_err(short)? != magic.as_slice() {
        return Err(Error::BadMagic);
    }
    let version = c.u16().map_err(short)?;
    if version != VERSION {
        return Err(Error::UnknownVersion(version));
    }
    Ok(c)
}

fn finish(c: Cursor<'_>) -> Result<(), Error> {
    c.finish().map_err(|_| Error::TrailingBytes)
}

/// One signature slot of a root v1: key id, algorithm, length, signature.
const SIG_SLOT_LEN: usize = root::KEY_ID_LEN + 1 + 2 + root::ED25519_SIG_LEN;

/// A prepared root that passed the rules it meets with no request in hand:
/// not empty, within the root cap, a strictly valid root v1 that consumes
/// every byte. It keeps the signed prefix of the exact received bytes, which
/// is what the caller's signature step is handed.
struct ShapedRoot<'a> {
    doc: RootDoc,
    prefix: &'a [u8],
}

/// The shape rules, with the header decoded once. A root that decoded ends in
/// exactly its signature count of slots, so the prefix is what precedes them.
fn root_shape(root: &[u8]) -> Result<ShapedRoot<'_>, Error> {
    if root.is_empty() {
        return Err(Error::RootEmpty);
    }
    if root.len() > ROOT_CAP {
        return Err(Error::RootTooLong);
    }
    let doc = root::decode_root(root).map_err(Error::RootInvalid)?;
    let prefix = doc
        .sigs
        .len()
        .checked_mul(SIG_SLOT_LEN)
        .and_then(|slots| slots.checked_add(1))
        .and_then(|tail| root.len().checked_sub(tail))
        .and_then(|boundary| root.get(..boundary))
        .ok_or(Error::RootInvalid(DecodeError::Truncated))?;
    Ok(ShapedRoot { doc, prefix })
}

/// The rule that needs the request: the volume asked for.
fn root_volume(shaped: &ShapedRoot<'_>, volume: &VolumeName) -> Result<(), Error> {
    if shaped.doc.volume == *volume {
        Ok(())
    } else {
        Err(Error::RootWrongVolume)
    }
}

/// The caller's signature step over a decoded root and its signed prefix.
fn root_signature(
    shaped: &ShapedRoot<'_>,
    verify: &mut impl FnMut(&RootDoc, &[u8]) -> bool,
) -> Result<(), Error> {
    if verify(&shaped.doc, shaped.prefix) {
        Ok(())
    } else {
        Err(Error::RootBadSignature)
    }
}

/// A decoded registration: the writer, the instance, the generation and the
/// prepared root's exact bytes, borrowed from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration<'a> {
    /// The writer identity.
    pub writer: [u8; WRITER_LEN],
    /// Authority-issued ownership epoch (distinct from the publication epoch).
    pub epoch: u64,
    /// The instance token of the sending process.
    pub instance: [u8; INSTANCE_LEN],
    /// The generation, in `1..=u64::MAX - 1`.
    pub generation: u64,
    /// The prepared root's exact bytes.
    pub root: &'a [u8],
}

impl Registration<'_> {
    /// The prepared root's id: the `GrainId` of its exact bytes.
    #[must_use]
    pub fn root_id(&self) -> GrainId {
        GrainId::of(self.root)
    }
}

/// Decode a registration. The prepared root must be a strictly valid root v1
/// naming `volume`, and `verify` must accept it; `verify` is handed the
/// decoded root and the signed prefix of the received bytes.
///
/// # Errors
/// Refuses a body over [`REGISTER_MAX_BYTES`], short or foreign magic, another
/// version; then, in field order, truncation, epoch 0, generation 0 or
/// `u64::MAX`; then an empty or invalid root v1 (including trailing bytes),
/// a root for another volume, and a root `verify` refuses.
pub fn decode_register<'a>(
    bytes: &'a [u8],
    volume: &VolumeName,
    mut verify: impl FnMut(&RootDoc, &[u8]) -> bool,
) -> Result<Registration<'a>, Error> {
    let mut c = open(bytes, REGISTER_MAGIC, REGISTER_MAX_BYTES)?;
    let writer = array_of(&mut c)?;
    let epoch = epoch_ok(c.u64().map_err(short)?)?;
    let instance = array_of(&mut c)?;
    let generation = generation_ok(c.u64().map_err(short)?)?;
    let root = c.take(c.remaining()).map_err(short)?;
    let shaped = root_shape(root)?;
    root_volume(&shaped, volume)?;
    root_signature(&shaped, &mut verify)?;
    Ok(Registration {
        writer,
        epoch,
        instance,
        generation,
        root,
    })
}

fn put_envelope(
    out: &mut Vec<u8>,
    magic: [u8; 8],
    writer: &[u8; WRITER_LEN],
    epoch: u64,
    instance: &[u8; INSTANCE_LEN],
    generation: u64,
) {
    out.extend_from_slice(&magic);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(writer);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(instance);
    out.extend_from_slice(&generation.to_be_bytes());
}

/// Encode a registration. The root must pass the shape rules the decoder
/// applies without a request: not empty, within the cap, a strictly valid
/// root v1. The volume and the signature are the decoder's and its caller's.
///
/// # Errors
/// Refuses epoch 0, generation 0 or `u64::MAX`, and an empty, over-long or
/// invalid root v1. Does not check the volume or signature.
pub fn encode_register(
    writer: &[u8; WRITER_LEN],
    epoch: u64,
    instance: &[u8; INSTANCE_LEN],
    generation: u64,
    root: &[u8],
) -> Result<Vec<u8>, Error> {
    epoch_ok(epoch)?;
    generation_ok(generation)?;
    root_shape(root)?;
    let mut out = Vec::with_capacity(ENVELOPE_LEN.saturating_add(root.len()));
    put_envelope(
        &mut out,
        REGISTER_MAGIC,
        writer,
        epoch,
        instance,
        generation,
    );
    out.extend_from_slice(root);
    Ok(out)
}

/// A decoded release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Release {
    /// The writer identity.
    pub writer: [u8; WRITER_LEN],
    /// Authority-issued ownership epoch (distinct from the publication epoch).
    pub epoch: u64,
    /// The instance token of the sending process.
    pub instance: [u8; INSTANCE_LEN],
    /// The generation released, in `1..=u64::MAX - 1`: everything at or below
    /// it.
    pub generation: u64,
}

/// Decode a release: exactly [`RELEASE_BYTES`].
///
/// # Errors
/// Refuses a body over the size, a short or foreign magic, another version,
/// a truncated field, epoch 0, generation 0 or `u64::MAX`, and trailing bytes.
pub fn decode_release(bytes: &[u8]) -> Result<Release, Error> {
    let mut c = open(bytes, RELEASE_MAGIC, RELEASE_BYTES)?;
    let writer = array_of(&mut c)?;
    let epoch = epoch_ok(c.u64().map_err(short)?)?;
    let instance = array_of(&mut c)?;
    let generation = generation_ok(c.u64().map_err(short)?)?;
    finish(c)?;
    Ok(Release {
        writer,
        epoch,
        instance,
        generation,
    })
}

/// Encode a release.
///
/// # Errors
/// Refuses epoch 0, generation 0 and `u64::MAX`.
pub fn encode_release(release: Release) -> Result<Vec<u8>, Error> {
    epoch_ok(release.epoch)?;
    generation_ok(release.generation)?;
    let mut out = Vec::with_capacity(RELEASE_BYTES);
    put_envelope(
        &mut out,
        RELEASE_MAGIC,
        &release.writer,
        release.epoch,
        &release.instance,
        release.generation,
    );
    Ok(out)
}

/// What a receipt reports about its row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptState {
    /// A live row, with the id of its prepared root (state 0x01).
    Live {
        /// The `GrainId` of the recorded prepared root's exact bytes.
        prepared_root_id: GrainId,
    },
    /// A released row (state 0x02).
    Released,
}

/// A decoded receipt. It reports a row's recorded generation, state and
/// current ownership epoch and instance token; the registered and already-registered answers are
/// the same bytes by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    /// The writer identity.
    pub writer: [u8; WRITER_LEN],
    /// Authority-issued ownership epoch.
    pub epoch: u64,
    /// The row's current instance token.
    pub instance: [u8; INSTANCE_LEN],
    /// Recorded generation, zero only when released, never `u64::MAX`.
    pub generation: u64,
    /// Live with the root id, or released.
    pub state: ReceiptState,
}

/// Decode a receipt. It knows no status: whether this receipt fits an answer
/// is the agreement function's check ([`judge_register`]).
///
/// # Errors
/// Refuses a body over [`RECEIPT_MAX_BYTES`], a short or foreign magic,
/// another version, a truncated field, a state other than 0x01 and 0x02, epoch 0,
/// live generation 0 or any `u64::MAX`, an unregistered grain id tag, and trailing
/// bytes (a released receipt carries no root id).
pub fn decode_receipt(bytes: &[u8]) -> Result<Receipt, Error> {
    let mut c = open(bytes, RECEIPT_MAGIC, RECEIPT_MAX_BYTES)?;
    let receipt = take_receipt_fields(&mut c)?;
    finish(c)?;
    Ok(receipt)
}

/// Encode a receipt.
///
/// # Errors
/// Refuses zero epochs, live generation 0 and any generation `u64::MAX`.
pub fn encode_receipt(receipt: Receipt) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(RECEIPT_MAX_BYTES);
    out.extend_from_slice(&RECEIPT_MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    put_receipt_fields(&mut out, receipt)?;
    Ok(out)
}

/// One live row of a readback. The row's instance token is not on the wire:
/// a recovering instance takes the row over under a token of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadbackRow<'a> {
    /// The writer identity.
    pub writer: [u8; WRITER_LEN],
    /// Authority-issued ownership epoch.
    pub epoch: u64,
    /// The recorded generation, in `1..=u64::MAX - 1`.
    pub generation: u64,
    /// The prepared root's exact bytes.
    pub root: &'a [u8],
}

impl ReadbackRow<'_> {
    /// The prepared root's id: the `GrainId` of its exact bytes.
    #[must_use]
    pub fn root_id(&self) -> GrainId {
        GrainId::of(self.root)
    }
}

/// A decoded readback: the requesting principal's live rows, ascending by
/// writer. An empty readback is a success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readback<'a> {
    /// Durable allocator high-water for the requesting principal and volume.
    pub cursor: u64,
    /// The rows, strictly ascending by writer.
    pub rows: Vec<ReadbackRow<'a>>,
}

/// Decode a readback for `volume`. Every row's root must be a strictly valid
/// root v1 naming `volume`, and `verify` must accept every one; the body is
/// accepted whole or not at all.
///
/// # Errors
/// Refuses, in this order, a body over [`READBACK_MAX_BYTES`], a short or
/// foreign magic, another version, a truncated cursor/count, a count over
/// [`MAX_LIVE_ROWS`]; then row by row in byte order a writer not above its predecessor (equal is a duplicate),
/// a truncated field, epoch 0 or above the cursor, generation 0 or `u64::MAX`,
/// an empty or over-long root, a root that is not root v1, a root for another volume; then a body that
/// ends cleanly before its count or carries bytes after it; and last the
/// first row `verify` refuses.
pub fn decode_readback<'a>(
    bytes: &'a [u8],
    volume: &VolumeName,
    mut verify: impl FnMut(&RootDoc, &[u8]) -> bool,
) -> Result<Readback<'a>, Error> {
    let mut c = open(bytes, READBACK_MAGIC, READBACK_MAX_BYTES)?;
    let cursor = c.u64().map_err(short)?;
    let count = usize::from(c.u16().map_err(short)?);
    if count > MAX_LIVE_ROWS {
        return Err(Error::CountOverCeiling);
    }
    // `count` is at most MAX_LIVE_ROWS here, so these allocate at most that
    // many slots.
    let mut rows: Vec<ReadbackRow<'a>> = Vec::with_capacity(count);
    let mut shaped: Vec<ShapedRoot<'a>> = Vec::with_capacity(count);
    for _ in 0..count {
        if c.remaining() == 0 {
            return Err(Error::CountMismatch);
        }
        let writer: [u8; WRITER_LEN] = array_of(&mut c)?;
        if let Some(previous) = rows.last() {
            match writer.cmp(&previous.writer) {
                std::cmp::Ordering::Greater => {}
                std::cmp::Ordering::Equal => return Err(Error::RowsDuplicate),
                std::cmp::Ordering::Less => return Err(Error::RowsUnsorted),
            }
        }
        let epoch = epoch_ok(c.u64().map_err(short)?)?;
        if epoch > cursor {
            return Err(Error::EpochPastCursor);
        }
        let generation = generation_ok(c.u64().map_err(short)?)?;
        let root_len = usize::try_from(c.u32().map_err(short)?).map_err(|_| Error::RootTooLong)?;
        if root_len > ROOT_CAP {
            return Err(Error::RootTooLong);
        }
        let root = c.take(root_len).map_err(short)?;
        let row_root = root_shape(root)?;
        root_volume(&row_root, volume)?;
        rows.push(ReadbackRow {
            writer,
            epoch,
            generation,
            root,
        });
        shaped.push(row_root);
    }
    finish(c)?;
    for row_root in &shaped {
        root_signature(row_root, &mut verify)?;
    }
    Ok(Readback { cursor, rows })
}

/// Encode a readback from rows already ascending by writer. Each root must
/// pass the shape rules the decoder applies without a request; the volume and
/// the signature are the decoder's and its caller's.
///
/// # Errors
/// Refuses more than [`MAX_LIVE_ROWS`] rows, rows not strictly ascending,
/// epoch 0 or above the cursor, generation 0 or `u64::MAX`, and an empty,
/// over-long or invalid root.
pub fn encode_readback(cursor: u64, rows: &[ReadbackRow<'_>]) -> Result<Vec<u8>, Error> {
    if rows.len() > MAX_LIVE_ROWS {
        return Err(Error::CountOverCeiling);
    }
    let count = u16::try_from(rows.len()).map_err(|_| Error::CountOverCeiling)?;
    let mut out = Vec::new();
    out.extend_from_slice(&READBACK_MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&cursor.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    let mut previous: Option<&[u8; WRITER_LEN]> = None;
    for row in rows {
        if let Some(previous) = previous {
            match row.writer.cmp(previous) {
                std::cmp::Ordering::Greater => {}
                std::cmp::Ordering::Equal => return Err(Error::RowsDuplicate),
                std::cmp::Ordering::Less => return Err(Error::RowsUnsorted),
            }
        }
        previous = Some(&row.writer);
        epoch_ok(row.epoch)?;
        if row.epoch > cursor {
            return Err(Error::EpochPastCursor);
        }
        generation_ok(row.generation)?;
        root_shape(row.root)?;
        let root_len = u32::try_from(row.root.len()).map_err(|_| Error::RootTooLong)?;
        out.extend_from_slice(&row.writer);
        out.extend_from_slice(&row.epoch.to_be_bytes());
        out.extend_from_slice(&row.generation.to_be_bytes());
        out.extend_from_slice(&root_len.to_be_bytes());
        out.extend_from_slice(row.root);
    }
    Ok(out)
}

/// Acquisition or a conditional transfer of an existing record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipMode {
    /// Requires absence and the observed principal/volume allocator cursor.
    Acquire {
        /// Cursor read in the same snapshot as absence.
        observed_cursor: u64,
    },
    /// Compares every selected field atomically and preserves exact root bytes.
    Takeover {
        /// Selected ownership epoch.
        expected_epoch: u64,
        /// Selected generation (zero only when released).
        generation: u64,
        /// Selected state and root identity.
        state: ReceiptState,
        /// Client consent bound to this selection; server only checks its encoding.
        recovery_ack: bool,
    },
}

/// Exact ownership request identity; persist its encoded bytes before sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ownership {
    /// Store-stable writer identity.
    pub writer: [u8; WRITER_LEN],
    /// New process token.
    pub instance: [u8; INSTANCE_LEN],
    /// Acquisition or selected transfer.
    pub mode: OwnershipMode,
}

fn take_state(c: &mut Cursor<'_>) -> Result<u8, Error> {
    let state = c.u8().map_err(short)?;
    if state == 1 || state == 2 {
        Ok(state)
    } else {
        Err(Error::BadState(state))
    }
}
fn take_root_id(c: &mut Cursor<'_>, state: u8) -> Result<ReceiptState, Error> {
    if state == 1 {
        let bytes = c.take(GRAIN_ID_BINARY_LEN).map_err(short)?;
        Ok(ReceiptState::Live {
            prepared_root_id: GrainId::from_bytes(bytes).map_err(|_| Error::BadGrainIdTag)?,
        })
    } else {
        Ok(ReceiptState::Released)
    }
}
fn put_state(out: &mut Vec<u8>, state: ReceiptState) {
    out.push(if matches!(state, ReceiptState::Live { .. }) {
        1
    } else {
        2
    });
}
fn put_root_id(out: &mut Vec<u8>, state: ReceiptState) {
    if let ReceiptState::Live { prepared_root_id } = state {
        out.extend_from_slice(&prepared_root_id.to_bytes());
    }
}

// Receipt and grant carry the same snapshot field layout after their prefixes.
fn take_receipt_fields(c: &mut Cursor<'_>) -> Result<Receipt, Error> {
    let state = take_state(c)?;
    let writer = array_of(c)?;
    let epoch = epoch_ok(c.u64().map_err(short)?)?;
    let instance = array_of(c)?;
    let generation = snapshot_generation(c.u64().map_err(short)?, state == 1)?;
    let state = take_root_id(c, state)?;
    Ok(Receipt {
        writer,
        epoch,
        instance,
        generation,
        state,
    })
}

fn put_receipt_fields(out: &mut Vec<u8>, rec: Receipt) -> Result<(), Error> {
    epoch_ok(rec.epoch)?;
    snapshot_generation(
        rec.generation,
        matches!(rec.state, ReceiptState::Live { .. }),
    )?;
    put_state(out, rec.state);
    out.extend_from_slice(&rec.writer);
    out.extend_from_slice(&rec.epoch.to_be_bytes());
    out.extend_from_slice(&rec.instance);
    out.extend_from_slice(&rec.generation.to_be_bytes());
    put_root_id(out, rec.state);
    Ok(())
}

/// Decode an ownership request with strict bounds, ranges and exact consumption.
/// # Errors
/// Refuses a body over [`OWNERSHIP_MAX_BYTES`], short or foreign magic, another
/// version, truncated fields, modes other than 1/2, takeover epoch 0, invalid
/// state-coupled generations, invalid states or grain id tags, acknowledgement
/// bytes other than 0/1 and trailing bytes.
pub fn decode_ownership(bytes: &[u8]) -> Result<Ownership, Error> {
    let mut c = open(bytes, OWNERSHIP_MAGIC, OWNERSHIP_MAX_BYTES)?;
    let mode = c.u8().map_err(short)?;
    if mode != 1 && mode != 2 {
        return Err(Error::BadOwnershipMode(mode));
    }
    let writer = array_of(&mut c)?;
    let instance = array_of(&mut c)?;
    let mode = if mode == 1 {
        OwnershipMode::Acquire {
            observed_cursor: c.u64().map_err(short)?,
        }
    } else {
        let expected_epoch = epoch_ok(c.u64().map_err(short)?)?;
        let generation = c.u64().map_err(short)?;
        let state = take_state(&mut c)?;
        snapshot_generation(generation, state == 1)?;
        let state = take_root_id(&mut c, state)?;
        let ack = c.u8().map_err(short)?;
        if ack > 1 {
            return Err(Error::BadRecoveryAck(ack));
        }
        OwnershipMode::Takeover {
            expected_epoch,
            generation,
            state,
            recovery_ack: ack == 1,
        }
    };
    finish(c)?;
    Ok(Ownership {
        writer,
        instance,
        mode,
    })
}

/// Encode the exact acquisition/transfer request.
/// # Errors
/// Refuses zero expected epochs and invalid state-coupled generations.
pub fn encode_ownership(request: Ownership) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(OWNERSHIP_MAX_BYTES);
    out.extend_from_slice(&OWNERSHIP_MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.push(if matches!(request.mode, OwnershipMode::Acquire { .. }) {
        1
    } else {
        2
    });
    out.extend_from_slice(&request.writer);
    out.extend_from_slice(&request.instance);
    match request.mode {
        OwnershipMode::Acquire { observed_cursor } => {
            out.extend_from_slice(&observed_cursor.to_be_bytes());
        }
        OwnershipMode::Takeover {
            expected_epoch,
            generation,
            state,
            recovery_ack,
        } => {
            epoch_ok(expected_epoch)?;
            snapshot_generation(generation, matches!(state, ReceiptState::Live { .. }))?;
            out.extend_from_slice(&expected_epoch.to_be_bytes());
            out.extend_from_slice(&generation.to_be_bytes());
            put_state(&mut out, state);
            put_root_id(&mut out, state);
            out.push(u8::from(recovery_ack));
        }
    }
    Ok(out)
}

/// Historical grant, replayable only while the granted epoch/token remain current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// `GrainId` of the exact request bytes (Q).
    pub request_id: GrainId,
    /// Installed ownership and preserved snapshot; no prepared acknowledgement.
    pub receipt: Receipt,
}

/// Decode a strictly bounded grant.
/// # Errors
/// Refuses a body over [`GRANT_MAX_BYTES`], short or foreign magic, another
/// version, truncation, invalid request/root grain id tags, invalid states,
/// epoch 0, invalid state-coupled generations and trailing bytes.
pub fn decode_grant(bytes: &[u8]) -> Result<Grant, Error> {
    let mut c = open(bytes, GRANT_MAGIC, GRANT_MAX_BYTES)?;
    let request_id = GrainId::from_bytes(c.take(GRAIN_ID_BINARY_LEN).map_err(short)?)
        .map_err(|_| Error::BadGrainIdTag)?;
    let receipt = take_receipt_fields(&mut c)?;
    finish(c)?;
    Ok(Grant {
        request_id,
        receipt,
    })
}

/// Encode a grant in its unique wire layout.
/// # Errors
/// Refuses zero epochs and invalid state-coupled generations.
pub fn encode_grant(grant: Grant) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(GRANT_MAX_BYTES);
    out.extend_from_slice(&GRANT_MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&grant.request_id.to_bytes());
    put_receipt_fields(&mut out, grant.receipt)?;
    Ok(out)
}

#[cfg(test)]
mod tests;
