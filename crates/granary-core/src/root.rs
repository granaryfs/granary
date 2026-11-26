// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Root format v1 — the ONE signed object type.
//!
//!
//! A root is a volume's published state at one sequence number: what
//! the volume is called, which commit produced it, and the three ids a
//! reader needs to mount it. Roots form a numbered chain
//! (`root/{volume}/{seq:020}`, put-if-absent); the chain
//! plus the signatures are the TRUTH about a volume, and the CURRENT
//! hint object is only an accelerator (see [`crate::rootstore`]).
//!
//! Layout (all integers big-endian):
//!
//! ```text
//! envelope (10)      GRANARY\0, type 0x09, version 1
//! volume_name        len u8 1..=63, bytes (DNS-1123 label)
//! seq                u64, >= 1 (0 never valid)
//! parent             presence u8: 0x00 = none | 0x01 + grain_id 33
//!                    (the PARENT ROOT's id; absent iff seq == 1)
//! writer_uuid        16 opaque bytes
//! epoch              u64
//! timestamp          secs i64 + nanos u32   (Unix epoch, UTC; nanos < 1e9; leap seconds ignored)
//! chunker_spec       len u8 1..=255, UTF-8 bytes (algorithm, crate version, min/avg/max, normalization)
//! manifest_root      grain_id 33
//! metadata_root      u8 presence, RESERVED: 0x00 is the ONLY v1
//!                    value (the slot
//!                    exists so metadata trees attach root-side later
//!                    without a manifest break; 0x01+id refused BY
//!                    NAME in v1 — accept-and-ignore would serve a
//!                    tree while silently dropping its metadata, so
//!                    readers ship support before writers emit it,
//!                    the dict_id fleet rule)
//! binmap_index       grain_id 33
//! sheaf_head         grain_id 33
//! ── signature boundary: everything above is the SIGNED PREFIX ──
//! sig_count          u8, 1..=2 (a second signature slot is available)
//! signatures         sig_count × { key_id 32, alg u8, sig_len u16,
//!                                  sig sig_len }
//! ```
//!
//! **The signing domain** (load-bearing): a signature
//! covers the canonical bytes from the FIRST ENVELOPE BYTE through the
//! last byte before the signature section — the type tag is the domain
//! separator (the same cell key later signs trust documents and tally
//! checkpoints, and must never produce a signature valid for two object
//! kinds). Each signature stands INDEPENDENTLY over that identical
//! prefix; no signature ever covers another (otherwise the second slot
//! would be order-dependent and the first signer could not be verified
//! after the second signs). Verification uses [`signed_prefix`] of the
//! RECEIVED bytes — never re-encode-then-verify: `signed_prefix`
//! returns a subslice borrowed FROM the input, which is what makes the
//! rule structural rather than a comment. [`decode_root`] is built on
//! the same header parse, so the boundary the verifier signs over and
//! the boundary the decoder walks past cannot drift apart.
//!
//! **Signature agility**: `alg`/`sig_len` exist so
//! the ML-DSA switch-on spec §11 promises needs no format change
//! (ML-DSA-44 = 2,420 B, ML-DSA-87 = 4,627 B, both inside
//! [`SIG_MAX_LEN`]). v1 accepts `alg = 0x01` (Ed25519) ONLY, refused by
//! name otherwise, with `sig_len` required to be exactly 64.
//!
//! **`chunker_spec`** pins the chunker identity tuple in the PUBLISHED volume, not
//! only in the local-store marker. Byte-equality with the local
//! [`crate::thresh::CHUNKER_SPEC`] rendering is a READ-TIME
//! COMPATIBILITY policy, not format validation: a root written under a
//! future tuple must still DECODE (so a reader can say what it found),
//! and the decision to refuse it belongs to the mount path.

use crate::encoding::{self, Cursor, DecodeError, ObjectType};
use crate::hash::{GRAIN_ID_BINARY_LEN, GrainId};
use crate::sheaf::{push_optional_id, push_timestamp, take_id, take_optional_id, take_timestamp};

pub use crate::sheaf::Timestamp;

/// Max volume-name length: the DNS-1123 label limit.
pub const VOLUME_NAME_MAX: usize = 63;
/// Max `chunker_spec` length in bytes (the u8 length prefix's ceiling).
pub const CHUNKER_SPEC_MAX: usize = 255;
/// TUF-style key id: SHA-256 of the canonical public key.
pub const KEY_ID_LEN: usize = 32;
/// Writer identity carried per publish invocation for fencing.
pub const WRITER_UUID_LEN: usize = 16;
/// The only signature algorithm v1 writes or accepts.
/// Registry tags are never reused or renumbered.
pub const ALG_ED25519: u8 = 0x01;
/// Ed25519 signature length — REQUIRED when `alg == 0x01`.
pub const ED25519_SIG_LEN: usize = 64;
/// Frozen decode cap on one signature's bytes. Sized for the
/// post-quantum switch-on, not for Ed25519.
pub const SIG_MAX_LEN: usize = 8192;
/// Signature slots per root: the second slot is the whole point —
/// algorithm agility protects FUTURE entries, never an append-only
/// history, so the slot ships from v1 even though v1 fills one.
pub const ROOT_MAX_SIGS: u8 = 2;
/// Every signature algorithm a v1 root decoder accepts, with the exact
/// signature length each requires. [`decode_root`] looks an algorithm up
/// here, and [`ROOT_SIG_SLOT_LEN`] is derived from the longest entry, so
/// an algorithm cannot be accepted without moving that bound (and the
/// authority log's tail bound, which is derived from it).
pub const ROOT_V1_ACCEPTED_ALGS: [(u8, usize); 1] = [(ALG_ED25519, ED25519_SIG_LEN)];

/// The longest signature any entry of `algs` requires.
const fn longest_sig_len(mut algs: &[(u8, usize)]) -> usize {
    let mut longest = 0;
    while let [(_, len), rest @ ..] = algs {
        if *len > longest {
            longest = *len;
        }
        algs = rest;
    }
    longest
}

/// A decoded signature is held as `[u8; ED25519_SIG_LEN]`: an accepted
/// algorithm with a longer signature needs [`RootSig`] to change too, and
/// this refuses to build until it does.
const _: () = assert!(longest_sig_len(&ROOT_V1_ACCEPTED_ALGS) == ED25519_SIG_LEN);

/// One v1 signature slot on the wire at its longest: `key_id` + `alg` +
/// `sig_len` + the longest signature an accepted algorithm requires.
pub const ROOT_SIG_SLOT_LEN: usize = KEY_ID_LEN + 1 + 2 + longest_sig_len(&ROOT_V1_ACCEPTED_ALGS);

/// The largest root a v1 ENCODER can actually produce: every field at
/// its cap, `sig_count` at [`ROOT_MAX_SIGS`], and every slot filled
/// at the longest signature an accepted algorithm requires
/// ([`ROOT_SIG_SLOT_LEN`], derived from [`ROOT_V1_ACCEPTED_ALGS`]; today
/// only [`ALG_ED25519`], a 64-byte signature), since `SIG_MAX_LEN`'s
/// headroom is for a future algorithm no v1 decoder accepts yet. `signed prefix 508 + sig_count 1 + 2 ×
/// ROOT_SIG_SLOT_LEN 99 = 707`, measured by
/// `root::tests::a_maximal_v1_root_encodes_inside_the_cap` rather than derived a
/// second time. Unlike [`ROOT_MAX_BYTES`] (a decoder's `DoS` bound sized
/// for algorithm agility), this is what the log format's classifier
/// uses to bound a decision record's candidate: a reader older than the
/// writer refuses a crashed tail it cannot bound rather than discard
/// one it should not.
pub const ROOT_V1_MAX_ENCODABLE: usize =
    ROOT_V1_SIGNED_PREFIX_MAX + 1 + ROOT_MAX_SIGS as usize * ROOT_SIG_SLOT_LEN;

const _: () = assert!(ROOT_V1_MAX_ENCODABLE == 707);

/// The largest root ANY conforming reader accepts. A root encoder MUST
/// stay under it, and this format's own field bounds already guarantee
/// that by construction — the `maximal <= ROOT_MAX_BYTES` assertion
/// below is what proves it, not a separate runtime check in
/// [`encode_root`]. A [`crate::rootstore::RootStore::get_root`]
/// adapter's own read cap is this same constant, which is what lets a
/// refusal for exceeding it mean "not a root this format could have
/// produced" rather than merely "this particular reader declined a
/// large answer".
///
/// The derivation, in the wire order of this module's own layout table:
///
/// ```text
/// envelope            10   MAGIC 8 + type 1 + version 1
/// volume_name         64   u8 length + VOLUME_NAME_MAX 63
/// seq                  8
/// parent              34   presence u8 + GRAIN_ID_BINARY_LEN 33
/// writer_uuid         16   WRITER_UUID_LEN
/// epoch                8
/// timestamp           12   secs i64 + nanos u32
/// chunker_spec       256   u8 length + CHUNKER_SPEC_MAX 255
/// manifest_root       33
/// metadata_root        1   presence only; v1's sole value is absent
/// binmap_index        33
/// sheaf_head          33
///                    ---
/// signed prefix      508
/// sig_count            1
/// signatures      16,454   ROOT_MAX_SIGS 2 × (KEY_ID_LEN 32 + alg 1
///                          + sig_len u16 2 + SIG_MAX_LEN 8,192)
///                    ---
/// maximal root    16,963
/// ```
///
/// **The two signature bounds do not add.** `ROOT_MAX_SIGS` is a COUNT
/// and `SIG_MAX_LEN` is a SIZE, so the section contributes their PRODUCT
/// (plus the per-slot header), which is where the bulk of the total comes
/// from — the signature slots are 97% of a maximal root because they are
/// sized for ML-DSA-87, not for the 64-byte Ed25519 signature v1 writes.
/// A v1 root cannot reach the total at all: with Ed25519 in both slots
/// the maximum ENCODABLE root today is 508 + 1 + 2 × 99 = 707 bytes,
/// MEASURED by `root::tests::a_maximal_v1_root_encodes_inside_the_cap` rather than
/// derived a second time.
///
/// 64 KiB is ~3.9× the maximal root. The headroom is deliberate: this cap
/// is a denial-of-service bound, not a format rule — [`decode_root`] is
/// the authority on what a root may contain, and a cap that tracked the
/// derivation exactly would turn every future field addition into a
/// silent read failure at the store's read cap before the decoder could
/// name it.
///
/// The authority log's own root-field cap
/// ([`crate::authlog::ROOT_BYTES_MAX`]) must stay at or above this cap —
/// a const assertion there checks it — so widening this cap past that
/// log format's own ceiling is also a change to that log format.
///
/// The static assertions below BRACKET that headroom from both sides, and
/// the upper one is not decoration. `>= maximal root` alone pins the
/// FLOOR: it says the cap admits every legal root and nothing about how
/// much more it admits, so this constant could be widened eightfold with
/// every assertion and every test still green (measured). A cap this
/// permissive is what the whole read bound is spending its budget on, so
/// the multiple is stated as a RANGE — no smaller than a maximal root, no
/// larger than 4× one — and any future widening has to argue for itself
/// here rather than pass unnoticed.
pub const ROOT_MAX_BYTES: u64 = 64 * 1024;

/// The signed prefix's length at every field's cap: envelope through
/// `sheaf_head`, before `sig_count` or any signature slot. Built from
/// this module's own field constants, so a widened field bound (a
/// longer `chunker_spec`, a longer volume name) moves this and everything
/// derived from it instead of silently drifting apart from it.
pub(crate) const ROOT_V1_SIGNED_PREFIX_MAX: usize = 10
    + (1 + VOLUME_NAME_MAX)
    + 8
    + (1 + GRAIN_ID_BINARY_LEN)
    + WRITER_UUID_LEN
    + 8
    + 12
    + (1 + CHUNKER_SPEC_MAX)
    + GRAIN_ID_BINARY_LEN
    + 1
    + GRAIN_ID_BINARY_LEN
    + GRAIN_ID_BINARY_LEN;

const _: () = {
    let sigs = ROOT_MAX_SIGS as usize * (KEY_ID_LEN + 1 + 2 + SIG_MAX_LEN);
    let maximal = (ROOT_V1_SIGNED_PREFIX_MAX + 1 + sigs) as u64;
    assert!(ROOT_V1_SIGNED_PREFIX_MAX == 508);
    assert!(maximal == 16_963);
    // The FLOOR: every legal root must be readable.
    assert!(maximal <= ROOT_MAX_BYTES);
    // The CEILING: the documented ~3.9× is what this cap costs, and a
    // widening past 4× is a decision, not a tweak.
    assert!(ROOT_MAX_BYTES <= 4 * maximal);
};

const _: () = {
    // The agility headroom is real, not decorative: ML-DSA-87's 4,627-byte
    // signature must fit the frozen cap.
    assert!(4627 <= SIG_MAX_LEN);
    // sig_len is a u16 on the wire.
    assert!(SIG_MAX_LEN <= u16::MAX as usize);
    assert!(ED25519_SIG_LEN <= SIG_MAX_LEN);
    // The volume name's length prefix is a u8.
    assert!(VOLUME_NAME_MAX <= u8::MAX as usize);
    assert!(CHUNKER_SPEC_MAX <= u8::MAX as usize);
};

/// A validated volume name: a DNS-1123 label — 1..=63 bytes of
/// `[a-z0-9-]`, not starting or ending with `-`. Lowercase ONLY;
/// uppercase is rejected rather than folded, because the name is object-
/// store key material (enforced at key construction) and
/// case folding would make two distinct volumes collide on
/// case-insensitive backends while staying distinct in the signed bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VolumeName(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeNameError {
    Empty,
    TooLong { len: usize },
    BadByte { byte: u8 },
    LeadingDash,
    TrailingDash,
}

impl std::fmt::Display for VolumeNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty volume name"),
            Self::TooLong { len } => {
                write!(f, "volume name is {len} bytes (max {VOLUME_NAME_MAX})")
            }
            Self::BadByte { byte } => {
                write!(f, "volume name byte 0x{byte:02x} (DNS-1123: [a-z0-9-])")
            }
            Self::LeadingDash => write!(f, "volume name starts with '-'"),
            Self::TrailingDash => write!(f, "volume name ends with '-'"),
        }
    }
}

impl std::error::Error for VolumeNameError {}

impl VolumeName {
    /// The label rules, stated ONCE — both constructors and therefore
    /// the decoder share them, so a name the decoder accepts is exactly
    /// a name the writer could have built.
    fn check(raw: &[u8]) -> Result<(), VolumeNameError> {
        if raw.is_empty() {
            return Err(VolumeNameError::Empty);
        }
        if raw.len() > VOLUME_NAME_MAX {
            return Err(VolumeNameError::TooLong { len: raw.len() });
        }
        for &b in raw {
            if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                return Err(VolumeNameError::BadByte { byte: b });
            }
        }
        if raw.first() == Some(&b'-') {
            return Err(VolumeNameError::LeadingDash);
        }
        if raw.last() == Some(&b'-') {
            return Err(VolumeNameError::TrailingDash);
        }
        Ok(())
    }

    /// Validate raw bytes as a DNS-1123 label (the decode path).
    ///
    /// # Errors
    /// The [`VolumeNameError`] naming the violated rule.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, VolumeNameError> {
        Self::check(raw)?;
        // Every accepted byte is ASCII, so this is exact and infallible
        // (no `from_utf8` error path to pretend to handle).
        Ok(Self(raw.iter().copied().map(char::from).collect()))
    }

    /// # Errors
    /// The [`VolumeNameError`] naming the violated rule.
    pub fn new(name: String) -> Result<Self, VolumeNameError> {
        Self::check(name.as_bytes())?;
        Ok(Self(name))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Length as the u8 the wire encoding carries (invariant 1..=63).
    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "invariant: len <= 63 enforced at construction"
    )]
    pub fn wire_len(&self) -> u8 {
        self.0.len() as u8
    }
}

/// Whether `name` falls in the reserved volume-name registry.
///
/// The registry holds exactly two prefixes:
///
/// - **`gran-`** — granary's own namespace. The prefix is `gran-` and
///   not `gran` because names already in use begin with `gran` and must
///   stay constructible.
/// - **`xn--`** — the IDNA A-label marker. It is DNS-1123-legal ASCII
///   that any layer treating a volume name as a hostname label
///   punycode-decodes into a DIFFERENT string, so one name here would
///   not be the same name there.
///
/// **This is admission policy, and it is deliberately NOT part of
/// [`VolumeName`]'s label rules.** Those rules are the format's accept
/// set, shared by both constructors and therefore by the decoder, so a
/// name the decoder accepts is exactly a name the writer could have
/// built; folding a policy list into them would narrow the accept set
/// of a hashed, signature-covered field and make already-signed bytes
/// undecodable. A reserved name must also stay MINTABLE by granary and
/// READABLE by every reader — a decoder that refused `gran-*` could do
/// neither.
///
/// The refusal therefore belongs where a volume is first brought into
/// existence, not where a name is decoded: it bounds who may CREATE a
/// reserved name, never who may read or extend one that already exists.
#[must_use]
pub fn is_reserved_volume_name(name: &VolumeName) -> bool {
    // Private on purpose: a caller that could iterate the registry could
    // write a test that iterates it, and such a test passes over an
    // empty registry while reserving nothing.
    const RESERVED_PREFIXES: [&str; 2] = ["gran-", "xn--"];
    RESERVED_PREFIXES
        .iter()
        .any(|prefix| name.as_str().starts_with(prefix))
}

/// One signature slot. `alg` is implicit in v1 (Ed25519, the only
/// registered value); a future algorithm widens this type, not the
/// format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootSig {
    /// TUF-style key id: SHA-256 of the canonical public key.
    pub key_id: [u8; KEY_ID_LEN],
    /// Ed25519 signature over [`signed_prefix`] of this object.
    pub sig: [u8; ED25519_SIG_LEN],
}

/// A decoded root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootDoc {
    pub volume: VolumeName,
    /// Sequence number; starts at 1, one per publish (0 never valid).
    pub seq: u64,
    /// Previous ROOT's id — `None` iff `seq == 1` (enforced both ways).
    pub parent: Option<GrainId>,
    /// Opaque per-publish-invocation writer identity for fencing.
    pub writer_uuid: [u8; WRITER_UUID_LEN],
    /// v1: `parent.epoch + 1` per publish invocation; the fencing
    /// semantics sharpen in Phase 2. Not format-validated
    /// — a reader cannot see the parent's epoch without fetching it.
    pub epoch: u64,
    pub timestamp: Timestamp,
    /// The chunker identity tuple as rendered by
    /// [`crate::thresh::CHUNKER_SPEC`]'s `Display`.
    pub chunker_spec: String,
    pub manifest_root: GrainId,
    pub binmap_index: GrainId,
    pub sheaf_head: GrainId,
    /// 1..=[`ROOT_MAX_SIGS`] signatures over [`signed_prefix`], each
    /// under a DISTINCT key id.
    pub sigs: Vec<RootSig>,
}

/// Encode error — the canonical encoder refuses every rule the decoder
/// rejects. A `volume` that exists is already
/// valid: [`VolumeName`] is the validation seam, so there is no
/// bad-name variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeRootError {
    SeqZero,
    /// The cross-rule: parent absent ⟺ `seq == 1`.
    ParentSeqMismatch {
        seq: u64,
        has_parent: bool,
    },
    ChunkerSpecLen {
        len: usize,
    },
    NanosOverflow {
        nanos: u32,
    },
    SigCount {
        count: usize,
    },
    DuplicateKeyId,
}

impl std::fmt::Display for EncodeRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SeqZero => write!(f, "root seq starts at 1 (0 is never valid)"),
            Self::ParentSeqMismatch { seq, has_parent } => write!(
                f,
                "seq {seq} with parent {has_parent}: parent is absent if and only if seq == 1"
            ),
            Self::ChunkerSpecLen { len } => {
                write!(f, "chunker_spec is {len} bytes (1..={CHUNKER_SPEC_MAX})")
            }
            Self::NanosOverflow { nanos } => {
                write!(f, "timestamp nanos {nanos} >= 1e9")
            }
            Self::SigCount { count } => {
                write!(f, "{count} signatures (1..={ROOT_MAX_SIGS})")
            }
            Self::DuplicateKeyId => write!(f, "the same key_id in both signature slots"),
        }
    }
}

impl std::error::Error for EncodeRootError {}

/// The signed prefix of `doc`, for the WRITER: exactly the bytes a
/// signer signs, before any signature exists. Byte-for-byte equal to
/// [`signed_prefix`] of [`encode_root`]'s output — guaranteed by
/// construction (`encode_root` starts from this function's result and
/// appends), not by two parallel field lists.
///
/// Returns a `Result` deliberately: an infallible version would hand a
/// signer non-canonical bytes for a document the encoder is about to
/// refuse, and a signature over bytes that never become an object is a
/// silent failure. Refusing early is the encoder-refuses rule applied
/// to the signing path.
///
/// # Errors
/// The [`EncodeRootError`] naming the violated header rule (`sigs` is
/// NOT inspected here — a doc with no signatures yet is exactly the
/// writer's state when it calls this).
pub fn signing_prefix_of(doc: &RootDoc) -> Result<Vec<u8>, EncodeRootError> {
    if doc.seq == 0 {
        return Err(EncodeRootError::SeqZero);
    }
    if (doc.seq == 1) != doc.parent.is_none() {
        return Err(EncodeRootError::ParentSeqMismatch {
            seq: doc.seq,
            has_parent: doc.parent.is_some(),
        });
    }
    if doc.chunker_spec.is_empty() || doc.chunker_spec.len() > CHUNKER_SPEC_MAX {
        return Err(EncodeRootError::ChunkerSpecLen {
            len: doc.chunker_spec.len(),
        });
    }
    if !doc.timestamp.is_valid() {
        return Err(EncodeRootError::NanosOverflow {
            nanos: doc.timestamp.nanos,
        });
    }
    let mut out = encoding::envelope(ObjectType::Root);
    out.push(doc.volume.wire_len());
    out.extend_from_slice(doc.volume.as_str().as_bytes());
    out.extend_from_slice(&doc.seq.to_be_bytes());
    push_optional_id(&mut out, doc.parent.as_ref());
    out.extend_from_slice(&doc.writer_uuid);
    out.extend_from_slice(&doc.epoch.to_be_bytes());
    push_timestamp(&mut out, doc.timestamp);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "chunker_spec.len() <= CHUNKER_SPEC_MAX = 255 checked above"
    )]
    out.push(doc.chunker_spec.len() as u8);
    out.extend_from_slice(doc.chunker_spec.as_bytes());
    out.extend_from_slice(&doc.manifest_root.to_bytes());
    // Reserved metadata-root slot: v1 writes absent, always.
    out.push(0x00);
    out.extend_from_slice(&doc.binmap_index.to_bytes());
    out.extend_from_slice(&doc.sheaf_head.to_bytes());
    Ok(out)
}

/// Encode a root in canonical form.
///
/// # Errors
/// The [`EncodeRootError`] naming the violated rule.
pub fn encode_root(doc: &RootDoc) -> Result<Vec<u8>, EncodeRootError> {
    // The signed prefix IS the head of the object: one code path, so a
    // writer can never sign bytes that differ from what it publishes.
    let mut out = signing_prefix_of(doc)?;
    if doc.sigs.is_empty() || doc.sigs.len() > ROOT_MAX_SIGS as usize {
        return Err(EncodeRootError::SigCount {
            count: doc.sigs.len(),
        });
    }
    // A general scan, not a two-slot comparison: a pairwise check would
    // silently stop covering the rule the day ROOT_MAX_SIGS grows, and
    // the decoder's check IS general — the two must not diverge.
    for (i, s) in doc.sigs.iter().enumerate() {
        if doc.sigs.iter().take(i).any(|prev| prev.key_id == s.key_id) {
            return Err(EncodeRootError::DuplicateKeyId);
        }
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "sigs.len() <= ROOT_MAX_SIGS = 2 checked above"
    )]
    out.push(doc.sigs.len() as u8);
    for s in &doc.sigs {
        out.extend_from_slice(&s.key_id);
        out.push(ALG_ED25519);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "ED25519_SIG_LEN = 64 is a constant far inside u16"
        )]
        out.extend_from_slice(&(ED25519_SIG_LEN as u16).to_be_bytes());
        out.extend_from_slice(&s.sig);
    }
    Ok(out)
}

/// Everything above the signature boundary, decoded once.
struct RootHeader {
    volume: VolumeName,
    seq: u64,
    parent: Option<GrainId>,
    writer_uuid: [u8; WRITER_UUID_LEN],
    epoch: u64,
    timestamp: Timestamp,
    chunker_spec: String,
    manifest_root: GrainId,
    binmap_index: GrainId,
    sheaf_head: GrainId,
}

fn volume_err(e: VolumeNameError) -> DecodeError {
    DecodeError::Invalid {
        what: match e {
            VolumeNameError::Empty => "root volume_name empty",
            VolumeNameError::TooLong { .. } => "root volume_name over 63 bytes",
            VolumeNameError::BadByte { .. } => "root volume_name byte (DNS-1123: [a-z0-9-])",
            VolumeNameError::LeadingDash => "root volume_name leading '-'",
            VolumeNameError::TrailingDash => "root volume_name trailing '-'",
        },
    }
}

/// THE boundary logic. [`signed_prefix`] and [`decode_root`] both go
/// through this function and nothing else, so the signature domain and
/// the decoded object can never disagree about where the header ends —
/// a drifting boundary is a signature-domain break, not a bug you would
/// notice.
fn decode_header(bytes: &[u8]) -> Result<(RootHeader, Cursor<'_>), DecodeError> {
    let (ty, mut c) = encoding::open_envelope(bytes)?;
    if ty != ObjectType::Root {
        return Err(DecodeError::Invalid {
            what: "object type (want root)",
        });
    }
    let name_len = usize::from(c.u8()?);
    let volume = VolumeName::from_bytes(c.take(name_len)?).map_err(volume_err)?;
    let seq = c.u64()?;
    if seq == 0 {
        return Err(DecodeError::Invalid {
            what: "root seq zero",
        });
    }
    let parent = take_optional_id(&mut c, "root parent presence byte", "root parent grain id")?;
    if (seq == 1) != parent.is_none() {
        return Err(DecodeError::Invalid {
            what: "root parent/seq cross-rule (parent absent iff seq == 1)",
        });
    }
    let writer_uuid: [u8; WRITER_UUID_LEN] = c
        .take(WRITER_UUID_LEN)?
        .try_into()
        .map_err(|_| DecodeError::Truncated)?;
    let epoch = c.u64()?;
    let timestamp = take_timestamp(&mut c)?;
    let spec_len = usize::from(c.u8()?);
    if spec_len == 0 {
        return Err(DecodeError::Invalid {
            what: "root chunker_spec empty",
        });
    }
    let chunker_spec = core::str::from_utf8(c.take(spec_len)?)
        .map_err(|_| DecodeError::Invalid {
            what: "root chunker_spec (invalid UTF-8)",
        })?
        .to_owned();
    let manifest_root = take_id(&mut c, "root manifest_root grain id")?;
    let metadata_presence = c.u8()?;
    if metadata_presence != 0x00 {
        return Err(DecodeError::Invalid {
            what: "metadata_root presence (reserved, v1 accepts only 0x00)",
        });
    }
    let binmap_index = take_id(&mut c, "root binmap_index grain id")?;
    let sheaf_head = take_id(&mut c, "root sheaf_head grain id")?;
    Ok((
        RootHeader {
            volume,
            seq,
            parent,
            writer_uuid,
            epoch,
            timestamp,
            chunker_spec,
            manifest_root,
            binmap_index,
            sheaf_head,
        },
        c,
    ))
}

/// The exact bytes every signature on this object covers: `bytes` from
/// its first envelope byte up to (not including) the signature section.
///
/// The return type is a subslice OF THE INPUT — verification therefore
/// operates on the RECEIVED bytes and cannot silently become
/// re-encode-then-verify (a re-encoding implementation has no owned
/// buffer to borrow from and would not compile). Only the header is
/// validated here; use [`decode_root`] for the whole object, including
/// the signature slots themselves.
///
/// # Errors
/// The [`DecodeError`] naming the violated header rule.
pub fn signed_prefix(bytes: &[u8]) -> Result<&[u8], DecodeError> {
    let (_, c) = decode_header(bytes)?;
    let boundary = bytes
        .len()
        .checked_sub(c.remaining())
        .ok_or(DecodeError::Truncated)?;
    bytes.get(..boundary).ok_or(DecodeError::Truncated)
}

/// Decode a root from the full object bytes. Strict: exact length,
/// every registry value named, every cross-rule enforced.
///
/// Signature VERIFICATION is not done here — core holds no crypto.
/// A verifier decodes, then checks each [`RootSig`] against
/// [`signed_prefix`] of the same received bytes.
///
/// # Errors
/// The [`DecodeError`] naming the violated rule.
pub fn decode_root(bytes: &[u8]) -> Result<RootDoc, DecodeError> {
    let (h, mut c) = decode_header(bytes)?;
    let sig_count = c.u8()?;
    if sig_count == 0 {
        return Err(DecodeError::Invalid {
            what: "root sig_count zero",
        });
    }
    if sig_count > ROOT_MAX_SIGS {
        return Err(DecodeError::CapExceeded {
            what: "root sig_count",
            got: u64::from(sig_count),
            cap: u64::from(ROOT_MAX_SIGS),
        });
    }
    // Cap validated above: at most two slots are ever allocated.
    let mut sigs: Vec<RootSig> = Vec::with_capacity(usize::from(sig_count));
    for _ in 0..sig_count {
        let key_id: [u8; KEY_ID_LEN] = c
            .take(KEY_ID_LEN)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        let alg = c.u8()?;
        let Some(&(_, required_len)) = ROOT_V1_ACCEPTED_ALGS.iter().find(|(a, _)| *a == alg) else {
            return Err(DecodeError::Invalid {
                what: "root signature alg (v1 accepts only 0x01 Ed25519)",
            });
        };
        let sig_len = usize::from(c.u16()?);
        // The algorithm pins the length exactly; SIG_MAX_LEN is the
        // frozen headroom a future alg decodes against (it cannot be
        // reached while the table's longest entry is 64).
        if sig_len != required_len {
            return Err(DecodeError::Invalid {
                what: "root signature sig_len (Ed25519 requires 64)",
            });
        }
        let sig: [u8; ED25519_SIG_LEN] = c
            .take(sig_len)?
            .try_into()
            .map_err(|_| DecodeError::Truncated)?;
        if sigs.iter().any(|s| s.key_id == key_id) {
            return Err(DecodeError::Invalid {
                what: "root duplicate signature key_id",
            });
        }
        sigs.push(RootSig { key_id, sig });
    }
    c.finish()?;
    Ok(RootDoc {
        volume: h.volume,
        seq: h.seq,
        parent: h.parent,
        writer_uuid: h.writer_uuid,
        epoch: h.epoch,
        timestamp: h.timestamp,
        chunker_spec: h.chunker_spec,
        manifest_root: h.manifest_root,
        binmap_index: h.binmap_index,
        sheaf_head: h.sheaf_head,
        sigs,
    })
}

/// A stored root failed the identity checks every root gets: strict
/// decode, then the volume and the seq it was stored under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootIdentityError {
    /// The bytes are not a strictly valid root.
    Decode(DecodeError),
    /// The root names another volume than the one it was read from.
    VolumeMismatch {
        /// The volume the caller asked for.
        expected: String,
        /// The volume the root names.
        found: String,
    },
    /// The root carries another seq than the one it was read at.
    SeqMismatch {
        /// The seq the caller asked for.
        expected: u64,
        /// The seq the root carries.
        found: u64,
    },
}

impl std::fmt::Display for RootIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "root does not decode: {e}"),
            Self::VolumeMismatch { expected, found } => {
                write!(f, "root names volume {found}, expected {expected}")
            }
            Self::SeqMismatch { expected, found } => {
                write!(f, "root carries seq {found}, expected {expected}")
            }
        }
    }
}

impl std::error::Error for RootIdentityError {}

/// Decode `bytes` strictly as the root of `volume` at `seq`.
///
/// A signature or a hash link proves which BYTES were committed to, never
/// that those bytes were this volume's root at this seq; this is the
/// check for that. It checks no signature.
///
/// # Errors
/// [`RootIdentityError`] naming the first failed rule, in the order
/// decode, volume, seq.
pub fn decode_expected(bytes: &[u8], volume: &str, seq: u64) -> Result<RootDoc, RootIdentityError> {
    let doc = decode_root(bytes).map_err(RootIdentityError::Decode)?;
    if doc.volume.as_str() != volume {
        return Err(RootIdentityError::VolumeMismatch {
            expected: volume.to_owned(),
            found: doc.volume.as_str().to_owned(),
        });
    }
    if doc.seq != seq {
        return Err(RootIdentityError::SeqMismatch {
            expected: seq,
            found: doc.seq,
        });
    }
    Ok(doc)
}

/// Why [`check_link`] refused an ancestor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// The child's `parent` is not the id of the stored ancestor bytes.
    ParentMismatch {
        /// The id of the bytes actually stored at the ancestor's seq.
        expected: GrainId,
        /// The parent the child names.
        found: Option<GrainId>,
    },
    /// The ancestor's bytes failed the decode, volume or seq check.
    Identity(RootIdentityError),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParentMismatch { expected, found } => match found {
                Some(found) => write!(f, "child names parent {found}, ancestor is {expected}"),
                None => write!(f, "child names no parent, ancestor is {expected}"),
            },
            Self::Identity(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for LinkError {}

/// Check one ancestor against the child that names it: `parent` (the
/// child's `parent` field) is the id of exactly `bytes`, and `bytes`
/// decode strictly as the root of `volume` at `prev`.
///
/// **Checks no signature, and that is sound.** A root's signature covers
/// its `parent` field, which is the id of the stored bytes one seq down,
/// so one verified head authenticates every ancestor transitively,
/// provided each link is this comparison over the STORED ancestor bytes.
/// An ancestor may have been signed by a key the caller does not (or no
/// longer) trust, and refusing it would refuse chains a head-only reader
/// reads. Never hash a re-encoding of the decoded ancestor in its place:
/// that severs the transitive argument while every head signature check
/// stays green.
///
/// The id comparison runs first and is over `bytes` as stored. The walk
/// over seqs, the store reads and what a missing ancestor means all stay
/// with the caller.
///
/// # Errors
/// [`LinkError`]; the parent comparison runs before the decode.
pub fn check_link(
    parent: Option<GrainId>,
    bytes: &[u8],
    volume: &str,
    prev: u64,
) -> Result<RootDoc, LinkError> {
    let expected = GrainId::of(bytes);
    if parent != Some(expected) {
        return Err(LinkError::ParentMismatch {
            expected,
            found: parent,
        });
    }
    decode_expected(bytes, volume, prev).map_err(LinkError::Identity)
}

#[cfg(test)]
mod tests;
