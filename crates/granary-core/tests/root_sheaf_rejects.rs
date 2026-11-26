// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Root and sheaf rejects corpus. Every documented validation rule
//! gets its own red vector asserting the SPECIFIC error.
//!
//!
//!
//!
//! Most of these bodies CANNOT be produced by the encoders (that is the
//! encoder-refuses rule working), so they are hand-built by the raw
//! builders below — the same technique `manifest_rejects.rs` uses. The
//! builders are themselves guarded: [`raw_sheaf_matches_the_encoder`]
//! and [`raw_root_matches_the_encoder`] assert that each builder's
//! UNMODIFIED output is byte-identical to the real encoder's. Without
//! that pin a builder typo would make every red vector below fail for
//! the wrong reason and the corpus would prove nothing.

use granary_core::binfmt;
use granary_core::encoding::{DecodeError, MAGIC, ObjectType, VERSION_V1};
use granary_core::hash::GrainId;
use granary_core::root::{
    CHUNKER_SPEC_MAX, ED25519_SIG_LEN, KEY_ID_LEN, RootDoc, RootSig, VolumeName, VolumeNameError,
    WRITER_UUID_LEN, decode_root, encode_root, signed_prefix,
};
use granary_core::sheaf::{SheafDoc, SheafOp, Timestamp, decode_sheaf, encode_sheaf};
use granary_core::testkit;

const SECS: i64 = 1_760_000_000;
const NANOS: u32 = 123_456_789;
const VOLUME: &[u8] = b"granary-test";

fn gid(s: &str) -> GrainId {
    GrainId::of(s.as_bytes())
}

fn id_bytes(s: &str) -> Vec<u8> {
    gid(s).to_bytes().to_vec()
}

fn fill_n(seed: u64, len: usize) -> Vec<u8> {
    testkit::fill(seed, len)
}

/// A [`RootSig`] built the same way the golden vectors build one — used
/// by the accept-side tests below, which go through the real encoder
/// (`RootDoc`/`encode_root`) rather than the raw byte builders.
fn root_sig(seed: u64) -> RootSig {
    RootSig {
        key_id: fill_n(seed, KEY_ID_LEN)
            .as_slice()
            .try_into()
            .unwrap_or_else(|e| panic!("{e}")),
        sig: fill_n(seed ^ 0xFFFF, ED25519_SIG_LEN)
            .as_slice()
            .try_into()
            .unwrap_or_else(|e| panic!("{e}")),
    }
}

fn invalid(what: &'static str) -> Result<(), DecodeError> {
    Err(DecodeError::Invalid { what })
}

// ======================================================= sheaf builder

struct RawSheaf {
    object_type: ObjectType,
    version: u8,
    /// Presence byte written verbatim; `parent` bytes follow it.
    presence: u8,
    parent: Vec<u8>,
    manifest_root: Vec<u8>,
    secs: i64,
    nanos: u32,
    /// Declared count — deliberately independent of `ops`.
    op_count: u32,
    ops: Vec<u8>,
    trailing: Vec<u8>,
}

impl RawSheaf {
    /// The canonical first-commit sheaf, byte-identical to the encoder's
    /// output (pinned by `raw_sheaf_matches_the_encoder`).
    fn valid() -> Self {
        Self {
            object_type: ObjectType::Sheaf,
            version: VERSION_V1,
            presence: 0x00,
            parent: Vec::new(),
            manifest_root: id_bytes("manifest-root-1"),
            secs: SECS,
            nanos: NANOS,
            op_count: 1,
            ops: vec![0x01],
            trailing: Vec::new(),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.push(self.object_type.tag());
        out.push(self.version);
        out.push(self.presence);
        out.extend_from_slice(&self.parent);
        out.extend_from_slice(&self.manifest_root);
        out.extend_from_slice(&self.secs.to_be_bytes());
        out.extend_from_slice(&self.nanos.to_be_bytes());
        out.extend_from_slice(&self.op_count.to_be_bytes());
        out.extend_from_slice(&self.ops);
        out.extend_from_slice(&self.trailing);
        out
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the expected error is a value at every call site — a reference would only add noise to the vectors"
)]
fn sheaf_rejects(raw: &RawSheaf, want: Result<(), DecodeError>) {
    assert_eq!(decode_sheaf(&raw.bytes()).map(|_| ()), want);
}

// ======================================================== root builder

struct RawSig {
    key_id: Vec<u8>,
    alg: u8,
    sig_len: u16,
    sig: Vec<u8>,
}

impl RawSig {
    fn valid(seed: u64) -> Self {
        Self {
            key_id: fill_n(seed, KEY_ID_LEN),
            alg: 0x01,
            #[expect(
                clippy::cast_possible_truncation,
                reason = "ED25519_SIG_LEN = 64 is a constant far inside u16"
            )]
            sig_len: ED25519_SIG_LEN as u16,
            sig: fill_n(seed ^ 0xFFFF, ED25519_SIG_LEN),
        }
    }
}

struct RawRoot {
    object_type: ObjectType,
    version: u8,
    /// Declared name length — deliberately independent of `volume`.
    volume_len: u8,
    volume: Vec<u8>,
    seq: u64,
    presence: u8,
    parent: Vec<u8>,
    writer_uuid: Vec<u8>,
    epoch: u64,
    secs: i64,
    nanos: u32,
    spec_len: u8,
    spec: Vec<u8>,
    manifest_root: Vec<u8>,
    /// Reserved metadata-root slot: 0x00 is
    /// the only v1 value.
    metadata_presence: u8,
    binmap_index: Vec<u8>,
    sheaf_head: Vec<u8>,
    /// Declared count — deliberately independent of `sigs`.
    sig_count: u8,
    sigs: Vec<RawSig>,
    trailing: Vec<u8>,
}

impl RawRoot {
    /// The canonical seq-1 root, byte-identical to the encoder's output
    /// (pinned by `raw_root_matches_the_encoder`).
    fn valid() -> Self {
        let spec = granary_core::thresh::CHUNKER_SPEC.to_string().into_bytes();
        Self {
            object_type: ObjectType::Root,
            version: VERSION_V1,
            volume_len: u8::try_from(VOLUME.len()).unwrap_or_else(|e| panic!("{e}")),
            volume: VOLUME.to_vec(),
            seq: 1,
            presence: 0x00,
            parent: Vec::new(),
            writer_uuid: vec![0x11; WRITER_UUID_LEN],
            epoch: 1,
            secs: SECS,
            nanos: NANOS,
            spec_len: u8::try_from(spec.len()).unwrap_or_else(|e| panic!("{e}")),
            spec,
            manifest_root: id_bytes("manifest-root-1"),
            metadata_presence: 0x00,
            binmap_index: id_bytes("binmap-index-1"),
            sheaf_head: id_bytes("sheaf-head-1"),
            sig_count: 1,
            sigs: vec![RawSig::valid(1)],
            trailing: Vec::new(),
        }
    }

    /// The canonical seq-2 root: parent present, two signature slots.
    fn valid_seq2() -> Self {
        Self {
            seq: 2,
            presence: 0x01,
            parent: id_bytes("root-seq-1"),
            sig_count: 2,
            sigs: vec![RawSig::valid(1), RawSig::valid(2)],
            ..Self::valid()
        }
    }

    fn with_volume(volume: &[u8]) -> Self {
        Self {
            volume_len: u8::try_from(volume.len()).unwrap_or_else(|e| panic!("{e}")),
            volume: volume.to_vec(),
            ..Self::valid()
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.push(self.object_type.tag());
        out.push(self.version);
        out.push(self.volume_len);
        out.extend_from_slice(&self.volume);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.push(self.presence);
        out.extend_from_slice(&self.parent);
        out.extend_from_slice(&self.writer_uuid);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.secs.to_be_bytes());
        out.extend_from_slice(&self.nanos.to_be_bytes());
        out.push(self.spec_len);
        out.extend_from_slice(&self.spec);
        out.extend_from_slice(&self.manifest_root);
        out.push(self.metadata_presence);
        out.extend_from_slice(&self.binmap_index);
        out.extend_from_slice(&self.sheaf_head);
        out.push(self.sig_count);
        for s in &self.sigs {
            out.extend_from_slice(&s.key_id);
            out.push(s.alg);
            out.extend_from_slice(&s.sig_len.to_be_bytes());
            out.extend_from_slice(&s.sig);
        }
        out.extend_from_slice(&self.trailing);
        out
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the expected error is a value at every call site — a reference would only add noise to the vectors"
)]
fn root_rejects(raw: &RawRoot, want: Result<(), DecodeError>) {
    assert_eq!(decode_root(&raw.bytes()).map(|_| ()), want);
}

/// The reserved metadata-root slot: 0x01 — "present" — is
/// refused in v1 by name. Accept-and-ignore would serve a tree while
/// silently dropping its metadata; readers ship support before any
/// writer emits presence (the `dict_id` fleet rule).
#[test]
fn root_rejects_reserved_metadata_root_presence() {
    root_rejects(
        &RawRoot {
            metadata_presence: 0x01,
            ..RawRoot::valid()
        },
        Err(DecodeError::Invalid {
            what: "metadata_root presence (reserved, v1 accepts only 0x00)",
        }),
    );
}

// ============================================ anti-vacuity: the builders

/// The builder's unmodified output IS the encoder's output. Without
/// this, every sheaf vector below could be red for a builder typo.
#[test]
fn raw_sheaf_matches_the_encoder() {
    let doc = SheafDoc {
        parent: None,
        manifest_root: gid("manifest-root-1"),
        timestamp: Timestamp {
            secs: SECS,
            nanos: NANOS,
        },
        ops: vec![SheafOp::PublishTree],
    };
    assert_eq!(
        RawSheaf::valid().bytes(),
        encode_sheaf(&doc).unwrap_or_else(|e| panic!("{e}"))
    );
    // …and it decodes back to the same document (the positive control).
    assert_eq!(decode_sheaf(&RawSheaf::valid().bytes()), Ok(doc));
}

/// Same pin for the root builder, on BOTH parent shapes.
#[test]
fn raw_root_matches_the_encoder() {
    fn sig(seed: u64) -> RootSig {
        RootSig {
            key_id: fill_n(seed, KEY_ID_LEN)
                .as_slice()
                .try_into()
                .unwrap_or_else(|e| panic!("{e}")),
            sig: fill_n(seed ^ 0xFFFF, ED25519_SIG_LEN)
                .as_slice()
                .try_into()
                .unwrap_or_else(|e| panic!("{e}")),
        }
    }
    let doc = RootDoc {
        volume: VolumeName::from_bytes(VOLUME).unwrap_or_else(|e| panic!("{e}")),
        seq: 1,
        parent: None,
        writer_uuid: [0x11; WRITER_UUID_LEN],
        epoch: 1,
        timestamp: Timestamp {
            secs: SECS,
            nanos: NANOS,
        },
        chunker_spec: granary_core::thresh::CHUNKER_SPEC.to_string(),
        manifest_root: gid("manifest-root-1"),
        binmap_index: gid("binmap-index-1"),
        sheaf_head: gid("sheaf-head-1"),
        sigs: vec![sig(1)],
    };
    assert_eq!(
        RawRoot::valid().bytes(),
        encode_root(&doc).unwrap_or_else(|e| panic!("{e}"))
    );
    assert_eq!(decode_root(&RawRoot::valid().bytes()), Ok(doc.clone()));

    let doc2 = RootDoc {
        seq: 2,
        parent: Some(gid("root-seq-1")),
        sigs: vec![sig(1), sig(2)],
        ..doc
    };
    assert_eq!(
        RawRoot::valid_seq2().bytes(),
        encode_root(&doc2).unwrap_or_else(|e| panic!("{e}"))
    );
    assert_eq!(decode_root(&RawRoot::valid_seq2().bytes()), Ok(doc2));
}

// ================================================================ sheaf

#[test]
fn sheaf_rejects_nanos_at_or_over_one_second() {
    for nanos in [1_000_000_000, 1_000_000_001, u32::MAX] {
        sheaf_rejects(
            &RawSheaf {
                nanos,
                ..RawSheaf::valid()
            },
            invalid("timestamp nanos (>= 1e9)"),
        );
    }
    // …and 999_999_999 is legal (the boundary is not off by one).
    assert!(
        decode_sheaf(
            &RawSheaf {
                nanos: 999_999_999,
                ..RawSheaf::valid()
            }
            .bytes()
        )
        .is_ok()
    );
}

#[test]
fn sheaf_rejects_unregistered_op_tag() {
    for tag in [0x00, 0x02, 0xFF] {
        sheaf_rejects(
            &RawSheaf {
                ops: vec![tag],
                ..RawSheaf::valid()
            },
            invalid("sheaf op tag (unregistered)"),
        );
    }
}

#[test]
fn sheaf_rejects_op_count_zero_and_over_cap() {
    sheaf_rejects(
        &RawSheaf {
            op_count: 0,
            ops: Vec::new(),
            ..RawSheaf::valid()
        },
        invalid("sheaf op_count zero"),
    );
    // Over-cap is refused BEFORE the ops are allocated: the body here
    // carries a single byte, not 1025.
    sheaf_rejects(
        &RawSheaf {
            op_count: 1025,
            ..RawSheaf::valid()
        },
        Err(DecodeError::CapExceeded {
            what: "sheaf op_count",
            got: 1025,
            cap: 1024,
        }),
    );
    // A count that outruns the body is Truncated, not a silent short read.
    sheaf_rejects(
        &RawSheaf {
            op_count: 2,
            ..RawSheaf::valid()
        },
        Err(DecodeError::Truncated),
    );
    // Exactly the cap, with a full body, is accepted.
    assert!(
        decode_sheaf(
            &RawSheaf {
                op_count: 1024,
                ops: vec![0x01; 1024],
                ..RawSheaf::valid()
            }
            .bytes()
        )
        .is_ok()
    );
}

#[test]
fn sheaf_rejects_bad_parent_presence_byte() {
    for presence in [0x02, 0x03, 0xFF] {
        sheaf_rejects(
            &RawSheaf {
                presence,
                ..RawSheaf::valid()
            },
            invalid("sheaf parent presence byte"),
        );
    }
}

#[test]
fn sheaf_rejects_truncated_id_after_presence_one() {
    // Presence says "a parent follows"; only 32 of its 33 bytes do, and
    // the object ends there — the id read itself runs out.
    let mut short = id_bytes("root-seq-1");
    short.pop();
    sheaf_rejects(
        &RawSheaf {
            presence: 0x01,
            parent: short.clone(),
            manifest_root: Vec::new(),
            ops: Vec::new(),
            ..RawSheaf::valid()
        },
        Err(DecodeError::Truncated),
    );
    // Nothing at all after the presence byte.
    sheaf_rejects(
        &RawSheaf {
            presence: 0x01,
            parent: Vec::new(),
            manifest_root: Vec::new(),
            ops: Vec::new(),
            ..RawSheaf::valid()
        },
        Err(DecodeError::Truncated),
    );
    // A short parent followed by a full body does NOT truncate — the
    // 33-byte read borrows the next field's first byte and every
    // downstream field shifts. It still refuses (here on the shifted
    // manifest_root's algorithm tag): a fixed-width field can slide,
    // but it can never slide into acceptance, because every id carries
    // a validated tag and the object must end exactly on a field
    // boundary.
    sheaf_rejects(
        &RawSheaf {
            presence: 0x01,
            parent: short,
            ..RawSheaf::valid()
        },
        invalid("sheaf manifest_root grain id"),
    );
}

#[test]
fn sheaf_rejects_unregistered_hash_algorithm_in_ids() {
    let mut bad = id_bytes("root-seq-1");
    bad.splice(0..1, [0x00]); // 0x00 is invalid forever
    sheaf_rejects(
        &RawSheaf {
            presence: 0x01,
            parent: bad.clone(),
            ..RawSheaf::valid()
        },
        invalid("sheaf parent grain id"),
    );
    sheaf_rejects(
        &RawSheaf {
            manifest_root: bad,
            ..RawSheaf::valid()
        },
        invalid("sheaf manifest_root grain id"),
    );
}

#[test]
fn sheaf_rejects_trailing_bytes() {
    sheaf_rejects(
        &RawSheaf {
            trailing: vec![0x00],
            ..RawSheaf::valid()
        },
        Err(DecodeError::TrailingBytes { remaining: 1 }),
    );
    sheaf_rejects(
        &RawSheaf {
            trailing: vec![0xAA; 64],
            ..RawSheaf::valid()
        },
        Err(DecodeError::TrailingBytes { remaining: 64 }),
    );
}

#[test]
fn sheaf_rejects_envelope_faults() {
    sheaf_rejects(
        &RawSheaf {
            version: 0x02,
            ..RawSheaf::valid()
        },
        Err(DecodeError::UnknownVersion { version: 0x02 }),
    );
    assert_eq!(decode_sheaf(&[]).map(|_| ()), Err(DecodeError::Truncated));
    assert_eq!(
        decode_sheaf(b"XXXXXXXX\x0a\x01").map(|_| ()),
        Err(DecodeError::BadMagic)
    );
}

// ================================================================= root

#[test]
fn root_rejects_seq_zero() {
    // seq 0 is refused before the cross-rule can be consulted: there is
    // no root numbered 0, with or without a parent.
    root_rejects(
        &RawRoot {
            seq: 0,
            ..RawRoot::valid()
        },
        invalid("root seq zero"),
    );
    root_rejects(
        &RawRoot {
            seq: 0,
            ..RawRoot::valid_seq2()
        },
        invalid("root seq zero"),
    );
}

#[test]
fn root_rejects_the_parent_seq_cross_rule_both_directions() {
    // seq 1 WITH a parent: the first root cannot have a predecessor.
    root_rejects(
        &RawRoot {
            seq: 1,
            ..RawRoot::valid_seq2()
        },
        invalid("root parent/seq cross-rule (parent absent iff seq == 1)"),
    );
    // seq 2 WITHOUT a parent: a chain link that names no predecessor is
    // how history gets silently truncated.
    root_rejects(
        &RawRoot {
            seq: 2,
            ..RawRoot::valid()
        },
        invalid("root parent/seq cross-rule (parent absent iff seq == 1)"),
    );
    root_rejects(
        &RawRoot {
            seq: u64::MAX,
            ..RawRoot::valid()
        },
        invalid("root parent/seq cross-rule (parent absent iff seq == 1)"),
    );
}

#[test]
fn root_rejects_bad_parent_presence_byte() {
    root_rejects(
        &RawRoot {
            presence: 0x02,
            ..RawRoot::valid_seq2()
        },
        invalid("root parent presence byte"),
    );
}

/// A2: the root path shares the rule that `nanos` must be below 1e9
/// (`take_timestamp`) with the sheaf path, but before this test the rule
/// had no vector on the ROOT side in either direction — deleting the
/// check from the root decoder left 226/226 green, because only the
/// sheaf's own vectors (`sheaf_rejects_nanos_at_or_over_one_second`)
/// exercised it. This test adds a root-side red vector for the rule.
/// It mirrors the sheaf test's shape exactly.
///
#[test]
fn root_rejects_nanos_at_or_over_one_second() {
    for nanos in [1_000_000_000, 1_000_000_001, u32::MAX] {
        root_rejects(
            &RawRoot {
                nanos,
                ..RawRoot::valid()
            },
            invalid("timestamp nanos (>= 1e9)"),
        );
    }
    // …and 999_999_999 is legal (the boundary is not off by one).
    assert!(
        decode_root(
            &RawRoot {
                nanos: 999_999_999,
                ..RawRoot::valid()
            }
            .bytes()
        )
        .is_ok()
    );
}

#[test]
fn root_rejects_every_non_dns_1123_volume_name() {
    // Empty (declared length 0).
    root_rejects(
        &RawRoot::with_volume(b""),
        invalid("root volume_name empty"),
    );
    // 64 bytes — one over the label limit.
    root_rejects(
        &RawRoot::with_volume(&[b'a'; 64]),
        invalid("root volume_name over 63 bytes"),
    );
    // Uppercase is REJECTED, never folded.
    root_rejects(
        &RawRoot::with_volume(b"Granary"),
        invalid("root volume_name byte (DNS-1123: [a-z0-9-])"),
    );
    // Leading / trailing dash.
    root_rejects(
        &RawRoot::with_volume(b"-vol"),
        invalid("root volume_name leading '-'"),
    );
    root_rejects(
        &RawRoot::with_volume(b"vol-"),
        invalid("root volume_name trailing '-'"),
    );
    // Bytes outside the label alphabet, including non-UTF-8 and the
    // key-separator characters a name must never smuggle in.
    for bad in [
        b"vol.ume".as_slice(),
        b"vol_ume",
        b"vol/ume",
        b"vol ume",
        b"\xffvol",
        b"vol\x00",
    ] {
        root_rejects(
            &RawRoot::with_volume(bad),
            invalid("root volume_name byte (DNS-1123: [a-z0-9-])"),
        );
    }
    // Exactly 63 is legal (the limit is not off by one).
    assert!(decode_root(&RawRoot::with_volume(&[b'a'; 63]).bytes()).is_ok());
    // The same rules, stated once, at the validation type.
    assert_eq!(
        VolumeName::from_bytes(b"Granary"),
        Err(VolumeNameError::BadByte { byte: b'G' })
    );
}

#[test]
fn root_rejects_declared_volume_length_that_outruns_the_object() {
    root_rejects(
        &RawRoot {
            volume_len: 63,
            ..RawRoot::valid()
        },
        // 63 declared bytes swallow the seq/parent/uuid fields, so the
        // name itself becomes illegal before the object runs out.
        invalid("root volume_name byte (DNS-1123: [a-z0-9-])"),
    );
    root_rejects(
        &RawRoot {
            volume_len: 63,
            volume: Vec::new(),
            seq: 0,
            writer_uuid: Vec::new(),
            spec: Vec::new(),
            manifest_root: Vec::new(),
            binmap_index: Vec::new(),
            sheaf_head: Vec::new(),
            sigs: Vec::new(),
            ..RawRoot::valid()
        },
        Err(DecodeError::Truncated),
    );
}

#[test]
fn root_rejects_bad_chunker_spec() {
    // Invalid UTF-8 (a lone continuation byte).
    root_rejects(
        &RawRoot {
            spec_len: 3,
            spec: vec![0x66, 0xC3, 0x28],
            ..RawRoot::valid()
        },
        invalid("root chunker_spec (invalid UTF-8)"),
    );
    // Empty.
    root_rejects(
        &RawRoot {
            spec_len: 0,
            spec: Vec::new(),
            ..RawRoot::valid()
        },
        invalid("root chunker_spec empty"),
    );
    // A DIFFERENT but well-formed tuple DECODES: equality with the local
    // rendering is read-time compatibility policy, not format
    // validation — a v2-tuple root must still be readable enough to
    // report what it is.
    let other = b"fastcdc-v2020/9.9.9 min=1 avg=2 max=3 nl=0".to_vec();
    let raw = RawRoot {
        spec_len: u8::try_from(other.len()).unwrap_or_else(|e| panic!("{e}")),
        spec: other.clone(),
        ..RawRoot::valid()
    };
    let decoded = decode_root(&raw.bytes()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(decoded.chunker_spec.as_bytes(), other.as_slice());
    assert_ne!(
        decoded.chunker_spec,
        granary_core::thresh::CHUNKER_SPEC.to_string()
    );
}

/// A5 (`chunker_spec` half): the ENCODER's own
/// accept side at `CHUNKER_SPEC_MAX` was unpinned — flipping
/// `encode_root`'s `>` to `>=` ships green, because the rejects above
/// only test the DECODER's refuse side (empty, invalid UTF-8) and the
/// decoder has no accept-at-cap check of its own to invert (`spec_len` is
/// a `u8`, whose max value 255 already equals `CHUNKER_SPEC_MAX`, so
/// there is no `>` comparison on that side to narrow). This goes through
/// the real encoder, at exactly the cap, and round-trips.
#[test]
fn root_encoder_accepts_chunker_spec_at_the_cap() {
    let doc = RootDoc {
        volume: VolumeName::from_bytes(VOLUME).unwrap_or_else(|e| panic!("{e}")),
        seq: 1,
        parent: None,
        writer_uuid: [0x11; WRITER_UUID_LEN],
        epoch: 1,
        timestamp: Timestamp {
            secs: SECS,
            nanos: NANOS,
        },
        chunker_spec: "x".repeat(CHUNKER_SPEC_MAX),
        manifest_root: gid("manifest-root-1"),
        binmap_index: gid("binmap-index-1"),
        sheaf_head: gid("sheaf-head-1"),
        sigs: vec![root_sig(1)],
    };
    let bytes = encode_root(&doc).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(decode_root(&bytes), Ok(doc));
}

#[test]
fn root_rejects_unregistered_signature_algorithm_by_name() {
    for alg in [0x00, 0x02, 0xFF] {
        root_rejects(
            &RawRoot {
                sigs: vec![RawSig {
                    alg,
                    ..RawSig::valid(1)
                }],
                ..RawRoot::valid()
            },
            invalid("root signature alg (v1 accepts only 0x01 Ed25519)"),
        );
    }
}

#[test]
fn root_rejects_sig_len_other_than_64_under_ed25519() {
    for len in [0u16, 63, 65, 8192, u16::MAX] {
        root_rejects(
            &RawRoot {
                sigs: vec![RawSig {
                    sig_len: len,
                    sig: fill_n(2, usize::from(len)),
                    ..RawSig::valid(1)
                }],
                ..RawRoot::valid()
            },
            invalid("root signature sig_len (Ed25519 requires 64)"),
        );
    }
}

#[test]
fn root_rejects_sig_count_zero_and_over_two() {
    root_rejects(
        &RawRoot {
            sig_count: 0,
            sigs: Vec::new(),
            ..RawRoot::valid()
        },
        invalid("root sig_count zero"),
    );
    // An unsigned root is never a root: dropping the section entirely
    // is the same refusal.
    root_rejects(
        &RawRoot {
            sig_count: 0,
            ..RawRoot::valid()
        },
        invalid("root sig_count zero"),
    );
    for count in [3u8, 4, u8::MAX] {
        root_rejects(
            &RawRoot {
                sig_count: count,
                sigs: vec![RawSig::valid(1), RawSig::valid(2), RawSig::valid(3)],
                ..RawRoot::valid()
            },
            Err(DecodeError::CapExceeded {
                what: "root sig_count",
                got: u64::from(count),
                cap: 2,
            }),
        );
    }
    // A count that outruns the slots is Truncated.
    root_rejects(
        &RawRoot {
            sig_count: 2,
            ..RawRoot::valid()
        },
        Err(DecodeError::Truncated),
    );
}

#[test]
fn root_rejects_duplicate_key_id_across_slots() {
    root_rejects(
        &RawRoot {
            sig_count: 2,
            sigs: vec![RawSig::valid(1), RawSig::valid(1)],
            ..RawRoot::valid()
        },
        invalid("root duplicate signature key_id"),
    );
    // Same key id, DIFFERENT signature bytes — still one key, so still
    // not two signatures (this is the shape a replayed slot takes).
    root_rejects(
        &RawRoot {
            sig_count: 2,
            sigs: vec![
                RawSig::valid(1),
                RawSig {
                    sig: fill_n(99, ED25519_SIG_LEN),
                    ..RawSig::valid(1)
                },
            ],
            ..RawRoot::valid()
        },
        invalid("root duplicate signature key_id"),
    );
}

/// A4: the duplicate-`key_id` comparison
/// width was unpinned on both sides — narrowing it to, say, byte 0 alone
/// leaves the suite green, because every key id in the corpus above is
/// either wholly identical or differs in byte 0. The code correctly
/// compares all 32 bytes; a narrowing regression would OVER-REJECT two
/// legitimate keys sharing a prefix, during exactly the key-transition
/// operation the second slot exists for. Two key ids sharing every byte
/// but the last must decode as two DISTINCT signatures, not a duplicate.
#[test]
fn root_accepts_key_ids_sharing_every_byte_but_the_last() {
    let mut near_dup = RawSig::valid(1);
    let last = near_dup.key_id.len() - 1;
    near_dup.key_id[last] ^= 0xFF;
    near_dup.sig = fill_n(2, ED25519_SIG_LEN);
    assert!(
        decode_root(
            &RawRoot {
                sig_count: 2,
                sigs: vec![RawSig::valid(1), near_dup],
                ..RawRoot::valid()
            }
            .bytes()
        )
        .is_ok()
    );
}

#[test]
fn root_rejects_unregistered_hash_algorithm_in_ids() {
    let mut bad = id_bytes("x");
    bad.splice(0..1, [0x00]);
    for (field, what) in [
        ("manifest_root", "root manifest_root grain id"),
        ("binmap_index", "root binmap_index grain id"),
        ("sheaf_head", "root sheaf_head grain id"),
        ("parent", "root parent grain id"),
    ] {
        let mut raw = RawRoot::valid_seq2();
        match field {
            "manifest_root" => raw.manifest_root = bad.clone(),
            "binmap_index" => raw.binmap_index = bad.clone(),
            "sheaf_head" => raw.sheaf_head = bad.clone(),
            _ => raw.parent = bad.clone(),
        }
        root_rejects(&raw, invalid(what));
    }
}

#[test]
fn root_rejects_trailing_bytes() {
    root_rejects(
        &RawRoot {
            trailing: vec![0x00],
            ..RawRoot::valid()
        },
        Err(DecodeError::TrailingBytes { remaining: 1 }),
    );
    // A third slot appended after a count of 2 is trailing bytes, not a
    // third signature.
    root_rejects(
        &RawRoot {
            trailing: fill_n(5, 99),
            ..RawRoot::valid_seq2()
        },
        Err(DecodeError::TrailingBytes { remaining: 99 }),
    );
}

// ================================================== cross-type feeding

/// Every object type refuses every other type's bytes BY NAME. The
/// envelope's type tag is also the signature domain separator, so a
/// decoder that accepted a neighbouring type would let one signature
/// authenticate two different objects.
#[test]
fn decoders_refuse_cross_fed_object_types() {
    let sheaf = RawSheaf::valid().bytes();
    let root = RawRoot::valid().bytes();
    let bin = binfmt::encode_bin(&[binfmt::PackedFrame {
        id: gid("frame"),
        frame: {
            let mut f = binfmt::encode_frame_header(4)
                .unwrap_or_else(|e| panic!("{e}"))
                .to_vec();
            f.extend_from_slice(b"data");
            f
        },
    }])
    .unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        decode_root(&sheaf).map(|_| ()),
        invalid("object type (want root)")
    );
    assert_eq!(
        decode_root(&bin).map(|_| ()),
        invalid("object type (want root)")
    );
    assert_eq!(
        decode_sheaf(&root).map(|_| ()),
        invalid("object type (want sheaf)")
    );
    assert_eq!(
        decode_sheaf(&bin).map(|_| ()),
        invalid("object type (want sheaf)")
    );
    // The bin decoder refuses ours in the same way.
    assert_eq!(
        binfmt::decode_bin(&root).map(|_| ()),
        invalid("object type (want bin)")
    );
    // A root's type byte rewritten to the sheaf tag does not become a
    // sheaf: the sheaf decoder reads the byte right after the envelope as
    // its parent PRESENCE byte, and that byte is the root's `volume_len`
    // (12, for `VOLUME` = b"granary-test") — neither 0x00 nor 0x01, so it
    // is refused BY NAME on that field specifically (A6).
    let mut disguised = root.clone();
    disguised
        .get_mut(8..9)
        .unwrap_or_else(|| panic!("slice"))
        .copy_from_slice(&[ObjectType::Sheaf.tag()]);
    assert_eq!(
        decode_sheaf(&disguised).map(|_| ()),
        invalid("sheaf parent presence byte")
    );
    // signed_prefix is type-checked too — it is the verifier's entry
    // point, so it must never hand back a prefix of a non-root.
    assert_eq!(
        signed_prefix(&sheaf).map(|_| ()),
        invalid("object type (want root)")
    );
}

// ========================================================= totality

/// Truncating a valid object at EVERY length never panics and never
/// succeeds — the decoders are total over short input, which is what
/// the fuzz targets assert continuously.
#[test]
fn every_truncation_is_a_clean_error() {
    for full in [
        RawSheaf::valid().bytes(),
        RawRoot::valid().bytes(),
        RawRoot::valid_seq2().bytes(),
    ] {
        for cut in 0..full.len() {
            let short = full.get(..cut).unwrap_or_else(|| panic!("slice"));
            assert!(decode_sheaf(short).is_err(), "sheaf accepted {cut} bytes");
            assert!(decode_root(short).is_err(), "root accepted {cut} bytes");
            let _ = signed_prefix(short); // must not panic
        }
    }
}
