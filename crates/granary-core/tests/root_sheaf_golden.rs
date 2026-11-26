// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Root and sheaf golden vectors. Both object types are
//! consensus surfaces, and the root is
//! the SIGNED one: a red here means
//! the FORMAT moved bytes — a deliberate versioned event, never a
//! refactor side effect.
//!
//! Each root case additionally pins `signed_prefix_len`: the offset
//! where the signature section begins. That number IS the signing
//! domain. A drifting boundary would leave every existing
//! signature verifying over a different message — a silent
//! signature-domain break that no roundtrip test can see, because
//! encode and decode would drift together.
//!
//! Regenerate DELIBERATELY:
//! `GRANARY_REGEN_VECTORS=1 cargo nextest run -p granary-core --test root_sheaf_golden`

#![expect(
    clippy::unwrap_used,
    reason = "render/build helpers below sit outside #[test] fns (test code, standards rule 3)"
)]

use std::fmt::Write as _;
use std::path::Path;

use granary_core::encoding::{self, ObjectType};
use granary_core::hash::GrainId;
use granary_core::root::{
    ED25519_SIG_LEN, KEY_ID_LEN, RootDoc, RootSig, VolumeName, WRITER_UUID_LEN, decode_root,
    encode_root, signed_prefix, signing_prefix_of,
};
use granary_core::sheaf::{SheafDoc, SheafOp, Timestamp, decode_sheaf, encode_sheaf};
use granary_core::testkit;

mod common;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").unwrap();
    }
    out
}

/// Deterministic synthetic signature material (`testkit::fill`): core
/// holds no crypto, so these are STRUCTURE vectors — real
/// Ed25519 signatures over these same prefixes are granary-store's
/// full-stack vectors.
fn sig(seed: u64) -> RootSig {
    RootSig {
        key_id: testkit::fill(seed, KEY_ID_LEN)
            .as_slice()
            .try_into()
            .unwrap(),
        sig: testkit::fill(seed ^ 0xFFFF, ED25519_SIG_LEN)
            .as_slice()
            .try_into()
            .unwrap(),
    }
}

fn uuid(seed: u64) -> [u8; WRITER_UUID_LEN] {
    testkit::fill(seed, WRITER_UUID_LEN)
        .as_slice()
        .try_into()
        .unwrap()
}

fn ts(secs: i64, nanos: u32) -> Timestamp {
    Timestamp { secs, nanos }
}

// sheaf/first: a volume's FIRST commit — parent absent (presence 0x00,
// no sentinel id follows).
fn sheaf_first() -> SheafDoc {
    SheafDoc {
        parent: None,
        manifest_root: GrainId::of(b"manifest-root-1"),
        timestamp: ts(1_760_000_000, 123_456_789),
        ops: vec![SheafOp::PublishTree],
    }
}

// sheaf/chained: the second commit, hash-chained to the first.
fn sheaf_chained(parent: GrainId) -> SheafDoc {
    SheafDoc {
        parent: Some(parent),
        manifest_root: GrainId::of(b"manifest-root-2"),
        timestamp: ts(1_760_000_060, 0),
        ops: vec![SheafOp::PublishTree],
    }
}

// root/seq1: the first published root — no parent, one signature.
fn root_seq1(sheaf_head: GrainId) -> RootDoc {
    RootDoc {
        volume: VolumeName::new("granary-golden".to_owned()).unwrap(),
        seq: 1,
        parent: None,
        writer_uuid: uuid(7),
        epoch: 1,
        timestamp: ts(1_760_000_000, 123_456_789),
        chunker_spec: granary_core::thresh::CHUNKER_SPEC.to_string(),
        manifest_root: GrainId::of(b"manifest-root-1"),
        binmap_index: GrainId::of(b"binmap-index-1"),
        sheaf_head,
        sigs: vec![sig(1)],
    }
}

// root/seq2: chained to root/seq1 and carrying BOTH signature slots
// — the shape a key transition or a hybrid PQ signing produces.
fn root_seq2(parent: GrainId, sheaf_head: GrainId) -> RootDoc {
    RootDoc {
        seq: 2,
        parent: Some(parent),
        writer_uuid: uuid(8),
        epoch: 2,
        timestamp: ts(1_760_000_060, 0),
        manifest_root: GrainId::of(b"manifest-root-2"),
        binmap_index: GrainId::of(b"binmap-index-2"),
        sheaf_head,
        sigs: vec![sig(1), sig(2)],
        ..root_seq1(sheaf_head)
    }
}

fn render_sheaf(out: &mut String, case: &str, doc: &SheafDoc) -> Vec<u8> {
    let bytes = encode_sheaf(doc).unwrap();
    writeln!(
        out,
        "case {case} id={} bytes={}",
        GrainId::of(&bytes),
        hex(&bytes)
    )
    .unwrap();
    bytes
}

fn render_root(out: &mut String, case: &str, doc: &RootDoc) -> Vec<u8> {
    let bytes = encode_root(doc).unwrap();
    let prefix = signed_prefix(&bytes).unwrap();
    // The writer's prefix and the reader's prefix are the same bytes —
    // asserted HERE so the pinned number below cannot be produced by a
    // reader-only definition of the boundary.
    assert_eq!(prefix, signing_prefix_of(doc).unwrap().as_slice());
    writeln!(
        out,
        "case {case} id={} signed_prefix_len={} bytes={}",
        GrainId::of(&bytes),
        prefix.len(),
        hex(&bytes)
    )
    .unwrap();
    bytes
}

fn build_vectors() -> String {
    let mut out = String::new();
    writeln!(out, "# granary root + sheaf golden vectors v1").unwrap();

    let first = render_sheaf(&mut out, "sheaf/first", &sheaf_first());
    let first_id = GrainId::of(&first);
    let chained = render_sheaf(&mut out, "sheaf/chained", &sheaf_chained(first_id));
    let chained_id = GrainId::of(&chained);

    let r1 = render_root(&mut out, "root/seq1", &root_seq1(first_id));
    let r1_id = GrainId::of(&r1);
    render_root(&mut out, "root/seq2", &root_seq2(r1_id, chained_id));

    out
}

#[test]
fn matches_committed_vectors() {
    common::assert_golden(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/root_sheaf_v1.txt"),
        &build_vectors(),
    );
}

/// Closes the same hole closed for `bin_golden`/`binmap_golden`:
/// `matches_committed_vectors` only string-compares the ENCODER's output
/// against the committed file and never calls a decoder, so a decoder
/// that started REFUSING a committed vector would be indistinguishable
/// from one that still accepts it. Dispatch on the envelope's object
/// type, exactly as a real reader would, then re-encode the decoded
/// value and check it reproduces the identical bytes.
fn assert_decodes_and_reencodes(bytes: &[u8]) {
    let (ty, _) = encoding::open_envelope(bytes).unwrap_or_else(|e| panic!("{e}"));
    let re = match ty {
        ObjectType::Sheaf => {
            let doc = decode_sheaf(bytes).unwrap_or_else(|e| panic!("{e}"));
            encode_sheaf(&doc).unwrap_or_else(|e| panic!("{e}"))
        }
        ObjectType::Root => {
            let doc = decode_root(bytes).unwrap_or_else(|e| panic!("{e}"));
            encode_root(&doc).unwrap_or_else(|e| panic!("{e}"))
        }
        other => panic!("unexpected object type in root/sheaf goldens: {other:?}"),
    };
    assert_eq!(
        re, bytes,
        "decode→re-encode must reproduce the golden bytes exactly"
    );
}

/// Every object emitted by every case above must decode successfully
/// and re-encode to the identical bytes — goldens pin the ENCODER's
/// output, but the decoder's accept set is what must hold forever, and
/// nothing pinned that until now (SCOPE RULE: `root_sheaf_golden` must
/// not repeat bin/binmap's encode-only hole).
#[test]
fn committed_vectors_decode_and_reencode() {
    let first = encode_sheaf(&sheaf_first()).unwrap_or_else(|e| panic!("{e}"));
    let first_id = GrainId::of(&first);
    let chained = encode_sheaf(&sheaf_chained(first_id)).unwrap_or_else(|e| panic!("{e}"));
    let chained_id = GrainId::of(&chained);
    let r1 = encode_root(&root_seq1(first_id)).unwrap_or_else(|e| panic!("{e}"));
    let r1_id = GrainId::of(&r1);
    let r2 = encode_root(&root_seq2(r1_id, chained_id)).unwrap_or_else(|e| panic!("{e}"));
    for bytes in [first, chained, r1, r2] {
        assert_decodes_and_reencodes(&bytes);
    }
}

/// The signing boundary is exercised at exactly ONE `chunker_spec`
/// length everywhere else in the suite —
/// every root anywhere in the suite happens to carry the local
/// rendering's 58 bytes, so a boundary that quietly started reading the
/// spec length from `crate::thresh::CHUNKER_SPEC` instead of the PARSED
/// field would leave the whole suite green. This walks the boundary
/// across all four axes that can move it — volume-name length ×
/// `chunker_spec` length (four of the five values below are NOT 58) ×
/// parent present/absent × 1 vs 2 signatures, 80 combinations — and for
/// each: `signed_prefix` of the encoded bytes equals `signing_prefix_of`
/// the doc byte-for-byte, AND the boundary lands exactly at the
/// arithmetic header end (the same computation
/// `signed_prefix_boundary_is_the_signature_section_start` above pins
/// for the two golden cases, generalized to arbitrary lengths).
#[test]
fn signing_boundary_holds_across_all_four_axes() {
    let volume_lens = [1usize, 10, 32, 63];
    let spec_lens = [1usize, 10, 58, 100, 255];
    let mut cases = 0usize;
    for &vlen in &volume_lens {
        let volume = VolumeName::new("v".repeat(vlen)).unwrap();
        for &slen in &spec_lens {
            let spec = "s".repeat(slen);
            for &has_parent in &[false, true] {
                let (seq, parent) = if has_parent {
                    (2u64, Some(GrainId::of(b"axis-parent")))
                } else {
                    (1u64, None)
                };
                for &nsigs in &[1usize, 2usize] {
                    let sigs = if nsigs == 1 {
                        vec![sig(1)]
                    } else {
                        vec![sig(1), sig(2)]
                    };
                    let doc = RootDoc {
                        volume: volume.clone(),
                        seq,
                        parent,
                        writer_uuid: uuid(9),
                        epoch: 1,
                        timestamp: ts(1_760_000_000, 0),
                        chunker_spec: spec.clone(),
                        manifest_root: GrainId::of(b"axis-manifest"),
                        binmap_index: GrainId::of(b"axis-binmap"),
                        sheaf_head: GrainId::of(b"axis-sheaf"),
                        sigs,
                    };
                    let bytes = encode_root(&doc).unwrap_or_else(|e| panic!("{e}"));
                    let prefix = signed_prefix(&bytes).unwrap_or_else(|e| panic!("{e}"));
                    let signing = signing_prefix_of(&doc).unwrap_or_else(|e| panic!("{e}"));
                    assert_eq!(
                        prefix,
                        signing.as_slice(),
                        "writer/reader prefix mismatch: vlen={vlen} slen={slen} \
                         parent={has_parent} nsigs={nsigs}"
                    );
                    // envelope(10) + volume_len(1) + volume(vlen) + seq(8) +
                    // parent presence(1) [+ id(33) iff present] +
                    // writer_uuid(16) + epoch(8) + timestamp(12) +
                    // spec_len(1) + chunker_spec(slen) + manifest_root(33) +
                    // metadata presence(1) + binmap_index(33) + sheaf_head(33).
                    let fixed = 10 + 1 + 8 + 1 + 16 + 8 + 12 + 1 + 33 + 1 + 33 + 33;
                    let expected = fixed + vlen + slen + if has_parent { 33 } else { 0 };
                    assert_eq!(
                        prefix.len(),
                        expected,
                        "boundary arithmetic: vlen={vlen} slen={slen} parent={has_parent} \
                         nsigs={nsigs}"
                    );
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, volume_lens.len() * spec_lens.len() * 2 * 2);
    assert_eq!(cases, 80);
}

/// The boundary is arithmetic, not a guess: it is exactly the object
/// minus `sig_count` and its slots. Pinned here as well as in the
/// vector file so a rendering change cannot quietly retire the check.
#[test]
fn signed_prefix_boundary_is_the_signature_section_start() {
    let first_id = GrainId::of(&encode_sheaf(&sheaf_first()).unwrap());
    let r1 = encode_root(&root_seq1(first_id)).unwrap();
    let r2 = encode_root(&root_seq2(GrainId::of(&r1), first_id)).unwrap();
    // volume "granary-golden" (14) + chunker_spec (58) are the only
    // variable-width fields in these cases. The lone +1 after the three
    // ids is the RESERVED metadata_root presence byte.
    let spec_len = granary_core::thresh::CHUNKER_SPEC.to_string().len();
    let fixed = 10 + 1 + 14 + 8 + 1 + 16 + 8 + 12 + 1 + 33 * 3 + 1;
    assert_eq!(signed_prefix(&r1).unwrap().len(), fixed + spec_len);
    assert_eq!(signed_prefix(&r2).unwrap().len(), fixed + spec_len + 33);
    assert_eq!(r1.len() - signed_prefix(&r1).unwrap().len(), 1 + 99);
    assert_eq!(r2.len() - signed_prefix(&r2).unwrap().len(), 1 + 2 * 99);
}
