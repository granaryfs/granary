// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::root` — the root format v1 — the one signed object type.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::encoding::{DecodeError, ObjectType, envelope};
use crate::hash::{GRAIN_ID_BINARY_LEN, GrainId};
use crate::sheaf::{PRESENCE_ABSENT, PRESENCE_PRESENT};
use crate::testkit;

fn vol(s: &str) -> VolumeName {
    VolumeName::new(s.to_owned()).unwrap_or_else(|e| panic!("{e}"))
}

fn sig(seed: u64) -> RootSig {
    let key = testkit::fill(seed, KEY_ID_LEN);
    let s = testkit::fill(seed ^ 0xFFFF, ED25519_SIG_LEN);
    RootSig {
        key_id: key.as_slice().try_into().unwrap_or_else(|e| panic!("{e}")),
        sig: s.as_slice().try_into().unwrap_or_else(|e| panic!("{e}")),
    }
}

fn seq1() -> RootDoc {
    RootDoc {
        volume: vol("granary-test"),
        seq: 1,
        parent: None,
        writer_uuid: [0x11; WRITER_UUID_LEN],
        epoch: 1,
        timestamp: Timestamp {
            secs: 1_760_000_000,
            nanos: 123_456_789,
        },
        chunker_spec: crate::thresh::CHUNKER_SPEC.to_string(),
        manifest_root: GrainId::of(b"manifest-1"),
        binmap_index: GrainId::of(b"binmap-1"),
        sheaf_head: GrainId::of(b"sheaf-1"),
        sigs: vec![sig(1)],
    }
}

fn seq2(parent: GrainId) -> RootDoc {
    RootDoc {
        seq: 2,
        parent: Some(parent),
        epoch: 2,
        writer_uuid: [0x22; WRITER_UUID_LEN],
        sigs: vec![sig(1), sig(2)],
        ..seq1()
    }
}

fn enc(doc: &RootDoc) -> Vec<u8> {
    encode_root(doc).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn constants_are_frozen() {
    assert_eq!(VOLUME_NAME_MAX, 63);
    assert_eq!(CHUNKER_SPEC_MAX, 255);
    assert_eq!(KEY_ID_LEN, 32);
    assert_eq!(WRITER_UUID_LEN, 16);
    assert_eq!(ALG_ED25519, 0x01);
    assert_eq!(ED25519_SIG_LEN, 64);
    assert_eq!(SIG_MAX_LEN, 8192);
    assert_eq!(ROOT_MAX_SIGS, 2);
    assert_eq!(ROOT_SIG_SLOT_LEN, 99);
}

/// The derivation in [`ROOT_MAX_BYTES`]'s doc comment is checked by
/// READING the layout table. This checks the v1-reachable part of it by
/// MEASURING: encode a root with every field at its limit and compare.
///
/// It cannot reach the whole derived total, and that is not a gap in the
/// test — `SIG_MAX_LEN` is 8,192 for the post-quantum switch-on, while a
/// v1 encoder writes Ed25519's 64 bytes and nothing else, so the 16,963
/// figure is not encodable until a larger algorithm is registered. What
/// is measurable is the header plus two filled Ed25519 slots.
#[test]
fn a_maximal_v1_root_encodes_inside_the_cap() {
    let doc = RootDoc {
        volume: VolumeName::new("v".repeat(63)).unwrap_or_else(|e| panic!("{e}")),
        // seq >= 2 so the parent slot is PRESENT — the larger of the two
        // encodings the presence byte selects.
        seq: 2,
        parent: Some(GrainId::of(b"parent")),
        writer_uuid: [0xAB; 16],
        epoch: u64::MAX,
        timestamp: Timestamp {
            secs: i64::MAX,
            nanos: 999_999_999,
        },
        chunker_spec: "c".repeat(255),
        manifest_root: GrainId::of(b"manifest"),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![
            RootSig {
                key_id: [0x01; KEY_ID_LEN],
                sig: [0x11; ED25519_SIG_LEN],
            },
            RootSig {
                key_id: [0x02; KEY_ID_LEN],
                sig: [0x22; ED25519_SIG_LEN],
            },
        ],
    };
    let bytes = enc(&doc);

    assert_eq!(
        bytes.len(),
        ROOT_V1_MAX_ENCODABLE,
        "the measured maximal v1 root disagrees with ROOT_V1_MAX_ENCODABLE"
    );
    assert!(u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= ROOT_MAX_BYTES);
}

#[test]
fn encoder_accepts_key_ids_sharing_every_byte_but_the_last() {
    // The ENCODER's duplicate-key_id scan must compare the FULL 32
    // bytes. Narrowing it to a prefix over-rejects two legitimate
    // keys that share one — during exactly the key-transition
    // operation the second slot exists for. The decoder side is
    // pinned by `root_accepts_key_ids_sharing_every_byte_but_the_last`
    // in the rejects corpus; that vector builds bytes directly and
    // never calls `encode_root`, so this side needed its own pin
    // [mutation-probed: narrowing this scan to `key_id[0]` left 231/231
    // green until this test existed].
    let mut a = sig(1);
    let mut b = sig(2);
    a.key_id = [0x7Au8; KEY_ID_LEN];
    b.key_id = [0x7Au8; KEY_ID_LEN];
    b.key_id[KEY_ID_LEN - 1] = 0x7B;
    let doc = RootDoc {
        sigs: vec![a, b],
        ..seq1()
    };
    let bytes = encode_root(&doc).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(decode_root(&bytes), Ok(doc));
}

#[test]
fn roundtrip_is_canonical_both_parent_shapes() {
    let a = enc(&seq1());
    assert_eq!(decode_root(&a), Ok(seq1()));
    assert_eq!(enc(&decode_root(&a).unwrap_or_else(|e| panic!("{e}"))), a);
    let b = enc(&seq2(GrainId::of(&a)));
    assert_eq!(decode_root(&b), Ok(seq2(GrainId::of(&a))));
    assert_eq!(enc(&decode_root(&b).unwrap_or_else(|e| panic!("{e}"))), b);
    // Presence byte, no sentinel: parent sits right after
    // envelope + volume(1+12) + seq(8).
    let at = 10 + 1 + "granary-test".len() + 8;
    assert_eq!(a.get(at), Some(&PRESENCE_ABSENT));
    assert_eq!(b.get(at), Some(&PRESENCE_PRESENT));
    // Two sigs cost exactly one slot more than one.
    assert_eq!(b.len() - a.len(), GRAIN_ID_BINARY_LEN + ROOT_SIG_SLOT_LEN);
}

/// The signing domain: every signature covers the
/// canonical bytes from the FIRST envelope byte through the last
/// byte before the signature section — the type tag is the domain
/// separator, and no signature ever covers another signature.
#[test]
fn signing_prefix_is_the_signed_domain() {
    for doc in [seq1(), seq2(GrainId::of(b"parent"))] {
        let bytes = enc(&doc);
        let prefix = signed_prefix(&bytes).unwrap_or_else(|e| panic!("{e}"));
        // Writer side and reader side agree byte-for-byte.
        assert_eq!(
            prefix,
            signing_prefix_of(&doc)
                .unwrap_or_else(|e| panic!("{e}"))
                .as_slice()
        );
        // It IS a prefix of the object, starting at the magic.
        assert_eq!(bytes.get(..prefix.len()), Some(prefix));
        assert_eq!(prefix.first(), Some(&b'G'));
        // …and it stops exactly at sig_count.
        assert_eq!(
            bytes.len() - prefix.len(),
            1 + doc.sigs.len() * ROOT_SIG_SLOT_LEN
        );
        assert_eq!(
            bytes.get(prefix.len()),
            Some(&u8::try_from(doc.sigs.len()).unwrap_or_else(|e| panic!("{e}")))
        );
    }
}

/// A signature's own bytes are OUTSIDE its own message: rewriting
/// the signature section cannot change what was signed (otherwise
/// signing would be circular and verification unimplementable),
/// while every header byte IS inside the domain.
#[test]
fn signature_bytes_are_outside_the_signed_prefix() {
    let doc = seq2(GrainId::of(b"parent"));
    let bytes = enc(&doc);
    let prefix_len = signed_prefix(&bytes)
        .unwrap_or_else(|e| panic!("{e}"))
        .len();
    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    *tampered.get_mut(last).unwrap_or_else(|| panic!("slice")) ^= 0xFF;
    assert_eq!(
        signed_prefix(&tampered).unwrap_or_else(|e| panic!("{e}")),
        bytes.get(..prefix_len).unwrap_or_else(|| panic!("slice"))
    );
    // The last byte INSIDE the boundary (sheaf_head's final digest
    // byte) still decodes when flipped — and moves the message.
    let mut moved = bytes;
    *moved
        .get_mut(prefix_len - 1)
        .unwrap_or_else(|| panic!("slice")) ^= 0x01;
    assert!(decode_root(&moved).is_ok());
    assert_ne!(
        signed_prefix(&moved).unwrap_or_else(|e| panic!("{e}")),
        signing_prefix_of(&doc)
            .unwrap_or_else(|e| panic!("{e}"))
            .as_slice()
    );
}

#[test]
fn volume_name_is_a_dns_1123_label() {
    let longest = "x".repeat(VOLUME_NAME_MAX);
    for ok in ["a", "0", "a-b", "granary-test", longest.as_str()] {
        VolumeName::new(ok.to_owned()).unwrap_or_else(|e| panic!("{e} for {ok}"));
    }
    assert_eq!(VolumeName::new(String::new()), Err(VolumeNameError::Empty));
    assert_eq!(
        VolumeName::new("x".repeat(VOLUME_NAME_MAX + 1)),
        Err(VolumeNameError::TooLong {
            len: VOLUME_NAME_MAX + 1
        })
    );
    assert_eq!(
        VolumeName::new("Vol".to_owned()),
        Err(VolumeNameError::BadByte { byte: b'V' })
    );
    assert_eq!(
        VolumeName::new("a.b".to_owned()),
        Err(VolumeNameError::BadByte { byte: b'.' })
    );
    assert_eq!(
        VolumeName::new("a_b".to_owned()),
        Err(VolumeNameError::BadByte { byte: b'_' })
    );
    assert_eq!(
        VolumeName::new("-a".to_owned()),
        Err(VolumeNameError::LeadingDash)
    );
    assert_eq!(
        VolumeName::new("a-".to_owned()),
        Err(VolumeNameError::TrailingDash)
    );
    assert_eq!(
        VolumeName::new("-".to_owned()),
        Err(VolumeNameError::LeadingDash)
    );
}

/// The two frozen registry entries, named HERE rather than read out
/// of whatever list the implementation happens to hold: a test that
/// iterates the registry passes over an empty registry and reserves
/// nothing. Both must be DNS-1123-legal — the registry sits above the
/// format, so a reserved name is one a writer could otherwise mint.
#[test]
fn the_frozen_reserved_prefixes_are_legal_names_that_admission_refuses() {
    for name in ["gran-anything", "xn--anything", "gran-a", "xn--a"] {
        let v = VolumeName::new(name.to_owned()).unwrap_or_else(|e| panic!("{e} for {name}"));
        assert!(is_reserved_volume_name(&v), "{name} must be reserved");
    }
}

/// The boundary, in the direction that matters more: a prefix rule
/// that over-refuses takes names nobody agreed to reserve. The three
/// `gran`-but-not-`gran-` names are the repo's own — one of them is
/// inside a committed golden vector.
#[test]
fn names_outside_the_frozen_prefixes_are_not_reserved() {
    for name in [
        "granary-golden",
        "granary-test",
        "granary-docs",
        "grand",
        "my-gran-vol",
        "gran",
        "xn",
        "xn-a",
        "my-xn--vol",
        "a",
    ] {
        let v = VolumeName::new(name.to_owned()).unwrap_or_else(|e| panic!("{e} for {name}"));
        assert!(!is_reserved_volume_name(&v), "{name} must NOT be reserved");
    }
}

/// Every volume name the workspace already uses, enumerated from the
/// workspace and not from the registry, still constructs AND is still
/// admissible. Asserted rather than assumed: a registry entry that
/// collided with one of these would make an existing artifact
/// unmintable.
///
/// **Scope, exactly.** The list is a SNAPSHOT swept out of the
/// workspace's Rust sources, not a live view of them, so it grows by
/// hand and a name added elsewhere later is not covered until it is
/// added here. Swept by taking, across `crates/**/*.rs`, every string
/// literal in a volume position: the `VolumeName` constructors, the
/// `RootStore`/`BinStore` methods whose first argument is a volume
/// (`put_root`, `get_root`, `read_hint`, `write_hint`, `max_seq`,
/// `put_meta`, `get_meta`), the `root/…/` and `meta/…/` store-key
/// literals, the `VOLUME` consts, and the volume positionals the CLI
/// parser tests pass. Names that do not construct are excluded — the
/// reject corpora (`Vol`, `a.b`, `a_b`, `-vol`, `vol-`, `demo-`,
/// `a/b`) are refused by the label rules, which is a different test.
///
/// A literal sweep alone would MISS the names built at run time, so
/// those are enumerated from their template instead — see
/// `bucket_lane` below. Any future call site that assembles a volume
/// name rather than writing it has to be added the same way; a sweep
/// for literals cannot see it.
///
/// **Deliberately excluded: `gran-reserved`.** It exists only to
/// exercise the registry, so it is the one name in the workspace that
/// must NOT be admissible; asserting it here would assert the
/// opposite of what it is for.
///
/// This is the check an entry proposed for the registry has to
/// survive, so it is worth stating what makes it fail: it fails when
/// a proposed prefix matches any name below. Adding `vol-` to the
/// registry, for one worked example, collides with every `vol-*`
/// name below — thirty-one of them as written.
#[test]
fn every_volume_name_the_repo_already_uses_stays_admissible() {
    // The golden suite's signing-boundary sweep walks volume lengths
    // 1, 10, 32 and 63, so all four are names in use — not just the
    // shortest and the longest.
    let v10 = "v".repeat(10);
    let v32 = "v".repeat(32);
    let max_v = "v".repeat(VOLUME_NAME_MAX);
    let max_x = "x".repeat(VOLUME_NAME_MAX);
    // The lane that needs a live bucket does NOT use its tags as
    // volume names: it builds `gtest-{tag}-{pid}` at run time, so
    // the names that reach a bucket are the template below
    // instantiated. Two pid widths, because the suffix is the only
    // part that varies and a prefix rule is decided by the front.
    let bucket_lane: Vec<String> = [
        "winner-loser",
        "hint-lifecycle",
        "race",
        "max-seq",
        "max-seq-empty",
        "hint-zero-recovery",
        "hint-garbage-zero-byte",
        "hint-garbage-short",
        "hint-garbage-non-digit",
        "hint-garbage-trailing-newline",
        "hint-garbage-oversized",
        "hint-garbage-non-utf8",
    ]
    .iter()
    .flat_map(|tag| [format!("gtest-{tag}-1"), format!("gtest-{tag}-99999")])
    .collect();
    for name in [
        // Format-level fixtures and the committed golden vector.
        "a",
        "0",
        "a-b",
        "granary-test",
        "granary-golden",
        "granary-docs",
        v10.as_str(),
        v32.as_str(),
        max_v.as_str(),
        max_x.as_str(),
        // The core trait suites and the shared conformance bodies.
        "v",
        "w",
        "nope",
        "nope-v",
        "vol-conf",
        "vol-other",
        "root-conf-cas",
        "root-conf-empty",
        "root-conf-guard",
        "root-conf-hint",
        "root-conf-max",
        "root-conf-ns-a",
        "root-conf-ns-b",
        "root-conf-zero",
        // The client: publish, resolve, the seam suite, the CLI.
        "cp3-vol",
        "other-vol",
        "seam-vol",
        "vol",
        // The object-store backend suites.
        "vol-1",
        "vol-2",
        "vol-3",
        "vol-5",
        "vol-8",
        "vol-g",
        "vol-m",
        "vol-cap",
        "vol-many",
        "vol-liar",
        "vol-cross",
        "vol-table",
        "vol-trait",
        "vol-yield",
        "vol-nested",
        "vol-nothing",
        "vol-onepast",
        "vol-seq-zero",
        "vol-huge-hint",
        "vol-liar-hint",
        "vol-many-empty",
        "vol-overclaim",
        "vol-body-yield",
        "vol-c2-seq-max",
        "vol-interleave",
        "vol-boundary-ok",
        "vol-layout-pin-b",
        "vol-c3-empty-token",
        "vol-empty-for-max-seq",
        // The simulator.
        "d",
        "demo",
        "9-9",
        "a-b-c",
        "sim-vol",
    ]
    .into_iter()
    .chain(bucket_lane.iter().map(String::as_str))
    {
        let v = VolumeName::new(name.to_owned()).unwrap_or_else(|e| panic!("{e} for {name}"));
        assert!(
            !is_reserved_volume_name(&v),
            "{name} is already in use and must stay admissible"
        );
    }
}

/// The registry did not leak into format validation: a root naming a
/// reserved volume round-trips, because the decoder's accept set is
/// untouched by an admission policy that lives above it.
#[test]
fn a_root_naming_a_reserved_volume_still_decodes() {
    let doc = RootDoc {
        volume: vol("gran-reserved"),
        ..seq1()
    };
    let bytes = enc(&doc);
    let back = decode_root(&bytes).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back, doc);
    assert!(
        is_reserved_volume_name(&back.volume),
        "the fixture must actually be a reserved name, or this proves nothing"
    );
    assert_eq!(
        VolumeName::from_bytes(b"gran-reserved"),
        Ok(vol("gran-reserved")),
        "the decode-path constructor is unaffected too"
    );
}

#[test]
fn encoder_refuses_what_the_decoder_rejects() {
    // seq 0 is never valid.
    assert_eq!(
        encode_root(&RootDoc { seq: 0, ..seq1() }),
        Err(EncodeRootError::SeqZero)
    );
    // The cross-rule, BOTH directions.
    assert_eq!(
        encode_root(&RootDoc {
            parent: Some(GrainId::of(b"p")),
            ..seq1()
        }),
        Err(EncodeRootError::ParentSeqMismatch {
            seq: 1,
            has_parent: true
        })
    );
    assert_eq!(
        encode_root(&RootDoc {
            seq: 2,
            parent: None,
            ..seq1()
        }),
        Err(EncodeRootError::ParentSeqMismatch {
            seq: 2,
            has_parent: false
        })
    );
    // Signature slots: 0 and 3.
    assert_eq!(
        encode_root(&RootDoc {
            sigs: vec![],
            ..seq1()
        }),
        Err(EncodeRootError::SigCount { count: 0 })
    );
    assert_eq!(
        encode_root(&RootDoc {
            sigs: vec![sig(1), sig(2), sig(3)],
            ..seq1()
        }),
        Err(EncodeRootError::SigCount { count: 3 })
    );
    // The same key twice is never two signatures.
    assert_eq!(
        encode_root(&RootDoc {
            sigs: vec![sig(1), sig(1)],
            ..seq1()
        }),
        Err(EncodeRootError::DuplicateKeyId)
    );
    // chunker_spec bounds.
    assert_eq!(
        encode_root(&RootDoc {
            chunker_spec: String::new(),
            ..seq1()
        }),
        Err(EncodeRootError::ChunkerSpecLen { len: 0 })
    );
    assert_eq!(
        encode_root(&RootDoc {
            chunker_spec: "x".repeat(CHUNKER_SPEC_MAX + 1),
            ..seq1()
        }),
        Err(EncodeRootError::ChunkerSpecLen {
            len: CHUNKER_SPEC_MAX + 1
        })
    );
    // Refuse a timestamp whose nanoseconds equal one second.
    assert!(matches!(
        encode_root(&RootDoc {
            timestamp: Timestamp {
                secs: 0,
                nanos: 1_000_000_000
            },
            ..seq1()
        }),
        Err(EncodeRootError::NanosOverflow { .. })
    ));
    // The writer path refuses the same header rules BEFORE a
    // signature exists (signing non-canonical bytes is a silent
    // failure, not a late one).
    assert_eq!(
        signing_prefix_of(&RootDoc {
            seq: 0,
            sigs: vec![],
            ..seq1()
        }),
        Err(EncodeRootError::SeqZero)
    );
}

#[test]
fn decoder_rejects_the_structural_rules() {
    let good = enc(&seq1());
    // Wrong object type.
    let mut wrong = envelope(ObjectType::Sheaf);
    wrong.extend_from_slice(good.get(10..).unwrap_or_else(|| panic!("slice")));
    assert_eq!(
        decode_root(&wrong),
        Err(DecodeError::Invalid {
            what: "object type (want root)"
        })
    );
    // Trailing bytes.
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        decode_root(&trailing),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );
    // seq 0.
    let mut zero = good.clone();
    let seq_at = 10 + 1 + "granary-test".len();
    zero.get_mut(seq_at..seq_at + 8)
        .unwrap_or_else(|| panic!("slice"))
        .copy_from_slice(&0u64.to_be_bytes());
    assert_eq!(
        decode_root(&zero),
        Err(DecodeError::Invalid {
            what: "root seq zero"
        })
    );
    // An unregistered signature algorithm is refused BY NAME.
    let alg_at = good.len() - ROOT_SIG_SLOT_LEN + KEY_ID_LEN;
    let mut alg = good.clone();
    *alg.get_mut(alg_at).unwrap_or_else(|| panic!("slice")) = 0x02;
    assert_eq!(
        decode_root(&alg),
        Err(DecodeError::Invalid {
            what: "root signature alg (v1 accepts only 0x01 Ed25519)"
        })
    );
    // sig_len must be exactly 64 under alg 0x01.
    let mut len63 = good.clone();
    len63
        .get_mut(alg_at + 1..alg_at + 3)
        .unwrap_or_else(|| panic!("slice"))
        .copy_from_slice(&63u16.to_be_bytes());
    assert_eq!(
        decode_root(&len63),
        Err(DecodeError::Invalid {
            what: "root signature sig_len (Ed25519 requires 64)"
        })
    );
    // sig_count 0.
    let count_at = good.len() - ROOT_SIG_SLOT_LEN - 1;
    let mut none = good.clone();
    *none.get_mut(count_at).unwrap_or_else(|| panic!("slice")) = 0;
    assert_eq!(
        decode_root(&none),
        Err(DecodeError::Invalid {
            what: "root sig_count zero"
        })
    );
    // sig_count 3.
    let mut three = good;
    *three.get_mut(count_at).unwrap_or_else(|| panic!("slice")) = 3;
    assert_eq!(
        decode_root(&three),
        Err(DecodeError::CapExceeded {
            what: "root sig_count",
            got: 3,
            cap: u64::from(ROOT_MAX_SIGS),
        })
    );
}

/// The published root mirrors the chunker identity tuple — the contract
/// is pinned in the VOLUME, not only in the local-store marker.
/// Equality with the local rendering is a READ-TIME COMPATIBILITY
/// policy — a root carrying another tuple still decodes.
#[test]
fn chunker_spec_mirrors_the_local_rendering_but_is_not_format_validated() {
    let doc = seq1();
    assert_eq!(doc.chunker_spec, crate::thresh::CHUNKER_SPEC.to_string());
    assert_eq!(
        doc.chunker_spec,
        "fastcdc-v2020/4.0.1 min=131072 avg=262144 max=2097152 nl=1"
    );
    let other = RootDoc {
        chunker_spec: "fastcdc-v2020/9.9.9 min=1 avg=2 max=3 nl=0".to_owned(),
        ..seq1()
    };
    let bytes = enc(&other);
    assert_eq!(decode_root(&bytes), Ok(other));
}

// ------------------------------------------------ identity and link checks

fn seq1_bytes() -> Vec<u8> {
    enc(&seq1())
}

#[test]
fn decode_expected_accepts_the_root_of_that_volume_and_seq() {
    let doc = decode_expected(&seq1_bytes(), "granary-test", 1).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(doc, seq1());
}

#[test]
fn decode_expected_refuses_bytes_that_do_not_decode() {
    assert!(matches!(
        decode_expected(b"not a root", "granary-test", 1),
        Err(RootIdentityError::Decode(_))
    ));
}

#[test]
fn decode_expected_refuses_another_volume() {
    assert_eq!(
        decode_expected(&seq1_bytes(), "other-vol", 1),
        Err(RootIdentityError::VolumeMismatch {
            expected: "other-vol".to_owned(),
            found: "granary-test".to_owned(),
        })
    );
}

#[test]
fn decode_expected_refuses_another_seq() {
    assert_eq!(
        decode_expected(&seq1_bytes(), "granary-test", 2),
        Err(RootIdentityError::SeqMismatch {
            expected: 2,
            found: 1,
        })
    );
}

#[test]
fn decode_expected_checks_the_volume_before_the_seq() {
    assert!(matches!(
        decode_expected(&seq1_bytes(), "other-vol", 9),
        Err(RootIdentityError::VolumeMismatch { .. })
    ));
}

#[test]
fn link_accepts_the_ancestor_the_child_names() {
    let bytes = seq1_bytes();
    let doc = check_link(Some(GrainId::of(&bytes)), &bytes, "granary-test", 1)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(doc.seq, 1);
}

#[test]
fn link_checks_no_signature_on_the_ancestor() {
    // The signature slots here are arbitrary bytes no key made, and then
    // one is corrupted: the link is about content, and only the head is
    // authenticated.
    let mut bytes = seq1_bytes();
    if let Some(last) = bytes.last_mut() {
        *last ^= 0x01;
    }
    assert!(check_link(Some(GrainId::of(&bytes)), &bytes, "granary-test", 1).is_ok());
}

#[test]
fn link_refuses_a_parent_that_is_not_the_stored_bytes_id() {
    let bytes = seq1_bytes();
    let wrong = GrainId::of(b"some other root");
    assert_eq!(
        check_link(Some(wrong), &bytes, "granary-test", 1),
        Err(LinkError::ParentMismatch {
            expected: GrainId::of(&bytes),
            found: Some(wrong),
        })
    );
}

#[test]
fn link_refuses_a_child_that_names_no_parent() {
    let bytes = seq1_bytes();
    assert_eq!(
        check_link(None, &bytes, "granary-test", 1),
        Err(LinkError::ParentMismatch {
            expected: GrainId::of(&bytes),
            found: None,
        })
    );
}

#[test]
fn link_checks_the_parent_before_it_decodes() {
    // Garbage bytes with the wrong parent: the parent comparison is the
    // reported failure, not the decode.
    assert!(matches!(
        check_link(Some(GrainId::of(b"x")), b"not a root", "granary-test", 1),
        Err(LinkError::ParentMismatch { .. })
    ));
}

#[test]
fn link_refuses_ancestor_bytes_that_do_not_decode() {
    let garbage = b"not a root".to_vec();
    assert!(matches!(
        check_link(Some(GrainId::of(&garbage)), &garbage, "granary-test", 1),
        Err(LinkError::Identity(RootIdentityError::Decode(_)))
    ));
}

#[test]
fn link_refuses_an_ancestor_of_another_volume() {
    // Hash-linked from above, so the parent id matches: the volume is the
    // only thing wrong.
    let bytes = seq1_bytes();
    assert_eq!(
        check_link(Some(GrainId::of(&bytes)), &bytes, "other-vol", 1),
        Err(LinkError::Identity(RootIdentityError::VolumeMismatch {
            expected: "other-vol".to_owned(),
            found: "granary-test".to_owned(),
        }))
    );
}

#[test]
fn link_refuses_an_ancestor_at_another_seq() {
    let bytes = enc(&seq2(GrainId::of(b"one")));
    assert_eq!(
        check_link(Some(GrainId::of(&bytes)), &bytes, "granary-test", 1),
        Err(LinkError::Identity(RootIdentityError::SeqMismatch {
            expected: 1,
            found: 2,
        }))
    );
}
