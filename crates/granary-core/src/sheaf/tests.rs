// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::sheaf` — the sheaf format v1 — the commit record.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;
use crate::encoding::{DecodeError, ObjectType, envelope};
use crate::hash::GrainId;

fn gid(s: &str) -> GrainId {
    GrainId::of(s.as_bytes())
}

fn ts() -> Timestamp {
    Timestamp {
        secs: 1_760_000_000,
        nanos: 123_456_789,
    }
}

fn first() -> SheafDoc {
    SheafDoc {
        parent: None,
        manifest_root: gid("manifest-1"),
        timestamp: ts(),
        ops: vec![SheafOp::PublishTree],
    }
}

fn chained(parent: GrainId) -> SheafDoc {
    SheafDoc {
        parent: Some(parent),
        manifest_root: gid("manifest-2"),
        timestamp: Timestamp {
            secs: 1_760_000_060,
            nanos: 0,
        },
        ops: vec![SheafOp::PublishTree],
    }
}

fn enc(doc: &SheafDoc) -> Vec<u8> {
    encode_sheaf(doc).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn constants_are_frozen() {
    assert_eq!(SHEAF_MAX_OPS, 1024);
    assert_eq!(OP_TAG_PUBLISH_TREE, 0x01);
    assert_eq!(NANOS_PER_SEC, 1_000_000_000);
    assert_eq!(PRESENCE_ABSENT, 0x00);
    assert_eq!(PRESENCE_PRESENT, 0x01);
    // A3: SHEAF_FIXED_HEADER_LEN was
    // pinned by nothing — it appears only inside a `const _` assert
    // that a `+1` still satisfies, and this test's neighbours never
    // named it. It is `pub`, so granary-store will size against it.
    assert_eq!(SHEAF_FIXED_HEADER_LEN, 60);
    // Cross-checked against a DERIVED value, not only the literal
    // above: the fixed header is exactly the encoded first-commit
    // sheaf minus its one variable-width part (the op bytes), so the
    // constant and the encoder cannot drift apart from each other
    // even if both drift from 60 together.
    let doc = first();
    assert_eq!(
        SHEAF_FIXED_HEADER_LEN,
        encode_sheaf(&doc).unwrap_or_else(|e| panic!("{e}")).len() - doc.ops.len()
    );
}

#[test]
fn roundtrip_is_canonical_both_parent_shapes() {
    let a = enc(&first());
    // envelope 10 + presence 1 + manifest_root 33 + secs 8 + nanos 4
    // + op_count 4 + one op tag 1.
    assert_eq!(a.len(), 61);
    assert_eq!(decode_sheaf(&a), Ok(first()));
    assert_eq!(enc(&decode_sheaf(&a).unwrap_or_else(|e| panic!("{e}"))), a);

    let b = enc(&chained(GrainId::of(&a)));
    assert_eq!(b.len(), 61 + 33);
    assert_eq!(decode_sheaf(&b), Ok(chained(GrainId::of(&a))));
    assert_eq!(enc(&decode_sheaf(&b).unwrap_or_else(|e| panic!("{e}"))), b);

    // The presence byte is the ONLY parent discriminator: no
    // all-zeros sentinel id anywhere.
    assert_eq!(a.get(10), Some(&PRESENCE_ABSENT));
    assert_eq!(b.get(10), Some(&PRESENCE_PRESENT));
}

/// Forward shape: the DECODER takes 1..=cap
/// registered ops even though v1's publish path emits exactly one.
#[test]
fn decoder_accepts_multiple_registered_ops() {
    let doc = SheafDoc {
        ops: vec![SheafOp::PublishTree, SheafOp::PublishTree],
        ..first()
    };
    let bytes = enc(&doc);
    assert_eq!(decode_sheaf(&bytes), Ok(doc));
}

#[test]
fn encoder_refuses_what_the_decoder_rejects() {
    assert_eq!(
        encode_sheaf(&SheafDoc {
            ops: vec![],
            ..first()
        }),
        Err(EncodeSheafError::NoOps)
    );
    assert!(matches!(
        encode_sheaf(&SheafDoc {
            ops: vec![SheafOp::PublishTree; SHEAF_MAX_OPS as usize + 1],
            ..first()
        }),
        Err(EncodeSheafError::TooManyOps { .. })
    ));
    assert_eq!(
        encode_sheaf(&SheafDoc {
            timestamp: Timestamp {
                secs: 0,
                nanos: NANOS_PER_SEC
            },
            ..first()
        }),
        Err(EncodeSheafError::NanosOverflow {
            nanos: NANOS_PER_SEC
        })
    );
}

/// A5 (sheaf-ops half): the ENCODER's own
/// accept side at `SHEAF_MAX_OPS` was unpinned — flipping
/// `encode_sheaf`'s `>` to `>=` ships green, because
/// `encoder_refuses_what_the_decoder_rejects` above only tests
/// `SHEAF_MAX_OPS + 1`. The DECODER's accept-at-cap IS pinned
/// (`sheaf_rejects_op_count_zero_and_over_cap`,
/// `root_sheaf_rejects.rs`), so a narrowed encoder cap would invert
/// the encoder-refuses-what-the-decoder-rejects rule at exactly this
/// boundary. Exactly the cap, through the real encoder, round-trips.
#[test]
fn encoder_accepts_ops_at_the_cap() {
    let doc = SheafDoc {
        ops: vec![SheafOp::PublishTree; SHEAF_MAX_OPS as usize],
        ..first()
    };
    let bytes = enc(&doc);
    assert_eq!(decode_sheaf(&bytes), Ok(doc));
}

#[test]
fn decoder_rejects_each_rule() {
    let good = enc(&first());

    // nanos == 1e9 (nsec >= 10^9 rejected at parse).
    let mut nanos = good.clone();
    let at = 10 + 1 + 33 + 8;
    nanos
        .get_mut(at..at + 4)
        .unwrap_or_else(|| panic!("slice"))
        .copy_from_slice(&NANOS_PER_SEC.to_be_bytes());
    assert_eq!(
        decode_sheaf(&nanos),
        Err(DecodeError::Invalid {
            what: "timestamp nanos (>= 1e9)"
        })
    );

    // Unregistered op tag.
    let mut tag = good.clone();
    let last = tag.len() - 1;
    *tag.get_mut(last).unwrap_or_else(|| panic!("slice")) = 0x02;
    assert_eq!(
        decode_sheaf(&tag),
        Err(DecodeError::Invalid {
            what: "sheaf op tag (unregistered)"
        })
    );

    // op_count 0 and over-cap.
    let count_at = 10 + 1 + 33 + 8 + 4;
    let mut zero = good.clone();
    zero.get_mut(count_at..count_at + 4)
        .unwrap_or_else(|| panic!("slice"))
        .copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        decode_sheaf(&zero),
        Err(DecodeError::Invalid {
            what: "sheaf op_count zero"
        })
    );
    let mut over = good.clone();
    over.get_mut(count_at..count_at + 4)
        .unwrap_or_else(|| panic!("slice"))
        .copy_from_slice(&(SHEAF_MAX_OPS + 1).to_be_bytes());
    assert_eq!(
        decode_sheaf(&over),
        Err(DecodeError::CapExceeded {
            what: "sheaf op_count",
            got: u64::from(SHEAF_MAX_OPS) + 1,
            cap: u64::from(SHEAF_MAX_OPS),
        })
    );

    // Presence byte 0x02 (neither absent nor present).
    let mut presence = good.clone();
    *presence.get_mut(10).unwrap_or_else(|| panic!("slice")) = 0x02;
    assert_eq!(
        decode_sheaf(&presence),
        Err(DecodeError::Invalid {
            what: "sheaf parent presence byte"
        })
    );

    // Truncated id after presence 0x01.
    let mut truncated = good.clone();
    *truncated.get_mut(10).unwrap_or_else(|| panic!("slice")) = PRESENCE_PRESENT;
    assert_eq!(decode_sheaf(&truncated), Err(DecodeError::Truncated));

    // Trailing bytes.
    let mut trailing = good.clone();
    trailing.push(0xAA);
    assert_eq!(
        decode_sheaf(&trailing),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );

    // Wrong object type in a well-formed envelope.
    let mut wrong = envelope(ObjectType::Bin);
    wrong.extend_from_slice(good.get(10..).unwrap_or_else(|| panic!("slice")));
    assert_eq!(
        decode_sheaf(&wrong),
        Err(DecodeError::Invalid {
            what: "object type (want sheaf)"
        })
    );
}
