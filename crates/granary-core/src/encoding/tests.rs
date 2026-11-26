// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::encoding` — the object envelope and strict decode cursor for hashed formats.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

#[test]
fn registry_closed() {
    // Exhaustive: adding a variant without extending ALL/from_tag
    // fails to compile here.
    for ty in ObjectType::ALL {
        match ty {
            ObjectType::DirLeaf
            | ObjectType::DirInterior
            | ObjectType::GrainListLeaf
            | ObjectType::GrainListIndex
            | ObjectType::Bin
            | ObjectType::BinmapIndex
            | ObjectType::BinTable
            | ObjectType::BinmapShard
            | ObjectType::Root
            | ObjectType::Sheaf => {
                assert_eq!(ObjectType::from_tag(ty.tag()), Ok(*ty));
            }
        }
    }
    assert_eq!(
        ObjectType::from_tag(0x00),
        Err(DecodeError::UnknownObjectType { tag: 0x00 })
    );

    // Tags are FROZEN — never reused, never renumbered.
    // The roundtrip loop above is blind to a CONSISTENT permutation
    // (e.g. swapping Root/Sheaf or BinTable/BinmapShard everywhere):
    // tag() -> from_tag() still roundtrips under a swap, so pin every
    // tag to its literal numeric value, independent of from_tag.
    assert_eq!(ObjectType::DirLeaf.tag(), 0x01);
    assert_eq!(ObjectType::DirInterior.tag(), 0x02);
    assert_eq!(ObjectType::GrainListLeaf.tag(), 0x03);
    assert_eq!(ObjectType::GrainListIndex.tag(), 0x04);
    assert_eq!(ObjectType::Bin.tag(), 0x05);
    assert_eq!(ObjectType::BinmapIndex.tag(), 0x06);
    assert_eq!(ObjectType::BinTable.tag(), 0x07);
    assert_eq!(ObjectType::BinmapShard.tag(), 0x08);
    assert_eq!(ObjectType::Root.tag(), 0x09);
    assert_eq!(ObjectType::Sheaf.tag(), 0x0A);

    // `ALL` covers EXACTLY the ten registered tags. Deleting a
    // variant from `ALL` leaves the loop above green (it just checks
    // fewer variants), so pin the count and the tag SET separately
    // from the loop that walks it, and confirm from_tag accepts
    // every tag ALL claims to cover.
    assert_eq!(ObjectType::ALL.len(), 10);
    let mut all_tags: Vec<u8> = ObjectType::ALL.iter().map(|t| t.tag()).collect();
    all_tags.sort_unstable();
    assert_eq!(all_tags, (0x01u8..=0x0A).collect::<Vec<u8>>());
    for tag in 0x01u8..=0x0A {
        assert!(
            ObjectType::from_tag(tag).is_ok(),
            "from_tag must accept every tag ALL claims to cover: {tag:#04x}"
        );
    }

    // Aliasing closure: everything above proves the ten
    // registered tags are ACCEPTED; it says nothing about any OTHER
    // byte. An extra `from_tag` arm mapping e.g. 0x0B onto an
    // existing variant — two wire tags decoding to the same
    // ObjectType — would satisfy every assertion above, since none
    // of them ever look past the ten tags they already expect to
    // find. Close it exhaustively over the whole u8 space: every
    // tag outside 0x01..=0x0A must be REJECTED, and every accepted
    // tag must round-trip back to its own numeric value via
    // `.tag()` — the round-trip is what actually rules out
    // aliasing (a second tag mapping to an already-covered variant
    // would still individually decode "ok", but could never
    // round-trip to ITS OWN tag if `.tag()` reports the original).
    for t in 0u8..=255 {
        let expect_ok = (0x01..=0x0A).contains(&t);
        assert_eq!(
            ObjectType::from_tag(t).is_ok(),
            expect_ok,
            "from_tag({t:#04x}) accept/reject must match the registered range"
        );
        if expect_ok {
            let ty = ObjectType::from_tag(t).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(ty.tag(), t, "from_tag({t:#04x}) must round-trip to itself");
        }
    }
}

#[test]
fn be_roundtrip_and_order() {
    // BE property: byte order == numeric order.
    let pairs = [(1u64, 2u64), (255, 256), (u64::MAX - 1, u64::MAX)];
    for (lo, hi) in pairs {
        assert!(lo.to_be_bytes() < hi.to_be_bytes());
    }
    let mut c = Cursor::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    assert_eq!(c.u64(), Ok(0x0102_0304_0506_0708));
    c.finish().expect("consumed exactly");
}

#[test]
fn reader_widths_are_exact() {
    // Every reader consumes EXACTLY its width. Drain one buffer
    // through u8/u16/u32/u64 and let `finish` prove the arithmetic:
    // a reader taking the wrong number of bytes is otherwise
    // INVISIBLE to the suite (the error-path tests stay green for
    // any width >= 2, and `u32 -> take(8)` was a real corruption
    // during the magic-rename sweep, caught by review rather
    // than by a test).
    let mut c = Cursor::new(&[
        0xAB, 0x01, 0x02, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]);
    assert_eq!(c.u8(), Ok(0xAB));
    assert_eq!(c.u16(), Ok(0x0102));
    assert_eq!(c.u32(), Ok(0x0102_0304));
    assert_eq!(c.u64(), Ok(0x0102_0304_0506_0708));
    c.finish().expect("consumed exactly");
}

#[test]
fn cursor_is_strict() {
    let mut c = Cursor::new(&[0x01]);
    assert_eq!(c.u32(), Err(DecodeError::Truncated));
    let c = Cursor::new(&[0x01]);
    assert_eq!(c.finish(), Err(DecodeError::TrailingBytes { remaining: 1 }));
}

#[test]
fn envelope_roundtrip_and_rejects() {
    // The frozen magic, pinned INDEPENDENTLY of the roundtrip
    // below (encode+decode share the constant, so the roundtrip
    // alone stays green under any magic change): "GRANARY\0".
    assert_eq!(MAGIC, [0x47, 0x52, 0x41, 0x4E, 0x41, 0x52, 0x59, 0x00]);
    let mut bytes = envelope(ObjectType::DirLeaf);
    bytes.push(0xAA); // one body byte
    let (ty, mut c) = open_envelope(&bytes).expect("valid envelope");
    assert_eq!(ty, ObjectType::DirLeaf);
    assert_eq!(c.u8(), Ok(0xAA));
    c.finish().expect("body consumed");

    // 7 bytes: one short of the 8-byte magic read — Truncated, not
    // BadMagic (the magic comparison never happens).
    assert_eq!(
        open_envelope(b"GRANARY").map(|_| ()),
        Err(DecodeError::Truncated)
    );
    // 8 wrong magic bytes + type/version bytes — BadMagic.
    assert_eq!(
        open_envelope(b"XXXXXXXX\x01\x01").map(|_| ()),
        Err(DecodeError::BadMagic)
    );
    assert_eq!(
        open_envelope(b"GRANARY\0\x00\x01").map(|_| ()),
        Err(DecodeError::UnknownObjectType { tag: 0x00 })
    );
    assert_eq!(
        open_envelope(b"GRANARY\0\x01\x02").map(|_| ()),
        Err(DecodeError::UnknownVersion { version: 0x02 })
    );
}
