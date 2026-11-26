// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::manifest::name` — name and symlink-target validation.
//!
//! Out-of-line: `granary-core`'s non-test artifact has workspace consumers
//! (`granary-bench`, `granary-cli`, `granary-client`, `granary-conformance`,
//! `granary-fuse`, `granary-server`, `granary-sim`, `granary-store`, `granary-vfs`),
//! so the module's own tests move out of the parent file while it keeps its path and
//! declares `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

#[test]
fn accepts_exact_bytes_including_non_utf8() {
    for ok in [
        b"a".as_slice(),
        b"Makefile",
        b"caf\xc3\xa9",       // NFC
        b"cafe\xcc\x81",      // NFD — distinct name, both legal
        b"\xff\xfe not utf8", // non-UTF-8 accepted
        b"granny",            // 'gran' without the dot prefix is fine
        &[b'x'; 255],
    ] {
        Name::new(ok.to_vec()).unwrap_or_else(|e| panic!("{e} for {ok:?}"));
    }
}

#[test]
fn rejects_every_d12_rule() {
    assert_eq!(Name::new(b"".to_vec()), Err(NameError::Empty));
    assert_eq!(
        Name::new(vec![b'x'; 256]),
        Err(NameError::TooLong { len: 256 })
    );
    assert_eq!(Name::new(b"a\0b".to_vec()), Err(NameError::Nul));
    assert_eq!(Name::new(b"a/b".to_vec()), Err(NameError::Slash));
    assert_eq!(Name::new(b".".to_vec()), Err(NameError::Dot));
    assert_eq!(Name::new(b"..".to_vec()), Err(NameError::DotDot));
    assert_eq!(Name::new(b".gran".to_vec()), Err(NameError::GranPrefix));
    assert_eq!(
        Name::new(b".granite.txt".to_vec()),
        Err(NameError::GranPrefix)
    );
    // '...' and '.g' are fine (only exact '.'/'..' and the prefix die).
    Name::new(b"...".to_vec()).unwrap();
    Name::new(b".g".to_vec()).unwrap();
}

#[test]
fn ord_is_memcmp() {
    // Derived Ord on Vec<u8> is bytewise — pin it, and pin the
    // anti-git property: "foo" < "foo-x" (git would sort the dir
    // 'foo' AFTER 'foo-x'; we never do).
    let foo = Name::new(b"foo".to_vec()).unwrap();
    let foo_dash = Name::new(b"foo-x".to_vec()).unwrap();
    let foo_dot = Name::new(b"foo.txt".to_vec()).unwrap();
    let mut v = vec![foo_dot.clone(), foo_dash.clone(), foo.clone()];
    v.sort();
    assert_eq!(v, vec![foo, foo_dash, foo_dot]);

    // The trio above sorts IDENTICALLY under a length-first
    // ordering, so on its own it does not pin memcmp at all. These
    // pairs do: memcmp and length-first DISAGREE on each, and each
    // is checked against `<[u8]>::cmp` over the same bytes.
    for (shorter_greater, longer_lesser) in [
        (b"z".as_slice(), b"ab".as_slice()),
        (b"\xff".as_slice(), b"aa".as_slice()), // non-UTF-8 high byte
        (b"b".as_slice(), b"aaa".as_slice()),
    ] {
        let a = Name::new(shorter_greater.to_vec()).unwrap();
        let b = Name::new(longer_lesser.to_vec()).unwrap();
        assert_eq!(
            a.cmp(&b),
            shorter_greater.cmp(longer_lesser),
            "Name's Ord must BE <[u8]>::cmp"
        );
        assert!(b < a, "longer-but-bytewise-lesser must sort FIRST");
    }
}

#[test]
fn symlink_target_rules() {
    SymlinkTarget::new(b"../rel/\xff\xfe".to_vec()).unwrap(); // non-UTF-8 + dotdot fine
    SymlinkTarget::new(vec![b'x'; 4096]).unwrap();
    assert_eq!(SymlinkTarget::new(vec![]), Err(SymlinkTargetError::Empty));
    assert_eq!(
        SymlinkTarget::new(vec![b'x'; 4097]),
        Err(SymlinkTargetError::TooLong { len: 4097 })
    );
    assert_eq!(
        SymlinkTarget::new(b"a\0".to_vec()),
        Err(SymlinkTargetError::Nul)
    );
}
