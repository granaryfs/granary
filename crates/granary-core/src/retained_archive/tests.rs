// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn settled_archive_names_are_canonical_and_malformed_claimants_refuse() {
    let bytes = b"vol.settled-00000000000000000000000000000000.sub";
    assert_eq!(
        crate::hash::GrainId::of(bytes).to_string(),
        "blake3:3a9fa91302ce07a16088430ee67b685eaecc1c5e84df42167d55feceac6ad30f"
    );
    let mut cases = 0;
    for (name, valid) in [
        (bytes.as_slice(), true),
        (b"vol.settled-000.sub".as_slice(), false),
        (
            b"vol.settled-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.sub".as_slice(),
            false,
        ),
        (
            b"bad/vol.settled-00000000000000000000000000000000.sub".as_slice(),
            false,
        ),
    ] {
        let result = ArchiveName::parse(name);
        if valid {
            assert_eq!(
                result
                    .as_ref()
                    .ok()
                    .and_then(|n| n.as_ref())
                    .map(ArchiveName::file_name)
                    .as_deref(),
                std::str::from_utf8(name).ok(),
                "{result:?}"
            );
        } else {
            assert_eq!(
                result.err().map(|e| e.to_string()).as_deref(),
                Some("malformed retained archive name")
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn reserved_names_are_strict_and_disjoint() {
    for name in [
        b"vol.sub".as_slice(),
        b"vol.sub.tmp-1",
        b"unrelated",
        b"\xff",
    ] {
        assert_eq!(ArchiveName::parse(name), Ok(None));
    }
    let corpus =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/archive-name");
    let mut rejects = 0;
    for entry in std::fs::read_dir(corpus).unwrap() {
        let entry = entry.unwrap();
        let bytes = std::fs::read(entry.path()).unwrap();
        if entry.file_name().to_str().unwrap().starts_with("reject-") {
            assert_eq!(ArchiveName::parse(&bytes), Err(InvalidArchiveName));
            rejects += 1;
        } else if let Some(name) = ArchiveName::parse(&bytes).unwrap() {
            assert_eq!(name.file_name().as_bytes(), bytes);
        }
    }
    assert!(rejects >= 12);
    assert!(is_scope_digest(
        b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ));
    assert!(!is_scope_digest(
        b"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
    ));
}
