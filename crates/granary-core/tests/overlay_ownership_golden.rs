// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

mod common;
use granary_core::overlay_ownership::{self as codec, CHECK_CONTEXT};
use std::fmt::Write as _;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").unwrap_or_else(|e| panic!("fixture formatting: {e}"));
        text
    })
}
fn check(bytes: &mut [u8]) {
    let end = bytes.len() - 32;
    let sum = blake3::derive_key(
        CHECK_CONTEXT,
        bytes.get(..end).unwrap_or_else(|| panic!("fixture prefix")),
    );
    bytes
        .get_mut(end..)
        .unwrap_or_else(|| panic!("fixture suffix"))
        .copy_from_slice(&sum);
}

#[test]
fn overlay_ownership_goldens_and_rejects() {
    let c = granary_core::testkit::ownership_fixture();
    let canonical = codec::encode(&c).unwrap();
    let mut text = String::from(
        "# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>\n# SPDX-License-Identifier: Apache-2.0\n",
    );
    writeln!(text, "unowned\t{}", hex(&canonical)).unwrap();
    let mut rejects = String::from(
        "# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>\n# SPDX-License-Identifier: Apache-2.0\n",
    );
    let mut cases = 0;
    for (offset, value, reason) in [(0, b'X', "magic"), (9, 2, "version"), (11, 1, "flags")] {
        let mut bytes = canonical.clone();
        bytes[offset] = value;
        check(&mut bytes);
        assert_eq!(
            codec::decode(&bytes).unwrap_err().to_string(),
            format!("ownership refused: {reason}")
        );
        writeln!(rejects, "{reason}\t{}", hex(&bytes)).unwrap();
        cases += 1;
    }
    assert_eq!(cases, 3);
    assert_eq!(
        codec::encode(&codec::decode(&canonical).unwrap()).unwrap(),
        canonical
    );
    let vectors = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    common::assert_golden(&vectors.join("overlay_ownership_v1.tsv"), &text);
    common::assert_golden(&vectors.join("overlay_ownership_v1_rejects.tsv"), &rejects);
    if std::env::var_os("GRANARY_REGEN_VECTORS").is_some() {
        let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus/overlay_ownership_decode");
        std::fs::write(corpus.join("unowned"), canonical).unwrap();
    }
}
