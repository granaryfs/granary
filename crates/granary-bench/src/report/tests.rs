// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::report` — the result-record completeness gates on
//! `RunMetadata::new` and `write_record`.
//!
//! Out-of-line: `granary-bench`'s non-test artifact has its own
//! `[[bin]]` (`granary-bench`) and its own `tests/` directory
//! (`crates/granary-bench/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

fn full() -> Vec<(String, String)> {
    REQUIRED_METADATA
        .iter()
        .map(|k| ((*k).to_owned(), "value".to_owned()))
        .collect()
}

#[test]
fn a_complete_block_is_accepted_in_field_order() {
    let m = RunMetadata::new(&full()).expect("complete");
    let rendered = m.to_json().to_pretty();
    let first = REQUIRED_METADATA.first().expect("non-empty");
    let last = REQUIRED_METADATA.last().expect("non-empty");
    let a = rendered.find(first).expect("first field");
    let b = rendered.find(last).expect("last field");
    assert!(a < b, "{rendered}");
}

/// NEGATIVE: a record missing its provenance must be impossible to
/// construct, not merely discouraged.
#[test]
fn a_missing_field_is_refused() {
    let mut pairs = full();
    pairs.retain(|(k, _)| k != "granary_git_sha");
    assert_eq!(
        RunMetadata::new(&pairs),
        Err(MetadataError::Missing("granary_git_sha"))
    );
}

/// NEGATIVE: an empty string is not provenance.
#[test]
fn an_empty_field_is_refused() {
    let mut pairs = full();
    for (k, v) in &mut pairs {
        if k == "machine" {
            *v = "   ".to_owned();
        }
    }
    assert_eq!(
        RunMetadata::new(&pairs),
        Err(MetadataError::Empty("machine"))
    );
}

/// NEGATIVE: the token binding must not be defeatable by appending a
/// second `controls` key — most JSON parsers take the last value, so a
/// genuine token could otherwise ship substituted evidence.
#[test]
fn a_body_supplying_a_reserved_field_is_refused() {
    for reserved in RESERVED_FIELDS {
        let err = super::reserved_check(&[(reserved.to_owned(), Json::Null)])
            .expect_err("reserved field must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}

/// NEGATIVE: a body that repeats its own key is equally ambiguous.
#[test]
fn a_body_repeating_a_key_is_refused() {
    let err = super::reserved_check(&[
        ("arms".to_owned(), Json::Null),
        ("arms".to_owned(), Json::Null),
    ])
    .expect_err("duplicate body key must be refused");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

/// NEGATIVE: a typo'd key must not silently become a new schema.
#[test]
fn an_unknown_field_is_refused() {
    let mut pairs = full();
    pairs.push(("dataset_name".to_owned(), "W1".to_owned()));
    assert_eq!(
        RunMetadata::new(&pairs),
        Err(MetadataError::Unknown("dataset_name".to_owned()))
    );
}
