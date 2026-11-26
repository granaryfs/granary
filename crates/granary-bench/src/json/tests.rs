// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::json` — the ~90-line JSON writer's formatting and
//! escaping behaviour.
//!
//! Out-of-line: `granary-bench`'s non-test artifact has its own
//! `[[bin]]` (`granary-bench`) and its own `tests/` directory
//! (`crates/granary-bench/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

#[test]
fn strings_are_escaped() {
    let mut out = String::new();
    Json::s("a\"b\\c\nd\te\u{1}").write(&mut out);
    assert_eq!(out, "\"a\\\"b\\\\c\\nd\\te\\u0001\"");
}

#[test]
fn byte_counts_stay_exact() {
    let mut out = String::new();
    Json::UInt(1_849_207_377).write(&mut out);
    assert_eq!(out, "1849207377");
}

/// Above 2^53 an `f64` round-trip stops being lossless, so these are
/// the values that actually pin integer exactness.
#[test]
fn integers_above_two_to_the_fifty_third_stay_exact() {
    let mut out = String::new();
    Json::UInt(u64::MAX).write(&mut out);
    assert_eq!(out, "18446744073709551615");

    let mut out = String::new();
    Json::UInt((1 << 53) + 1).write(&mut out);
    assert_eq!(out, "9007199254740993");

    let mut out = String::new();
    Json::Int(i64::MIN).write(&mut out);
    assert_eq!(out, "-9223372036854775808");
}

/// NEGATIVE: a NaN or infinity must not smuggle an unparseable
/// token into a committed results file.
#[test]
fn non_finite_numbers_become_null() {
    let mut out = String::new();
    Json::Arr(vec![
        Json::Num(f64::NAN),
        Json::Num(f64::INFINITY),
        Json::Num(1.5),
    ])
    .write(&mut out);
    assert!(out.contains("null"), "{out}");
    assert!(!out.contains("NaN"), "{out}");
    assert!(!out.contains("inf"), "{out}");
    assert!(out.contains("1.500000"), "{out}");
}

/// NEGATIVE, per value: the array form above is satisfied by the NaN
/// alone, so each non-finite value is pinned separately here. `1e999`
/// is the dangerous mutant — real parsers accept it as infinity.
#[test]
fn every_non_finite_value_becomes_null() {
    for v in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let mut out = String::new();
        Json::Num(v).write(&mut out);
        assert_eq!(out, "null", "{v}");
    }
}

#[test]
fn objects_keep_insertion_order() {
    let v = Json::Obj(vec![
        ("z".to_owned(), Json::UInt(1)),
        ("a".to_owned(), Json::UInt(2)),
    ]);
    let text = v.to_pretty();
    let z = text.find("\"z\"").expect("z present");
    let a = text.find("\"a\"").expect("a present");
    assert!(z < a, "{text}");
}

#[test]
fn empty_containers_are_compact() {
    assert_eq!(Json::Arr(vec![]).to_pretty().trim(), "[]");
    assert_eq!(Json::Obj(vec![]).to_pretty().trim(), "{}");
}

mod parse_tests;
