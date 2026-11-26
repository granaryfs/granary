// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::compare` — `granconf compare`'s sorted merge-join over
//! two dumps' rows, the divergence classification, and the
//! `--expect` mode that fails a dead or empty mount rather than
//! passing vacuously.
//!
//! Out-of-line: `granary-conformance`'s non-test artifact
//! has its own `[[bin]]` (`granconf`) and its own `tests/`
//! directory (`crates/granary-conformance/tests/cli.rs`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)] mod
//! tests;` — the sibling-directory form.

use super::{Class, check_expect, check_identical, merge};
use crate::row::{DType, Kind, Payload, new_row};

fn file(path: &str, size: u64, exec: bool, hex: char) -> crate::row::Row {
    new_row(
        path.as_bytes().to_vec(),
        Kind::File,
        DType::File,
        Some(size),
        exec,
        Payload::Content(hex.to_string().repeat(64)),
    )
    .expect("valid row")
}

fn dir(path: &str) -> crate::row::Row {
    new_row(
        path.as_bytes().to_vec(),
        Kind::Dir,
        DType::Dir,
        None,
        false,
        Payload::None,
    )
    .expect("valid row")
}

fn symlink(path: &str, target: &str, dtype: DType) -> crate::row::Row {
    new_row(
        path.as_bytes().to_vec(),
        Kind::Symlink,
        dtype,
        None,
        false,
        Payload::Target(target.as_bytes().to_vec()),
    )
    .expect("valid row")
}

#[test]
fn identical_dumps_classify_every_row_as_equal_and_nothing_else() {
    let a = vec![file("a", 1, false, 'a'), dir("b")];
    let b = a.clone();
    let out = merge(&a, &b);
    assert!(out.iter().all(|d| d.class.is_none()), "{out:?}");
    assert_eq!(out.len(), 2);
}

#[test]
fn a_row_missing_on_one_side_classifies_as_presence_and_nothing_else_shifts() {
    let a = vec![
        file("a", 1, false, 'a'),
        file("m", 1, false, 'a'),
        file("z", 1, false, 'a'),
    ];
    let b = vec![file("a", 1, false, 'a'), file("z", 1, false, 'a')];
    let out = merge(&a, &b);
    let classes: Vec<Option<Class>> = out.iter().map(|d| d.class).collect();
    assert_eq!(
        classes,
        vec![None, Some(Class::Presence), None],
        "only the missing row 'm' should diverge, and only as presence: {out:?}"
    );
}

#[test]
fn precedence_picks_kind_over_size_when_both_differ() {
    let a = vec![file("x", 10, false, 'a')];
    let b = vec![dir("x")];
    let out = merge(&a, &b);
    assert_eq!(out[0].class, Some(Class::Kind));
}

#[test]
fn precedence_picks_size_over_content_when_both_differ() {
    let a = vec![file("x", 10, false, 'a')];
    let b = vec![file("x", 11, false, 'b')];
    let out = merge(&a, &b);
    assert_eq!(out[0].class, Some(Class::Size));
}

#[test]
fn precedence_picks_size_over_exec_when_both_differ() {
    let a = vec![file("x", 10, true, 'a')];
    let b = vec![file("x", 11, false, 'a')];
    let out = merge(&a, &b);
    assert_eq!(out[0].class, Some(Class::Size));
}

#[test]
fn precedence_picks_exec_over_content_when_both_differ() {
    let a = vec![file("x", 10, true, 'a')];
    let b = vec![file("x", 10, false, 'b')];
    let out = merge(&a, &b);
    assert_eq!(out[0].class, Some(Class::Exec));
}

#[test]
fn content_alone_diverging_classifies_as_content() {
    let a = vec![file("x", 10, false, 'a')];
    let b = vec![file("x", 10, false, 'b')];
    let out = merge(&a, &b);
    assert_eq!(out[0].class, Some(Class::Content));
}

#[test]
fn target_divergence_is_classified_before_dtype() {
    let a = vec![symlink("x", "one", DType::Symlink)];
    let b = vec![symlink("x", "two", DType::File)];
    let out = merge(&a, &b);
    assert_eq!(out[0].class, Some(Class::Target));

    let equal_target = vec![symlink("x", "one", DType::File)];
    let out = merge(&a, &equal_target);
    assert_eq!(out[0].class, Some(Class::Dtype));
}

#[test]
fn dtype_is_the_last_resort_when_every_other_field_agrees() {
    let a = new_row(
        b"x".to_vec(),
        Kind::File,
        DType::File,
        Some(1),
        false,
        Payload::Content("a".repeat(64)),
    )
    .unwrap();
    let mut b = a.clone();
    b.dtype = DType::Symlink; // a lying dtype, everything else honest
    let out = merge(&[a], &[b]);
    assert_eq!(out[0].class, Some(Class::Dtype));
}

#[test]
fn expect_refuses_when_a_second_class_also_diverges() {
    let a = vec![
        file("eq", 1, false, 'q'),
        file("x", 10, false, 'a'),
        file("y", 5, false, 'c'),
    ];
    let b = vec![
        file("eq", 1, false, 'q'),
        file("x", 10, false, 'b'),
        file("y", 6, false, 'c'),
    ];
    let out = merge(&a, &b);
    // x diverges as content, y diverges as size — two classes.
    let error = check_expect(&out, Class::Content)
        .expect_err("an equal row must not mask a second divergence class");
    assert!(
        error.contains("class size diverged too"),
        "the OTHER-class leg must refuse this input: {error}"
    );
}

#[test]
fn identical_dumps_pass_the_baseline_and_report_their_row_count() {
    let a = vec![file("x", 10, false, 'a'), file("y", 5, true, 'c')];
    let out = merge(&a, &a);
    assert_eq!(check_identical(&out), Ok(2));
}

#[test]
fn the_baseline_refuses_any_divergence_and_names_its_class() {
    // The defect this closes: a compare that prints DIVERGE lines and
    // still reports success, so a shell gate accepts a broken mount.
    let a = vec![file("x", 10, false, 'a'), file("y", 5, false, 'c')];
    let b = vec![file("x", 10, false, 'b'), file("y", 5, false, 'c')];
    let out = merge(&a, &b);
    let err = check_identical(&out).expect_err("a content divergence must fail the baseline");
    assert!(err.contains("content"), "the class must be named: {err}");
}

#[test]
fn the_baseline_refuses_two_empty_dumps_rather_than_calling_them_a_match() {
    // Same polarity control `--expect` gets: nothing compared is not
    // agreement, and two empty dumps are what a dead mount produces.
    let out = merge(&[], &[]);
    assert!(check_identical(&out).is_err());
}

#[test]
fn expect_refuses_when_no_row_compares_equal() {
    let a = vec![file("x", 10, false, 'a')];
    let b = vec![file("x", 10, false, 'b')];
    let out = merge(&a, &b); // one row, and it diverges — zero EQUAL rows
    assert!(check_expect(&out, Class::Content).is_err());
}

#[test]
fn expect_refuses_on_two_identical_dumps_for_every_class() {
    let a = vec![file("x", 10, false, 'a'), dir("y")];
    let out = merge(&a, &a.clone());
    for class in [
        Class::Presence,
        Class::Kind,
        Class::Size,
        Class::Exec,
        Class::Content,
        Class::Target,
        Class::Dtype,
    ] {
        assert!(
            check_expect(&out, class).is_err(),
            "--expect {class} affirmed on two identical dumps"
        );
    }
}

#[test]
fn expect_passes_on_the_triple() {
    let a = vec![file("eq", 1, false, 'a'), file("x", 10, false, 'a')];
    let b = vec![file("eq", 1, false, 'a'), file("x", 10, false, 'b')];
    let out = merge(&a, &b);
    assert!(check_expect(&out, Class::Content).is_ok());
}
