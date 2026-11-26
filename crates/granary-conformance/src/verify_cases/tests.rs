// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::verify_cases` — `granconf verify-cases`'s witness
//! predicates, each an existence check over the rows a real walk
//! produced off the real filesystem, never over `gendir`'s own
//! tally.
//!
//! Out-of-line: `granary-conformance`'s non-test artifact
//! has its own `[[bin]]` (`granconf`) and its own `tests/`
//! directory (`crates/granary-conformance/tests/cli.rs`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)] mod
//! tests;` — the sibling-directory form.

use super::*;
use crate::row::{DType, new_row};

fn file(path: &str, size: u64, exec: bool) -> Row {
    new_row(
        path.as_bytes().to_vec(),
        Kind::File,
        DType::File,
        Some(size),
        exec,
        Payload::Content("a".repeat(64)),
    )
    .expect("valid row")
}

fn dir(path: &str) -> Row {
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

fn symlink(path: &str, target: &[u8]) -> Row {
    new_row(
        path.as_bytes().to_vec(),
        Kind::Symlink,
        DType::Symlink,
        None,
        false,
        Payload::Target(target.to_vec()),
    )
    .expect("valid row")
}

/// A tree with every property EXCEPT the one under test, so each
/// predicate's own red is meaningful (missing exactly one thing),
/// not merely "no rows at all".
fn baseline() -> Vec<Row> {
    vec![
        file("alpha", 100, false),
        file("beta", 100, true),
        dir("delta"),
    ]
}

#[test]
fn verify_all_refuses_an_empty_dump() {
    assert!(verify_all(&[]).is_err());
}

#[test]
fn verify_all_reports_every_named_failure_for_a_nonempty_inadequate_dump() {
    let missing_everything = vec![dir("ordinary")];
    let results = verify_all(&missing_everything).expect("the dump is nonempty");
    let failed: Vec<&str> = results
        .iter()
        .filter(|result| result.outcome.is_err())
        .map(|result| result.name)
        .collect();
    assert_eq!(
        failed,
        [
            "name-len-1",
            "name-len-255",
            "case-fold-siblings",
            "depth-100",
            "wide-dir",
            "empty-file",
            "grain-boundary-sizes",
            "exec-and-nonexec",
            "symlink-absolute",
            "symlink-dotdot",
            "symlink-dangling",
            "symlink-to-dir",
            "symlink-to-sibling-file",
            "dup-subtrees",
            "name-byte-0xff",
            "name-literal-backslash-x2f",
        ],
        "verify_all must run and report every registered predicate"
    );
}

#[test]
fn name_len_1_red_then_green() {
    assert!(check_name_len_1(&baseline()).is_err());
    let mut rows = baseline();
    rows.push(file("x", 1, false));
    assert!(check_name_len_1(&rows).is_ok());
}

#[test]
fn name_len_255_red_then_green() {
    let mut rows = baseline();
    rows.push(file(&"x".repeat(254), 1, false));
    assert!(
        check_name_len_255(&rows).is_err(),
        "a 254-byte name is immediately below the required boundary"
    );
    let name = "x".repeat(255);
    rows.push(file(&name, 1, false));
    assert!(check_name_len_255(&rows).is_ok());
}

#[test]
fn case_fold_siblings_red_then_green() {
    assert!(check_case_fold_siblings(&baseline()).is_err());
    let mut rows = baseline();
    rows.push(file("CaseA", 1, false));
    rows.push(file("casea", 1, false));
    assert!(check_case_fold_siblings(&rows).is_ok());
}

#[test]
fn depth_100_red_then_green() {
    let depth_99 = (0..99)
        .map(|i| format!("d{i}"))
        .collect::<Vec<_>>()
        .join("/");
    let mut rows = baseline();
    rows.push(file(&depth_99, 1, false));
    assert!(
        check_depth_100(&rows).is_err(),
        "depth 99 is immediately below the required boundary"
    );
    let depth_100 = format!("{depth_99}/last");
    rows.push(file(&depth_100, 1, false));
    assert!(check_depth_100(&rows).is_ok());
}

#[test]
fn wide_dir_red_then_green() {
    let mut rows = baseline();
    let threshold = usize::try_from(2 * DIR_LEAF_MAX_ENTRIES).expect("threshold fits usize");
    for i in 0..threshold {
        rows.push(file(&format!("wide/{i:04}"), 1, false));
    }
    assert!(
        check_wide_dir(&rows).is_err(),
        "exactly {threshold} children must not satisfy a >{threshold} boundary"
    );
    rows.push(file(&format!("wide/{threshold:04}"), 1, false));
    assert!(check_wide_dir(&rows).is_ok());
}

#[test]
fn empty_file_red_then_green() {
    assert!(check_empty_file(&baseline()).is_err());
    let mut rows = baseline();
    rows.push(file("z", 0, false));
    assert!(check_empty_file(&rows).is_ok());
}

fn assert_grain_size_is_independently_required(missing_index: usize) {
    let sizes: [u64; 8] = [
        (MIN_GRAIN - 1) as u64,
        MIN_GRAIN as u64,
        (MIN_GRAIN + 1) as u64,
        AVG_GRAIN as u64,
        (MAX_GRAIN - 1) as u64,
        MAX_GRAIN as u64,
        (MAX_GRAIN + 1) as u64,
        (2 * MAX_GRAIN + MIN_GRAIN) as u64,
    ];
    let missing_size = sizes
        .get(missing_index)
        .copied()
        .expect("test boundary index is in range");
    let mut rows = baseline();
    for (i, size) in sizes.iter().enumerate() {
        if i != missing_index {
            rows.push(file(&format!("sz{i}"), *size, false));
        }
    }
    assert!(
        check_grain_boundary_sizes(&rows).is_err(),
        "omitting only size {missing_size} must fail its own gate"
    );
    rows.push(file("restored-boundary", missing_size, false));
    assert!(
        check_grain_boundary_sizes(&rows).is_ok(),
        "restoring size {missing_size} must satisfy all eight gates"
    );
}

macro_rules! grain_boundary_test {
    ($name:ident, $missing_index:expr) => {
        #[test]
        fn $name() {
            assert_grain_size_is_independently_required($missing_index);
        }
    };
}

grain_boundary_test!(grain_boundary_min_minus_one_red_then_green, 0);
grain_boundary_test!(grain_boundary_min_red_then_green, 1);
grain_boundary_test!(grain_boundary_min_plus_one_red_then_green, 2);
grain_boundary_test!(grain_boundary_avg_red_then_green, 3);
grain_boundary_test!(grain_boundary_max_minus_one_red_then_green, 4);
grain_boundary_test!(grain_boundary_max_red_then_green, 5);
grain_boundary_test!(grain_boundary_max_plus_one_red_then_green, 6);
grain_boundary_test!(grain_boundary_two_max_plus_min_red_then_green, 7);

#[test]
fn exec_and_nonexec_red_then_green() {
    // A dump with ONLY exec files is missing the property.
    let rows = vec![file("a", 1, true)];
    assert!(check_exec_and_nonexec(&rows).is_err());
    assert!(check_exec_and_nonexec(&baseline()).is_ok());
}

#[test]
fn symlink_absolute_red_then_green() {
    assert!(check_symlink_absolute(&baseline()).is_err());
    let mut rows = baseline();
    rows.push(symlink("s", b"/etc/passwd"));
    assert!(check_symlink_absolute(&rows).is_ok());
}

#[test]
fn symlink_dotdot_red_then_green() {
    assert!(check_symlink_dotdot(&baseline()).is_err());
    let mut rows = baseline();
    rows.push(symlink("s", b"../elsewhere"));
    assert!(check_symlink_dotdot(&rows).is_ok());
}

#[test]
fn symlink_dangling_red_then_green() {
    assert!(check_symlink_dangling(&baseline()).is_err());
    let mut rows = baseline();
    rows.push(symlink("s", b"../above-root"));
    assert!(check_symlink_dangling(&rows).is_ok());
}

#[test]
fn symlink_to_dir_red_then_green() {
    assert!(check_symlink_to_dir(&baseline()).is_err());
    let mut rows = baseline();
    rows.push(symlink("s", b"delta"));
    assert!(check_symlink_to_dir(&rows).is_ok());
}

#[test]
fn symlink_to_sibling_file_red_then_green() {
    let mut rows = baseline();
    rows.push(symlink("nested/s", b"../alpha"));
    assert!(
        check_symlink_to_sibling_file(&rows).is_err(),
        "a slash-containing target is not a same-directory sibling reference"
    );
    rows.push(symlink("s", b"alpha"));
    assert!(check_symlink_to_sibling_file(&rows).is_ok());
}

#[test]
fn dup_subtrees_red_then_green() {
    assert!(check_dup_subtrees(&baseline()).is_err());
    let mut rows = baseline();
    rows.push(dir("dup"));
    rows.push(dir("dup/one"));
    rows.push(dir("dup/two"));
    rows.push(file("dup/one/x", 5, false));
    rows.push(file("dup/two/x", 5, false));
    assert!(check_dup_subtrees(&rows).is_ok());
}

#[test]
fn dup_subtrees_rejects_a_look_alike_that_actually_differs() {
    let mut rows = baseline();
    rows.push(dir("dup"));
    rows.push(dir("dup/one"));
    rows.push(dir("dup/two"));
    rows.push(file("dup/one/x", 5, false));
    rows.push(file("dup/two/x", 6, false)); // different size — not identical
    assert!(check_dup_subtrees(&rows).is_err());
}

#[test]
fn byte_0xff_red_then_green() {
    assert!(check_byte_0xff(&baseline()).is_err());
    // Built directly as raw bytes — 0xff is not valid UTF-8, so
    // this is the only honest way to construct the case; a `Row`
    // accepting it is `crates/granary-core/src/manifest/name.rs`'s
    // `Name` discipline extended to this crate (raw bytes in, no
    // `to_string_lossy` anywhere on the path).
    let mut rows = baseline();
    let row = new_row(
        vec![0xffu8],
        Kind::File,
        DType::File,
        Some(1),
        false,
        Payload::Content("a".repeat(64)),
    )
    .expect("raw non-UTF-8 name is a valid row");
    rows.push(row);
    assert!(check_byte_0xff(&rows).is_ok());
}

#[test]
fn literal_backslash_x2f_red_then_green() {
    assert!(check_literal_backslash_x2f(&baseline()).is_err());
    let mut rows = baseline();
    rows.push(file("has\\x2fliteral", 1, false));
    assert!(check_literal_backslash_x2f(&rows).is_ok());
}
