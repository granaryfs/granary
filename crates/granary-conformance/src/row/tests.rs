// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::row` — the dump row's text format and its
//! (de)serialization.
//!
//! Out-of-line: `granary-conformance`'s non-test artifact
//! has its own `[[bin]]` (`granconf`) and its own `tests/`
//! directory (`crates/granary-conformance/tests/cli.rs`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)] mod
//! tests;` — the sibling-directory form.

use super::{DType, Kind, Payload, new_row, parse_dump, parse_line, render_line};

fn file_row(path: &str, size: u64, exec: bool, hex: &str) -> super::Row {
    new_row(
        path.as_bytes().to_vec(),
        Kind::File,
        DType::File,
        Some(size),
        exec,
        Payload::Content(hex.to_owned()),
    )
    .expect("valid file row")
}

#[test]
fn a_dir_row_whose_payload_column_is_not_a_dash_is_refused() {
    // Synthesising Payload::None regardless of the column would let a
    // corrupted or concatenated dump parse and then compare EQUAL to the
    // canonical row -- corruption hidden by the parser that exists to
    // refuse it.
    let good = "d\tdir\tdir\t-\t-\t-";
    assert!(parse_line(good).is_ok(), "the canonical dir row must parse");
    let bad = "d\tdir\tdir\t-\t-\tgarbage";
    assert!(
        parse_line(bad).is_err(),
        "a non-dash dir payload must be refused"
    );
}

#[test]
fn a_file_row_round_trips_through_render_and_parse() {
    let row = file_row("a/b.txt", 12, true, &"ab".repeat(32));
    let line = render_line(&row);
    assert_eq!(
        line,
        format!("a/b.txt\tfile\tfile\t12\tx\t{}", "ab".repeat(32))
    );
    assert_eq!(parse_line(&line).unwrap(), row);
}

#[test]
fn a_dir_row_renders_dashes_for_size_and_payload() {
    let row = new_row(
        b"d".to_vec(),
        Kind::Dir,
        DType::Dir,
        None,
        false,
        Payload::None,
    )
    .expect("valid dir row");
    let line = render_line(&row);
    assert_eq!(line, "d\tdir\tdir\t-\t-\t-");
    assert_eq!(parse_line(&line).unwrap(), row);
}

#[test]
fn a_symlink_row_escapes_its_target_as_the_payload() {
    let row = new_row(
        b"link".to_vec(),
        Kind::Symlink,
        DType::Symlink,
        None,
        false,
        Payload::Target(b"../\xfftarget".to_vec()),
    )
    .expect("valid symlink row");
    let line = render_line(&row);
    assert!(
        line.contains("\\xff"),
        "target bytes were not escaped: {line}"
    );
    assert_eq!(parse_line(&line).unwrap(), row);
}

#[test]
fn new_row_refuses_a_kind_payload_mismatch() {
    assert!(
        new_row(
            b"x".to_vec(),
            Kind::File,
            DType::File,
            None,
            false,
            Payload::None
        )
        .is_err()
    );
    assert!(
        new_row(
            b"x".to_vec(),
            Kind::Dir,
            DType::Dir,
            None,
            false,
            Payload::Content("a".repeat(64))
        )
        .is_err()
    );
}

#[test]
fn parse_line_refuses_the_wrong_field_count() {
    assert!(parse_line("a\tfile\tfile\t1\tx").is_err());
    assert!(parse_line("a\tfile\tfile\t1\tx\thash\textra").is_err());
}

#[test]
fn file_content_requires_exactly_64_lowercase_hex_digits() {
    let line = |payload: &str| format!("a\tfile\tfile\t1\t-\t{payload}");
    assert!(parse_line(&line(&"a".repeat(64))).is_ok());
    for bad in [
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        format!("{}g", "a".repeat(63)),
    ] {
        assert!(
            parse_line(&line(&bad)).is_err(),
            "non-canonical content digest was accepted: {bad}"
        );
    }
}

#[test]
fn parse_dump_sorts_by_raw_path_bytes_regardless_of_input_order() {
    let a = file_row("b", 1, false, &"a".repeat(64));
    let z = file_row("a", 1, false, &"b".repeat(64));
    let text = format!("{}\n{}\n", render_line(&a), render_line(&z));
    let rows = parse_dump(&text).unwrap();
    assert_eq!(rows[0].path, b"a");
    assert_eq!(rows[1].path, b"b");
}

#[test]
fn parse_dump_refuses_duplicate_paths_after_canonical_decoding() {
    let row = file_row("same", 1, false, &"a".repeat(64));
    let line = render_line(&row);
    let error = parse_dump(&format!("{line}\n{line}\n"))
        .expect_err("a concatenated dump must not admit the same path twice");
    assert!(
        matches!(error, super::DumpParseError::DuplicatePath(_)),
        "unexpected parse error: {error}"
    );
}
