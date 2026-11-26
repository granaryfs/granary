// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::json`'s parser — the writer/parser round-trip
//! that the writer's own output must survive.
//!
//! Out-of-line, because a module's second conforming test body
//! becomes a leaf under `tests`, declared by `json/tests.rs`'s `mod
//! parse_tests;` rather than a second sibling declaration in the
//! parent (`json.rs`). This file has no `super::X` named paths, but
//! it does open `use super::*;`, which is a `super::` path like any
//! other: nesting one level deeper under `tests` changes what
//! `super` reaches, so it is rewritten to `use super::super::*;` to
//! keep glob-importing `json` rather than `tests`.

use super::super::*;

/// The round-trip that matters: everything the WRITER can produce,
/// the parser reads back to an equal value (floats compare by their
/// canonical {:.6} rendering, which is what the writer emits).
#[test]
fn the_parser_round_trips_the_writer() {
    let v = Json::Obj(vec![
        (
            "metadata".to_owned(),
            Json::Obj(vec![("kind".to_owned(), Json::s("m3-grain-sweep"))]),
        ),
        (
            "arms".to_owned(),
            Json::Arr(vec![Json::Obj(vec![
                ("arm".to_owned(), Json::s("cdc-256K")),
                ("novel_stored_bytes".to_owned(), Json::UInt(402_231_140)),
                ("realized_mean_span".to_owned(), Json::Num(8970.25)),
                ("max_bytes".to_owned(), Json::Null),
                ("max_clamped".to_owned(), Json::Bool(false)),
                ("delta".to_owned(), Json::Int(-42)),
                // The boundary value strip-then-negate could not
                // represent.
                ("floor".to_owned(), Json::Int(i64::MIN)),
                ("escaped".to_owned(), Json::s("a\"b\\c\nd\u{1}")),
            ])]),
        ),
        ("empty_arr".to_owned(), Json::Arr(vec![])),
        ("empty_obj".to_owned(), Json::Obj(vec![])),
    ]);
    let text = v.to_pretty();
    let parsed = Json::parse(&text).expect("round trip");
    assert_eq!(parsed, v);
}

/// The COMMITTED baseline records must parse — control 1 reads them.
/// (An integration-level duplicate lives in the reproduce tests;
/// this one pins the parser against the real bytes early.)
#[test]
fn a_committed_record_snippet_parses() {
    let text = r#"{
  "arm": "cdc-256K",
  "kind": "cdc",
  "configured_avg": 262144,
  "novel_pct": 22.518511,
  "manifest_status": "exact"
}"#;
    let v = Json::parse(text).expect("parse");
    assert_eq!(v.get("configured_avg"), Some(&Json::UInt(262_144)));
    assert_eq!(v.get("novel_pct"), Some(&Json::Num(22.518_511)));
}

/// NEGATIVE: malformed input is refused with an offset, not folded.
#[test]
fn garbage_is_refused_with_an_offset() {
    for bad in [
        "",
        "{",
        "[1,",
        "{\"a\" 1}",
        "nulll",
        "1 2",
        "\"unterminated",
        "\u{1}",
        "-",
        "{\"a\": 99999999999999999999999999}",
        // An unknown escape: the writer emits only \" \\ \n \r \t
        // \uXXXX, and accepting anything else survived the suite.
        "\"\\q\"",
    ] {
        assert!(Json::parse(bad).is_err(), "{bad:?} must be refused");
    }
    let deep = "[".repeat(100) + &"]".repeat(100);
    assert!(Json::parse(&deep).is_err(), "the depth cap must hold");
}

#[test]
fn get_and_items_navigate_objects_and_arrays() {
    let v = Json::parse(r#"{"pairs": [{"label": "a"}]}"#).expect("parse");
    let pairs = v.get("pairs").and_then(Json::items).expect("pairs");
    assert_eq!(pairs.len(), 1);
    assert_eq!(
        pairs.first().and_then(|p| p.get("label")),
        Some(&Json::s("a"))
    );
    assert_eq!(v.get("absent"), None);
    assert_eq!(Json::Null.get("x"), None);
    assert_eq!(Json::Null.items(), None);
}
