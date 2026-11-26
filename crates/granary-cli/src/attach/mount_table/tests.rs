// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::attach::mount_table` — the bounded read, both
//! escape grammars, and both doors onto the kernel's mount table.
//!
//! Out-of-line, at the sibling-directory path
//! `attach/mount_table/tests.rs`, applied recursively because
//! the module these cover is itself a child of `attach`.
//!
//! **SEVEN rows that depend on a member of this module stayed with `attach`**,
//! because tests belong to what they ASSERT ABOUT: `umount_preflight_verdict_authorizes_all_gran`,
//! `umount_preflight_verdict_refuses_absent`,
//! `umount_preflight_verdict_refuses_mixed_naming_the_condition`,
//! `umount_preflight_verdict_refuses_err`,
//! `umount_postcheck_verdict_maps_every_target_rows_variant`,
//! `the_preflight_authorizes_all_gran_and_the_postcheck_refuses_it` and
//! `mount_attempt_calls_preflight_and_reports_which_refusal_fired` either pass a
//! `TargetRows` value or name `refuse_if_already_mounted` in a comment, and every
//! one of them ASSERTS ABOUT the parent's policy. Reading a table is not deciding
//! what the reading permits.
//!
//! **SIX is what a name scan sees and SEVEN is the family**, which shows why
//! a reference scan is a worklist and never a verdict, here biting in
//! the direction nobody budgets for. `umount_preflight_verdict_refuses_err`
//! never spells `TargetRows`: it passes `Err(std::io::Error::other("boom"))`
//! into a parameter whose type is `std::io::Result<TargetRows>`, so the
//! dependency is in an INFERRED argument position and no lexical instrument can
//! reach it. The name scan reported 58 candidates but missed it.
//! **A name-positive row needs a map exactly as much as a `count() == 0` row
//! needs an anchor.**
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;
use crate::attach::MountScratchDir;
use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

// ------------------------------------------------- the mountinfo door

// --------------------------------------------- the bounded read (F1)

#[test]
fn read_bounded_accepts_a_body_exactly_at_the_limit() {
    let body = vec![b'x'; 8];
    let got = read_bounded(body.as_slice(), 8).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, body);
}

#[test]
fn read_bounded_refuses_a_body_one_byte_over_the_limit() {
    // `Read::take(limit)` alone would silently stop at 8 bytes and
    // report `Ok` — the fail-open shape F1 is about. This must
    // instead REFUSE, naming the bound.
    let body = vec![b'x'; 9];
    let err = read_bounded(body.as_slice(), 8)
        .expect_err("one byte over the bound must refuse, not silently truncate");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        err.to_string().contains("8-byte bound"),
        "expected the message to name the bound: {err}"
    );
}

// ------------------------------------------- mountinfo parsing (pure)

#[test]
fn mountinfo_unescape_decodes_octal_space() {
    assert_eq!(mountinfo_unescape(b"a\\040b"), b"a b".to_vec());
    // `\040`'s first digit is 0, so this row alone cannot tell the
    // correct `* 64` weight for the first digit from a mutant that
    // weights it `* 8` instead — both give the same answer when
    // that digit is 0, so that mutant survives this row alone.
    // `\134` is backslash (octal 134 = 1*64 +
    // 3*8 + 4 = 92), with a NONZERO first digit, so a `* 8` mutant
    // computes 1*8 + 3*8 + 4 = 32 (space) instead — a different,
    // wrong byte.
    assert_eq!(mountinfo_unescape(b"a\\134b"), b"a\\b".to_vec());
}

#[test]
fn mountinfo_unescape_leaves_plain_text_unchanged() {
    assert_eq!(mountinfo_unescape(b"/mnt/plain"), b"/mnt/plain".to_vec());
}

#[test]
fn mountinfo_unescape_ignores_a_trailing_backslash_with_no_digits() {
    // A malformed/truncated escape at the very end must not panic
    // (this is the `.get()`-vs-indexing property): kept literal.
    assert_eq!(mountinfo_unescape(b"a\\"), b"a\\".to_vec());
    assert_eq!(mountinfo_unescape(b"a\\04"), b"a\\04".to_vec());
}

#[test]
fn mountinfo_unescape_leaves_a_non_utf8_byte_unchanged() {
    // mountinfo escapes only space/tab/newline/backslash; every
    // other byte — including one that is not valid UTF-8 on its
    // own — passes through RAW (F3). A lossy `String` round-trip
    // would collapse it to the 3-byte replacement character
    // instead of returning it unchanged.
    assert_eq!(
        mountinfo_unescape(b"/mnt/\xffgranary"),
        b"/mnt/\xffgranary".to_vec()
    );
}

#[test]
fn octal_escape_at_decodes_the_largest_legal_escape() {
    // `\377` is the largest legal single-byte octal escape:
    // 3*64 + 7*8 + 7 = 255.
    assert_eq!(octal_escape_at(b"\\377", 0), Some(0xFF));
}

#[test]
fn octal_escape_at_refuses_the_first_digit_above_3_rather_than_overflow() {
    // `\400` is not representable as a single byte at all (a first
    // digit of 4 alone implies 4*64 = 256, already past u8::MAX) —
    // refused outright, never computed (F2).
    assert_eq!(octal_escape_at(b"\\400", 0), None);
}

// --------------------------------- findmnt's hex escapes

#[test]
fn findmnt_unescape_decodes_known_hex_escapes_both_cases() {
    assert_eq!(findmnt_unescape(b"a\\x20b"), Some(b"a b".to_vec()));
    assert_eq!(findmnt_unescape(b"a\\x09b"), Some(b"a\tb".to_vec()));
    assert_eq!(findmnt_unescape(b"a\\x0ab"), Some(b"a\nb".to_vec()));
    assert_eq!(findmnt_unescape(b"a\\x5cb"), Some(b"a\\b".to_vec()));
    // Both hex cases are accepted, deliberately: findmnt(8)'s own
    // contract is `\x<code>`; util-linux's current implementation
    // emits lowercase, but this is a foreign tool's output, not a
    // canonical format whose accept set must stay minimal.
    assert_eq!(findmnt_unescape(b"a\\x0Ab"), Some(b"a\nb".to_vec()));
}

#[test]
fn findmnt_unescape_leaves_ordinary_bytes_alone() {
    assert_eq!(
        findmnt_unescape(b"/mnt/plain"),
        Some(b"/mnt/plain".to_vec())
    );
}

/// The decoder regression at the unescaper level: findmnt(8) never
/// emits the OCTAL spelling `mountinfo_unescape` decodes — a `\`
/// that does not begin a complete `\xHH` escape means this byte
/// string is not well-formed findmnt output, so the WHOLE field is
/// refused rather than silently copied through (silently copying it
/// could turn an unreadable target into a false absence). The
/// `\040` row must be refused outright, since `0` never begins
/// a `\x` escape.
#[test]
fn findmnt_unescape_refuses_malformed_or_octal_escapes() {
    assert_eq!(findmnt_unescape(b"a\\"), None, "bare trailing backslash");
    assert_eq!(findmnt_unescape(b"a\\x2"), None, "truncated escape");
    assert_eq!(findmnt_unescape(b"a\\xzz"), None, "not hex digits");
    assert_eq!(
        findmnt_unescape(b"a\\040b"),
        None,
        "the OCTAL spelling must be refused; accepting it would admit the wrong escape grammar"
    );
}

/// ONE PASS, left to right, never rescanned: a path that literally
/// contains the four bytes `\`, `x`, `2`, `0` arrives from findmnt
/// as `\x5cx20` (the backslash escaped, the rest literal). A second
/// pass over the decoded bytes would misread the literal `x20` as
/// another escape and produce a space; a single pass must not.
#[test]
fn findmnt_unescape_does_not_rescan_decoded_bytes() {
    assert_eq!(
        findmnt_unescape(b"\\x5cx20"),
        Some(vec![b'\\', b'x', b'2', b'0'])
    );
}

fn mountinfo_line(mount_point: &str) -> String {
    format!(
        "36 35 98:0 / {mount_point} rw,noatime master:1 - ext3 /dev/root \
         rw,errors=continue"
    )
}

/// Byte-level counterpart of [`mountinfo_line`] for a mount point
/// that is not valid UTF-8 — `format!`/`String` cannot carry such a
/// byte, so this builds the line directly as bytes.
fn mountinfo_line_bytes(mount_point: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"36 35 98:0 / ");
    out.extend_from_slice(mount_point);
    out.extend_from_slice(b" rw,noatime master:1 - ext3 /dev/root rw,errors=continue");
    out
}

#[test]
fn mountinfo_lists_target_finds_an_exact_match() {
    let text = mountinfo_line("/mnt/granary");
    assert!(mountinfo_lists_target(
        text.as_bytes(),
        Path::new("/mnt/granary")
    ));
}

#[test]
fn mountinfo_lists_target_is_absent_when_not_listed() {
    let text = mountinfo_line("/mnt/other");
    assert!(!mountinfo_lists_target(
        text.as_bytes(),
        Path::new("/mnt/granary")
    ));
}

#[test]
fn mountinfo_lists_target_matches_after_unescaping_a_space() {
    let text = mountinfo_line("/mnt/a\\040b");
    assert!(mountinfo_lists_target(
        text.as_bytes(),
        Path::new("/mnt/a b")
    ));
}

#[test]
fn mountinfo_lists_target_ignores_a_short_malformed_line() {
    assert!(!mountinfo_lists_target(b"36 35\n", Path::new("/mnt")));
}

#[test]
fn mountinfo_lists_target_matches_a_non_utf8_target_byte_for_byte() {
    // A raw, non-UTF-8 byte in an UNRELATED mount's path must still
    // be matched byte-for-byte (F3) rather than making the whole
    // read refuse (which is what `read_to_string` did). The real
    // file read through `/proc/self/mountinfo` is Linux-only and
    // exercised only by Linux CI; this pins the pure parse, which
    // is platform-independent.
    let text = mountinfo_line_bytes(b"/mnt/\xffgranary");
    let target = Path::new(OsStr::from_bytes(b"/mnt/\xffgranary"));
    assert!(mountinfo_lists_target(&text, target));
}

// -------------------------------------------------- the findmnt door

fn findmnt_line(target: &str, fstype: &str, source: &str) -> String {
    format!("{target} {fstype} {source}")
}

// -------------------------- findmnt_rows_at_target row-level pins

/// PINS: SOURCE alone is not proof — a tmpfs filesystem that merely
/// NAMES itself `gran` (`mount -t tmpfs gran /mnt/gran`) must not
/// authorize anything; `is_fuse_family_fstype` is what refuses it,
/// at the ROW level, not only in that helper's own unit test.
///
/// EXECUTED mutation: `source == b"gran" && is_fuse_family_fstype(&fstype)`
/// -> `source == b"gran"` leaves the whole suite green without this.
#[test]
fn findmnt_rows_at_target_refuses_a_tmpfs_impostor_that_names_gran_as_its_source() {
    let stdout = findmnt_line("/mnt/gran", "tmpfs", "gran");
    assert_eq!(
        findmnt_rows_at_target(stdout.as_bytes(), Path::new("/mnt/gran")),
        Some(TargetRows::Mixed { any_gran: false })
    );
}

/// PINS: FSTYPE alone is not proof either — a FUSE row whose SOURCE
/// is not the literal string `gran` must not authorize anything,
/// at the ROW level.
///
/// EXECUTED mutation: dropping `source == b"gran" &&` leaves the suite green.
#[test]
fn findmnt_rows_at_target_refuses_a_foreign_source_on_a_fuse_row() {
    let stdout = findmnt_line("/mnt/gran", "fuse", "notgran");
    assert_eq!(
        findmnt_rows_at_target(stdout.as_bytes(), Path::new("/mnt/gran")),
        Some(TargetRows::Mixed { any_gran: false })
    );
}

/// PINS: the fusermount-group shape (`fuse.gran`, SOURCE `gran`) at
/// the ROW level, not only in `is_fuse_family_fstype`'s own unit
/// test above.
#[test]
fn findmnt_rows_at_target_is_all_gran_for_the_fusermount_group_row() {
    let stdout = findmnt_line("/mnt/gran", "fuse.gran", "gran");
    assert_eq!(
        findmnt_rows_at_target(stdout.as_bytes(), Path::new("/mnt/gran")),
        Some(TargetRows::AllGran)
    );
}

/// PINS: a sibling path whose name EXTENDS the target (shares it as
/// a PREFIX) must never authorize a detach of the target — the two
/// are different mountpoints.
///
/// EXECUTED mutation: `t != target_bytes` -> `!t.starts_with(target_bytes)`
/// leaves the suite green. A sibling whose name EXTENDS the target must
/// never authorize a detach of the target.
#[test]
fn findmnt_rows_at_target_matches_the_target_exactly_not_by_prefix() {
    let stdout = findmnt_line("/mnt/granary-other", "fuse", "gran");
    assert_eq!(
        findmnt_rows_at_target(stdout.as_bytes(), Path::new("/mnt/gran")),
        Some(TargetRows::Absent)
    );
}

/// This row's TARGET matches: the parser scopes the exactly-three-fields
/// check to a row whose TARGET already matches. Pins that a
/// MATCHING row with a fourth field is still `None`, not
/// `AllGran` from folding the extra field into SOURCE and
/// not silently skipped as if it were unrelated.
/// `findmnt_rows_at_target_is_all_gran_when_an_unrelated_row_has_a_fourth_raw_field`
/// below is this test's opposite number: an UNRELATED row
/// with the same shape must NOT reach this check at all.
///
/// A parser that split with `splitn(3, ..)` would fold the fourth
/// field into SOURCE, so `source == b"gran extra"`, which is not
/// `b"gran"`, and answer `Some(TargetRows::Mixed { any_gran: false })`.
/// That answer is fail-CLOSED for the PRE-FLIGHT (an unauthorized row
/// is refused either way) but fail-OPEN for the POST-CHECK, where
/// `umount_postcheck_verdict` maps `Mixed { any_gran: false }` to "the
/// mount is gone" — reporting a granary-shaped row this parser could
/// not fully read as proof the unmount worked, without ever detaching
/// anything. The same bytes cannot mean two different things depending
/// on which call site reads them, so this row is `None` — inconclusive
/// — which both call sites treat as a refusal. This test is the one a
/// `splitn(3, ..)` parser fails.
#[test]
fn findmnt_rows_at_target_is_none_for_a_matching_row_with_a_fourth_raw_field() {
    assert_eq!(
        findmnt_rows_at_target(b"/mnt/gran fuse gran extra", Path::new("/mnt/gran")),
        None
    );
}

/// The control for the test above: exactly-three must not refuse a
/// LEGITIMATE row whose last column (SOURCE) is empty. findmnt's own
/// formatter (libsmartcols) prints the separator after every column
/// that is not the last, whatever the cell holds, so an empty SOURCE
/// still yields three fields (`"TARGET FSTYPE "`, note the trailing
/// space) — not two. This must keep parsing, with the empty SOURCE
/// counting as non-granary.
///
/// EXECUTED mutation: deleting the exactly-three check (matching only
/// the first three `Some`s, keeping `split` rather than `splitn`)
/// leaves this test green — it is unaffected either way, which is
/// what proves the exactly-three check is not over-broad rather than
/// merely coincidentally passing.
#[test]
fn findmnt_rows_at_target_accepts_an_empty_last_column() {
    assert_eq!(
        findmnt_rows_at_target(b"/mnt/gran fuse ", Path::new("/mnt/gran")),
        Some(TargetRows::Mixed { any_gran: false })
    );
}

// ----------------------------- findmnt_rows_at_target

/// The row parser decodes a hex-escaped space in TARGET, so
/// `/tmp/a\x20b` matches the path `/tmp/a b`.
#[test]
fn findmnt_rows_at_target_matches_a_hex_escaped_space_in_the_target() {
    let stdout = "/tmp/a\\x20b fuse gran";
    assert_eq!(
        findmnt_rows_at_target(stdout.as_bytes(), Path::new("/tmp/a b")),
        Some(TargetRows::AllGran)
    );
}

#[test]
fn findmnt_rows_at_target_is_all_gran_for_one_gran_row() {
    let stdout = findmnt_line("/mnt/gran", "fuse", "gran");
    assert_eq!(
        findmnt_rows_at_target(stdout.as_bytes(), Path::new("/mnt/gran")),
        Some(TargetRows::AllGran)
    );
}

/// The unsafe-detach regression: an over-mounted target where a granary
/// row AND a non-granary row both name the same TARGET. `umount2`
/// detaches only the TOPMOST mount, so the pre-flight must not
/// authorize this — see `umount_preflight_verdict`. This is the
/// mixed-row case: every matching row must participate in the verdict.
#[test]
fn findmnt_rows_at_target_is_mixed_with_any_gran_true_when_a_non_gran_row_shares_the_target() {
    let stdout = format!(
        "{}\n{}",
        findmnt_line("/mnt/gran", "ext4", "/dev/sda1"),
        findmnt_line("/mnt/gran", "fuse", "gran")
    );
    assert_eq!(
        findmnt_rows_at_target(stdout.as_bytes(), Path::new("/mnt/gran")),
        Some(TargetRows::Mixed { any_gran: true })
    );
}

#[test]
fn findmnt_rows_at_target_is_mixed_with_any_gran_false_for_a_foreign_only_target() {
    let stdout = findmnt_line("/mnt/gran", "ext4", "/dev/sda1");
    assert_eq!(
        findmnt_rows_at_target(stdout.as_bytes(), Path::new("/mnt/gran")),
        Some(TargetRows::Mixed { any_gran: false })
    );
}

#[test]
fn findmnt_rows_at_target_is_absent_when_no_row_names_it() {
    assert_eq!(
        findmnt_rows_at_target(b"", Path::new("/mnt/gran")),
        Some(TargetRows::Absent)
    );
    let other = findmnt_line("/mnt/other", "ext4", "/dev/sda1");
    assert_eq!(
        findmnt_rows_at_target(other.as_bytes(), Path::new("/mnt/gran")),
        Some(TargetRows::Absent)
    );
}

/// A matching row that does not split into three fields must make
/// verification inconclusive: skipping it
/// could turn an unreadable mount into a false absence. `None`
/// must mean nothing is concluded from the WHOLE table, not "ignore
/// this row".
#[test]
fn findmnt_rows_at_target_is_none_for_a_malformed_row_with_too_few_fields() {
    assert_eq!(
        findmnt_rows_at_target(b"/mnt/gran fuse", Path::new("/mnt/gran")),
        None
    );
}

/// The target field's escape is the OCTAL spelling (`\040`), which
/// `findmnt_unescape` refuses outright (findmnt never emits it) —
/// the row cannot even be checked against the target, so nothing
/// may be concluded from the table.
#[test]
fn findmnt_rows_at_target_is_none_for_a_row_with_an_invalid_escape() {
    let stdout = "/mnt/a\\040b fuse gran";
    assert_eq!(
        findmnt_rows_at_target(stdout.as_bytes(), Path::new("/mnt/a b")),
        None
    );
}

/// Both halves of the target-first decoding fix, in
/// one test — proving only one half would only prove something
/// changed, not that the fail-closed property survived:
///
/// (1) an odd row for a completely UNRELATED target — its SOURCE
/// uses the octal escape findmnt never emits, so it cannot be
/// decoded — must not poison the verdict for OUR target when a good
/// granary row for OUR target is also present.
///
/// (2) a row whose OWN target field cannot be decoded must still be
/// `None` for the whole table — it might BE the sought target, and
/// this parser cannot tell either way, so it stays inconclusive
/// rather than being skipped like an ordinary non-matching row.
///
/// EXECUTED mutation: reordering back to decoding all three fields
/// before comparing TARGET makes half (1) `None` instead of
/// `Some(AllGran)` — see the session report for the quoted run.
#[test]
fn findmnt_rows_at_target_skips_an_unrelated_malformed_row_but_still_refuses_an_undecodable_target()
{
    // Half 1: the unrelated row's SOURCE cannot be decoded at all,
    // but its TARGET plainly names some OTHER mount, so it must
    // never be reached.
    let stdout = format!(
        "/mnt/other fuse \\040bad\n{}",
        findmnt_line("/mnt/gran", "fuse", "gran")
    );
    assert_eq!(
        findmnt_rows_at_target(stdout.as_bytes(), Path::new("/mnt/gran")),
        Some(TargetRows::AllGran),
        "an unrelated row's undecodable SOURCE must not block the verdict for OUR target"
    );

    // Half 2: a row whose own TARGET cannot be decoded is still
    // inconclusive, not skippable.
    let stdout2 = "/mnt/a\\040b fuse gran";
    assert_eq!(
        findmnt_rows_at_target(stdout2.as_bytes(), Path::new("/mnt/a b")),
        None,
        "a row whose TARGET cannot be decoded must stay inconclusive, not be skipped"
    );
}

// ----------------------------- findmnt_rows_at_target: framing and targets

/// An UNRELATED row with a FOURTH raw field (framing this parser
/// has no argv-shaped explanation for) must not poison the verdict
/// for a DIFFERENT, matching target — framing is judged only on a row
/// whose TARGET already matches (TARGET decoding, by contrast, is
/// judged on every row: see the undecodable-TARGET test below).
/// If the exactly-three-fields check ran for EVERY row before TARGET
/// was compared, this unrelated row's stray fourth field would make
/// the whole table `None` — a healthy granary mount at `/mnt/gran`
/// would become un-unmountable because of some OTHER path's odd row,
/// and a successful detach would report "could not verify the
/// unmount".
///
/// EXECUTED mutation: checking field count before comparing TARGET
/// turns this test red.
#[test]
fn findmnt_rows_at_target_is_all_gran_when_an_unrelated_row_has_a_fourth_raw_field() {
    let stdout = format!(
        "/mnt/other fuse gran extra\n{}",
        findmnt_line("/mnt/gran", "fuse", "gran")
    );
    assert_eq!(
        findmnt_rows_at_target(stdout.as_bytes(), Path::new("/mnt/gran")),
        Some(TargetRows::AllGran),
        "an unrelated row's own unexpected field count must not block the verdict for OUR \
         target"
    );
}

/// A row whose own TARGET cannot be decoded
/// must still make the whole table `None` — inconclusive — even
/// though its first field plainly LOOKS like it names some other
/// path; this parser cannot tell what it actually decodes to, so
/// it might still be ours. Distinct from
/// `findmnt_rows_at_target_skips_an_unrelated_malformed_row_but_still_refuses_an_undecodable_target`'s
/// second half (which uses the SAME textual target as the one
/// sought, just badly escaped): this row's raw bytes visibly
/// name a DIFFERENT path, to pin that an apparently unrelated
/// TARGET must still be decoded before the row can be skipped.
#[test]
fn findmnt_rows_at_target_is_none_for_an_unrelated_row_whose_target_cannot_be_decoded() {
    let stdout = "/mnt/other\\040x fuse gran";
    assert_eq!(
        findmnt_rows_at_target(stdout.as_bytes(), Path::new("/mnt/gran")),
        None,
        "a row whose own TARGET cannot be decoded must stay inconclusive, whatever it looks \
         like"
    );
}

// -------------------------- FUSE family: exactly fuse or a fuse. prefix

#[test]
fn is_fuse_family_fstype_accepts_both_real_shapes() {
    assert!(is_fuse_family_fstype(b"fuse"));
    assert!(is_fuse_family_fstype(b"fuse.gran"));
}

#[test]
fn is_fuse_family_fstype_refuses_a_tmpfs_impostor() {
    assert!(!is_fuse_family_fstype(b"tmpfs"));
}

/// A prefix match without the separating `.` would let a filesystem
/// merely NAMED like `fuse` (e.g. a hypothetical `fusebox` type)
/// through — this pins that the family check requires either the
/// exact bare string or the `.`-delimited form, not a bare prefix.
#[test]
fn is_fuse_family_fstype_refuses_a_fuse_prefixed_lookalike() {
    assert!(!is_fuse_family_fstype(b"fusebox"));
}

// -------------------------- findmnt exit classification and helper selection

#[test]
fn classify_findmnt_exit_success_with_stdout_is_ran() {
    assert_eq!(classify_findmnt_exit(Some(0), false), FindmntVerdict::Ran);
}

/// Exit 1 with empty stdout must be inconclusive: read as "nothing
/// matched", the post-check would turn that absence into
/// `MountOutcome::Clean` — exit 0 with the mount still attached. A
/// whole-table listing that succeeded always prints at least the
/// namespace root, so this combination is refused, never read as a
/// conclusive "nothing matched".
#[test]
fn classify_findmnt_exit_one_with_empty_stdout_is_now_inconclusive() {
    assert_eq!(
        classify_findmnt_exit(Some(1), true),
        FindmntVerdict::Inconclusive
    );
}

/// Another impossible successful whole-table result:
/// exit 0 with EMPTY stdout. A whole-table listing that actually
/// succeeded always prints at least the namespace root, so this is
/// equally inconclusive, not a conclusive `Ran`.
#[test]
fn classify_findmnt_exit_zero_with_empty_stdout_is_inconclusive() {
    assert_eq!(
        classify_findmnt_exit(Some(0), true),
        FindmntVerdict::Inconclusive
    );
}

/// Exit 1 with non-empty stdout is inconclusive: output alone does
/// not establish that the command succeeded.
#[test]
fn classify_findmnt_exit_one_with_nonempty_stdout_is_inconclusive() {
    assert_eq!(
        classify_findmnt_exit(Some(1), false),
        FindmntVerdict::Inconclusive
    );
}

/// Every non-zero status and termination by signal must be
/// `Inconclusive`, never folded into a conclusive answer.
#[test]
fn classify_findmnt_exit_other_nonzero_codes_and_signals_are_inconclusive() {
    for code in [Some(2), Some(127), None] {
        assert_eq!(
            classify_findmnt_exit(code, true),
            FindmntVerdict::Inconclusive,
            "status code {code:?} (empty stdout) must not be read as \"not mounted\""
        );
    }
}

/// Mirroring `granary-fuse`'s own
/// `every_fusermount_candidate_is_an_absolute_path`: every
/// entry in the fixed list must be absolute, or
/// `Command::new` would resolve a non-absolute entry through
/// the inherited `PATH` — and this command can run as root.
#[test]
fn every_findmnt_candidate_is_an_absolute_path() {
    assert!(
        !FINDMNT_CANDIDATES.is_empty(),
        "an empty candidate list would make findmnt unreachable"
    );
    for candidate in FINDMNT_CANDIDATES {
        assert!(
            Path::new(candidate).is_absolute(),
            "`{candidate}` is not absolute, so Command::new would resolve it through the \
             inherited PATH — and this command can run as root"
        );
    }
}

/// Helper selection is checked directly: a bare candidate name is
/// refused with `NotFound`. On its own this row cannot tell the
/// `is_absolute()` guard from "the bare name resolves to nothing
/// from the working directory" — the fake script sits in a scratch
/// directory that is not on `PATH` — so the row below, whose
/// relative candidate DOES resolve, is what shows the guard is
/// load-bearing.
#[test]
fn still_mounted_via_findmnt_with_refuses_a_bare_candidate_name() {
    let dir = MountScratchDir::new();
    let script = dir.0.join("findmnt");
    write_fake_findmnt(&script, "0\n", 0);
    let err = still_mounted_via_findmnt_with(
        &["findmnt"],
        Path::new("/mnt/gran"),
        FINDMNT_STDOUT_MAX_BYTES,
    )
    .expect_err("a non-absolute candidate must never be spawned");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

/// The MECHANISM, not the constant: even a candidate that RESOLVES
/// to a real, executable file must be refused if it is not spelled
/// as an ABSOLUTE path — proving `is_absolute()` is load-bearing
/// rather than redundant with "the file happens not to exist" (which
/// the bare-name test above cannot rule out on its own, since that
/// candidate never resolves to anything either way).
///
/// No `std::env::set_current_dir` — this crate's own clippy.toml
/// bans it. The relative spelling is built by hand from the REAL
/// working directory (enough leading `..` to reach filesystem root,
/// which is harmless to over-count: `..` at `/` is a no-op), so it
/// resolves to the very file `symlink_metadata` would find directly,
/// with no process-global state touched.
#[test]
fn still_mounted_via_findmnt_with_refuses_a_relative_candidate_that_really_exists() {
    let dir = MountScratchDir::new();
    let script = dir.0.join("findmnt");
    write_fake_findmnt(&script, "", 1);
    let cwd = std::env::current_dir().unwrap_or_else(|e| panic!("{e}"));
    let mut relative = PathBuf::new();
    for _ in 0..cwd.components().count() {
        relative.push("..");
    }
    for comp in script.components() {
        if let std::path::Component::Normal(c) = comp {
            relative.push(c);
        }
    }
    assert!(
        !relative.is_absolute(),
        "fixture precondition: the constructed candidate must be relative"
    );
    // Fixture precondition: the relative spelling really does
    // resolve to the real script — proves this test is not
    // accidentally exercising "the file does not exist" instead of
    // "the path is not absolute".
    assert!(
        std::fs::symlink_metadata(&relative).is_ok(),
        "fixture precondition: {relative:?} must resolve to the real script at {script:?}"
    );
    let candidate = relative
        .to_str()
        .unwrap_or_else(|| panic!("non-UTF8 scratch path"));
    let err = still_mounted_via_findmnt_with(
        &[candidate],
        Path::new("/mnt/gran"),
        FINDMNT_STDOUT_MAX_BYTES,
    )
    .expect_err("a RELATIVE candidate must be refused even when it resolves to a real file");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

/// The positive helper-selection path: an absolute
/// candidate that exists and exits 0 is actually run, and its
/// stdout is parsed exactly like the real `findmnt` binary's would
/// be.
#[test]
fn still_mounted_via_findmnt_with_runs_the_first_existing_absolute_candidate() {
    let dir = MountScratchDir::new();
    let script = dir.0.join("findmnt");
    write_fake_findmnt(&script, "/mnt/gran fuse gran\n", 0);
    let candidate = script
        .to_str()
        .unwrap_or_else(|| panic!("non-UTF8 scratch path"));
    let found = still_mounted_via_findmnt_with(
        &[candidate],
        Path::new("/mnt/gran"),
        FINDMNT_STDOUT_MAX_BYTES,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(found, TargetRows::AllGran);
}

/// Checked end to end through the real process-spawning path
/// (not just `classify_findmnt_exit` in isolation): exit 1 with
/// non-empty stdout must come back `Err`, not a conclusive answer.
#[test]
fn still_mounted_via_findmnt_with_refuses_to_answer_on_exit_one_with_stdout() {
    let dir = MountScratchDir::new();
    let script = dir.0.join("findmnt");
    write_fake_findmnt(&script, "/mnt/gran fuse gran\n", 1);
    let candidate = script
        .to_str()
        .unwrap_or_else(|| panic!("non-UTF8 scratch path"));
    still_mounted_via_findmnt_with(
        &[candidate],
        Path::new("/mnt/gran"),
        FINDMNT_STDOUT_MAX_BYTES,
    )
    .expect_err("exit 1 with non-empty stdout must not be read as \"nothing matched\"");
}

/// Inconclusive helper output, checked end to end through the real
/// process-spawning path: a helper that exits 1 having written
/// NOTHING must return `Err`. `Ok(false)` ("not mounted") for this
/// exact combination is the fail-open the post-check would turn into
/// exit 0 with the mount still attached.
#[test]
fn still_mounted_via_findmnt_with_refuses_to_answer_on_exit_one_with_no_stdout() {
    let dir = MountScratchDir::new();
    let script = dir.0.join("findmnt");
    write_fake_findmnt(&script, "", 1);
    let candidate = script
        .to_str()
        .unwrap_or_else(|| panic!("non-UTF8 scratch path"));
    still_mounted_via_findmnt_with(
        &[candidate],
        Path::new("/mnt/gran"),
        FINDMNT_STDOUT_MAX_BYTES,
    )
    .expect_err("exit 1 with EMPTY stdout must not be read as \"nothing matched\"");
}

/// A helper that writes MORE than the
/// bound makes this return `Err` rather than a truncated parse —
/// `read_bounded` already refuses rather than truncating; this
/// proves the plumbing actually reaches it. A tiny 8-byte bound
/// (rather than the real 4 MiB [`FINDMNT_STDOUT_MAX_BYTES`]) keeps
/// the fixture cheap: this tests the MECHANISM, not the production
/// constant, which stays untouched — see [`still_mounted_via_findmnt`],
/// which is the only production caller and always passes
/// the real constant.
#[test]
fn still_mounted_via_findmnt_with_refuses_stdout_over_the_bound_rather_than_truncating() {
    let dir = MountScratchDir::new();
    let script = dir.0.join("findmnt");
    write_fake_findmnt(&script, "123456789", 0); // 9 bytes over an 8-byte bound
    let candidate = script
        .to_str()
        .unwrap_or_else(|| panic!("non-UTF8 scratch path"));
    let err = still_mounted_via_findmnt_with(&[candidate], Path::new("/mnt/gran"), 8)
        .expect_err("stdout past the bound must refuse, not silently truncate");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

/// The empty-output regression, through the real process path
/// rather than `classify_findmnt_exit` in isolation: exit 0 with
/// EMPTY stdout must refuse, not read as a conclusive `Absent` that
/// the post-check would then map to `MountOutcome::Clean`.
///
/// EXECUTED mutation: `classify_findmnt_exit(status.code(), stdout.is_empty())`
/// -> `(status.code(), false)` leaves the suite green, which restores
/// the false-absence failure through the composed path: exit 0 + empty stdout
/// would parse as `Absent`, and the post-check maps `Absent` to `Clean`.
#[test]
fn still_mounted_via_findmnt_with_refuses_exit_zero_with_empty_stdout() {
    let dir = MountScratchDir::new();
    let script = dir.0.join("findmnt");
    write_fake_findmnt(&script, "", 0);
    let candidate = script
        .to_str()
        .unwrap_or_else(|| panic!("non-UTF8 scratch path"));
    still_mounted_via_findmnt_with(&[candidate], Path::new("/mnt/gran"), 4096)
        .expect_err("a whole-table listing that printed nothing cannot be conclusive");
}

/// Proves the read-before-wait ordering is load-bearing, not just
/// documented: a table larger than the pipe buffer is what makes
/// read-before-wait observable at all, since every OTHER fixture's
/// stdout fits in one pipe buffer and would pass either ordering.
///
/// **Under its mutant this test DEADLOCKS rather than failing** — it
/// is caught only because `.config/nextest.toml` carries a
/// `slow-timeout` with `terminate-after` for `granary-cli`
/// (measured: `Summary [120.005s] 8 tests run: 7 passed, 1 timed
/// out`). Removing that override would turn this mutant into a
/// silent hang instead of a reported failure.
///
/// EXECUTED mutation: inserting `child.wait()?` before the read leaves the
/// suite green, because every other fixture's stdout fits in one pipe
/// buffer. A table larger than the pipe buffer is what makes
/// read-before-wait observable at all.
#[test]
fn still_mounted_via_findmnt_with_reads_before_it_waits_on_a_table_past_the_pipe_buffer() {
    let dir = MountScratchDir::new();
    let script = dir.0.join("findmnt");
    let body = "#!/bin/sh\nexec awk 'BEGIN{for(i=0;i<60000;i++)print \"/mnt/gran fuse gran\"}'\n";
    std::fs::write(&script, body).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("{e}"));
    let candidate = script
        .to_str()
        .unwrap_or_else(|| panic!("non-UTF8 scratch path"));
    let got = still_mounted_via_findmnt_with(&[candidate], Path::new("/mnt/gran"), 4 * 1024 * 1024)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, TargetRows::AllGran);
}

/// INLINE on purpose, not routed through `write_fake_findmnt`: that
/// helper's five existing callers all pass no log path, and a
/// recording helper that silently records nowhere is the fail-open
/// shape this file keeps paying for. This is the only caller that
/// needs the argv the child actually received, so it builds its own
/// script rather than growing `write_fake_findmnt` a parameter
/// nothing else uses.
///
/// EXECUTED mutation: `-rno TARGET,FSTYPE,SOURCE` -> `SOURCE,FSTYPE,TARGET`
/// leaves the suite green - nothing pins the argv that makes the parser
/// correct.
#[test]
fn still_mounted_via_findmnt_with_invokes_findmnt_with_the_argv_the_parser_assumes() {
    let dir = MountScratchDir::new();
    let script = dir.0.join("findmnt");
    let log = dir.0.join("argv.log");
    let body = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s' '/mnt/gran fuse gran'\n",
        log.display()
    );
    std::fs::write(&script, body).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("{e}"));
    let candidate = script
        .to_str()
        .unwrap_or_else(|| panic!("non-UTF8 scratch path"));
    let _ = still_mounted_via_findmnt_with(&[candidate], Path::new("/mnt/gran"), 4096)
        .unwrap_or_else(|e| panic!("{e}"));
    let seen = std::fs::read_to_string(&log).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(seen, "-rno\nTARGET,FSTYPE,SOURCE\n", "argv was {seen:?}");
}

/// Writes a `/bin/sh` stand-in for `findmnt` that
/// prints `stdout` verbatim and exits `code` — mirrors
/// `granary-fuse/src/unmount/tests.rs`'s own
/// `write_fake_helper`,
/// adapted for a program that prints rather than logs.
fn write_fake_findmnt(path: &Path, stdout: &str, code: i32) {
    let script = format!("#!/bin/sh\nprintf '%s' '{stdout}'\nexit {code}\n");
    std::fs::write(path, script).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("{e}"));
}

/// `still_mounted_via_findmnt` adds nothing over
/// `still_mounted_via_findmnt_with` but the fixed
/// [`FINDMNT_CANDIDATES`] list — proven by delegation, so this
/// production entry point is real, exercised coverage rather than
/// dead code sitting only behind the `#[expect(dead_code)]` this
/// module's other tests hold every sibling wrapper to.
#[test]
fn still_mounted_via_findmnt_delegates_to_the_fixed_candidate_list() {
    let target = Path::new("/mnt/granary-fixture-does-not-exist");
    match (
        still_mounted_via_findmnt(target),
        still_mounted_via_findmnt_with(FINDMNT_CANDIDATES, target, FINDMNT_STDOUT_MAX_BYTES),
    ) {
        (Ok(a), Ok(b)) => assert_eq!(a, b),
        (Err(_), Err(_)) => {} // both refused identically (e.g. no findmnt on this box)
        (a, b) => panic!("still_mounted_via_findmnt must delegate exactly: got {a:?} vs {b:?}"),
    }
}
#[test]
fn control_mount_observation() {
    let valid = b"8 1 0:42 / /mnt rw - fuse.gran gran rw,user_id=1000,group_id=2\n";
    let positive = control_mounts_in(valid, Path::new("/mnt"), (1, 2)).unwrap();
    assert_eq!(positive.len(), 1);
    assert_eq!(
        (
            positive[0].owner,
            positive[0].key.mount_id,
            positive[0].key.fuse_minor
        ),
        (1000, 8, 42)
    );
    let mut cases = 0;
    for (before, after, reason) in [
        (
            "user_id=1000",
            "group_id=1000",
            "missing, duplicate or malformed FUSE user_id",
        ),
        (
            "user_id=1000",
            "user_id=1000,user_id=1000",
            "missing, duplicate or malformed FUSE user_id",
        ),
        (
            "user_id=1000",
            "user_id=4294967296",
            "missing, duplicate or malformed FUSE user_id",
        ),
        (
            "user_id=1000",
            "user_id=-1",
            "missing, duplicate or malformed FUSE user_id",
        ),
        (
            "fuse.gran",
            "tmpfs",
            "the target carries a mount that is not granary's",
        ),
        (
            "gran rw,",
            "other rw,",
            "the target carries a mount that is not granary's",
        ),
    ] {
        let malformed = std::str::from_utf8(valid).unwrap().replace(before, after);
        let error = control_mounts_in(malformed.as_bytes(), Path::new("/mnt"), (1, 2))
            .unwrap_err()
            .to_string();
        assert_eq!(error, format!("refusing: {reason}"));
        cases += 1;
    }
    let stacked = [valid.as_slice(), valid.as_slice()].concat();
    let mounts = control_mounts_in(&stacked, Path::new("/mnt"), (1, 2)).unwrap();
    assert_eq!(
        super::super::umount_control_target(&mounts, 1000).unwrap_err(),
        "refusing: owner wait requires exactly one granary mount row"
    );
    assert_eq!(super::super::umount_control_target(&mounts, 0), Ok(None));
    assert_eq!(cases, 6);
}

#[test]
fn control_mount_observation_preserves_raw_identity() {
    use std::os::unix::ffi::OsStrExt as _;
    let mut cases = 0;
    for owner in [0, 1000] {
        let mut bytes = b"8 1 0:42 / /m\xff rw - fuse.gran gran rw,user_id=".to_vec();
        bytes.extend(owner.to_string().as_bytes());
        bytes.extend(b",group_id=1000\n");
        let target = Path::new(OsStr::from_bytes(b"/m\xff"));
        let rows = control_mounts_in(&bytes, target, (1, 2)).unwrap();
        assert_eq!(
            rows,
            vec![ControlMount {
                owner,
                key: granary_core::mount_control::MountKey {
                    namespace_dev: 1,
                    namespace_ino: 2,
                    mount_id: 8,
                    fuse_major: 0,
                    fuse_minor: 42
                }
            }]
        );
        assert!(
            control_mounts_in(&bytes, Path::new("/m\u{fffd}"), (1, 2))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            control_mounts_in(&bytes, target, (1, 0))
                .unwrap_err()
                .to_string(),
            "refusing: invalid mount namespace or mount id"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}
