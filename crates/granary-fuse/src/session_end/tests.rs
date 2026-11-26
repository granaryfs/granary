// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::session_end` — the session-end classifier, the
//! mount identity, and the mountinfo row parser they read the table with.
//!
//! Out-of-line: `granary-fuse`'s non-test artifact
//! has a workspace consumer (`granary-client`), so
//! the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use super::{MountIdentity, SessionEnd, SessionEndEvidence, classify_session_end, mountinfo_lists};
use std::io;
use std::path::{Path, PathBuf};

/// A verdict reduced to what a row compares: the variant's name and, for
/// the variants that carry one, the error's kind, raw errno and text.
type Shape = (&'static str, Option<(io::ErrorKind, Option<i32>, String)>);

fn error_shape(error: &io::Error) -> (io::ErrorKind, Option<i32>, String) {
    (error.kind(), error.raw_os_error(), error.to_string())
}

fn shape(end: &SessionEnd) -> Shape {
    match end {
        SessionEnd::Clean => ("Clean", None),
        SessionEnd::Forced => ("Forced", None),
        SessionEnd::Survived => ("Survived", None),
        SessionEnd::UnmountFailed(error) => ("UnmountFailed", Some(error_shape(error))),
        SessionEnd::Failed(error) => ("Failed", Some(error_shape(error))),
        SessionEnd::Unverified(error) => ("Unverified", Some(error_shape(error))),
    }
}

fn os(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

fn aborted() -> io::Result<()> {
    Err(os(fuser::Errno::ECONNABORTED.code()))
}

fn carrying(variant: &'static str, error: &io::Error) -> Shape {
    (variant, Some(error_shape(error)))
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one row per session end, each stated in full beside its expected verdict"
)]
fn session_end_classifier_table() {
    type Row = (
        &'static str,
        io::Result<()>,
        io::Result<()>,
        bool,
        io::Result<bool>,
        Shape,
    );
    let econnaborted = fuser::Errno::ECONNABORTED.code();
    let eio = fuser::Errno::EIO.code();
    let einval = fuser::Errno::EINVAL.code();
    let unreadable = || io::Error::other("mountinfo unreadable");
    let rows: Vec<Row> = vec![
        (
            "race after a clean unmount",
            Ok(()),
            aborted(),
            false,
            Ok(false),
            ("Clean", None),
        ),
        (
            "race under abort",
            Ok(()),
            aborted(),
            true,
            Ok(false),
            ("Forced", None),
        ),
        (
            // The mount is gone, so the failed detach only means someone
            // else's got there first.
            "race after a failed detach",
            Err(io::Error::other("detach failed")),
            aborted(),
            false,
            Ok(false),
            ("Clean", None),
        ),
        (
            "race with the mount listed",
            Ok(()),
            aborted(),
            false,
            Ok(true),
            carrying("Failed", &os(econnaborted)),
        ),
        (
            "other errno after a clean unmount",
            Ok(()),
            Err(os(eio)),
            false,
            Ok(false),
            carrying("Failed", &os(eio)),
        ),
        (
            "other errno under abort",
            Ok(()),
            Err(os(eio)),
            true,
            Ok(false),
            ("Forced", None),
        ),
        (
            "clean session end",
            Ok(()),
            Ok(()),
            false,
            Ok(false),
            ("Clean", None),
        ),
        (
            "clean session end with the mount listed",
            Ok(()),
            Ok(()),
            false,
            Ok(true),
            ("Survived", None),
        ),
        (
            "race with mountinfo unreadable",
            Ok(()),
            aborted(),
            false,
            Err(unreadable()),
            carrying("Failed", &os(econnaborted)),
        ),
        (
            "clean session end with mountinfo unreadable",
            Ok(()),
            Ok(()),
            false,
            Err(unreadable()),
            carrying("Unverified", &unreadable()),
        ),
        // The row outranks the unmount: both of ours failing (`EINVAL` on a
        // path someone else already detached) with the row gone is clean,
        // for a clean (`ENODEV`, which fuser returns as `Ok`) end and for the
        // teardown race alike.
        (
            "failed unmount, mount gone, clean end",
            Err(os(einval)),
            Ok(()),
            false,
            Ok(false),
            ("Clean", None),
        ),
        (
            "failed unmount, mount gone, race",
            Err(os(einval)),
            aborted(),
            false,
            Ok(false),
            ("Clean", None),
        ),
        (
            "failed unmount, mount listed, clean end",
            Err(os(einval)),
            Ok(()),
            false,
            Ok(true),
            carrying("UnmountFailed", &os(einval)),
        ),
        (
            "failed unmount, mount listed, race",
            Err(os(einval)),
            aborted(),
            false,
            Ok(true),
            carrying("UnmountFailed", &os(einval)),
        ),
        (
            "failed unmount, mountinfo unreadable",
            Err(os(einval)),
            Ok(()),
            false,
            Err(unreadable()),
            carrying("UnmountFailed", &os(einval)),
        ),
        (
            "failed unmount under abort",
            Err(os(einval)),
            Err(os(eio)),
            true,
            Ok(true),
            ("Forced", None),
        ),
    ];
    let mut cases = 0;
    for (row, unmount, joined, forced, listed, expected) in rows {
        let end = classify_session_end(SessionEndEvidence {
            unmount,
            joined,
            forced,
            listed,
        });
        assert_eq!(shape(&end), expected, "{row}");
        cases += 1;
    }
    assert_eq!(cases, 16);
}

#[test]
fn into_result_maps_each_verdict() {
    type Expected = Result<(), (io::ErrorKind, Option<i32>, String)>;
    let shaped = |result: io::Result<()>| result.map_err(|error| error_shape(&error));
    let rows: [(&str, SessionEnd, Expected); 6] = [
        ("Clean", SessionEnd::Clean, Ok(())),
        (
            "Forced",
            SessionEnd::Forced,
            Err((
                io::ErrorKind::TimedOut,
                None,
                "the FUSE session ended only through a connection abort".to_owned(),
            )),
        ),
        (
            "Survived",
            SessionEnd::Survived,
            Err((
                io::ErrorKind::Other,
                None,
                "the mount survived its unmount".to_owned(),
            )),
        ),
        (
            "UnmountFailed",
            SessionEnd::UnmountFailed(os(fuser::Errno::EINVAL.code())),
            Err(error_shape(&os(fuser::Errno::EINVAL.code()))),
        ),
        (
            "Failed",
            SessionEnd::Failed(os(fuser::Errno::ECONNABORTED.code())),
            Err(error_shape(&os(fuser::Errno::ECONNABORTED.code()))),
        ),
        (
            "Unverified",
            SessionEnd::Unverified(io::Error::other("mountinfo unreadable")),
            Err((
                io::ErrorKind::Other,
                None,
                "mountinfo unreadable".to_owned(),
            )),
        ),
    ];
    let mut cases = 0;
    for (row, end, expected) in rows {
        assert_eq!(shaped(end.into_result()), expected, "{row}");
        cases += 1;
    }
    assert_eq!(cases, 6);
}

/// One mountinfo row with the device, mount point and filesystem type
/// spliced in verbatim.
fn device_row(device: &str, mount_point: &[u8], fstype: &str) -> Vec<u8> {
    stacked_row((36, 35), device, mount_point, fstype)
}

/// [`device_row`] with its mount id and parent id given.
fn stacked_row(ids: (u32, u32), device: &str, mount_point: &[u8], fstype: &str) -> Vec<u8> {
    let (mount_id, parent_id) = ids;
    let mut row = format!("{mount_id} {parent_id} {device} / ").into_bytes();
    row.extend_from_slice(mount_point);
    row.extend_from_slice(format!(" rw,nosuid,nodev,relatime - {fstype} gran rw\n").as_bytes());
    row
}

fn body(rows: &[Vec<u8>]) -> Vec<u8> {
    rows.concat()
}

#[test]
fn mount_identity_follows_its_device_not_its_path() {
    let root = device_row("252:1", b"/", "ext4");
    let mounted = body(&[root.clone(), device_row("0:47", b"/mnt/gran", "fuse.gran")]);
    let identity = MountIdentity::capture_in(&mounted, Path::new("/mnt/gran"))
        .expect("the FUSE row at the path is captured");
    assert_eq!(identity.listed_in(&mounted).ok(), Some(true));

    // Moved, or a parent renamed: the same device at another path.
    let moved = body(&[root.clone(), device_row("0:47", b"/srv/moved", "fuse.gran")]);
    let by_path = mountinfo_lists(&moved, Path::new("/mnt/gran"));
    assert_eq!(
        (identity.listed_in(&moved).ok(), by_path.ok()),
        (Some(true), Some(false)),
        "(by device, by the captured path) after a move: the device still lists it where \
         the path test reads it gone"
    );

    // Gone; and a different FUSE mount now at the old path is not ours.
    let gone = body(std::slice::from_ref(&root));
    assert_eq!(identity.listed_in(&gone).ok(), Some(false));
    let replaced = body(&[root.clone(), device_row("0:48", b"/mnt/gran", "fuse.gran")]);
    assert_eq!(identity.listed_in(&replaced).ok(), Some(false));

    // A non-FUSE row carrying the same anonymous device is not ours either.
    let reused = body(&[root, device_row("0:47", b"/run/other", "tmpfs")]);
    assert_eq!(identity.listed_in(&reused).ok(), Some(false));
}

/// A freed device number taken over by another FUSE mount at another path:
/// `listed` reads it as ours (the stated residual), `listed_at` does not.
#[test]
fn listed_at_ignores_a_reused_device_at_another_path() {
    let root = device_row("252:1", b"/", "ext4");
    let identity = MountIdentity::capture_in(
        &body(&[root.clone(), device_row("0:47", b"/mnt/gran", "fuse.gran")]),
        Path::new("/mnt/gran"),
    )
    .unwrap();
    let mut cases = 0;
    for (row, mountinfo, expected) in [
        (
            "ours, at its path",
            body(&[root.clone(), device_row("0:47", b"/mnt/gran", "fuse.gran")]),
            (Some(true), Some(true)),
        ),
        (
            "ours gone, its number reused elsewhere",
            body(&[
                root.clone(),
                device_row("0:47", b"/tmp/other-test", "fuse.gran"),
            ]),
            (Some(true), Some(false)),
        ),
        (
            "ours gone",
            body(std::slice::from_ref(&root)),
            (Some(false), Some(false)),
        ),
        (
            "a non-FUSE mount at the path with our number",
            body(&[root.clone(), device_row("0:47", b"/mnt/gran", "tmpfs")]),
            (Some(false), Some(false)),
        ),
    ] {
        assert_eq!(
            (
                identity.listed_in(&mountinfo).ok(),
                identity
                    .listed_at_in(&mountinfo, Path::new("/mnt/gran"))
                    .ok()
            ),
            expected,
            "{row}: (listed, listed_at)"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn mount_identity_capture_takes_the_topmost_fuse_row_at_the_path() {
    let root = stacked_row((1, 0), "252:1", b"/", "ext4");
    let lower = stacked_row((40, 1), "0:47", b"/mnt/gran", "fuse.gran");
    let upper = stacked_row((41, 40), "0:52", b"/mnt/gran", "fuse");
    let only_lower = body(&[root.clone(), lower.clone()]);
    let only_upper = body(&[root.clone(), upper.clone()]);
    let mut cases = 0;
    // The top is the row no other row at the path is attached to, in either
    // order the table lists them.
    for (order, stacked) in [
        (
            "lower listed first",
            body(&[root.clone(), lower.clone(), upper.clone()]),
        ),
        (
            "upper listed first",
            body(&[root.clone(), upper.clone(), lower.clone()]),
        ),
    ] {
        let identity = MountIdentity::capture_in(&stacked, Path::new("/mnt/gran")).unwrap();
        assert_eq!(
            (
                identity.listed_in(&only_upper).ok(),
                identity.listed_in(&only_lower).ok()
            ),
            (Some(true), Some(false)),
            "{order}: (upper listed, lower listed): the capture must be the top mount's device"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
    // Rows that each name the other as parent have no top: refused, not guessed.
    let cyclic = body(&[
        root,
        stacked_row((40, 41), "0:47", b"/mnt/gran", "fuse.gran"),
        stacked_row((41, 40), "0:52", b"/mnt/gran", "fuse"),
    ]);
    let captured = MountIdentity::capture_in(&cyclic, Path::new("/mnt/gran"));
    assert_eq!(
        captured.as_ref().map_err(io::Error::kind).err(),
        Some(io::ErrorKind::InvalidData),
        "got {captured:?}"
    );
}

/// A table holding our mount in a row the parser cannot read must never
/// classify gone: a lenient reader that skipped the row would answer
/// `Ok(false)`, and a failed unmount with a teardown race would then read
/// `Clean` while the mount lives on.
#[test]
fn a_listed_mount_whose_row_fails_to_parse_never_reads_clean() {
    let root = device_row("252:1", b"/", "ext4");
    let identity = MountIdentity::capture_in(
        &body(&[root.clone(), device_row("0:47", b"/mnt/gran", "fuse.gran")]),
        Path::new("/mnt/gran"),
    )
    .unwrap();
    let mut cases = 0;
    for (row, unreadable) in [
        (
            "a malformed escape",
            device_row("0:47", br"/srv/bad\04x", "fuse.gran"),
        ),
        ("a malformed mount id", {
            let mut row = b"x".to_vec();
            row.extend_from_slice(&device_row("0:47", b"/srv/moved", "fuse.gran"));
            row
        }),
    ] {
        let listed = identity.listed_in(&body(&[root.clone(), unreadable]));
        let listed_kind = listed.as_ref().map_err(io::Error::kind).err();
        let end = classify_session_end(SessionEndEvidence {
            unmount: Err(os(fuser::Errno::EINVAL.code())),
            joined: aborted(),
            forced: false,
            listed,
        });
        assert_eq!(
            (listed_kind, shape(&end).0),
            (Some(io::ErrorKind::InvalidData), "UnmountFailed"),
            "{row}: (listed error kind, verdict)"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn mount_identity_capture_refuses_a_missing_or_non_fuse_mount() {
    let root = device_row("252:1", b"/", "ext4");
    let mut cases = 0;
    for (row, mountinfo, expected) in [
        (
            "no row at the path",
            body(std::slice::from_ref(&root)),
            io::ErrorKind::NotFound,
        ),
        (
            "a non-FUSE mount at the path",
            body(&[root.clone(), device_row("0:47", b"/mnt/gran", "tmpfs")]),
            io::ErrorKind::InvalidData,
        ),
        (
            "a FUSE row whose type only begins with fuse",
            body(&[root.clone(), device_row("0:47", b"/mnt/gran", "fuseblk2")]),
            io::ErrorKind::InvalidData,
        ),
        ("an empty body", Vec::new(), io::ErrorKind::InvalidData),
    ] {
        let captured = MountIdentity::capture_in(&mountinfo, Path::new("/mnt/gran"));
        assert_eq!(
            captured.as_ref().map_err(io::Error::kind).err(),
            Some(expected),
            "{row}: got {captured:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn mountinfo_rows_refuse_a_malformed_device_field() {
    let root = device_row("252:1", b"/", "ext4");
    let identity = MountIdentity::capture_in(
        &body(&[root.clone(), device_row("0:47", b"/mnt/gran", "fuse.gran")]),
        Path::new("/mnt/gran"),
    )
    .unwrap();
    let mut cases = 0;
    for device in [
        "0-47",
        "0:",
        ":47",
        "0:4x",
        "0:47:1",
        "+0:47",
        "0:99999999999",
    ] {
        let mountinfo = body(&[root.clone(), device_row(device, b"/srv/other", "fuse.gran")]);
        let listed = identity.listed_in(&mountinfo);
        assert_eq!(
            listed.as_ref().map_err(io::Error::kind).err(),
            Some(io::ErrorKind::InvalidData),
            "device field {device:?}: got {listed:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 7);
}

/// One `/proc/self/mountinfo` row in the kernel's format, with the
/// caller's mount-point field (field 5) spliced in VERBATIM — escaped
/// or not, exactly as the test wants the parser to see it.
fn mountinfo_row(mount_point: &[u8]) -> Vec<u8> {
    let mut row = b"36 35 0:47 / ".to_vec();
    row.extend_from_slice(mount_point);
    row.extend_from_slice(b" rw,nosuid,nodev,relatime - fuse.gran gran ro,user_id=0\n");
    row
}

#[test]
fn mount_state_decodes_an_octal_escaped_space_in_the_mount_point() {
    let body = mountinfo_row(br"/tmp/granary\040tests/mp");
    assert!(
        mountinfo_lists(&body, Path::new("/tmp/granary tests/mp")).expect("a healthy row parses"),
        "the kernel writes a space as `\\040`; the decoded field must equal the real path"
    );
    assert!(
        !mountinfo_lists(&body, Path::new(r"/tmp/granary\040tests/mp"))
            .expect("a healthy row parses"),
        "the RAW escaped spelling is not a path that is mounted"
    );
}

#[test]
fn mount_state_decodes_backslash_tab_and_newline_escapes() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let body = mountinfo_row(br"/tmp/a\134b\011c\012d");
    let real = PathBuf::from(OsString::from_vec(b"/tmp/a\\b\tc\nd".to_vec()));
    assert!(
        mountinfo_lists(&body, &real).expect("a healthy row parses"),
        "`\\134`, `\\011` and `\\012` decode to backslash, tab and newline"
    );
}

#[test]
fn mount_state_refuses_a_malformed_escape_rather_than_guessing() {
    let short = mountinfo_row(br"/tmp/bad\04x");
    assert!(
        mountinfo_lists(&short, Path::new("/tmp/bad")).is_err(),
        "a backslash not followed by three octal digits is not a row the kernel writes"
    );
    let trailing = mountinfo_row(br"/tmp/bad\");
    assert!(
        mountinfo_lists(&trailing, Path::new("/tmp/bad")).is_err(),
        "a lone trailing backslash is malformed too"
    );
    let overflow = mountinfo_row(br"/tmp/bad\400");
    assert!(
        mountinfo_lists(&overflow, Path::new("/tmp/bad")).is_err(),
        "`\\400` would not fit a byte; the first digit is 0..=3 on a healthy row"
    );
}

#[test]
fn mount_state_tolerates_a_non_utf8_byte_in_another_mount_point() {
    let mut body = mountinfo_row(b"/tmp/other\xff");
    body.extend(mountinfo_row(b"/tmp/mine"));
    assert!(
        mountinfo_lists(&body, Path::new("/tmp/mine")).expect("bytes, not a str"),
        "an unrelated mount's non-UTF-8 byte must not make this check unverifiable"
    );
    assert!(!mountinfo_lists(&body, Path::new("/tmp/absent")).expect("bytes, not a str"),);
}

#[test]
fn mount_state_answers_false_when_a_real_row_does_not_list_the_path() {
    let body = mountinfo_row(b"/tmp/elsewhere");
    assert!(
        !mountinfo_lists(&body, Path::new("/tmp/mine")).expect("a valid body parses"),
        "a valid mountinfo whose rows do not name the path answers false"
    );
}

#[test]
fn mount_state_refuses_a_body_with_no_mount_row() {
    // A live process's mountinfo always lists at least the root mount,
    // so a readable body with NO five-field row is an empty or truncated
    // read, never a real "nothing is mounted" — reporting `Ok(false)`
    // there would be fail-open (a caller would `remove_dir_all` on the
    // strength of a body that verified nothing). Both are `Err`.
    assert!(
        mountinfo_lists(b"36 35\n", Path::new("/tmp/mine")).is_err(),
        "a body whose only line has fewer than five fields verifies nothing"
    );
    assert!(
        mountinfo_lists(b"", Path::new("/tmp/mine")).is_err(),
        "an empty mountinfo read verifies nothing"
    );
}

#[test]
fn mount_state_refuses_an_incomplete_row() {
    // Every one of these is a torn read a mid-file cut can leave, and a
    // valid unrelated row before it must not let the incomplete tail pass
    // as `not mounted`. The complete-row check refuses the whole class:
    // a nonempty line that is not `>= 6 fields, ` - ` separator, >= 3
    // after` is an `Err`, whichever way it was cut.
    let shapes: &[&[u8]] = &[
        b"36 35 0:47 / /truncated",           // 5 fields, no separator
        b"42 36 0:99 /tmp",                   // 4 fields (cut before field 5)
        b"36 35 0:47 / /elsewhere rw -",      // cut right after the separator
        b"36 35 0:47 / /elsewhere rw - fuse", // only one field after separator
    ];
    for shape in shapes {
        // The shape alone.
        assert!(
            mountinfo_lists(shape, Path::new("/tmp/mine")).is_err(),
            "an incomplete row must be refused: {:?}",
            String::from_utf8_lossy(shape)
        );
        // And a complete unrelated row FOLLOWED by the incomplete tail —
        // the shape a mid-file truncation actually produces.
        let mut body = mountinfo_row(b"/tmp/other");
        body.extend_from_slice(shape);
        assert!(
            mountinfo_lists(&body, Path::new("/tmp/mine")).is_err(),
            "a complete row then an incomplete tail is a torn read, not `not mounted`: {:?}",
            String::from_utf8_lossy(shape)
        );
    }
}
