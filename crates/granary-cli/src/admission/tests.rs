// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for [`super`], at the sibling-directory address a
//! module's own tests.
//!
//! **TWO rows moved and THREE stayed, which is the widest split of the four
//! children so far: tests belong to the subject they ASSERT ABOUT.** The two
//! here assert about this module: one names every firing condition of
//! `set_id_refusal` exhaustively, the other checks a created file's owner
//! against the snapshot's `euid`.
//!
//! The three that stayed all CALL `process_credentials()` and assert about
//! something else — `publish_refuses_set_id_credentials_before_creating_the_seed`
//! and `publish_refuses_a_source_nested_seed_before_creating_key_material` are
//! about what PUBLISH refuses and when, and the third
//! (`cmd_mount_gran_forwards_a_parsed_invocation_into_cmd_mount`) is about the
//! dispatch shim. **That name is kept on one line deliberately**: a bare test
//! name wrapped inside backticks renders with a space in the middle and is
//! invisible to the `grep` a later ownership audit uses. **Obtaining
//! credentials does not make a row a test OF credential acquisition** — the
//! ownership follows what the assertions test, not every function called
//! to prepare their inputs.
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;
use crate::tests::ScratchDir;
use std::fs::File;

#[test]
fn set_id_refusal_exhaustively_names_every_firing_condition() {
    for uid_differs in [false, true] {
        for gid_differs in [false, true] {
            for set_id_tainted in [false, true] {
                let credentials = ProcessCredentials {
                    ruid: 1_000,
                    euid: if uid_differs { 1_001 } else { 1_000 },
                    rgid: 2_000,
                    egid: if gid_differs { 2_001 } else { 2_000 },
                    set_id_tainted,
                };
                let refusal = set_id_refusal(&credentials);
                if !uid_differs && !gid_differs && !set_id_tainted {
                    assert!(
                        refusal.is_none(),
                        "matching, untainted credentials must be accepted: {refusal:?}"
                    );
                    continue;
                }

                let message = refusal.unwrap_or_else(|| {
                    panic!(
                        "uid_differs={uid_differs}, gid_differs={gid_differs}, \
                         set_id_tainted={set_id_tainted} must be refused"
                    )
                });
                assert_eq!(
                    message.contains("real uid 1000 differs from effective uid 1001"),
                    uid_differs,
                    "the message must name the uid condition exactly when it fired: {message}"
                );
                assert_eq!(
                    message.contains("real gid 2000 differs from effective gid 2001"),
                    gid_differs,
                    "the message must name the gid condition exactly when it fired: {message}"
                );
                assert_eq!(
                    message.contains("set_id_tainted=true"),
                    set_id_tainted,
                    "the message must name the platform taint condition exactly when it fired: \
                     {message}"
                );
            }
        }
    }
}

#[test]
fn a_created_files_owner_independently_matches_the_snapshot_euid() {
    use std::os::unix::fs::MetadataExt as _;

    let dir = ScratchDir::new();
    let probe = dir.0.join("credential-owner-probe");
    // The HANDLE is bound and stat-ed, not the path re-resolved: the row's
    // claim is about the inode this test created, and a second path lookup
    // asserts about whatever the name means at stat time instead.
    let created = File::create(&probe).unwrap_or_else(|e| panic!("{}: {e}", probe.display()));
    let owner = created
        .metadata()
        .unwrap_or_else(|e| panic!("{}: {e}", probe.display()))
        .uid();
    let credentials = process_credentials();
    assert_eq!(
        owner, credentials.euid,
        "the kernel must assign a newly created file to the effective uid reported by the \
         independent libc snapshot"
    );
}

/// **The NEGATIVE control on the snapshot itself, and the reason it exists is
/// that nothing else in the suite has one.** Every other `set_id_tainted`
/// value under test is hand-written into a `ProcessCredentials` literal, and
/// the oracle above checks `euid` alone — so DELETING the platform taint probe
/// (`issetugid` on Apple, `AT_SECURE` on Linux, the visible-ID fallback
/// elsewhere) and hard-coding `set_id_tainted: false` left the whole suite
/// green. **That is the fail-open direction**: an inverted probe is caught
/// indirectly by publish's refusal rows, and a REMOVED one admits a set-ID
/// process with nothing red.
///
/// An ordinary `cargo test` process is not set-ID, so the honest assertion is
/// that the snapshot says so — on every field, not only the one the row above
/// happens to read. If this ever fires, the suite is being run set-ID and the
/// failure is the correct answer.
#[test]
fn the_snapshot_reports_an_ordinary_test_process_as_untainted() {
    let credentials = process_credentials();
    assert_eq!(
        credentials.ruid, credentials.euid,
        "a test process runs with real uid == effective uid"
    );
    assert_eq!(
        credentials.rgid, credentials.egid,
        "a test process runs with real gid == effective gid"
    );
    assert!(
        !credentials.set_id_tainted,
        "the platform taint probe must report FALSE for an ordinary process — if this \
         assertion is the one that fails, read it as 'the probe was removed or blinded' \
         before reading it as 'the harness is set-ID'"
    );
}

/// **The POSITIVE companion the row above needs, and cannot supply on its
/// own.** `!set_id_tainted` on an ordinary process is
/// satisfied equally by "the probe ran and said no" and by "the probe is
/// gone" — EXECUTED: hard-coding `set_id_tainted: false` in all three platform
/// arms left the suite at 259/259 green. No runtime assertion can tell those
/// apart, because the honest value on this machine is `false` either way.
///
/// So the distinguishing check is on the SOURCE: every `count() == 0`
/// needs a `count() >= 1` on the same construct family.
/// The haystack is this module's own production file and
/// NOTHING ELSE — widening it would let a sibling satisfy a needle, the
/// pollution `production_source()` exists to prevent.
///
/// Needles are ASSEMBLED so this row's own text matches none of them.
#[test]
fn every_platform_arm_still_calls_its_own_taint_probe() {
    const SOURCE: &str = include_str!("../admission.rs");

    let apple = ["libc::isset", "ugid()"].concat();
    let linux = ["libc::getauxval(libc::AT_", "SECURE)"].concat();
    let fallback = ["ruid != euid || rgid != ", "egid"].concat();

    for (needle, arm) in [
        (&apple, "the Apple arm"),
        (&linux, "the Linux arm"),
        (&fallback, "the other-Unix fallback"),
    ] {
        assert_eq!(
            SOURCE.matches(needle.as_str()).count(),
            1,
            "{arm} must still compute set_id_tainted from its own probe, exactly once — a \
             hard-coded `false` here admits a set-ID process on that platform with every \
             runtime assertion in this suite still green"
        );
    }

    // The zero, anchored by the three ones above: no arm may short-circuit.
    let hardcoded = ["set_id_tainted: ", "false"].concat();
    assert_eq!(
        SOURCE.matches(hardcoded.as_str()).count(),
        0,
        "no platform arm may hard-code the taint verdict"
    );
}
