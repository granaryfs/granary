// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The ext4 operator workload. The successful unfence uses constructed boot
//! times through the seam; this venue never performs a host reboot.

use std::process::{Command, Stdio};

use super::*;

#[test]
#[ignore = "scripts/authority-venue.sh on Linux ext4"]
fn lifecycle_workload() {
    let state = PathBuf::from(std::env::var("GRANARY_VENUE_STATE").unwrap());
    let control = PathBuf::from(std::env::var("GRANARY_VENUE_CONTROL").unwrap());
    let mut random = random();
    let (code, out, err) = cli(&state, "initialise", false, &mut random, 1);
    assert_eq!(
        (code, out.starts_with("created vol-a ")),
        (0, true),
        "{err}"
    );
    std::fs::write(control.join("lifecycle-returned-initialise"), b"").unwrap();
    let clean = decode_marker(&std::fs::read(state.join("MARKER")).unwrap()).unwrap();
    assert_eq!(clean, RunMarker::Clean);
    std::fs::write(control.join("lifecycle-initialise-clean"), b"clean").unwrap();
    // No host reboot: all real times are required to predate a constructed
    // future boot start. Production never reads this value from argv or env.
    let (code, out, err) = cli(&state, "unfence", false, &mut random, i64::MAX);
    assert_eq!((code, out), (0, "clean\n".into()), "{err}");
    std::fs::write(control.join("lifecycle-returned-unfence"), b"").unwrap();

    let (code, _, err) = cli(
        &state,
        "unfence",
        false,
        &mut random,
        crate::host_boot_start().unwrap(),
    );
    assert_eq!(
        (code, err.contains("requires a host reboot")),
        (65, true),
        "{err}"
    );
    std::fs::write(state.join("vol-a.log"), records_bytes()).unwrap();
    let (code, _, err) = cli(&state, "initialise", false, &mut random, 1);
    assert_eq!(
        (code, err.contains("holds committed records")),
        (65, true),
        "{err}"
    );

    // The child holds the real server adapter's directory lock; the parent
    // attempts both verbs while that separate process is alive.
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "lifecycle::tests::venue::lock_holder",
            "--include-ignored",
            "--nocapture",
        ])
        .env("GRANARY_VENUE_STATE", &state)
        .env("GRANARY_VENUE_CONTROL", &control)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let ready = control.join("lifecycle-lock-ready");
    for _ in 0..500 {
        if ready.exists() {
            break;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "lock child exited before readiness"
        );
        #[expect(
            clippy::disallowed_methods,
            reason = "bounded polling of a real child process readiness file; this wait decides no boot time, log value or lifecycle admission"
        )]
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(ready.exists(), "lock child never signalled readiness");
    for verb in ["initialise", "unfence"] {
        let (code, _, err) = cli(&state, verb, false, &mut random, i64::MAX);
        assert_eq!(
            (code, err.contains("locked by another process")),
            (65, true),
            "{err}"
        );
    }
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());

    let tmpfs = PathBuf::from(std::env::var("GRANARY_VENUE_UNSUPPORTED").unwrap()).join("state");
    std::fs::create_dir(&tmpfs).unwrap();
    std::fs::set_permissions(&tmpfs, std::fs::Permissions::from_mode(0o700)).unwrap();
    for verb in ["initialise", "unfence"] {
        let (code, _, err) = cli(&tmpfs, verb, false, &mut random, i64::MAX);
        assert_eq!((code, err.contains("filesystem type")), (65, true), "{err}");
        let (code, _, err) = cli(&tmpfs, verb, true, &mut random, i64::MAX);
        assert_eq!(code, 0, "{err}");
    }
}

#[test]
#[ignore = "child of the ext4 lifecycle workload"]
fn lock_holder() {
    use std::io::Read as _;
    let state = PathBuf::from(std::env::var("GRANARY_VENUE_STATE").unwrap());
    let _log = FileLog::new(state, false).unwrap();
    let control = PathBuf::from(std::env::var("GRANARY_VENUE_CONTROL").unwrap());
    std::fs::write(control.join("lifecycle-lock-ready"), b"ready").unwrap();
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes).unwrap();
}

#[test]
#[ignore = "scripts/authority-venue.sh root operator on Linux ext4"]
fn root_verb_preserves_state_owner() {
    use crate::protected_dir::{DirOps as _, NixOps};
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(NixOps.euid(), 0, "this row requires a root operator");
    let state = PathBuf::from(std::env::var("GRANARY_VENUE_STATE").unwrap());
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    NixOps
        .fchown(&std::fs::File::open(&state).unwrap(), 1000, 1000)
        .unwrap();
    for verb in ["initialise", "unfence"] {
        let (code, _, err) = cli(&state, verb, false, &mut random(), i64::MAX);
        assert_eq!(code, 0, "{err}");
    }
    for name in ["vol-a.log", "MARKER"] {
        let metadata = std::fs::metadata(state.join(name)).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
            (1000, 1000, 0o600)
        );
    }
}
