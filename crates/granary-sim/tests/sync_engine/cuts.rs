// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::support::Scratch;
use granary_core::hash::GrainId;
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    #[expect(
        clippy::unwrap_used,
        reason = "reap only the child owned by this harness"
    )]
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
        }
        self.0.wait().unwrap();
    }
}

pub(crate) fn run(
    argument: &str,
    name: &str,
    phase: &str,
    occurrence: u64,
    kind: Option<&str>,
    large: bool,
    armed: bool,
) -> Option<GrainId> {
    run_case(
        argument, name, phase, occurrence, kind, large, armed, "plain",
    )
}

#[expect(
    clippy::too_many_arguments,
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "bounded harness-owned process rendezvous and wall-clock watchdog"
)]
pub(crate) fn run_case(
    argument: &str,
    name: &str,
    phase: &str,
    occurrence: u64,
    kind: Option<&str>,
    large: bool,
    armed: bool,
    case: &str,
) -> Option<GrainId> {
    let scratch = Scratch::new();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "sync_process_child", "--ignored", "--nocapture"])
        .env(
            "GRANARY_SYNC_CUT",
            format!(
                "{argument},{phase},{occurrence},{}",
                if armed { "armed" } else { "control" }
            ),
        )
        .env("GRANARY_SYNC_SCRATCH", &scratch.0)
        .env("GRANARY_SYNC_SHARD_CASE", case)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if large {
        command.env("GRANARY_SYNC_SPILL", "1");
    } else {
        command.env_remove("GRANARY_SYNC_SPILL");
    }
    let mut child = OwnedChild(command.spawn().unwrap());
    let stdout = child.0.stdout.take().unwrap();
    let (send, receive) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    let prefix = format!(
        "{},{name},{phase},{occurrence}",
        if armed { "FIRED" } else { "CONTROL" }
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(if large { 60 } else { 10 });
    let line = loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let line = receive
            .recv_timeout(remaining)
            .unwrap_or_else(|e| panic!("SyncCutReportMissing: {prefix}: {e}"))
            .unwrap();
        if line.starts_with(&prefix) {
            break line;
        }
    };
    let root = if armed {
        verify(&line, name, phase, occurrence, kind).unwrap();
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "SyncCutExitedBeforeKill"
        );
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());
        None
    } else {
        assert!(child.0.wait().unwrap().success(), "SyncCutControlFailed");
        let fields: Vec<_> = line.split(',').collect();
        Some(fields.last().unwrap().parse().unwrap())
    };
    reader.join().unwrap();
    root
}

pub(crate) fn verify(
    line: &str,
    name: &str,
    phase: &str,
    occurrence: u64,
    kind: Option<&str>,
) -> Result<(), &'static str> {
    if occurrence == 0 {
        return Err("SyncCutEmptySelection");
    }
    let fields: Vec<_> = line.split(',').collect();
    if fields.len() != 7 {
        return Err("SyncCutReportMalformed");
    }
    if fields.first() != Some(&"FIRED")
        || fields.get(1) != Some(&name)
        || fields.get(2) != Some(&phase)
        || fields.get(3).and_then(|v| v.parse::<u64>().ok()) != Some(occurrence)
    {
        return Err("SyncCutFaultIdentity");
    }
    let expected_capture = u64::from(name != "sync.commit_wait" && !name.starts_with("overlay."));
    if fields.get(4).and_then(|v| v.parse::<u64>().ok()) != Some(expected_capture) {
        return Err("SyncCutCaptureUnbound");
    }
    if (name == "sync.registration" || name == "sync.reply" || phase == "landed_refresh")
        && fields
            .get(5)
            .and_then(|v| v.parse::<GrainId>().ok())
            .is_none()
    {
        return Err("SyncCutRequestUnbound");
    }
    if name != "sync.registration"
        && name != "sync.reply"
        && phase != "landed_refresh"
        && fields.get(5) != Some(&"none")
    {
        return Err("SyncCutRequestUnbound");
    }
    if kind.is_some_and(|k| fields.get(6) != Some(&k)) {
        return Err("SyncCutObjectKind");
    }
    Ok(())
}
