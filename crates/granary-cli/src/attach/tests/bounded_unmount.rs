// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Owned-process fixture for bounded writable-daemon endings.

use super::super::*;
use granary_client::{FaultAction, FaultControl, RecordWriter};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing_subscriber::EnvFilter;

const CHILD: &str = "GRANARY_BOUNDED_UNMOUNT_CHILD";
const SIZES: [usize; 5] = [65_536, 131_072, 196_608, 262_144, 327_680];

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl RecordWriter for Captured {
    fn write_record(&self, record: &granary_client::LogRecord) {
        self.0.lock().unwrap().extend_from_slice(record.as_bytes());
    }
}

fn config(root: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(root.join("config"))
        .unwrap()
        .lines()
        .map(|line| {
            let (name, value) = line.split_once('=').expect("bounded fixture config field");
            (name.to_owned(), value.to_owned())
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn wait_for_mount(mountpoint: &Path) {
    let started = Instant::now();
    loop {
        if mount_table::control_mounts(mountpoint).is_ok_and(|rows| rows.len() == 1) {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "writable daemon did not mount within 10 s"
        );
        crate::tests::pause(Duration::from_millis(10));
    }
}

#[cfg(not(target_os = "linux"))]
fn wait_for_mount(_mountpoint: &Path) {
    panic!("bounded unmount child requires Linux FUSE");
}

fn verify_payloads(mountpoint: &Path) {
    for (index, size) in SIZES.into_iter().enumerate() {
        let bytes = std::fs::read(mountpoint.join(format!("file-{index}"))).unwrap();
        assert_eq!(bytes, vec![b'a' + u8::try_from(index).unwrap(); size]);
    }
}

fn prepare(root: &Path, values: &BTreeMap<String, String>, faults: &FaultControl) {
    let mountpoint = PathBuf::from(&values["mount"]);
    wait_for_mount(&mountpoint);
    if values["mode"] == *"recover" {
        verify_payloads(&mountpoint);
        std::fs::write(root.join("ready.next"), b"recovered").unwrap();
        std::fs::rename(root.join("ready.next"), root.join("ready")).unwrap();
        return;
    }
    // Keep the dirty set non-quiescent until the exact fault/trace is installed.
    let seeding = Instant::now();
    let mut sentinel = None;
    for (index, size) in SIZES.into_iter().enumerate() {
        let mut file = std::fs::File::create(mountpoint.join(format!("file-{index}"))).unwrap();
        file.write_all(&vec![b'a' + u8::try_from(index).unwrap(); size])
            .unwrap();
        if index + 1 == SIZES.len() {
            sentinel = Some(file);
        }
    }
    match values["fault"].as_str() {
        "none" => faults.trace_sync(),
        "stalled" => faults.arm(
            "sync.registration",
            "before_dispatch",
            1,
            FaultAction::Block,
        ),
        "graduated" => faults.arm(
            "sync.registration",
            "before_dispatch",
            3,
            FaultAction::Block,
        ),
        other => panic!("unknown bounded fixture fault {other:?}"),
    }
    assert!(
        seeding.elapsed() < Duration::from_secs(4),
        "dirty-set construction approached the 5 s coalescer maximum age"
    );
    drop(sentinel);
    std::fs::write(root.join("ready.next"), values["fault"].as_bytes()).unwrap();
    std::fs::rename(root.join("ready.next"), root.join("ready")).unwrap();
    if values["fault"] != *"none" {
        let started = Instant::now();
        loop {
            let fired = faults.sync_fired();
            if let Some(event) = fired.last() {
                std::fs::write(
                    root.join("fault"),
                    format!(
                        "{}/{}/{}/{}/{}",
                        event.name,
                        event.phase,
                        event.occurrence,
                        event.capture,
                        event.request.is_some()
                    ),
                )
                .unwrap();
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(12),
                "shutdown did not reach its armed fault"
            );
            crate::tests::pause(Duration::from_millis(5));
        }
    }
}

fn mount_args(values: &BTreeMap<String, String>) -> MountArgs {
    let mut args = vec![
        "--writable".into(),
        "--foreground".into(),
        "--endpoint".into(),
        values["endpoint"].clone().into(),
        "--pin".into(),
        values["pin"].clone().into(),
        "--root-key".into(),
        values["root_key"].clone().into(),
        "--key-seed".into(),
        values["seed"].clone().into(),
        "--store-dir".into(),
        values["store"].clone().into(),
        "--cache-dir".into(),
        values["cache"].clone().into(),
        "--client-cert".into(),
        values["certificate"].clone().into(),
        "--client-key".into(),
        values["credential_key"].clone().into(),
        "--credential-context".into(),
        "principal-0".into(),
        "--shutdown-bound".into(),
        "10".into(),
    ];
    if values["profile"] == *"published" {
        args.push("--commit-on-sync".into());
    }
    args.push(values["volume"].clone().into());
    args.push(values["mount"].clone().into());
    parse_mount(&args).unwrap()
}

#[test]
#[ignore = "re-executed by the mounted authority rows"]
fn bounded_unmount_child() {
    let Some(root) = std::env::var_os(CHILD).map(PathBuf::from) else {
        return;
    };
    let values = config(&root);
    let captured = Captured::default();
    let subscriber = granary_client::closed_subscriber_with_paths(
        granary_client::LogFormat::Json,
        EnvFilter::new("trace"),
        captured.clone(),
        granary_client::LogPaths::Redacted,
        granary_client::BundleHistory::default(),
    );
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let faults = FaultControl::default();
    granary_client::start_faults_for_test(faults.clone());
    let worker_root = root.clone();
    let worker_values = values.clone();
    let worker = std::thread::spawn(move || prepare(&worker_root, &worker_values, &faults));
    let reports = Mutex::new(Vec::new());
    let outcome = mount_attempt_with_credentials(
        &mount_args(&values),
        &crate::admission::process_credentials(),
        &mut std::io::sink(),
        &|line| writeln!(reports.lock().unwrap(), "{line}").unwrap(),
    )
    .unwrap();
    worker.join().unwrap();
    std::fs::write(root.join("events"), captured.0.lock().unwrap().as_slice()).unwrap();
    std::fs::write(root.join("reports"), reports.into_inner().unwrap()).unwrap();
    let expected = if values["fault"] == *"none" || values["mode"] == *"recover" {
        (MountOutcome::Clean, 0)
    } else {
        (MountOutcome::Stopped, 4)
    };
    assert_eq!(outcome, expected.0);
    assert_eq!(
        mount_exit_code(outcome),
        std::process::ExitCode::from(expected.1)
    );
    std::process::exit(expected.1.into());
}
