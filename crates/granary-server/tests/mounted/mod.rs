// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mounted client regression alongside the authority's binary signal rows.
//! The caller supplies a built client and a synthetic loopback publication.
//! There is no dependency from the Apache CLI to the authority test harness.
#![expect(
    clippy::disallowed_methods,
    reason = "test fixture owns its scratch, FIFO, child and proc observations; no store or secret-file access"
)]

use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const START_BOUND: Duration = Duration::from_secs(20);
const EXIT_BOUND: Duration = Duration::from_secs(3);
const SENTINEL: &[u8] = b"local-signal-sentinel";

fn pause() {
    let (_held, receiver) = mpsc::channel::<()>();
    let _ = receiver.recv_timeout(Duration::from_millis(10));
}

fn mount_present(path: &Path) -> bool {
    let table = fs::read_to_string("/proc/self/mountinfo")
        .unwrap_or_else(|_| panic!("mount table available"));
    assert!(!table.is_empty(), "mount table capture must be nonempty");
    table
        .lines()
        .any(|row| row.split_whitespace().nth(4) == path.to_str())
}

struct Fixture {
    root: PathBuf,
    child: Option<Child>,
}
impl Fixture {
    fn new() -> Self {
        #[expect(
            clippy::disallowed_methods,
            reason = "process id only makes an owned runtime scratch name unique; it reaches no identity or signed value"
        )]
        let root =
            std::env::temp_dir().join(format!("granary-signal-local-{}", std::process::id()));
        fs::create_dir(&root)
            .unwrap_or_else(|_| panic!("fresh scratch must be owned by this test"));
        Self { root, child: None }
    }
    fn mounted(&self) -> PathBuf {
        self.root.join("mountpoint")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let mount = self.mounted();
        if mount_present(&mount) {
            let _ = Command::new("/bin/umount")
                .args(["-l"])
                .arg(&mount)
                .status();
        }
        if !mount_present(&mount) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn loopback_environment() -> (PathBuf, String, String, String) {
    let binary = std::env::var_os("GRANARY_SIGNAL_GRAN")
        .unwrap_or_else(|| panic!("built gran path required"));
    let binary = fs::canonicalize(binary).unwrap_or_else(|_| panic!("built gran must exist"));
    let endpoint = std::env::var("GRANARY_SIGNAL_ENDPOINT")
        .unwrap_or_else(|_| panic!("synthetic loopback endpoint required"));
    let address = endpoint
        .strip_prefix("https://")
        .and_then(|authority| authority.parse::<std::net::SocketAddr>().ok());
    assert!(
        address.is_some_and(|address| address.ip().is_loopback() && address.port() != 0),
        "synthetic peer must be a numeric loopback endpoint"
    );
    let pin = std::env::var("GRANARY_SIGNAL_PIN")
        .unwrap_or_else(|_| panic!("synthetic TLS public pin required"));
    let root_key = std::env::var("GRANARY_SIGNAL_ROOT_KEY")
        .unwrap_or_else(|_| panic!("synthetic publication public key required"));
    (binary, endpoint, pin, root_key)
}

fn fill(holder: &mut File) -> usize {
    let mut bytes = 0;
    loop {
        match holder.write(&[0; 4096]) {
            Ok(0) => panic!("pipe fill made no progress"),
            Ok(size) => bytes += size,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("pipe fill failed before backpressure: {:?}", error.kind()),
        }
    }
    assert!(bytes >= 4096, "nonempty kernel pipe capacity premise");
    assert!(
        holder
            .write(&[0])
            .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
        "one-byte fullness probe must refuse"
    );
    bytes
}

fn blocked_writer(pid: u32) -> bool {
    let tasks = fs::read_dir(format!("/proc/{pid}/task"))
        .unwrap_or_else(|_| panic!("owned live child tasks available"));
    tasks.filter_map(Result::ok).any(|task| {
        fs::read_to_string(task.path().join("wchan")).is_ok_and(|wait| wait.trim() == "pipe_write")
    })
}

#[test]
#[ignore = "requires Linux FUSE, a built gran and the documented synthetic loopback publication"]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered mounted/draining/backpressured signal matrix pins all premises and cleanup"
)]
fn sigterm_unmounts_with_local_stderr_backpressured_and_file_logging() {
    assert!(
        std::env::consts::OS == "linux",
        "mounted regression requires Linux"
    );
    assert!(Path::new("/dev/fuse").exists(), "FUSE device premise");
    let (binary, endpoint, pin, root_key) = loopback_environment();
    for format in ["text", "json"] {
        for with_file in [false, true] {
            for blocked in [false, true] {
                let mut fixture = Fixture::new();
                let mount = fixture.mounted();
                fs::create_dir(&mount).unwrap();
                let fifo = fixture.root.join("stderr.pipe");
                assert!(
                    Command::new("/usr/bin/mkfifo")
                        .arg(&fifo)
                        .status()
                        .unwrap()
                        .success(),
                    "owned FIFO creation"
                );
                let mut holder = File::options()
                    .read(true)
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&fifo)
                    .unwrap();
                let filled = if blocked { fill(&mut holder) } else { 0 };
                let stderr = File::options().write(true).open(&fifo).unwrap();
                let mut command = Command::new(&binary);
                command
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("NO_COLOR", "1")
                    .current_dir(&fixture.root)
                    .args([
                        "--log-format",
                        format,
                        "--log-filter",
                        "trace",
                        "--log-paths",
                        "redacted",
                    ]);
                if with_file {
                    command.args(["--log-file", "telemetry.log"]);
                }
                command
                    .args([
                        "mount",
                        "signal-local-volume",
                        "mountpoint",
                        "--endpoint",
                        &endpoint,
                        "--pin",
                        &pin,
                        "--root-key",
                        &root_key,
                        "--foreground",
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::from(stderr));
                fixture.child = Some(
                    command
                        .spawn()
                        .unwrap_or_else(|_| panic!("owned mount child starts")),
                );
                let mut local = Vec::new();
                let started = Instant::now();
                while !mount_present(&mount) {
                    assert!(
                        started.elapsed() < START_BOUND,
                        "mount readiness exceeded bound"
                    );
                    assert!(
                        fixture
                            .child
                            .as_mut()
                            .unwrap()
                            .try_wait()
                            .unwrap()
                            .is_none(),
                        "child exited before real kernel mount"
                    );
                    if !blocked {
                        let mut bytes = [0; 4096];
                        if let Ok(size) = holder.read(&mut bytes) {
                            local.extend_from_slice(&bytes[..size]);
                        }
                    }
                    pause();
                }
                // Read the mounted file in an independently bounded child. This
                // proves a usable FUSE session, rather than a readiness message.
                let mut reader = Command::new("/bin/cat")
                    .arg(mount.join("sentinel.txt"))
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                let read_start = Instant::now();
                while reader.try_wait().unwrap().is_none() {
                    if read_start.elapsed() > EXIT_BOUND {
                        let _ = reader.kill();
                        let _ = reader.wait();
                        panic!("mounted sentinel read exceeded bound");
                    }
                    pause();
                }
                let output = reader.wait_with_output().unwrap();
                assert!(
                    output.status.success() && output.stdout == SENTINEL,
                    "mounted synthetic sentinel must match"
                );
                let child = fixture.child.as_mut().unwrap();
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "signal must reach a live mounted child"
                );
                let pid = child.id();
                if blocked {
                    let started = Instant::now();
                    while !blocked_writer(pid) {
                        assert!(
                            started.elapsed() < EXIT_BOUND,
                            "owned Local/stderr writer never entered blocked pipe"
                        );
                        pause();
                    }
                    assert!(
                        holder
                            .write(&[0])
                            .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
                        "stderr must remain full at SIGTERM"
                    );
                }
                let signalled = Instant::now();
                assert!(
                    Command::new("/bin/kill")
                        .args(["-TERM", &pid.to_string()])
                        .status()
                        .unwrap()
                        .success(),
                    "SIGTERM delivered only to owned child"
                );
                let status = loop {
                    if let Some(status) = fixture.child.as_mut().unwrap().try_wait().unwrap() {
                        break status;
                    }
                    assert!(
                        signalled.elapsed() < EXIT_BOUND,
                        "SIGTERM exit exceeded mounted close bound"
                    );
                    if !blocked {
                        let mut bytes = [0; 4096];
                        if let Ok(size) = holder.read(&mut bytes) {
                            local.extend_from_slice(&bytes[..size]);
                        }
                    }
                    pause();
                };
                assert!(
                    status.code() == Some(0),
                    "SIGTERM must cleanly drain the mounted client"
                );
                assert!(
                    !mount_present(&mount),
                    "SIGTERM must remove the real kernel mount"
                );
                let mut residue = [0; 4096];
                while let Ok(size) = holder.read(&mut residue) {
                    if size == 0 {
                        break;
                    }
                    local.extend_from_slice(&residue[..size]);
                }
                if blocked {
                    assert!(local.len() >= filled, "held pipe pressure witness lost");
                } else {
                    let text = String::from_utf8(local)
                        .unwrap_or_else(|_| panic!("draining fixture UTF-8"));
                    assert!(
                        text.contains("gran mount: pinned volume=signal-local-volume")
                            && text.contains("gran mount: history:"),
                        "draining Local pinned/history premise must deliver"
                    );
                }
                if with_file {
                    let log = fs::read_to_string(fixture.root.join("telemetry.log")).unwrap();
                    assert!(
                        log.contains("log.config"),
                        "file destination must be active"
                    );
                    assert!(
                        !log.contains("gran mount: pinned")
                            && !log.contains("gran mount: history:"),
                        "Local output must never tee into file telemetry"
                    );
                }
                fixture.child.take();
            }
        }
    }
}
