// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mounted multi-writer composition over the real authority transport.

#[cfg(feature = "crash-points")]
pub(super) mod server_crash;

use crate::config::{
    ENV_AWS_ACCESS_KEY_ID, ENV_AWS_SECRET_ACCESS_KEY, ENV_AWS_SESSION_TOKEN, ENV_STORE,
    ENV_STORE_BUCKET, ENV_STORE_ENDPOINT, ENV_STORE_REGION, STORE_MEMORY, STORE_S3,
};
use object_store::ObjectStore;
use std::collections::BTreeMap;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::PathBuf;
use std::sync::{Arc, atomic::AtomicU64, atomic::Ordering};

const CI_MARKER: &str = "GRAN_CI_ID";
const MINIO_DISCRIMINANTS: [&str; 3] = [ENV_STORE_BUCKET, ENV_STORE_ENDPOINT, ENV_STORE_REGION];
const MINIO_REQUIRED: [&str; 5] = [
    ENV_STORE_BUCKET,
    ENV_STORE_ENDPOINT,
    ENV_STORE_REGION,
    ENV_AWS_ACCESS_KEY_ID,
    ENV_AWS_SECRET_ACCESS_KEY,
];

#[cfg(any(target_os = "linux", feature = "crash-points"))]
fn write_direct(bytes: &[u8]) {
    use std::io::Write as _;
    let _ = tracing_subscriber::fmt::TestWriter::new().write_all(bytes);
}

struct SelectedStore {
    backend: Arc<dyn ObjectStore>,
    label: &'static str,
}

struct ProtectedKeys(PathBuf);

impl ProtectedKeys {
    fn new(euid: u32) -> Result<Self, String> {
        let current = std::env::current_dir()
            .and_then(std::fs::canonicalize)
            .map_err(|error| {
                format!("writable integration cannot resolve its checkout: {error}")
            })?;
        let checkout = current
            .ancestors()
            .find(|path| path.join("Cargo.lock").is_file() && path.join("crates").is_dir())
            .unwrap_or(&current)
            .to_owned();
        // A shared sticky /tmp fails the seed custody walk, so HOME is the
        // last candidate; both are checked against the checkout below.
        let mut bases = Vec::new();
        if let Some(temporary) = std::env::var_os("TMPDIR") {
            bases.push(PathBuf::from(temporary));
        }
        if let Some(home) = std::env::var_os("HOME") {
            bases.push(PathBuf::from(home));
        }
        if bases.is_empty() {
            return Err("writable integration key custody requires TMPDIR or HOME".to_owned());
        }
        Self::new_among(euid, &bases, &checkout)
    }

    fn new_under(
        euid: u32,
        temporary: &std::path::Path,
        checkout: &std::path::Path,
    ) -> Result<Self, String> {
        Self::new_among(euid, &[temporary.to_owned()], checkout)
    }

    fn new_among(euid: u32, bases: &[PathBuf], checkout: &std::path::Path) -> Result<Self, String> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut candidates = Vec::new();
        for base in bases {
            let Ok(base) = std::fs::canonicalize(base) else {
                continue;
            };
            if let Some(parent) = base.parent() {
                let parent = parent.to_owned();
                candidates.push(base);
                candidates.push(parent);
            } else {
                candidates.push(base);
            }
        }
        let mut random = [0_u8; 16];
        granary_core::secure_random::SecureRandom::fill(
            &mut granary_net::secure_random::OsSecureRandom::new(),
            &mut random,
        )
        .map_err(|_| "writable integration key custody could not mint a run name".to_owned())?;
        let mut run_name = String::with_capacity(random.len() * 2);
        for byte in random {
            std::fmt::Write::write_fmt(&mut run_name, format_args!("{byte:02x}"))
                .map_err(|_| "writable integration key custody could not format a run name")?;
        }
        for candidate in candidates {
            let Ok(base) = std::fs::canonicalize(candidate) else {
                continue;
            };
            if base.starts_with(checkout) {
                continue;
            }
            if granary_client::signing_seed_paths(&base.join("integration-custody-probe"), euid)
                .is_err()
            {
                continue;
            }
            let parent = base.join(".granary-integration-keys");
            match std::fs::DirBuilder::new().mode(0o700).create(&parent) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => continue,
            }
            let Ok(parent) = std::fs::canonicalize(parent) else {
                continue;
            };
            if parent.starts_with(checkout)
                || granary_client::signing_seed_paths(
                    &parent.join("integration-custody-probe"),
                    euid,
                )
                .is_err()
            {
                continue;
            }
            for _ in 0..1_024 {
                let path = parent.join(format!(
                    "run-{run_name}-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => {
                        if granary_client::signing_seed_paths(&path.join("root.seed"), euid).is_ok()
                        {
                            return Ok(Self(path));
                        }
                        let _ = std::fs::remove_dir(&path);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(_) => break,
                }
            }
        }
        Err(format!(
            "writable integration key custody found no external TMPDIR run directory accepted by the signing-seed ancestor rule for uid {euid}"
        ))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    #[cfg(target_os = "linux")]
    fn run_name(&self) -> Result<&str, String> {
        self.0
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "writable integration run directory has no UTF-8 name".to_owned())
    }
}

impl Drop for ProtectedKeys {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn select_store(get: &dyn Fn(&str) -> Option<String>) -> Result<SelectedStore, String> {
    let configured = MINIO_DISCRIMINANTS
        .iter()
        .any(|name| get(name).is_some_and(|value| !value.is_empty()));
    if !configured {
        if get(CI_MARKER).is_some() {
            return Err(format!(
                "integration MinIO configuration is required under {CI_MARKER}: {ENV_STORE_ENDPOINT} is not set"
            ));
        }
        let config = crate::config::store_from_lookup(&|name| {
            (name == ENV_STORE).then(|| STORE_MEMORY.to_owned())
        })?;
        return Ok(SelectedStore {
            backend: config.store,
            label: "InMemory",
        });
    }
    for name in MINIO_REQUIRED {
        if get(name).is_none_or(|value| value.is_empty()) {
            return Err(format!(
                "integration MinIO configuration is incomplete: {name} is not set"
            ));
        }
    }
    let config = crate::config::store_from_lookup(&|name| match name {
        ENV_STORE => Some(STORE_S3.to_owned()),
        ENV_STORE_BUCKET
        | ENV_STORE_ENDPOINT
        | ENV_STORE_REGION
        | ENV_AWS_ACCESS_KEY_ID
        | ENV_AWS_SECRET_ACCESS_KEY => get(name),
        _ => None,
    })?;
    Ok(SelectedStore {
        backend: config.store,
        label: "S3/MinIO",
    })
}

#[cfg(target_os = "linux")]
fn selected_for_row(keys: &ProtectedKeys) -> Result<SelectedStore, String> {
    let selected = select_store(&|name| std::env::var(name).ok())?;
    let prefix = format!("mounted-convergence-{}", keys.run_name()?);
    Ok(SelectedStore {
        backend: Arc::new(object_store::prefix::PrefixStore::new(
            selected.backend,
            prefix,
        )),
        label: selected.label,
    })
}

fn complete_minio() -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        (ENV_STORE_BUCKET, "fixture-bucket".to_owned()),
        (ENV_STORE_ENDPOINT, "http://127.0.0.1:9000".to_owned()),
        (ENV_STORE_REGION, "us-east-1".to_owned()),
        (ENV_AWS_ACCESS_KEY_ID, "fixture-access".to_owned()),
        (ENV_AWS_SECRET_ACCESS_KEY, "fixture-secret".to_owned()),
    ])
}

#[test]
fn integration_store_selection_valid_and_malformed_controls() {
    let valid = complete_minio();
    let selected = select_store(&|name| {
        assert_ne!(
            name, ENV_AWS_SESSION_TOKEN,
            "session token must not be read"
        );
        valid.get(name).cloned()
    })
    .unwrap();
    let iteration = select_store(&|_| None).unwrap();
    let ambient = BTreeMap::from([
        (ENV_AWS_ACCESS_KEY_ID, "ambient-access".to_owned()),
        (ENV_AWS_SECRET_ACCESS_KEY, "ambient-secret".to_owned()),
        (ENV_AWS_SESSION_TOKEN, "ambient-session".to_owned()),
    ]);
    let ignored = select_store(&|name| ambient.get(name).cloned()).unwrap();
    let mut malformed = valid.clone();
    malformed.insert(ENV_AWS_SECRET_ACCESS_KEY, String::new());
    let refused = select_store(&|name| {
        assert_ne!(
            name, ENV_AWS_SESSION_TOKEN,
            "session token must not be read"
        );
        malformed.get(name).cloned()
    })
    .err()
    .unwrap();
    let cases = 4;
    assert_eq!(
        (
            selected.label,
            selected.backend.to_string(),
            iteration.label,
            iteration.backend.to_string(),
            ignored.label,
            ignored.backend.to_string(),
            refused.as_str(),
            cases,
        ),
        (
            "S3/MinIO",
            "AmazonS3(fixture-bucket)".to_owned(),
            "InMemory",
            "InMemory".to_owned(),
            "InMemory",
            "InMemory".to_owned(),
            "integration MinIO configuration is incomplete: AWS_SECRET_ACCESS_KEY is not set",
            4
        )
    );
}

#[test]
fn integration_ci_requires_minio_valid_and_malformed_controls() {
    let mut valid = complete_minio();
    valid.insert(CI_MARKER, "fixture-run".to_owned());
    let selected = select_store(&|name| valid.get(name).cloned()).unwrap();
    let refused = select_store(&|name| (name == CI_MARKER).then(|| "fixture-run".to_owned()))
        .err()
        .unwrap();
    let cases = 2;
    assert_eq!(
        (
            selected.label,
            selected.backend.to_string(),
            refused.as_str(),
            cases,
        ),
        (
            "S3/MinIO",
            "AmazonS3(fixture-bucket)".to_owned(),
            "integration MinIO configuration is required under GRAN_CI_ID: GRANARY_STORE_ENDPOINT is not set",
            2
        )
    );
}

#[test]
fn integration_key_custody_valid_and_malformed_controls() {
    let euid = nix::unistd::geteuid().as_raw();
    let keys = ProtectedKeys::new(euid).unwrap();
    let valid = granary_client::signing_seed_paths(&keys.path("root.seed"), euid).is_ok();
    let current = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
    let checkout = current
        .ancestors()
        .find(|path| path.join("Cargo.lock").is_file() && path.join("crates").is_dir())
        .unwrap_or(&current)
        .to_owned();
    let external = !keys.0.starts_with(&checkout);
    let refused_external = ProtectedKeys::new_under(euid, &checkout.join("crates"), &checkout)
        .err()
        .unwrap();
    let unsafe_ancestor = keys.path("unsafe-ancestor");
    std::fs::DirBuilder::new()
        .mode(0o777)
        .create(&unsafe_ancestor)
        .unwrap();
    std::fs::set_permissions(&unsafe_ancestor, std::fs::Permissions::from_mode(0o777)).unwrap();
    let refused = granary_client::signing_seed_paths(&unsafe_ancestor.join("root.seed"), euid)
        .err()
        .unwrap();
    let expected_external = format!(
        "writable integration key custody found no external TMPDIR run directory accepted by the signing-seed ancestor rule for uid {euid}"
    );
    let cases = 3;
    assert_eq!(
        (
            valid,
            external,
            refused_external.as_str(),
            refused.contains("unsafe seed ancestor"),
            cases
        ),
        (true, true, expected_external.as_str(), true, 3,),
        "valid custody and writable-ancestor refusal"
    );
}

#[cfg(target_os = "linux")]
mod mounted {
    #[cfg(feature = "overlay-fault-tests")]
    mod bounded_unmount;
    mod crash;
    #[cfg(all(feature = "crash-points", feature = "overlay-fault-tests"))]
    mod disk_loss;
    #[cfg(feature = "crash-points")]
    mod server_crash;

    use super::super::{Fixture, Server, roomy};
    use super::*;
    use granary_client::{
        BundleHistory, CacheOrigin, FaultAction, FaultControl, LocalRecord, LocalRecordWriter,
        LogFormat, LogPaths, MetricsError, MetricsSnapshot, MountOptions, MountSession,
        SyncProfile, ViewMode, WritableProcess, WritableStart, WritableSyncRuntime, start_writable,
    };
    use granary_core::rootstore::RootStore as _;
    use granary_fuse::{MountIdentity, SessionEndEvidence, classify_session_end};
    use granary_net::secure_random::OsSecureRandom;
    use granary_sim::secure_random::SeededSecureRandom;
    use granary_store::crypto::{SigningKey, TrustedKeys};
    use nix::mount::{MntFlags, umount2};
    use std::io::{self, Read as _, Write as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    use tracing_subscriber::EnvFilter;

    const WAIT: Duration = Duration::from_secs(10);
    #[cfg(feature = "crash-points")]
    const REFRESH: (&str, &str) = ("sync.commit", "landed_refresh");
    const CACHE_QUOTA: u64 = 1_073_741_824;
    const WRITABLE_JOIN_BOUND: Duration = Duration::from_secs(31);
    const READER_JOIN_BOUND: Duration = Duration::from_secs(2);
    const ABORT_JOIN_BOUND: Duration = Duration::from_secs(5);
    const FULL_PATH_CHILD_BOUND: Duration = WAIT
        .saturating_add(WAIT)
        .saturating_add(WAIT)
        .saturating_add(WRITABLE_JOIN_BOUND)
        .saturating_add(WRITABLE_JOIN_BOUND)
        .saturating_add(WRITABLE_JOIN_BOUND);
    const JOIN_POLL: Duration = Duration::from_millis(10);
    const FULL_PATH_CHILD: &str = "GRANARY_MOUNTED_FULL_PATH_CHILD";
    const CONFLICT_NAME: &str = "granary-conflict-\npath-7f3a";
    const BASE_BYTES: &[u8] = b"base bytes";
    const LOSER_BYTES: &[u8] = b"writer-a bytes";
    const WINNER_BYTES: &[u8] = b"writer-b bytes";

    static ROW: Mutex<()> = Mutex::new(());

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);
    impl granary_client::RecordWriter for Captured {
        fn write_record(&self, record: &granary_client::LogRecord) {
            self.write(record.as_bytes());
        }
    }
    impl Captured {
        fn write(&self, bytes: &[u8]) {
            if bytes
                .windows(b"\"event\":\"integration.".len())
                .any(|window| window == b"\"event\":\"integration.")
            {
                write_direct(bytes);
            }
            self.0.lock().unwrap().extend_from_slice(bytes);
        }
        fn store(&self, label: &str) {
            self.write(
                format!("{{\"event\":\"integration.store\",\"store\":\"{label}\"}}\n").as_bytes(),
            );
        }
        fn clear(&self) {
            self.0.lock().unwrap().clear();
        }
        fn lines(&self) -> Vec<String> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    fn capture(paths: LogPaths) -> Captured {
        static CAPTURE: OnceLock<Captured> = OnceLock::new();
        static PATHS: OnceLock<LogPaths> = OnceLock::new();
        assert_eq!(PATHS.get_or_init(|| paths), &paths);
        CAPTURE
            .get_or_init(|| {
                let captured = Captured::default();
                let writer = captured.clone();
                let subscriber = granary_client::closed_subscriber_with_paths(
                    LogFormat::Json,
                    EnvFilter::new("trace"),
                    writer,
                    paths,
                    BundleHistory::default(),
                );
                tracing::subscriber::set_global_default(subscriber).unwrap();
                captured
            })
            .clone()
    }

    #[derive(Clone, Default)]
    struct LocalCaptured(Arc<Mutex<Vec<Vec<u8>>>>);
    impl LocalRecordWriter for LocalCaptured {
        fn write_local(&self, record: &LocalRecord) {
            self.0.lock().unwrap().push(record.as_bytes().to_vec());
        }
    }
    impl LocalCaptured {
        fn clear(&self) {
            self.0.lock().unwrap().clear();
        }

        fn records(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .map(|record| String::from_utf8(record.clone()).unwrap())
                .collect()
        }
    }

    fn local_capture() -> LocalCaptured {
        static CAPTURE: OnceLock<LocalCaptured> = OnceLock::new();
        CAPTURE
            .get_or_init(|| {
                let captured = LocalCaptured::default();
                granary_client::install_local_reports(Arc::new(captured.clone())).unwrap();
                captured
            })
            .clone()
    }

    fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
        let prefix = format!("\"{name}\":\"");
        line.split_once(&prefix)?
            .1
            .split_once('"')
            .map(|(value, _)| value)
    }

    fn number_field(line: &str, name: &str) -> Option<u64> {
        let prefix = format!("\"{name}\":");
        let value = line.split_once(&prefix)?.1;
        let end = value
            .find(|byte: char| !byte.is_ascii_digit())
            .unwrap_or(value.len());
        value.get(..end)?.parse().ok()
    }

    fn retry_attributed_to_armed_fault(lines: &[String]) -> Option<(String, String, String)> {
        let fault = lines.iter().find(|line| {
            field(line, "event") == Some("sync.fault")
                && field(line, "point") == Some("sync.commit")
                && field(line, "phase") == Some("before_submit")
        });
        let operation = fault.and_then(|line| field(line, "op"))?;
        lines.iter().find_map(|line| {
            (field(line, "event") == Some("op.retry") && field(line, "op") == Some(operation)).then(
                || {
                    (
                        operation.to_owned(),
                        field(line, "kind").unwrap_or("<missing>").to_owned(),
                        field(line, "reason").unwrap_or("<missing>").to_owned(),
                    )
                },
            )
        })
    }

    fn metric(snapshot: &dyn Fn() -> Result<MetricsSnapshot, MetricsError>, name: &str) -> u64 {
        let text = snapshot()
            .and_then(|snapshot| snapshot.render_prometheus())
            .unwrap();
        text.lines()
            .find_map(|line| {
                let (got_name, value) = line.split_once(' ')?;
                (got_name == name).then(|| value.parse::<u64>().unwrap())
            })
            .unwrap_or_else(|| panic!("metrics snapshot omitted {name}: {text}"))
    }

    fn venue(name: &str) -> bool {
        let root = nix::unistd::geteuid().is_root();
        let fuse = std::fs::metadata("/dev/fuse")
            .is_ok_and(|metadata| metadata.file_type().is_char_device());
        if !root || !fuse {
            let marker = if root {
                "SKIPPED-NO-DEV-FUSE"
            } else {
                "NOT EXECUTED"
            };
            write_direct(
                format!(
                    "{{\"event\":\"integration.skipped\",\"case\":\"{name}\",\"marker\":\"{marker}\",\"reason\":\"root-and-dev-fuse-required\"}}\n"
                )
                .as_bytes(),
            );
        }
        root && fuse
    }

    fn mount_connection(path: &Path) -> io::Result<Option<u64>> {
        let mut escaped = Vec::new();
        for &byte in path.as_os_str().as_bytes() {
            match byte {
                b' ' => escaped.extend_from_slice(b"\\040"),
                b'\t' => escaped.extend_from_slice(b"\\011"),
                b'\n' => escaped.extend_from_slice(b"\\012"),
                b'\\' => escaped.extend_from_slice(b"\\134"),
                _ => escaped.push(byte),
            }
        }
        let mountinfo = std::fs::read("/proc/self/mountinfo")?;
        for line in mountinfo.split(|&byte| byte == b'\n') {
            let mut fields = line.split(|&byte| byte == b' ');
            let device = fields.nth(2);
            if fields.nth(1) != Some(escaped.as_slice()) {
                continue;
            }
            let kind = fields.skip_while(|field| *field != b"-").nth(1);
            if !kind.is_some_and(|field| field == b"fuse" || field.starts_with(b"fuse.")) {
                return Err(io::Error::other("integration mount is not FUSE"));
            }
            let minor = device
                .and_then(|value| value.strip_prefix(b"0:"))
                .and_then(|value| std::str::from_utf8(value).ok())
                .and_then(|value| value.parse().ok())
                .ok_or_else(|| {
                    io::Error::other("integration FUSE mount has no anonymous device number")
                })?;
            return Ok(Some(minor));
        }
        Ok(None)
    }

    fn wait_for_session(session: &granary_fuse::BackgroundMount, bound: Duration) -> bool {
        let started = Instant::now();
        while !session.guard.is_finished() && started.elapsed() < bound {
            std::thread::sleep(JOIN_POLL);
        }
        session.guard.is_finished()
    }

    struct FuseCleanup {
        mountpoint: PathBuf,
        identity: io::Result<MountIdentity>,
        abort: Option<std::fs::File>,
        join_bound: Duration,
    }
    impl FuseCleanup {
        fn arm(mountpoint: &Path, join_bound: Duration) -> Self {
            let connection = mount_connection(mountpoint);
            let abort = connection
                .as_ref()
                .ok()
                .and_then(|connection| *connection)
                .and_then(|connection| {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(format!("/sys/fs/fuse/connections/{connection}/abort"))
                        .ok()
                });
            if abort.is_none() {
                write_direct(
                    format!(
                        "{{\"event\":\"integration.fuse_abort_unavailable\",\"mount\":{:?},\"connection\":{:?}}}\n",
                        mountpoint.display().to_string(),
                        format!("{connection:?}")
                    )
                    .as_bytes(),
                );
            }
            Self {
                mountpoint: mountpoint.to_owned(),
                identity: MountIdentity::capture(mountpoint),
                abort,
                join_bound,
            }
        }

        fn abort(&mut self) -> io::Result<()> {
            self.abort
                .as_mut()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "integration FUSE connection abort unavailable",
                    )
                })?
                .write_all(b"1")
        }

        fn finish(mut self, session: granary_fuse::BackgroundMount) -> io::Result<()> {
            let detached = umount2(
                &self.mountpoint,
                MntFlags::MNT_DETACH | MntFlags::UMOUNT_NOFOLLOW,
            )
            .map_err(io::Error::from);
            let mut forced = false;
            if !wait_for_session(&session, self.join_bound) {
                self.abort()?;
                forced = true;
                if !wait_for_session(&session, ABORT_JOIN_BOUND) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "integration FUSE worker did not exit after abort",
                    ));
                }
            }
            let joined = session.join();
            let was_detached = detached.is_ok();
            let was_joined = joined.is_ok();
            // A pending FUSE read can return ECONNABORTED during teardown.
            // Verify that the captured mount left this fixture's path.
            let listed = self
                .identity
                .and_then(|identity| identity.listed_at(&self.mountpoint));
            let end = classify_session_end(SessionEndEvidence {
                unmount: detached,
                joined,
                forced,
                listed,
            });
            let verdict = format!("{end:?}");
            write_direct(
                format!(
                    "{{\"event\":\"integration.fuse_cleanup\",\"mount\":{:?},\"forced\":{forced},\"detached\":{was_detached},\"joined\":{was_joined},\"end\":{verdict:?}}}\n",
                    self.mountpoint.display().to_string()
                )
                .as_bytes(),
            );
            end.into_result()
        }
    }

    struct MountGuard {
        mount: Option<granary_fuse::BackgroundMount>,
        cleanup: Option<FuseCleanup>,
    }
    impl MountGuard {
        fn new(mount: granary_fuse::BackgroundMount, cleanup: FuseCleanup) -> Self {
            Self {
                mount: Some(mount),
                cleanup: Some(cleanup),
            }
        }

        fn close(&mut self) -> io::Result<()> {
            let Some(mount) = self.mount.take() else {
                return Ok(());
            };
            let cleanup = self
                .cleanup
                .take()
                .ok_or_else(|| io::Error::other("integration FUSE cleanup state is incomplete"))?;
            cleanup.finish(mount)
        }

        fn abort(&mut self) -> io::Result<()> {
            self.cleanup
                .as_mut()
                .ok_or_else(|| io::Error::other("integration FUSE cleanup state is incomplete"))?
                .abort()
        }
    }
    impl Drop for MountGuard {
        fn drop(&mut self) {
            let _ = self.abort();
            if let Err(error) = self.close() {
                write_direct(
                    format!(
                        "{{\"event\":\"integration.fuse_cleanup_failed\",\"error\":{:?}}}\n",
                        error.to_string()
                    )
                    .as_bytes(),
                );
            }
        }
    }

    struct WritableHandle {
        // Unmount and release every backend owner before stopping the sync runtime.
        mount: MountGuard,
        sync_runtime: Option<WritableSyncRuntime>,
        faults: FaultControl,
        metrics: Box<dyn Fn() -> Result<MetricsSnapshot, MetricsError> + Send + Sync>,
        mountpoint: PathBuf,
        overlay: PathBuf,
        writer: [u8; 16],
    }
    impl WritableHandle {
        fn start(
            input: &WritableStart<'_>,
            clock: &super::super::Ticks,
            random: u8,
            overlay: PathBuf,
        ) -> Self {
            Self::start_with(input, clock, random, overlay, |_| {})
        }

        fn start_with<C: granary_core::clock::Clock + Clone + 'static>(
            input: &WritableStart<'_>,
            clock: &C,
            random: u8,
            overlay: PathBuf,
            arm: impl FnOnce(&FaultControl),
        ) -> Self {
            let mut reports = std::io::sink();
            let proof = start_writable(
                input,
                clock,
                &mut granary_core::rng::SeededRng::new(u64::from(random)),
                &mut SeededSecureRandom::from_key([random; 32]),
                &mut reports,
            )
            .unwrap();
            let writer = proof.owner().0;
            let mut attachment = proof.attach();
            let faults = attachment
                .backend
                .shared_mediator()
                .with(|store| Ok(store.fault_control()))
                .unwrap();
            arm(&faults);
            let metrics = Box::new(attachment.metrics_snapshot());
            let sync_runtime = attachment.start_sync(Arc::new(clock.clone())).unwrap();
            let mount = attachment.mount(u64::from(random)).unwrap();
            let cleanup = FuseCleanup::arm(input.mountpoint, WRITABLE_JOIN_BOUND);
            Self {
                mount: MountGuard::new(mount, cleanup),
                sync_runtime: Some(sync_runtime),
                faults,
                metrics,
                mountpoint: input.mountpoint.to_owned(),
                overlay,
                writer,
            }
        }

        fn finish(mut self) {
            self.faults.resume();
            self.mount.close().unwrap();
            drop(self.sync_runtime.take());
        }
    }
    impl Drop for WritableHandle {
        fn drop(&mut self) {
            self.faults.resume();
            if std::thread::panicking() {
                let _ = self.mount.abort();
            }
        }
    }

    struct ReaderHandle {
        mount: MountGuard,
        mountpoint: PathBuf,
    }
    impl ReaderHandle {
        fn finish(mut self) {
            self.mount.close().unwrap();
        }
    }

    struct Harness {
        runtime: tokio::runtime::Runtime,
        fixture: Fixture,
        server: Option<Server>,
        addr: std::net::SocketAddr,
        keys: ProtectedKeys,
        seed: PathBuf,
        key: SigningKey,
        capture: Captured,
        local_capture: LocalCaptured,
        store_label: &'static str,
    }

    impl Harness {
        fn new(base: Option<(&str, &[u8])>, log_paths: LogPaths) -> Self {
            Self::with_fixture(base, log_paths, |_| {})
        }

        fn with_fixture(
            base: Option<(&str, &[u8])>,
            log_paths: LogPaths,
            configure: impl FnOnce(&mut Fixture),
        ) -> Self {
            let capture = capture(log_paths);
            capture.clear();
            let local_capture = local_capture();
            local_capture.clear();
            let euid = nix::unistd::geteuid().as_raw();
            let keys = ProtectedKeys::new(euid).unwrap_or_else(|error| panic!("{error}"));
            let selected = selected_for_row(&keys).unwrap();
            capture.store(selected.label);
            let mut fixture = Fixture::new(Some(selected.backend));
            configure(&mut fixture);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .unwrap();
            let server = runtime.block_on(fixture.start(41, roomy(), true, None));
            let seed = keys.path("root.seed");
            std::fs::write(&seed, [23; 32]).unwrap();
            std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
            for principal in 0..2 {
                for extension in ["pem", "key"] {
                    let name = format!("client-{principal}.{extension}");
                    let destination = keys.path(&name);
                    std::fs::copy(fixture.dir.join(&name), &destination).unwrap();
                    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
            }
            let key = SigningKey::from_seed(&[23; 32]).unwrap();
            runtime.block_on(publish_base(&fixture, server.addr, &key, base));
            let published_head = runtime
                .block_on(
                    fixture
                        .client(server.addr, 0)
                        .max_seq(fixture.volume().as_str()),
                )
                .unwrap();
            assert_eq!(
                published_head,
                Some(1),
                "the authority must serve the base head before writable admission"
            );
            Self {
                runtime,
                fixture,
                addr: server.addr,
                server: Some(server),
                keys,
                seed,
                key,
                capture,
                local_capture,
                store_label: selected.label,
            }
        }

        fn writer(&self, principal: usize, label: &str, random: u8) -> WritableHandle {
            let root = self.fixture.dir.join(label);
            let store = root.join("store");
            let cache = root.join("cache");
            let mountpoint = root.join("mount");
            for path in [&root, &store, &cache, &mountpoint] {
                std::fs::create_dir_all(path).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let cert = self.keys.path(&format!("client-{principal}.pem"));
            let credential_key = self.keys.path(&format!("client-{principal}.key"));
            let euid = nix::unistd::geteuid().as_raw();
            let group = nix::unistd::getegid().as_raw();
            let endpoint = format!("https://{}", self.addr);
            let public = *self.key.public_key();
            let scope = self.fixture.scope(self.addr, principal);
            let overlay = store
                .join("overlay")
                .join(scope.digest().unwrap())
                .join(self.fixture.volume().as_str());
            let input = WritableStart {
                volume: self.fixture.volume(),
                process: WritableProcess {
                    ruid: euid,
                    rgid: group,
                    egid: group,
                    set_id_tainted: false,
                },
                foreground: true,
                force: false,
                mountpoint: &mountpoint,
                root_key: Some(public),
                manifest_root: None,
                trust_server: false,
                options: MountOptions {
                    allow_other: false,
                    allow_root: false,
                },
                seq: None,
                seed: Some(&self.seed),
                certificate: Some(&cert),
                credential_key: Some(&credential_key),
                scope: Some(scope),
                store: Some(&store),
                cache: Some(&cache),
                cache_origin: CacheOrigin {
                    endpoint_url: endpoint,
                    pin_set_digest: CacheOrigin::pin_set_digest(&[self.fixture.pin]),
                    root_key_id: Some(CacheOrigin::root_key_digest(&public)),
                },
                cache_quota: CACHE_QUOTA,
                contention_threshold: granary_client::ContentionThreshold::default(),
                construction_workspace_bytes: granary_client::SyncOptions::default()
                    .workspace_bytes,
                overlay_cap_bytes: 134_217_728,
                reset_floor: false,
                policy: granary_vfs::AttrPolicy {
                    uid: euid,
                    gid: group,
                },
                euid,
                sync_profile: SyncProfile::Published,
                view: ViewMode::Default,
            };
            WritableHandle::start(&input, &self.fixture.clock, random, overlay)
        }

        fn reader(&self) -> ReaderHandle {
            let root = self.fixture.dir.join("reader");
            let cache = root.join("cache");
            let mountpoint = root.join("mount");
            for path in [&root, &cache, &mountpoint] {
                std::fs::create_dir_all(path).unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let public = *self.key.public_key();
            let remote = self.fixture.client(self.addr, 0);
            let origin = CacheOrigin {
                endpoint_url: format!("https://{}", self.addr),
                pin_set_digest: CacheOrigin::pin_set_digest(&[self.fixture.pin]),
                root_key_id: Some(CacheOrigin::root_key_digest(&public)),
            };
            let mut reports = Vec::new();
            let mut session = MountSession::open(
                remote,
                self.fixture.volume(),
                Some(Box::new(public)),
                None,
                false,
                None,
                &cache,
                CACHE_QUOTA,
                &origin,
                MountOptions {
                    allow_other: false,
                    allow_root: false,
                },
                &mut reports,
            )
            .unwrap();
            let snapshot = session
                .snapshot(granary_vfs::AttrPolicy {
                    uid: nix::unistd::geteuid().as_raw(),
                    gid: nix::unistd::getegid().as_raw(),
                })
                .unwrap();
            let mount = granary_fuse::spawn_session(
                snapshot,
                session,
                99,
                granary_fuse::MountWritability::ReadOnly,
                &mountpoint,
                &granary_fuse::session_config(false),
            )
            .unwrap();
            let cleanup = FuseCleanup::arm(&mountpoint, READER_JOIN_BOUND);
            ReaderHandle {
                mount: MountGuard::new(mount, cleanup),
                mountpoint,
            }
        }

        fn stop(mut self) {
            self.stop_server();
        }

        fn stop_server(&mut self) {
            if let Some(server) = self.server.take() {
                self.runtime.block_on(server.stop());
            }
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.stop_server();
        }
    }

    async fn publish_base(
        fx: &Fixture,
        addr: std::net::SocketAddr,
        key: &SigningKey,
        seed: Option<(&str, &[u8])>,
    ) {
        let path = fx.dir.join("base-store");
        let source = fx.dir.join("base-source");
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(&source).unwrap();
        if let Some((name, bytes)) = seed {
            std::fs::write(source.join(name), bytes).unwrap();
        }
        let mut store = granary_client::Store::open(&path).unwrap();
        let (manifest, _) = granary_client::harvest(&source, &store).unwrap();
        let trusted = TrustedKeys::new([*key.public_key()]).unwrap();
        let remote = fx.client(addr, 0);
        let mut journal = store
            .publications(std::fs::metadata(&path).unwrap().uid())
            .unwrap();
        let landed = granary_client::begin_publication(
            granary_client::RecoveryParts {
                transport: &remote,
                journal: &mut journal,
                publisher_keys: &trusted,
                signer: key,
                secure: &mut OsSecureRandom::new(),
                clock: &fx.clock,
                delay: &mut granary_client::RecoveryBackoff {
                    rng: granary_core::rng::SeededRng::new(1),
                },
            },
            fx.scope(addr, 0),
            fx.volume(),
            manifest,
            granary_client::Policy::default(),
        )
        .await
        .unwrap();
        assert!(matches!(
            landed.outcome,
            granary_client::PublicationOutcome::Landed(_)
        ));
    }

    fn wait_until(mut predicate: impl FnMut() -> bool, message: &str) {
        let started = Instant::now();
        while !predicate() {
            assert!(started.elapsed() < WAIT, "{message}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(feature = "crash-points")]
    fn held(faults: &FaultControl, (point, phase): (&str, &str)) -> granary_client::SyncFaultEvent {
        let mut held = None;
        wait_until(
            || {
                held = faults
                    .sync_fired()
                    .into_iter()
                    .find(|event| (event.name, event.phase) == (point, phase));
                held.is_some()
            },
            &format!("mounted client did not reach {point}/{phase}"),
        );
        held.unwrap()
    }

    fn finished_within<T>(handle: &std::thread::JoinHandle<T>, bound: Duration) -> bool {
        let started = Instant::now();
        while !handle.is_finished() && started.elapsed() < bound {
            std::thread::sleep(JOIN_POLL);
        }
        handle.is_finished()
    }

    enum FuseCallResult<T> {
        Returned(T),
        Panicked,
    }

    struct FuseCall<T> {
        handle: std::thread::JoinHandle<()>,
        result: std::sync::mpsc::Receiver<FuseCallResult<T>>,
    }

    fn spawn_fuse<T: Send + 'static>(call: impl FnOnce() -> T + Send + 'static) -> FuseCall<T> {
        let (sender, result) = std::sync::mpsc::sync_channel(1);
        let handle = std::thread::spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(call))
                .map_or(FuseCallResult::Panicked, FuseCallResult::Returned);
            let _ = sender.send(outcome);
        });
        FuseCall { handle, result }
    }

    fn join_fuse_within<T>(
        call: FuseCall<T>,
        mount: &mut MountGuard,
        bound: Duration,
        message: &str,
    ) -> T {
        let received = call.result.recv_timeout(bound);
        let normal = matches!(&received, Ok(FuseCallResult::Returned(_)));
        if !normal {
            mount
                .abort()
                .unwrap_or_else(|error| panic!("{message}: cannot abort FUSE connection: {error}"));
        }
        let stopped = finished_within(&call.handle, ABORT_JOIN_BOUND);
        if !stopped && normal {
            mount
                .abort()
                .unwrap_or_else(|error| panic!("{message}: cannot abort FUSE connection: {error}"));
        }
        assert!(
            stopped || finished_within(&call.handle, ABORT_JOIN_BOUND),
            "{message}: thread survived FUSE abort"
        );
        call.handle
            .join()
            .unwrap_or_else(|_| panic!("{message}: wrapper thread panicked"));
        match received {
            Ok(FuseCallResult::Returned(result)) => result,
            Ok(FuseCallResult::Panicked) => panic!("{message}: FUSE syscall thread panicked"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("{message}"),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("{message}: FUSE syscall result disconnected")
            }
        }
    }

    fn join_within<T>(handle: std::thread::JoinHandle<T>, bound: Duration, message: &str) -> T {
        assert!(finished_within(&handle, bound), "{message}");
        handle
            .join()
            .unwrap_or_else(|_| panic!("{message}: thread panicked"))
    }

    struct ReexecChild(std::process::Child);

    impl Drop for ReexecChild {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }

    struct ReexecOutput {
        status: std::process::ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        timed_out: bool,
    }

    fn run_full_path_child() -> ReexecOutput {
        let mut child = ReexecChild(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "conformance_http::intents::convergence::mounted::mounted_full_path_conflict_reexec_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(FULL_PATH_CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut stdout = child.0.stdout.take().unwrap();
        let stdout = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).map(|_| bytes)
        });
        let mut stderr = child.0.stderr.take().unwrap();
        let stderr = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes).map(|_| bytes)
        });
        let started = Instant::now();
        let (status, timed_out) = 'child: loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break (status, false);
            }
            if started.elapsed() >= FULL_PATH_CHILD_BOUND {
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(i32::try_from(child.0.id()).unwrap()),
                    nix::sys::signal::Signal::SIGTERM,
                )
                .unwrap();
                let grace_started = Instant::now();
                loop {
                    if let Some(status) = child.0.try_wait().unwrap() {
                        break 'child (status, true);
                    }
                    if grace_started.elapsed() >= ABORT_JOIN_BOUND {
                        nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(i32::try_from(child.0.id()).unwrap()),
                            nix::sys::signal::Signal::SIGKILL,
                        )
                        .unwrap();
                        break 'child (child.0.wait().unwrap(), true);
                    }
                    std::thread::sleep(JOIN_POLL);
                }
            }
            std::thread::sleep(JOIN_POLL);
        };
        ReexecOutput {
            status,
            stdout: stdout.join().unwrap().unwrap(),
            stderr: stderr.join().unwrap().unwrap(),
            timed_out,
        }
    }

    fn head_seq(harness: &Harness) -> u64 {
        harness
            .runtime
            .block_on(async {
                tokio::time::timeout(
                    WAIT,
                    harness
                        .fixture
                        .client(harness.addr, 0)
                        .max_seq(harness.fixture.volume().as_str()),
                )
                .await
            })
            .unwrap_or_else(|_| panic!("authority head query exceeded {WAIT:?}"))
            .unwrap()
            .unwrap()
    }

    fn root(harness: &Harness, seq: u64) -> Vec<u8> {
        harness
            .runtime
            .block_on(
                harness
                    .fixture
                    .client(harness.addr, 0)
                    .get_root(harness.fixture.volume().as_str(), seq),
            )
            .unwrap()
            .unwrap()
    }

    fn verify_root(bytes: &[u8], trusted: &TrustedKeys) -> granary_core::root::RootDoc {
        let doc = granary_core::root::decode_root(bytes).unwrap();
        let prefix = granary_core::root::signing_prefix_of(&doc).unwrap();
        granary_store::crypto::check_signatures(&doc, &prefix, trusted).unwrap();
        doc
    }

    fn mounted_names(mountpoint: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(mountpoint)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct IntentSnapshot {
        epoch: u64,
        generation: u64,
        root: Vec<u8>,
        live_rows: usize,
        live_root_bytes: usize,
    }

    fn intent_snapshot(harness: &Harness, principal: usize, writer: [u8; 16]) -> IntentSnapshot {
        let trusted = TrustedKeys::new([*harness.key.public_key()]).unwrap();
        let addr = harness.addr;
        let reply = harness
            .runtime
            .block_on(
                harness
                    .fixture
                    .client(addr, principal)
                    .intent_readback_once(
                        &harness.fixture.scope(addr, principal),
                        &harness.fixture.volume(),
                        |doc, prefix| {
                            granary_store::crypto::check_signatures(doc, prefix, &trusted).is_ok()
                        },
                    ),
            )
            .unwrap();
        let readback = granary_core::intent::decode_readback(
            reply.body(),
            &harness.fixture.volume(),
            |doc, prefix| granary_store::crypto::check_signatures(doc, prefix, &trusted).is_ok(),
        )
        .unwrap();
        let rows: Vec<_> = readback
            .rows
            .iter()
            .filter(|row| row.writer == writer)
            .collect();
        let [row] = rows.as_slice() else {
            panic!(
                "the loser's registered intent is ambiguous: {} rows",
                rows.len()
            );
        };
        IntentSnapshot {
            epoch: row.epoch,
            generation: row.generation,
            root: row.root.to_vec(),
            live_rows: readback.rows.len(),
            live_root_bytes: readback.rows.iter().map(|row| row.root.len()).sum(),
        }
    }

    fn overlay_records(writer: &WritableHandle) -> Vec<granary_core::overlay_journal::Record> {
        let bytes = std::fs::read(writer.overlay.join("journal")).unwrap();
        let mut records = Vec::new();
        granary_core::overlay_journal::scan_journal_with(&bytes, |_, record| {
            records.push(record.clone());
        })
        .unwrap();
        records
    }

    fn location_is(at: &granary_core::overlay_journal::Location, name: &str) -> bool {
        at.parent.names().is_empty() && at.name.as_bytes() == name.as_bytes()
    }

    fn staging_payloads(writer: &WritableHandle) -> Vec<Vec<u8>> {
        std::fs::read_dir(writer.overlay.join("staging"))
            .unwrap()
            .map(|entry| {
                let bytes = std::fs::read(entry.unwrap().path()).unwrap();
                bytes
                    .get(granary_core::overlay_journal::STAGING_HEADER_LEN..)
                    .unwrap()
                    .to_vec()
            })
            .collect()
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Race {
        Disjoint,
        ModifyModify,
        ModifyDelete,
        DeleteModify,
    }
    impl Race {
        fn seed(self) -> Option<(&'static str, &'static [u8])> {
            (self != Self::Disjoint).then_some((CONFLICT_NAME, BASE_BYTES))
        }

        fn names(self) -> (&'static str, &'static str) {
            if self == Self::Disjoint {
                ("from-a", "from-b")
            } else {
                (CONFLICT_NAME, CONFLICT_NAME)
            }
        }

        fn conflicts(self) -> bool {
            self != Self::Disjoint
        }
    }

    fn loser_sync(writer: &WritableHandle, race: Race) -> std::thread::JoinHandle<io::Result<()>> {
        let (name, _) = race.names();
        if race == Race::DeleteModify {
            std::fs::remove_file(writer.mountpoint.join(name)).unwrap();
            let directory = std::fs::File::open(&writer.mountpoint).unwrap();
            std::thread::spawn(move || directory.sync_all())
        } else {
            let mut file = std::fs::File::create(writer.mountpoint.join(name)).unwrap();
            file.write_all(LOSER_BYTES).unwrap();
            std::thread::spawn(move || file.sync_all())
        }
    }

    fn winner_sync(writer: &WritableHandle, race: Race) {
        let (_, name) = race.names();
        if race == Race::ModifyDelete {
            std::fs::remove_file(writer.mountpoint.join(name)).unwrap();
            std::fs::File::open(&writer.mountpoint)
                .unwrap()
                .sync_all()
                .unwrap();
        } else {
            let mut file = std::fs::File::create(writer.mountpoint.join(name)).unwrap();
            file.write_all(WINNER_BYTES).unwrap();
            file.sync_all().unwrap();
        }
    }

    fn assert_conflict_events(harness: &Harness, paths: LogPaths) {
        let lines = harness.capture.lines();
        let conflicts: Vec<_> = lines
            .iter()
            .filter(|line| field(line, "event") == Some("op.conflict"))
            .collect();
        let failures = lines
            .iter()
            .filter(|line| {
                field(line, "event") == Some("op.failed")
                    && field(line, "kind") == Some("commit")
                    && field(line, "class") == Some("conflict")
            })
            .count();
        let expected_path = if paths == LogPaths::Redacted {
            "<file>"
        } else {
            "granary-conflict-\\\\x0apath-7f3a"
        };
        assert_eq!(
            (
                conflicts.len(),
                conflicts
                    .iter()
                    .filter(|line| field(line, "path") == Some(expected_path))
                    .count(),
                failures,
                paths == LogPaths::Full
                    || !lines.iter().any(|line| line.contains("granary-conflict-")),
            ),
            (1, 1, 1, true),
            "conflict event count/path, failed class, and default redaction: {lines:?}"
        );

        let local: Vec<_> = harness
            .local_capture
            .records()
            .into_iter()
            .filter(|record| record.starts_with("gran mount: conflict path="))
            .collect();
        assert_eq!(local.len(), 1, "local conflict status: {local:?}");
        assert!(
            local[0].contains("path=\"granary-conflict-\\x0apath-7f3a\"")
                && local[0].contains(&format!("errno={} ESTALE", libc::ESTALE)),
            "local conflict status did not retain the escaped path and ESTALE: {local:?}"
        );
    }

    fn assert_retained_conflict_work(writer: &WritableHandle, race: Race) {
        use granary_core::overlay_journal::Record;
        let records = overlay_records(writer);
        let named = records.iter().any(|record| match record {
            Record::StageBind { at, .. } if race != Race::DeleteModify => {
                location_is(at, CONFLICT_NAME)
            }
            Record::Delete { at, .. } if race == Race::DeleteModify => {
                location_is(at, CONFLICT_NAME)
            }
            _ => false,
        });
        let payload = race == Race::DeleteModify
            || staging_payloads(writer)
                .iter()
                .any(|payload| payload == LOSER_BYTES);
        assert_eq!(
            (named, payload),
            (true, true),
            "loser's acknowledged namespace record and staged bytes: {records:?}"
        );
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the held loser, winner landing, durable evidence and reader assertions are one race"
    )]
    fn run_race(race: Race, paths: LogPaths) {
        let _row = ROW
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let harness = Harness::new(race.seed(), paths);
        let a = harness.writer(0, "writer-a", 51);
        let b = harness.writer(1, "writer-b", 52);
        assert_ne!(a.writer, b.writer);
        a.faults
            .arm("sync.commit", "before_submit", 1, FaultAction::Block);
        let (a_name, b_name) = race.names();
        let a_sync = loser_sync(&a, race);
        wait_until(
            || {
                a.faults.sync_fired().iter().any(|event| {
                    (event.name, event.phase, event.occurrence)
                        == ("sync.commit", "before_submit", 1)
                })
            },
            "writer A did not fire the armed before-submit point",
        );
        let retained_intent = race
            .conflicts()
            .then(|| intent_snapshot(&harness, 0, a.writer));
        let before_b = head_seq(&harness);
        winner_sync(&b, race);
        wait_until(
            || head_seq(&harness) > before_b,
            "writer B did not advance the authority head",
        );
        a.faults.resume();
        let a_result = join_within(
            a_sync,
            WAIT,
            "writer A fsync thread did not finish after fault resume",
        );
        let a_errno = a_result
            .as_ref()
            .err()
            .and_then(std::io::Error::raw_os_error);
        if race == Race::Disjoint && a_result.is_ok() {
            wait_until(
                || head_seq(&harness) > before_b + 1,
                "writer A did not land its rebased root",
            );
        }

        let lines = harness.capture.lines();
        let point_fired: Vec<_> = a
            .faults
            .sync_fired()
            .into_iter()
            .filter(|event| event.name == "sync.commit" && event.phase == "before_submit")
            .map(|event| (event.name, event.phase, event.occurrence))
            .collect();
        let attributed_retry = retry_attributed_to_armed_fault(&lines);
        let a_retry = metric(
            &*a.metrics,
            "granary_client_commit_retries_total{reason=\"conflict\"}",
        );
        let b_retry = metric(
            &*b.metrics,
            "granary_client_commit_retries_total{reason=\"conflict\"}",
        );
        let conflicts = metric(&*a.metrics, "granary_client_rebase_conflicts_total");
        let final_seq = head_seq(&harness);
        let expected_advance = if race == Race::Disjoint { 2 } else { 1 };
        let trusted = TrustedKeys::new([*harness.key.public_key()]).unwrap();
        let base_root = root(&harness, before_b);
        let b_root = root(&harness, before_b + 1);
        let final_root = root(&harness, final_seq);
        let b_doc = verify_root(&b_root, &trusted);
        let final_doc = verify_root(&final_root, &trusted);
        let reader = harness.reader();
        let names = mounted_names(&reader.mountpoint);
        let bytes = if race == Race::Disjoint {
            vec![
                std::fs::read(reader.mountpoint.join(a_name)).unwrap(),
                std::fs::read(reader.mountpoint.join(b_name)).unwrap(),
            ]
        } else if race == Race::ModifyDelete {
            Vec::new()
        } else {
            vec![std::fs::read(reader.mountpoint.join(b_name)).unwrap()]
        };
        let expected_retry = if race == Race::Disjoint {
            Some((
                attributed_retry.as_ref().map_or_else(
                    || "<writer-a-operation>".to_owned(),
                    |event| event.0.clone(),
                ),
                "commit".to_owned(),
                "conflict".to_owned(),
            ))
        } else {
            None
        };
        let expected_names = if race == Race::Disjoint {
            vec!["from-a".to_owned(), "from-b".to_owned()]
        } else if race == Race::ModifyDelete {
            Vec::new()
        } else {
            vec![CONFLICT_NAME.to_owned()]
        };
        let expected_bytes = if race == Race::Disjoint {
            vec![LOSER_BYTES.to_vec(), WINNER_BYTES.to_vec()]
        } else if race == Race::ModifyDelete {
            Vec::new()
        } else {
            vec![WINNER_BYTES.to_vec()]
        };
        let expected_final_writer = if race == Race::Disjoint {
            a.writer
        } else {
            b.writer
        };
        let expected_final_parent = if race == Race::Disjoint {
            granary_core::hash::GrainId::of(&b_root)
        } else {
            granary_core::hash::GrainId::of(&base_root)
        };
        let store_event = lines.iter().find_map(|line| {
            (field(line, "event") == Some("integration.store"))
                .then(|| field(line, "store").map(str::to_owned))
                .flatten()
        });
        assert_eq!(
            (
                point_fired,
                attributed_retry,
                a_retry,
                b_retry,
                conflicts,
                a_errno,
                (
                    final_seq,
                    final_doc.seq,
                    final_doc.writer_uuid,
                    final_doc.parent,
                ),
                (b_doc.seq, b_doc.writer_uuid, b_doc.parent),
                names,
                bytes,
                store_event,
            ),
            (
                vec![("sync.commit", "before_submit", 1)],
                expected_retry,
                u64::from(race == Race::Disjoint),
                0,
                u64::from(race.conflicts()),
                if race.conflicts() {
                    Some(libc::ESTALE)
                } else {
                    None
                },
                (
                    before_b + expected_advance,
                    before_b + expected_advance,
                    expected_final_writer,
                    Some(expected_final_parent),
                ),
                (
                    before_b + 1,
                    b.writer,
                    Some(granary_core::hash::GrainId::of(&base_root)),
                ),
                expected_names,
                expected_bytes,
                Some(harness.store_label.to_owned()),
            ),
            "store={} point/retry/counters/errno/head/roots/listing/content premise",
            harness.store_label
        );
        if race.conflicts() {
            assert_conflict_events(&harness, paths);
            assert_retained_conflict_work(&a, race);
            let current_intent = intent_snapshot(&harness, 0, a.writer);
            assert_eq!(
                retained_intent.as_ref(),
                Some(&current_intent),
                "loser's registered intent changed after the rejected commit"
            );
            assert_eq!(
                std::fs::metadata(a.mountpoint.join(a_name))
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::ESTALE),
                "the losing mount did not retain its sticky conflict fence"
            );
        }
        a.finish();
        b.finish();
        reader.finish();
        harness.stop();
    }

    #[expect(
        clippy::too_many_lines,
        reason = "all eight held submissions and their exact terminal evidence form one race"
    )]
    fn run_stale_base_exhaustion() {
        let _row = ROW
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let harness = Harness::new(None, LogPaths::Redacted);
        let a = harness.writer(0, "writer-a", 61);
        let b = harness.writer(1, "writer-b", 62);
        assert_ne!(a.writer, b.writer);
        a.faults.arm_repeated(
            "sync.commit",
            "before_submit",
            std::num::NonZeroU64::new(8).unwrap(),
            FaultAction::Block,
        );
        let mut a_file = std::fs::File::create(a.mountpoint.join("from-a")).unwrap();
        a_file.write_all(LOSER_BYTES).unwrap();
        let a_sync = std::thread::spawn(move || a_file.sync_all());
        let initial_head = head_seq(&harness);
        let mut retained_intent = None;
        let mut winner_names = Vec::new();
        for occurrence in 1..=8 {
            wait_until(
                || {
                    a.faults.sync_fired().iter().any(|event| {
                        (event.name, event.phase, event.occurrence)
                            == ("sync.commit", "before_submit", occurrence)
                    })
                },
                "writer A did not reach the next held submission",
            );
            if occurrence == 8 {
                retained_intent = Some(intent_snapshot(&harness, 0, a.writer));
            }
            let before = head_seq(&harness);
            let name = format!("winner-{occurrence}");
            let mut winner = std::fs::File::create(b.mountpoint.join(&name)).unwrap();
            winner.write_all(WINNER_BYTES).unwrap();
            winner.sync_all().unwrap();
            drop(winner);
            wait_until(
                || head_seq(&harness) == before + 1,
                "writer B did not advance the head exactly once",
            );
            winner_names.push(name);
            a.faults.resume_one();
        }
        let a_result = join_within(
            a_sync,
            WAIT,
            "writer A fsync did not finish after the eighth stale-base answer",
        );
        let lines = harness.capture.lines();
        let fired: Vec<_> = a
            .faults
            .sync_fired()
            .into_iter()
            .filter(|event| event.name == "sync.commit" && event.phase == "before_submit")
            .map(|event| event.occurrence)
            .collect();
        let retry_attempts: Vec<_> = lines
            .iter()
            .filter(|line| {
                field(line, "event") == Some("op.retry")
                    && field(line, "kind") == Some("commit")
                    && field(line, "reason") == Some("conflict")
            })
            .filter_map(|line| number_field(line, "attempt"))
            .collect();
        let failed = lines
            .iter()
            .filter(|line| {
                field(line, "event") == Some("op.failed")
                    && field(line, "kind") == Some("commit")
                    && field(line, "class") == Some("refused")
            })
            .count();
        let conflict_events = lines
            .iter()
            .filter(|line| field(line, "event") == Some("op.conflict"))
            .count();
        let final_seq = head_seq(&harness);
        let final_root = root(&harness, final_seq);
        let trusted = TrustedKeys::new([*harness.key.public_key()]).unwrap();
        let final_doc = verify_root(&final_root, &trusted);
        assert_eq!(
            (
                a_result
                    .as_ref()
                    .err()
                    .and_then(std::io::Error::raw_os_error),
                fired,
                retry_attempts,
                metric(
                    &*a.metrics,
                    "granary_client_commit_retries_total{reason=\"conflict\"}"
                ),
                metric(&*a.metrics, "granary_client_rebase_conflicts_total"),
                metric(
                    &*a.metrics,
                    "granary_client_commits_total{result=\"exhausted\"}"
                ),
                metric(
                    &*b.metrics,
                    "granary_client_commit_retries_total{reason=\"conflict\"}"
                ),
                failed,
                conflict_events,
                (final_seq, final_doc.seq, final_doc.writer_uuid),
            ),
            (
                Some(libc::ESTALE),
                (1..=8).collect::<Vec<_>>(),
                (2..=8).collect::<Vec<u64>>(),
                7,
                0,
                1,
                0,
                1,
                0,
                (initial_head + 8, initial_head + 8, b.writer),
            ),
            "errno, attempts, retries, metrics, events and exact head advance: {lines:?}"
        );
        let records = overlay_records(&a);
        assert!(
            records.iter().any(|record| matches!(
                record,
                granary_core::overlay_journal::Record::Create { at, .. }
                    if location_is(at, "from-a")
            )) && staging_payloads(&a)
                .iter()
                .any(|payload| payload == LOSER_BYTES),
            "exhausted loser's acknowledged work was not retained: {records:?}"
        );
        assert_eq!(
            retained_intent.as_ref(),
            Some(&intent_snapshot(&harness, 0, a.writer)),
            "exhausted loser's registered intent changed"
        );
        assert_eq!(
            std::fs::metadata(a.mountpoint.join("from-a"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ESTALE),
            "attempt exhaustion did not leave a sticky fence"
        );

        let reader = harness.reader();
        winner_names.sort();
        assert_eq!(mounted_names(&reader.mountpoint), winner_names);
        for name in &winner_names {
            assert_eq!(
                std::fs::read(reader.mountpoint.join(name)).unwrap(),
                WINNER_BYTES,
                "winner content changed at {name}"
            );
        }
        assert_eq!(
            std::fs::metadata(reader.mountpoint.join("from-a"))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOENT),
            "the exhausted candidate reached the authority head"
        );
        a.finish();
        b.finish();
        reader.finish();
        harness.stop();
    }

    #[test]
    fn mounted_disjoint_writers_force_rebase_and_reader_convergence() {
        let _capture = capture(LogPaths::Redacted);
        if venue("mounted_disjoint_writers_force_rebase_and_reader_convergence") {
            run_race(Race::Disjoint, LogPaths::Redacted);
        }
    }

    #[test]
    fn mounted_same_path_writers_refuse_silent_convergence() {
        let _capture = capture(LogPaths::Redacted);
        if venue("mounted_same_path_writers_refuse_silent_convergence") {
            run_race(Race::ModifyModify, LogPaths::Redacted);
        }
    }

    #[test]
    fn mounted_same_path_loser_modify_winner_delete_refuses_silent_convergence() {
        let _capture = capture(LogPaths::Redacted);
        if venue("mounted_same_path_loser_modify_winner_delete_refuses_silent_convergence") {
            run_race(Race::ModifyDelete, LogPaths::Redacted);
        }
    }

    #[test]
    fn mounted_same_path_loser_delete_winner_modify_refuses_silent_convergence() {
        let _capture = capture(LogPaths::Redacted);
        if venue("mounted_same_path_loser_delete_winner_modify_refuses_silent_convergence") {
            run_race(Race::DeleteModify, LogPaths::Redacted);
        }
    }

    #[test]
    fn mounted_same_path_conflict_full_path_event() {
        if venue("mounted_same_path_conflict_full_path_event") {
            let output = run_full_path_child();
            let one_test_passed = String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.starts_with("test result: ok. 1 passed;"));
            assert!(
                !output.timed_out && output.status.success() && one_test_passed,
                "full-path child failed (status={}, timed_out={}, one_test_passed={}):\nstdout:\n{}\nstderr:\n{}",
                output.status,
                output.timed_out,
                one_test_passed,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            let mut writer = tracing_subscriber::fmt::TestWriter::new();
            writer.write_all(&output.stdout).unwrap();
            writer.write_all(&output.stderr).unwrap();
        }
    }

    #[test]
    #[ignore = "re-execed by the full-path parent in an isolated test process"]
    fn mounted_full_path_conflict_reexec_child() {
        assert_eq!(
            std::env::var_os(FULL_PATH_CHILD).as_deref(),
            Some(std::ffi::OsStr::new("1")),
            "full-path child refuses a manual ignored-test run without its parent marker"
        );
        let _capture = capture(LogPaths::Full);
        run_race(Race::ModifyModify, LogPaths::Full);
    }

    #[test]
    fn mounted_stale_base_exhaustion_stops_after_eight_attempts() {
        let _capture = capture(LogPaths::Redacted);
        if venue("mounted_stale_base_exhaustion_stops_after_eight_attempts") {
            run_stale_base_exhaustion();
        }
    }
}
