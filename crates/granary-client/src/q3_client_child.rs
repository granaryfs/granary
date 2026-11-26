// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Ignored measurement children using the public writable mount path.

#![cfg(test)]
#![cfg_attr(
    target_os = "linux",
    expect(
        clippy::disallowed_methods,
        reason = "the ignored child reads its private handoff and drives its own mounted scratch tree"
    )
)]

#[cfg(target_os = "linux")]
use crate::{
    AmbientNetwork, BundleHistory, CacheOrigin, ContentionThreshold, HeadContext, HttpStore,
    InstantClock, LogFormat, LogPaths, MountOptions, RecordWriter, ResolveError, ResolveTarget,
    RootVerifier, SyncProfile, ViewMode, WritableProcess, WritableStart, WritableSyncRuntime,
    closed_subscriber_with_paths, resolve_head_verified, start_writable,
};
#[cfg(target_os = "linux")]
use granary_core::{
    clock::Clock,
    intent,
    retained_submission::Scope,
    root::{self, Timestamp, VolumeName},
};
#[cfg(target_os = "linux")]
use granary_fuse::{MountIdentity, SessionEndEvidence, classify_session_end};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
#[cfg(target_os = "linux")]
use std::io::{self, Read as _, Seek as _, Write as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::{Child, Command};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

const HANDOFF_ARGUMENT: &str = "--skip=granary-q3-handoff=";
const FILTER: &str = "off,granary_client::event=trace";
#[cfg(target_os = "linux")]
const FIELD_MAX: u64 = 4096;
#[cfg(target_os = "linux")]
const CALIBRATION_FSYNC_COUNT: usize = 3;
#[cfg(target_os = "linux")]
const DEFAULT_PLAN: [usize; 3] = [0, 0, 1];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Q3SyncProfile {
    DurablePrepared,
    Published,
}

fn sync_profile(value: &str) -> Result<Q3SyncProfile, &'static str> {
    match value {
        "durable-prepared" => Ok(Q3SyncProfile::DurablePrepared),
        "published" => Ok(Q3SyncProfile::Published),
        _ => Err("client child sync profile is invalid"),
    }
}

#[cfg(target_os = "linux")]
impl Q3SyncProfile {
    fn client_profile(self) -> SyncProfile {
        match self {
            Self::DurablePrepared => SyncProfile::DurablePrepared,
            Self::Published => SyncProfile::Published,
        }
    }
}

#[cfg(target_os = "linux")]
struct ChildHandoff {
    base: String,
    pin: [u8; 32],
    root_key: [u8; 32],
    certificate: PathBuf,
    credential: PathBuf,
    seed: PathBuf,
    root: PathBuf,
    log_path: PathBuf,
}

#[cfg(target_os = "linux")]
struct ChildPaths {
    mountpoint: PathBuf,
    store: PathBuf,
    cache: PathBuf,
}

#[cfg(target_os = "linux")]
type Quiescence = Box<dyn Fn() -> Result<bool, String>>;
#[cfg(target_os = "linux")]
type MetricsSnapshot = Box<dyn Fn() -> Result<u64, String>>;

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct LogWriter {
    file: Arc<Mutex<std::fs::File>>,
    failed: Arc<AtomicBool>,
}

#[cfg(target_os = "linux")]
impl RecordWriter for LogWriter {
    fn write_record(&self, record: &crate::LogRecord) {
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if file.write_all(record.as_bytes()).is_err() || file.flush().is_err() {
            self.failed.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct HarnessClock;

#[cfg(target_os = "linux")]
impl Clock for HarnessClock {
    // A frozen wall clock would never let a scheduled intent retry come due,
    // so one transient error would fail the measured fsync; the measured
    // client reads real time, as the shipped client does.
    #[expect(
        clippy::disallowed_methods,
        reason = "the measured client's wall clock; retries must come due as in production"
    )]
    fn now(&self) -> Timestamp {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(elapsed) => Timestamp {
                secs: i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
                nanos: elapsed.subsec_nanos(),
            },
            Err(_) => Timestamp { secs: 0, nanos: 0 },
        }
    }
}

fn handoff_argument(
    args: impl IntoIterator<Item = OsString>,
) -> Result<Option<PathBuf>, &'static str> {
    let prefix = OsStr::new(HANDOFF_ARGUMENT);
    let mut selected = None;
    for argument in args {
        let Some(value) = argument
            .as_encoded_bytes()
            .strip_prefix(prefix.as_encoded_bytes())
        else {
            continue;
        };
        if selected.is_some() {
            return Err("client child handoff argument is duplicated");
        }
        if value.is_empty() {
            return Err("client child handoff path is empty");
        }
        selected = Some(PathBuf::from(OsString::from_vec(value.to_vec())));
    }
    Ok(selected)
}

fn judge_private_directory(
    directory: bool,
    mode: u32,
    owner: u32,
    device: u64,
    expected_owner: u32,
    expected_device: Option<u64>,
) -> Result<(), &'static str> {
    if !directory || mode & 0o777 != 0o700 || owner != expected_owner {
        return Err("client child private directory ownership or mode is invalid");
    }
    if expected_device.is_some_and(|expected| expected != device) {
        return Err("client child private directory device changed");
    }
    Ok(())
}

#[expect(
    clippy::disallowed_methods,
    reason = "create-or-open one harness directory, then validate its no-follow descriptor"
)]
fn prepare_private_directory(
    path: &Path,
    expected_owner: u32,
    expected_device: Option<u64>,
) -> Result<u64, String> {
    let created = match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(format!(
                "client child cannot create private directory: {error}"
            ));
        }
    };
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("client child cannot open private directory: {error}"))?;
    if created {
        directory
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("client child cannot set private directory mode: {error}"))?;
    }
    let metadata = directory
        .metadata()
        .map_err(|error| format!("client child cannot inspect private directory: {error}"))?;
    judge_private_directory(
        metadata.file_type().is_dir(),
        metadata.mode(),
        metadata.uid(),
        metadata.dev(),
        expected_owner,
        expected_device,
    )
    .map_err(str::to_owned)?;
    Ok(metadata.dev())
}

#[cfg(target_os = "linux")]
fn read_field(dir: &Path, name: &str) -> Result<Vec<u8>, String> {
    let path = dir.join(name);
    let file = std::fs::File::open(&path)
        .map_err(|error| format!("client child cannot open handoff field {name}: {error}"))?;
    let mut bytes = Vec::new();
    file.take(FIELD_MAX.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("client child cannot read handoff field {name}: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > FIELD_MAX {
        return Err(format!("client child handoff field {name} is too large"));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn read_text(dir: &Path, name: &str) -> Result<String, String> {
    String::from_utf8(read_field(dir, name)?)
        .map_err(|_| format!("client child handoff field {name} is not UTF-8"))
}

#[cfg(target_os = "linux")]
fn read_path(dir: &Path, name: &str) -> Result<PathBuf, String> {
    let value = PathBuf::from(read_text(dir, name)?);
    if !value.is_absolute() {
        return Err(format!("client child handoff field {name} is not absolute"));
    }
    Ok(value)
}

#[cfg(target_os = "linux")]
fn decode_hex<const N: usize>(value: &str, name: &str) -> Result<[u8; N], String> {
    if value.len() != N.saturating_mul(2) {
        return Err(format!(
            "client child handoff field {name} is not {N} bytes"
        ));
    }
    let mut decoded = Vec::with_capacity(N);
    for pair in value.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| format!("client child handoff field {name} is not hex"))?;
        decoded.push(
            u8::from_str_radix(pair, 16)
                .map_err(|_| format!("client child handoff field {name} is not hex"))?,
        );
    }
    decoded
        .try_into()
        .map_err(|_| format!("client child handoff field {name} is not {N} bytes"))
}

#[cfg(target_os = "linux")]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("client child cannot create signal: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("client child cannot write signal: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("client child cannot sync signal: {error}"))
}

#[cfg(target_os = "linux")]
fn write_workload_signal(path: &Path, bytes: &[u8]) -> Result<(), String> {
    // The workload is traced for fsync, so its signals are never synced: the
    // hard link alone makes a complete file appear at once.
    let temporary = path.with_extension("partial");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("workload child cannot create signal: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("workload child cannot write signal: {error}"))?;
    drop(file);
    std::fs::hard_link(&temporary, path)
        .map_err(|error| format!("workload child cannot publish signal: {error}"))?;
    std::fs::remove_file(temporary)
        .map_err(|error| format!("workload child cannot retire signal staging file: {error}"))
}

#[cfg(target_os = "linux")]
fn wait_for(path: &Path) -> Result<(), String> {
    let (_keepalive, pause) = std::sync::mpsc::channel::<()>();
    for _ in 0..3000 {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => return Ok(()),
            Ok(_) => return Err("client child signal is not a file".to_owned()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let _ = pause.recv_timeout(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("client child cannot inspect signal: {error}")),
        }
    }
    Err("client child signal wait timed out".to_owned())
}

#[cfg(target_os = "linux")]
fn read_handoff(handoff: &Path) -> Result<ChildHandoff, String> {
    let base = read_text(handoff, "base-url")?;
    let pin = decode_hex::<32>(&read_text(handoff, "server-pin")?, "server-pin")?;
    let root_key = decode_hex::<32>(&read_text(handoff, "root-key")?, "root-key")?;
    let certificate = read_path(handoff, "client-cert-path")?;
    let credential = read_path(handoff, "client-credential-path")?;
    let seed = read_path(handoff, "signing-seed-path")?;
    let root = read_path(handoff, "client-root-path")?;
    let log_path = read_path(handoff, "client-log-path")?;
    if log_path.starts_with(&root) {
        return Err("client child log is inside the store image".to_owned());
    }
    Ok(ChildHandoff {
        base,
        pin,
        root_key,
        certificate,
        credential,
        seed,
        root,
        log_path,
    })
}

#[cfg(target_os = "linux")]
fn recorded_root_device(handoff: &Path, owner: u32) -> Result<Option<u64>, String> {
    let path = handoff.join("client-root-device");
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("client child cannot inspect root device: {error}")),
    };
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != owner
    {
        return Err("client child root device witness is invalid".to_owned());
    }
    read_text(handoff, "client-root-device")?
        .parse()
        .map(Some)
        .map_err(|_| "client child root device witness is invalid".to_owned())
}

#[cfg(target_os = "linux")]
fn install_subscriber(
    config: &ChildHandoff,
    handoff: &Path,
    owner: u32,
) -> Result<(ChildPaths, LogWriter), String> {
    let expected_device = recorded_root_device(handoff, owner)?;
    let device = prepare_private_directory(&config.root, owner, expected_device)?;
    if expected_device.is_none() {
        write_private(
            &handoff.join("client-root-device"),
            device.to_string().as_bytes(),
        )?;
    }
    let mountpoint = config.root.join("mount");
    prepare_private_directory(&mountpoint, owner, Some(device))?;
    let log_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&config.log_path)
        .map_err(|error| format!("client child cannot create log: {error}"))?;
    let writer = LogWriter {
        file: Arc::new(Mutex::new(log_file)),
        failed: Arc::new(AtomicBool::new(false)),
    };
    let subscriber = closed_subscriber_with_paths(
        LogFormat::Json,
        tracing_subscriber::EnvFilter::new(FILTER),
        writer.clone(),
        LogPaths::Redacted,
        BundleHistory::default(),
    );
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| "client child cannot install the global subscriber".to_owned())?;
    Ok((
        ChildPaths {
            store: config.root.join("store"),
            cache: config.root.join("cache"),
            mountpoint,
        },
        writer,
    ))
}

#[cfg(target_os = "linux")]
fn writable_input<'a>(
    config: &'a ChildHandoff,
    paths: &'a ChildPaths,
    handoff: &Path,
    uid: u32,
    gid: u32,
) -> Result<WritableStart<'a>, String> {
    let volume =
        VolumeName::new(read_text(handoff, "volume")?).map_err(|error| error.to_string())?;
    let profile =
        sync_profile(&read_text(handoff, "client-sync-profile")?).map_err(str::to_owned)?;
    Ok(WritableStart {
        volume,
        process: WritableProcess {
            ruid: nix::unistd::getuid().as_raw(),
            rgid: nix::unistd::getgid().as_raw(),
            egid: gid,
            set_id_tainted: false,
        },
        foreground: true,
        force: false,
        mountpoint: &paths.mountpoint,
        root_key: Some(config.root_key),
        manifest_root: None,
        trust_server: false,
        options: MountOptions::default(),
        seq: None,
        seed: Some(&config.seed),
        certificate: Some(&config.certificate),
        credential_key: Some(&config.credential),
        scope: Some(Scope {
            authority_base: config.base.as_bytes().to_vec(),
            pins: vec![config.pin],
            credential_context: read_field(handoff, "credential-context")?,
        }),
        store: Some(&paths.store),
        cache: Some(&paths.cache),
        cache_origin: CacheOrigin {
            endpoint_url: config.base.clone(),
            pin_set_digest: CacheOrigin::pin_set_digest(&[config.pin]),
            root_key_id: Some(CacheOrigin::root_key_digest(&config.root_key)),
        },
        cache_quota: 268_435_456,
        contention_threshold: ContentionThreshold::default(),
        construction_workspace_bytes: crate::SyncOptions::default().workspace_bytes,
        overlay_cap_bytes: 134_217_728,
        reset_floor: false,
        policy: granary_vfs::AttrPolicy { uid, gid },
        euid: uid,
        sync_profile: profile.client_profile(),
        view: ViewMode::Default,
    })
}

#[cfg(target_os = "linux")]
fn print_intent_transport_cause(input: &WritableStart<'_>) {
    let Ok((_, _, credential)) = crate::writable_start::load_local(input) else {
        eprintln!("q3 client intent transport cause: diagnostic credential unavailable");
        return;
    };
    let Some(scope) = input.scope.as_ref() else {
        eprintln!("q3 client intent transport cause: diagnostic scope unavailable");
        return;
    };
    let Ok(base) = std::str::from_utf8(&scope.authority_base) else {
        eprintln!("q3 client intent transport cause: diagnostic authority unavailable");
        return;
    };
    let Ok(remote) = HttpStore::with_client_credential(
        base,
        scope.pins.clone(),
        &AmbientNetwork,
        Some(credential),
    ) else {
        eprintln!("q3 client intent transport cause: diagnostic client unavailable");
        return;
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        eprintln!("q3 client intent transport cause: diagnostic runtime unavailable");
        return;
    };
    match runtime.block_on(remote.intent_readback_once(scope, &input.volume, |_, _| true)) {
        Ok(reply) => eprintln!(
            "q3 client intent transport cause: no transport error (readback status {})",
            reply.status()
        ),
        Err(error) => eprintln!("q3 client intent transport cause: {error}"),
    }
}

#[cfg(target_os = "linux")]
fn mount(
    config: &ChildHandoff,
    paths: &ChildPaths,
    handoff: &Path,
    uid: u32,
    gid: u32,
    random: &mut granary_net::secure_random::OsSecureRandom,
) -> Result<
    (
        granary_fuse::BackgroundMount,
        WritableSyncRuntime,
        Quiescence,
        MetricsSnapshot,
    ),
    String,
> {
    let input = writable_input(config, paths, handoff, uid, gid)?;
    let ready = start_writable(
        &input,
        &HarnessClock,
        &mut granary_core::rng::SeededRng::new(376),
        random,
        &mut Vec::new(),
    );
    let mut ready = match ready {
        Ok(ready) => ready,
        Err(error) => {
            if error.name() == "WritableIntentUnavailable" {
                print_intent_transport_cause(&input);
            }
            return Err(error.name().to_owned());
        }
    };
    if ready.backend_for_test().live_driver_for_test() {
        return Err("client child live commit driver is enabled".to_owned());
    }
    let writer = {
        use std::fmt::Write as _;
        let mut encoded = String::with_capacity(32);
        for byte in ready.mediator_for_test().writer_uuid() {
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    };
    write_private(&handoff.join("client-writer"), writer.as_bytes())?;
    let remote = ready.sync_remote_for_test();
    let content = Arc::new(
        ready
            .backend_for_test()
            .sync_content(remote.clone())
            .map_err(|error| error.to_string())?,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("client child cannot create sync runtime: {error}"))?;
    // The engine records into the session's recorder, the one the metrics
    // snapshot below reads; a separate recorder would leave M15 at zero.
    let metrics = ready
        .session_metrics_for_test()
        .ok_or_else(|| "client child session has no metrics recorder".to_owned())?;
    let engine = runtime
        .block_on(ready.backend_for_test().attach_sync(
            remote,
            content,
            Arc::new(HarnessClock),
            Arc::new(InstantClock::default()),
            metrics,
            granary_net::secure_random::OsSecureRandom::new(),
        ))
        .map_err(|error| error.to_string())?;
    let quiescence: Quiescence = Box::new(move || {
        engine
            .quiescent()
            .map_err(|error| format!("client child cannot observe sync quiescence: {error}"))
    });
    let attachment = ready.attach();
    let snapshot = attachment.metrics_snapshot();
    let metrics: MetricsSnapshot = Box::new(move || {
        snapshot()
            .map(|value| value.bundle_projection().rechunks)
            .map_err(|error| error.to_string())
    });
    let sync_runtime = WritableSyncRuntime::serve(runtime)
        .map_err(|error| format!("client child cannot serve sync runtime: {error}"))?;
    let mounted = attachment
        .mount(1)
        .map_err(|error| error.name().to_owned())?;
    Ok((mounted, sync_runtime, quiescence, metrics))
}

#[cfg(target_os = "linux")]
fn spawn_workload(handoff: &Path) -> Result<Child, String> {
    Command::new(
        std::env::current_exe()
            .map_err(|error| format!("client child cannot locate workload binary: {error}"))?,
    )
    .args([
        OsStr::new("q3_client_child::q3_measurement_workload_child"),
        OsStr::new("--ignored"),
        OsStr::new("--exact"),
        OsStr::new("--nocapture"),
        OsStr::new("--test-threads=1"),
    ])
    .arg(format!("{HANDOFF_ARGUMENT}{}", handoff.display()))
    .spawn()
    .map_err(|error| format!("client child cannot launch workload: {error}"))
}

#[cfg(target_os = "linux")]
fn workload_edit(index: usize) -> (u64, Vec<u8>) {
    // Establish a large base, make one bounded page edit while M15 can still
    // discriminate, then replace every byte so no old grain can be reused.
    if index == 0 {
        (0, vec![1; 4 * 1024 * 1024])
    } else if index == 2 {
        (0, vec![2; 4 * 1024 * 1024])
    } else {
        let mut bytes = vec![0_u8; 4096];
        bytes[..8].copy_from_slice(&u64::try_from(index).unwrap_or(u64::MAX).to_be_bytes());
        // Page edits stay inside the first 2 MiB grain of the constant-byte
        // file. An edit starting on the grain boundary re-cuts from the
        // preceding grain to the end of file, which is a counted fallback.
        (
            u64::try_from(index.saturating_sub(1) % 512).unwrap_or(0) * 4096,
            bytes,
        )
    }
}

#[cfg(target_os = "linux")]
fn workload_step(file: &mut std::fs::File, index: usize) -> Result<Vec<u8>, String> {
    let (offset, bytes) = workload_edit(index);
    file.seek(std::io::SeekFrom::Start(offset))
        .and_then(|_| file.write_all(&bytes))
        .map_err(|error| format!("workload child mounted write failed: {error}"))?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn expected_workload_content(last: usize) -> Result<Vec<u8>, String> {
    if last > 10_000 {
        return Err("client probe index is invalid".to_owned());
    }
    let mut content = Vec::new();
    for index in 0..=last {
        let (offset, bytes) = workload_edit(index);
        let start =
            usize::try_from(offset).map_err(|_| "client probe offset exceeds usize".to_owned())?;
        let end = start
            .checked_add(bytes.len())
            .ok_or_else(|| "client probe content is too large".to_owned())?;
        if content.len() < end {
            content.resize(end, 0);
        }
        content
            .get_mut(start..end)
            .ok_or_else(|| "client probe range is invalid".to_owned())?
            .copy_from_slice(&bytes);
    }
    Ok(content)
}

#[cfg(target_os = "linux")]
#[expect(
    clippy::disallowed_methods,
    reason = "the process id identifies this workload child for strace attachment"
)]
fn workload_process_id() -> u32 {
    std::process::id()
}

#[cfg(target_os = "linux")]
#[expect(
    clippy::disallowed_methods,
    reason = "the workload requires its own monotonic stopwatch immediately around fsync"
)]
fn workload_stopwatch() -> Instant {
    Instant::now()
}

fn sha256_hex(bytes: &[u8]) -> Result<String, String> {
    let suite = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .ok_or_else(|| "workload ledger SHA-256 suite is not TLS 1.3".to_owned())?;
    let digest = suite.common.hash_provider.hash(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest.as_ref() {
        write!(encoded, "{byte:02x}")
            .map_err(|_| "workload ledger SHA-256 encoding failed".to_owned())?;
    }
    Ok(encoded)
}

#[cfg(target_os = "linux")]
fn append_workload_ledger(
    (file, directory): &mut (std::fs::File, std::fs::File),
    record: &str,
) -> Result<(), String> {
    writeln!(file, "{record}")
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .and_then(|()| directory.sync_all())
        .map_err(|error| format!("workload child cannot sync recovery ledger: {error}"))
}

fn record_successful_fsync(
    result: Result<(), String>,
    append: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    result?;
    append()
}

#[cfg(target_os = "linux")]
fn append_successful_fsync_record(
    ledger: Option<&mut (std::fs::File, std::fs::File)>,
    index: usize,
    written: &[u8],
    cumulative_write_call_bytes: usize,
) -> Result<(), String> {
    let Some(ledger) = ledger else { return Ok(()) };
    let content_sha256 = sha256_hex(written)?;
    append_workload_ledger(
        ledger,
        &format!(
            "{{\"content_sha256\":\"{content_sha256}\",\"cumulative_write_call_bytes\":{cumulative_write_call_bytes},\"kind\":\"successful-fsync\",\"operation_id\":\"a-{index:04}\",\"unique_content_bytes\":{}}}",
            written.len()
        ),
    )
}

#[cfg(target_os = "linux")]
fn run_workload(handoff: &Path) -> Result<(), String> {
    let plan = workload_plan(handoff)?;
    let planned = plan.iter().sum();
    let root = read_path(handoff, "client-root-path")?;
    let result_path = handoff.join("workload-results.jsonl");
    if result_path.starts_with(&root) {
        return Err("workload child results are inside the store image".to_owned());
    }
    let ledger_path = handoff
        .join("client-ledger-path")
        .is_file()
        .then(|| read_path(handoff, "client-ledger-path"))
        .transpose()?;
    if ledger_path
        .as_ref()
        .is_some_and(|path| path.starts_with(&root))
    {
        return Err("workload child ledger is inside the store image".to_owned());
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("mount/unique.bin"))
        .map_err(|error| format!("workload child cannot create mounted file: {error}"))?;
    let mut results = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(result_path)
        .map_err(|error| format!("workload child cannot create results: {error}"))?;
    let mut ledger = if let Some(path) = ledger_path {
        let parent = path
            .parent()
            .ok_or_else(|| "workload child ledger has no parent".to_owned())?;
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| format!("workload child cannot create recovery ledger: {error}"))?;
        let directory = std::fs::File::open(parent)
            .map_err(|error| format!("workload child cannot open ledger directory: {error}"))?;
        file.sync_all()
            .and_then(|()| directory.sync_all())
            .map_err(|error| format!("workload child cannot sync recovery ledger: {error}"))?;
        Some((file, directory))
    } else {
        None
    };
    let pid = workload_process_id();
    write_workload_signal(
        &handoff.join("client-workload-pid"),
        pid.to_string().as_bytes(),
    )?;
    write_workload_signal(&handoff.join("client-workload-created"), b"")?;
    wait_for(&handoff.join("client-go"))?;
    let mut cumulative_write_call_bytes = 0_usize;
    for index in 0..planned {
        let written = workload_step(&mut file, index)?;
        cumulative_write_call_bytes = cumulative_write_call_bytes
            .checked_add(written.len())
            .ok_or_else(|| "workload child write-call byte count overflowed".to_owned())?;
        if let Some(ledger) = ledger.as_mut() {
            append_workload_ledger(
                ledger,
                &format!(
                    "{{\"cumulative_write_call_bytes\":{cumulative_write_call_bytes},\"kind\":\"write-call-bytes\"}}"
                ),
            )?;
        }
        let tid = nix::unistd::gettid().as_raw();
        let started = workload_stopwatch();
        let unsynced = handoff.join("client-unsynced-last").is_file() && index + 1 == planned;
        let result = if unsynced { Ok(()) } else { file.sync_all() };
        let duration = started.elapsed().as_nanos();
        let return_code = if result.is_ok() { 0 } else { -1 };
        writeln!(
            results,
            "{{\"index\":{index},\"warmup\":{},\"duration_ns\":{duration},\"syscall\":\"{}\",\"return_code\":{return_code},\"pid\":{},\"tid\":{tid}}}",
            index < plan[0] + plan[1],
            if unsynced { "write" } else { "fsync" },
            pid,
        )
        .and_then(|()| results.flush())
        .map_err(|error| format!("workload child cannot write results: {error}"))?;
        if !unsynced {
            let result = result.map_err(|error| format!("workload child fsync failed: {error}"));
            record_successful_fsync(result, || {
                append_successful_fsync_record(
                    ledger.as_mut(),
                    index,
                    &written,
                    cumulative_write_call_bytes,
                )
            })?;
        }
        write_workload_signal(&handoff.join(format!("workload-step-{index}")), b"")?;
        wait_for(&handoff.join(format!("workload-next-{index}")))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn wait_for_quiescence(quiescence: &Quiescence) -> Result<(), String> {
    let (_keepalive, pause) = std::sync::mpsc::channel::<()>();
    for _ in 0..3000 {
        if quiescence()? {
            return Ok(());
        }
        let _ = pause.recv_timeout(Duration::from_millis(10));
    }
    Err("client child sync quiescence wait timed out".to_owned())
}

#[cfg(target_os = "linux")]
fn workload_plan(handoff: &Path) -> Result<[usize; 3], String> {
    let path = handoff.join("client-workload-plan");
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(DEFAULT_PLAN),
        Err(error) => return Err(format!("client child cannot read workload plan: {error}")),
    };
    let values = text
        .split_ascii_whitespace()
        .map(str::parse)
        .collect::<Result<Vec<usize>, _>>()
        .map_err(|_| "client child workload plan is invalid".to_owned())?;
    values
        .try_into()
        .map_err(|_| "client child workload plan is invalid".to_owned())
}

fn release_workload_step(
    handoff: &Path,
    index: usize,
    runner_gates_steps: bool,
    wait_for_signal: impl FnOnce(&Path) -> Result<(), String>,
    release_signal: impl FnOnce(&Path, &[u8]) -> Result<(), String>,
) -> Result<(), String> {
    if runner_gates_steps {
        wait_for_signal(&handoff.join(format!("runner-next-{index}")))?;
    }
    release_signal(&handoff.join(format!("workload-next-{index}")), b"")
}

#[cfg(target_os = "linux")]
struct IntentRowEvidence {
    epoch: u64,
    generation: u64,
    root: String,
    parent_seq: u64,
    root_bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
fn probe_remote(
    config: &ChildHandoff,
    handoff: &Path,
    uid: u32,
) -> Result<(VolumeName, HttpStore, Scope), String> {
    let volume =
        VolumeName::new(read_text(handoff, "volume")?).map_err(|error| error.to_string())?;
    let credential = crate::ClientCredential::from_configured(
        Some(&config.certificate),
        Some(&config.credential),
        uid,
    )
    .map_err(|error| error.to_string())?
    .ok_or_else(|| "client intent probe has no credential".to_owned())?;
    let scope = Scope {
        authority_base: config.base.as_bytes().to_vec(),
        pins: vec![config.pin],
        credential_context: read_field(handoff, "credential-context")?,
    };
    let remote = HttpStore::with_client_credential(
        &config.base,
        scope.pins.clone(),
        &AmbientNetwork,
        Some(credential),
    )
    .map_err(|error| error.to_string())?;
    Ok((volume, remote, scope))
}

#[cfg(target_os = "linux")]
fn read_writer_intent(
    config: &ChildHandoff,
    handoff: &Path,
    uid: u32,
) -> Result<(Vec<u8>, Option<IntentRowEvidence>), String> {
    let writer = decode_hex::<16>(&read_text(handoff, "client-writer")?, "client-writer")?;
    let (volume, remote, scope) = probe_remote(config, handoff, uid)?;
    let trusted = granary_store::crypto::TrustedKeys::new([config.root_key])
        .map_err(|error| error.to_string())?;
    let verify = |doc: &root::RootDoc, prefix: &[u8]| {
        granary_store::crypto::check_signatures(doc, prefix, &trusted).is_ok()
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("client intent probe cannot create runtime: {error}"))?;
    let reply = runtime
        .block_on(remote.intent_readback_once(&scope, &volume, verify))
        .map_err(|error| error.to_string())?;
    let body = reply.body().to_vec();
    let readback =
        intent::decode_readback(&body, &volume, verify).map_err(|error| error.to_string())?;
    let mut rows = readback.rows.iter().filter(|row| row.writer == writer);
    let row = rows.next();
    if rows.next().is_some() {
        return Err("client intent probe found duplicate writer rows".to_owned());
    }
    let evidence = row
        .map(|row| {
            let root = root::decode_root(row.root).map_err(|error| error.to_string())?;
            Ok::<_, String>(IntentRowEvidence {
                epoch: row.epoch,
                generation: row.generation,
                root: row.root_id().to_string(),
                parent_seq: root.seq.saturating_sub(1),
                root_bytes: row.root.to_vec(),
            })
        })
        .transpose()?;
    Ok((body, evidence))
}

#[cfg(target_os = "linux")]
fn record_chain_head(config: &ChildHandoff, handoff: &Path, uid: u32) -> Result<(), String> {
    let path = read_path(handoff, "client-chain-head-path")?;
    if path.starts_with(&config.root) {
        return Err("client chain head evidence is inside the store image".to_owned());
    }
    let (volume, remote, _) = probe_remote(config, handoff, uid)?;
    let verifier = RootVerifier::trusting(config.root_key).map_err(|error| error.to_string())?;
    let context = HeadContext::new(
        Box::new(HarnessClock),
        Box::new(granary_core::rng::SeededRng::new(376)),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("client chain probe cannot create runtime: {error}"))?;
    let mut sink = |_id: granary_core::hash::GrainId, _bytes: &[u8]| Ok(());
    let evidence = match runtime.block_on(resolve_head_verified(
        &remote,
        volume.as_str(),
        &verifier,
        &context,
        None,
        ResolveTarget::WholeTree,
        &mut sink,
    )) {
        Ok(outcome) => format!(
            "sequence\t{}\nidentifier\t{}\n",
            outcome.seq,
            granary_core::hash::GrainId::of(&outcome.root_bytes),
        ),
        Err(ResolveError::NoHead) => "sequence\t0\nidentifier\tnone\n".to_owned(),
        Err(error) => return Err(format!("client chain probe failed: {error}")),
    };
    write_private(&path, evidence.as_bytes())
}

#[cfg(target_os = "linux")]
fn record_intent_selection(
    config: &ChildHandoff,
    handoff: &Path,
    uid: u32,
    index: usize,
) -> Result<(), String> {
    let (_, row) = read_writer_intent(config, handoff, uid)?;
    let row = row.ok_or_else(|| "client intent probe found no writer row".to_owned())?;
    write_private(
        &handoff.join(format!("client-intent-selection-{index}")),
        format!(
            "{} {} {} {}",
            row.epoch, row.generation, row.root, row.parent_seq
        )
        .as_bytes(),
    )
}

#[cfg(target_os = "linux")]
fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(target_os = "linux")]
fn root_fields(bytes: &[u8]) -> Result<String, String> {
    let doc = root::decode_root(bytes).map_err(|error| error.to_string())?;
    Ok(format!(
        "root_id\t{}\nseq\t{}\nparent\t{}\nmanifest_root\t{}\nwriter\t{}\n",
        granary_core::hash::GrainId::of(bytes),
        doc.seq,
        doc.parent
            .map_or_else(|| "none".to_owned(), |id| id.to_string()),
        doc.manifest_root,
        hex_bytes(&doc.writer_uuid),
    ))
}

#[cfg(target_os = "linux")]
fn changed_root_fields(prepared: &root::RootDoc, published: &root::RootDoc) -> String {
    let mut changed = Vec::new();
    for (different, name) in [
        (prepared.volume != published.volume, "volume"),
        (prepared.seq != published.seq, "seq"),
        (prepared.parent != published.parent, "parent"),
        (prepared.writer_uuid != published.writer_uuid, "writer"),
        (prepared.epoch != published.epoch, "epoch"),
        (prepared.timestamp != published.timestamp, "timestamp"),
        (
            prepared.chunker_spec != published.chunker_spec,
            "chunker_spec",
        ),
        (
            prepared.manifest_root != published.manifest_root,
            "manifest_root",
        ),
        (
            prepared.binmap_index != published.binmap_index,
            "binmap_index",
        ),
        (prepared.sheaf_head != published.sheaf_head, "sheaf_head"),
        (
            prepared.sigs.len() != published.sigs.len(),
            "signature_count",
        ),
    ] {
        if different {
            changed.push(name.to_owned());
        }
    }
    for index in 0..prepared.sigs.len().max(published.sigs.len()) {
        if prepared.sigs.get(index) != published.sigs.get(index) {
            changed.push(format!("signature_{index}"));
        }
    }
    if changed.is_empty() {
        "none".to_owned()
    } else {
        changed.join(",")
    }
}

#[cfg(target_os = "linux")]
fn root_comparison_fields(prepared: &[u8], published: &[u8]) -> Result<String, String> {
    let prepared_doc = root::decode_root(prepared).map_err(|error| error.to_string())?;
    let published_doc = root::decode_root(published).map_err(|error| error.to_string())?;
    Ok(format!(
        "prepared_root_id\t{}\npublished_root_id\t{}\nprepared_seq\t{}\n\
         published_seq\t{}\nprepared_parent\t{}\npublished_parent\t{}\n\
         prepared_manifest_root\t{}\npublished_manifest_root\t{}\n\
         prepared_writer\t{}\npublished_writer\t{}\nfield_diff\t{}\n",
        granary_core::hash::GrainId::of(prepared),
        granary_core::hash::GrainId::of(published),
        prepared_doc.seq,
        published_doc.seq,
        prepared_doc
            .parent
            .map_or_else(|| "none".to_owned(), |id| id.to_string()),
        published_doc
            .parent
            .map_or_else(|| "none".to_owned(), |id| id.to_string()),
        prepared_doc.manifest_root,
        published_doc.manifest_root,
        hex_bytes(&prepared_doc.writer_uuid),
        hex_bytes(&published_doc.writer_uuid),
        changed_root_fields(&prepared_doc, &published_doc),
    ))
}

#[cfg(target_os = "linux")]
fn record_recovery_intent(config: &ChildHandoff, handoff: &Path, uid: u32) -> Result<(), String> {
    let (body, row) = read_writer_intent(config, handoff, uid)?;
    let readback_path = read_path(handoff, "client-intent-readback-path")?;
    let evidence_path = read_path(handoff, "client-root-evidence-path")?;
    if readback_path.starts_with(&config.root) || evidence_path.starts_with(&config.root) {
        return Err("client recovery evidence is inside the store image".to_owned());
    }
    match read_text(handoff, "client-intent-probe-mode")?.as_str() {
        "prepared" => {
            let row = row.ok_or_else(|| "client prepared intent row is absent".to_owned())?;
            let prepared_path = read_path(handoff, "client-prepared-root-path")?;
            if prepared_path.starts_with(&config.root) {
                return Err("client recovery evidence is inside the store image".to_owned());
            }
            write_private(&readback_path, &body)?;
            write_private(&prepared_path, &row.root_bytes)?;
            write_private(&evidence_path, root_fields(&row.root_bytes)?.as_bytes())
        }
        "released" => {
            if row.is_some() {
                return Err("client post-recovery intent row was retained".to_owned());
            }
            let prepared_path = read_path(handoff, "client-prepared-root-path")?;
            let published_path = read_path(handoff, "client-published-root-path")?;
            let prepared = std::fs::read(prepared_path)
                .map_err(|error| format!("client cannot read prepared root evidence: {error}"))?;
            let published = std::fs::read(published_path)
                .map_err(|error| format!("client cannot read published root evidence: {error}"))?;
            write_private(&readback_path, &body)?;
            write_private(
                &evidence_path,
                root_comparison_fields(&prepared, &published)?.as_bytes(),
            )?;
            write_private(&handoff.join("client-post-recovery-intent"), b"released")
        }
        _ => Err("client intent probe mode is invalid".to_owned()),
    }
}

#[cfg(target_os = "linux")]
fn perform_workload(
    config: &ChildHandoff,
    handoff: &Path,
    uid: u32,
    quiescence: &Quiescence,
    metrics: &MetricsSnapshot,
) -> Result<(), String> {
    let plan = workload_plan(handoff)?;
    let planned: usize = plan.iter().sum();
    let runner_gates_steps = handoff.join("client-runner-gates-steps").is_file();
    if planned == 0 || (plan[0] != 0 && plan[0] != CALIBRATION_FSYNC_COUNT) {
        return Err("client child workload plan is invalid".to_owned());
    }
    let mut workload = spawn_workload(handoff)?;
    write_private(&handoff.join("client-uid"), uid.to_string().as_bytes())?;
    write_private(
        &handoff.join("client-planned-fsyncs"),
        planned.to_string().as_bytes(),
    )?;
    wait_for(&handoff.join("client-workload-created"))?;
    wait_for_quiescence(quiescence)?;
    write_private(&handoff.join("client-quiescent-before-start"), b"")?;
    wait_for(&handoff.join("client-go"))?;
    let before = metrics()?;
    let mut milestones = Vec::new();
    for index in 0..planned {
        wait_for(&handoff.join(format!("workload-step-{index}")))?;
        wait_for_quiescence(quiescence)?;
        if runner_gates_steps {
            record_intent_selection(config, handoff, uid, index)?;
        }
        write_private(&handoff.join(format!("client-step-quiescent-{index}")), b"")?;
        if index < plan[0] || index + 1 == planned {
            milestones.push(metrics()?);
        }
        release_workload_step(handoff, index, runner_gates_steps, wait_for, write_private)?;
    }
    let status = workload
        .wait()
        .map_err(|error| format!("client child cannot wait for workload: {error}"))?;
    if !status.success() {
        return Err("client child workload failed".to_owned());
    }
    let deltas = if plan[0] == CALIBRATION_FSYNC_COUNT {
        [
            milestones
                .get(2)
                .copied()
                .unwrap_or(0)
                .saturating_sub(milestones.get(1).copied().unwrap_or(0)),
            milestones
                .get(1)
                .copied()
                .unwrap_or(0)
                .saturating_sub(milestones.first().copied().unwrap_or(before)),
            milestones
                .last()
                .copied()
                .unwrap_or(0)
                .saturating_sub(milestones.get(2).copied().unwrap_or(0)),
        ]
    } else {
        [
            0,
            0,
            milestones
                .last()
                .copied()
                .unwrap_or(before)
                .saturating_sub(before),
        ]
    };
    write_private(
        &handoff.join("client-m15-deltas"),
        format!("{} {} {}", deltas[0], deltas[1], deltas[2]).as_bytes(),
    )?;
    write_private(&handoff.join("client-workload-done"), b"")?;
    wait_for(&handoff.join("client-stop"))
}

#[cfg(target_os = "linux")]
fn perform_probe(
    handoff: &Path,
    mountpoint: &Path,
    uid: u32,
    quiescence: &Quiescence,
) -> Result<(), String> {
    let index = read_text(handoff, "client-probe-index")?
        .parse::<usize>()
        .map_err(|_| "client probe index is invalid".to_owned())?;
    wait_for_quiescence(quiescence)?;
    let observed = std::fs::read(mountpoint.join("unique.bin"))
        .map_err(|error| format!("client probe cannot read mounted content: {error}"))?;
    let expected = expected_workload_content(index)?;
    if observed != expected {
        return Err("client probe mounted content mismatch".to_owned());
    }
    write_private(&handoff.join("client-uid"), uid.to_string().as_bytes())?;
    write_private(
        &handoff.join("client-probe-result"),
        format!("{index} {}", observed.len()).as_bytes(),
    )?;
    wait_for(&handoff.join("client-stop"))
}

#[cfg(target_os = "linux")]
fn drain(
    mountpoint: &Path,
    mounted: granary_fuse::BackgroundMount,
    identity: io::Result<MountIdentity>,
    sync_runtime: WritableSyncRuntime,
    writer: &LogWriter,
) -> Result<(), String> {
    // A failed detach can leave the event loop running, so return before joining.
    granary_fuse::detach_unmount(mountpoint).map_err(|error| error.to_string())?;
    let joined = mounted.join();
    // A pending FUSE read can return ECONNABORTED during teardown.
    let listed = identity.and_then(|identity| identity.listed_at(mountpoint));
    classify_session_end(SessionEndEvidence {
        unmount: Ok(()),
        joined,
        forced: false,
        listed,
    })
    .into_result()
    .map_err(|error| error.to_string())?;
    drop(sync_runtime);
    if writer.failed.load(Ordering::Relaxed) {
        return Err("client child log write failed".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run(handoff: &Path) -> Result<(), String> {
    let config = read_handoff(handoff)?;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let (paths, writer) = install_subscriber(&config, handoff, uid)?;
    let mut random = granary_net::secure_random::OsSecureRandom::new();
    let (mounted, sync_runtime, quiescence, metrics) =
        mount(&config, &paths, handoff, uid, gid, &mut random)?;
    let identity = MountIdentity::capture(&paths.mountpoint);
    if handoff.join("client-probe-index").is_file() {
        perform_probe(handoff, &paths.mountpoint, uid, &quiescence)?;
    } else {
        perform_workload(&config, handoff, uid, &quiescence, &metrics)?;
    }
    drain(&paths.mountpoint, mounted, identity, sync_runtime, &writer)
}

#[test]
fn q3_client_handoff_argument_controls() {
    assert_eq!(handoff_argument(Vec::<OsString>::new()), Ok(None));
    assert_eq!(
        handoff_argument([OsString::from("--skip=granary-q3-handoff=/tmp/q3-handoff",)]),
        Ok(Some(PathBuf::from("/tmp/q3-handoff")))
    );
    let cases = [
        (
            vec![OsString::from("--skip=granary-q3-handoff=")],
            "client child handoff path is empty",
        ),
        (
            vec![
                OsString::from("--skip=granary-q3-handoff=/tmp/a"),
                OsString::from("--skip=granary-q3-handoff=/tmp/b"),
            ],
            "client child handoff argument is duplicated",
        ),
    ];
    assert!(!cases.is_empty());
    for (args, refusal) in cases {
        assert_eq!(handoff_argument(args), Err(refusal));
    }
}

#[test]
fn q3_client_sync_profile_controls() {
    assert_eq!(
        sync_profile("durable-prepared"),
        Ok(Q3SyncProfile::DurablePrepared)
    );
    assert_eq!(sync_profile("published"), Ok(Q3SyncProfile::Published));
    let cases = ["", "durable_prepared", "request-correlated"];
    assert!(!cases.is_empty());
    for value in cases {
        assert_eq!(
            sync_profile(value),
            Err("client child sync profile is invalid")
        );
    }
}

#[test]
fn q3_client_runner_gates_recovery_steps() {
    use std::cell::{Cell, RefCell};

    let handoff = PathBuf::from("handoff");
    let runner_next = Cell::new(false);
    let released = Cell::new(false);
    let blocked = release_workload_step(
        &handoff,
        0,
        true,
        |path| {
            assert_eq!(path, handoff.join("runner-next-0"));
            runner_next
                .get()
                .then_some(())
                .ok_or_else(|| "runner gate absent".to_owned())
        },
        |path, bytes| {
            assert_eq!(path, handoff.join("workload-next-0"));
            assert!(bytes.is_empty());
            released.set(true);
            Ok(())
        },
    );
    assert_eq!(blocked, Err("runner gate absent".to_owned()));
    assert!(!released.get(), "the client released a runner-gated step");

    runner_next.set(true);
    let events = RefCell::new(Vec::new());
    release_workload_step(
        &handoff,
        0,
        true,
        |path| {
            events.borrow_mut().push(("wait", path.to_path_buf()));
            Ok(())
        },
        |path, _| {
            events.borrow_mut().push(("release", path.to_path_buf()));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        events.into_inner(),
        [
            ("wait", handoff.join("runner-next-0")),
            ("release", handoff.join("workload-next-0")),
        ]
    );

    release_workload_step(
        &handoff,
        1,
        false,
        |_| panic!("network cells must not wait for a runner gate"),
        |path, _| {
            assert_eq!(path, handoff.join("workload-next-1"));
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn q3_workload_ledger_records_only_successful_fsyncs() {
    use std::cell::Cell;

    assert_eq!(
        sha256_hex(b"abc"),
        Ok("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_owned())
    );
    let appended = Cell::new(false);
    assert_eq!(
        record_successful_fsync(Err("fsync failed".to_owned()), || {
            appended.set(true);
            Ok(())
        }),
        Err("fsync failed".to_owned())
    );
    assert!(!appended.get(), "a failed fsync wrote a ledger entry");
    record_successful_fsync(Ok(()), || {
        appended.set(true);
        Ok(())
    })
    .unwrap();
    assert!(
        appended.get(),
        "a successful fsync omitted its ledger entry"
    );
}

#[test]
fn q3_client_filter_emits_operation_events_without_foreign_refusals() {
    #[derive(Clone, Default)]
    struct Capture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
    impl crate::RecordWriter for Capture {
        fn write_record(&self, record: &crate::LogRecord) {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(String::from_utf8_lossy(record.as_bytes()).into_owned());
        }
    }
    struct Fixed;
    impl granary_core::secure_random::SecureRandom for Fixed {
        fn fill(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), granary_core::secure_random::EntropyUnavailable> {
            dest.fill(0x37);
            Ok(())
        }
    }

    let capture = Capture::default();
    let subscriber = crate::closed_subscriber_with_paths(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new(FILTER),
        capture.clone(),
        crate::LogPaths::Redacted,
        crate::BundleHistory::default(),
    );
    tracing::subscriber::with_default(subscriber, || {
        let id = crate::CorrelationId::draw(&mut Fixed).unwrap();
        crate::operation_span(crate::OperationKind::Fsync, &id).in_scope(|| {
            crate::op_begin(crate::OperationKind::Fsync);
            tracing::trace!(target: "q3_test_dependency", "foreign request detail");
            crate::op_end(crate::OperationKind::Fsync, crate::Outcome::Ok);
        });
    });
    let records = capture
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(records.len(), 2, "{records:?}");
    assert!(
        records
            .iter()
            .all(|record| record.contains("cor-3737373737373737")
                && !record.contains("log.record_refused")),
        "{records:?}"
    );
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "exercise directory and symlink refusals inside a test-owned scratch directory"
)]
fn q3_client_private_directory_restart_controls() {
    use std::os::unix::fs::PermissionsExt as _;

    let scratch = crate::overlay_test_support::ScratchDir::new();
    let root = scratch.0.join("root");
    let uid = nix::unistd::geteuid().as_raw();
    let device = prepare_private_directory(&root, uid, None).unwrap();
    assert!(root.is_dir(), "first start must create the private root");
    assert_eq!(
        prepare_private_directory(&root, uid, Some(device)),
        Ok(device)
    );

    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        prepare_private_directory(&root, uid, Some(device)),
        Err("client child private directory ownership or mode is invalid".to_owned())
    );

    let target = scratch.0.join("target");
    std::fs::create_dir(&target).unwrap();
    let link = scratch.0.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        prepare_private_directory(&link, uid, None)
            .unwrap_err()
            .starts_with("client child cannot open private directory:"),
        "a final-component symlink must be refused without following it"
    );

    let foreign_uid = uid.checked_add(1).unwrap_or_else(|| uid.saturating_sub(1));
    assert_eq!(
        judge_private_directory(true, 0o700, foreign_uid, device, uid, Some(device)),
        Err("client child private directory ownership or mode is invalid")
    );
    assert_eq!(
        judge_private_directory(true, 0o700, uid, device ^ 1, uid, Some(device)),
        Err("client child private directory device changed")
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "real writable FUSE mount and HTTPS authority; use the measurement runner"]
fn q3_measurement_client_child() -> Result<(), String> {
    let handoff = handoff_argument(std::env::args_os())?
        .ok_or_else(|| "client child handoff argument is required".to_owned())?;
    run(&handoff)
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "spawned by the ignored mounted measurement child"]
fn q3_measurement_workload_child() -> Result<(), String> {
    let handoff = handoff_argument(std::env::args_os())?
        .ok_or_else(|| "workload child handoff argument is required".to_owned())?;
    run_workload(&handoff)
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "spawned by the recovery runner after the offline recovery verb"]
fn q3_measurement_intent_probe_child() -> Result<(), String> {
    let handoff = handoff_argument(std::env::args_os())?
        .ok_or_else(|| "intent probe child handoff argument is required".to_owned())?;
    let config = read_handoff(&handoff)?;
    record_recovery_intent(&config, &handoff, nix::unistd::geteuid().as_raw())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "spawned by the recovery runner for signature-verified chain evidence"]
fn q3_measurement_chain_head_child() -> Result<(), String> {
    let handoff = handoff_argument(std::env::args_os())?
        .ok_or_else(|| "chain head child handoff argument is required".to_owned())?;
    let config = read_handoff(&handoff)?;
    record_chain_head(&config, &handoff, nix::unistd::geteuid().as_raw())
}
