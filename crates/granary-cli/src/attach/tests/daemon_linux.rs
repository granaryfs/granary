// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! The daemon's endings on a real kernel mount: `run_fuse_daemon` over a
//! test backend and a fake engine shutdown, with the signal producer
//! replaced by the row, which sends `Exit::Signal` into the daemon's own
//! channel instead of signalling the test process.
//!
//! Linux only, and root only: each row returns early, printing `NOT
//! EXECUTED`, when it cannot mount.

use super::*;
use crate::tests::{OwnedChild, test_command};
use granary_client::{ShutdownCause as C, ShutdownOutcome as O};
use std::os::unix::{
    ffi::OsStringExt as _,
    fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    process::CommandExt as _,
};

/// How long a row waits for the daemon before it names the hang.
const HANG: std::time::Duration = std::time::Duration::from_secs(30);
/// How long drop keeps fixture paths alive for a daemon cleanup already asked to stop.
const DROP_EXIT_BOUND: std::time::Duration = std::time::Duration::from_secs(6);

fn require_root(name: &str) -> bool {
    let root = crate::admission::process_credentials().euid == 0;
    let fuse = std::path::Path::new("/dev/fuse").exists();
    if !(root && fuse) {
        eprintln!("SKIPPED {name}: needs root and /dev/fuse to mount — NOT EXECUTED on this run");
    }
    root && fuse
}

fn support_key() -> granary_core::mount_control::MountKey {
    granary_core::mount_control::MountKey {
        namespace_dev: 1,
        namespace_ino: 2,
        mount_id: 3,
        fuse_major: 0,
        fuse_minor: 4,
    }
}

#[test]
fn support_layout_binds_mount_and_each_session_root_identity() {
    let scratch = crate::tests::ScratchDir::new();
    let cache = scratch.0.join("cache");
    let store = scratch.0.join("store");
    std::fs::create_dir(&cache).unwrap();
    std::fs::create_dir(&store).unwrap();
    let key = support_key();
    let (mountpoint, _) = granary_client::prove_mountpoint(&scratch.0).unwrap();
    let roots = prove_support_roots(&[
        (RootRole::Cache, cache.clone()),
        (RootRole::Store, store.clone()),
    ])
    .unwrap();
    let layout = support_layout(mountpoint, key, roots);
    let expected = [cache, store].map(|path| {
        let (identity, _) = granary_client::prove_mountpoint(&path).unwrap();
        (path.into_os_string().into_vec(), identity)
    });
    assert_eq!(
        (
            layout.mount,
            layout
                .roots
                .iter()
                .map(|root| (root.role, root.path.clone(), (root.dev, root.ino)))
                .collect::<Vec<_>>(),
        ),
        (
            SupportMountState::Mounted { mountpoint, key },
            vec![
                (RootRole::Cache, expected[0].0.clone(), expected[0].1),
                (RootRole::Store, expected[1].0.clone(), expected[1].1),
            ],
        ),
        "support header lost the session mount or source identities"
    );
}

#[test]
fn support_root_proof_refuses_unresolved_relative_and_symlinked_roots() {
    let scratch = crate::tests::ScratchDir::new();
    let real = scratch.0.join("real");
    let linked = scratch.0.join("linked");
    std::fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, &linked).unwrap();
    let mut cases = 0;
    for root in [PathBuf::from("relative-cache"), linked] {
        let error = prove_support_roots(&[(RootRole::Cache, root)]).unwrap_err();
        assert_eq!(
            error.to_string(),
            "support source identity unavailable",
            "unresolved source unexpectedly reached the header"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

fn relative_from_current(path: &Path) -> PathBuf {
    let depth = std::env::current_dir()
        .unwrap()
        .components()
        .filter(|component| matches!(component, std::path::Component::Normal(_)))
        .count();
    let mut relative = PathBuf::new();
    for _ in 0..depth {
        relative.push("..");
    }
    relative.push(path.strip_prefix("/").unwrap());
    relative
}

fn assert_support_cache_root(daemon: &Daemon, expected: &Path) {
    use std::os::unix::ffi::OsStrExt as _;

    let (header, bundle) = daemon.support_reply();
    let granary_core::support_trigger::Header::Layout(layout) = header else {
        panic!("support daemon did not return its source layout");
    };
    let [root] = layout.roots.as_slice() else {
        panic!("support layout did not contain exactly one source root");
    };
    let (identity, _) = granary_client::prove_mountpoint(expected).unwrap();
    assert_eq!(
        (
            matches!(layout.mount, SupportMountState::Mounted { .. }),
            root.role,
            root.path.as_slice(),
            (root.dev, root.ino),
            bundle.is_some(),
        ),
        (
            true,
            RootRole::Cache,
            expected.as_os_str().as_bytes(),
            identity,
            true,
        ),
        "support layout did not carry the resolved source identity"
    );
}

#[test]
fn daemon_linux_support_armed_daemon_resolves_a_relative_source_root() {
    if !require_root("daemon_linux_support_armed_daemon_resolves_a_relative_source_root") {
        return;
    }
    let scratch = crate::tests::ScratchDir::new();
    let cache = scratch.0.join("cache");
    std::fs::create_dir(&cache).unwrap();
    let configured = relative_from_current(&cache);
    assert!(!configured.is_absolute());
    let expected = granary_client::managed_path(&configured).unwrap();
    let daemon = Daemon::start_with_support_root(
        committed(),
        false,
        std::time::Duration::ZERO,
        scratch,
        Some(configured),
    );
    assert_support_cache_root(&daemon, &expected);
    daemon.signal();
    assert_eq!(daemon.exited(), MountOutcome::Clean);
}

#[test]
fn daemon_linux_support_armed_daemon_resolves_a_symlinked_source_ancestor() {
    if !require_root("daemon_linux_support_armed_daemon_resolves_a_symlinked_source_ancestor") {
        return;
    }
    let scratch = crate::tests::ScratchDir::new();
    let real = scratch.0.join("real");
    let cache = real.join("cache");
    let linked = scratch.0.join("linked");
    std::fs::create_dir_all(&cache).unwrap();
    std::os::unix::fs::symlink(&real, &linked).unwrap();
    let configured = linked.join("cache");
    let expected = granary_client::managed_path(&configured).unwrap();
    let daemon = Daemon::start_with_support_root(
        committed(),
        false,
        std::time::Duration::ZERO,
        scratch,
        Some(configured),
    );
    assert_support_cache_root(&daemon, &expected);
    daemon.signal();
    assert_eq!(daemon.exited(), MountOutcome::Clean);
}

#[test]
fn daemon_linux_support_armed_daemon_serves_a_bundle_without_entering_its_mount() {
    if !require_root("daemon_linux_support_armed_daemon_serves_a_bundle_without_entering_its_mount")
    {
        return;
    }
    let daemon =
        Daemon::start_with_support(committed(), false, std::time::Duration::ZERO, None, true);
    let started = std::time::Instant::now();
    let (header, bundle) = daemon.support_reply();
    assert!(
        matches!(
            header,
            granary_core::support_trigger::Header::Layout(
                granary_core::support_trigger::SourceLayout {
                    mount: SupportMountState::Mounted { .. },
                    ..
                }
            )
        ) && bundle.is_some()
            && started.elapsed() <= std::time::Duration::from_millis(2_500),
        "armed support did not answer from the live daemon within its deadline"
    );
    daemon.signal();
    assert_eq!(daemon.exited(), MountOutcome::Clean);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one wedged mount carries the root, output and requester checks in a single bounded sequence"
)]
fn daemon_linux_support_bundle_requester_does_not_enter_an_unserved_mount() {
    if !require_root("daemon_linux_support_bundle_requester_does_not_enter_an_unserved_mount") {
        return;
    }
    let scratch = crate::tests::ScratchDir::new();
    let mountpoint = scratch.0.join("wedged");
    let cache = mountpoint.join("cache");
    let output_parent = scratch.0.join("output");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&output_parent)
        .unwrap();
    let output = output_parent.join("wedged.gsb");
    let owner = crate::admission::process_credentials().euid;
    let (covered, _) = granary_client::prove_mountpoint(&mountpoint).unwrap();
    let (cache_identity, _) = granary_client::prove_mountpoint(&cache).unwrap();
    let prepared = control::Support::prepare(owner, &mountpoint).unwrap();
    let built = granary_core::manifest::build_dir(&[]).unwrap();
    let snapshot = granary_vfs::Snapshot::new(
        built.nodes.into_iter().collect(),
        built.root,
        granary_core::sheaf::Timestamp { secs: 1, nanos: 0 },
        granary_core::manifest::TreeStats::default(),
        granary_vfs::AttrPolicy { uid: 12345, gid: 0 },
        granary_fuse::FUSE_SERVE_LIMITS,
    )
    .unwrap();
    let (exit, _exits) = std::sync::mpsc::channel();
    let backend = DaemonBackend {
        session: LiveBackend::default(),
        cache_close: std::sync::Arc::new(std::sync::Mutex::new(None)),
        exit,
    };
    let filesystem = granary_fuse::GranaryFs::new(
        snapshot,
        backend,
        1,
        granary_fuse::MountWritability::ReadOnly,
    )
    .unwrap();
    let mut session = fuser::Session::new(
        filesystem,
        &mountpoint,
        &granary_fuse::session_config(false),
    )
    .unwrap();
    let rows = mount_table::control_mounts(&mountpoint).unwrap();
    let [mount] = rows.as_slice() else {
        panic!("unserved fixture mount rows={rows:?}");
    };
    let archive = crate::support_bundle::offline_archive(
        granary_core::sheaf::Timestamp { secs: 2, nanos: 0 },
        crate::support_bundle::writer_version().unwrap(),
        false,
        false,
    )
    .unwrap();
    let producer = control::SupportProducer::new(
        support_layout(
            covered,
            mount.key,
            vec![granary_core::support_trigger::SourceRoot {
                role: RootRole::Cache,
                path: cache.into_os_string().into_vec(),
                dev: cache_identity.0,
                ino: cache_identity.1,
            }],
        ),
        move || Ok(archive.clone()),
    );
    let service = control::Support::start(owner, prepared, producer).unwrap();
    let run = |destination: &Path| {
        let args = crate::support_bundle::parse(
            &[
                mountpoint.as_os_str(),
                std::ffi::OsStr::new("--output"),
                destination.as_os_str(),
            ]
            .map(std::ffi::OsString::from),
        )
        .unwrap();
        let target = mountpoint.clone();
        let (send, receive) = std::sync::mpsc::channel();
        let started = std::time::Instant::now();
        std::thread::spawn(move || {
            let reasons = std::cell::RefCell::new(Vec::new());
            let exit =
                crate::support_bundle::invoke_live_fixture(&args, &target, owner, |reason| {
                    reasons.borrow_mut().push(reason.to_owned());
                });
            let _ = send.send((exit, reasons.into_inner()));
        });
        (
            receive.recv_timeout(std::time::Duration::from_millis(2_500)),
            started.elapsed() <= std::time::Duration::from_millis(2_500),
        )
    };
    let published = run(&output);
    let refused = run(&mountpoint.join("nested.gsb"));
    drop(service);
    session.unmount().unwrap();
    let bytes = std::fs::read(&output).unwrap();
    assert_eq!(
        (
            published,
            refused,
            granary_core::support::BundleArchive::decode(&bytes).is_ok(),
        ),
        (
            (Ok((std::process::ExitCode::SUCCESS, Vec::new())), true),
            (
                Ok((
                    std::process::ExitCode::FAILURE,
                    vec!["output inside mounted namespace".to_owned()],
                )),
                true,
            ),
            true,
        ),
        "requester entered the non-empty unserved FUSE root or output path, or missed its bound"
    );
}

#[test]
fn daemon_linux_support_bundle_verb_publishes_live_archive() {
    if !require_root("daemon_linux_support_bundle_verb_publishes_live_archive") {
        return;
    }
    let scratch = crate::tests::ScratchDir::new();
    let output_parent = scratch.0.join("output");
    let linked_parent = scratch.0.join("linked-parent");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&output_parent)
        .unwrap();
    std::os::unix::fs::symlink(&scratch.0, &linked_parent).unwrap();
    let daemon = Daemon::start_with_support(
        committed(),
        false,
        std::time::Duration::ZERO,
        Some(scratch),
        true,
    );
    let mut trailing = daemon.mountpoint.clone().into_os_string();
    trailing.push("/");
    let targets = [
        daemon.mountpoint.clone(),
        relative_from_current(&daemon.mountpoint),
        PathBuf::from(trailing),
        linked_parent.join("mnt"),
    ];
    let mut cases = 0;
    for (index, target) in targets.into_iter().enumerate() {
        let output = output_parent.join(format!("live-{index}.gsb"));
        let args = crate::support_bundle::parse(
            &[
                target.as_os_str(),
                std::ffi::OsStr::new("--output"),
                output.as_os_str(),
            ]
            .map(std::ffi::OsString::from),
        )
        .unwrap();
        let started = std::time::Instant::now();
        let exit = crate::support_bundle::invoke(&args);
        let bytes = std::fs::read(&output).unwrap();
        assert_eq!(
            (
                exit,
                granary_core::support::BundleArchive::decode(&bytes).is_ok(),
                started.elapsed() <= std::time::Duration::from_millis(2_500),
            ),
            (std::process::ExitCode::SUCCESS, true, true),
            "live target spelling {target:?} did not reach the healthy producer"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
    daemon.signal();
    assert_eq!(daemon.exited(), MountOutcome::Clean);
}

#[test]
fn daemon_linux_support_bundle_verb_refuses_output_inside_live_mount() {
    if !require_root("daemon_linux_support_bundle_verb_refuses_output_inside_live_mount") {
        return;
    }
    let daemon =
        Daemon::start_with_support(committed(), false, std::time::Duration::ZERO, None, true);
    let output = daemon.mountpoint.join("refused.gsb");
    let args = crate::support_bundle::parse(
        &[
            daemon.mountpoint.as_os_str(),
            std::ffi::OsStr::new("--output"),
            output.as_os_str(),
        ]
        .map(std::ffi::OsString::from),
    )
    .unwrap();
    let reasons = std::cell::RefCell::new(Vec::new());
    let exit = crate::support_bundle::invoke_live_fixture(
        &args,
        &daemon.mountpoint,
        crate::admission::process_credentials().euid,
        |reason| reasons.borrow_mut().push(reason.to_owned()),
    );
    assert_eq!(
        (exit, reasons.into_inner()),
        (
            std::process::ExitCode::FAILURE,
            vec!["output inside mounted namespace".to_owned()],
        ),
        "live verb did not refuse its mounted namespace before publication"
    );
    daemon.signal();
    assert_eq!(daemon.exited(), MountOutcome::Clean);
}

#[test]
fn daemon_linux_support_armed_forced_mount_with_cache_beneath_mount_serves_bundle() {
    use std::os::unix::ffi::OsStrExt as _;

    if !require_root(
        "daemon_linux_support_armed_forced_mount_with_cache_beneath_mount_serves_bundle",
    ) {
        return;
    }
    let scratch = crate::tests::ScratchDir::new();
    let mountpoint = scratch.0.join("mnt");
    let cache = mountpoint.join("cache");
    let output_parent = scratch.0.join("output");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&output_parent)
        .unwrap();
    let forced = parse_mount(&mount_argv_at(&mountpoint, &["--trust-server", "--force"])).unwrap();
    assert!(
        forced.force && mount_preflight(&mountpoint, forced.force).is_ok(),
        "--force did not admit the non-empty mountpoint"
    );
    let expected = granary_client::managed_path(&cache).unwrap();
    let (identity, _) = granary_client::prove_mountpoint(&expected).unwrap();
    let daemon = Daemon::start_with_support_root(
        committed(),
        false,
        std::time::Duration::ZERO,
        scratch,
        Some(cache),
    );
    let started = std::time::Instant::now();
    let (header, bundle) = daemon.support_reply();
    let granary_core::support_trigger::Header::Layout(layout) = header else {
        panic!("support daemon did not return its source layout");
    };
    let [root] = layout.roots.as_slice() else {
        panic!("support layout did not contain exactly one source root");
    };
    assert_eq!(
        (
            matches!(layout.mount, SupportMountState::Mounted { .. }),
            root.role,
            root.path.as_slice(),
            (root.dev, root.ino),
            bundle.is_some(),
            started.elapsed() <= std::time::Duration::from_millis(2_500),
        ),
        (
            true,
            RootRole::Cache,
            expected.as_os_str().as_bytes(),
            identity,
            true,
            true,
        ),
        "forced mount did not answer from its pre-proved nested source"
    );
    let output = output_parent.join("forced-live.gsb");
    let args = crate::support_bundle::parse(
        &[
            daemon.mountpoint.as_os_str(),
            std::ffi::OsStr::new("--output"),
            output.as_os_str(),
        ]
        .map(std::ffi::OsString::from),
    )
    .unwrap();
    let verb_started = std::time::Instant::now();
    let exit = crate::support_bundle::invoke(&args);
    assert_eq!(
        (
            exit,
            granary_core::support::BundleArchive::decode(&std::fs::read(output).unwrap()).is_ok(),
            verb_started.elapsed() <= std::time::Duration::from_millis(2_500),
        ),
        (std::process::ExitCode::SUCCESS, true, true),
        "forced mount requester entered the nested cache instead of publishing"
    );
    daemon.signal();
    assert_eq!(daemon.exited(), MountOutcome::Clean);
}

#[test]
fn daemon_linux_support_daemon_reports_the_production_unmount_transition_as_absent() {
    if !require_root(
        "daemon_linux_support_daemon_reports_the_production_unmount_transition_as_absent",
    ) {
        return;
    }
    let daemon = Daemon::start_with_support(
        committed(),
        false,
        std::time::Duration::from_secs(2),
        None,
        true,
    );
    let (owner, socket) = daemon.support_endpoint();
    daemon.signal();
    let started = std::time::Instant::now();
    while daemon.listed() {
        assert!(
            started.elapsed() <= std::time::Duration::from_millis(500),
            "production unmount did not begin within its bound"
        );
        pause(std::time::Duration::from_millis(5));
    }
    // The kernel removes the mount before the daemon can verify and publish its absence.
    let bound = std::time::Duration::from_secs(2);
    let started = std::time::Instant::now();
    let deadline = started + bound;
    let absent_with_bundle = Some((Some(SupportMountState::Absent), true));
    let mut last_reply = None;
    let mut last_error = None;
    while std::time::Instant::now() < deadline {
        match Daemon::try_support_reply_at(owner, &socket, deadline) {
            Ok((header, bundle)) => {
                let mount = match header {
                    granary_core::support_trigger::Header::Layout(layout) => Some(layout.mount),
                    granary_core::support_trigger::Header::Unavailable => None,
                };
                last_reply = Some((mount, bundle.is_some()));
                last_error = None;
            }
            Err(error) => last_error = Some(error),
        }
        if last_reply == absent_with_bundle {
            break;
        }
        pause(
            std::time::Duration::from_millis(5)
                .min(deadline.saturating_duration_since(std::time::Instant::now())),
        );
    }
    let elapsed = started.elapsed();
    assert!(
        last_reply == absent_with_bundle,
        "production unmount did not publish absent state with collectable members within {bound:?} \
         (elapsed {elapsed:?}), last reply (mount state, bundle present): {last_reply:?}, \
         last request error: {last_error:?}"
    );
    assert_eq!(daemon.exited(), MountOutcome::Clean);
}

struct UserRuntime {
    path: PathBuf,
    user_created: bool,
    control_created: bool,
}
impl UserRuntime {
    fn new(uid: u32) -> Self {
        let path = PathBuf::from(format!("/run/user/{uid}"));
        let user_created = match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => panic!("runtime fixture {}: {error}", path.display()),
        };
        let mut runtime = Self {
            path,
            user_created,
            control_created: false,
        };
        if user_created {
            std::fs::set_permissions(&runtime.path, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            std::os::unix::fs::chown(&runtime.path, Some(uid), Some(uid)).unwrap();
        }
        let meta = std::fs::symlink_metadata(&runtime.path).unwrap();
        assert_eq!(
            (meta.is_dir(), meta.uid(), meta.mode() & 0o7777),
            (true, uid, 0o700)
        );
        runtime.control_created = !runtime.path.join("granary-umount").try_exists().unwrap();
        runtime
    }
}
impl Drop for UserRuntime {
    fn drop(&mut self) {
        if self.control_created {
            let _ = std::fs::remove_dir(self.path.join("granary-umount"));
        }
        if self.user_created {
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

struct MountedChild {
    child: Option<OwnedChild>,
    target: PathBuf,
}
impl Drop for MountedChild {
    fn drop(&mut self) {
        drop(self.child.take());
        let _ = granary_fuse::detach_unmount(&self.target);
    }
}

fn owner_child(mode: &str, directory: &Path, uid: u32) -> OwnedChild {
    OwnedChild(
        test_command()
            .args([
                "--exact",
                "attach::tests::daemon_linux::control_owner_child",
                "--nocapture",
            ])
            .env("GRANARY_CONTROL_OWNER_MODE", mode)
            .env("GRANARY_CONTROL_OWNER_DIR", directory)
            .uid(uid)
            .gid(uid)
            .spawn()
            .unwrap(),
    )
}

fn wait_owner_ready(child: &mut OwnedChild, marker: &Path) {
    for _ in 0..3000 {
        if marker.try_exists().unwrap() {
            return;
        }
        let status = child.0.try_wait().unwrap();
        assert!(
            status.is_none(),
            "owned daemon exited before readiness: {status:?}"
        );
        pause(std::time::Duration::from_millis(10));
    }
    panic!("owned daemon did not publish readiness within 30 s");
}

fn control_fixture_path(target: &Path, mount: mount_table::ControlMount, suffix: &str) -> PathBuf {
    use std::os::unix::ffi::OsStrExt as _;
    let directory = if mount.owner == 0 {
        PathBuf::from("/run/granary-umount")
    } else {
        PathBuf::from(format!("/run/user/{}/granary-umount", mount.owner))
    };
    let mut bytes = b"granary-umount-path-v1\0".to_vec();
    bytes.extend(mount.key.namespace_dev.to_be_bytes());
    bytes.extend(mount.key.namespace_ino.to_be_bytes());
    bytes.extend(target.as_os_str().as_bytes());
    directory.join(format!(
        "{}.{suffix}",
        granary_core::hash::GrainId::of(&bytes).digest_hex()
    ))
}

#[test]
fn control_owner_child() {
    let Some(mode) = std::env::var_os("GRANARY_CONTROL_OWNER_MODE") else {
        return;
    };
    let directory = PathBuf::from(std::env::var_os("GRANARY_CONTROL_OWNER_DIR").unwrap());
    if mode == "command" {
        assert_eq!(
            cmd_umount(&directory.join("mnt"), &mut Vec::new()),
            std::process::ExitCode::SUCCESS
        );
        return;
    }
    assert!(
        mode == "root" || mode == "owner" || mode == "busy",
        "fixture mode={mode:?}"
    );
    let daemon = Daemon::start(
        committed(),
        false,
        std::time::Duration::ZERO,
        Some(crate::tests::ScratchDir(directory.clone())),
    );
    std::fs::write(directory.join("ready"), b"ready").unwrap();
    let expected = if mode == "busy" {
        (MountOutcome::CacheCloseFailed, 1)
    } else if mode == "owner" {
        (MountOutcome::Clean, 1)
    } else {
        (MountOutcome::RuntimeFailure, 0)
    };
    assert_eq!((daemon.exited(), daemon.stop_begins()), expected);
}

/// Kernel ownership and peer credentials are real; the engine report is a fake.
#[test]
fn daemon_linux_control_owner_credentials() {
    if !require_root("daemon_linux_control_owner_credentials") {
        return;
    }
    let mut nonce = [0; 16];
    granary_core::secure_random::SecureRandom::fill(
        &mut granary_net::secure_random::OsSecureRandom::new(),
        &mut nonce,
    )
    .unwrap();
    let path = PathBuf::from(format!(
        "/run/granary-owner-{:032x}",
        u128::from_be_bytes(nonce)
    ));
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(&path)
        .unwrap();
    let scratch = crate::tests::ScratchDir(path);
    std::fs::set_permissions(&scratch.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    let _runtime = UserRuntime::new(65534);
    let mut cases = 0;
    for mode in ["root", "owner"] {
        let directory = scratch.0.join(mode);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        std::os::unix::fs::chown(&directory, Some(65534), Some(65534)).unwrap();
        let mut daemon = MountedChild {
            child: Some(owner_child(mode, &directory, 65534)),
            target: directory.join("mnt"),
        };
        wait_owner_ready(daemon.child.as_mut().unwrap(), &directory.join("ready"));
        let rows = mount_table::control_mounts(&daemon.target).unwrap();
        let [mount] = rows.as_slice() else {
            panic!("fixture mount rows={rows:?}");
        };
        assert_eq!(mount.owner, 65534);
        let lock = control_fixture_path(&daemon.target, *mount, "lock");
        if mode == "root" {
            assert_eq!(cmd_umount_linux(&daemon.target, 0), MountOutcome::Clean);
        } else {
            let status = owner_child("command", &directory, 65534).wait();
            assert!(status.success(), "owner command exit={status:?}");
        }
        let status = daemon.child.as_mut().unwrap().wait();
        assert!(status.success(), "owned daemon exit={status:?}");
        assert!(
            mount_table::control_mounts(&daemon.target)
                .unwrap()
                .is_empty()
        );
        let meta = std::fs::symlink_metadata(&lock).unwrap();
        assert_eq!(
            (
                meta.is_file(),
                meta.uid(),
                meta.mode() & 0o7777,
                meta.nlink()
            ),
            (true, 65534, 0o600, 1)
        );
        std::fs::remove_file(lock).unwrap();
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// The process exit and held descriptor are real; the committed report is a fake.
#[test]
fn daemon_linux_control_busy_descriptor_delivery() {
    use std::os::fd::AsRawFd as _;
    if !require_root("daemon_linux_control_busy_descriptor_delivery") {
        return;
    }
    let scratch = crate::tests::ScratchDir::new();
    let directory = scratch.0.join("daemon");
    std::fs::create_dir(&directory).unwrap();
    let mut daemon = MountedChild {
        child: Some(owner_child("busy", &directory, 0)),
        target: directory.join("mnt"),
    };
    wait_owner_ready(daemon.child.as_mut().unwrap(), &directory.join("ready"));
    let holder = std::fs::File::open(&daemon.target).unwrap();
    assert_eq!(
        cmd_umount_linux(&daemon.target, 0),
        MountOutcome::CacheCloseFailed
    );
    let status = daemon.child.as_mut().unwrap().wait();
    assert!(status.success(), "owned daemon exit={status:?}");
    assert!(
        mount_table::control_mounts(&daemon.target)
            .unwrap()
            .is_empty()
    );
    let alias = PathBuf::from(format!("/proc/self/fd/{}", holder.as_raw_fd()));
    let read =
        std::fs::read_dir(alias).and_then(|mut entries| entries.next().transpose().map(|_| ()));
    assert_eq!(read.unwrap_err().raw_os_error(), Some(107));
}

/// Everything the shared serving body needs for one backend.
struct DaemonSetup<B, K> {
    backend: B,
    snapshot: granary_vfs::Snapshot,
    writability: granary_fuse::MountWritability,
    config: fuser::Config,
    wire: MountWireSnapshot,
    bind: Option<BindView<B>>,
    stop: std::sync::Arc<dyn DaemonStop>,
    store: PathBuf,
    mode: granary_core::mount_control::Mode,
    keepalive: K,
}

/// A running daemon: its exit, its channel, and its mount point.
struct Daemon {
    exit: std::sync::mpsc::Receiver<MountOutcome>,
    #[cfg(feature = "overlay-fault-tests")]
    connection_outlived_run: Option<std::sync::mpsc::Receiver<bool>>,
    signals: std::sync::mpsc::Sender<Exit>,
    stop: Option<std::sync::Arc<FakeStop>>,
    #[cfg(feature = "overlay-fault-tests")]
    control: Option<granary_client::overlay_test_support::AuthorityControl>,
    mountpoint: PathBuf,
    scratch: Option<crate::tests::ScratchDir>,
}

impl Daemon {
    /// Mount a fake read-only engine through the shared serving body.
    ///
    /// `answer` is its shutdown result, `held` pre-seeds that result as
    /// `destroy`'s own shutdown would, and `close_delay` is the cache close's
    /// duration.
    fn start(
        answer: granary_client::ShutdownReport,
        held: bool,
        close_delay: std::time::Duration,
        scratch: Option<crate::tests::ScratchDir>,
    ) -> Self {
        Self::start_with_support(answer, held, close_delay, scratch, false)
    }

    fn start_with_support(
        answer: granary_client::ShutdownReport,
        held: bool,
        close_delay: std::time::Duration,
        scratch: Option<crate::tests::ScratchDir>,
        support_armed: bool,
    ) -> Self {
        let scratch = scratch.unwrap_or_else(crate::tests::ScratchDir::new);
        let support_root = support_armed.then(|| {
            let cache = scratch.0.join("cache");
            std::fs::create_dir(&cache).unwrap();
            cache
        });
        Self::start_with_support_root(answer, held, close_delay, scratch, support_root)
    }

    fn start_with_support_root(
        answer: granary_client::ShutdownReport,
        held: bool,
        close_delay: std::time::Duration,
        scratch: crate::tests::ScratchDir,
        support_root: Option<PathBuf>,
    ) -> Self {
        let mountpoint = scratch.0.join("mnt");
        std::fs::create_dir_all(&mountpoint).unwrap();
        let support = support_root.map(|cache| {
            let roots = resolve_support_roots([(RootRole::Cache, cache)]).unwrap();
            SupportOwners {
                context: SupportContext {
                    configuration: Err(BundleRefusal::Unavailable),
                    history: granary_client::BundleHistory::default(),
                },
                metrics: None,
                overlay: None,
                roots,
            }
        });
        let stop = std::sync::Arc::new(FakeStop::answering(answer));
        if held {
            *stop.done.lock().unwrap() = Some(answer);
        }
        let engine = stop.clone();
        let target = mountpoint.clone();
        Self::start_body(
            target,
            Some(scratch),
            Some(stop),
            #[cfg(feature = "overlay-fault-tests")]
            None,
            #[cfg(feature = "overlay-fault-tests")]
            false,
            support,
            move |serving| {
                let built = granary_core::manifest::build_dir(&[]).unwrap();
                let snapshot = granary_vfs::Snapshot::new(
                    built.nodes.into_iter().collect(),
                    built.root,
                    granary_core::sheaf::Timestamp { secs: 1, nanos: 0 },
                    granary_core::manifest::TreeStats::default(),
                    granary_vfs::AttrPolicy { uid: 12345, gid: 0 },
                    granary_fuse::FUSE_SERVE_LIMITS,
                )
                .unwrap();
                let args = parse_mount(&mount_argv(&["--trust-server"])).unwrap();
                let store =
                    HttpStore::new(&args.endpoint, args.tls_pins.clone(), &AmbientNetwork).unwrap();
                DaemonSetup {
                    backend: LiveBackend {
                        close_delay,
                        ..LiveBackend::default()
                    },
                    snapshot,
                    writability: granary_fuse::MountWritability::ReadOnly,
                    config: granary_fuse::session_config(false),
                    wire: MountWireSnapshot {
                        config: None,
                        handle: store.wire_bytes(),
                        endpoint: args.endpoint,
                        pinned_seq: None,
                    },
                    bind: Some(Box::new(move |_| {
                        let _ = serving.send(());
                        Ok(())
                    })),
                    stop: engine as std::sync::Arc<dyn DaemonStop>,
                    store: PathBuf::from("store"),
                    mode: granary_core::mount_control::Mode::Writable {
                        bound_seconds: 1,
                        store: b"store".to_vec(),
                    },
                    keepalive: (),
                }
            },
        )
    }

    /// Mount the real writable engine through the shared serving body.
    ///
    /// `profile` selects its sync acknowledgement and `bound` limits the
    /// shutdown whose result the control unmount waits for.
    #[cfg(feature = "overlay-fault-tests")]
    fn start_engine(profile: granary_client::SyncProfile, bound: std::time::Duration) -> Self {
        use std::os::unix::ffi::OsStrExt as _;

        let parts =
            granary_client::overlay_test_support::writable_daemon_parts(profile, bound).unwrap();
        let control = parts.control.clone();
        let mountpoint = control.mountpoint().to_path_buf();
        let store = control.store_path().to_path_buf();
        let target = mountpoint.clone();
        Self::start_body(
            target,
            None,
            None,
            Some(control),
            true,
            None,
            move |serving| {
                let granary_client::overlay_test_support::WritableDaemonParts {
                    mut attachment,
                    sync_runtime,
                    control,
                    shutdown,
                } = parts;
                let args = parse_mount(&mount_argv(&["--trust-server"])).unwrap();
                let wire_store =
                    HttpStore::new(&args.endpoint, args.tls_pins.clone(), &AmbientNetwork).unwrap();
                let bind = attachment.backend.take_view_binding().map(|binding| {
                    Box::new(move |view| {
                        let _ = serving.send(());
                        binding.bind(view, daemon_session)
                    }) as BindView<_>
                });
                DaemonSetup {
                    backend: attachment.backend,
                    snapshot: attachment.snapshot,
                    writability: granary_fuse::MountWritability::Writable,
                    config: attachment.config,
                    wire: MountWireSnapshot {
                        config: None,
                        handle: wire_store.wire_bytes(),
                        endpoint: args.endpoint,
                        pinned_seq: None,
                    },
                    bind,
                    stop: std::sync::Arc::new(shutdown) as std::sync::Arc<dyn DaemonStop>,
                    store: store.clone(),
                    mode: granary_core::mount_control::Mode::Writable {
                        bound_seconds: u32::try_from(bound.as_secs()).unwrap(),
                        store: store.as_os_str().as_bytes().to_vec(),
                    },
                    keepalive: (sync_runtime, control),
                }
            },
        )
    }

    fn start_body<B, K>(
        mountpoint: PathBuf,
        scratch: Option<crate::tests::ScratchDir>,
        stop: Option<std::sync::Arc<FakeStop>>,
        #[cfg(feature = "overlay-fault-tests")] control: Option<
            granary_client::overlay_test_support::AuthorityControl,
        >,
        #[cfg(feature = "overlay-fault-tests")] abort_after_run: bool,
        support: Option<SupportOwners>,
        setup: impl FnOnce(std::sync::mpsc::Sender<()>) -> DaemonSetup<B, K> + Send + 'static,
    ) -> Self
    where
        B: granary_fuse::MountBackend + SupportBackend + Send + 'static,
        K: Send + 'static,
    {
        let (give, take) = std::sync::mpsc::channel();
        let (serving, ready) = std::sync::mpsc::channel();
        let (exited, exit) = std::sync::mpsc::channel();
        #[cfg(feature = "overlay-fault-tests")]
        let (connection_give, connection_take) = std::sync::mpsc::channel();
        #[cfg(feature = "overlay-fault-tests")]
        let (outlived_give, outlived_take) = std::sync::mpsc::channel();
        let owner = crate::admission::process_credentials().euid;
        let target = mountpoint.clone();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        std::thread::spawn(move || {
            let _dispatch = tracing::dispatcher::set_default(&dispatch);
            let setup = setup(serving);
            let DaemonSetup {
                backend,
                snapshot,
                writability,
                config,
                wire,
                bind,
                stop,
                store,
                mode,
                keepalive,
            } = setup;
            let outcome = run_fuse_daemon(
                backend,
                snapshot,
                1,
                writability,
                &target,
                &config,
                #[cfg(feature = "conformance-breakage")]
                None,
                &wire,
                bind,
                Some((stop, store.as_path())),
                support,
                None,
                owner,
                mode,
                move |tx, ready| {
                    let _ = give.send(tx);
                    let _ = ready.send(());
                    let _ = ready.send(());
                },
                #[cfg(feature = "conformance-breakage")]
                &mut Vec::new(),
            );
            #[cfg(feature = "overlay-fault-tests")]
            if abort_after_run {
                let outlived = connection_take
                    .recv_timeout(HANG)
                    .ok()
                    .flatten()
                    .is_some_and(
                        |mut abort: granary_client::overlay_test_support::ArmedFuseAbort| {
                            abort.abort()
                        },
                    );
                let _ = outlived_give.send(outlived);
            }
            drop(keepalive);
            let _ = exited.send(outcome);
        });
        let signals = take.recv_timeout(HANG).unwrap();
        ready.recv_timeout(HANG).unwrap();
        let poll = std::time::Duration::from_millis(5);
        let mut polls = 0;
        while granary_fuse::MountIdentity::capture(&mountpoint).is_err() {
            assert!(
                polls < HANG.as_millis() / poll.as_millis(),
                "the daemon never mounted"
            );
            pause(poll);
            polls += 1;
        }
        #[cfg(feature = "overlay-fault-tests")]
        let connection_outlived_run = abort_after_run.then_some(outlived_take);
        #[cfg(feature = "overlay-fault-tests")]
        if abort_after_run {
            connection_give
                .send(granary_client::overlay_test_support::ArmedFuseAbort::arm(
                    &mountpoint,
                ))
                .unwrap();
        }
        Self {
            exit,
            #[cfg(feature = "overlay-fault-tests")]
            connection_outlived_run,
            signals,
            stop,
            #[cfg(feature = "overlay-fault-tests")]
            control,
            mountpoint,
            scratch,
        }
    }

    fn signal(&self) {
        self.signals.send(Exit::Signal("SIGTERM")).unwrap();
    }

    fn support_endpoint(&self) -> (u32, PathBuf) {
        let [mount] = mount_table::control_mounts(&self.mountpoint)
            .unwrap()
            .try_into()
            .unwrap();
        let socket = control::support_fixture_path(
            mount.owner,
            (mount.key.namespace_dev, mount.key.namespace_ino),
            &self.mountpoint,
        );
        (mount.owner, socket)
    }

    fn try_support_reply_at(
        owner: u32,
        socket: &Path,
        deadline: std::time::Instant,
    ) -> std::io::Result<(
        granary_core::support_trigger::Header,
        Option<granary_core::support::BundleArchive>,
    )> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let deadline = tokio::time::Instant::from_std(deadline);
            let stream = tokio::time::timeout_at(deadline, tokio::net::UnixStream::connect(socket))
                .await??;
            control::request_support_fixture(stream, owner, deadline)
                .await
                .map_err(std::io::Error::other)
        })
    }

    fn support_reply(
        &self,
    ) -> (
        granary_core::support_trigger::Header,
        Option<granary_core::support::BundleArchive>,
    ) {
        let (owner, socket) = self.support_endpoint();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        Self::try_support_reply_at(owner, &socket, deadline).unwrap()
    }

    fn exited(&self) -> MountOutcome {
        self.exit.recv_timeout(HANG).unwrap()
    }

    #[cfg(feature = "overlay-fault-tests")]
    fn try_exited(&self) -> Result<MountOutcome, std::sync::mpsc::TryRecvError> {
        self.exit.try_recv()
    }

    fn listed(&self) -> bool {
        granary_fuse::MountIdentity::capture(&self.mountpoint).is_ok()
    }

    fn connection_path(mountpoint: &Path) -> PathBuf {
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let wanted = mountpoint.to_str().unwrap();
        let minor = mountinfo
            .lines()
            .find_map(|line| {
                let fields: Vec<&str> = line.split(' ').collect();
                (fields.get(4) == Some(&wanted))
                    .then(|| fields.get(2).and_then(|device| device.strip_prefix("0:")))
                    .flatten()
            })
            .unwrap();
        PathBuf::from("/sys/fs/fuse/connections").join(minor)
    }

    /// The mount's fusectl connection, from its anonymous device's minor.
    fn connection(&self) -> PathBuf {
        Self::connection_path(&self.mountpoint)
    }

    fn open_root(&self) -> std::fs::File {
        std::fs::File::open(&self.mountpoint).unwrap()
    }

    fn stop_begins(&self) -> usize {
        self.stop.as_ref().map_or(0, |stop| {
            stop.began.load(std::sync::atomic::Ordering::SeqCst)
        })
    }

    fn scratch(&self) -> &crate::tests::ScratchDir {
        self.scratch.as_ref().unwrap()
    }

    fn scratch_mut(&mut self) -> &mut crate::tests::ScratchDir {
        self.scratch.as_mut().unwrap()
    }

    #[cfg(feature = "overlay-fault-tests")]
    fn control(&self) -> &granary_client::overlay_test_support::AuthorityControl {
        self.control.as_ref().unwrap()
    }

    #[cfg(feature = "overlay-fault-tests")]
    fn dirty_writer(&self, name: &str, bytes: &[u8]) -> std::fs::File {
        use std::io::Write as _;

        // A newly created file has a stage, so the store counts this descriptor.
        let mut writer = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(self.mountpoint.join(name))
            .unwrap();
        writer.write_all(bytes).unwrap();
        writer
    }

    #[cfg(feature = "overlay-fault-tests")]
    fn start_umount(&self) -> std::sync::mpsc::Receiver<MountOutcome> {
        let target = self.mountpoint.clone();
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = send.send(cmd_umount_linux(&target, 0));
        });
        receive
    }

    #[cfg(feature = "overlay-fault-tests")]
    fn wait_stalled(&self) {
        let started = std::time::Instant::now();
        while !self.control().dispatch_is_stalled() {
            assert!(
                started.elapsed() < HANG,
                "shutdown never reached authority dispatch"
            );
            pause(std::time::Duration::from_millis(5));
        }
    }

    #[cfg(feature = "overlay-fault-tests")]
    fn wait_coordination_idle(&self) {
        let started = std::time::Instant::now();
        loop {
            match self.control().coordination_is_idle() {
                Ok(true) => return,
                Ok(false) => assert!(
                    started.elapsed() < HANG,
                    "writable coordination never became idle"
                ),
                Err(error) => panic!("writable coordination inspection failed: {error}"),
            }
            pause(std::time::Duration::from_millis(5));
        }
    }

    #[cfg(feature = "overlay-fault-tests")]
    fn wait_report(&self) -> granary_client::ShutdownReport {
        let started = std::time::Instant::now();
        loop {
            if let Some(report) = self.control().shutdown().report() {
                return report;
            }
            assert!(
                started.elapsed() < HANG,
                "shutdown never published its report"
            );
            pause(std::time::Duration::from_millis(5));
        }
    }

    #[cfg(feature = "overlay-fault-tests")]
    fn connection_outlived_run(&self) -> bool {
        self.connection_outlived_run
            .as_ref()
            .unwrap()
            .recv_timeout(HANG)
            .unwrap()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        #[cfg(feature = "overlay-fault-tests")]
        if let Some(control) = &self.control {
            control.release_stall();
        }
        let _ = self.signals.send(Exit::Signal("SIGTERM"));
        let _ = granary_fuse::detach_unmount(&self.mountpoint);
        if matches!(
            self.exit.recv_timeout(DROP_EXIT_BOUND),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) && let Some(scratch) = self.scratch.take()
        {
            std::mem::forget(scratch);
        }
    }
}

/// Keeps the original kernel handle open and probes that handle directly.
/// Reopening `/proc/self/fd/N` would test a new path open, not the busy handle.
#[cfg(feature = "overlay-fault-tests")]
struct BusyHolder {
    child: std::process::Child,
    replies: std::io::BufReader<std::process::ChildStdout>,
}

#[cfg(feature = "overlay-fault-tests")]
impl BusyHolder {
    fn open(path: &Path, directory: bool) -> Self {
        use std::io::BufRead as _;

        let mut child = std::process::Command::new("python3")
            .arg("-c")
            .arg(granary_client::overlay_test_support::HELD_HANDLE_SCRIPT)
            .arg(path)
            .arg(if directory { "directory" } else { "file" })
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut replies = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut opened = String::new();
        replies.read_line(&mut opened).unwrap();
        assert_eq!(
            opened.trim(),
            "OPEN ok",
            "the busy holder must exercise its descriptor while the mount is healthy"
        );
        Self { child, replies }
    }

    fn probe(&mut self) -> Result<(), String> {
        use std::io::{BufRead as _, Write as _};

        self.child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"PROBE\n")
            .unwrap();
        let mut reply = String::new();
        self.replies.read_line(&mut reply).unwrap();
        match reply.trim() {
            "ok" => Ok(()),
            error => Err(error.to_owned()),
        }
    }
}

#[cfg(feature = "overlay-fault-tests")]
impl Drop for BusyHolder {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[cfg(feature = "overlay-fault-tests")]
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "both profiles run one premise, stall, latch and release sequence against the real engine"
)]
fn daemon_linux_umount_waits_while_mounted() {
    use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};

    if !require_root("daemon_linux_umount_waits_while_mounted") {
        return;
    }
    let mut cases = 0;
    for profile in [
        granary_client::SyncProfile::DurablePrepared,
        granary_client::SyncProfile::Published,
    ] {
        let daemon = Daemon::start_engine(profile, std::time::Duration::from_secs(10));
        let seq_before = daemon.control().head_seq();
        let publications_before = daemon.control().publications();
        let registrations_before = daemon.control().registrations();
        let held = daemon.dirty_writer("a", &[b'a'; 64]);
        for file in ["b", "c"] {
            std::fs::write(daemon.mountpoint.join(file), file.repeat(64)).unwrap();
        }
        let shutdown_premise = (
            daemon.control().head_seq() - seq_before,
            daemon.control().publications() - publications_before,
            daemon.control().registrations() - registrations_before,
            daemon.control().has_open_write_handles(),
        );
        assert_eq!(
            shutdown_premise,
            (0, 0, 0, Ok(true)),
            "profile={profile:?}: (head movement, publications, registrations, open writer) \
             before shutdown"
        );
        daemon.wait_coordination_idle();
        daemon.control().stall_before_dispatch();
        // A pre-existing/background registration that takes the newly armed
        // stall is pending in the store and cannot pass this idle boundary.
        daemon.wait_coordination_idle();
        let registration_window_start = daemon.control().registrations();
        assert_eq!(
            registration_window_start, registrations_before,
            "profile={profile:?}: accepted registration before start_umount"
        );
        let client = daemon.start_umount();
        daemon.wait_stalled();
        let stalled = daemon.control().stalled_dispatch();
        let file = daemon.mountpoint.join("f.txt");
        let latched = (
            held.write_at(b"x", 0).map_err(|error| error.raw_os_error()),
            std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_SYNC)
                .open(&file)
                .and_then(|synced| synced.write_at(b"y", 0))
                .map_err(|error| error.raw_os_error()),
            held.sync_all().map_err(|error| error.raw_os_error()),
            std::fs::read(&file)
                .map(|bytes| !bytes.is_empty())
                .map_err(|error| error.raw_os_error()),
        );
        let pending = (
            client.try_recv(),
            daemon.try_exited(),
            daemon.listed(),
            daemon.control().shutdown().report(),
        );
        drop(held);
        daemon.control().release_stall();
        let report = daemon.wait_report();
        let shutdown_registrations = daemon
            .control()
            .registration_requests_since(registration_window_start);
        let client_outcome = client.recv_timeout(HANG).ok();
        let daemon_outcome = daemon.exited();
        let head_advanced = daemon.control().head_seq() - seq_before;
        let publications = daemon.control().publications() - publications_before;
        let shutdown_request = stalled.map(|(occurrence, capture, request)| {
            (
                occurrence,
                capture > 0,
                request.is_some_and(|request| shutdown_registrations.contains(&request)),
                daemon.control().registrations()
                    == registration_window_start + shutdown_registrations.len(),
            )
        });
        assert_eq!(
            (
                latched,
                pending,
                shutdown_request,
                client_outcome,
                daemon_outcome,
                Some(report.outcome),
                publications,
                head_advanced,
            ),
            (
                (
                    Err(Some(libc::EROFS)),
                    Err(Some(libc::EROFS)),
                    Err(Some(libc::EROFS)),
                    Ok(true),
                ),
                (
                    Err(std::sync::mpsc::TryRecvError::Empty),
                    Err(std::sync::mpsc::TryRecvError::Empty),
                    true,
                    None,
                ),
                Some((1, true, true, true)),
                Some(MountOutcome::Clean),
                MountOutcome::Clean,
                Some(granary_client::ShutdownOutcome::Committed(seq_before + 1)),
                1,
                1,
            ),
            "profile={profile:?}: ((write, O_SYNC write, fsync, read), (client, daemon, listed, \
             report while stalled), (stall occurrence, capture, accepted during shutdown, no \
             registration after report), client outcome, daemon outcome, final report, \
             publications, head movement)"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[cfg(feature = "overlay-fault-tests")]
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "both profiles run the stalled, superseded and released authority arms against the real engine"
)]
fn daemon_linux_umount_bound_and_fence() {
    if !require_root("daemon_linux_umount_bound_and_fence") {
        return;
    }
    let mut cases = 0;
    for profile in [
        granary_client::SyncProfile::DurablePrepared,
        granary_client::SyncProfile::Published,
    ] {
        let daemon = Daemon::start_engine(profile, std::time::Duration::from_secs(1));
        let seq_before = daemon.control().head_seq();
        let publications_before = daemon.control().publications();
        let registrations_before = daemon.control().registrations();
        let held = daemon.dirty_writer("a", &[b'a'; 64]);
        for file in ["b", "c"] {
            std::fs::write(daemon.mountpoint.join(file), file.repeat(64)).unwrap();
        }
        let shutdown_premise = (
            daemon.control().head_seq() - seq_before,
            daemon.control().publications() - publications_before,
            daemon.control().registrations() - registrations_before,
            daemon.control().has_open_write_handles(),
        );
        assert_eq!(
            shutdown_premise,
            (0, 0, 0, Ok(true)),
            "profile={profile:?}: (head movement, publications, registrations, open writer) \
             before bounded shutdown"
        );
        daemon.control().stall_before_dispatch();
        let client = daemon.start_umount();
        daemon.wait_stalled();
        let shutdown_stall = daemon
            .control()
            .stalled_dispatch()
            .map(|(occurrence, capture, request)| (occurrence, capture > 0, request.is_some()));
        drop(held);
        let client_outcome = client.recv_timeout(HANG).ok();
        let report = daemon.wait_report();
        let kept = daemon.control().kept_state();
        let kept_observed = kept
            .as_ref()
            .map(|state| {
                (
                    state.journal_records > 0,
                    state.staging_files,
                    state.authority_intent,
                    state.local_intent,
                )
            })
            .map_err(String::as_str);
        daemon.control().release_stall();
        let daemon_outcome = daemon.exited();
        assert_eq!(
            (
                client_outcome,
                daemon_outcome,
                report.outcome,
                report.cut,
                report
                    .residue
                    .map(|counts| { (counts.files, counts.bytes > 0, counts.operations > 0) }),
                shutdown_stall,
                kept_observed,
            ),
            (
                Some(MountOutcome::Stopped),
                MountOutcome::Stopped,
                granary_client::ShutdownOutcome::Incomplete(
                    granary_client::ShutdownCause::Deadline,
                ),
                Some(granary_client::ShutdownCut::Bound),
                Some((3, true, true)),
                Some((1, true, true)),
                Ok((true, 3, true, true)),
            ),
            "profile={profile:?}: (client, daemon, outcome, cut, counts, shutdown registration, \
             kept state)"
        );
        cases += 1;

        let daemon = Daemon::start_engine(profile, std::time::Duration::from_secs(10));
        std::fs::write(daemon.mountpoint.join("fenced"), b"dirty").unwrap();
        daemon.control().supersede();
        let client = daemon.start_umount();
        let client_outcome = client.recv_timeout(HANG).ok();
        let daemon_outcome = daemon.exited();
        let report = daemon
            .control()
            .shutdown()
            .report()
            .map(|report| report.outcome);
        assert_eq!(
            (client_outcome, daemon_outcome, report),
            (
                Some(MountOutcome::Fenced),
                MountOutcome::Fenced,
                Some(granary_client::ShutdownOutcome::Fenced),
            ),
            "profile={profile:?}: superseded authority result"
        );
        cases += 1;

        let daemon = Daemon::start_engine(profile, std::time::Duration::from_secs(10));
        std::fs::write(daemon.mountpoint.join("released"), b"dirty").unwrap();
        let client = daemon.start_umount();
        let client_outcome = client.recv_timeout(HANG).ok();
        let daemon_outcome = daemon.exited();
        let report = daemon
            .control()
            .shutdown()
            .report()
            .map(|report| report.outcome);
        assert!(
            matches!(report, Some(granary_client::ShutdownOutcome::Committed(_))),
            "profile={profile:?}: released authority report={report:?}"
        );
        assert_eq!(
            (client_outcome, daemon_outcome),
            (Some(MountOutcome::Clean), MountOutcome::Clean),
            "profile={profile:?}: released authority result"
        );
        cases += 1;
    }
    assert_eq!(cases, 6);
}

#[cfg(feature = "overlay-fault-tests")]
#[test]
fn daemon_linux_umount_busy_descriptor() {
    if !require_root("daemon_linux_umount_busy_descriptor") {
        return;
    }
    let mut cases = 0;
    for profile in [
        granary_client::SyncProfile::DurablePrepared,
        granary_client::SyncProfile::Published,
    ] {
        for root in [true, false] {
            let daemon = Daemon::start_engine(profile, std::time::Duration::from_secs(10));
            let seq_before = daemon.control().head_seq();
            let publications_before = daemon.control().publications();
            let registrations_before = daemon.control().registrations();
            let dirty = daemon.dirty_writer("dirty", b"dirty");
            let holder_path = if root {
                daemon.mountpoint.clone()
            } else {
                daemon.mountpoint.join("f.txt")
            };
            let mut holder = BusyHolder::open(&holder_path, root);
            let shutdown_premise = (
                daemon.control().head_seq() - seq_before,
                daemon.control().publications() - publications_before,
                daemon.control().registrations() - registrations_before,
                daemon.control().has_open_write_handles(),
            );
            let client = daemon.start_umount();
            let report = daemon.wait_report();
            let committed_before_return = client.try_recv();
            drop(dirty);
            let client_outcome = client.recv_timeout(HANG).ok();
            let daemon_outcome = daemon.exited();
            let listed = daemon.listed();
            let connection_outlived_run = daemon.connection_outlived_run();
            let disconnected = holder.probe();
            // The listing reaches the dead connection and answers ENOTCONN. The
            // file read's errno depends on the kernel: a direct request answers
            // ENOTCONN, while a read through readahead leaves the page not
            // uptodate and reports EIO (Fedora 7.1 does the second, the CI
            // runner's Ubuntu kernel the first). Either is the dead connection.
            let file_errors = [
                format!("pread:{}", libc::ENOTCONN),
                format!("pread:{}", libc::EIO),
            ];
            let disconnected_expected = if root {
                Err(format!("getdents64:{}", libc::ENOTCONN))
            } else {
                match &disconnected {
                    Err(error) if file_errors.contains(error) => disconnected.clone(),
                    _ => Err(file_errors.join(" or ")),
                }
            };
            assert_eq!(
                (
                    shutdown_premise,
                    report.outcome,
                    daemon.control().head_seq() - seq_before,
                    daemon.control().publications() - publications_before,
                    committed_before_return,
                    client_outcome,
                    daemon_outcome,
                    listed,
                    connection_outlived_run,
                    disconnected,
                ),
                (
                    (0, 0, 0, Ok(true)),
                    granary_client::ShutdownOutcome::Committed(seq_before + 1),
                    1,
                    1,
                    Err(std::sync::mpsc::TryRecvError::Empty),
                    Some(MountOutcome::CacheCloseFailed),
                    MountOutcome::CacheCloseFailed,
                    false,
                    true,
                    disconnected_expected,
                ),
                "profile={profile:?}, root={root}: ((head movement, publications, registrations, \
                 open writer) before shutdown, shutdown, head movement, publications, \
                 client before grace, client final, daemon final, listed, connection outlived \
                 run, holder after daemon exit)"
            );
            drop(holder);
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

/// Exercise command routing on a real mount. The engine is a fake here;
/// this row makes no claim about authority dispatch or writable commits.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one finite matrix covers endpoint locking, absent reporting, moved targets and mixed mounts"
)]
fn daemon_linux_umount_identity_and_fallback() {
    if !require_root("daemon_linux_umount_identity_and_fallback") {
        return;
    }
    let mut cases = 0;
    let daemon = Daemon::start(committed(), false, std::time::Duration::ZERO, None);
    let rows = mount_table::control_mounts(&daemon.mountpoint).unwrap();
    assert_eq!(
        (
            rows.len(),
            rows.first().map(|row| row.owner),
            std::fs::metadata(&daemon.mountpoint).unwrap().uid()
        ),
        (1, Some(0), 12345)
    );
    let (send, _receive) = std::sync::mpsc::channel();
    let duplicate = control::Control::start(
        0,
        &daemon.mountpoint,
        granary_core::mount_control::Mode::ReadOnly,
        send,
    );
    assert_eq!(
        duplicate.err().unwrap().to_string(),
        "refusing: control endpoint is locked by another daemon"
    );
    assert_eq!(
        (
            cmd_umount_linux(&daemon.mountpoint, 0),
            daemon.exited(),
            daemon.stop_begins()
        ),
        (MountOutcome::Clean, MountOutcome::Clean, 1)
    );
    cases += 1;

    let daemon = Daemon::start(committed(), false, std::time::Duration::ZERO, None);
    let rows = mount_table::control_mounts(&daemon.mountpoint).unwrap();
    let [mount] = rows.as_slice() else {
        panic!("fixture mount rows={rows:?}");
    };
    std::fs::remove_file(control_fixture_path(&daemon.mountpoint, *mount, "sock")).unwrap();
    assert_eq!(
        (
            cmd_umount_linux(&daemon.mountpoint, 0),
            daemon.exited(),
            daemon.stop_begins(),
            daemon.listed()
        ),
        (
            MountOutcome::RuntimeFailure,
            MountOutcome::RuntimeFailure,
            0,
            false
        )
    );
    cases += 1;

    let mut daemon = Daemon::start(committed(), false, std::time::Duration::ZERO, None);
    let moved = daemon.scratch().0.with_extension("moved");
    std::fs::rename(&daemon.scratch().0, &moved).unwrap();
    daemon.scratch_mut().0 = moved;
    daemon.mountpoint = daemon.scratch().0.join("mnt");
    assert_eq!(
        (
            cmd_umount_linux(&daemon.mountpoint, 0),
            daemon.exited(),
            daemon.stop_begins(),
            daemon.listed()
        ),
        (
            MountOutcome::RuntimeFailure,
            MountOutcome::RuntimeFailure,
            0,
            false
        )
    );
    cases += 1;

    let daemon = Daemon::start(committed(), false, std::time::Duration::ZERO, None);
    assert!(
        std::process::Command::new("mount")
            .args(["-t", "tmpfs", "gran"])
            .arg(&daemon.mountpoint)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        (
            cmd_umount_linux(&daemon.mountpoint, 0),
            daemon.stop_begins(),
            granary_fuse::mountinfo_rows_at(
                &std::fs::read("/proc/self/mountinfo").unwrap(),
                &daemon.mountpoint
            )
            .unwrap()
            .len()
        ),
        (MountOutcome::RuntimeFailure, 0, 2)
    );
    assert!(
        std::process::Command::new("umount")
            .arg(&daemon.mountpoint)
            .status()
            .unwrap()
            .success()
    );
    daemon.signal();
    assert_eq!(daemon.exited(), MountOutcome::Clean);
    cases += 1;
    assert_eq!(cases, 4);
}

/// A signal runs the engine's shutdown, then the unmount, and the daemon
/// exits by its outcome: committed is 0, stopped at the bound 4, fenced 5.
/// The committed case's cache close outlasts the grace, so only the
/// teardown notice that `destroy` sends keeps the daemon waiting for its
/// session end; without it the daemon gives up and exits 3.
#[test]
fn daemon_linux_signal_then_unmount_exits_by_the_outcome() {
    if !require_root("daemon_linux_signal_then_unmount_exits_by_the_outcome") {
        return;
    }
    let mut rows = Vec::new();
    for (answer, close_delay) in [
        (
            committed(),
            SESSION_END_GRACE + std::time::Duration::from_secs(1),
        ),
        (
            report_of(O::Incomplete(C::Deadline)),
            std::time::Duration::ZERO,
        ),
        (report_of(O::Fenced), std::time::Duration::ZERO),
    ] {
        let daemon = Daemon::start(answer, false, close_delay, None);
        daemon.signal();
        let outcome = daemon.exited();
        rows.push((
            answer.outcome,
            daemon.stop_begins(),
            outcome,
            daemon.listed(),
        ));
    }
    assert_eq!(
        rows,
        vec![
            (committed().outcome, 1, MountOutcome::Clean, false),
            (O::Incomplete(C::Deadline), 1, MountOutcome::Stopped, false),
            (O::Fenced, 1, MountOutcome::Fenced, false),
        ],
        "(answer, begins, exit, listed after)"
    );
}

/// An operator's fusectl abort with the root directory held open: the
/// kernel ends the session, `destroy` runs, but fuser's own drop-unmount
/// cannot remove the busy dead mount, so the row stays and the end is never
/// clean: exit 1. With nothing held the drop-unmount removes the row
/// before the join, the end is clean, and the daemon exits by the engine's
/// report.
#[test]
fn daemon_linux_fusectl_abort_with_a_held_descriptor_is_survived() {
    if !require_root("daemon_linux_fusectl_abort_with_a_held_descriptor_is_survived") {
        return;
    }
    let mut rows = Vec::new();
    for held in [true, false] {
        let daemon = Daemon::start(committed(), true, std::time::Duration::ZERO, None);
        let holder = held.then(|| daemon.open_root());
        std::fs::write(daemon.connection().join("abort"), b"1").unwrap();
        let outcome = daemon.exited();
        let listed = daemon.listed();
        drop(holder);
        if listed {
            let _ = granary_fuse::detach_unmount(&daemon.mountpoint);
        }
        rows.push((held, outcome, listed));
    }
    assert_eq!(
        rows,
        vec![
            (true, MountOutcome::RuntimeFailure, true),
            (false, MountOutcome::Clean, false),
        ],
        "(held, exit, the dead row listed after the join)"
    );
}

/// A lazy detach with the root directory held, then a signal: the shutdown
/// runs, then the daemon's unmount and detach both fail, the mount being
/// already out of the table. The descriptor is closed inside the grace, so
/// the session ends and is joined, and with the row gone the end is clean
/// however the unmount answered: exit 0.
#[test]
fn daemon_linux_lazy_detach_then_signal_is_clean() {
    if !require_root("daemon_linux_lazy_detach_then_signal_is_clean") {
        return;
    }
    let daemon = Daemon::start(committed(), false, std::time::Duration::ZERO, None);
    let holder = daemon.open_root();
    granary_fuse::detach_unmount(&daemon.mountpoint).unwrap();
    let detached = !daemon.listed();
    daemon.signal();
    pause(std::time::Duration::from_millis(500));
    drop(holder);
    assert_eq!(
        (detached, daemon.exited()),
        (true, MountOutcome::Clean),
        "(the row gone after the detach, exit)"
    );
}

/// The root directory held open as root: the signal's shutdown commits, the
/// unmount answers `EBUSY`, the detach takes the mount out of the table,
/// and no session end comes within the grace. The daemon exits with the
/// committed outcome it already holds and the cache close that never ran:
/// exit 3. The row's own cleanup aborts the connection.
#[test]
fn daemon_linux_busy_root_unmount_detaches_and_exits_three() {
    if !require_root("daemon_linux_busy_root_unmount_detaches_and_exits_three") {
        return;
    }
    let daemon = Daemon::start(committed(), false, std::time::Duration::ZERO, None);
    let holder = daemon.open_root();
    let connection = daemon.connection();
    daemon.signal();
    let outcome = daemon.exited();
    let listed = daemon.listed();
    let _ = std::fs::write(connection.join("abort"), b"1");
    drop(holder);
    assert_eq!(
        (outcome, listed),
        (MountOutcome::CacheCloseFailed, false),
        "(exit, listed after)"
    );
}

/// A private namespace copy holds the kernel session open after the daemon
/// unmounts it from its own namespace.
#[test]
fn daemon_linux_namespace_copy_outlives_the_unmount_and_exits_three() {
    if !require_root("daemon_linux_namespace_copy_outlives_the_unmount_and_exits_three") {
        return;
    }
    let mut rows = Vec::new();
    for copied in [false, true] {
        let ((outcome, listed, connection_alive), records) = emitted_records(|| {
            let daemon = Daemon::start(committed(), false, std::time::Duration::ZERO, None);
            let connection = daemon.connection();
            let before = connection.try_exists();
            assert!(
                matches!(before, Ok(true)),
                "the live mount's fusectl connection at {connection:?}: {before:?}"
            );
            let copy = copied.then(|| {
                let mut child = OwnedChild(
                    std::process::Command::new("unshare")
                        .args(["--mount", "--propagation", "private", "sleep", "30"])
                        .spawn()
                        .unwrap(),
                );
                // unshare execs sleep only after cloning and privatizing the mount namespace.
                let comm = format!("/proc/{}/comm", child.0.id());
                let started = std::time::Instant::now();
                while started.elapsed() < HANG {
                    if std::fs::read(&comm)
                        .as_deref()
                        .is_ok_and(|name| name == b"sleep\n")
                    {
                        return child;
                    }
                    assert_eq!(
                        child.0.try_wait().unwrap(),
                        None,
                        "unshare exited before sleep"
                    );
                    pause(std::time::Duration::from_millis(10));
                }
                panic!(
                    "unshare did not exec sleep: {:?}",
                    std::fs::read_to_string(comm)
                );
            });
            daemon.signal();
            let outcome = daemon.exited();
            let listed = daemon.listed();
            let connection_alive = connection.try_exists();
            if copy.is_some() {
                let _ = std::fs::write(connection.join("abort"), b"1");
            }
            drop(copy);
            (outcome, listed, connection_alive.unwrap())
        });
        let warnings: Vec<_> = records
            .into_iter()
            .filter(|line| line.contains(NOT_JOINED_EVENT))
            .collect();
        rows.push((copied, outcome, listed, connection_alive, warnings));
    }
    assert_eq!(
        rows,
        vec![
            (false, MountOutcome::Clean, false, false, vec![]),
            (
                true,
                MountOutcome::CacheCloseFailed,
                false,
                true,
                vec![not_joined_record("gone", "alive")],
            ),
        ],
        "(copied, exit, listed after, connection alive after, session warning)"
    );
}

/// Twenty mounts, each closing twenty handles and then taking a signal:
/// every one exits 0, a teardown race included.
#[test]
fn daemon_linux_closing_handles_before_a_signal_never_exits_one() {
    if !require_root("daemon_linux_closing_handles_before_a_signal_never_exits_one") {
        return;
    }
    let mut outcomes = Vec::new();
    for _ in 0..20 {
        let daemon = Daemon::start(committed(), false, std::time::Duration::ZERO, None);
        for _ in 0..20 {
            drop(daemon.open_root());
        }
        daemon.signal();
        outcomes.push(daemon.exited());
    }
    assert_eq!(outcomes, vec![MountOutcome::Clean; 20]);
}
