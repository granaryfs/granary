// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Paired common-start admission, with checked wire replies and durable local state.

mod abort;
mod cleanup_wait;
mod commit_lane;
#[cfg(target_os = "linux")]
mod mounted;
mod observed;
mod queries;
#[cfg(target_os = "linux")]
mod session_guard;
use super::*;
use crate::writable_start::{WritableAuthority, WritableStart, WritableStartError, start_with};
use crate::{IntentReply, IntentTransportError, OverlayDisk, PendingIntent};
use granary_core::{
    intent::{self, Receipt, ReceiptState},
    overlay_ownership::Operation,
    retained_submission::Scope,
};
#[cfg(target_os = "linux")]
use granary_fuse::{BackgroundMount as BackgroundSession, detach_unmount};
#[cfg(target_os = "linux")]
use session_guard::SessionGuard;
use std::collections::BTreeMap;
use std::io;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::sync::Mutex;

#[derive(Debug, Clone, Default)]
struct Events(Arc<Mutex<Vec<u8>>>);
impl io::Write for Events {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Events {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}
impl Events {
    fn subscriber(&self) -> Box<dyn tracing::Subscriber + Send + Sync> {
        self.formatted(crate::LogFormat::Json)
    }
    fn formatted(&self, format: crate::LogFormat) -> Box<dyn tracing::Subscriber + Send + Sync> {
        crate::subscriber(
            format,
            tracing_subscriber::EnvFilter::new("trace"),
            self.clone(),
        )
    }
    fn failed(&self, class: &str) -> bool {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .any(|line| {
                line.contains("\"event\":\"op.failed\"")
                    && line.contains("\"kind\":\"session\"")
                    && line.contains(&format!("\"class\":\"{class}\""))
                    && line.contains("\"level\":\"ERROR\"")
            })
    }
    fn commit_stopped(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|line| line.contains("\"event\":\"commit.stopped\""))
            .map(str::to_owned)
            .collect()
    }
}

#[test]
fn writable_fixture_keys_survive_sticky_store_scratch() {
    let tree = PublishedTree::publish("v");
    let parent = Paths::new();
    let sticky = parent.scratch.join("sticky-temp");
    std::fs::create_dir(&sticky).unwrap();
    std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).unwrap();
    let paths = Paths::with_store_base(&sticky);
    let input = input(&tree, &paths);
    provision(&input, &tree, "valid");
    let loaded = crate::writable_start::load_local(&input);
    assert!(
        loaded.is_ok(),
        "private key scratch must survive sticky store ancestors: {:?}",
        loaded.err()
    );
    assert_eq!(
        (
            paths.seed.metadata().unwrap().mode() & 0o777,
            paths.seed.metadata().unwrap().uid()
        ),
        (0o600, input.euid)
    );
    let unsafe_seed = paths.scratch.join("unsafe-seed");
    std::fs::write(&unsafe_seed, tree.seed).unwrap();
    std::fs::set_permissions(&unsafe_seed, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut bad = input;
    bad.seed = Some(&unsafe_seed);
    let error = crate::writable_start::load_local(&bad).err().unwrap();
    assert_eq!(error.name(), "WritableKeyInputRefused");
    assert!(
        crate::signing_seed_paths(&unsafe_seed, bad.euid)
            .err()
            .unwrap()
            .contains("unsafe seed ancestor")
    );
}

#[test]
fn writable_fixture_key_custody_controls() {
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let initial = input(&tree, &paths);
    provision(&initial, &tree, "valid");
    assert!(crate::writable_start::load_local(&initial).is_ok());
    for path in [&paths.seed, &paths.credential_key] {
        assert_eq!(
            (
                path.metadata().unwrap().uid(),
                path.metadata().unwrap().mode() & 0o777
            ),
            (initial.euid, 0o600)
        );
    }
    assert!(
        crate::signing_seed_paths(&paths.seed, initial.euid + 1)
            .err()
            .unwrap()
            .contains("unsafe seed ancestor")
    );
    let mut cases = 0;
    for mode in [0o777, 0o1777] {
        let parent = paths.scratch.join(format!("temp-{mode:o}"));
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(mode)).unwrap();
        let alias = paths.scratch.join(format!("temp-alias-{mode:o}"));
        std::os::unix::fs::symlink(&parent, &alias).unwrap();
        let relocated = Paths::with_store_base(&alias);
        assert!(
            relocated
                .scratch
                .starts_with(parent.canonicalize().unwrap())
        );
        let valid = input(&tree, &relocated);
        provision(&valid, &tree, "valid");
        assert!(crate::writable_start::load_local(&valid).is_ok());
        let unsafe_seed = relocated.scratch.join("seed");
        std::fs::write(&unsafe_seed, tree.seed).unwrap();
        std::fs::set_permissions(&unsafe_seed, std::fs::Permissions::from_mode(0o600)).unwrap();
        let bad = WritableStart {
            seed: Some(&unsafe_seed),
            ..valid
        };
        assert_eq!(
            crate::writable_start::load_local(&bad)
                .err()
                .unwrap()
                .name(),
            "WritableKeyInputRefused"
        );
        cases += 1;
    }
    std::fs::set_permissions(&paths.seed, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        crate::writable_start::load_local(&initial)
            .err()
            .unwrap()
            .name(),
        "WritableKeyInputRefused"
    );
    assert_eq!(cases, 2);
}

fn provision(input: &WritableStart<'_>, tree: &PublishedTree, rule: &str) {
    if let Some(seed) = input.seed {
        let bytes = if rule == "key_mismatch" {
            vec![0x41; 32]
        } else if rule == "key_input" {
            vec![0x41; 33]
        } else {
            tree.seed.to_vec()
        };
        std::fs::write(seed, bytes).unwrap();
        std::fs::set_permissions(seed, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    if let (Some(cert), Some(key)) = (input.certificate, input.credential_key) {
        let pair = rcgen::generate_simple_self_signed(vec!["fixture.invalid".to_owned()]).unwrap();
        std::fs::write(cert, pair.cert.pem()).unwrap();
        std::fs::write(
            key,
            if rule == "credential_input" {
                "synthetic-invalid-key".to_owned()
            } else {
                pair.signing_key.serialize_pem()
            },
        )
        .unwrap();
        std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
type Attempt = (
    Result<crate::WritableReadiness<Authority, OverlayDisk>, WritableStartError>,
    Arc<Mutex<AuthorityState>>,
    u64,
);

fn start_job(
    job: Box<dyn granary_fuse::MountSyncJob>,
) -> tokio::sync::oneshot::Receiver<Result<(), granary_fuse::MountSyncError>> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    job.start(Box::new(move |result| {
        let _ = sender.send(result);
    }));
    receiver
}

fn attempt(
    input: &WritableStart<'_>,
    tree: &PublishedTree,
    rule: &'static str,
    events: &Events,
) -> Attempt {
    let state = Arc::new(Mutex::new(AuthorityState::default()));
    let authority = Authority::with_scope_and_rule(tree, input.scope.clone(), &state, rule);
    let authority = if rule == "sync_publish" {
        authority.with_publication()
    } else {
        authority
    };
    provision(input, tree, rule);
    let mut loads = 0;
    let result = tracing::subscriber::with_default(events.subscriber(), || {
        start_with(
            input,
            true,
            || {
                loads += 1;
                let (key, spare, _credential) = crate::writable_start::load_local(input)?;
                Ok((key, spare, authority))
            },
            |store: &Store| OverlayDisk::new(store.publication_root(), input.euid),
            &mut Entropy(20),
            &Time(Arc::clone(&state)),
            &mut granary_core::rng::SeededRng::new(1),
            &mut Vec::new(),
        )
    });
    (result, state, loads)
}
fn successful_control(tree: &PublishedTree) {
    let paths = Paths::new();
    let input = input(tree, &paths);
    let (result, state, loads) = attempt(&input, tree, "valid", &Events::default());
    let proof =
        result.unwrap_or_else(|error| panic!("successful writable control refused: {error}"));
    assert_eq!(proof.verified_base().1, tree.seq);
    assert_eq!(proof.owner().1, 1);
    let attached = proof.attach();
    let flags = format!("{:?}", attached.config.mount_options);
    assert!(flags.starts_with(
        "[RW, NoSuid, NoDev, DefaultPermissions, FSName(\"gran\"), Subtype(\"gran\")]"
    ));
    assert_eq!(
        (attached.config.n_threads, attached.config.clone_fd),
        (Some(1), false)
    );
    assert_eq!((loads, state.lock().unwrap().calls), (1, [1, 2, 2, 0]));
}
#[test]
fn writable_start_posture_pairs_preserve_refusal_precedence() {
    let mut tree = PublishedTree::publish("v");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let parent = runtime
        .block_on(tree.remote.get_root("v", 1))
        .unwrap()
        .unwrap();
    let mut doc = root::decode_root(&parent).unwrap();
    doc.seq = 2;
    doc.parent = Some(GrainId::of(&parent));
    doc.sigs.clear();
    let prefix = root::signing_prefix_of(&doc).unwrap();
    doc.sigs.push(RootSig {
        key_id: tree.key.key_id(),
        sig: tree.key.sign(&prefix),
    });
    runtime
        .block_on(
            tree.remote
                .put_root("v", 2, root::encode_root(&doc).unwrap()),
        )
        .unwrap();
    runtime.block_on(tree.remote.write_hint("v", 2)).unwrap();
    tree.seq = 2;
    let mut cases = 0;
    for (rule, reason) in [
        ("none", "NoTrustMode"),
        ("conflict", "ConflictingTrustModes"),
        ("server", "WritableTrustServerRefused"),
        ("manifest", "WritableManifestRootRefused"),
        ("other", "WritableAllowOtherRefused"),
        ("root", "WritableAllowRootRefused"),
        ("seq_current", "WritableSeqRefused"),
        ("seq_old", "WritableSeqRefused"),
    ] {
        successful_control(&tree);
        let paths = Paths::new();
        let mut input = input(&tree, &paths);
        match rule {
            "none" => input.root_key = None,
            "conflict" => input.trust_server = true,
            "server" => {
                input.root_key = None;
                input.trust_server = true;
                input.options.allow_other = true;
            }
            "manifest" => {
                input.root_key = None;
                input.manifest_root = Some(tree.manifest_root);
            }
            "other" => {
                input.options.allow_other = true;
                input.options.allow_root = true;
            }
            "root" => input.options.allow_root = true,
            "seq_current" => input.seq = Some(tree.seq),
            "seq_old" => input.seq = Some(1),
            _ => unreachable!(),
        }
        let events = Events::default();
        let (result, state, loads) = attempt(&input, &tree, "valid", &events);
        let Err(error) = result else {
            panic!("writable posture refusal and event: refusal missing");
        };
        assert_eq!(
            (
                error.name(),
                events.failed("refused"),
                loads,
                state.lock().unwrap().calls,
                paths.store.exists()
            ),
            (reason, true, 0, [0; 4], false),
            "writable posture refusal and event"
        );
        cases += 1;
    }
    assert_eq!(cases, 8);
}
#[test]
fn writable_start_local_input_pairs_and_signer_equality() {
    let tree = PublishedTree::publish("v");
    let mut cases = 0;
    for (rule, reason, loads) in [
        ("seed", "WritableSigningKeyRequired", 0),
        ("credentials", "WritableCredentialsRequired", 0),
        ("store", "WritableStoreRequired", 0),
        ("cache", "CacheDirRequired", 0),
        ("key_mismatch", "WritableKeyMismatch", 1),
        ("key_input", "WritableKeyInputRefused", 1),
        ("credential_input", "WritableCredentialInputRefused", 1),
    ] {
        successful_control(&tree);
        let paths = Paths::new();
        let mut input = input(&tree, &paths);
        match rule {
            "seed" => input.seed = None,
            "credentials" => input.scope = None,
            "store" => input.store = None,
            "cache" => input.cache = None,
            _ => (),
        }
        let events = Events::default();
        let (result, state, observed_loads) = attempt(&input, &tree, rule, &events);
        let Err(error) = result else {
            panic!("signer binding refusal and event: refusal missing");
        };
        assert_eq!(
            (
                error.name(),
                events.failed("refused"),
                observed_loads,
                state.lock().unwrap().calls
            ),
            (reason, true, loads, [0; 4]),
            "signer binding refusal and event"
        );
        cases += 1;
    }
    assert_eq!(cases, 7);
}
#[test]
fn writable_start_authority_intent_and_no_head_pairs() {
    let tree = PublishedTree::publish("v");
    let mut cases = 0;
    for (rule, reason, class, calls) in [
        (
            "unknown_target",
            "WritableAuthorityRequired",
            "refused",
            [1, 0, 0, 0],
        ),
        (
            "unknown_volume",
            "WritableVolumeUnserved",
            "refused",
            [1, 0, 0, 0],
        ),
        (
            "no_log",
            "WritableAuthorityUninitialised",
            "refused",
            [1, 0, 0, 0],
        ),
        (
            "status_unavailable",
            "WritableAuthorityUnavailable",
            "unavailable",
            [1, 0, 0, 0],
        ),
        (
            "status_invalid",
            "WritableDiscoveryInvalid",
            "corrupt",
            [1, 0, 0, 0],
        ),
        (
            "family_missing",
            "WritableIntentResourcesMissing",
            "refused",
            [1, 1, 0, 0],
        ),
        (
            "family_volume",
            "WritableVolumeUnserved",
            "refused",
            [1, 1, 0, 0],
        ),
        (
            "family_access",
            "WritableIntentAccessRefused",
            "refused",
            [1, 1, 0, 0],
        ),
        (
            "family_invalid",
            "WritableIntentDiscoveryInvalid",
            "corrupt",
            [1, 1, 0, 0],
        ),
        (
            "family_unavailable",
            "WritableIntentUnavailable",
            "unavailable",
            [1, 1, 0, 0],
        ),
        ("no_head", "NoHead", "refused", [1, 1, 0, 0]),
        (
            "acquire_missing",
            "IntentNotImplemented",
            "refused",
            [1, 2, 1, 0],
        ),
        (
            "register_missing",
            "IntentNotImplemented",
            "refused",
            [1, 2, 2, 0],
        ),
    ] {
        successful_control(&tree);
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let events = Events::default();
        let (result, state, loads) = attempt(&input, &tree, rule, &events);
        let Err(error) = result else {
            panic!("authority admission refusal missing");
        };
        assert_eq!(
            (
                error.name(),
                events.failed(class),
                loads,
                state.lock().unwrap().calls
            ),
            (reason, true, 1, calls),
            "authority refusal and event"
        );
        cases += 1;
    }
    assert_eq!(cases, 13);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "literal read-only compatibility matrix and attribute tuples"
)]
fn read_only_trust_matrix_keeps_modes_floors_and_zero_writable_calls() {
    use granary_core::manifest::{EntryKind, Name, SymlinkTarget};
    let tree = PublishedTree::publish_nested("v");
    let mut cases = 0;
    for mode in ["root", "server", "manifest"] {
        for sharing in ["owner", "other", "root"] {
            let paths = Paths::new();
            let input = input(&tree, &paths);
            let state = Arc::new(Mutex::new(AuthorityState::default()));
            let authority =
                Authority::with_scope_and_rule(&tree, input.scope.clone(), &state, "valid");
            let options = MountOptions {
                allow_other: sharing == "other",
                allow_root: sharing == "root",
            };
            let result = MountSession::open(
                authority,
                tree.volume.clone(),
                (mode == "root").then(|| Box::new(*tree.key.public_key())),
                (mode == "manifest").then_some(tree.manifest_root),
                mode == "server",
                Some(1),
                &paths.cache,
                input.cache_quota,
                &input.cache_origin,
                options,
                &mut Vec::new(),
            );
            if mode != "root" && sharing != "owner" {
                assert!(
                    matches!(result, Err(MountError::MachineWideRequiresRootKey { .. })),
                    "keyless read-only sharing refusal"
                );
            } else {
                let mut session = result.unwrap();
                let snapshot = session
                    .snapshot(granary_vfs::AttrPolicy { uid: 417, gid: 418 })
                    .unwrap();
                let ordinary = snapshot.lookup(&tree.manifest_root, b"f.txt").unwrap();
                let mut executable = ordinary.clone();
                if let EntryKind::File { exec, .. } = &mut executable.kind {
                    *exec = true;
                }
                let directory = granary_vfs::Entry {
                    name: Name::new(b"dir".to_vec()).unwrap(),
                    kind: EntryKind::Dir {
                        child: tree.manifest_root,
                    },
                    leaf: tree.manifest_root,
                };
                let symlink = granary_vfs::Entry {
                    name: Name::new(b"link".to_vec()).unwrap(),
                    kind: EntryKind::Symlink {
                        target: SymlinkTarget::new(b"f.txt".to_vec()).unwrap(),
                    },
                    leaf: tree.manifest_root,
                };
                for (entry, perm) in [
                    (&ordinary, 0o444),
                    (&executable, 0o555),
                    (&directory, 0o555),
                    (&symlink, 0o777),
                ] {
                    let attr = snapshot.attr_for(entry, 5, 7).unwrap();
                    assert_eq!(
                        (attr.perm, attr.uid, attr.gid, attr.generation, attr.time),
                        (perm, 417, 418, 7, snapshot.timestamp()),
                        "unchanged read-only attribute tuple"
                    );
                }
                let config = granary_fuse::session_config(options.allow_other);
                assert!(format!("{:?}", config.mount_options).starts_with(
                    "[RO, NoSuid, NoDev, DefaultPermissions, FSName(\"gran\"), Subtype(\"gran\")]"
                ));
                assert_eq!((config.n_threads, config.clone_fd), (Some(1), false));
                assert_eq!(
                    format!("{:?}", config.acl),
                    if options.allow_other { "All" } else { "Owner" }
                );
                granary_fuse::MountBackend::shutdown(&mut session).unwrap();
                assert_eq!(
                    paths.cache.join("anchors/v.mount").exists(),
                    mode != "manifest",
                    "manifest-root does not read or persist floors"
                );
            }
            assert_eq!(
                state.lock().unwrap().calls,
                [0; 4],
                "read-only never enters any writable seam"
            );
            cases += 1;
        }
        // Signature and content-pin failures remain discriminating in their respective modes.
        let paths = Paths::new();
        let mut sink = Vec::new();
        let result = MountSession::open(
            remote_handle(&tree.mem),
            tree.volume.clone(),
            (mode == "root")
                .then(|| Box::new(*SigningKey::from_seed(&[0x51; 32]).unwrap().public_key())),
            (mode == "manifest").then_some(GrainId::of(b"wrong-manifest")),
            mode == "server",
            None,
            &paths.cache,
            268_435_456,
            &origin(),
            MountOptions::default(),
            &mut sink,
        );
        assert_eq!(
            result.is_err(),
            mode != "server",
            "read-only signature/content-pin trust matrix"
        );
        cases += 1;
    }
    assert_eq!(cases, 12);
}

#[test]
fn writable_start_retries_retained_bytes_and_transfers_reopened_ownership() {
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let events = Events::default();
    let (result, state, loads) = attempt(&input, &tree, "lost_grant", &events);
    let proof = result.unwrap_or_else(|error| panic!("retained acquire retry refused: {error}"));
    assert_eq!(loads, 1);
    assert_eq!(state.lock().unwrap().calls, [1, 2, 3, 0]);
    {
        let state = state.lock().unwrap();
        assert!(
            state.sends[0].iter().eq(&state.sends[1]),
            "unknown grant retries exact bytes"
        );
    }
    let owner = proof.owner();
    drop(proof);
    let authority = Authority::with_scope_and_rule(&tree, input.scope.clone(), &state, "valid");
    let result = start_with(
        &input,
        true,
        || {
            Ok((
                SigningKey::from_seed(&tree.seed).unwrap(),
                SigningKey::from_seed(&tree.seed).unwrap(),
                authority,
            ))
        },
        |store: &Store| OverlayDisk::new(store.publication_root(), input.euid),
        &mut Entropy(30),
        &Time(Arc::clone(&state)),
        &mut granary_core::rng::SeededRng::new(1),
        &mut Vec::new(),
    );
    let resumed = result
        .unwrap_or_else(|error| panic!("base-only registration must allow succession: {error}"));
    let row = state.lock().unwrap().row.unwrap();
    assert_eq!(row.writer, owner.0);
    assert!(
        row.epoch > owner.1 && row.instance != owner.2,
        "reopen must transfer to a fresh instance before registration"
    );
    assert_eq!(resumed.owner(), (row.writer, row.epoch, row.instance));
    assert_eq!(state.lock().unwrap().calls[3], 0);
}

#[cfg(target_os = "linux")]
#[test]
fn writable_linux_ready_intent_mount_is_rw_and_ordinary_write_open_succeeds() {
    if !Path::new("/dev/fuse").exists() {
        eprintln!(
            "SKIPPED-NO-DEV-FUSE writable_linux_ready_intent_mount_is_rw_and_ordinary_write_open_succeeds"
        );
        return;
    }
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, state, _) = attempt(&input, &tree, "valid", &Events::default());
    let proof = result.unwrap_or_else(|error| panic!("ready-intent start refused: {error}"));
    assert!(
        state
            .lock()
            .unwrap()
            .row
            .is_some_and(|row| matches!(row.state, ReceiptState::Live { .. }))
    );
    let mountpoint = paths.mountpoint.clone();
    let mounted = proof
        .attach()
        .mount(1)
        .unwrap_or_else(|error| panic!("RW attach refused: {error}"));
    let mut mounted = SessionGuard::new(mounted, &mountpoint);
    let content = std::fs::read(mountpoint.join("f.txt"));
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    let row = mountinfo
        .lines()
        .find(|line| line.split_whitespace().nth(4) == mountpoint.to_str())
        .unwrap();
    let flags: Vec<_> = row.split_whitespace().nth(5).unwrap().split(',').collect();
    let writable = flags.contains(&"rw")
        && flags.contains(&"nosuid")
        && flags.contains(&"nodev")
        && !flags.contains(&"ro");
    let write = std::fs::OpenOptions::new()
        .write(true)
        .open(mountpoint.join("f.txt"))
        .map(drop);
    mounted.finish().unwrap();
    assert_eq!(content.unwrap(), FILE_CONTENT);
    assert!(writable, "kernel mount row must be RW, nosuid and nodev");
    assert!(
        write.is_ok(),
        "admitted ordinary write-open must succeed: {write:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn writable_linux_attach_failure_is_named_and_retains_owned_intent() {
    let tree = PublishedTree::publish("v");
    successful_control(&tree);
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let events = Events::default();
    let (result, state, _) = attempt(&input, &tree, "valid", &events);
    let attached = result
        .unwrap_or_else(|error| panic!("ready control refused: {error}"))
        .attach();
    std::fs::remove_dir(&paths.mountpoint).unwrap();
    let result = tracing::subscriber::with_default(events.subscriber(), || attached.mount(1));
    let Err(error) = result else {
        panic!("missing mountpoint attached");
    };
    assert_eq!(
        (error.name(), events.failed("io")),
        ("WritableMountAttachFailed", true)
    );
    assert_eq!(
        state.lock().unwrap().calls,
        [1, 2, 2, 0],
        "attachment refusal never releases or uploads"
    );
    assert!(
        state
            .lock()
            .unwrap()
            .row
            .is_some_and(|row| matches!(row.state, ReceiptState::Live { .. }))
    );
    assert!(
        paths.store.join("overlay").exists(),
        "retained evidence stays on disk"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "capture four actual common starts and provision typed support-export inputs"
)]
fn writable_start_output_captures() {
    let tree = PublishedTree::publish("v");
    let material = Paths::new();
    let initial = input(&tree, &material);
    provision(&initial, &tree, "valid");
    let tls = std::fs::read(&material.credential_key).unwrap();
    let certificate = std::fs::read(&material.certificate).unwrap();
    let mut captures = BTreeMap::<&str, Vec<u8>>::new();
    let mut cases = 0;
    for (format, surface) in [
        (crate::LogFormat::Text, "text"),
        (crate::LogFormat::Json, "json"),
    ] {
        for accepted in [true, false] {
            let paths = Paths::new();
            let mut input = input(&tree, &paths);
            std::fs::write(&paths.seed, tree.seed).unwrap();
            std::fs::set_permissions(&paths.seed, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::write(&paths.certificate, &certificate).unwrap();
            std::fs::write(&paths.credential_key, &tls).unwrap();
            std::fs::set_permissions(
                &paths.credential_key,
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            if !accepted {
                input.root_key = Some(*SigningKey::from_seed(&[0x41; 32]).unwrap().public_key());
            }
            let events = Events::default();
            let state = Arc::new(Mutex::new(AuthorityState::default()));
            let authority =
                Authority::with_scope_and_rule(&tree, input.scope.clone(), &state, "valid");
            let mut diagnostics = Vec::new();
            let result = tracing::subscriber::with_default(events.formatted(format), || {
                start_with(
                    &input,
                    true,
                    || {
                        let (key, spare, _credential) = crate::writable_start::load_local(&input)?;
                        Ok((key, spare, authority))
                    },
                    |store: &Store| OverlayDisk::new(store.publication_root(), input.euid),
                    &mut Entropy(20),
                    &Time(Arc::clone(&state)),
                    &mut granary_core::rng::SeededRng::new(1),
                    &mut diagnostics,
                )
            });
            match result {
                Ok(proof) => {
                    assert!(accepted);
                    drop(proof.attach());
                    captures.entry("stdout").or_default().extend_from_slice(
                        b"writable admission accepted; attachment configuration consumed\n",
                    );
                }
                Err(error) => {
                    assert!(!accepted);
                    assert_eq!(error.name(), "WritableKeyMismatch");
                    writeln!(&mut diagnostics, "{error}").unwrap();
                    captures
                        .entry("stdout")
                        .or_default()
                        .extend_from_slice(b"writable admission refused\n");
                }
            }
            captures.entry("stderr").or_default().extend(diagnostics);
            captures
                .entry(surface)
                .or_default()
                .extend(events.0.lock().unwrap().clone());
            assert_eq!(
                state.lock().unwrap().calls,
                if accepted { [1, 2, 2, 0] } else { [0; 4] }
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
    assert!(captures.values().all(|capture| !capture.is_empty()));
    let Some(destination) = std::env::var_os("GRAN_WRITABLE_CAPTURE_DIR") else {
        return;
    };
    let destination = Path::new(&destination);
    for (name, bytes) in captures {
        // Captures contain the real startup records. Remove host path spellings
        // before persistence; keys and event fields are not transformed.
        let mut capture = String::from_utf8(bytes).unwrap();
        for path in [
            std::env::current_dir().unwrap(),
            std::env::temp_dir(),
            std::env::temp_dir().canonicalize().unwrap(),
        ] {
            capture = capture.replace(path.to_str().unwrap(), "<local>");
        }
        std::fs::write(destination.join(name), capture).unwrap();
    }
    std::fs::write(destination.join("seed"), tree.seed).unwrap();
    std::fs::write(destination.join("tls-key"), &tls).unwrap();
    let support = destination.join("support");
    let state = destination.join("state");
    for directory in [&support, &state] {
        std::fs::create_dir(directory).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let vector = |name: &str| {
        include_str!("../../../../granary-core/tests/vectors/support_v1.tsv")
            .lines()
            .find(|line| line.split('\t').next() == Some(name))
            .unwrap()
            .split('\t')
            .nth(1)
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|hex| u8::from_str_radix(std::str::from_utf8(hex).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    let snapshot = granary_core::support::SupportSnapshot::decode(&vector("snapshot")).unwrap();
    let mut configuration =
        granary_core::support::SupportConfiguration::decode(&vector("configuration")).unwrap();
    configuration.volumes = snapshot
        .volumes
        .keys()
        .map(|volume| (volume.clone(), 1))
        .collect();
    for (name, bytes) in [
        ("SUPPORT-SNAPSHOT", snapshot.encode().unwrap()),
        ("SUPPORT-CONFIGURATION", configuration.encode().unwrap()),
    ] {
        std::fs::write(support.join(name), bytes).unwrap();
        std::fs::set_permissions(support.join(name), std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    for name in ["seed", "tls-key", "stdout", "stderr", "text", "json"] {
        std::fs::copy(destination.join(name), support.join(name)).unwrap();
        std::fs::set_permissions(support.join(name), std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }
}

/// A dirty replay is finished before readiness; a publication still in
/// doubt beside a clean journal refuses after the succession and before a
/// new registration.
#[test]
fn writable_start_retains_dirty_replay_and_unfinished_publication() {
    let tree = PublishedTree::publish("v");
    let mut cases = 0;
    // The finished arm publishes, so it runs after the control's last use.
    for publication in [true, false] {
        successful_control(&tree);
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let events = Events::default();
        let (result, state, _) = attempt(&input, &tree, "valid", &events);
        let mut proof = result.unwrap_or_else(|error| panic!("ready control refused: {error}"));
        if publication {
            let fixture = include_bytes!(
                "../../../../granary-core/tests/vectors/retained-submission/ready.bin"
            );
            let mut submission = granary_core::retained_submission::decode(fixture).unwrap();
            submission.scope = input.scope.clone().unwrap();
            submission.volume = input.volume.clone();
            for candidate in &mut submission.candidates {
                let mut doc = root::decode_root(&candidate.root).unwrap();
                doc.volume = input.volume.clone();
                candidate.root = root::encode_root(&doc).unwrap();
                candidate.id = GrainId::of(&candidate.root);
            }
            let mut frozen = root::decode_root(&submission.frozen.initial_root).unwrap();
            frozen.volume = input.volume.clone();
            submission.frozen.initial_root = root::encode_root(&frozen).unwrap();
            proof
                .mediator_for_test()
                .publication_transaction(|store| store.begin(&submission))
                .unwrap();
        } else {
            proof
                .mediator_for_test()
                .overlay_transaction(|overlay| {
                    overlay.create_file(
                        granary_core::overlay_journal::Location {
                            parent: granary_core::overlay_journal::Parent::root(),
                            name: granary_core::manifest::Name::new(b"dirty".to_vec()).unwrap(),
                        },
                        false,
                    )
                })
                .unwrap();
        }
        drop(proof);
        if !publication {
            // A dirty replay is finished on its base before the start
            // serves: one commit publishes it.
            let result = restart_publishing(&input, &tree, &state);
            assert_eq!(
                (
                    result.as_ref().err().map(WritableStartError::name),
                    state.lock().unwrap().publications.len()
                ),
                (None, 1),
                "a dirty replay is finished before readiness"
            );
            cases += 1;
            continue;
        }
        let authority = Authority::with_scope_and_rule(&tree, input.scope.clone(), &state, "valid");
        let result = tracing::subscriber::with_default(events.subscriber(), || {
            start_with(
                &input,
                true,
                || {
                    let (key, spare, _credential) = crate::writable_start::load_local(&input)?;
                    Ok((key, spare, authority))
                },
                |store: &Store| OverlayDisk::new(store.publication_root(), input.euid),
                &mut Entropy(40),
                &Time(Arc::clone(&state)),
                &mut granary_core::rng::SeededRng::new(1),
                &mut Vec::new(),
            )
        });
        let Err(error) = result else {
            panic!("unfinished recovery must prevent readiness");
        };
        assert_eq!(
            (error.name(), events.failed("refused")),
            ("WritableRecoveryRequired", true)
        );
        assert_eq!(
            state.lock().unwrap().calls,
            [2, 3, 3, 0],
            "recovery refuses after succession and before a new registration"
        );
        assert!(paths.store.join("overlay").exists());
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn writable_start_resumes_retained_handshake_before_new_instance_registration() {
    let tree = PublishedTree::publish("v");
    successful_control(&tree);
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let events = Events::default();
    let (result, state, _) = attempt(&input, &tree, "always_lost", &events);
    let Err(error) = result else {
        panic!("unanswered ownership may not mint readiness");
    };
    assert_eq!(
        (error.name(), events.failed("unavailable")),
        ("IntentStartupAttemptsExhausted", true)
    );
    assert_eq!(state.lock().unwrap().calls, [1, 2, 8, 0]);
    let authority = Authority::with_scope_and_rule(&tree, input.scope.clone(), &state, "valid");
    let proof = start_with(
        &input,
        true,
        || {
            let (key, spare, _credential) = crate::writable_start::load_local(&input)?;
            Ok((key, spare, authority))
        },
        |store: &Store| OverlayDisk::new(store.publication_root(), input.euid),
        &mut Entropy(40),
        &Time(Arc::clone(&state)),
        &mut granary_core::rng::SeededRng::new(1),
        &mut Vec::new(),
    )
    .unwrap_or_else(|error| panic!("retained handshake resume refused: {error}"));
    assert_eq!(proof.owner().1, 2);
    {
        let state = state.lock().unwrap();
        assert_eq!(state.calls, [2, 3, 11, 0]);
        assert!(
            state.sends[..9]
                .iter()
                .all(|body| body.iter().eq(&state.sends[0])),
            "retained handshake is replayed exactly before succession"
        );
    }
    drop(proof.attach());
}

#[test]
fn writable_start_library_rails_refuse_before_any_key_or_authority_call() {
    let tree = PublishedTree::publish("v");
    let mut cases = 0;
    for (rule, name) in [
        ("uid", "SetIdExecution"),
        ("gid", "SetIdExecution"),
        ("taint", "SetIdExecution"),
        ("background", "ForegroundRefused"),
        ("missing", "MountpointNotFound"),
        ("symlink", "MountpointSymlink"),
        ("file", "MountpointNotDirectory"),
        ("nonempty", "MountpointNotEmpty"),
    ] {
        successful_control(&tree);
        let paths = Paths::new();
        let mut input = input(&tree, &paths);
        match rule {
            "uid" => input.process.ruid = input.euid.wrapping_add(1),
            "gid" => input.process.rgid = 1,
            "taint" => input.process.set_id_tainted = true,
            "background" => input.foreground = false,
            "missing" => std::fs::remove_dir(&paths.mountpoint).unwrap(),
            "symlink" => {
                std::fs::remove_dir(&paths.mountpoint).unwrap();
                std::os::unix::fs::symlink(&paths.scratch, &paths.mountpoint).unwrap();
            }
            "file" => {
                std::fs::remove_dir(&paths.mountpoint).unwrap();
                std::fs::write(&paths.mountpoint, b"fixture").unwrap();
            }
            "nonempty" => std::fs::write(paths.mountpoint.join("file"), b"fixture").unwrap(),
            _ => unreachable!(),
        }
        let events = Events::default();
        let (result, state, loads) = attempt(&input, &tree, "valid", &events);
        let Err(error) = result else {
            panic!("library rails admitted a refused start");
        };
        assert_eq!(
            (
                error.name(),
                events.failed("refused"),
                loads,
                state.lock().unwrap().calls
            ),
            (name, true, 0, [0; 4])
        );
        cases += 1;
    }
    assert_eq!(cases, 8);
}

#[test]
fn writable_start_unsupported_platform_sends_no_requests() {
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let state = Arc::new(Mutex::new(AuthorityState::default()));
    let authority = Authority::with_scope_and_rule(&tree, input.scope.clone(), &state, "valid");
    let mut loads = 0;
    let result = start_with(
        &input,
        false,
        || {
            loads += 1;
            Ok((
                SigningKey::from_seed(&tree.seed).unwrap(),
                SigningKey::from_seed(&tree.seed).unwrap(),
                authority,
            ))
        },
        |store: &Store| OverlayDisk::new(store.publication_root(), input.euid),
        &mut Entropy(20),
        &Time(Arc::clone(&state)),
        &mut granary_core::rng::SeededRng::new(1),
        &mut Vec::new(),
    );
    assert_eq!(
        result.err().map(|error| error.name()),
        Some("WritablePlatformUnsupported"),
        "unsupported platform must refuse before custody or requests"
    );
    assert_eq!((loads, state.lock().unwrap().calls), (0, [0; 4]));
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        crate::start_writable(
            &input,
            &Time(Arc::clone(&state)),
            &mut granary_core::rng::SeededRng::new(1),
            &mut Entropy(20),
            &mut Vec::new()
        )
        .err()
        .map(|error| error.name()),
        Some("WritablePlatformUnsupported"),
        "production platform wiring must refuse before custody"
    );
    assert!(!paths.store.exists() && !paths.cache.exists());
}

fn restart(
    input: &WritableStart<'_>,
    tree: &PublishedTree,
    state: &Arc<Mutex<AuthorityState>>,
) -> Result<crate::WritableReadiness<Authority, OverlayDisk>, WritableStartError> {
    restart_with_rule(input, tree, state, "valid")
}

fn restart_with_rule(
    input: &WritableStart<'_>,
    tree: &PublishedTree,
    state: &Arc<Mutex<AuthorityState>>,
    rule: &'static str,
) -> Result<crate::WritableReadiness<Authority, OverlayDisk>, WritableStartError> {
    let authority = Authority::with_scope_and_rule(tree, input.scope.clone(), state, rule);
    start_with(
        input,
        true,
        || {
            Ok((
                SigningKey::from_seed(&tree.seed).unwrap(),
                SigningKey::from_seed(&tree.seed).unwrap(),
                authority,
            ))
        },
        |store: &Store| OverlayDisk::new(store.publication_root(), input.euid),
        &mut Entropy(40),
        &Time(Arc::clone(state)),
        &mut granary_core::rng::SeededRng::new(1),
        &mut Vec::new(),
    )
}

/// [`restart`] through an authority that publishes, as a start finishing
/// what its store's journal holds does.
fn restart_publishing(
    input: &WritableStart<'_>,
    tree: &PublishedTree,
    state: &Arc<Mutex<AuthorityState>>,
) -> Result<crate::WritableReadiness<Authority, OverlayDisk>, WritableStartError> {
    let authority = Authority::with_scope_and_rule(tree, input.scope.clone(), state, "valid")
        .with_publication();
    start_with(
        input,
        true,
        || {
            Ok((
                SigningKey::from_seed(&tree.seed).unwrap(),
                SigningKey::from_seed(&tree.seed).unwrap(),
                authority,
            ))
        },
        |store: &Store| OverlayDisk::new(store.publication_root(), input.euid),
        &mut Entropy(40),
        &Time(Arc::clone(state)),
        &mut granary_core::rng::SeededRng::new(1),
        &mut Vec::new(),
    )
}

#[test]
fn writable_start_superseded_succession_persists_its_fence() {
    use granary_core::overlay_ownership::{self, Phase};

    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let events = Events::default();
    let (ready, state, _) = attempt(&input, &tree, "valid", &Events::default());
    drop(ready.unwrap());
    let (original, successor, first_send) = {
        let mut state = state.lock().unwrap();
        let original = state.row.unwrap();
        state.cursor += 1;
        let successor = Receipt {
            epoch: state.cursor,
            instance: [99; 16],
            ..original
        };
        state.row = Some(successor);
        (original, successor, state.sends.len())
    };
    let result = tracing::subscriber::with_default(events.subscriber(), || {
        restart_with_rule(&input, &tree, &state, "superseded_succession")
    });
    assert_eq!(
        result.err().map(|error| error.name()),
        Some("IntentFenced (ESTALE)")
    );
    assert!(events.failed("conflict"));
    let state = state.lock().unwrap();
    let [takeover] = &state.sends[first_send..] else {
        panic!("displaced startup must stop after its first takeover");
    };
    assert_eq!(
        intent::decode_ownership(takeover).unwrap().mode,
        intent::OwnershipMode::Takeover {
            expected_epoch: original.epoch,
            generation: original.generation,
            state: original.state,
            recovery_ack: false,
        }
    );
    assert!(state.publications.is_empty());
    let carrier = overlay_ownership::decode(
        &std::fs::read(overlay_area(&paths, &input).join("ownership")).unwrap(),
    )
    .unwrap();
    assert_eq!((carrier.phase, carrier.fence), (Phase::Fenced, 1));
    assert_eq!(
        intent::decode_receipt(&carrier.fence_evidence).unwrap(),
        successor
    );
    assert!(
        !carrier
            .pending
            .iter()
            .any(|pending| pending.body == *takeover)
    );
}

#[test]
fn writable_start_resolves_retained_release_before_succession() {
    for dispatched in [false, true] {
        let tree = PublishedTree::publish("v");
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let (result, state, _) = attempt(&input, &tree, "valid", &Events::default());
        let mut proof = result.unwrap();
        let request = proof
            .mediator_for_test()
            .prepare_release(
                &Time(Arc::clone(&state)),
                std::time::Duration::from_secs(10),
                None,
            )
            .unwrap();
        if dispatched {
            proof
                .mediator_for_test()
                .dispatch(&request, &Time(Arc::clone(&state)))
                .unwrap();
        }
        let body = request.bytes().to_vec();
        let expires = proof
            .mediator_for_test()
            .snapshot()
            .pending
            .iter()
            .find(|pending| pending.operation == Operation::Release)
            .unwrap()
            .expires;
        drop(proof);
        state.lock().unwrap().tick = expires - 1001; // One millisecond before expiry.
        let resumed = restart(&input, &tree, &state).unwrap_or_else(|error| {
            panic!("retained release must resolve before succession: {error}")
        });
        assert_eq!(resumed.owner().1, 2);
        let state = state.lock().unwrap();
        assert!(
            state.sends[2].iter().eq(&body),
            "retained release must replay exact bytes"
        );
        assert_eq!(state.calls, [2, 3, 5, 0]);
    }
}

#[test]
fn writable_start_settles_expired_release_before_succession() {
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, state, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    let owner = proof.owner();
    let request = proof
        .mediator_for_test()
        .prepare_release(
            &Time(Arc::clone(&state)),
            std::time::Duration::from_secs(10),
            None,
        )
        .unwrap();
    let expires = proof
        .mediator_for_test()
        .snapshot()
        .pending
        .iter()
        .find(|pending| pending.operation == Operation::Release)
        .unwrap()
        .expires;
    let selected = state.lock().unwrap().row.unwrap();
    drop(proof); // Crash after prepare persisted, before dispatch.
    state.lock().unwrap().tick = expires - 1000; // Exactly the persisted expiry.
    let mut resumed = restart(&input, &tree, &state).unwrap_or_else(|error| {
        panic!("expired retained release must permit conditional succession: {error}")
    });
    assert_eq!(resumed.owner().0, owner.0);
    assert!(resumed.owner().1 > owner.1 && resumed.owner().2 != owner.2);
    assert!(
        resumed
            .mediator_for_test()
            .snapshot()
            .pending
            .iter()
            .all(|pending| pending.operation != Operation::Release),
        "the new owner grant must retire the expired release"
    );
    let state = state.lock().unwrap();
    assert!(!state.sends.iter().any(|sent| sent == request.bytes()));
    let takeover = intent::decode_ownership(&state.sends[2]).unwrap();
    assert_eq!(takeover.writer, owner.0);
    assert_eq!(takeover.instance, resumed.owner().2);
    assert_eq!(
        takeover.mode,
        intent::OwnershipMode::Takeover {
            expected_epoch: selected.epoch,
            generation: selected.generation,
            state: selected.state,
            recovery_ack: false,
        },
        "expiry must transfer the retained live row before registering"
    );
    assert_eq!(state.calls, [2, 3, 4, 0]);
    assert!(paths.store.join("overlay").exists());
}

#[test]
fn writable_shutdown_closes_cache_despite_coordination_refusal() {
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    proof
        .mediator_for_test()
        .phase_for_test(granary_core::overlay_ownership::Phase::Releasing)
        .unwrap();
    let mut backend = proof.attach().backend;
    let error = granary_fuse::MountBackend::shutdown(&mut backend).unwrap_err();
    assert!(
        error.starts_with("WritableShutdownCoordinationFailed"),
        "coordination and cache outcomes must be distinct"
    );
    let cache = Cache::open(&paths.cache, input.cache_quota, &input.cache_origin).unwrap();
    assert!(
        !cache.is_read_only_degraded(),
        "shutdown must close the cache on coordination refusal"
    );
    Cache::close(cache).unwrap();
}

#[test]
fn writable_selected_prepared_root_requires_recovery_without_replacement() {
    for field in ["manifest", "binmap", "sheaf", "chunker"] {
        let tree = PublishedTree::publish("v");
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let (result, state, _) = attempt(&input, &tree, "valid", &Events::default());
        let mut proof = result.unwrap();
        let mut prepared = root::decode_root(&state.lock().unwrap().root).unwrap();
        match field {
            "manifest" => {
                prepared.manifest_root = granary_core::manifest::build_dir(&[]).unwrap().root;
            }
            "binmap" => prepared.binmap_index = GrainId::of(b"changed-binmap"),
            "sheaf" => prepared.sheaf_head = GrainId::of(b"changed-sheaf"),
            "chunker" => prepared.chunker_spec.push_str("-changed"),
            _ => unreachable!(),
        }
        prepared.timestamp.secs += 1;
        prepared.sigs.clear();
        let prefix = root::signing_prefix_of(&prepared).unwrap();
        prepared.sigs.push(RootSig {
            key_id: tree.key.key_id(),
            sig: tree.key.sign(&prefix),
        });
        let bytes = root::encode_root(&prepared).unwrap();
        let request = proof
            .mediator_for_test()
            .prepare_registration(&bytes, vec![], &Time(Arc::clone(&state)), |_, _| true)
            .unwrap();
        proof
            .mediator_for_test()
            .dispatch(&request, &Time(Arc::clone(&state)))
            .unwrap();
        let authority = Authority::with_scope_and_rule(&tree, input.scope.clone(), &state, "valid");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // The newer root is acknowledged, then the process crashes before publication.
        let reply = rt
            .block_on(authority.writable_send(
                input.scope.as_ref().unwrap(),
                &request,
                tree.key.public_key(),
            ))
            .unwrap();
        proof
            .mediator_for_test()
            .complete(
                &request,
                Ok(&reply),
                &Time(Arc::clone(&state)),
                &mut granary_core::rng::SeededRng::new(1),
                0,
                None,
            )
            .unwrap();
        let selected = state.lock().unwrap().root.clone();
        drop(proof);
        let result = restart(&input, &tree, &state);
        assert_eq!(
            result.err().map(|error| error.name()),
            Some("WritableRecoveryRequired"),
            "selected prepared root must not be replaced by the base snapshot"
        );
        assert!(
            state.lock().unwrap().root.iter().eq(&selected),
            "prepared evidence remains selected"
        );
        assert!(paths.store.join("overlay").exists());
        let store = Store::open(&paths.store).unwrap();
        let carrier = crate::WritableStore::new(
            store,
            crate::OverlayConfig {
                scope: input.scope.clone().unwrap(),
                volume: input.volume.clone(),
                euid: input.euid,
                cap: 134_217_728,
                ownership_completion_reserve: granary_core::overlay_ownership::REPLACEMENT_RESERVE,
                instance: [0; 16],
            },
            OverlayDisk::new(&paths.store, input.euid),
            &mut Entropy(60),
            crate::FaultControl::default(),
            |_, _| true,
        )
        .unwrap();
        assert_eq!(carrier.snapshot().root, selected);
        assert_eq!(carrier.snapshot().selected_root, selected);
    }
}

#[test]
fn writable_base_file_content_matches_canonical_seal_payload() {
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let snapshot = result.unwrap().attach().snapshot;
    let entry = snapshot.lookup(&tree.manifest_root, b"f.txt").unwrap();
    let granary_core::manifest::EntryKind::File { size, grains, .. } = entry.kind else {
        panic!("file fixture")
    };
    let sealed = GrainId::of(&granary_core::manifest::node::file_payload(size, &grains).unwrap());
    let base = crate::writable_start::overlay_base(&snapshot).unwrap();
    assert!(
        base.iter().any(|entry| matches!(entry.kind,
        crate::OverlayKind::File { content: Some(id) } if id == sealed)),
        "base file content must match the sealed canonical payload"
    );
}

#[test]
fn writable_http_read_facade_keeps_transport_metrics() {
    let remote = crate::HttpStore::with_client_credential(
        "https://fixture.invalid",
        vec![[1; 32]],
        &crate::AmbientNetwork,
        None,
    )
    .unwrap();
    let remote = crate::writable_start::metered_remote(&remote);
    let read = remote.read_facade();
    let metrics = read
        .client_metrics()
        .expect("writable read facade must retain session metrics");
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let state = Arc::new(Mutex::new(AuthorityState::default()));
    let authority = Authority::with_scope_and_rule(&tree, input.scope.clone(), &state, "valid")
        .with_metrics(metrics.clone());
    let session = MountSession::open(
        authority,
        tree.volume.clone(),
        Some(Box::new(*tree.key.public_key())),
        None,
        false,
        None,
        &paths.cache,
        input.cache_quota,
        &input.cache_origin,
        input.options,
        &mut Vec::new(),
    )
    .unwrap();
    assert!(
        session.metrics().is_some(),
        "read path must receive the same session recorder"
    );
    let text = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(
        text.contains("group=\"transport\"} 1"),
        "transport metric group must be available"
    );
    assert!(
        text.contains("group=\"cache\"} 1"),
        "read-path cache metric group must be available"
    );
}

/// `remote_for_sync` crosses from the mount session's runtime ownership
/// domain into the sync runtime's. Cloning the session's `Arc<R>` here would
/// leave `runtime_facades` at zero and share the mount runtime's pool.
#[test]
fn writable_sync_remote_is_a_runtime_facade() {
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let state = Arc::new(Mutex::new(AuthorityState::default()));
    let authority = Authority::with_scope_and_rule(&tree, input.scope.clone(), &state, "valid");
    let session = MountSession::open(
        authority,
        tree.volume.clone(),
        Some(Box::new(*tree.key.public_key())),
        None,
        false,
        None,
        &paths.cache,
        input.cache_quota,
        &input.cache_origin,
        input.options,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(
        state.lock().unwrap().runtime_facades,
        0,
        "opening the mount session must not mint the later sync facade"
    );

    let _sync_remote = session.remote_for_sync();

    assert_eq!(
        state.lock().unwrap().runtime_facades,
        1,
        "the sync handoff must mint one runtime facade instead of cloning the session remote"
    );
}

#[test]
fn writable_mountpoint_without_leaf_is_refused_before_requests() {
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let mut input = input(&tree, &paths);
    input.force = true;
    for mountpoint in [Path::new("."), Path::new(".."), Path::new("/")] {
        input.mountpoint = mountpoint;
        let (result, state, loads) = attempt(&input, &tree, "valid", &Events::default());
        assert_eq!(
            result.err().map(|error| error.name()),
            Some("MountpointComponentRefused"),
            "mountpoint without a leaf must not bypass mount-table comparison"
        );
        assert_eq!((loads, state.lock().unwrap().calls), (0, [0; 4]));
    }
}

#[test]
fn writable_shutdown_diagnostic_carries_the_coordination_refusals_own_class() {
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    proof
        .mediator_for_test()
        .phase_for_test(granary_core::overlay_ownership::Phase::Releasing)
        .unwrap();
    let mut backend = proof.attach().backend;
    let events = Events::default();
    let error = tracing::subscriber::with_default(events.subscriber(), || {
        granary_fuse::MountBackend::shutdown(&mut backend).unwrap_err()
    });
    assert!(error.starts_with("WritableShutdownCoordinationFailed"));
    let text = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
    let line = text
        .lines()
        .find(|line| line.contains("writable.shutdown.coordination.failed"))
        .unwrap_or_else(|| panic!("no shutdown diagnostic: {text}"));
    assert!(
        line.contains("\"coordination\":\"refused\""),
        "a refusal must report refused, not a fixed io class: {line}"
    );
}

#[test]
fn writable_shutdown_reports_coordination_and_cache_close_failures_together() {
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    proof
        .mediator_for_test()
        .phase_for_test(granary_core::overlay_ownership::Phase::Releasing)
        .unwrap();
    let mut backend = proof.attach().backend;
    // A directory at the owned cache guard forces close failure even as root.
    std::fs::remove_file(paths.cache.join("guard")).unwrap();
    std::fs::create_dir(paths.cache.join("guard")).unwrap();
    let error = granary_fuse::MountBackend::shutdown(&mut backend).unwrap_err();
    assert!(
        error.starts_with(
            "WritableShutdownCoordinationFailed: intent refused: WritableRecoveryRequired; cache="
        ),
        "both shutdown outcomes must be retained"
    );
    assert!(
        error.contains("remove guard"),
        "cache close failure must also be reported"
    );
    std::fs::remove_dir(paths.cache.join("guard")).unwrap();
    let cache = Cache::open(&paths.cache, input.cache_quota, &input.cache_origin).unwrap();
    assert!(
        !cache.is_read_only_degraded(),
        "even failed close releases the owned cache"
    );
    Cache::close(cache).unwrap();
}

#[test]
fn writable_callback_observer_uses_closed_events_and_separate_counters() {
    use granary_fuse::{Callback, CallbackObserver, CallbackOutcome, MountError};
    let metrics = crate::metrics::tests::metrics();
    metrics.set_available(crate::MetricsGroup::Fuse, true);
    let observer = crate::mount::FuseObserver {
        writability: granary_fuse::MountWritability::Writable,
        metrics: Some(metrics.clone()),
    };
    let mut cases = 0;
    for format in [crate::LogFormat::Text, crate::LogFormat::Json] {
        let events = Events::default();
        tracing::subscriber::with_default(events.formatted(format), || {
            assert_eq!(
                (
                    observer.begin(Callback::Fsync).is_none(),
                    observer.begin(Callback::Fsyncdir).is_none()
                ),
                (true, true),
                "sync callbacks must not open thread-local write capture scopes"
            );
            observer.deferred_completed(Callback::Fsync, CallbackOutcome::Refused);
            for callback in [Callback::Getxattr, Callback::Listxattr] {
                let _scope = observer.begin(callback);
                observer.completed(callback, CallbackOutcome::Refused);
            }
            let _scope = observer.begin(Callback::Release);
            observer.completed(Callback::Release, CallbackOutcome::Failed(MountError::Io));
        });
        let output = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("op.begin")
                && output.contains("op.end")
                && output.contains("op.failed")
        );
        assert_eq!(
            output.matches("op.failed").count(),
            3,
            "queries and resource release emit local failures; sync has its engine observation"
        );
        assert!(
            output.contains("overlay_write") && output.contains("refused") && output.contains("io")
        );
        assert!(!output.contains("caller/path") && !output.contains("token=secret"));
        cases += 1;
    }
    let output = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(output.contains("fuse_requests_total{callback=\"fsync\",outcome=\"refused\"} 2"));
    assert!(output.contains("fuse_requests_total{callback=\"release\",outcome=\"failed\"} 2"));
    assert!(!output.contains("syncs_total{"));
    assert_eq!(cases, 2);
}

#[cfg(target_os = "linux")]
fn mount_refusal_pair(
    tree: &PublishedTree,
    paths: &Paths,
    input: &WritableStart<'_>,
    journal: &Path,
    writable: bool,
) -> (SessionGuard, Option<Vec<u8>>, Arc<Mutex<AuthorityState>>) {
    if writable {
        let (result, state, _) = attempt(input, tree, "valid", &Events::default());
        let proof = result.unwrap();
        let before = std::fs::read(journal).unwrap();
        let mounted = SessionGuard::new(proof.attach().mount(1).unwrap(), &paths.mountpoint);
        (mounted, Some(before), state)
    } else {
        let state = Arc::new(Mutex::new(AuthorityState::default()));
        let authority = Authority::with_scope_and_rule(tree, input.scope.clone(), &state, "valid");
        let mut session = MountSession::open(
            authority,
            tree.volume.clone(),
            Some(Box::new(*tree.key.public_key())),
            None,
            false,
            Some(1),
            &paths.cache,
            input.cache_quota,
            &input.cache_origin,
            MountOptions::default(),
            &mut Vec::new(),
        )
        .unwrap();
        let snapshot = session.snapshot(input.policy).unwrap();
        let mounted = granary_fuse::spawn_session(
            snapshot,
            session,
            1,
            granary_fuse::MountWritability::ReadOnly,
            &paths.mountpoint,
            &granary_fuse::session_config(false),
        )
        .unwrap();
        (SessionGuard::new(mounted, &paths.mountpoint), None, state)
    }
}

#[cfg(target_os = "linux")]
fn admitted_sync_handles(mountpoint: &Path, file: &Path) -> usize {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut cases = 0;
    for sync in [0x0010_1000, 0x1000] {
        let created = mountpoint.join(format!("sync-{sync:x}"));
        for write in [
            std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(sync)
                .open(file),
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(sync)
                .open(&created),
        ] {
            assert!(
                write.is_ok(),
                "writable mount admits synchronous open/create ({sync:#x}): {write:?}"
            );
            cases += 1;
        }
        assert!(created.exists());
    }
    cases
}

/// Exercise the consumed readiness path and pair every attempted mutation with RO.
#[cfg(target_os = "linux")]
#[test]
fn writable_linux_refusals_modes_and_synchronous_read_pairs() {
    use std::os::unix::fs::OpenOptionsExt as _;
    if !Path::new("/dev/fuse").exists() {
        eprintln!("SKIPPED-NO-DEV-FUSE writable_linux_refusals_modes_and_synchronous_read_pairs");
        return;
    }
    let tree = PublishedTree::publish("v");
    let mut cases = 0;
    for writable in [true, false] {
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let journal = paths
            .store
            .join("overlay")
            .join(input.scope.as_ref().unwrap().digest().unwrap())
            .join(input.volume.as_str())
            .join("journal");
        let (mut mounted, before, state) =
            mount_refusal_pair(&tree, &paths, &input, &journal, writable);
        let file = paths.mountpoint.join("f.txt");
        let new = paths.mountpoint.join("new");
        assert_eq!(
            (
                std::fs::metadata(&file).unwrap().mode() & 0o777,
                std::fs::metadata(&paths.mountpoint).unwrap().mode() & 0o777
            ),
            if writable {
                (0o644, 0o755)
            } else {
                (0o444, 0o555)
            }
        );
        let expected = if writable { 95 } else { 30 };
        for (name, operation) in [
            ("link", std::fs::hard_link(&file, &new)),
            (
                "chmod",
                std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)),
            ),
        ] {
            assert_eq!(
                operation.err().and_then(|error| error.raw_os_error()),
                Some(expected),
                "{name}: writable={writable}"
            );
            cases += 1;
        }
        for sync in [0x0010_1000, 0x1000] {
            let read = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(sync)
                .open(&file);
            assert!(read.is_ok(), "pure read with synchronous flag: {read:?}");
            if !writable {
                for write in [
                    std::fs::OpenOptions::new()
                        .write(true)
                        .custom_flags(sync)
                        .open(&file),
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .custom_flags(sync)
                        .open(&new),
                ] {
                    assert_eq!(
                        write.err().and_then(|error| error.raw_os_error()),
                        Some(expected)
                    );
                    cases += 1;
                }
            }
        }
        assert_eq!(std::fs::read(&file).unwrap(), FILE_CONTENT);
        assert!(!new.exists());
        if let Some(before) = &before {
            assert_eq!(
                &std::fs::read(&journal).unwrap(),
                before,
                "refusals and synchronous reads append no operation record"
            );
            cases += admitted_sync_handles(&paths.mountpoint, &file);
        }
        mounted.finish().unwrap();
        if before.is_none() {
            assert!(!journal.exists(), "RO attempts must not create an overlay");
            assert_eq!(state.lock().unwrap().calls, [0; 4]);
        }
    }
    assert_eq!(cases, 12);
}

fn handler_path(name: &[u8]) -> Vec<granary_core::manifest::Name> {
    vec![granary_core::manifest::Name::new(name.to_vec()).unwrap()]
}

fn overlay_area(paths: &Paths, input: &WritableStart<'_>) -> std::path::PathBuf {
    paths
        .store
        .join("overlay")
        .join(input.scope.as_ref().unwrap().digest().unwrap())
        .join(input.volume.as_str())
}

/// Every staging file by name, with its full contents.
fn captured_staging(paths: &Paths, input: &WritableStart<'_>) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(overlay_area(paths, input).join("staging"))
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

fn staged_lengths(files: &BTreeMap<String, Vec<u8>>) -> Vec<usize> {
    files.values().map(Vec::len).collect()
}

fn captured_records(
    paths: &Paths,
    input: &WritableStart<'_>,
) -> (
    granary_core::overlay_journal::JournalHeader,
    Vec<granary_core::overlay_journal::Record>,
) {
    let bytes = std::fs::read(overlay_area(paths, input).join("journal")).unwrap();
    let mut records = Vec::new();
    let scan = granary_core::overlay_journal::scan_journal_with(&bytes, |_, record| {
        records.push(record.clone());
    })
    .unwrap();
    (scan.header, records)
}

#[expect(
    clippy::too_many_lines,
    reason = "one controlled fixture ties each callback to exact records, live bytes and replay"
)]
fn handler_capture_control(operation: &str) {
    use granary_core::overlay_journal::{CreateKind, DeleteKind, Record};
    use granary_fuse::{MountBackend as _, OverlayMutation as M};
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    let base = crate::writable_start::overlay_base(proof.snapshot_for_test()).unwrap();
    let file = handler_path(b"f.txt");
    let new = handler_path(b"new");
    let (before, _) = captured_records(&paths, &input);
    if operation == "rmdir" {
        proof
            .mediator_for_test()
            .overlay_transaction(|overlay| {
                overlay.namespace_record(Record::Create {
                    at: granary_core::overlay_journal::Location {
                        parent: granary_core::overlay_journal::Parent::root(),
                        name: new.first().unwrap().clone(),
                    },
                    kind: CreateKind::Dir,
                })
            })
            .unwrap();
    }
    let initial = captured_records(&paths, &input).1.len();
    let request = match operation {
        "create" | "mknod" => M::Create {
            path: &new,
            kind: granary_vfs::NodeKind::File,
            exec: true,
        },
        "mkdir" => M::Create {
            path: &new,
            kind: granary_vfs::NodeKind::Dir,
            exec: false,
        },
        "write" => M::Write {
            path: &file,
            offset: 1,
            bytes: b"Z",
            append: false,
        },
        "truncate" => M::Setattr {
            path: &file,
            size: Some(2),
            exec: None,
        },
        "chmod" => M::Setattr {
            path: &file,
            size: None,
            exec: Some(true),
        },
        "unlink" => M::Remove {
            path: &file,
            directory: false,
        },
        "rename" => M::Rename {
            from: &file,
            to: &new,
            no_replace: false,
        },
        "rmdir" => M::Remove {
            path: &new,
            directory: true,
        },
        _ => panic!("unknown test operation"),
    };
    if matches!(operation, "write" | "truncate") {
        proof.backend_for_test().prepare_overlay(&file).unwrap();
    }
    let answer = proof.backend_for_test().overlay_mutate(request);
    assert_eq!(
        answer,
        Ok(()),
        "{operation}: reply-only or unimplemented handler"
    );
    let (_, records) = captured_records(&paths, &input);
    let captured = &records[initial..];
    let discriminates = match operation {
        "create" | "mknod" => matches!(
            captured,
            [Record::Create {
                kind: CreateKind::File { exec: true, .. },
                ..
            }]
        ),
        "mkdir" => matches!(
            captured,
            [Record::Create {
                kind: CreateKind::Dir,
                ..
            }]
        ),
        "write" => matches!(
            captured,
            [
                Record::StageBind { .. },
                Record::WriteExtent {
                    offset: 1,
                    length: 1,
                    ..
                }
            ]
        ),
        "truncate" => matches!(
            captured,
            [
                Record::StageBind { .. },
                Record::Truncate { new_size: 2, .. }
            ]
        ),
        "chmod" => matches!(captured, [Record::SetattrExec { exec: true, .. }]),
        "unlink" => matches!(
            captured,
            [Record::Delete {
                kind: DeleteKind::File { stage_id: None },
                ..
            }]
        ),
        "rename" => matches!(captured, [Record::Move { .. }]),
        "rmdir" => matches!(
            captured,
            [Record::Delete {
                kind: DeleteKind::Dir,
                ..
            }]
        ),
        _ => false,
    };
    assert!(
        discriminates,
        "{operation}: wrong or omitted journal record: {captured:?}"
    );
    for record in captured {
        let at = match record {
            Record::Create { at, .. }
            | Record::Delete { at, .. }
            | Record::SetattrExec { at, .. }
            | Record::StageBind { at, .. } => Some(at),
            _ => None,
        };
        if let Some(at) = at {
            let mut path = at.parent.names().to_vec();
            path.push(at.name.clone());
            assert_eq!(
                path,
                if matches!(operation, "create" | "mknod" | "mkdir" | "rmdir") {
                    new.clone()
                } else {
                    file.clone()
                },
                "{operation}: journal captured the wrong location"
            );
        }
        if let Record::Move { from, to } = record {
            assert_eq!(
                (from.parent.names(), &from.name, to.parent.names(), &to.name),
                (
                    &[][..],
                    file.first().unwrap(),
                    &[][..],
                    new.first().unwrap()
                ),
                "rename captured wrong parents or names"
            );
        }
    }
    let expected_bytes = match operation {
        "write" => {
            let mut bytes = FILE_CONTENT.to_vec();
            bytes[1] = b'Z';
            Some(bytes)
        }
        "truncate" => Some(FILE_CONTENT[..2].to_vec()),
        _ => None,
    };
    let live = proof.backend_for_test().overlay_nodes().unwrap();
    if matches!(operation, "create" | "mknod" | "mkdir") {
        let node = live
            .iter()
            .find(|node| node.path == new)
            .expect("created name must be live");
        assert_eq!(
            (node.kind, node.exec, node.size),
            if operation == "mkdir" {
                (granary_vfs::NodeKind::Dir, false, 4096)
            } else {
                (granary_vfs::NodeKind::File, true, 0)
            }
        );
    }
    if operation == "rmdir" {
        assert!(!live.iter().any(|node| node.path == new));
    }
    let expected_size = match operation {
        "truncate" => 2,
        _ => FILE_CONTENT.len() as u64,
    };
    if matches!(operation, "write" | "truncate" | "chmod") {
        let node = live.iter().find(|n| n.path == file).unwrap();
        assert_eq!(
            (node.size, node.exec),
            (expected_size, operation == "chmod")
        );
    }
    if matches!(operation, "unlink" | "rename") {
        assert!(!live.iter().any(|n| n.path == file));
    }
    if let Some(expected) = &expected_bytes {
        let stage = live
            .iter()
            .find(|node| node.path == file)
            .unwrap()
            .stage
            .unwrap();
        let bytes = proof
            .mediator_for_test()
            .overlay_transaction(|overlay| overlay.read_stage(stage, 0, 65536))
            .unwrap();
        assert_eq!(
            &bytes, expected,
            "{operation}: journal-only handler lost live bytes"
        );
    }
    // Reopen the controlled captured fixture. Ordinary replies do not promise crash durability.
    proof
        .mediator_for_test()
        .open_overlay_local(
            before,
            base,
            OverlayDisk::new(&paths.store, input.euid),
            false,
        )
        .unwrap();
    assert_eq!(
        proof.backend_for_test().overlay_nodes().unwrap(),
        live,
        "{operation}: replay lost a callback effect"
    );
    if let Some(expected) = &expected_bytes {
        let stage = live
            .iter()
            .find(|node| node.path == file)
            .unwrap()
            .stage
            .unwrap();
        let bytes = proof
            .mediator_for_test()
            .overlay_transaction(|overlay| overlay.read_stage(stage, 0, 65536))
            .unwrap();
        assert_eq!(
            &bytes, expected,
            "{operation}: replay resurrected or dropped bytes"
        );
    }
}

#[test]
fn writable_handlers_create_captures_and_replays() {
    handler_capture_control("create");
}
#[test]
fn writable_handlers_regular_mknod_captures_and_replays() {
    handler_capture_control("mknod");
}
#[test]
fn writable_handlers_write_copy_up_captures_and_replays() {
    handler_capture_control("write");
}
#[test]
fn writable_handlers_truncate_captures_and_replays() {
    handler_capture_control("truncate");
}
#[test]
fn writable_handlers_mkdir_captures_and_replays() {
    handler_capture_control("mkdir");
}
#[test]
fn writable_handlers_unlink_captures_and_replays() {
    handler_capture_control("unlink");
}
#[test]
fn writable_handlers_rmdir_captures_and_replays() {
    handler_capture_control("rmdir");
}
#[test]
fn writable_handlers_rename_captures_and_replays() {
    handler_capture_control("rename");
}
#[test]
fn writable_handlers_exec_chmod_captures_and_replays() {
    handler_capture_control("chmod");
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the explicit refusal table shares one namespace and unchanged journal witness"
)]
fn writable_handlers_namespace_guards_are_atomic() {
    use granary_fuse::{MountBackend as _, OverlayMutation as M, WriteError as E};
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    let file = handler_path(b"f.txt");
    let dir = handler_path(b"dir");
    let missing = handler_path(b"missing");
    let mut child = dir.clone();
    child.extend(handler_path(b"child"));
    let mut bad_parent = file.clone();
    bad_parent.extend(handler_path(b"child"));
    let mut absent_parent = missing.clone();
    absent_parent.extend(handler_path(b"child"));
    proof
        .backend_for_test()
        .overlay_mutate(M::Create {
            path: &dir,
            kind: granary_vfs::NodeKind::Dir,
            exec: false,
        })
        .unwrap();
    proof
        .backend_for_test()
        .overlay_mutate(M::Create {
            path: &child,
            kind: granary_vfs::NodeKind::File,
            exec: false,
        })
        .unwrap();
    let before = captured_records(&paths, &input).1;
    let nodes = proof.backend_for_test().overlay_nodes().unwrap();
    let mut cases = 0;
    for (operation, expected) in [
        (
            M::Create {
                path: &file,
                kind: granary_vfs::NodeKind::File,
                exec: false,
            },
            E::Exists,
        ),
        (
            M::Create {
                path: &bad_parent,
                kind: granary_vfs::NodeKind::File,
                exec: false,
            },
            E::NotDirectory,
        ),
        (
            M::Create {
                path: &absent_parent,
                kind: granary_vfs::NodeKind::File,
                exec: false,
            },
            E::Missing,
        ),
        (
            M::Create {
                path: &[],
                kind: granary_vfs::NodeKind::File,
                exec: false,
            },
            E::Invalid,
        ),
        (
            M::Create {
                path: &missing,
                kind: granary_vfs::NodeKind::Symlink,
                exec: false,
            },
            E::Unsupported,
        ),
        (
            M::Remove {
                path: &missing,
                directory: false,
            },
            E::Missing,
        ),
        (
            M::Remove {
                path: &dir,
                directory: true,
            },
            E::NotEmpty,
        ),
        (
            M::Remove {
                path: &dir,
                directory: false,
            },
            E::IsDirectory,
        ),
        (
            M::Remove {
                path: &file,
                directory: true,
            },
            E::NotDirectory,
        ),
        (
            M::Rename {
                from: &file,
                to: &file,
                no_replace: true,
            },
            E::Exists,
        ),
        (
            M::Rename {
                from: &missing,
                to: &missing,
                no_replace: false,
            },
            E::Missing,
        ),
        (
            M::Rename {
                from: &dir,
                to: &child,
                no_replace: false,
            },
            E::Invalid,
        ),
        (
            M::Rename {
                from: &file,
                to: &dir,
                no_replace: false,
            },
            E::IsDirectory,
        ),
        (
            M::Rename {
                from: &dir,
                to: &file,
                no_replace: false,
            },
            E::NotDirectory,
        ),
        (
            M::Setattr {
                path: &dir,
                size: Some(1),
                exec: None,
            },
            E::IsDirectory,
        ),
        (
            M::Setattr {
                path: &file,
                size: Some(u64::MAX),
                exec: None,
            },
            E::TooBig,
        ),
        (
            M::Write {
                path: &file,
                offset: u64::MAX,
                bytes: b"x",
                append: false,
            },
            E::Invalid,
        ),
        (
            M::Write {
                path: &file,
                offset: u64::MAX,
                bytes: b"",
                append: false,
            },
            E::TooBig,
        ),
    ] {
        assert_eq!(
            (
                proof.backend_for_test().overlay_mutate(operation),
                captured_records(&paths, &input).1,
                proof.backend_for_test().overlay_nodes().unwrap()
            ),
            (Err(expected), before.clone(), nodes.clone()),
            "wrong errno, partial effect or omitted namespace guard"
        );
        cases += 1;
    }
    assert_eq!(cases, 18);
    proof
        .backend_for_test()
        .overlay_mutate(M::Rename {
            from: &file,
            to: &file,
            no_replace: false,
        })
        .unwrap();
    proof
        .backend_for_test()
        .overlay_mutate(M::Write {
            path: &file,
            offset: granary_core::overlay_journal::SIZE_MAX,
            bytes: b"",
            append: false,
        })
        .unwrap();
    assert_eq!(
        captured_records(&paths, &input).1,
        before,
        "validated no-ops append nothing"
    );
}

#[test]
fn writable_handlers_dense_resize_append_and_cap_preserve_capture() {
    use granary_fuse::{MountBackend as _, MountError, OverlayMutation as M, WriteError};
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    let base = crate::writable_start::overlay_base(proof.snapshot_for_test()).unwrap();
    let file = handler_path(b"f.txt");
    let header = captured_records(&paths, &input).0;
    proof.backend_for_test().prepare_overlay(&file).unwrap();
    for size in [2, 8] {
        proof
            .backend_for_test()
            .overlay_mutate(M::Setattr {
                path: &file,
                size: Some(size),
                exec: None,
            })
            .unwrap();
    }
    proof
        .backend_for_test()
        .overlay_mutate(M::Write {
            path: &file,
            offset: 999,
            bytes: b"A",
            append: true,
        })
        .unwrap();
    let stage = proof
        .backend_for_test()
        .overlay_nodes()
        .unwrap()
        .into_iter()
        .find(|n| n.path == file)
        .unwrap()
        .stage
        .unwrap();
    let mut expected = FILE_CONTENT[..2].to_vec();
    expected.extend([0; 6]);
    expected.push(b'A');
    let bytes = proof
        .mediator_for_test()
        .overlay_transaction(|o| o.read_stage(stage, 0, 64))
        .unwrap();
    assert_eq!(
        bytes, expected,
        "shrink/extend resurrected tail or append ignored EOF"
    );
    let before = captured_records(&paths, &input).1;
    let over_extent = vec![1; 8_388_609];
    assert_eq!(
        (
            proof.backend_for_test().overlay_mutate(M::Write {
                path: &file,
                offset: 0,
                bytes: &over_extent,
                append: false
            }),
            captured_records(&paths, &input).1
        ),
        (Err(WriteError::Invalid), before.clone())
    );
    assert_eq!(
        (
            proof.backend_for_test().overlay_mutate(M::Setattr {
                path: &file,
                size: Some(134_217_728),
                exec: None
            }),
            captured_records(&paths, &input).1
        ),
        (Err(WriteError::Backend(MountError::NoSpace)), before)
    );
    proof
        .mediator_for_test()
        .open_overlay_local(
            header,
            base,
            OverlayDisk::new(&paths.store, input.euid),
            false,
        )
        .unwrap();
    assert_eq!(
        proof
            .mediator_for_test()
            .overlay_transaction(|o| o.read_stage(stage, 0, 64))
            .unwrap(),
        expected,
        "replay must preserve dense zeros and refused prefix"
    );
}

fn observe_bound_overlay(
    overlay: &mut crate::WritableOverlay<'_, OverlayDisk>,
) -> Result<crate::OverlayObservation, crate::OverlayError> {
    overlay.observation()
}

#[expect(
    clippy::too_many_lines,
    reason = "shared holds, orphan bytes, refusal and replay belong to one captured fixture"
)]
fn object_binding_control(dirty: bool, replace: bool) {
    use granary_core::overlay_journal::Record;
    use granary_fuse::{MountBackend as _, OverlayMutation as M};
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    let file = handler_path(b"f.txt");
    let source = handler_path(b"source");
    let opened = proof.backend_for_test().overlay_open(&file).unwrap();
    assert!(
        opened.is_some(),
        "handle must receive an object binding, got {opened:?}"
    );
    let id = opened.unwrap();
    assert_eq!(
        proof.backend_for_test().overlay_open(&file),
        Ok(Some(id)),
        "handles must bind one overlay object"
    );
    proof.backend_for_test().prepare_object(id).unwrap();
    assert_eq!(
        proof.backend_for_test().read_object(id, 0, 65536).unwrap(),
        FILE_CONTENT
    );
    let initial = captured_records(&paths, &input).1.len();
    if dirty {
        proof
            .backend_for_test()
            .overlay_mutate(M::BoundWrite {
                object: id,
                offset: 1,
                bytes: b"Z",
                append: false,
            })
            .unwrap();
    }
    let expected = if dirty {
        let mut bytes = FILE_CONTENT.to_vec();
        bytes[1] = b'Z';
        bytes
    } else {
        FILE_CONTENT.to_vec()
    };
    if replace {
        proof
            .backend_for_test()
            .overlay_mutate(M::Create {
                path: &source,
                kind: granary_vfs::NodeKind::File,
                exec: true,
            })
            .unwrap();
        proof.backend_for_test().prepare_detach(&file).unwrap();
        proof
            .backend_for_test()
            .overlay_mutate(M::Rename {
                from: &source,
                to: &file,
                no_replace: false,
            })
            .unwrap();
    } else {
        proof.backend_for_test().prepare_detach(&file).unwrap();
        proof
            .backend_for_test()
            .overlay_mutate(M::Remove {
                path: &file,
                directory: false,
            })
            .unwrap();
        proof
            .backend_for_test()
            .overlay_mutate(M::Create {
                path: &file,
                kind: granary_vfs::NodeKind::File,
                exec: true,
            })
            .unwrap();
    }
    let old = proof.backend_for_test().overlay_object(id).unwrap();
    let stage = old
        .stage
        .expect("clean open orphan must copy up before detachment");
    let records = captured_records(&paths, &input).1;
    assert_eq!(
        records[initial..]
            .iter()
            .filter(|r| matches!(r, Record::StageBind { .. }))
            .count(),
        1,
        "one shared stage, never one per handle"
    );
    assert!(if replace {
        records.iter().any(|r| matches!(r, Record::Replace { .. }))
    } else {
        records.iter().any(|r| matches!(r, Record::Delete { kind: granary_core::overlay_journal::DeleteKind::File { stage_id: Some(s) }, .. } if *s == stage))
    });
    let replacement = proof
        .backend_for_test()
        .overlay_open(&file)
        .unwrap()
        .unwrap();
    assert_ne!(
        replacement, id,
        "recreating a name must not retarget a held object"
    );
    assert_eq!(
        proof.backend_for_test().read_object(id, 0, 65536),
        Ok(expected.clone()),
        "open orphan must retain the shared stage holds"
    );
    let before = captured_records(&paths, &input).1;
    assert_eq!(
        proof.backend_for_test().overlay_mutate(M::BoundSetattr {
            object: id,
            size: Some(1),
            exec: Some(true)
        }),
        Err(granary_fuse::WriteError::Unsupported),
        "detached exec refusal must precede truncate"
    );
    assert_eq!(captured_records(&paths, &input).1, before);
    assert_eq!(
        proof.backend_for_test().overlay_mutate(M::BoundSetattr {
            object: id,
            size: None,
            exec: Some(false)
        }),
        Ok(()),
        "detached unchanged canonical exec is a no-op"
    );
    assert_eq!(captured_records(&paths, &input).1, before);
    proof
        .backend_for_test()
        .overlay_mutate(M::BoundWrite {
            object: id,
            offset: 0,
            bytes: b"!",
            append: true,
        })
        .unwrap();
    proof
        .backend_for_test()
        .overlay_mutate(M::BoundSetattr {
            object: id,
            size: Some(2),
            exec: None,
        })
        .unwrap();
    proof
        .backend_for_test()
        .overlay_mutate(M::BoundSetattr {
            object: id,
            size: Some(5),
            exec: None,
        })
        .unwrap();
    let expected = [expected[0], expected[1], 0, 0, 0];
    assert_eq!(
        (
            proof.backend_for_test().overlay_object(id).unwrap().size,
            proof.backend_for_test().read_object(id, 0, 65536).unwrap()
        ),
        (5, expected.to_vec()),
        "detached stage size and dense bytes must remain live"
    );
    assert_eq!(
        (
            proof
                .backend_for_test()
                .overlay_object(replacement)
                .unwrap()
                .size,
            proof
                .backend_for_test()
                .overlay_object(replacement)
                .unwrap()
                .exec
        ),
        (0, true),
        "orphan writes/chmod must not touch the replacement"
    );
    let charged = proof
        .mediator_for_test()
        .overlay_transaction(observe_bound_overlay)
        .unwrap();
    assert!(charged.summary.orphan_bytes > 0);
    let before_close = captured_records(&paths, &input).1;
    assert_eq!(
        proof.backend_for_test().overlay_close(u64::MAX),
        Err(granary_fuse::WriteError::Missing)
    );
    proof.backend_for_test().overlay_close(id).unwrap();
    assert_eq!(
        proof.backend_for_test().read_object(id, 0, 65536),
        Ok(expected.to_vec()),
        "one remaining hold must keep detached bytes accessible"
    );
    proof.backend_for_test().overlay_close(id).unwrap();
    assert_eq!(
        proof.backend_for_test().overlay_close(id),
        Err(granary_fuse::WriteError::Missing),
        "duplicate close cannot release another handle"
    );
    let inaccessible = proof
        .mediator_for_test()
        .overlay_transaction(|o| o.read_stage(stage, 0, 1));
    assert!(
        matches!(
            inaccessible,
            Err(crate::CoordinationError::Overlay(
                crate::OverlayError::Refused("detached stage has no handle")
            ))
        ),
        "exactly two holds must disappear on two closes: {inaccessible:?}"
    );
    proof.backend_for_test().overlay_close(replacement).unwrap();
    let closed = proof
        .mediator_for_test()
        .overlay_transaction(observe_bound_overlay)
        .unwrap();
    assert_eq!(
        (
            closed.summary.charged_bytes,
            closed.summary.orphan_bytes,
            captured_records(&paths, &input).1
        ),
        (
            charged.summary.charged_bytes,
            charged.summary.orphan_bytes,
            before_close
        ),
        "close retains charge/evidence and appends no sync record"
    );
}

#[test]
fn writable_objects_clean_unlink_keeps_two_exact_stage_holds() {
    object_binding_control(false, false);
}
#[test]
fn writable_objects_dirty_unlink_keeps_two_exact_stage_holds() {
    object_binding_control(true, false);
}
#[test]
fn writable_objects_clean_replacement_preserves_displaced_identity() {
    object_binding_control(false, true);
}
#[test]
fn writable_objects_dirty_replacement_preserves_displaced_identity() {
    object_binding_control(true, true);
}

#[test]
fn writable_objects_first_copy_up_shares_backing_and_rename_rebinds_names() {
    use granary_fuse::{MountBackend as _, OverlayMutation as M};
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    let file = handler_path(b"f.txt");
    let moved = handler_path(b"moved");
    let first = proof
        .backend_for_test()
        .overlay_open(&file)
        .unwrap()
        .unwrap();
    let second = proof
        .backend_for_test()
        .overlay_open(&file)
        .unwrap()
        .unwrap();
    proof.backend_for_test().prepare_object(first).unwrap();
    proof
        .backend_for_test()
        .overlay_mutate(M::BoundWrite {
            object: first,
            offset: 0,
            bytes: b"Q",
            append: false,
        })
        .unwrap();
    let stage = proof
        .backend_for_test()
        .overlay_object(first)
        .unwrap()
        .stage
        .unwrap();
    assert_eq!(
        (first, Some(stage)),
        (
            second,
            proof
                .backend_for_test()
                .overlay_object(second)
                .unwrap()
                .stage
        )
    );
    let mut expected = FILE_CONTENT.to_vec();
    expected[0] = b'Q';
    assert_eq!(
        proof
            .backend_for_test()
            .read_object(second, 0, 65536)
            .unwrap(),
        expected,
        "second clean handle must see first copy-up"
    );
    proof
        .backend_for_test()
        .overlay_mutate(M::Rename {
            from: &file,
            to: &moved,
            no_replace: true,
        })
        .unwrap();
    assert_eq!(
        proof.backend_for_test().overlay_object(first).unwrap().path,
        moved
    );
    assert_eq!(
        proof.backend_for_test().overlay_open(&moved),
        Ok(Some(first))
    );
    proof.backend_for_test().prepare_detach(&moved).unwrap();
    proof
        .backend_for_test()
        .overlay_mutate(M::Remove {
            path: &moved,
            directory: false,
        })
        .unwrap();
    for _ in 0..2 {
        proof.backend_for_test().overlay_close(first).unwrap();
        assert_eq!(
            proof
                .backend_for_test()
                .read_object(first, 0, 65536)
                .unwrap(),
            expected
        );
    }
    proof.backend_for_test().overlay_close(first).unwrap();
    assert!(
        proof
            .mediator_for_test()
            .overlay_transaction(|o| o.read_stage(stage, 0, 1))
            .is_err(),
        "third staged open must release its own hold"
    );
}

#[test]
fn writable_readlink_copies_only_the_addressed_entry() {
    use granary_fuse::{MountBackend as _, OverlayMutation as M};
    let tree = PublishedTree::publish("v");
    let paths = Paths::with_store_base(&runtime_workspace_scratch().unwrap());
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    let path = handler_path(b"link");
    let target = granary_core::manifest::SymlinkTarget::new(b"../file".to_vec()).unwrap();
    let backend = proof.backend_for_test();
    backend
        .overlay_mutate(M::Symlink {
            path: &path,
            target: &target,
        })
        .unwrap();
    for name in [b"unrelated-a", b"unrelated-b", b"unrelated-c"] {
        backend
            .overlay_mutate(M::Create {
                path: &handler_path(name),
                kind: granary_vfs::NodeKind::Dir,
                exec: false,
            })
            .unwrap();
    }
    let cardinality = backend.overlay_nodes().unwrap().len();
    assert_eq!(cardinality, 6, "fixture cardinality: {cardinality}");
    let result = crate::overlay_store::measure_query(|| backend.overlay_readlink(&path));
    assert_eq!(
        result,
        (Ok(b"../file".to_vec()), (0, 0, 1)),
        "readlink must copy the addressed entry rather than the namespace"
    );
}

fn projection_links(nodes: &[granary_fuse::OverlayNode], node: &granary_fuse::OverlayNode) -> u32 {
    if node.kind != granary_vfs::NodeKind::Dir {
        return 1;
    }
    2 + u32::try_from(
        nodes
            .iter()
            .filter(|child| {
                child.kind == granary_vfs::NodeKind::Dir
                    && child.path.len() == node.path.len() + 1
                    && child.path.starts_with(&node.path)
            })
            .count(),
    )
    .unwrap()
}

#[test]
fn writable_owned_query_seam_matches_whole_tree_projection_without_namespace_copies() {
    use granary_fuse::{MountBackend as _, OverlayMutation as M};
    use granary_vfs::NodeKind;
    let tree = PublishedTree::publish("v");
    let paths = Paths::with_store_base(&runtime_workspace_scratch().unwrap());
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    let backend = proof.backend_for_test();
    for name in [b"directory-a", b"directory-b", b"directory-c"] {
        backend
            .overlay_mutate(M::Create {
                path: &handler_path(name),
                kind: NodeKind::Dir,
                exec: false,
            })
            .unwrap();
    }
    let link = handler_path(b"link");
    let target = granary_core::manifest::SymlinkTarget::new(b"../file".to_vec()).unwrap();
    backend
        .overlay_mutate(M::Symlink {
            path: &link,
            target: &target,
        })
        .unwrap();
    let oracle = backend.overlay_nodes().unwrap();
    assert_eq!(oracle.len(), 6, "fixture cardinality: {}", oracle.len());
    let mut counts = [0; 4];
    for expected in &oracle {
        let nlink = projection_links(&oracle, expected);
        let (result, work) =
            crate::overlay_store::measure_query(|| backend.overlay_path(&expected.path));
        let result = result.unwrap();
        assert_eq!(
            (result.node, result.nlink, work),
            (
                expected.clone(),
                nlink,
                (0, 0, usize::from(!expected.path.is_empty()))
            )
        );
        counts[0] += 1;
        if let Some((name, parent)) = expected.path.split_last() {
            let (result, work) =
                crate::overlay_store::measure_query(|| backend.overlay_lookup(parent, name));
            let result = result.unwrap();
            assert_eq!(
                (result.node, result.nlink, work),
                (expected.clone(), nlink, (0, 0, 1))
            );
            counts[1] += 1;
        }
        if expected.kind == NodeKind::Dir {
            let (result, work) =
                crate::overlay_store::measure_query(|| backend.overlay_directory(&expected.path));
            let directory = result.unwrap();
            assert_eq!(
                (directory.directory.node, directory.directory.nlink, work),
                (
                    expected.clone(),
                    nlink,
                    (0, 0, usize::from(!expected.path.is_empty()))
                )
            );
            let (result, work) =
                crate::overlay_store::measure_query(|| backend.overlay_children(&directory.cursor));
            let page = result.unwrap();
            let expected_children: Vec<_> = oracle
                .iter()
                .filter(|n| {
                    n.path.len() == expected.path.len() + 1 && n.path.starts_with(&expected.path)
                })
                .cloned()
                .collect();
            assert_eq!(
                (
                    page.entries.into_iter().map(|e| e.node).collect::<Vec<_>>(),
                    page.next.is_none(),
                    work
                ),
                (
                    expected_children.clone(),
                    true,
                    (0, 0, expected_children.len())
                )
            );
            counts[2] += 1;
            counts[3] += 1;
        }
    }
    assert_eq!(counts, [6, 5, 4, 4], "owned query route counts: {counts:?}");
    let file = handler_path(b"f.txt");
    let object = backend.overlay_open(&file).unwrap().unwrap();
    let (result, work) = crate::overlay_store::measure_query(|| backend.overlay_object(object));
    assert_eq!((result.unwrap().path, work), (file, (0, 0, 1)));
    backend.overlay_close(object).unwrap();
}

#[test]
fn writable_objects_symlink_capture_target_and_replay() {
    use granary_core::overlay_journal::{CreateKind, Record};
    use granary_fuse::{MountBackend as _, OverlayMutation as M};
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    let base = crate::writable_start::overlay_base(proof.snapshot_for_test()).unwrap();
    let path = handler_path(b"link");
    let target =
        granary_core::manifest::SymlinkTarget::new(b"../secret-shaped-\xff".to_vec()).unwrap();
    let (header, before) = captured_records(&paths, &input);
    proof
        .backend_for_test()
        .overlay_mutate(M::Symlink {
            path: &path,
            target: &target,
        })
        .unwrap();
    let captured = captured_records(&paths, &input).1;
    assert!(
        matches!(&captured[before.len()..], [Record::Create { kind: CreateKind::Symlink { target: t }, at }] if t == &target && at.parent.names().is_empty() && at.name == path[0]),
        "symlink must capture its exact kind, target and location"
    );
    assert_eq!(
        proof.backend_for_test().overlay_readlink(&path).unwrap(),
        target.as_bytes()
    );
    assert_eq!(
        proof.backend_for_test().overlay_mutate(M::Symlink {
            path: &path,
            target: &target
        }),
        Err(granary_fuse::WriteError::Exists)
    );
    let over = granary_core::manifest::SymlinkTarget::new(vec![b'x'; 4096]).unwrap();
    assert_eq!(
        proof.backend_for_test().overlay_mutate(M::Symlink {
            path: &handler_path(b"over"),
            target: &over
        }),
        Err(granary_fuse::WriteError::Invalid)
    );
    assert_eq!(
        captured_records(&paths, &input).1,
        captured,
        "refusals must not append"
    );
    proof
        .mediator_for_test()
        .open_overlay_local(
            header,
            base,
            OverlayDisk::new(&paths.store, input.euid),
            false,
        )
        .unwrap();
    assert_eq!(
        proof.backend_for_test().overlay_readlink(&path).unwrap(),
        target.as_bytes(),
        "replay must retain exact opaque target bytes"
    );
}

#[test]
fn writable_objects_held_reads_span_local_buffers_without_short_reply() {
    use granary_fuse::{MountBackend as _, OverlayMutation as M};
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    let path = handler_path(b"large");
    proof
        .backend_for_test()
        .overlay_mutate(M::Create {
            path: &path,
            kind: granary_vfs::NodeKind::File,
            exec: false,
        })
        .unwrap();
    let id = proof
        .backend_for_test()
        .overlay_open(&path)
        .unwrap()
        .unwrap();
    let bytes: Vec<u8> = (0..70000).map(|n| u8::try_from(n % 251).unwrap()).collect();
    proof
        .backend_for_test()
        .overlay_mutate(M::BoundWrite {
            object: id,
            offset: 0,
            bytes: &bytes,
            append: false,
        })
        .unwrap();
    proof
        .backend_for_test()
        .overlay_mutate(M::Remove {
            path: &path,
            directory: false,
        })
        .unwrap();
    assert_eq!(
        proof.backend_for_test().read_object(id, 0, 16_777_217),
        Err(granary_fuse::WriteError::Invalid),
        "held reads must preserve the immutable reader's bound before clamping to EOF"
    );
    assert_eq!(
        proof
            .backend_for_test()
            .read_object(id, 0, 16_777_216)
            .unwrap()
            .len(),
        70000
    );
    let read = proof
        .backend_for_test()
        .read_object(id, 0, 131_072)
        .unwrap();
    assert_eq!(
        (read.len(), GrainId::of(&read)),
        (70000, GrainId::of(&bytes)),
        "a single local buffer must not become a short FUSE reply"
    );
    assert_eq!(
        proof
            .backend_for_test()
            .read_object(id, 65530, 131_072)
            .unwrap(),
        bytes[65530..]
    );
    proof.backend_for_test().overlay_close(id).unwrap();
}

/// Immediate ESTALE and an unbounded retry loop both fail this exact attempt witness.
#[test]
fn writable_planning_retries_changed_context_and_classifies_exhaustion() {
    use granary_fuse::{MountBackend as _, MountError, WriteError};
    let mut cases = 0;
    for changes in [0, 1, 2, 3] {
        let tree = PublishedTree::publish("v");
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
        let mut proof = result.unwrap();
        let before = captured_records(&paths, &input).1.len();
        let backend = proof.backend_for_test();
        backend.planning_changes_remaining = changes;
        let answer = backend.prepare_overlay(&handler_path(b"f.txt"));
        let wanted = if changes < 3 {
            Ok(())
        } else {
            Err(WriteError::Backend(MountError::PlanningExhausted))
        };
        assert_eq!(
            (answer, backend.planning_attempts),
            (wanted, (changes + 1).min(3)),
            "changed planning context must retry with a finite budget"
        );
        let records = captured_records(&paths, &input).1;
        let injected = &records[before..];
        assert_eq!(injected.len(), changes);
        assert!(
            injected.iter().all(|record| matches!(
                record,
                granary_core::overlay_journal::Record::SetattrExec { .. }
            )),
            "preparation appends only the injected namespace changes"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn writable_statfs_backend_forwards_the_mediated_observation() {
    use granary_fuse::MountBackend as _;
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    let expected = proof
        .mediator_for_test()
        .overlay_transaction(observe_bound_overlay)
        .unwrap();
    let actual = proof.backend_for_test().overlay_capacity();
    assert_eq!(
        actual,
        Ok(granary_fuse::OverlayCapacity {
            cap: expected.cap,
            charged: expected.summary.charged_bytes,
            reserved: expected.summary.reserved_bytes,
            captured: expected.summary.captured_bytes,
            files: expected.namespace_len,
            free_entries: expected.free_entries,
        }),
        "statfs backend must forward the mediated summary"
    );
    assert!(
        actual.unwrap().free_entries > 0,
        "empty-file admission has conservative headroom"
    );
}

#[test]
fn writable_start_applies_the_invocation_overlay_cap() {
    use granary_fuse::MountBackend as _;
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = WritableStart {
        overlay_cap_bytes: 268_435_456,
        ..input(&tree, &paths)
    };
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    assert_eq!(
        proof.backend_for_test().overlay_capacity().unwrap().cap,
        268_435_456
    );
}

#[test]
fn writable_planning_exhaustion_reports_closed_conflict_completion() {
    use granary_fuse::{Callback, CallbackObserver as _, CallbackOutcome, MountError};
    let metrics = crate::metrics::tests::metrics();
    metrics.set_available(crate::MetricsGroup::Fuse, true);
    let observer = crate::mount::FuseObserver {
        writability: granary_fuse::MountWritability::Writable,
        metrics: Some(metrics.clone()),
    };
    let mut cases = 0;
    for format in [crate::LogFormat::Text, crate::LogFormat::Json] {
        let events = Events::default();
        tracing::subscriber::with_default(events.formatted(format), || {
            let _scope = observer.begin(Callback::Write);
            observer.completed(
                Callback::Write,
                CallbackOutcome::from_errno(Some(MountError::PlanningExhausted.errno())),
            );
        });
        let output = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            (
                output.matches("op.failed").count(),
                output.contains("conflict")
            ),
            (1, true),
            "planning exhaustion must remain a conflict: {output}"
        );
        cases += 1;
    }
    let output = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(output.contains("fuse_requests_total{callback=\"write\",outcome=\"failed\"} 2"));
    assert_eq!(cases, 2);
}

/// Replanning by pathname would accept the replacement object's unrelated binding.
#[test]
fn writable_planning_never_retargets_a_recreated_name() {
    use granary_fuse::{MountBackend as _, WriteError};
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    let backend = proof.backend_for_test();
    backend.planning_replace = true;
    let answer = backend.prepare_overlay(&handler_path(b"f.txt"));
    assert_eq!(
        (answer, backend.planning_attempts),
        (Err(WriteError::Missing), 1),
        "recreated path cannot replace the planned inode"
    );
    let replacement = backend
        .overlay_nodes()
        .unwrap()
        .into_iter()
        .find(|node| node.path == handler_path(b"f.txt"))
        .unwrap();
    assert_eq!(
        (replacement.size, replacement.stage.is_some()),
        (0, true),
        "replacement fixture really installed a new staged object"
    );
}

#[test]
fn writable_planning_staged_orphans_need_no_named_replan() {
    use granary_fuse::{MountBackend as _, OverlayMutation as M};
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (result, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = result.unwrap();
    let path = handler_path(b"orphan");
    let backend = proof.backend_for_test();
    backend
        .overlay_mutate(M::Create {
            path: &path,
            kind: granary_vfs::NodeKind::File,
            exec: false,
        })
        .unwrap();
    let object = backend.overlay_open(&path).unwrap().unwrap();
    backend
        .overlay_mutate(M::Remove {
            path: &path,
            directory: false,
        })
        .unwrap();
    let before = captured_records(&paths, &input).1;
    let backend = proof.backend_for_test();
    let answer = backend.prepare_object(object);
    assert_eq!(
        (answer, backend.planning_attempts),
        (Ok(()), 0),
        "held stages need readiness, never a named planning context"
    );
    assert_eq!(backend.read_object(object, 0, 1), Ok(Vec::new()));
    backend.overlay_close(object).unwrap();
    assert_eq!(
        captured_records(&paths, &input).1,
        before,
        "orphan preparation and close append no capture"
    );
}

#[test]
fn writable_fixture_attribute_owner_matches_the_admitted_caller() {
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    assert_eq!(
        (input.policy.uid, input.policy.gid, input.process.ruid),
        (
            input.euid,
            paths.scratch.metadata().unwrap().gid(),
            input.euid
        ),
        "ordinary write-open and chmod need owner DAC before daemon dispatch"
    );
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let attachment = ready.unwrap().attach();
    assert_eq!(attachment.snapshot.policy(), input.policy);
}

#[test]
fn writable_mounted_fixture_has_owned_file_empty_directory_and_exact_symlink() {
    use granary_fuse::MountBackend as _;
    let tree = mounted_operation_tree();
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (ready, state, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut ready = ready.unwrap();
    let nodes = ready.backend_for_test().overlay_nodes().unwrap();
    assert_eq!(
        nodes.len(),
        6,
        "fixture must include both rmdir premises and the unlink symlink"
    );
    for (name, kind, size) in [
        (b"empty".as_slice(), granary_vfs::NodeKind::Dir, 4096),
        (b"original-link", granary_vfs::NodeKind::Symlink, 5),
        (
            b"f.txt",
            granary_vfs::NodeKind::File,
            FILE_CONTENT.len() as u64,
        ),
    ] {
        let node = nodes.iter().find(|n| n.path == handler_path(name)).unwrap();
        assert_eq!((node.kind, node.size), (kind, size));
    }
    assert_eq!(
        ready
            .backend_for_test()
            .overlay_readlink(&handler_path(b"original-link")),
        Ok(b"f.txt".to_vec())
    );
    assert_eq!(ready.snapshot_for_test().policy(), input.policy);
    assert_eq!(state.lock().unwrap().calls[3], 0);
}

fn writable_dac_permissions(status: &str) -> Result<(), &'static str> {
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok());
    if effective.is_some_and(|mask| mask & 2 == 0) {
        Ok(())
    } else {
        Err("DAC witness must lack CAP_DAC_OVERRIDE, with a readable capability field")
    }
}

#[test]
fn writable_dac_permission_fixture_requires_readable_capabilities_without_override() {
    let mut cases = 0;
    for bad in [
        "CapEff:\t0000000000000002\n",
        "CapPrm:\t0000000000000000\n",
        "CapEff:\tinvalid\n",
    ] {
        assert_eq!(
            writable_dac_permissions("CapEff:\t0000000000000000\n"),
            Ok(())
        );
        assert_eq!(
            writable_dac_permissions(bad),
            Err("DAC witness must lack CAP_DAC_OVERRIDE, with a readable capability field")
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

/// Content failures share EIO but retain distinct closed events and failed counters.
#[test]
fn writable_terminal_content_classes_emit_closed_events_and_failed_counters() {
    use granary_fuse::{Callback, CallbackObserver, CallbackOutcome, MountError};
    let metrics = crate::metrics::tests::metrics();
    metrics.set_available(crate::MetricsGroup::Fuse, true);
    let observer = crate::mount::FuseObserver {
        writability: granary_fuse::MountWritability::Writable,
        metrics: Some(metrics.clone()),
    };
    let mut cases = 0;
    for format in [crate::LogFormat::Text, crate::LogFormat::Json] {
        for (cause, class) in [
            (MountError::Corrupt, "corrupt"),
            (MountError::Unavailable, "unavailable"),
            (MountError::Io, "io"),
        ] {
            let events = Events::default();
            tracing::subscriber::with_default(events.formatted(format), || {
                let _scope = observer.begin(Callback::Write);
                observer.completed(Callback::Write, CallbackOutcome::Failed(cause));
            });
            let output = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
            assert_eq!(output.matches("op.failed").count(), 1);
            assert!(
                output.contains(class) && output.contains("overlay_write"),
                "typed closed class {class}: {output}"
            );
            assert_eq!(output.matches("op.begin").count(), 1);
            assert_eq!(output.matches("op.end").count(), 1);
            assert!(!output.contains("token=secret") && !output.contains("caller/path"));
            cases += 1;
        }
    }
    let output = metrics.snapshot().unwrap().render_prometheus().unwrap();
    assert!(output.contains("fuse_requests_total{callback=\"write\",outcome=\"failed\"} 6"));
    assert!(output.contains("fuse_requests_total{callback=\"write\",outcome=\"refused\"} 0"));
    assert!(!output.contains("syncs_total{"));
    assert_eq!(cases, 6);
}

#[test]
fn readonly_callback_observer_counts_without_overlay_events() {
    use granary_fuse::{Callback, CallbackOutcome, MountBackend};
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let metrics = crate::metrics::tests::metrics();
    let state = Arc::new(Mutex::new(AuthorityState::default()));
    let authority = Authority::with_scope_and_rule(&tree, input.scope.clone(), &state, "valid")
        .with_metrics(metrics.clone());
    let session = MountSession::open(
        authority,
        tree.volume.clone(),
        Some(Box::new(*tree.key.public_key())),
        None,
        false,
        Some(1),
        &paths.cache,
        input.cache_quota,
        &input.cache_origin,
        MountOptions::default(),
        &mut Vec::new(),
    )
    .unwrap();
    let observer = session.callback_observer().unwrap();
    let events = Events::default();
    tracing::subscriber::with_default(events.subscriber(), || {
        for (callback, outcome) in [
            (Callback::Open, CallbackOutcome::Ok),
            (Callback::Release, CallbackOutcome::Ok),
            (Callback::Getxattr, CallbackOutcome::Refused),
        ] {
            let _scope = observer.begin(callback);
            observer.completed(callback, outcome);
        }
    });
    let output = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
    assert!(
        !output.contains("overlay_write"),
        "RO probes emitted overlay events: {output}"
    );
    let output = metrics.snapshot().unwrap().render_prometheus().unwrap();
    for counter in [
        "callback=\"open\",outcome=\"ok\"",
        "callback=\"release\",outcome=\"ok\"",
        "callback=\"getxattr\",outcome=\"refused\"",
    ] {
        assert!(output.contains(&format!("fuse_requests_total{{{counter}}} 1")));
    }
}

#[test]
fn writable_content_failure_and_callback_emit_one_terminal_error() {
    use crate::overlay_store::OverlayError;
    use granary_fuse::{Callback, CallbackObserver, CallbackOutcome, MountError, WriteError};
    let mut failures = Vec::new();
    for (case, expected, class) in [
        ("refused", MountError::Access, "refused"),
        ("no_space", MountError::NoSpace, "io"),
        ("poisoned", MountError::Io, "io"),
        ("io", MountError::Io, "io"),
        ("payload", MountError::Unavailable, "unavailable"),
        ("grain", MountError::Unavailable, "unavailable"),
        ("corrupt", MountError::Corrupt, "corrupt"),
    ] {
        let tree = PublishedTree::publish("v");
        let paths = Paths::new();
        let input = input(&tree, &paths);
        let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
        let mut proof = ready.unwrap();
        let metrics = crate::metrics::tests::metrics();
        metrics.set_available(crate::MetricsGroup::Fuse, true);
        let observer = crate::mount::FuseObserver {
            metrics: Some(metrics.clone()),
            writability: granary_fuse::MountWritability::Writable,
        };
        let events = Events::default();
        tracing::subscriber::with_default(events.subscriber(), || {
            let _scope = observer.begin(Callback::Write);
            if case == "grain" {
                let payload = granary_core::manifest::node::file_payload(
                    FILE_CONTENT.len() as u64,
                    &granary_core::manifest::FileGrains::Inline(vec![
                        granary_core::manifest::GrainRef {
                            id: GrainId::of(FILE_CONTENT),
                            unpacked_len: u32::try_from(FILE_CONTENT.len()).unwrap(),
                        },
                    ]),
                )
                .unwrap();
                proof
                    .mediator_for_test()
                    .put_immutable(GrainId::of(&payload), &payload)
                    .unwrap();
            }
            let error = if matches!(case, "refused" | "no_space" | "poisoned" | "io") {
                proof
                    .mediator_for_test()
                    .overlay_transaction::<()>(|_| {
                        Err(match case {
                            "refused" => OverlayError::refused("composed refusal"),
                            "no_space" => OverlayError::no_space(),
                            "poisoned" => OverlayError::poisoned(),
                            _ => io::Error::other("composed I/O").into(),
                        })
                    })
                    .unwrap_err()
            } else if case == "corrupt" {
                proof
                    .mediator_for_test()
                    .put_immutable(GrainId::of(b"expected"), b"wrong")
                    .unwrap_err()
            } else {
                proof
                    .mediator_for_test()
                    .overlay_transaction(|overlay| {
                        overlay.copy_up(granary_core::overlay_journal::Location {
                            parent: granary_core::overlay_journal::Parent::root(),
                            name: granary_core::manifest::Name::new(b"f.txt".to_vec()).unwrap(),
                        })
                    })
                    .unwrap_err()
            };
            let WriteError::Backend(cause) = crate::writable_start::write_error(&error) else {
                panic!("content error lost its class")
            };
            assert_eq!(cause, expected, "{case} lost its terminal class");
            observer.completed(Callback::Write, CallbackOutcome::Failed(cause));
        });
        let output = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
        let count = output.matches("op.failed").count();
        if count != 1 {
            failures.push(format!("{case}: expected one op.failed, got {count}"));
        }
        assert!(output.contains(&format!("\"class\":\"{class}\"")));
        assert_eq!(output.matches("op.begin").count(), 1, "{case}");
        assert_eq!(output.matches("op.end").count(), 1);
        let output = metrics.snapshot().unwrap().render_prometheus().unwrap();
        assert!(output.contains("fuse_requests_total{callback=\"write\",outcome=\"failed\"} 1"));
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
}

#[test]
fn writable_callback_panic_flushes_and_leaves_thread_reporting() {
    use crate::overlay_store::OverlayError;
    use granary_fuse::{Callback, CallbackObserver};
    let observer = crate::mount::FuseObserver {
        metrics: None,
        writability: granary_fuse::MountWritability::Writable,
    };
    for format in [crate::LogFormat::Text, crate::LogFormat::Json] {
        let events = Events::default();
        tracing::subscriber::with_default(events.formatted(format), || {
            let result = std::panic::catch_unwind(|| {
                let _scope = observer.begin(Callback::Write);
                let _handled = OverlayError::no_space();
                let output = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
                assert_eq!(output.matches("op.failed").count(), 0);
                panic!("callback abandonment");
            });
            assert!(result.is_err());
            let _later = OverlayError::refused("after caught callback panic");
        });
        let output = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            output.matches("op.failed").count(),
            2,
            "abandoned and later failures: {output}"
        );
        assert!(
            output.contains("refused")
                && !output.contains("class=io")
                && !output.contains("\"class\":\"io\"")
        );
        assert_eq!(output.matches("op.begin").count(), 1);
        assert_eq!(output.matches("op.end").count(), 1);
        let end = output.lines().find(|line| line.contains("op.end")).unwrap();
        assert!(end.contains("cancelled"), "abandoned outcome: {end}");
        assert!(output.find("op.begin") < output.find("op.failed"));
        assert!(output.find("op.failed") < output.find("op.end"));
    }
}

#[test]
fn writable_callback_other_failure_kinds_emit_immediately() {
    use crate::observe::{FailureClass, OperationKind};
    use granary_fuse::{Callback, CallbackObserver, CallbackOutcome, MountError};
    let observer = crate::mount::FuseObserver {
        metrics: None,
        writability: granary_fuse::MountWritability::Writable,
    };
    for format in [crate::LogFormat::Text, crate::LogFormat::Json] {
        let events = Events::default();
        tracing::subscriber::with_default(events.formatted(format), || {
            let _scope = observer.begin(Callback::Write);
            for kind in OperationKind::ALL
                .iter()
                .copied()
                .filter(|kind| *kind != OperationKind::OverlayWrite)
            {
                crate::observe::op_failed(kind, FailureClass::Unavailable);
            }
            let output = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
            assert_eq!(
                output.matches("op.failed").count(),
                OperationKind::ALL.len() - 1,
                "other kinds must emit before completion: {output}"
            );
            observer.completed(Callback::Write, CallbackOutcome::Failed(MountError::Io));
        });
        let output = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            output.matches("op.failed").count(),
            OperationKind::ALL.len()
        );
    }
}

#[test]
fn writable_callback_handled_store_error_emits_once_on_success() {
    use crate::overlay_store::OverlayError;
    use granary_fuse::{Callback, CallbackObserver, CallbackOutcome};
    let observer = crate::mount::FuseObserver {
        metrics: None,
        writability: granary_fuse::MountWritability::Writable,
    };
    for format in [crate::LogFormat::Text, crate::LogFormat::Json] {
        let events = Events::default();
        tracing::subscriber::with_default(events.formatted(format), || {
            let _scope = observer.begin(Callback::Write);
            let handled = OverlayError::refused("handled store error");
            assert!(matches!(handled, OverlayError::Refused(_)));
            let output = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
            assert_eq!(output.matches("op.failed").count(), 0);
            observer.completed(Callback::Write, CallbackOutcome::Ok);
        });
        let output = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            output.matches("op.failed").count(),
            1,
            "handled store error: {output}"
        );
        assert!(output.contains("overlay_write") && output.contains("refused"));
        assert_eq!(output.matches("op.begin").count(), 1);
        assert_eq!(output.matches("op.end").count(), 1);
        assert!(output.contains("ok"));
    }
}

#[test]
fn writable_store_failures_outside_callback_keep_one_error() {
    use crate::overlay_store::OverlayError;
    use granary_fuse::{Callback, CallbackObserver, CallbackOutcome};
    type MakeError = fn() -> OverlayError;
    let observer = crate::mount::FuseObserver {
        metrics: None,
        writability: granary_fuse::MountWritability::Writable,
    };
    let errors: [(MakeError, &str); 4] = [
        (|| OverlayError::refused("standalone refusal"), "refused"),
        (OverlayError::no_space, "refused"),
        (OverlayError::poisoned, "io"),
        (|| io::Error::other("standalone I/O").into(), "io"),
    ];
    for (make_error, class) in errors {
        for format in [crate::LogFormat::Text, crate::LogFormat::Json] {
            // Mount-start replay and CLI have no callback. Sync runs on its
            // own thread, even while a callback owns a report on this thread.
            let events = Events::default();
            tracing::subscriber::with_default(events.formatted(format), || {
                let _scope = observer.begin(Callback::Write);
                std::thread::scope(|scope| {
                    scope
                        .spawn(|| {
                            tracing::subscriber::with_default(events.formatted(format), || {
                                make_error();
                            });
                        })
                        .join()
                        .unwrap();
                });
                observer.completed(Callback::Write, CallbackOutcome::Ok);
            });
            let output = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
            assert_eq!(output.matches("op.failed").count(), 1, "{output}");
            assert!(output.contains(class) && output.contains("overlay_write"));
            assert_eq!(output.matches("op.end").count(), 1);

            for after_callback in [false, true] {
                let events = Events::default();
                tracing::subscriber::with_default(events.formatted(format), || {
                    if after_callback {
                        let _scope = observer.begin(Callback::Write);
                        observer.completed(Callback::Write, CallbackOutcome::Ok);
                    }
                    make_error();
                });
                let output = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
                assert_eq!(output.matches("op.failed").count(), 1, "{output}");
                assert!(output.contains(class) && output.contains("overlay_write"));
                assert_eq!(
                    output.matches("op.end").count(),
                    usize::from(after_callback)
                );
            }
        }
    }
}

fn capture_kinds(records: &[granary_core::overlay_journal::Record]) -> Vec<&'static str> {
    use granary_core::overlay_journal::{CreateKind, DeleteKind, Record};
    records
        .iter()
        .map(|r| match r {
            Record::Create {
                kind: CreateKind::File { .. },
                ..
            } => "file",
            Record::Create {
                kind: CreateKind::Dir,
                ..
            } => "directory",
            Record::Create {
                kind: CreateKind::Symlink { .. },
                ..
            } => "symlink",
            Record::StageBind { .. } => "bind",
            Record::WriteExtent { .. } => "write",
            Record::Truncate { .. } => "truncate",
            Record::Delete {
                kind: DeleteKind::Dir,
                ..
            } => "rmdir",
            Record::Delete { .. } => "unlink",
            Record::Move { .. } => "move",
            Record::Replace { .. } => "replace",
            Record::SetattrExec { .. } => "exec",
            _ => "unexpected",
        })
        .collect()
}

#[test]
fn writable_capture_window_preserves_readiness_witness() {
    use granary_core::overlay_journal::{IntentCause, Record};
    use granary_fuse::{MountBackend, OverlayMutation as M};
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let input = input(&tree, &paths);
    let (ready, _, _) = attempt(&input, &tree, "valid", &Events::default());
    let mut proof = ready.unwrap();
    let before = captured_records(&paths, &input).1;
    assert!(matches!(
        before.as_slice(),
        [Record::IntentRegistered {
            cause: IntentCause::DirectorySync,
            ..
        }]
    ));
    let path = vec![granary_core::manifest::Name::new(b"new".to_vec()).unwrap()];
    proof
        .backend_for_test()
        .overlay_mutate(M::Create {
            path: &path,
            kind: granary_vfs::NodeKind::File,
            exec: false,
        })
        .unwrap();
    let records = captured_records(&paths, &input).1;
    assert_eq!(&records[..before.len()], &before);
    assert_eq!(capture_kinds(&records[before.len()..]), vec!["file"]);
}

fn dac_child_root() -> std::path::PathBuf {
    runtime_workspace_scratch().unwrap()
}

fn dac_child_paths() -> (std::path::PathBuf, std::path::PathBuf) {
    let base = dac_child_root();
    let home = base.join(format!("dac-child-{}", std::process::id()));
    (base, home)
}

fn dac_chain_traversable(path: &Path, uid: u32, gid: u32) -> bool {
    path.ancestors().all(|ancestor| {
        let Ok(metadata) = ancestor.metadata() else {
            return false;
        };
        let execute = if metadata.uid() == uid {
            0o100
        } else if metadata.gid() == gid {
            0o010
        } else {
            0o001
        };
        metadata.is_dir() && metadata.mode() & execute != 0
    })
}

#[test]
fn dac_child_scratch_stays_in_target() {
    let source = include_str!("writable/mounted.rs");
    assert!(
        source.contains("let (base, home) = dac_child_paths();"),
        "mounted DAC child must use the tested base/HOME decision"
    );
    let (base, home) = dac_child_paths();
    let target = runtime_workspace_scratch().unwrap();
    assert_eq!(base, target);
    assert_eq!(home.parent(), Some(target.as_path()));
    assert_eq!(
        home.file_name().unwrap(),
        std::ffi::OsStr::new(&format!("dac-child-{}", std::process::id()))
    );
}

#[test]
fn dac_traversal_rejects_private_ancestors() {
    let paths = Paths::new();
    let nested = paths.scratch.join("private-parent/child");
    std::fs::create_dir_all(&nested).unwrap();
    let uid = paths.scratch.metadata().unwrap().uid();
    let gid = paths.scratch.metadata().unwrap().gid();
    assert!(dac_chain_traversable(&nested, uid, gid));
    std::fs::set_permissions(
        nested.parent().unwrap(),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(!dac_chain_traversable(nested.parent().unwrap(), uid, gid));
    std::fs::set_permissions(
        nested.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(dac_chain_traversable(&nested, uid, gid));
}

fn prepared_entries(
    state: &Arc<Mutex<AuthorityState>>,
    content: &impl crate::SyncContent,
    volume: &VolumeName,
) -> Vec<granary_core::manifest::DirEntry> {
    let request = state.lock().unwrap().sends.last().unwrap().clone();
    let registration = intent::decode_register(&request, volume, |_, _| true).unwrap();
    let root = granary_core::root::decode_root(registration.root).unwrap();
    let bytes = content.get(&root.manifest_root).unwrap();
    let (_, cursor) = granary_core::encoding::open_envelope(&bytes).unwrap();
    granary_core::manifest::decode_dir_leaf(cursor).unwrap()
}

fn prepared_bytes(
    state: &Arc<Mutex<AuthorityState>>,
    content: &impl crate::SyncContent,
    volume: &VolumeName,
    name: &[u8],
    runtime: &tokio::runtime::Runtime,
) -> Vec<u8> {
    use crate::SyncRuntime as _;
    use granary_core::grainsource::GrainSource as _;

    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let _entered = runtime.enter();
            let content = content.with_deadline(
                Arc::new(crate::TokioSyncRuntime),
                crate::TokioSyncRuntime.now() + std::time::Duration::from_secs(5),
            );
            let entries = prepared_entries(state, &content, volume);
            let entry = entries
                .iter()
                .find(|entry| entry.name.as_bytes() == name)
                .unwrap();
            let granary_core::manifest::EntryKind::File {
                grains: granary_core::manifest::FileGrains::Inline(refs),
                ..
            } = &entry.kind
            else {
                panic!("expected inline file: {entry:?}");
            };
            refs.iter()
                .flat_map(|grain| content.get(&grain.id).unwrap())
                .collect()
        });
        // Keep a current-thread scheduler driving remote reads while the
        // scoped worker performs the provider's blocking reads.
        runtime.block_on(async {
            while !worker.is_finished() {
                tokio::task::yield_now().await;
            }
        });
        worker.join().unwrap()
    })
}

#[derive(Default)]
struct FastWaitRuntime;
impl crate::SyncRuntime for FastWaitRuntime {
    fn now(&self) -> tokio::time::Instant {
        crate::TokioSyncRuntime.now()
    }
    fn spawn<T: Send + 'static>(
        &self,
        work: impl std::future::Future<Output = T> + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        crate::TokioSyncRuntime.spawn(work)
    }
    fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        crate::TokioSyncRuntime.blocking(work)
    }
    fn blocking_async<T: Send + 'static, F: std::future::Future<Output = T> + Send + 'static>(
        &self,
        work: impl FnOnce() -> F + Send + 'static,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        crate::TokioSyncRuntime.blocking_async(work)
    }
    fn sleep(&self, duration: std::time::Duration) -> impl std::future::Future<Output = ()> + Send {
        // A short wait keeps a twentieth of its length rather than none, so a
        // bounded backoff, such as a commit's drain of in-flight
        // registrations, still gives concurrent work real time to finish.
        let scaled = if duration == crate::fetcher::UNAVAILABLE_RETRY_DELAY {
            duration
        } else if duration <= std::time::Duration::from_secs(5) {
            duration / 20
        } else {
            duration
        };
        crate::TokioSyncRuntime.sleep(scaled)
    }
    fn timeout_at<T: Send>(
        &self,
        deadline: tokio::time::Instant,
        work: impl std::future::Future<Output = T> + Send,
    ) -> impl std::future::Future<Output = Result<T, crate::SyncRuntimeError>> + Send {
        crate::TokioSyncRuntime.timeout_at(deadline, work)
    }
}

fn drive_real_landing<R, S, E>(
    engine: &Arc<crate::SyncEngine<OverlayDisk, R, S, Time, crate::InstantClock, E>>,
    mediator: &crate::SharedWritableStore<OverlayDisk>,
    tree: &PublishedTree,
) -> GrainId
where
    R: crate::SyncRemote + RootStore + 'static,
    S: crate::SyncContent + 'static,
    E: crate::SyncRuntime + 'static,
{
    use granary_core::retained_submission::{
        Candidate, Completion, Evidence, FrozenIntent, Phase, RequestIdentity, Role, Submission,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(async {
            let (bytes, scope, writer) = mediator
                .with(|local| {
                    Ok((
                        local.snapshot().root.clone(),
                        local.snapshot().scope.clone(),
                        local.writer_uuid(),
                    ))
                })
                .unwrap();
            let doc = granary_core::root::decode_root(&bytes).unwrap();
            let landed_root = GrainId::of(&bytes);
            let entries = mediator
                .overlay_transaction(queries::query_fixture_entries)
                .unwrap();
            let capture = engine.begin_commit(crate::SyncOptions::default()).await?;
            let request = RequestIdentity {
                epoch: [3; 16],
                operation: [4; 16],
            };
            let record = Submission {
                generation: 1,
                publication_id: [8; 16],
                scope,
                volume: doc.volume.clone(),
                frozen: FrozenIntent {
                    writer_identity: writer,
                    min_prefix_bits: 0,
                    initial_root: bytes.clone(),
                },
                current: Some(request),
                candidates: vec![Candidate {
                    number: 1,
                    role: Role::Active,
                    request,
                    seq: doc.seq,
                    id: landed_root,
                    root: bytes.clone(),
                    evidence: Evidence::default(),
                }],
                phase: Phase::Ready,
                last_response: None,
                unavailable_exemptions: 0,
            };
            let lane = engine.retain_commit(capture, &record).await?;
            let mut done = record;
            done.phase = Phase::Complete(Completion {
                seq: doc.seq,
                id: landed_root,
                root: bytes.clone(),
                receipt: None,
            });
            done.current = None;
            done.generation += 1;
            mediator
                .with(|local| local.publication_transaction(|j| j.replace(1, &done)))
                .unwrap();
            remote_handle(&tree.mem)
                .put_root(doc.volume.as_str(), doc.seq, bytes)
                .await
                .unwrap();
            engine
                .finish_landed_commit(
                    &lane,
                    crate::LandedProof {
                        boundary_seq: lane.boundary_seq(),
                        landed_root,
                        landed_seq: doc.seq,
                        captured_entries: entries.clone(),
                        entries,
                    },
                    crate::SyncOptions::default(),
                )
                .await?;
            Ok::<_, crate::CoordinationError>(landed_root)
        })
        .unwrap()
}

#[test]
fn pending_setattr_observer_waits_for_actual_result() {
    use granary_fuse::{Callback, CallbackObserver, CallbackOutcome, MountError};
    for outcome in [
        Some(CallbackOutcome::Ok),
        Some(CallbackOutcome::Failed(MountError::Io)),
        None,
    ] {
        let events = Events::default();
        tracing::subscriber::with_default(events.formatted(crate::LogFormat::Json), || {
            let observer = crate::mount::FuseObserver {
                writability: granary_fuse::MountWritability::Writable,
                metrics: None,
            };
            let scope = observer.begin(Callback::Setattr);
            let deferred = observer.captured(Callback::Setattr);
            drop(scope);
            let before = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
            assert_eq!(
                before.matches("op.end").count(),
                0,
                "pending setattr reported a terminal outcome before its retry: {before}"
            );
            let deferred = deferred.expect("pending observation must be owned across retry");
            if let Some(outcome) = outcome {
                deferred.completed(outcome);
            } else {
                drop(deferred);
            }
        });
        let text = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
        let ends: Vec<_> = text
            .lines()
            .filter(|line| line.contains("op.end"))
            .collect();
        let expected = match outcome {
            Some(CallbackOutcome::Ok) => "ok",
            Some(_) => "failed",
            None => "cancelled",
        };
        assert_eq!(
            (
                ends.len(),
                ends.first()
                    .is_some_and(|line| line.contains(&format!("\"outcome\":\"{expected}\"")))
            ),
            (1, true),
            "deferred observation: {text}"
        );
    }
}

#[test]
fn sync_write_observer_ends_overlay_scope_before_dispatch_and_counts_one_completion() {
    use granary_fuse::{Callback, CallbackObserver, CallbackOutcome, MountError};
    for (outcome, metric_label) in [
        (CallbackOutcome::Ok, "ok"),
        (CallbackOutcome::Failed(MountError::Io), "failed"),
        (CallbackOutcome::Cancelled, "cancelled"),
    ] {
        let events = Events::default();
        let metrics = crate::metrics::tests::metrics();
        metrics.set_available(crate::MetricsGroup::Fuse, true);
        tracing::subscriber::with_default(events.formatted(crate::LogFormat::Json), || {
            let observer = crate::mount::FuseObserver {
                writability: granary_fuse::MountWritability::Writable,
                metrics: Some(metrics.clone()),
            };
            let scope = observer.begin(Callback::Write);
            let deferred = observer.captured(Callback::Write);
            drop(scope);
            let before_dispatch = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
            let pre_ends: Vec<_> = before_dispatch
                .lines()
                .filter(|line| line.contains("op.end"))
                .collect();
            assert_eq!(
                (
                    deferred.is_none(),
                    before_dispatch.matches("op.begin").count(),
                    pre_ends.len(),
                    pre_ends
                        .first()
                        .is_some_and(|line| line.contains("\"outcome\":\"ok\"")),
                ),
                (true, 1, 1, true),
                "captured write must end its local overlay_write scope on the worker before dispatch: {before_dispatch}"
            );
            observer.deferred_completed(Callback::Write, outcome);
        });
        let text = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
        let rendered = metrics.snapshot().unwrap().render_prometheus().unwrap();
        assert_eq!(
            (
                text.matches("op.begin").count(),
                text.matches("op.end").count(),
                rendered.contains(&format!(
                    "fuse_requests_total{{callback=\"write\",outcome=\"{metric_label}\"}} 1"
                )),
            ),
            (1, 1, true),
            "deferred completion must not emit a second overlay_write scope and must count one FUSE completion: {text}\n{rendered}"
        );
    }
}
