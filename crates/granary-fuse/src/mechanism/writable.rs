// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Mutable adapter mechanism witnesses; real persisted capture lives in client rows.

use super::*;
use crate::{OverlayMutation as M, OverlayNode, WriteError as E};

mod endings;
mod indexed;

#[derive(Debug)]
struct Backend {
    nodes: BTreeMap<Vec<Name>, OverlayNode>,
    targets: BTreeMap<Vec<Name>, Vec<u8>>,
    captures: Arc<Mutex<Vec<&'static str>>>,
    query_calls: Arc<Mutex<(usize, usize)>>,
    /// How many times `destroy` ran the backend's shutdown.
    shutdowns: Arc<AtomicU32>,
}

fn path(name: &[u8]) -> Vec<Name> {
    vec![Name::new(name.to_vec()).unwrap()]
}

impl GrainFetch for Backend {
    fn grain(&mut self, _: &GrainId, _: u32) -> Result<Vec<u8>, GrainUnavailable> {
        Err(GrainUnavailable::new("unused opcode fixture content"))
    }
}
impl MountBackend for Backend {
    type DirectoryCursor = crate::test_queries::Cursor;
    fn overlay_path(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<crate::OverlayMetadata, crate::WriteError> {
        crate::test_queries::path(&self.nodes, path)
    }
    fn overlay_lookup(
        &mut self,
        parent: &[granary_core::manifest::Name],
        name: &granary_core::manifest::Name,
    ) -> Result<crate::OverlayMetadata, crate::WriteError> {
        crate::test_queries::lookup(&self.nodes, parent, name)
    }
    fn overlay_directory(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<crate::OverlayDirectory<Self::DirectoryCursor>, crate::WriteError> {
        crate::test_queries::directory(&self.nodes, path)
    }
    fn overlay_children(
        &mut self,
        cursor: &Self::DirectoryCursor,
    ) -> Result<crate::OverlayChildren<Self::DirectoryCursor>, crate::WriteError> {
        self.query_calls.lock().unwrap().1 += 1;
        crate::test_queries::children(&self.nodes, cursor)
    }

    fn overlay_capacity(&mut self) -> Result<crate::OverlayCapacity, E> {
        Err(E::Unimplemented)
    }
    fn prepare_shrink_retry(
        &mut self,
        _request: crate::MountShrinkRequest,
    ) -> Result<Box<dyn crate::MountSyncJob>, crate::MountSyncError> {
        Err(crate::MountSyncError::InvalidRequest)
    }

    fn prepare_sync(
        &mut self,
        _request: crate::MountSyncRequest,
    ) -> Result<Box<dyn crate::MountSyncJob>, crate::MountSyncError> {
        Err(crate::MountSyncError::InvalidRequest)
    }

    fn overlay_open(&mut self, _path: &[granary_core::manifest::Name]) -> Result<Option<u64>, E> {
        Ok(None)
    }
    fn overlay_object(&mut self, _object: u64) -> Result<OverlayNode, E> {
        Err(E::Unimplemented)
    }
    fn overlay_close(&mut self, _object: u64) -> Result<(), E> {
        Err(E::Unimplemented)
    }
    fn prepare_object(&mut self, _object: u64) -> Result<(), E> {
        Err(E::Unimplemented)
    }
    fn prepare_detach(&mut self, _path: &[granary_core::manifest::Name]) -> Result<(), E> {
        Ok(())
    }
    fn read_object(&mut self, _object: u64, _offset: u64, _length: usize) -> Result<Vec<u8>, E> {
        Err(E::Unimplemented)
    }
    fn prepare_overlay(&mut self, _path: &[granary_core::manifest::Name]) -> Result<(), E> {
        Ok(())
    }

    fn mutation_readiness(&mut self) -> Result<(), crate::MountError> {
        Ok(())
    }
    fn overlay_nodes(&mut self) -> Result<Vec<OverlayNode>, E> {
        self.query_calls.lock().unwrap().0 += 1;
        Ok(self.nodes.values().cloned().collect())
    }
    fn overlay_readlink(&mut self, path: &[Name]) -> Result<Vec<u8>, E> {
        self.targets.get(path).cloned().ok_or(E::Missing)
    }
    fn overlay_setattr(
        &mut self,
        path: &[granary_core::manifest::Name],
        size: Option<u64>,
        exec: Option<bool>,
    ) -> Result<crate::OverlayMetadata, crate::WriteError> {
        if size.is_some() {
            self.prepare_overlay(path)?;
        }
        self.overlay_mutate(crate::OverlayMutation::Setattr { path, size, exec })?;
        self.overlay_path(path)
    }
    fn overlay_mutate(&mut self, operation: M<'_>) -> Result<(), E> {
        let capture = match operation {
            M::Create { path, kind, exec } => {
                if self.nodes.contains_key(path) {
                    return Err(E::Exists);
                }
                self.nodes.insert(
                    path.to_vec(),
                    OverlayNode {
                        path: path.to_vec(),
                        kind,
                        exec,
                        size: if kind == NodeKind::Dir { 4096 } else { 0 },
                        stage: None,
                    },
                );
                "create"
            }
            M::Symlink { path, target } => {
                self.targets
                    .insert(path.to_vec(), target.as_bytes().to_vec());
                self.nodes.insert(
                    path.to_vec(),
                    OverlayNode {
                        path: path.to_vec(),
                        kind: NodeKind::Symlink,
                        exec: false,
                        size: u64::from(target.wire_len()),
                        stage: None,
                    },
                );
                "symlink"
            }
            M::Remove { path, directory } => {
                let node = self.nodes.get(path).ok_or(E::Missing)?;
                if directory && node.kind != NodeKind::Dir {
                    return Err(E::NotDirectory);
                }
                if directory
                    && self
                        .nodes
                        .keys()
                        .any(|p| p.len() > path.len() && p.starts_with(path))
                {
                    return Err(E::NotEmpty);
                }
                self.nodes.remove(path);
                "delete"
            }
            M::Rename {
                from,
                to,
                no_replace,
            } => {
                if !self.nodes.contains_key(from) {
                    return Err(E::Missing);
                }
                if no_replace && self.nodes.contains_key(to) {
                    return Err(E::Exists);
                }
                if from == to {
                    return Ok(());
                }
                let mut node = self.nodes.remove(from).unwrap();
                node.path = to.to_vec();
                self.nodes.insert(to.to_vec(), node);
                "move"
            }
            M::Setattr { path, size, exec } => {
                let node = self.nodes.get_mut(path).ok_or(E::Missing)?;
                if let Some(size) = size {
                    node.size = size;
                }
                if let Some(exec) = exec {
                    node.exec = exec;
                }
                "setattr"
            }
            _ => return Err(E::Unimplemented),
        };
        self.captures.lock().unwrap().push(capture);
        Ok(())
    }
    fn shutdown(&mut self) -> Result<(), String> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn abandon(&mut self) {}
}

fn fixture() -> (Snapshot, Backend, Arc<Mutex<Vec<&'static str>>>) {
    let (snapshot, _) = refusal_fixture();
    let captures = Arc::new(Mutex::new(Vec::new()));
    let mut nodes = BTreeMap::new();
    for (key, kind, size) in [
        (vec![], NodeKind::Dir, 4096),
        (path(N_FILE), NodeKind::File, 16),
        (path(N_FRAG), NodeKind::File, 8192),
        (path(N_ABSENT_GRAIN), NodeKind::File, 16),
        (path(N_DIR), NodeKind::Dir, 4096),
        (
            vec![
                Name::new(N_DIR.to_vec()).unwrap(),
                Name::new(N_INNER.to_vec()).unwrap(),
            ],
            NodeKind::File,
            0,
        ),
        (path(N_LOOP), NodeKind::Symlink, 4),
    ] {
        nodes.insert(
            key.clone(),
            OverlayNode {
                path: key,
                kind,
                size,
                exec: false,
                stage: None,
            },
        );
    }
    (
        snapshot,
        Backend {
            nodes,
            targets: [(path(N_LOOP), N_LOOP.to_vec())].into_iter().collect(),
            captures: captures.clone(),
            query_calls: Arc::new(Mutex::new((0, 0))),
            shutdowns: Arc::default(),
        },
        captures,
    )
}

fn drive_regular(mountpoint: &Path) -> Driven {
    rx_outcome(rustix::fs::mknodat(
        rustix::fs::CWD,
        at(mountpoint, N_NEW),
        rustix::fs::FileType::RegularFile,
        rustix::fs::Mode::from_raw_mode(0o644),
        0,
    ))
}
fn drive_empty_dir(mountpoint: &Path) -> Driven {
    std::fs::create_dir(at(mountpoint, N_NEW)).unwrap();
    io_outcome(std::fs::remove_dir(at(mountpoint, N_NEW)))
}
fn drive_exec(mountpoint: &Path) -> Driven {
    io_outcome(std::fs::set_permissions(
        at(mountpoint, N_FILE),
        std::fs::Permissions::from_mode(0o755),
    ))
}
fn drive_noop(mountpoint: &Path) -> Driven {
    io_outcome(std::fs::set_permissions(
        at(mountpoint, N_FILE),
        std::fs::Permissions::from_mode(0o644),
    ))
}
fn drive_noreplace_roundtrip(mountpoint: &Path) -> Driven {
    let first = rx_outcome(rustix::fs::renameat_with(
        rustix::fs::CWD,
        at(mountpoint, N_FILE),
        rustix::fs::CWD,
        at(mountpoint, N_NEW),
        rustix::fs::RenameFlags::NOREPLACE,
    ));
    // The first rename removed N_FILE: the reverse target is absent too.
    assert!(!at(mountpoint, N_FILE).exists());
    let second = rx_outcome(rustix::fs::renameat_with(
        rustix::fs::CWD,
        at(mountpoint, N_NEW),
        rustix::fs::CWD,
        at(mountpoint, N_FILE),
        rustix::fs::RenameFlags::NOREPLACE,
    ));
    Driven {
        first: Some(first.outcome),
        outcome: second.outcome,
    }
}
fn drive_noreplace_existing(mountpoint: &Path) -> Driven {
    twice(|| {
        rx_outcome(rustix::fs::renameat_with(
            rustix::fs::CWD,
            at(mountpoint, N_FILE),
            rustix::fs::CWD,
            at(mountpoint, N_FRAG),
            rustix::fs::RenameFlags::NOREPLACE,
        ))
    })
}

fn drive_exchange(mountpoint: &Path) -> Driven {
    rx_outcome(rustix::fs::renameat_with(
        rustix::fs::CWD,
        at(mountpoint, N_FILE),
        rustix::fs::CWD,
        at(mountpoint, N_FRAG),
        rustix::fs::RenameFlags::EXCHANGE,
    ))
}
fn drive_whiteout(mountpoint: &Path) -> Driven {
    rx_outcome(rustix::fs::renameat_with(
        rustix::fs::CWD,
        at(mountpoint, N_FILE),
        rustix::fs::CWD,
        at(mountpoint, N_FRAG),
        rustix::fs::RenameFlags::WHITEOUT,
    ))
}
fn drive_fallocate_twice(mountpoint: &Path) -> Driven {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(at(mountpoint, N_FILE))
        .unwrap();
    twice(|| {
        rx_outcome(rustix::fs::fallocate(
            &file,
            rustix::fs::FallocateFlags::empty(),
            0,
            4096,
        ))
    })
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Create,
    Regular,
    Mkdir,
    Unlink,
    Rename,
    Truncate,
    Symlink,
    Nonempty,
    Empty,
    Exec,
    Noop,
    Noreplace,
    Existing,
    Exchange,
    Whiteout,
    Fallocate,
}

type CaseSpec = (
    fn(&Path) -> Driven,
    Op,
    crate::Callback,
    Outcome,
    u64,
    Vec<&'static str>,
);

fn one(
    drive: fn(&Path) -> Driven,
    op: Op,
    callback: crate::Callback,
    capture: &'static str,
) -> CaseSpec {
    (drive, op, callback, Outcome::Success, 1, vec![capture])
}

impl Case {
    fn spec(self) -> CaseSpec {
        use crate::Callback as C;
        match self {
            Self::Create => one(drive_creat_new, Op::Create, C::Create, "create"),
            Self::Regular => one(drive_regular, Op::Mknod, C::Mknod, "create"),
            Self::Mkdir => one(drive_mkdir_new, Op::Mkdir, C::Mkdir, "create"),
            Self::Unlink => one(drive_unlink_file, Op::Unlink, C::Unlink, "delete"),
            Self::Rename => one(drive_rename_file_to_new, Op::Rename, C::Rename, "move"),
            Self::Truncate => one(drive_truncate_file, Op::Setattr, C::Setattr, "setattr"),
            Self::Symlink => one(drive_symlink_new, Op::Symlink, C::Symlink, "symlink"),
            Self::Exec => one(drive_exec, Op::Setattr, C::Setattr, "setattr"),
            Self::Nonempty => (
                drive_rmdir_dir,
                Op::Rmdir,
                C::Rmdir,
                Outcome::Errno(Errno::NOTEMPTY),
                1,
                vec![],
            ),
            Self::Empty => (
                drive_empty_dir,
                Op::Rmdir,
                C::Rmdir,
                Outcome::Success,
                1,
                vec!["create", "delete"],
            ),
            Self::Noop => (
                drive_noop,
                Op::Setattr,
                C::Setattr,
                Outcome::Success,
                1,
                vec![],
            ),
            Self::Noreplace => (
                drive_noreplace_roundtrip,
                Op::Rename,
                C::Rename,
                Outcome::Success,
                2,
                vec!["move", "move"],
            ),
            Self::Exchange => (
                drive_exchange,
                Op::Rename,
                C::Rename,
                Outcome::Errno(Errno::OPNOTSUPP),
                1,
                vec![],
            ),
            Self::Whiteout => (
                drive_whiteout,
                Op::Rename,
                C::Rename,
                Outcome::Errno(Errno::OPNOTSUPP),
                1,
                vec![],
            ),
            Self::Fallocate => (
                drive_fallocate_twice,
                Op::Fallocate,
                C::Fallocate,
                Outcome::Errno(Errno::OPNOTSUPP),
                2,
                vec![],
            ),
            Self::Existing => (
                drive_noreplace_existing,
                Op::Rename,
                C::Rename,
                Outcome::Errno(Errno::EXIST),
                0,
                vec![],
            ),
        }
    }
    fn state(self, mountpoint: &Path) {
        let names = observe_root_names(mountpoint);
        let mut expected: BTreeSet<_> = FIXTURE_ROOT_NAMES.iter().map(|n| n.to_vec()).collect();
        match self {
            Self::Create | Self::Regular | Self::Mkdir | Self::Symlink => {
                expected.insert(N_NEW.to_vec());
            }
            Self::Unlink => {
                expected.remove(N_FILE);
            }
            Self::Rename => {
                expected.remove(N_FILE);
                expected.insert(N_NEW.to_vec());
            }
            _ => (),
        }
        assert_eq!(names, expected, "live namespace: {self:?}");
        match self {
            Self::Create | Self::Regular => {
                assert_eq!(std::fs::metadata(at(mountpoint, N_NEW)).unwrap().len(), 0);
            }
            Self::Mkdir => assert!(std::fs::metadata(at(mountpoint, N_NEW)).unwrap().is_dir()),
            Self::Symlink => assert_eq!(
                std::fs::read_link(at(mountpoint, N_NEW)).unwrap(),
                PathBuf::from("file")
            ),
            Self::Truncate => {
                assert_eq!(std::fs::metadata(at(mountpoint, N_FILE)).unwrap().len(), 0);
            }
            Self::Exec => assert_eq!(
                std::fs::metadata(at(mountpoint, N_FILE)).unwrap().mode() & 0o777,
                0o755
            ),
            Self::Noop => assert_eq!(
                std::fs::metadata(at(mountpoint, N_FILE)).unwrap().mode() & 0o777,
                0o644
            ),
            Self::Rename => assert_eq!(std::fs::metadata(at(mountpoint, N_NEW)).unwrap().len(), 16),
            _ => (),
        }
    }
}

fn run(case: Case, name: &str) {
    if !require_root(name) {
        return;
    }
    let (snapshot, backend, captures) = fixture();
    let replies = Arc::new(TerminalReplies::default());
    let observer = Arc::new(Obs::new());
    let mut inner =
        GranaryFs::new(snapshot, backend, 1, crate::MountWritability::Writable).unwrap();
    inner.observer_for_test(replies.clone());
    let fs = Observed {
        inner,
        obs: observer.clone(),
        negotiate: true,
        expected_children: BTreeSet::new(),
    };
    let (mountpoint, guard) = spawn_guarded(name, fs, crate::writable_session_config());
    let (drive, op, callback, outcome, count, expected_capture) = case.spec();
    let driven = drive(&mountpoint);
    let state = observer.lock().clone();
    let layer = if matches!(case, Case::Existing) {
        // The VFS holds a positive target dentry and answers EEXIST itself.
        Layer::KernelPrecedence
    } else {
        Layer::DaemonHandler
    };
    let mut expected = Expect {
        outcome,
        ..succeeds(layer)
    }
    .with_ops(&[(op, Count::Exactly(count))]);
    if matches!(case, Case::Create) {
        expected = expected.with_ops(&[(Op::Mknod, ZERO), (Op::Open, ZERO)]);
    }
    let context = describe(name, Mode::NoRo, &expected, driven, &state);
    eprintln!("OBS {context}");
    check_expect(
        &context,
        &expected,
        driven,
        if driven.first.is_some() { 2 } else { 1 },
        &state,
    );
    let terminal = if outcome == Outcome::Success {
        crate::CallbackOutcome::Ok
    } else {
        crate::CallbackOutcome::Refused
    };
    assert_eq!(
        (
            replies
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|(c, o)| *c == callback && *o == terminal)
                .count(),
            captures.lock().unwrap().clone()
        ),
        (usize::try_from(count).unwrap(), expected_capture),
        "terminal/capture: {context}"
    );
    case.state(&mountpoint);
    guard.teardown();
}

macro_rules! rows { ($($name:ident => $case:ident;)+) => { $(#[test] fn $name() { run(Case::$case, stringify!($name)); })+ }; }
rows! {
    writable_linux_create_opcode_without_fallback => Create;
    writable_linux_regular_mknod_opcode_and_state => Regular;
    writable_linux_mkdir_opcode_and_state => Mkdir;
    writable_linux_unlink_opcode_and_state => Unlink;
    writable_linux_rename_opcode_and_state => Rename;
    writable_linux_truncate_opcode_and_state => Truncate;
    writable_linux_symlink_opcode_and_state => Symlink;
    writable_linux_nonempty_rmdir_opcode_and_refusal => Nonempty;
    writable_linux_empty_rmdir_opcode_and_state => Empty;
    writable_linux_exec_chmod_opcode_and_state => Exec;
    writable_linux_canonical_chmod_opcode_without_capture => Noop;
    writable_linux_noreplace_roundtrip_has_two_dispatches => Noreplace;
    writable_linux_noreplace_existing_has_two_refusals => Existing;
    writable_linux_exchange_refusal_has_dispatch => Exchange;
    writable_linux_whiteout_refusal_has_dispatch => Whiteout;
    writable_linux_fallocate_repeated_refusal_has_two_dispatches => Fallocate;
}
