// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]
#![cfg(target_os = "linux")]

//! Opcode and cookie witnesses for writable directory query dispatch.

use super::*;

fn mount_fixture(name: &str, fs: Observed<Backend>) -> (PathBuf, MountGuard) {
    let mountpoint = scratch_dir(&format!("indexed-{name}"));
    let session = fuser::spawn_mount(fs, &mountpoint, &crate::writable_session_config()).unwrap();
    let guard = MountGuard {
        session: SessionGuard::new(session, &mountpoint),
        mp: mountpoint.clone(),
        torn: false,
    };
    (mountpoint, guard)
}

fn wide_fixture() -> (Snapshot, Backend) {
    let (snapshot, mut backend, _) = fixture();
    for number in 0..600 {
        let key = path(format!("child-{number:06}").as_bytes());
        backend.nodes.insert(
            key.clone(),
            OverlayNode {
                path: key,
                kind: NodeKind::File,
                size: 0,
                exec: false,
                stage: None,
            },
        );
    }
    assert_eq!(
        backend.nodes.len(),
        607,
        "actual namespace plus root={}",
        backend.nodes.len()
    );
    (snapshot, backend)
}

fn observed(snapshot: Snapshot, backend: Backend, obs: &Arc<Obs>, plus: bool) -> Observed<Backend> {
    Observed {
        inner: GranaryFs::new(snapshot, backend, 1, crate::MountWritability::Writable).unwrap(),
        obs: obs.clone(),
        negotiate: plus,
        expected_children: BTreeSet::new(),
    }
}

#[test]
fn writable_linux_lookup_getattr_opcodes_without_whole_tree_query() {
    let name = stringify!(writable_linux_lookup_getattr_opcodes_without_whole_tree_query);
    if !require_root(name) {
        return;
    }
    let (snapshot, backend) = wide_fixture();
    let query_calls = backend.query_calls.clone();
    let obs = Arc::new(Obs::new());
    let (mountpoint, guard) = mount_fixture(name, observed(snapshot, backend, &obs, true));
    let file = std::fs::File::open(at(&mountpoint, N_FILE)).unwrap();
    let inode = file.metadata().unwrap().ino();
    for _ in 0..4 {
        let by_name = std::fs::metadata(at(&mountpoint, N_FILE)).unwrap();
        let by_handle = file.metadata().unwrap();
        assert_eq!(
            (
                by_name.ino(),
                by_name.len(),
                by_name.mode() & 0o777,
                by_handle.ino(),
                by_handle.len(),
                by_handle.mode() & 0o777
            ),
            (inode, 16, 0o644, inode, 16, 0o644)
        );
    }
    drop(file);
    guard.teardown();
    let state = obs.lock();
    assert_eq!(
        (
            state.op_count(Op::Lookup) > 0,
            state.op_count(Op::Getattr) > 0,
            query_calls.lock().unwrap().0
        ),
        (true, true, 0),
        "actual opcodes={state:?}"
    );
    eprintln!("cases=4; lookup/getattr opcode witness={state:?}; whole-tree queries=0");
}

fn cookies(plus: bool, name: &str) {
    if !require_root(name) {
        return;
    }
    let (snapshot, backend) = wide_fixture();
    let query_calls = backend.query_calls.clone();
    let captures = backend.captures.clone();
    let obs = Arc::new(Obs::new());
    let (mountpoint, guard) = mount_fixture(name, observed(snapshot, backend, &obs, plus));
    let file = std::fs::File::open(&mountpoint).unwrap();
    let (head, cookie) = {
        let mut buffer = [MaybeUninit::uninit(); 256];
        let mut dir = rustix::fs::RawDir::new(file.as_fd(), &mut buffer);
        let mut head = Vec::new();
        let mut cookie = 0;
        for _ in 0..300 {
            let entry = dir.next().unwrap().unwrap();
            head.push(entry.file_name().to_bytes().to_vec());
            cookie = entry.next_entry_cookie();
        }
        (head, cookie)
    };
    assert!(cookie > 0, "actual continuation={cookie}");
    // The mutation actor completes between refills on this same directory handle.
    let actor_root = mountpoint.clone();
    std::thread::spawn(move || {
        drop(std::fs::File::create(at(&actor_root, b"aaa-new")).unwrap());
        std::fs::remove_file(at(&actor_root, b"child-000599")).unwrap();
    })
    .join()
    .unwrap();
    let mut tails = Vec::new();
    for _ in 0..2 {
        rustix::fs::seek(file.as_fd(), rustix::fs::SeekFrom::Start(cookie)).unwrap();
        let mut buffer = [MaybeUninit::uninit(); 256];
        let mut dir = rustix::fs::RawDir::new(file.as_fd(), &mut buffer);
        let mut tail = Vec::new();
        while let Some(entry) = dir.next() {
            tail.push(entry.unwrap().file_name().to_bytes().to_vec());
        }
        tails.push(tail);
    }
    assert_eq!(tails[0], tails[1], "same-handle cookie replay");
    let all: Vec<_> = head.into_iter().chain(tails.remove(0)).collect();
    let actual: BTreeSet<_> = all.iter().cloned().collect();
    let mut expected: BTreeSet<_> = FIXTURE_ROOT_NAMES.iter().map(|n| n.to_vec()).collect();
    expected.extend([b".".to_vec(), b"..".to_vec(), b"aaa-new".to_vec()]);
    expected.extend((0..599).map(|n| format!("child-{n:06}").into_bytes()));
    assert_eq!(
        (all.len(), actual),
        (607, expected),
        "no duplicates, removed name absent, earlier-sorting new name retained"
    );
    drop(file);
    guard.teardown();
    let state = obs.lock();
    let op = if plus { Op::Readdirplus } else { Op::Readdir };
    let calls = *query_calls.lock().unwrap();
    assert_eq!(
        (
            state.op_count(op) > 1,
            calls.0,
            calls.1 > 2,
            captures.lock().unwrap().clone()
        ),
        (true, 0, true, vec!["create", "delete"]),
        "actual opcode/query tuple: state={state:?}, calls={calls:?}"
    );
    eprintln!(
        "cases=1; names=607; cookie replays=2; opcodes={state:?}; whole-tree/page calls={calls:?}"
    );
}

#[test]
fn writable_linux_readdir_pages_cookies_concurrent_create_unlink_opcodes() {
    cookies(
        false,
        stringify!(writable_linux_readdir_pages_cookies_concurrent_create_unlink_opcodes),
    );
}

#[test]
fn writable_linux_readdirplus_pages_cookies_concurrent_create_unlink_opcodes() {
    cookies(
        true,
        stringify!(writable_linux_readdirplus_pages_cookies_concurrent_create_unlink_opcodes),
    );
}
