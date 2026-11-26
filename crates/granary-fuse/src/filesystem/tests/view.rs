// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The view install's slot protocol, re-key, `ESTALE` and per-path times.

use super::*;
use crate::filesystem::{Bent, ReplyError, SlotBusy, ViewAdapter, ViewHandle};
use fuser::FileHandle;
use granary_vfs::PathKey;
use std::sync::mpsc;
use std::time::{Duration, SystemTime};

/// Runs inside a fixture preparation, while the preparation holds the slot.
pub(super) struct PrepareHook(pub(super) Arc<dyn Fn() + Send + Sync>);
impl std::fmt::Debug for PrepareHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrepareHook")
    }
}

type Action = Box<dyn FnOnce(&mut MutableBackend, &mut ViewAdapter<'_>) -> &'static str + Send>;
type Parked = Arc<Mutex<Option<(SlotBusy, Action)>>>;
type Log = Arc<Mutex<Vec<&'static str>>>;

/// A bounded wait for the other thread; a hang fails the row instead.
const BOUND: Duration = Duration::from_secs(10);
const CONTENTION_WINDOW: Duration = Duration::from_millis(200);

fn key(parts: &[&[u8]]) -> PathKey {
    parts.iter().map(|part| part.to_vec()).collect()
}

fn node(parts: &[&[u8]], kind: NodeKind, size: u64) -> crate::OverlayNode {
    crate::OverlayNode {
        path: parts
            .iter()
            .map(|part| Name::new(part.to_vec()).unwrap())
            .collect(),
        kind,
        size,
        exec: false,
        stage: None,
    }
}

fn with<R>(
    fs: &GranaryFs<MutableBackend>,
    action: impl FnOnce(&mut MountInner<MutableBackend>) -> R,
) -> R {
    action(fs.inner.lock().unwrap().as_mut().unwrap())
}

fn open_file(fs: &GranaryFs<MutableBackend>, parent: u64, name: &[u8]) -> (u64, FileHandle) {
    let (attr, fh) = fs
        .create_overlay(
            INodeNo(parent),
            name,
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .unwrap();
    (attr.ino, fh.unwrap())
}

fn make(fs: &GranaryFs<MutableBackend>, parent: u64, name: &[u8], kind: NodeKind) -> u64 {
    fs.create_overlay(INodeNo(parent), name, kind, 0o644, None)
        .unwrap()
        .0
        .ino
}

fn lookup(fs: &GranaryFs<MutableBackend>, parent: u64, name: &[u8]) -> u64 {
    fs.lookup_entry(INodeNo(parent), name).unwrap().ino
}

fn time(fs: &GranaryFs<MutableBackend>, ino: u64) -> SystemTime {
    fs.getattr_attr(INodeNo(ino)).unwrap().host_time()
}

fn rekey(
    handle: &ViewHandle<MutableBackend>,
    paths: &[(PathKey, bool)],
    displaced: &[crate::OverlayNode],
    time: SystemTime,
) {
    let displaced: BTreeMap<PathKey, crate::OverlayNode> = displaced
        .iter()
        .map(|node| (super::super::write::path_key(&node.path), node.clone()))
        .collect();
    handle
        .try_install(|_, adapter| adapter.rekey(paths, &|path| displaced.get(path).cloned(), time))
        .map_err(|(busy, _)| busy)
        .unwrap();
}

/// The next preparation attempts `action` while it holds the slot and parks
/// the answer; every later preparation appends `"prepare"` to `log`.
fn park_next_install(
    fs: &GranaryFs<MutableBackend>,
    handle: Arc<ViewHandle<MutableBackend>>,
    action: Action,
    log: Log,
) -> Parked {
    let parked: Parked = Arc::default();
    let out = parked.clone();
    let pending = Mutex::new(Some(action));
    let hook = move || {
        if let Some(action) = pending.lock().unwrap().take() {
            let Err(busy) = handle.try_install(action) else {
                panic!("an install ran while a preparation held the slot");
            };
            *out.lock().unwrap() = Some(busy);
        } else {
            log.lock().unwrap().push("prepare");
        }
    };
    with(fs, |inner| {
        inner.backend.prepare_hook = Some(PrepareHook(Arc::new(hook)));
    });
    parked
}

fn counted_waker(handle: &ViewHandle<MutableBackend>) -> Arc<AtomicUsize> {
    let wakes = Arc::new(AtomicUsize::new(0));
    let counter = wakes.clone();
    assert!(
        handle.on_slot_returned(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        })),
        "premise: the first waker registers"
    );
    wakes
}

fn signal_waits(fs: &GranaryFs<MutableBackend>) -> mpsc::Receiver<()> {
    let (waiting, waited) = mpsc::channel();
    *fs.view_slot.wait_hook.lock().unwrap() = Some(Box::new(move || {
        let _ = waiting.send(());
    }));
    waited
}

// A restore that does not notify leaves the install waiting to its deadline.
#[test]
fn a_waiting_install_takes_the_gate_when_the_slot_returns() {
    let fs = bound_adapter();
    let handle = Arc::new(fs.view_handle());
    let wakes = counted_waker(&handle);
    let (ino, fh) = open_file(&fs, 1, b"g");
    let parked = park_next_install(
        &fs,
        handle.clone(),
        Box::new(|_, _| "installed"),
        Log::default(),
    );
    fs.write_overlay(INodeNo(ino), fh, 0, b"x").unwrap();
    let (busy, action) = parked.lock().unwrap().take().unwrap();
    let woken = wakes.load(Ordering::SeqCst);
    let ran = handle.try_install(action).map_err(|(busy, _)| busy);
    assert_eq!((busy, woken, ran), (SlotBusy::Taken, 1, Ok("installed")));
}

// A second registration that replaced the first would strand the install
// that registered it; one reported as registered would let a second binding
// believe its own waker is the one called.
#[test]
fn a_second_slot_waker_is_refused_and_the_first_still_wakes() {
    let fs = bound_adapter();
    let handle = Arc::new(fs.view_handle());
    let first = counted_waker(&handle);
    let second = Arc::new(AtomicUsize::new(0));
    let counter = second.clone();
    let registered = handle.on_slot_returned(Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    let (ino, fh) = open_file(&fs, 1, b"g");
    fs.write_overlay(INodeNo(ino), fh, 0, b"x").unwrap();
    assert_eq!(
        (
            registered,
            first.load(Ordering::SeqCst) > 0,
            second.load(Ordering::SeqCst)
        ),
        (false, true, 0)
    );
}

// Catches an observation that blocks on the adapter gate, reads or changes the
// install slot, recovers poison, or keeps a dropped filesystem alive.
#[test]
fn backend_observation_is_read_only_and_never_waits_for_the_gate() {
    let fs = bound_adapter();
    let handle = fs.view_handle();
    assert_eq!(
        handle
            .try_observe(|backend| backend.nodes.len())
            .map_err(|(busy, _)| busy),
        Ok(1),
        "healthy observation must run"
    );
    let held = fs.inner.lock().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            send.send(handle.try_observe(|_| "ran").map_err(|(busy, _)| busy))
                .unwrap();
        });
        let observed = receive.recv_timeout(std::time::Duration::from_millis(200));
        drop(held);
        assert_eq!(
            observed,
            Ok(Err(SlotBusy::Taken)),
            "held gate blocked or returned the wrong closed outcome"
        );
    });

    let fs = Arc::new(bound_adapter());
    let handle = fs.view_handle();
    let poison = fs.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = poison.inner.lock().unwrap();
            panic!("poison observation gate");
        })
        .join()
        .is_err(),
        "poison premise"
    );
    assert_eq!(
        handle.try_observe(|_| "ran").map_err(|(busy, _)| busy),
        Err(SlotBusy::Poisoned)
    );

    let fs = bound_adapter();
    let handle = fs.view_handle();
    let taken = fs.inner.lock().unwrap().take().unwrap();
    assert_eq!(
        handle.try_observe(|_| "ran").map_err(|(busy, _)| busy),
        Err(SlotBusy::Taken),
        "a preparation-owned adapter must remain a retryable busy outcome"
    );
    *fs.inner.lock().unwrap() = Some(taken);

    let mut fs = bound_adapter();
    let handle = fs.view_handle();
    Filesystem::destroy(&mut fs);
    assert_eq!(
        handle.try_observe(|_| "ran").map_err(|(busy, _)| busy),
        Err(SlotBusy::Abandoned)
    );

    let fs = bound_adapter();
    let handle = fs.view_handle();
    drop(fs);
    assert_eq!(
        handle.try_observe(|_| "ran").map_err(|(busy, _)| busy),
        Err(SlotBusy::Abandoned)
    );
}

// An unwind or `destroy` that does not abandon leaves `Taken`, and a strong
// handle would run the action on a dropped filesystem's state.
#[test]
fn an_abandoned_or_destroyed_adapter_ends_a_waiting_install() {
    let mut cases = Vec::new();

    let fs = bound_adapter();
    let handle = Arc::new(fs.view_handle());
    let wakes = counted_waker(&handle);
    let (ino, fh) = open_file(&fs, 1, b"g");
    let parked = park_next_install(&fs, handle.clone(), Box::new(|_, _| "ran"), Log::default());
    with(&fs, |inner| inner.backend.prepare_panic = true);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fs.write_overlay(INodeNo(ino), fh, 0, b"x")
    }))
    .is_err();
    let (busy, action) = parked.lock().unwrap().take().unwrap();
    assert_eq!(
        (unwound, busy),
        (true, SlotBusy::Taken),
        "premise: the install waited on the unwinding preparation"
    );
    cases.push((
        "unwound preparation",
        wakes.load(Ordering::SeqCst) > 0,
        handle.try_install(action).map_err(|(busy, _)| busy),
    ));

    let mut fs = bound_adapter();
    let handle = Arc::new(fs.view_handle());
    let wakes = counted_waker(&handle);
    let (ino, fh) = open_file(&fs, 1, b"g");
    let parked = park_next_install(&fs, handle.clone(), Box::new(|_, _| "ran"), Log::default());
    fs.write_overlay(INodeNo(ino), fh, 0, b"x").unwrap();
    let (busy, action) = parked.lock().unwrap().take().unwrap();
    assert_eq!(busy, SlotBusy::Taken, "premise: the install is waiting");
    let before = wakes.load(Ordering::SeqCst);
    Filesystem::destroy(&mut fs);
    cases.push((
        "destroyed",
        wakes.load(Ordering::SeqCst) > before,
        handle.try_install(action).map_err(|(busy, _)| busy),
    ));

    let fs = bound_adapter();
    let handle = fs.view_handle();
    drop(fs);
    cases.push((
        "dropped",
        true,
        handle.try_install(|_, _| "ran").map_err(|(busy, _)| busy),
    ));

    let expected: Vec<_> = ["unwound preparation", "destroyed", "dropped"]
        .into_iter()
        .map(|case| (case, true, Err(SlotBusy::Abandoned)))
        .collect();
    assert_eq!(cases, expected);
}

// A slot-taker that ignores the waiting install prepares first.
#[test]
fn a_waiting_install_is_not_starved_by_later_reads() {
    let fs = Arc::new(bound_adapter());
    let handle = Arc::new(fs.view_handle());
    let log = Log::default();
    let (ino, fh) = open_file(&fs, 1, b"g");
    let installed = log.clone();
    let parked = park_next_install(
        &fs,
        handle.clone(),
        Box::new(move |_, _| {
            installed.lock().unwrap().push("install");
            "installed"
        }),
        log.clone(),
    );
    fs.write_overlay(INodeNo(ino), fh, 0, b"x").unwrap();
    let (busy, action) = parked.lock().unwrap().take().unwrap();
    let waited = signal_waits(&fs);
    let (done, finished) = mpsc::channel();
    let reader = fs.clone();
    std::thread::spawn(move || {
        let _ = done.send(reader.read_handle_bytes(INodeNo(ino), fh, 0, 1).is_ok());
    });
    let blocked = waited.recv_timeout(BOUND).is_ok();
    let ran = handle.try_install(action).map_err(|(busy, _)| busy);
    let read = finished.recv_timeout(BOUND);
    assert_eq!(
        (busy, blocked, ran, read, log.lock().unwrap().clone()),
        (
            SlotBusy::Taken,
            true,
            Ok("installed"),
            Ok(true),
            vec!["install", "prepare"]
        )
    );
}

// Catches an install action run without the adapter gate, a preparation that
// admits an install while its state is out of the slot, and a later backend
// call that reuses an earlier call's view check.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "three gate and slot cases share the same install-order assertion"
)]
fn a_hooked_install_never_runs_inside_a_backend_call() {
    let mut cases = 0;

    let (snapshot, _) = snapshot_fixture();
    let fs = Arc::new(
        GranaryFs::new(
            snapshot,
            TestBackend::default(),
            1,
            crate::MountWritability::Writable,
        )
        .unwrap(),
    );
    let handle = fs.view_handle();
    let gate_states = Arc::new(Mutex::new(Vec::new()));
    let action_calls = Arc::new(AtomicUsize::new(0));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (acted_tx, acted_rx) = mpsc::channel();
    let (backend, installed) = std::thread::scope(|threads| {
        let backend_fs = fs.clone();
        let backend_states = gate_states.clone();
        let backend = threads.spawn(move || {
            backend_fs.write_inner(|inner| {
                inner.backend.mutation_readiness()?;
                backend_states
                    .lock()
                    .unwrap()
                    .push(backend_fs.inner.try_lock().is_err());
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(BOUND).unwrap();
                inner.backend.mutation_readiness()?;
                backend_states
                    .lock()
                    .unwrap()
                    .push(backend_fs.inner.try_lock().is_err());
                Ok(())
            })
        });
        entered_rx.recv_timeout(BOUND).unwrap();
        let calls = action_calls.clone();
        let install_fs = fs.clone();
        let installed = threads.spawn(move || {
            handle
                .try_install(|backend, _| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    acted_tx.send(()).unwrap();
                    (
                        backend.readiness_calls.load(Ordering::SeqCst),
                        install_fs.inner.try_lock().is_err(),
                    )
                })
                .map_err(|(busy, _)| busy)
        });
        // The install has this window to reach the gate; an action that
        // runs inside the backend call reports within it.
        assert_eq!(
            acted_rx.recv_timeout(CONTENTION_WINDOW),
            Err(mpsc::RecvTimeoutError::Timeout),
            "an install action entered while the backend call held the gate"
        );
        release_tx.send(()).unwrap();
        (backend.join().unwrap(), installed.join().unwrap())
    });
    assert_eq!(
        (
            backend,
            installed,
            gate_states.lock().unwrap().clone(),
            action_calls.load(Ordering::SeqCst)
        ),
        (Ok(()), Ok((2, true)), vec![true, true], 1),
        "the backend call must hold the gate from its first check through its last effect"
    );
    cases += 1;

    let fs = bound_adapter();
    let handle = Arc::new(fs.view_handle());
    let (ino, fh) = open_file(&fs, 1, b"g");
    let parked = park_next_install(&fs, handle, Box::new(|_, _| "installed"), Log::default());
    fs.write_overlay(INodeNo(ino), fh, 0, b"x").unwrap();
    let (busy, _) = parked.lock().unwrap().take().unwrap();
    assert_eq!(
        busy,
        SlotBusy::Taken,
        "an install must see Taken for the whole preparation"
    );
    cases += 1;

    let (snapshot, _) = snapshot_fixture();
    let fs = GranaryFs::new(
        snapshot,
        TestBackend::default(),
        1,
        crate::MountWritability::Writable,
    )
    .unwrap();
    let handle = fs.view_handle();
    fs.mutation_gate().unwrap();
    let installed_after = handle
        .try_install(|backend, _| backend.readiness_calls.load(Ordering::SeqCst))
        .map_err(|(busy, _)| busy);
    fs.mutation_gate().unwrap();
    let checks = fs
        .inner
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .backend
        .readiness_calls
        .load(Ordering::SeqCst);
    assert_eq!(
        (installed_after, checks),
        (Ok(1), 2),
        "the install runs between separate holds and the second backend call checks for itself"
    );
    cases += 1;

    assert_eq!(cases, 3, "all gate and slot cases must execute");
}

// Catches skipping the detachment, re-keying ancestors, detaching without the
// displaced metadata, and selecting every resident inode under a path rather
// than the associations the table removed.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "six cases share one re-keyed namespace"
)]
fn rekeyed_path_gets_a_fresh_inode_and_old_handle_stays_detached() {
    let fs = bound_adapter();
    let handle = fs.view_handle();
    let start = fs.mount_time;
    let t2 = start + Duration::from_secs(1000);
    let dir_a = make(&fs, 1, b"a", NodeKind::Dir);
    let dir_ab = make(&fs, dir_a, b"b", NodeKind::Dir);
    let (held, _held_fh) = open_file(&fs, 1, b"g");
    let dir_d = make(&fs, 1, b"d", NodeKind::Dir);
    let child = make(&fs, dir_d, b"x", NodeKind::File);
    let sibling = make(&fs, 1, b"e", NodeKind::File);
    let dir_h = make(&fs, 1, b"h", NodeKind::Dir);
    let h_fh = fs.opendir_handle(INodeNo(dir_h)).unwrap();
    let (unlinked, unlinked_fh) = open_file(&fs, 1, b"u");
    fs.remove_overlay(INodeNo::ROOT, b"u", false).unwrap();
    let (recreated, recreated_fh) = open_file(&fs, 1, b"u");
    with(&fs, |inner| {
        let nodes = &mut inner.backend.nodes;
        let new = node(&[b"a", b"b", b"new"], NodeKind::File, 1);
        nodes.insert(new.path.clone(), new);
        nodes.retain(|path, _| path.first().is_none_or(|name| name.as_bytes() != b"d"));
        let file = node(&[b"h"], NodeKind::File, 3);
        nodes.insert(file.path.clone(), file);
    });
    rekey(
        &handle,
        &[
            (key(&[b"a", b"b", b"new"]), true),
            (key(&[b"d"]), false),
            (key(&[b"g"]), true),
            (key(&[b"h"]), true),
            (key(&[b"u"]), true),
        ],
        &[
            node(&[b"g"], NodeKind::File, 11),
            node(&[b"d"], NodeKind::Dir, 4096),
            node(&[b"d", b"x"], NodeKind::File, 77),
            node(&[b"h"], NodeKind::Dir, 4096),
            node(&[b"u"], NodeKind::File, 55),
        ],
        t2,
    );

    let deep = with(&fs, |inner| {
        let numbers =
            [key(&[]), key(&[b"a"]), key(&[b"a", b"b"])].map(|path| inner.inodes.peek(&path));
        let attached = [1, dir_a, dir_ab].map(|ino| inner.inodes.attached(ino));
        (numbers, attached)
    });
    assert_eq!(
        deep,
        ([Some(1), Some(dir_a), Some(dir_ab)], [true; 3]),
        "a deep addition leaves its ancestors keyed"
    );

    let fresh = lookup(&fs, 1, b"g");
    let held_attached = with(&fs, |inner| inner.inodes.attached(held));
    assert_eq!(
        (fresh != held, held_attached),
        (true, false),
        "a changed file"
    );

    let removed = with(&fs, |inner| {
        [child, dir_d, sibling].map(|ino| inner.inodes.attached(ino))
    });
    assert_eq!(
        (
            removed,
            fs.getattr_attr(INodeNo(child)).map(|attr| attr.size)
        ),
        ([false, false, true], Ok(77)),
        "a removed directory"
    );

    let held_dir = fs.getattr_attr(INodeNo(dir_h)).map(|attr| attr.kind);
    fs.release_handle(h_fh, HandleKind::Directory).unwrap();
    with(&fs, |inner| {
        inner.inodes.forget(dir_h, 1);
        inner.view.prune(&inner.inodes);
    });
    assert_eq!(
        (held_dir, fs.getattr_attr(INodeNo(dir_h)).is_err()),
        (Ok(NodeKind::Dir), true),
        "a held directory replaced by a file keeps its metadata until release"
    );

    let unlinked_record = with(&fs, |inner| {
        (
            inner
                .view
                .detached(unlinked)
                .and_then(|record| record.node.as_ref().map(|node| node.size)),
            inner.view.replaced(unlinked),
            inner.view.replaced(recreated),
        )
    });
    assert_eq!(
        (
            unlinked_record,
            time(&fs, unlinked),
            fs.write_overlay(INodeNo(unlinked), unlinked_fh, 0, b"y")
                .map(|_| ())
                .map_err(ReplyError::errno),
            fs.write_overlay(INodeNo(recreated), recreated_fh, 0, b"y")
                .map(|_| ())
                .map_err(ReplyError::errno),
        ),
        (
            (Some(0), false, true),
            start,
            Ok(()),
            Err(fuser::Errno::ESTALE)
        ),
        "an unlinked inode keeps its own record; the recreated one is replaced"
    );

    let fresh_fh = fs
        .open_flags_handle(INodeNo(fresh), fuser::OpenFlags(2))
        .unwrap();
    rekey(
        &handle,
        &[(key(&[b"g"]), true)],
        &[node(&[b"g"], NodeKind::File, 22)],
        t2 + Duration::from_secs(1),
    );
    let records = with(&fs, |inner| {
        [held, fresh].map(|ino| {
            (
                inner
                    .view
                    .detached(ino)
                    .and_then(|record| record.node.as_ref().map(|node| node.size)),
                inner.view.time(&inner.inodes, ino, &key(&[b"g"])),
            )
        })
    });
    assert_eq!(
        records,
        [(Some(11), start), (Some(22), t2)],
        "the first inode keeps its first metadata and time"
    );
    fs.release_handle(fresh_fh, HandleKind::File).unwrap();
}

fn interleaved(
    mutation: impl FnOnce(&GranaryFs<MutableBackend>, u64, FileHandle) -> Result<(), ReplyError>
    + Send
    + 'static,
) -> (Result<(), fuser::Errno>, usize) {
    let fs = Arc::new(bound_adapter());
    let handle = Arc::new(fs.view_handle());
    let (g, g_fh) = open_file(&fs, 1, b"g");
    let (h, h_fh) = open_file(&fs, 1, b"h");
    let parked = park_next_install(&fs, handle.clone(), Box::new(|_, _| "ran"), Log::default());
    // The preparation restores the slot; the install's claim stays set.
    fs.write_overlay(INodeNo(h), h_fh, 0, b"x").unwrap();
    let (busy, _) = parked.lock().unwrap().take().unwrap();
    assert_eq!(busy, SlotBusy::Taken, "premise: the install was refused");
    let waited = signal_waits(&fs);
    let before = with(&fs, |inner| inner.backend.prepare_count);
    let (done, finished) = mpsc::channel();
    let writer = fs.clone();
    std::thread::spawn(move || {
        let _ = done.send(mutation(&writer, g, g_fh).map_err(ReplyError::errno));
    });
    waited
        .recv_timeout(BOUND)
        .expect("premise: the mutation waits for the install at slot acquisition");
    rekey(
        &handle,
        &[(key(&[b"g"]), true)],
        &[node(&[b"g"], NodeKind::File, 0)],
        fs.mount_time,
    );
    let result = finished
        .recv_timeout(BOUND)
        .expect("the mutation finishes once the install ends");
    (
        result,
        with(&fs, |inner| inner.backend.prepare_count) - before,
    )
}

// Catches staleness checked only in the backend, every detached inode treated
// as replaced, and no recheck once the slot is held or in `setattr_path`.
#[test]
fn replaced_inode_mutations_answer_estale_before_preparation() {
    let fs = bound_adapter();
    let handle = fs.view_handle();
    let (g, g_fh) = open_file(&fs, 1, b"g");
    let (unlinked, unlinked_fh) = open_file(&fs, 1, b"l");
    fs.remove_overlay(INodeNo::ROOT, b"l", false).unwrap();
    rekey(
        &handle,
        &[(key(&[b"g"]), true)],
        &[node(&[b"g"], NodeKind::File, 0)],
        fs.mount_time,
    );
    let errno = |result: Result<Bent, ReplyError>| result.map(|_| ()).map_err(ReplyError::errno);
    let (prepares, calls) = with(&fs, |inner| {
        (inner.backend.prepare_count, inner.backend.calls.len())
    });
    let held = (
        fs.write_overlay(INodeNo(g), g_fh, 0, b"x")
            .map(|_| ())
            .map_err(ReplyError::errno),
        // An empty write prepares nothing, so only the adapter's own check
        // answers it before the backend.
        fs.write_overlay(INodeNo(g), g_fh, 0, b"")
            .map(|_| ())
            .map_err(ReplyError::errno),
        errno(fs.setattr_result(INodeNo(g), None, Some(1), false, Some(g_fh))),
        errno(fs.setattr_result(INodeNo(g), Some(0o755), None, false, Some(g_fh))),
        errno(fs.setattr_result(INodeNo(g), Some(0o755), None, false, None)),
        with(&fs, |inner| {
            (
                inner.backend.prepare_count - prepares,
                inner.backend.calls.len() - calls,
            )
        }),
    );
    let stale = Err(fuser::Errno::ESTALE);
    assert_eq!(
        held,
        (stale, stale, stale, stale, stale, (0, 0)),
        "held replaced file"
    );
    let control = (
        fs.write_overlay(INodeNo(unlinked), unlinked_fh, 0, b"x")
            .map(|_| ())
            .map_err(ReplyError::errno),
        errno(fs.setattr_result(
            INodeNo(unlinked),
            Some(0o755),
            None,
            false,
            Some(unlinked_fh),
        )),
    );
    assert_eq!(
        control,
        (Ok(()), Err(fuser::Errno::ENOTSUP)),
        "locally unlinked held file"
    );
    let write = interleaved(|fs, g, fh| fs.write_overlay(INodeNo(g), fh, 0, b"x").map(|_| ()));
    assert_eq!(write, (stale, 0), "a write that waited for the install");
    let truncate = interleaved(|fs, g, _| {
        fs.setattr_result(INodeNo(g), None, Some(1), false, None)
            .map(|_| ())
    });
    assert_eq!(truncate, (stale, 0), "an unbound truncate that waited");
}

// Catches untouched ancestors, a local detachment that forgets the displaced
// inode's time, and a rename that leaves its times behind.
#[test]
fn untouched_file_keeps_its_time_across_an_advance() {
    let fs = bound_adapter();
    let handle = fs.view_handle();
    let start = fs.mount_time;
    let t2 = start + Duration::from_secs(1000);
    let p = make(&fs, 1, b"p", NodeKind::Dir);
    let (old, _old_fh) = open_file(&fs, p, b"f");
    let untouched = make(&fs, p, b"u", NodeKind::File);
    make(&fs, p, b"v", NodeKind::File);
    make(&fs, p, b"k", NodeKind::File);
    make(&fs, p, b"m", NodeKind::File);
    let changed = [b"f".as_slice(), b"k", b"m"].map(|name| (key(&[b"p", name]), true));
    rekey(
        &handle,
        &changed,
        &[node(&[b"p", b"f"], NodeKind::File, 0)],
        t2,
    );
    let fresh = lookup(&fs, p, b"f");
    let advanced = [untouched, fresh, p, 1, old].map(|ino| time(&fs, ino));
    assert_eq!(advanced, [start, t2, t2, t2, start], "after one re-key");
    rekey(&handle, &[], &[], t2 + Duration::from_secs(1));
    let unmoved = [untouched, fresh, p, 1].map(|ino| time(&fs, ino));
    assert_eq!(
        unmoved,
        [start, t2, t2, t2],
        "an empty re-key moves nothing"
    );

    let fresh_fh = fs
        .open_flags_handle(INodeNo(fresh), fuser::OpenFlags(2))
        .unwrap();
    let kept = lookup(&fs, p, b"k");
    let kept_fh = fs
        .open_flags_handle(INodeNo(kept), fuser::OpenFlags(2))
        .unwrap();
    fs.rename_overlay(INodeNo(p), b"v", INodeNo(p), b"f", 0)
        .unwrap();
    fs.remove_overlay(INodeNo(p), b"k", false).unwrap();
    assert_eq!(
        [fresh, kept].map(|ino| time(&fs, ino)),
        [t2; 2],
        "a held inode renamed over or unlinked keeps its time"
    );

    let moved = lookup(&fs, p, b"m");
    fs.rename_overlay(INodeNo(p), b"m", INodeNo(p), b"n", 0)
        .unwrap();
    let created = make(&fs, p, b"m", NodeKind::File);
    assert_eq!(
        (time(&fs, moved), time(&fs, created)),
        (t2, start),
        "a rename carries its time"
    );
    for fh in [fresh_fh, kept_fh] {
        fs.release_handle(fh, HandleKind::File).unwrap();
    }
}

struct TimedSink {
    fs: Arc<GranaryFs<MutableBackend>>,
    times: Vec<(Vec<u8>, SystemTime)>,
}
impl crate::DirPlusSink for TimedSink {
    fn offer(&mut self, attr: Attr, name: &[u8], next: u64) -> SinkOutcome {
        self.offer_timed(attr, self.fs.mount_time, name, next)
    }

    fn offer_timed(
        &mut self,
        attr: Attr,
        time: SystemTime,
        name: &[u8],
        _next: u64,
    ) -> SinkOutcome {
        let (_, file_attr, _) = self.fs.bent_reply_parts(attr, time);
        self.times.push((name.to_vec(), file_attr.mtime));
        SinkOutcome::Added
    }
}

// A time lookup that retakes the gate wedges the listing.
#[test]
fn readdirplus_after_a_rekey_reads_times_without_retaking_the_gate() {
    let fs = Arc::new(bound_adapter());
    let handle = fs.view_handle();
    let start = fs.mount_time;
    let t2 = start + Duration::from_secs(1000);
    let p = make(&fs, 1, b"p", NodeKind::Dir);
    make(&fs, p, b"f", NodeKind::File);
    make(&fs, p, b"u", NodeKind::File);
    rekey(&handle, &[(key(&[b"p", b"f"]), true)], &[], t2);
    let directory = fs.opendir_handle(INodeNo(p)).unwrap();
    let (done, finished) = mpsc::channel();
    let lister = fs.clone();
    std::thread::spawn(move || {
        let mut sink = TimedSink {
            fs: lister.clone(),
            times: Vec::new(),
        };
        let result = lister.directory_entries_plus_handle(p, directory, 0, &mut sink);
        let _ = done.send((result.is_ok(), sink.times));
    });
    let (completed, times) = finished
        .recv_timeout(BOUND)
        .map_or((false, Vec::new()), |(listed, times)| (listed, times));
    let child = |name: &[u8]| {
        times
            .iter()
            .find(|(listed, _)| listed == name)
            .map(|(_, time)| *time)
    };
    assert_eq!(
        (completed, child(b"f"), child(b"u")),
        (true, Some(t2), Some(start))
    );
}

struct RecordingNotifier {
    sent: Mutex<Vec<u64>>,
    refuse: u64,
}
impl crate::ViewNotifier for RecordingNotifier {
    fn inval_inode(&self, ino: u64) -> std::io::Result<()> {
        self.sent.lock().unwrap().push(ino);
        if ino == self.refuse {
            return Err(std::io::Error::other("refused"));
        }
        Ok(())
    }
}

// Sending past a refusal, or a send without a notifier, would show here.
#[test]
fn revocation_stops_at_the_first_refused_send() {
    let fs = bound_adapter();
    let mut handle = fs.view_handle();
    let unbound = handle.revoke(&[2, 3]).is_ok();
    let notifier = Arc::new(RecordingNotifier {
        sent: Mutex::default(),
        refuse: 3,
    });
    handle.set_notifier(notifier.clone());
    let refused = handle.revoke(&[2, 3, 4]).is_err();
    assert_eq!(
        (unbound, refused, notifier.sent.lock().unwrap().clone()),
        (true, true, vec![2, 3])
    );
}

/// The adapter counts a handle as write-capable by its access mode alone,
/// from its open to its release: none after a read-only open, one after a
/// write-only or a read-write open, none once that handle is released.
#[test]
fn adapter_reports_write_capable_handles() {
    let fs = bound_adapter();
    let handle = fs.view_handle();
    let (ino, created) = open_file(&fs, 1, b"file");
    fs.release_handle(created, HandleKind::File).unwrap();
    let capable = || {
        handle
            .try_install(|_, adapter| adapter.write_capable())
            .map_err(|(busy, _)| busy)
            .unwrap()
    };
    let mut observed = Vec::new();
    let readonly = fs
        .open_flags_handle(INodeNo(ino), fuser::OpenFlags(0))
        .unwrap();
    observed.push(capable());
    let wronly = fs
        .open_flags_handle(INodeNo(ino), fuser::OpenFlags(1))
        .unwrap();
    observed.push(capable());
    fs.release_handle(wronly, HandleKind::File).unwrap();
    let rdwr = fs
        .open_flags_handle(INodeNo(ino), fuser::OpenFlags(2))
        .unwrap();
    observed.push(capable());
    fs.release_handle(rdwr, HandleKind::File).unwrap();
    observed.push(capable());
    let handles = with(&fs, |inner| inner.write_handles.len());
    assert_eq!(
        (observed, handles),
        (vec![false, true, true, false], 1),
        "(write-capable after O_RDONLY, O_WRONLY, O_RDWR and its release; handles still open)"
    );
    fs.release_handle(readonly, HandleKind::File).unwrap();
}

// Catches `ENOENT` from `bound_path` for a replaced inode, which Linux does
// not retry, and every detached inode treated as replaced.
#[test]
fn open_and_opendir_of_a_replaced_inode_answer_estale() {
    let fs = bound_adapter();
    let handle = fs.view_handle();
    let (g, _g_fh) = open_file(&fs, 1, b"g");
    let dir = make(&fs, 1, b"d", NodeKind::Dir);
    let _dir_fh = fs.opendir_handle(INodeNo(dir)).unwrap();
    let (unlinked, _unlinked_fh) = open_file(&fs, 1, b"l");
    fs.remove_overlay(INodeNo::ROOT, b"l", false).unwrap();
    rekey(
        &handle,
        &[(key(&[b"g"]), true), (key(&[b"d"]), true)],
        &[
            node(&[b"g"], NodeKind::File, 0),
            node(&[b"d"], NodeKind::Dir, 4096),
        ],
        fs.mount_time,
    );
    let errno =
        |result: Result<FileHandle, ReplyError>| result.map(|_| ()).map_err(ReplyError::errno);
    let replaced = (
        errno(fs.open_flags_handle(INodeNo(g), fuser::OpenFlags(0))),
        errno(fs.opendir_handle(INodeNo(dir))),
    );
    let unlinked = errno(fs.open_flags_handle(INodeNo(unlinked), fuser::OpenFlags(0)));
    let fresh = lookup(&fs, 1, b"g");
    let reopened = (
        fresh != g,
        errno(fs.open_flags_handle(INodeNo(fresh), fuser::OpenFlags(0))),
    );
    assert_eq!(
        (replaced, unlinked, reopened),
        (
            (Err(fuser::Errno::ESTALE), Err(fuser::Errno::ESTALE)),
            Err(fuser::Errno::ENOENT),
            (true, Ok(()))
        ),
        "((OPEN replaced file, OPENDIR replaced directory), OPEN locally unlinked file, \
         (fresh inode, its OPEN))"
    );
}

/// A view boundary that records each wait, whether the adapter's gate was
/// free during it, and answers as the row says.
#[derive(Debug, Default)]
struct RecordingBoundary {
    waits: Mutex<Vec<(crate::BoundaryKind, bool, bool)>>,
    /// The answer, and the node an `Installed` answer adds to the overlay,
    /// as an install would.
    answer: Mutex<Option<crate::OverlayNode>>,
    outcome: Mutex<Option<crate::BoundaryOutcome>>,
    label: Mutex<Option<Result<Vec<u8>, crate::MountError>>>,
    unconfirmed: std::sync::atomic::AtomicBool,
    gate: std::sync::OnceLock<std::sync::Weak<Mutex<Option<MountInner<MutableBackend>>>>>,
}
impl crate::ViewBoundary for RecordingBoundary {
    fn wait(
        &self,
        kind: crate::BoundaryKind,
        writers: &dyn Fn() -> bool,
    ) -> crate::BoundaryOutcome {
        let gate = self.gate.get().and_then(std::sync::Weak::upgrade);
        let free = gate.as_ref().is_some_and(|gate| gate.try_lock().is_ok());
        let writers = writers();
        self.waits.lock().unwrap().push((kind, writers, free));
        if let Some(outcome) = *self.outcome.lock().unwrap() {
            return outcome;
        }
        let Some(installed) = self.answer.lock().unwrap().take() else {
            return crate::BoundaryOutcome::Served;
        };
        if let Some(gate) = gate {
            let mut inner = gate.lock().unwrap();
            let backend = &mut inner.as_mut().unwrap().backend;
            backend.nodes.insert(installed.path.clone(), installed);
        }
        crate::BoundaryOutcome::Installed
    }

    fn label(&self) -> Option<Result<Vec<u8>, crate::MountError>> {
        self.label.lock().unwrap().clone()
    }

    fn unconfirmed(&self) -> bool {
        self.unconfirmed.load(Ordering::SeqCst)
    }
}

/// An adapter over a fresh mutable backend whose view boundary is `boundary`.
fn boundary_adapter(
    writable: bool,
    boundary: &Arc<RecordingBoundary>,
) -> GranaryFs<MutableBackend> {
    let fs = mutable_adapter_over(
        MutableBackend {
            bind_objects: true,
            view_boundary: Some(boundary.clone()),
            ..MutableBackend::default()
        },
        writable,
    );
    boundary.gate.set(Arc::downgrade(&fs.inner)).unwrap();
    fs
}

// Catches each dropped wait, a wait under the gate, a LOOKUP re-run on every
// miss, writers read from handle presence, and a boundary on a read-only
// mount.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table of the nine boundary cases over the same adapter shape"
)]
fn writable_callbacks_wait_at_their_boundaries() {
    use crate::BoundaryKind::{LookupMiss, Open, Opendir, Rewind};
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for case in [
        "open",
        "opendir",
        "lookup miss",
        "rewind",
        "rewind of a plus listing",
        "lookup hit and first listing",
        "lookup miss after an install",
        "write-capable descriptor",
        "read-only mount",
    ] {
        let boundary = Arc::new(RecordingBoundary::default());
        let fs = boundary_adapter(case != "read-only mount", &boundary);
        let (mut lookups, mut extra) = (0, None);
        match case {
            "open" => {
                let file = make(&fs, 1, b"f", NodeKind::File);
                boundary.waits.lock().unwrap().clear();
                fs.open_flags_handle(INodeNo(file), fuser::OpenFlags(0))
                    .unwrap();
            }
            "opendir" => {
                let dir = make(&fs, 1, b"d", NodeKind::Dir);
                fs.opendir_handle(INodeNo(dir)).unwrap();
            }
            "lookup miss" => {
                let missed = fs.lookup_entry(INodeNo::ROOT, b"absent").map(|_| ());
                extra = Some(format!("{:?}", missed.map_err(ReplyError::errno)));
                lookups = with(&fs, |inner| inner.backend.lookup_queries);
            }
            "rewind" => {
                let dir = make(&fs, 1, b"d", NodeKind::Dir);
                make(&fs, dir, b"x", NodeKind::File);
                let fh = fs.opendir_handle(INodeNo(dir)).unwrap();
                boundary.waits.lock().unwrap().clear();
                let mut sink = LiveSink::default();
                fs.directory_entries_handle(dir, fh, 0, &mut sink).unwrap();
                fs.directory_entries_handle(dir, fh, 1, &mut sink).unwrap();
                fs.directory_entries_handle(dir, fh, 0, &mut sink).unwrap();
            }
            "rewind of a plus listing" => {
                let dir = make(&fs, 1, b"d", NodeKind::Dir);
                make(&fs, dir, b"x", NodeKind::File);
                let fh = fs.opendir_handle(INodeNo(dir)).unwrap();
                boundary.waits.lock().unwrap().clear();
                let mut sink = LiveSink::default();
                fs.directory_entries_plus_handle(dir, fh, 0, &mut sink)
                    .unwrap();
                fs.directory_entries_plus_handle(dir, fh, 0, &mut sink)
                    .unwrap();
            }
            "lookup hit and first listing" => {
                let dir = make(&fs, 1, b"d", NodeKind::Dir);
                let fh = fs.opendir_handle(INodeNo(dir)).unwrap();
                boundary.waits.lock().unwrap().clear();
                fs.lookup_entry(INodeNo::ROOT, b"d").unwrap();
                let mut sink = LiveSink::default();
                fs.directory_entries_handle(dir, fh, 0, &mut sink).unwrap();
            }
            "lookup miss after an install" => {
                *boundary.answer.lock().unwrap() = Some(node(&[b"late"], NodeKind::File, 3));
                let found = fs
                    .lookup_entry(INodeNo::ROOT, b"late")
                    .map(|attr| attr.size);
                extra = Some(format!("{:?}", found.map_err(ReplyError::errno)));
                lookups = with(&fs, |inner| inner.backend.lookup_queries);
            }
            "write-capable descriptor" => {
                let (_, _held) = open_file(&fs, 1, b"w");
                let file = make(&fs, 1, b"f", NodeKind::File);
                boundary.waits.lock().unwrap().clear();
                fs.open_flags_handle(INodeNo(file), fuser::OpenFlags(0))
                    .unwrap();
            }
            _ => {
                let leaf = fs.lookup_entry(INodeNo::ROOT, b"leaf").unwrap().ino;
                let _ = fs.lookup_entry(INodeNo::ROOT, b"absent");
                fs.open_flags_handle(INodeNo(leaf), fuser::OpenFlags(0))
                    .unwrap();
                let child = fs.lookup_entry(INodeNo::ROOT, b"child").unwrap().ino;
                let fh = fs.opendir_handle(INodeNo(child)).unwrap();
                let mut sink = LiveSink::default();
                fs.directory_entries_handle(child, fh, 0, &mut sink)
                    .unwrap();
                fs.directory_entries_handle(child, fh, 0, &mut sink)
                    .unwrap();
            }
        }
        observed.push((case, boundary.waits.lock().unwrap().clone(), lookups, extra));
        expected.push(match case {
            "open" => (case, vec![(Open, false, true)], 0, None),
            "opendir" => (case, vec![(Opendir, false, true)], 0, None),
            "lookup miss" => (
                case,
                vec![(LookupMiss, false, true)],
                1,
                Some(format!("{:?}", Err::<(), _>(fuser::Errno::ENOENT))),
            ),
            "rewind" | "rewind of a plus listing" => (case, vec![(Rewind, false, true)], 0, None),
            "lookup miss after an install" => (
                case,
                vec![(LookupMiss, false, true)],
                2,
                Some(format!("{:?}", Ok::<u64, fuser::Errno>(3))),
            ),
            "write-capable descriptor" => (case, vec![(Open, true, true)], 0, None),
            // A lookup hit, a first listing and a read-only mount wait nowhere.
            _ => (case, vec![], 0, None),
        });
    }
    assert_eq!(
        observed, expected,
        "(case, waits as (kind, writers, gate free), overlay lookups, lookup answer)"
    );
    assert_eq!(observed.len(), 9);
}

// Catches root vs non-root dispatch, unknown xattr names, exact-size fit vs
// short-buffer `ERANGE` as a refused outcome, read-only refusal, and poisoned
// label error propagation.
#[test]
fn writable_root_view_label_answers_fresh_or_stale() {
    use crate::filesystem::XattrReply;
    use std::ffi::OsStr;
    let boundary = Arc::new(RecordingBoundary::default());
    let fs = boundary_adapter(true, &boundary);
    let child = make(&fs, 1, b"child", NodeKind::File);
    let view = Some(OsStr::new("user.granary.view"));
    let other = Some(OsStr::new("user.other"));

    *boundary.label.lock().unwrap() = Some(Ok(b"fresh:3".to_vec()));
    let fresh_size = fs.xattr_query(INodeNo::ROOT, view, 0);
    let fresh_exact = fs.xattr_query(INodeNo::ROOT, view, 7);
    let fresh_short = fs.xattr_query(INodeNo::ROOT, view, 6);

    *boundary.label.lock().unwrap() = Some(Ok(b"stale:3:1700000000000".to_vec()));
    let stale_exact = fs.xattr_query(INodeNo::ROOT, view, 21);
    let stale_short = fs.xattr_query(INodeNo::ROOT, view, 20);

    let list_size = fs.xattr_query(INodeNo::ROOT, None, 0);
    let list_exact = fs.xattr_query(INodeNo::ROOT, None, 18);
    let list_short = fs.xattr_query(INodeNo::ROOT, None, 17);

    let non_root_get = fs.xattr_query(INodeNo(child), view, 0);
    let non_root_list = fs.xattr_query(INodeNo(child), None, 0);
    let root_other = fs.xattr_query(INodeNo::ROOT, other, 0);

    *boundary.label.lock().unwrap() = Some(Err(crate::MountError::Io));
    let poisoned = fs.xattr_query(INodeNo::ROOT, view, 64);

    let ro_boundary = Arc::new(RecordingBoundary::default());
    *ro_boundary.label.lock().unwrap() = Some(Ok(b"fresh:0".to_vec()));
    let ro = boundary_adapter(false, &ro_boundary);
    let ro_get = ro.xattr_query(INodeNo::ROOT, view, 64);
    let ro_list_size = ro.xattr_query(INodeNo::ROOT, None, 0);
    let ro_list_data = ro.xattr_query(INodeNo::ROOT, None, 8);
    let erange_outcome = (
        fresh_short.clone().err().map(ReplyError::outcome),
        crate::CallbackOutcome::from_errno(Some(fuser::Errno::ERANGE)),
    );

    assert_eq!(
        (
            [
                fresh_size,
                fresh_exact,
                fresh_short,
                stale_exact,
                stale_short,
                list_size,
                list_exact,
                list_short,
                non_root_get,
                non_root_list,
                root_other,
                poisoned,
                ro_get,
                ro_list_size,
                ro_list_data,
            ],
            erange_outcome,
        ),
        (
            [
                Ok(XattrReply::Size(7)),
                Ok(XattrReply::Data(b"fresh:3".to_vec())),
                Err(ReplyError::Errno(fuser::Errno::ERANGE)),
                Ok(XattrReply::Data(b"stale:3:1700000000000".to_vec())),
                Err(ReplyError::Errno(fuser::Errno::ERANGE)),
                Ok(XattrReply::Size(18)),
                Ok(XattrReply::Data(b"user.granary.view\0".to_vec())),
                Err(ReplyError::Errno(fuser::Errno::ERANGE)),
                Err(ReplyError::Errno(fuser::Errno::ENOTSUP)),
                Err(ReplyError::Errno(fuser::Errno::ENOTSUP)),
                Err(ReplyError::Errno(fuser::Errno::ENOTSUP)),
                Err(ReplyError::Backend(crate::MountError::Io)),
                Err(ReplyError::Errno(fuser::Errno::NO_XATTR)),
                Ok(XattrReply::Size(0)),
                Ok(XattrReply::Data(Vec::new())),
            ],
            (
                Some(crate::CallbackOutcome::Refused),
                crate::CallbackOutcome::Refused,
            ),
        )
    );
}

// Catches skipping the new-name gate on create/mknod/mkdir/symlink, mutating
// the backend or waiting at a boundary when unconfirmed, and refusing when
// confirmed or when the boundary leaves `unconfirmed` at its default.
#[test]
fn strict_new_names_answer_etimedout() {
    #[derive(Debug)]
    struct DefaultBoundary;
    impl crate::ViewBoundary for DefaultBoundary {
        fn wait(&self, _: crate::BoundaryKind, _: &dyn Fn() -> bool) -> crate::BoundaryOutcome {
            crate::BoundaryOutcome::Served
        }
    }

    let boundary = Arc::new(RecordingBoundary::default());
    let fs = boundary_adapter(true, &boundary);
    boundary.unconfirmed.store(true, Ordering::SeqCst);

    let unconfirmed_file = fs
        .create_overlay(
            INodeNo::ROOT,
            b"new-file",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .map(|_| ());
    let unconfirmed_node = fs
        .create_overlay(INodeNo::ROOT, b"new-node", NodeKind::File, 0o644, None)
        .map(|_| ());
    let unconfirmed_dir = fs
        .create_overlay(INodeNo::ROOT, b"new-dir", NodeKind::Dir, 0o755, None)
        .map(|_| ());
    let unconfirmed_link = fs
        .symlink_overlay(INodeNo::ROOT, b"new-link", b"target")
        .map(|_| ());
    let nodes_after_unconfirmed = with(&fs, |inner| inner.backend.nodes.len());
    let waits = boundary.waits.lock().unwrap().len();

    boundary.unconfirmed.store(false, Ordering::SeqCst);
    let confirmed_file = fs
        .create_overlay(
            INodeNo::ROOT,
            b"new-file",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .map(|_| ());
    let confirmed_node = fs
        .create_overlay(INodeNo::ROOT, b"new-node", NodeKind::File, 0o644, None)
        .map(|_| ());
    let confirmed_dir = fs
        .create_overlay(INodeNo::ROOT, b"new-dir", NodeKind::Dir, 0o755, None)
        .map(|_| ());
    let confirmed_link = fs
        .symlink_overlay(INodeNo::ROOT, b"new-link", b"target")
        .map(|_| ());
    let default_unconfirmed = crate::ViewBoundary::unconfirmed(&DefaultBoundary);

    assert_eq!(
        (
            [
                unconfirmed_file,
                unconfirmed_node,
                unconfirmed_dir,
                unconfirmed_link,
                confirmed_file,
                confirmed_node,
                confirmed_dir,
                confirmed_link,
            ],
            nodes_after_unconfirmed,
            waits,
            default_unconfirmed,
        ),
        (
            [
                Err(ReplyError::Backend(crate::MountError::Unreachable)),
                Err(ReplyError::Backend(crate::MountError::Unreachable)),
                Err(ReplyError::Backend(crate::MountError::Unreachable)),
                Err(ReplyError::Backend(crate::MountError::Unreachable)),
                Ok(()),
                Ok(()),
                Ok(()),
                Ok(()),
            ],
            1,
            0,
            false,
        )
    );
}

// Catches mapping `BoundaryOutcome::Unreachable` to `Served` or `EIO` instead
// of `MountError::Unreachable` (`ETIMEDOUT`) across the four boundary points
// and both errno conversions.
#[test]
fn strict_boundaries_answer_etimedout() {
    let boundary = Arc::new(RecordingBoundary::default());
    let fs = boundary_adapter(true, &boundary);
    let file = make(&fs, 1, b"f", NodeKind::File);
    let dir = make(&fs, 1, b"d", NodeKind::Dir);
    make(&fs, dir, b"x", NodeKind::File);
    let dir_fh = fs.opendir_handle(INodeNo(dir)).unwrap();
    let plus_fh = fs.opendir_handle(INodeNo(dir)).unwrap();
    let mut sink = LiveSink::default();
    fs.directory_entries_handle(dir, dir_fh, 0, &mut sink)
        .unwrap();
    fs.directory_entries_plus_handle(dir, plus_fh, 0, &mut sink)
        .unwrap();

    boundary.waits.lock().unwrap().clear();
    *boundary.outcome.lock().unwrap() = Some(crate::BoundaryOutcome::Unreachable);

    let open_res = fs
        .open_flags_handle(INodeNo(file), fuser::OpenFlags(0))
        .map(|_| ());
    let opendir_res = fs.opendir_handle(INodeNo(dir)).map(|_| ());
    let lookup_miss = fs.lookup_entry(INodeNo::ROOT, b"absent").map(|_| ());
    let rewind_res = fs.directory_entries_handle(dir, dir_fh, 0, &mut sink);
    let rewind_plus_res = fs.directory_entries_plus_handle(dir, plus_fh, 0, &mut sink);
    let outcome = open_res.err().map(ReplyError::outcome);

    *boundary.outcome.lock().unwrap() = Some(crate::BoundaryOutcome::Served);
    let served_open = fs
        .open_flags_handle(INodeNo(file), fuser::OpenFlags(0))
        .map(|_| ());
    let served_opendir = fs.opendir_handle(INodeNo(dir)).map(|_| ());
    let served_miss = fs.lookup_entry(INodeNo::ROOT, b"absent").map(|_| ());
    let served_rewind = fs.directory_entries_handle(dir, dir_fh, 0, &mut sink);

    let errno = crate::MountError::Unreachable.errno();
    let from_errno = crate::CallbackOutcome::from_errno(Some(fuser::Errno::ETIMEDOUT));

    assert_eq!(
        (
            [
                open_res,
                opendir_res,
                lookup_miss,
                rewind_res,
                rewind_plus_res
            ],
            outcome,
            [served_open, served_opendir, served_miss, served_rewind],
            errno,
            from_errno,
        ),
        (
            [
                Err(ReplyError::Backend(crate::MountError::Unreachable)),
                Err(ReplyError::Backend(crate::MountError::Unreachable)),
                Err(ReplyError::Backend(crate::MountError::Unreachable)),
                Err(ReplyError::Backend(crate::MountError::Unreachable)),
                Err(ReplyError::Backend(crate::MountError::Unreachable)),
            ],
            Some(crate::CallbackOutcome::Failed(
                crate::MountError::Unreachable
            )),
            [
                Ok(()),
                Ok(()),
                Err(ReplyError::Errno(fuser::Errno::ENOENT)),
                Ok(()),
            ],
            fuser::Errno::ETIMEDOUT,
            crate::CallbackOutcome::Failed(crate::MountError::Unreachable),
        )
    );
}
