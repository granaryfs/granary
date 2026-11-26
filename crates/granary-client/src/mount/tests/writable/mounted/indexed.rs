// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]
#![cfg(target_os = "linux")]

//! Mounted syscall answers paired with work sampled on the single FUSE worker.

use super::super::observed::{CallbackHistory, WorkerScope};
use super::*;
use crate::overlay_store::work::QueryWork;
use crate::sync::{InstantClock, MonotonicClock as _, MonotonicToken};
use granary_core::manifest::{DirEntry, EntryKind, FileGrains, GrainRef, Name, build_dir};
use granary_fuse::{Callback, CallbackObserver, CallbackOutcome, CallbackScope, MountBackend};
use std::io::BufRead as _;

#[derive(Debug, Default, Clone)]
struct Work {
    query: QueryWork,
    storage_clones: usize,
    storage_rows: usize,
    child_rows: usize,
    listing_attempt_starts: Vec<(usize, usize)>,
    pages: usize,
    backend_ns: u128,
}

#[derive(Debug, Clone)]
struct Completion {
    callback: Callback,
    outcome: CallbackOutcome,
    work: Work,
    elapsed_ns: u128,
}

#[derive(Debug)]
pub(super) struct WorkerObserver {
    delegate: Arc<dyn CallbackObserver>,
    events: super::super::Events,
    dispatch: tracing::Dispatch,
    capture_events: std::sync::atomic::AtomicBool,
    current: Mutex<(Work, Option<MonotonicToken>)>,
    history: Arc<Mutex<CallbackHistory>>,
    opcodes: Mutex<Vec<Callback>>,
    clock: InstantClock,
    completed: Mutex<Vec<Completion>>,
    captured: Mutex<Vec<Callback>>,
    write_flags: Mutex<Vec<(i32, i32)>>,
}

struct SubscribedScope {
    _scope: WorkerScope,
    _subscriber: Option<tracing::dispatcher::DefaultGuard>,
}
impl std::fmt::Debug for SubscribedScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscribedScope").finish()
    }
}
impl CallbackScope for SubscribedScope {}

impl CallbackObserver for WorkerObserver {
    fn begin(&self, callback: Callback) -> Option<Box<dyn CallbackScope>> {
        let subscriber = self
            .capture_events
            .load(std::sync::atomic::Ordering::Relaxed)
            .then(|| tracing::dispatcher::set_default(&self.dispatch));
        *self.current.lock().unwrap() = (Work::default(), self.clock.start());
        self.history.lock().unwrap().active = Some(callback);
        self.opcodes.lock().unwrap().push(callback);
        Some(Box::new(SubscribedScope {
            _scope: WorkerScope {
                _delegate: self.delegate.begin(callback),
                history: self.history.clone(),
            },
            _subscriber: subscriber,
        }))
    }
    fn captured(&self, callback: Callback) -> Option<Box<dyn granary_fuse::DeferredCallbackScope>> {
        self.captured.lock().unwrap().push(callback);
        self.delegate.captured(callback)
    }
    fn deferred_completed(&self, callback: Callback, outcome: CallbackOutcome) {
        self.history
            .lock()
            .unwrap()
            .outcomes
            .push((callback, outcome));
        self.delegate.deferred_completed(callback, outcome);
    }
    fn write_flags_for_test(&self, request_flags: i32, retained_flags: i32) {
        self.write_flags
            .lock()
            .unwrap()
            .push((request_flags, retained_flags));
        self.delegate
            .write_flags_for_test(request_flags, retained_flags);
    }
    fn completed(&self, callback: Callback, outcome: CallbackOutcome) {
        let current = self.current.lock().unwrap();
        let row = Completion {
            callback,
            outcome,
            work: current.0.clone(),
            elapsed_ns: self
                .clock
                .elapsed(current.1.as_ref().unwrap())
                .unwrap()
                .as_nanos(),
        };
        self.completed.lock().unwrap().push(row);
        let mut history = self.history.lock().unwrap();
        history.outcomes.push((callback, outcome));
        history.active = None;
        drop(history);
        drop(current);
        self.delegate.completed(callback, outcome);
    }
}

pub(super) struct Measured<B> {
    backend: B,
    observer: Arc<WorkerObserver>,
}

impl WorkerObserver {
    pub(super) fn sync_floor_results(&self) -> Vec<(Callback, CallbackOutcome)> {
        self.history
            .lock()
            .unwrap()
            .outcomes
            .iter()
            .copied()
            .filter(|(callback, _)| matches!(callback, Callback::Fsync | Callback::Setattr))
            .collect()
    }

    fn new(
        delegate: Arc<dyn CallbackObserver>,
        capture: Option<(super::super::Events, tracing::Dispatch)>,
    ) -> Self {
        let (events, dispatch) = capture.unwrap_or_else(|| {
            let events = super::super::Events::default();
            let dispatch = tracing::Dispatch::new(events.subscriber());
            (events, dispatch)
        });
        Self {
            delegate,
            events,
            dispatch,
            capture_events: std::sync::atomic::AtomicBool::new(false),
            current: Mutex::new((Work::default(), None)),
            history: Arc::new(Mutex::new(CallbackHistory::default())),
            opcodes: Mutex::new(Vec::new()),
            clock: InstantClock::default(),
            completed: Mutex::new(Vec::new()),
            captured: Mutex::new(Vec::new()),
            write_flags: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn capture_events(&self) {
        self.capture_events
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub(super) fn events(&self) -> &super::super::Events {
        &self.events
    }

    /// Every callback the daemon has completed, in order.
    pub(super) fn callback_results(&self) -> Vec<(Callback, CallbackOutcome)> {
        self.history.lock().unwrap().outcomes.clone()
    }

    pub(super) fn sync_results(&self) -> Vec<(Callback, CallbackOutcome)> {
        self.history
            .lock()
            .unwrap()
            .outcomes
            .iter()
            .copied()
            .filter(|(callback, _)| matches!(callback, Callback::Fsync | Callback::Fsyncdir))
            .collect()
    }
    pub(super) fn sync_requests(&self) -> Vec<(bool, bool)> {
        self.history
            .lock()
            .unwrap()
            .sync_requests
            .iter()
            .copied()
            .filter(|(callback, _, _)| {
                matches!(callback, Some(Callback::Fsync | Callback::Fsyncdir))
            })
            .map(|(_, dir, datasync)| (dir, datasync))
            .collect()
    }
    pub(super) fn write_sync_requests(&self) -> Vec<(bool, bool)> {
        self.history
            .lock()
            .unwrap()
            .sync_requests
            .iter()
            .copied()
            .filter(|(callback, _, _)| *callback == Some(Callback::Write))
            .map(|(_, dir, datasync)| (dir, datasync))
            .collect()
    }
    pub(super) fn write_results(&self) -> Vec<CallbackOutcome> {
        self.history.lock().unwrap().write_results()
    }
    pub(super) fn attribution_failures(&self) -> Vec<(Option<Callback>, bool, bool)> {
        self.history
            .lock()
            .unwrap()
            .sync_requests
            .iter()
            .copied()
            .filter(|(callback, _, _)| callback.is_none())
            .collect()
    }
    pub(super) fn write_flags(&self) -> Vec<(i32, i32)> {
        self.write_flags.lock().unwrap().clone()
    }
    pub(super) fn opcodes(&self) -> Vec<Callback> {
        self.opcodes.lock().unwrap().clone()
    }
    pub(super) fn captured_setattr(&self) -> bool {
        self.captured.lock().unwrap().contains(&Callback::Setattr)
    }
}

pub(super) fn observed<B: MountBackend>(
    backend: B,
    capture: Option<(super::super::Events, tracing::Dispatch)>,
) -> (Measured<B>, Arc<WorkerObserver>) {
    let observer = Arc::new(WorkerObserver::new(
        backend.callback_observer().unwrap(),
        capture,
    ));
    (
        Measured {
            backend,
            observer: observer.clone(),
        },
        observer,
    )
}

impl<B> Measured<B> {
    /// The measured backend, as a view install reaches it.
    pub(super) fn backend(measured: &mut Self) -> &mut B {
        &mut measured.backend
    }
    fn call<T>(&mut self, action: impl FnOnce(&mut B) -> T) -> T {
        let start = self.observer.clock.start().unwrap();
        // The query oracle is disabled; transition and production guards remain active.
        let (answer, query, storage) =
            crate::overlay_store::work::measure(|| action(&mut self.backend));
        let mut current = self.observer.current.lock().unwrap();
        current.0.query.namespace_copies += query.namespace_copies;
        current.0.query.primary_visits += query.primary_visits;
        current.0.query.entry_copies += query.entry_copies;
        current.0.storage_clones += storage.namespace_clones;
        current.0.storage_rows += storage.primary_rows;
        current.0.backend_ns += self.observer.clock.elapsed(&start).unwrap().as_nanos();
        answer
    }
}

impl<B: granary_vfs::GrainFetch> granary_vfs::GrainFetch for Measured<B> {
    fn grain(
        &mut self,
        id: &GrainId,
        length: u32,
    ) -> Result<Vec<u8>, granary_vfs::GrainUnavailable> {
        self.call(|backend| backend.grain(id, length))
    }
}

impl<B: MountBackend> MountBackend for Measured<B> {
    type DirectoryCursor = B::DirectoryCursor;
    fn callback_observer(&self) -> Option<Arc<dyn CallbackObserver>> {
        Some(self.observer.clone())
    }
    fn view_boundary(&self) -> Option<Arc<dyn granary_fuse::ViewBoundary>> {
        self.backend.view_boundary()
    }
    fn overlay_children(
        &mut self,
        cursor: &Self::DirectoryCursor,
    ) -> Result<granary_fuse::OverlayChildren<Self::DirectoryCursor>, granary_fuse::WriteError>
    {
        let answer = self.call(|backend| backend.overlay_children(cursor));
        if let Ok(page) = &answer {
            let mut current = self.observer.current.lock().unwrap();
            current.0.child_rows += page.entries.len();
            current.0.pages += 1;
        }
        answer
    }
    fn overlay_path(
        &mut self,
        path: &[Name],
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        self.call(|backend| backend.overlay_path(path))
    }
    fn overlay_lookup(
        &mut self,
        parent: &[Name],
        name: &Name,
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        self.call(|backend| backend.overlay_lookup(parent, name))
    }
    fn overlay_directory(
        &mut self,
        path: &[Name],
    ) -> Result<granary_fuse::OverlayDirectory<Self::DirectoryCursor>, granary_fuse::WriteError>
    {
        {
            let mut current = self.observer.current.lock().unwrap();
            let start = (current.0.child_rows, current.0.query.entry_copies);
            current.0.listing_attempt_starts.push(start);
        }
        self.call(|backend| backend.overlay_directory(path))
    }
    fn mutation_readiness(&mut self) -> Result<(), granary_fuse::MountError> {
        self.call(B::mutation_readiness)
    }
    fn overlay_nodes(
        &mut self,
    ) -> Result<Vec<granary_fuse::OverlayNode>, granary_fuse::WriteError> {
        self.call(B::overlay_nodes)
    }
    fn overlay_capacity(
        &mut self,
    ) -> Result<granary_fuse::OverlayCapacity, granary_fuse::WriteError> {
        self.call(B::overlay_capacity)
    }
    fn overlay_readlink(&mut self, path: &[Name]) -> Result<Vec<u8>, granary_fuse::WriteError> {
        self.call(|backend| backend.overlay_readlink(path))
    }
    fn prepare_shrink_retry(
        &mut self,
        request: granary_fuse::MountShrinkRequest,
    ) -> Result<Box<dyn granary_fuse::MountSyncJob>, granary_fuse::MountSyncError> {
        self.call(|backend| backend.prepare_shrink_retry(request))
    }

    fn prepare_sync(
        &mut self,
        request: granary_fuse::MountSyncRequest,
    ) -> Result<Box<dyn granary_fuse::MountSyncJob>, granary_fuse::MountSyncError> {
        self.observer
            .history
            .lock()
            .unwrap()
            .sync_requested(&request);
        self.call(|backend| backend.prepare_sync(request))
    }

    fn overlay_open(&mut self, path: &[Name]) -> Result<Option<u64>, granary_fuse::WriteError> {
        self.call(|backend| backend.overlay_open(path))
    }
    fn overlay_object(
        &mut self,
        object: u64,
    ) -> Result<granary_fuse::OverlayNode, granary_fuse::WriteError> {
        self.call(|backend| backend.overlay_object(object))
    }
    fn overlay_close(&mut self, object: u64) -> Result<(), granary_fuse::WriteError> {
        self.call(|backend| backend.overlay_close(object))
    }
    fn prepare_object(&mut self, object: u64) -> Result<(), granary_fuse::WriteError> {
        self.call(|backend| backend.prepare_object(object))
    }
    fn prepare_detach(&mut self, path: &[Name]) -> Result<(), granary_fuse::WriteError> {
        self.call(|backend| backend.prepare_detach(path))
    }
    fn read_object(
        &mut self,
        object: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, granary_fuse::WriteError> {
        self.call(|backend| backend.read_object(object, offset, length))
    }
    fn prepare_overlay(&mut self, path: &[Name]) -> Result<(), granary_fuse::WriteError> {
        self.call(|backend| backend.prepare_overlay(path))
    }
    fn overlay_setattr(
        &mut self,
        path: &[Name],
        size: Option<u64>,
        exec: Option<bool>,
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        self.call(|backend| backend.overlay_setattr(path, size, exec))
    }
    fn overlay_mutate(
        &mut self,
        operation: granary_fuse::OverlayMutation<'_>,
    ) -> Result<(), granary_fuse::WriteError> {
        self.call(|backend| backend.overlay_mutate(operation))
    }
    fn shutdown(&mut self) -> Result<(), String> {
        self.call(B::shutdown)
    }

    fn abandon(&mut self) {
        self.backend.abandon();
    }
}

fn file(name: String, content: GrainId) -> DirEntry {
    DirEntry {
        name: Name::new(name.into_bytes()).unwrap(),
        kind: EntryKind::File {
            exec: false,
            size: u64::try_from(FILE_CONTENT.len()).unwrap(),
            grains: FileGrains::Inline(vec![GrainRef {
                id: content,
                unpacked_len: u32::try_from(FILE_CONTENT.len()).unwrap(),
            }]),
        },
    }
}

/// Publish a real signed tree without one host file per unrelated name.
fn tree(paths: &Paths, unrelated: usize, children: usize) -> PublishedTree {
    let store = Store::open(&paths.scratch.join("publication")).unwrap();
    let file_id = GrainId::of(FILE_CONTENT);
    store.put(&file_id, FILE_CONTENT).unwrap();
    let sub = build_dir(
        &(0..children)
            .map(|n| file(format!("child-{n:06}"), file_id))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    for (id, bytes) in &sub.nodes {
        store.put(id, bytes).unwrap();
    }
    let mut entries = vec![
        DirEntry {
            name: Name::new(b"sub".to_vec()).unwrap(),
            kind: EntryKind::Dir { child: sub.root },
        },
        file("zz-last".to_owned(), file_id),
    ];
    entries.extend((0..unrelated).map(|n| file(format!("unrelated-{n:06}"), file_id)));
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    let root = build_dir(&entries).unwrap();
    for (id, bytes) in &root.nodes {
        store.put(id, bytes).unwrap();
    }
    let mem = Arc::new(InMemory::new());
    let remote = GranaryStore::new(mem.clone());
    let (key, seed) = SigningKey::generate().unwrap();
    let volume = vol("v");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let prepared = rt
        .block_on(crate::publish::prepare_from_manifest(
            &remote,
            &store,
            root.root,
            crate::harvest::HarvestStats::default(),
            &volume,
            &key,
            &WriterIdentity::from_bytes(*b"mount-writer-id!"),
            stamp(),
            Policy::default(),
        ))
        .unwrap();
    let summary = rt
        .block_on(crate::publish::commit(&remote, prepared))
        .unwrap();
    let (outcome, _) = rt
        .block_on(crate::resolve::resolve_at_collecting(
            &remote,
            volume.as_str(),
            1,
        ))
        .unwrap();
    assert_eq!(summary.seq, 1, "actual published sequence={}", summary.seq);
    PublishedTree {
        seq: 1,
        seed,
        remote,
        mem,
        key,
        volume,
        file_id,
        manifest_root: outcome.doc.manifest_root,
        binmap_index: outcome.doc.binmap_index,
        sheaf_head: outcome.doc.sheaf_head,
    }
}

fn mounted(
    paths: &Paths,
    tree: &PublishedTree,
    cardinality: usize,
) -> (SessionGuard, Arc<WorkerObserver>) {
    let input = input(tree, paths);
    let (proof, _, _) = attempt(&input, tree, "valid", &Events::default());
    let mut attachment = proof.unwrap().attach();
    let (nodes, calibration, _) =
        crate::overlay_store::work::measure(|| attachment.backend.overlay_nodes());
    let nodes = nodes.unwrap();
    assert_eq!(
        (
            calibration.namespace_copies,
            calibration.primary_visits >= cardinality,
            calibration.entry_copies >= cardinality
        ),
        (1, true, true),
        "actual nonempty accounting calibration={calibration:?}"
    );
    assert_eq!(
        nodes.len(),
        cardinality + 1,
        "actual namespace plus root={}",
        nodes.len()
    );
    let observer = Arc::new(WorkerObserver::new(
        attachment.backend.callback_observer().unwrap(),
        None,
    ));
    let session = granary_fuse::spawn_session(
        attachment.snapshot,
        Measured {
            backend: attachment.backend,
            observer: observer.clone(),
        },
        1,
        granary_fuse::MountWritability::Writable,
        &paths.mountpoint,
        &attachment.config,
    )
    .unwrap();
    (SessionGuard::new(session, &paths.mountpoint), observer)
}

fn validate_rows(
    rows: &[Completion],
    callback: Callback,
    listing: bool,
) -> Result<usize, &'static str> {
    let mut count = 0;
    for row in rows.iter().filter(|row| row.callback == callback) {
        count += 1;
        if row.outcome != CallbackOutcome::Ok
            && !(callback == Callback::Lookup && row.outcome == CallbackOutcome::Refused)
        {
            return Err("callback outcome mismatch");
        }
        if row.work.query.namespace_copies != 0 {
            return Err("whole namespace query copy");
        }
        if row.work.query.primary_visits != 0 {
            return Err("primary map iteration");
        }
        if listing {
            if row.work.listing_attempt_starts.is_empty() {
                return Err("no listing attempts");
            }
            for (index, &(children, copies)) in row.work.listing_attempt_starts.iter().enumerate() {
                let (end_children, end_copies) = row
                    .work
                    .listing_attempt_starts
                    .get(index + 1)
                    .copied()
                    .unwrap_or((row.work.child_rows, row.work.query.entry_copies));
                let extra = end_copies
                    .saturating_sub(copies)
                    .saturating_sub(end_children.saturating_sub(children));
                if extra > 2 {
                    return Err("entry copy bound exceeded");
                }
            }
        } else if row.work.query.entry_copies > 2 {
            return Err("entry copy bound exceeded");
        }
    }
    if count == 0 {
        Err("no callback completions")
    } else {
        Ok(count)
    }
}

#[test]
fn writable_linux_work_witness_valid_and_malformed_controls() {
    let good = Completion {
        callback: Callback::Getattr,
        outcome: CallbackOutcome::Ok,
        work: Work {
            query: QueryWork {
                entry_copies: 2,
                ..QueryWork::default()
            },
            ..Work::default()
        },
        elapsed_ns: 1,
    };
    let mut cases = 0;
    for (field, refusal) in [
        (0, "whole namespace query copy"),
        (1, "primary map iteration"),
        (2, "entry copy bound exceeded"),
        (3, "callback outcome mismatch"),
        (4, "no callback completions"),
    ] {
        assert_eq!(
            validate_rows(std::slice::from_ref(&good), Callback::Getattr, false),
            Ok(1)
        );
        let mut bad = good.clone();
        match field {
            0 => bad.work.query.namespace_copies = 1,
            1 => bad.work.query.primary_visits = 1,
            2 => bad.work.query.entry_copies = 3,
            3 => bad.outcome = CallbackOutcome::Refused,
            _ => bad.callback = Callback::Lookup,
        }
        assert_eq!(
            (validate_rows(&[bad], Callback::Getattr, false), 1),
            (Err(refusal), 1)
        );
        cases += 1;
    }
    let mut page = good;
    page.callback = Callback::Readdirplus;
    page.work.child_rows = 600;
    page.work.listing_attempt_starts = vec![(0, 0)];
    page.work.query.entry_copies = 602;
    assert_eq!(
        validate_rows(std::slice::from_ref(&page), Callback::Readdirplus, true),
        Ok(1)
    );
    let mut retried = page.clone();
    retried.work.child_rows = 856;
    retried.work.query.entry_copies = 860;
    retried.work.listing_attempt_starts = vec![(0, 0), (256, 258)];
    assert_eq!(
        validate_rows(std::slice::from_ref(&retried), Callback::Readdirplus, true),
        Ok(1),
        "two listing attempts each copy 2 extra entries"
    );
    retried.work.listing_attempt_starts = vec![(0, 0), (256, 259)];
    assert_eq!(
        (
            validate_rows(std::slice::from_ref(&retried), Callback::Readdirplus, true),
            retried.work.listing_attempt_starts.len()
        ),
        (Err("entry copy bound exceeded"), 2),
        "an over-budget first attempt cannot borrow the second attempt's allowance"
    );
    let mut absent_attempt = page.clone();
    absent_attempt.work.listing_attempt_starts.clear();
    assert_eq!(
        (
            validate_rows(&[absent_attempt], Callback::Readdirplus, true),
            1
        ),
        (Err("no listing attempts"), 1)
    );
    page.work.query.entry_copies = 603;
    assert_eq!(
        (validate_rows(&[page], Callback::Readdirplus, true), cases),
        (Err("entry copy bound exceeded"), 5)
    );
    eprintln!("paired claims=8; valid cases=8; malformed cases=8");
}

fn max_work(selected: &[&Completion]) -> Work {
    let mut max = Work::default();
    for row in selected {
        max.query.namespace_copies = max
            .query
            .namespace_copies
            .max(row.work.query.namespace_copies);
        max.query.primary_visits = max.query.primary_visits.max(row.work.query.primary_visits);
        max.query.entry_copies = max.query.entry_copies.max(row.work.query.entry_copies);
        max.storage_clones = max.storage_clones.max(row.work.storage_clones);
        max.storage_rows = max.storage_rows.max(row.work.storage_rows);
        max.child_rows = max.child_rows.max(row.work.child_rows);
        max.pages = max.pages.max(row.work.pages);
        max.backend_ns = max.backend_ns.max(row.work.backend_ns);
        if row.work.listing_attempt_starts.len() > max.listing_attempt_starts.len() {
            max.listing_attempt_starts = row.work.listing_attempt_starts.clone();
        }
    }
    max
}

fn assert_work(observer: &WorkerObserver, callbacks: &[Callback], listing: bool) {
    let rows = observer.completed.lock().unwrap();
    for callback in callbacks {
        let selected: Vec<_> = rows
            .iter()
            .filter(|row| row.callback == *callback)
            .collect();
        assert!(
            !selected.is_empty(),
            "actual {callback:?} completions=0; all={rows:?}"
        );
        assert_eq!(
            validate_rows(&rows, *callback, listing),
            Ok(selected.len()),
            "actual callback rows={selected:?}"
        );
        assert!(
            selected
                .iter()
                .any(|row| row.outcome == CallbackOutcome::Ok),
            "actual successful {callback:?} completions=0; rows={selected:?}"
        );
        let mut times: Vec<_> = selected.iter().map(|row| row.elapsed_ns).collect();
        times.sort_unstable();
        let mut backend: Vec<_> = selected.iter().map(|row| row.work.backend_ns).collect();
        backend.sort_unstable();
        let max_work = max_work(&selected);
        eprintln!(
            "mounted work: callback={callback:?}, calls={}, p50_ns={}, p95_ns={}, backend_p50_ns={}, backend_p95_ns={}, max_work={max_work:?}",
            times.len(),
            times[times.len() / 2],
            times[(times.len() - 1) * 95 / 100],
            backend[backend.len() / 2],
            backend[(backend.len() - 1) * 95 / 100]
        );
    }
}

fn available(case: &str) -> bool {
    if Path::new("/dev/fuse").exists() {
        true
    } else {
        eprintln!("SKIPPED-NO-DEV-FUSE {case}");
        false
    }
}

fn workspace_paths() -> Paths {
    let base = runtime_workspace_scratch().unwrap();
    std::fs::create_dir_all(&base).unwrap();
    Paths::with_store_base(&base)
}

fn last_key(unrelated: usize) {
    let paths = workspace_paths();
    let tree = tree(&paths, unrelated, 100);
    let (mut mount, observer) = mounted(&paths, &tree, unrelated + 102);
    let path = paths.mountpoint.join("zz-last");
    let held = std::fs::File::open(&path).unwrap();
    let inode = held.metadata().unwrap().ino();
    observer.completed.lock().unwrap().clear();
    for _ in 0..100 {
        let by_name = std::fs::metadata(&path).unwrap();
        let by_handle = held.metadata().unwrap();
        let rows = observer.completed.lock().unwrap();
        let measured = rows
            .iter()
            .rev()
            .find(|row| row.callback == Callback::Getattr)
            .unwrap_or_else(|| panic!("actual GETATTR completions=0; rows={rows:?}"));
        assert_eq!(
            (
                (
                    by_name.ino(),
                    by_name.len(),
                    by_name.mode() & 0o777,
                    by_handle.ino(),
                    by_handle.len(),
                    by_handle.mode() & 0o777
                ),
                measured.outcome,
                measured.work.query.namespace_copies,
                measured.work.query.primary_visits,
                measured.work.query.entry_copies <= 2
            ),
            (
                (
                    inode,
                    u64::try_from(FILE_CONTENT.len()).unwrap(),
                    0o644,
                    inode,
                    u64::try_from(FILE_CONTENT.len()).unwrap(),
                    0o644
                ),
                CallbackOutcome::Ok,
                0,
                0,
                true
            ),
            "actual attributes and worker work={measured:?}"
        );
    }
    drop(held);
    mount.finish().unwrap();
    assert_work(&observer, &[Callback::Lookup, Callback::Getattr], false);
}

#[test]
fn writable_linux_last_key_getattr_lookup_work_10000() {
    if available(stringify!(
        writable_linux_last_key_getattr_lookup_work_10000
    )) {
        last_key(10_000);
    }
}

#[test]
#[ignore = "scale lane: run serially in the scheduled scale job with its own timeout"]
fn writable_linux_last_key_getattr_lookup_work_100000() {
    if available(stringify!(
        writable_linux_last_key_getattr_lookup_work_100000
    )) {
        last_key(100_000);
    }
}

#[test]
#[ignore = "scale lane: run serially in the scheduled scale job with its own timeout"]
fn writable_linux_last_key_getattr_lookup_work_1000000() {
    if available(stringify!(
        writable_linux_last_key_getattr_lookup_work_1000000
    )) {
        last_key(1_000_000);
    }
}

fn operations(unrelated: usize, held_count: usize) {
    let paths = workspace_paths();
    let tree = tree(&paths, unrelated, 100);
    let input = input(&tree, &paths);
    let journal = journal_path(&paths, &input);
    let (mut mount, observer) = mounted(&paths, &tree, unrelated + 102);
    let initial_records = captured_records(&paths, &input).1.len();
    let extra_holds: Vec<_> = (0..held_count - 1)
        .map(|n| std::fs::File::open(paths.mountpoint.join(format!("unrelated-{n:06}"))).unwrap())
        .collect();
    assert_eq!(
        extra_holds.len() + 1,
        held_count,
        "actual held-object cardinality"
    );
    let path = paths.mountpoint.join("zz-last");
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let inode = held.metadata().unwrap().ino();
    let shared = std::fs::File::open(&path).unwrap();
    let mut bytes = vec![0; FILE_CONTENT.len()];
    held.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(bytes, FILE_CONTENT);
    held.write_all_at(b"Z", 0).unwrap();
    held.set_len(2).unwrap();
    let mut shared_bytes = [0; 2];
    shared.read_exact_at(&mut shared_bytes, 0).unwrap();
    assert_eq!(
        (shared.metadata().unwrap().ino(), shared_bytes),
        (inode, [b'Z', FILE_CONTENT[1]])
    );
    std::fs::remove_file(&path).unwrap();
    let absent = std::fs::metadata(&path).unwrap_err().raw_os_error();
    let replacement = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    held.write_all_at(b"!", 1).unwrap();
    let mut orphan = [0; 2];
    held.read_exact_at(&mut orphan, 0).unwrap();
    assert_eq!(
        (
            absent,
            held.metadata().unwrap().ino(),
            orphan,
            replacement.metadata().unwrap().len(),
            replacement.metadata().unwrap().ino() != inode
        ),
        (Some(2), inode, *b"Z!", 0, true),
        "detached identity, old name absence and no reattachment"
    );
    drop(replacement);
    drop(shared);
    drop(held);
    drop(extra_holds);
    mount.finish().unwrap();
    let (_, records) = captured_records(&paths, &input);
    assert_eq!(
        records.get(initial_records..).map(capture_kinds),
        Some(vec!["bind", "write", "truncate", "unlink", "file", "write"])
    );
    assert!(std::fs::metadata(journal).unwrap().len() > 0);
    assert_work(
        &observer,
        &[
            Callback::Lookup,
            Callback::Getattr,
            Callback::Open,
            Callback::Read,
            Callback::Write,
            Callback::Setattr,
        ],
        false,
    );
    // Detach can prepare an object before the local delete; storage clones remain separate.
    assert_work(&observer, &[Callback::Unlink], false);
    let rows = observer.completed.lock().unwrap();
    assert!(
        rows.iter().any(|row| row.callback == Callback::Write
            && row.work.storage_clones > 0
            && row.work.storage_rows >= unrelated + 102),
        "actual storage work={rows:?}"
    );
}

#[test]
fn writable_linux_open_read_write_setattr_unlink_work_10000() {
    if available(stringify!(
        writable_linux_open_read_write_setattr_unlink_work_10000
    )) {
        operations(10_000, 1);
    }
}

#[test]
#[ignore = "scale lane: run serially in the scheduled scale job with its own timeout"]
fn writable_linux_open_read_write_setattr_unlink_work_100000() {
    if available(stringify!(
        writable_linux_open_read_write_setattr_unlink_work_100000
    )) {
        operations(100_000, 1);
    }
}

fn listing(unrelated: usize) {
    let paths = workspace_paths();
    let tree = tree(&paths, unrelated, 600);
    let (mut mount, observer) = mounted(&paths, &tree, unrelated + 602);
    let directory = paths.mountpoint.join("sub");
    // A separate actor mutates between small getdents refills on the same open handle.
    // Barriers make the mutation overlap deterministic rather than scheduler-dependent.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let actor_directory = directory.clone();
    let actor = std::thread::spawn(move || {
        ready_rx.recv().unwrap();
        let new = actor_directory.join("aaa-new");
        drop(std::fs::File::create(&new).unwrap());
        std::fs::remove_file(actor_directory.join("child-000599")).unwrap();
        done_tx.send(()).unwrap();
    });
    // libc is already the client's syscall seam. Python avoids adding another edge.
    let script = "import ctypes,os,sys\nr=sys.argv[1]\nc=ctypes.CDLL(None,use_errno=True)\nc.opendir.argtypes=[ctypes.c_char_p];c.opendir.restype=ctypes.c_void_p\nc.readdir.argtypes=[ctypes.c_void_p];c.readdir.restype=ctypes.c_void_p\nc.telldir.argtypes=[ctypes.c_void_p];c.telldir.restype=ctypes.c_long\nc.seekdir.argtypes=[ctypes.c_void_p,ctypes.c_long]\nc.closedir.argtypes=[ctypes.c_void_p]\nd=c.opendir(os.fsencode(r));assert d\ndef name():\n p=c.readdir(d)\n return None if not p else ctypes.string_at(p+19)\nhead=[name() for _ in range(300)];assert None not in head\nk=c.telldir(d);assert k>0\nprint('READY',flush=True)\nassert sys.stdin.readline().strip()=='GO'\nc.seekdir(d,k)\ntail=[]\nwhile True:\n n=name()\n if n is None: break\n tail.append(n)\nallnames=head+tail\nassert len(allnames)==len(set(allnames)),allnames\nexpected={b'.',b'..',b'aaa-new'}|{('child-%06d'%i).encode() for i in range(599)}\nassert set(allnames)==expected,(len(allnames),len(expected),set(allnames)^expected)\nc.seekdir(d,k)\nagain=[]\nwhile True:\n n=name()\n if n is None: break\n again.append(n)\nassert again==tail,(again,tail)\nassert c.closedir(d)==0\nprint('cases=1; names=602; cookie replay=1',flush=True)";
    let mut child = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(&directory)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "READY", "actual driver premise={line:?}");
    ready_tx.send(()).unwrap();
    done_rx.recv().unwrap();
    actor.join().unwrap();
    child.stdin.take().unwrap().write_all(b"GO\n").unwrap();
    line.clear();
    output.read_to_string(&mut line).unwrap();
    assert_eq!(
        (child.wait().unwrap().success(), line.trim()),
        (true, "cases=1; names=602; cookie replay=1")
    );
    assert_eq!(names(&directory).len(), 600);
    mount.finish().unwrap();
    let rows = observer.completed.lock().unwrap();
    assert!(
        rows.iter().any(
            |row| matches!(row.callback, Callback::Readdir | Callback::Readdirplus)
                && row.work.pages >= 3
        ),
        "actual multi-page callbacks={rows:?}"
    );
    let callbacks: Vec<_> = [Callback::Readdir, Callback::Readdirplus]
        .into_iter()
        .filter(|c| rows.iter().any(|row| row.callback == *c))
        .collect();
    drop(rows);
    assert!(!callbacks.is_empty());
    assert_work(&observer, &callbacks, true);
}

#[test]
fn writable_linux_listing_pages_concurrent_create_unlink_work_10000() {
    if available(stringify!(
        writable_linux_listing_pages_concurrent_create_unlink_work_10000
    )) {
        listing(10_000);
    }
}

#[test]
#[ignore = "scale lane: run serially in the scheduled scale job with its own timeout"]
fn writable_linux_listing_pages_concurrent_create_unlink_work_100000() {
    if available(stringify!(
        writable_linux_listing_pages_concurrent_create_unlink_work_100000
    )) {
        listing(100_000);
    }
}

#[test]
#[ignore = "scale lane: run serially in the scheduled scale job with its own timeout"]
fn writable_linux_open_read_write_setattr_unlink_work_1000000() {
    if available(stringify!(
        writable_linux_open_read_write_setattr_unlink_work_1000000
    )) {
        operations(1_000_000, 1);
    }
}

#[test]
fn writable_linux_open_read_write_setattr_unlink_work_17_held_objects() {
    if available(stringify!(
        writable_linux_open_read_write_setattr_unlink_work_17_held_objects
    )) {
        operations(10_000, 17);
    }
}

#[test]
#[ignore = "scale lane: run serially in the scheduled scale job with its own timeout"]
fn writable_linux_listing_pages_concurrent_create_unlink_work_1000000() {
    if available(stringify!(
        writable_linux_listing_pages_concurrent_create_unlink_work_1000000
    )) {
        listing(1_000_000);
    }
}
