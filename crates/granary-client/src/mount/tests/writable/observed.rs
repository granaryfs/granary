// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Ordered callback outcomes and sync-job attribution for mounted witnesses.

use crate::SyncRuntime as _;
use granary_core::hash::GrainId;
use granary_fuse::CallbackScope;
use granary_fuse::{Callback, CallbackOutcome, MountSyncRequest};
use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub(super) struct CallbackHistory {
    pub(super) active: Option<Callback>,
    pub(super) outcomes: Vec<(Callback, CallbackOutcome)>,
    pub(super) sync_requests: Vec<(Option<Callback>, bool, bool)>,
}
impl CallbackHistory {
    pub(super) fn write_results(&self) -> Vec<CallbackOutcome> {
        self.outcomes
            .iter()
            .copied()
            .filter(|(callback, _)| *callback == Callback::Write)
            .map(|(_, outcome)| outcome)
            .collect()
    }
    pub(super) fn sync_requested(&mut self, request: &MountSyncRequest) {
        let (directory, datasync) = match request {
            MountSyncRequest::File { datasync, .. } => (false, *datasync),
            MountSyncRequest::Directory { datasync, .. } => (true, *datasync),
        };
        self.sync_requests.push((self.active, directory, datasync));
    }
}

#[test]
fn write_results_preserve_arrival_order_after_seed() {
    let mut history = CallbackHistory::default();
    history
        .outcomes
        .push((Callback::Write, CallbackOutcome::Ok));
    let before = history.write_results().len();
    history
        .outcomes
        .push((Callback::Fsync, CallbackOutcome::Ok));
    history.outcomes.push((
        Callback::Write,
        CallbackOutcome::Failed(granary_fuse::MountError::Io),
    ));
    assert_eq!(
        history.write_results()[before..],
        [CallbackOutcome::Failed(granary_fuse::MountError::Io)],
        "new synchronous outcome must not select the seed write"
    );
}

#[test]
fn sync_requests_record_missing_attribution_instead_of_panicking() {
    let mut history = CallbackHistory::default();
    let request = MountSyncRequest::File {
        object: 42,
        datasync: true,
    };
    history.active = Some(Callback::Write);
    history.sync_requested(&request);
    history.active = None;
    history.sync_requested(&request);
    assert_eq!(
        history.sync_requests,
        [(Some(Callback::Write), false, true), (None, false, true)]
    );
}

pub(super) fn sync_write_boundary(
    events: &[crate::SyncFaultEvent],
    occurrence: u64,
) -> Result<(), &'static str> {
    match events {
        [event]
            if event.name == "sync.reply"
                && event.phase == "before"
                && event.occurrence == occurrence
                && event.capture > 0
                && event.request.is_some() =>
        {
            Ok(())
        }
        _ => Err("synchronous WRITE did not reach its armed sync.reply boundary"),
    }
}

#[test]
fn sync_write_boundary_requires_new_arm_identity_not_previous_event_count() {
    let faults = crate::FaultControl::default();
    let request = Some(GrainId::of(b"request"));
    let mut cases = 0;
    for _ in 0..2 {
        faults.arm("sync.reply", "before", 1, crate::FaultAction::Fail);
        assert_eq!(
            faults.sync_point("sync.reply", "before", 4, request, "none"),
            Some(crate::FaultAction::Fail)
        );
        let valid = faults.sync_fired();
        assert_eq!(sync_write_boundary(&valid, 1), Ok(()));
        let mut bad = valid.clone();
        for claim in 0..6 {
            bad.clone_from(&valid);
            match claim {
                0 => bad.clear(),
                1 => bad[0].name = "fuse.sync.reply",
                2 => bad[0].phase = "after",
                3 => bad[0].occurrence = 2,
                4 => bad[0].capture = 0,
                _ => bad[0].request = None,
            }
            assert_eq!(
                sync_write_boundary(&bad, 1),
                Err("synchronous WRITE did not reach its armed sync.reply boundary"),
                "claim={claim}, events={bad:?}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 12);
}

#[derive(Debug)]
pub(super) struct WorkerScope {
    pub(super) _delegate: Option<Box<dyn CallbackScope>>,
    pub(super) history: Arc<Mutex<CallbackHistory>>,
}
impl CallbackScope for WorkerScope {}
impl Drop for WorkerScope {
    fn drop(&mut self) {
        self.history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active = None;
    }
}

#[test]
fn callback_scope_clears_attribution_before_a_later_sync_request() {
    let history = Arc::new(Mutex::new(CallbackHistory::default()));
    history.lock().unwrap().active = Some(Callback::Write);
    let scope = WorkerScope {
        _delegate: None,
        history: history.clone(),
    };
    let request = MountSyncRequest::File {
        object: 42,
        datasync: false,
    };
    history.lock().unwrap().sync_requested(&request);
    drop(scope);
    history.lock().unwrap().sync_requested(&request);
    assert_eq!(
        history.lock().unwrap().sync_requests,
        [(Some(Callback::Write), false, false), (None, false, false)]
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SyncFaultRoute {
    pub(super) name: &'static str,
    pub(super) phase: &'static str,
    pub(super) directory: bool,
    pub(super) expected_errno: i32,
    pub(super) expected_outcome: CallbackOutcome,
    pub(super) engine_outcome: (u64, u64),
    pub(super) acknowledged: (usize, usize),
}

pub(super) const SYNC_FAULT_MATRIX_ROUTES: [SyncFaultRoute; 13] = [
    SyncFaultRoute {
        name: "fuse.sync.view",
        phase: "observed",
        directory: false,
        expected_errno: 5,
        expected_outcome: CallbackOutcome::Failed(granary_fuse::MountError::Io),
        engine_outcome: (0, 0),
        acknowledged: (0, 0),
    },
    SyncFaultRoute {
        name: "fuse.sync.view",
        phase: "cleared",
        directory: false,
        expected_errno: 5,
        expected_outcome: CallbackOutcome::Failed(granary_fuse::MountError::Io),
        engine_outcome: (0, 0),
        acknowledged: (0, 0),
    },
    SyncFaultRoute {
        name: "fuse.sync.rename_directory",
        phase: "before",
        directory: true,
        expected_errno: 5,
        expected_outcome: CallbackOutcome::Failed(granary_fuse::MountError::Io),
        engine_outcome: (0, 0),
        acknowledged: (0, 0),
    },
    SyncFaultRoute {
        name: "sync.capture",
        phase: "after",
        directory: false,
        expected_errno: 5,
        expected_outcome: CallbackOutcome::Failed(granary_fuse::MountError::Io),
        engine_outcome: (0, 1),
        acknowledged: (0, 0),
    },
    SyncFaultRoute {
        name: "sync.upload",
        phase: "before",
        directory: false,
        expected_errno: 5,
        expected_outcome: CallbackOutcome::Failed(granary_fuse::MountError::Io),
        engine_outcome: (0, 1),
        acknowledged: (0, 0),
    },
    SyncFaultRoute {
        name: "sync.upload",
        phase: "accepted",
        directory: false,
        expected_errno: 5,
        expected_outcome: CallbackOutcome::Failed(granary_fuse::MountError::Io),
        engine_outcome: (0, 1),
        acknowledged: (0, 0),
    },
    SyncFaultRoute {
        name: "sync.node_upload",
        phase: "before",
        directory: false,
        expected_errno: 5,
        expected_outcome: CallbackOutcome::Failed(granary_fuse::MountError::Io),
        engine_outcome: (0, 1),
        acknowledged: (0, 0),
    },
    SyncFaultRoute {
        name: "sync.node_upload",
        phase: "accepted",
        directory: false,
        expected_errno: 5,
        expected_outcome: CallbackOutcome::Failed(granary_fuse::MountError::Io),
        engine_outcome: (0, 1),
        acknowledged: (0, 0),
    },
    SyncFaultRoute {
        name: "sync.registration",
        phase: "before_dispatch",
        directory: false,
        expected_errno: 5,
        expected_outcome: CallbackOutcome::Failed(granary_fuse::MountError::Io),
        engine_outcome: (0, 1),
        acknowledged: (0, 0),
    },
    SyncFaultRoute {
        name: "sync.registration",
        phase: "after_response",
        directory: false,
        expected_errno: 5,
        expected_outcome: CallbackOutcome::Failed(granary_fuse::MountError::Io),
        engine_outcome: (0, 1),
        acknowledged: (1, 0),
    },
    SyncFaultRoute {
        name: "sync.reply",
        phase: "before",
        directory: false,
        expected_errno: 5,
        expected_outcome: CallbackOutcome::Failed(granary_fuse::MountError::Io),
        engine_outcome: (0, 1),
        acknowledged: (1, 1),
    },
    SyncFaultRoute {
        name: "sync.floor",
        phase: "checked",
        directory: false,
        expected_errno: 5,
        expected_outcome: CallbackOutcome::Failed(granary_fuse::MountError::Io),
        engine_outcome: (1, 0),
        acknowledged: (1, 1),
    },
    SyncFaultRoute {
        name: "fuse.sync.reply",
        phase: "before",
        directory: false,
        expected_errno: 5,
        expected_outcome: CallbackOutcome::Failed(granary_fuse::MountError::Io),
        engine_outcome: (1, 0),
        acknowledged: (1, 1),
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SyncFaultSample {
    pub(super) syscall_errno: Result<(), Option<i32>>,
    pub(super) engine_outcome: (u64, u64),
    pub(super) acknowledged: (usize, usize),
    pub(super) prepared_bytes: Vec<u8>,
    pub(super) published_head: (GrainId, u64),
    pub(super) terminal_outcomes: Vec<(Callback, CallbackOutcome)>,
    pub(super) fired: Vec<crate::SyncFaultEvent>,
}

pub(super) fn check_sync_fault_route(
    route: &SyncFaultRoute,
    sample: &SyncFaultSample,
    expected_bytes: &[u8],
    expected_head: (GrainId, u64),
) -> Result<(), &'static str> {
    let [event] = sample.fired.as_slice() else {
        return Err("fault route did not record exactly one SyncFaultEvent");
    };
    if (event.name, event.phase, event.occurrence) != (route.name, route.phase, 1) {
        return Err("fired SyncFaultEvent did not match armed route identity");
    }
    let context_valid = match (route.name, route.phase) {
        ("fuse.sync.view", _) => event.request.is_some() && event.object_kind == "none",
        ("fuse.sync.rename_directory", _) => {
            event.capture == 0
                && event.request.is_none()
                && event.object_kind == "directory"
                && event.rename_directory.is_some()
        }
        ("sync.capture", _) => {
            event.capture > 0 && event.request.is_none() && event.object_kind == "none"
        }
        ("sync.upload", _) => {
            event.capture > 0 && event.request.is_none() && event.object_kind == "bin"
        }
        ("sync.node_upload", _) => {
            event.capture > 0
                && event.request.is_none()
                && matches!(
                    event.object_kind,
                    "manifest" | "grain_list" | "binmap" | "sheaf"
                )
        }
        ("sync.registration" | "sync.reply", _) => {
            event.capture > 0 && event.request.is_some() && event.object_kind == "none"
        }
        ("sync.floor" | "fuse.sync.reply", _) => {
            event.capture == 0 && event.request.is_none() && event.object_kind == "none"
        }
        _ => false,
    };
    if !context_valid {
        return Err("fired SyncFaultEvent carried invalid context for route");
    }
    let expected_callback = if route.name == "sync.floor" {
        Callback::Setattr
    } else if route.directory {
        Callback::Fsyncdir
    } else {
        Callback::Fsync
    };
    let mut expected_terminal = vec![(expected_callback, route.expected_outcome)];
    if route.name == "sync.floor" {
        expected_terminal.push((Callback::Fsync, CallbackOutcome::Ok));
    }
    if (
        sample.syscall_errno,
        sample.engine_outcome,
        sample.acknowledged,
        sample.prepared_bytes.as_slice(),
        sample.published_head,
        sample.terminal_outcomes.as_slice(),
    ) != (
        Err(Some(route.expected_errno)),
        route.engine_outcome,
        route.acknowledged,
        expected_bytes,
        expected_head,
        expected_terminal.as_slice(),
    ) {
        return Err("fault route tuple mismatched expected 6-tuple");
    }
    Ok(())
}

pub(super) fn check_sync_fault_matrix_coverage(
    executed: &[(&str, &str)],
) -> Result<(), &'static str> {
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        std::path::PathBuf::from,
    );
    check_sync_fault_matrix_at(executed, &manifest.join("src/sync/engine.rs"))
}

fn check_sync_fault_matrix_at(
    executed: &[(&str, &str)],
    engine_path: &std::path::Path,
) -> Result<(), &'static str> {
    let source =
        std::fs::read_to_string(engine_path).map_err(|_| "cannot read engine sync fault points")?;
    check_engine_fault_coverage(&source, executed)?;
    if executed.len() != SYNC_FAULT_MATRIX_ROUTES.len() {
        return Err("sync fault matrix skipped a required route");
    }
    for (actual, expected) in executed.iter().zip(SYNC_FAULT_MATRIX_ROUTES.iter()) {
        if *actual != (expected.name, expected.phase) {
            return Err("sync fault matrix skipped a required route");
        }
    }
    Ok(())
}

fn engine_fault_points<'a>(
    source: &'a str,
    prefix: &str,
) -> std::collections::BTreeSet<(&'a str, &'a str)> {
    let mut points = std::collections::BTreeSet::new();
    // The engine's async `fault` and the store's own `sync_point` name a point
    // the same way: a literal point and phase as the first two arguments.
    for call in [".fault(", ".sync_point("]
        .into_iter()
        .flat_map(|opener| source.split(opener).skip(1))
    {
        let literals: Vec<_> = call.split('"').take(5).collect();
        if let [_, name, _, phase, _] = literals.as_slice()
            && name.starts_with(prefix)
        {
            points.insert((*name, *phase));
        }
    }
    points
}

fn check_engine_fault_coverage(
    source: &str,
    executed: &[(&str, &str)],
) -> Result<(), &'static str> {
    let required = engine_fault_points(source, "sync.");
    if required.is_empty() {
        return Err("cannot read engine sync fault points");
    }
    let actual: std::collections::BTreeSet<_> = executed
        .iter()
        .copied()
        .filter(|(name, _)| name.starts_with("sync."))
        .collect();
    if actual != required {
        return Err("sync fault matrix skipped an engine sync-path point");
    }
    Ok(())
}

/// A commit-lane fault point and what the engine leaves behind once it has
/// fired: where the authority's head stands, whether the mount still serves its
/// old view, and whether driving the same lane again lands it in this process.
/// A rebasing route first advances the authority's head on a path the commit
/// does not touch, so its retry merges onto that head, needs an explicit
/// recovery and lands a sequence later. A route with no retained lane keeps the
/// durable boundary it recorded until the process restarts.
/// The commit lane lives in its own engine files, so these routes are checked
/// against them rather than against `SYNC_FAULT_MATRIX_ROUTES`' source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CommitFaultRoute {
    pub(super) name: &'static str,
    pub(super) phase: &'static str,
    pub(super) remote_seq: u64,
    pub(super) serving: bool,
    pub(super) retry_lands: bool,
    pub(super) rebases: bool,
}

pub(super) const COMMIT_FAULT_ROUTES: [CommitFaultRoute; 9] = [
    CommitFaultRoute {
        name: "sync.commit_wait",
        phase: "before",
        remote_seq: 1,
        serving: false,
        retry_lands: true,
        rebases: false,
    },
    CommitFaultRoute {
        name: "sync.commit",
        phase: "captured",
        remote_seq: 1,
        serving: true,
        retry_lands: true,
        rebases: false,
    },
    CommitFaultRoute {
        name: "sync.commit",
        phase: "boundary_recorded",
        remote_seq: 1,
        serving: true,
        retry_lands: false,
        rebases: false,
    },
    CommitFaultRoute {
        name: "sync.commit",
        phase: "before_submit",
        remote_seq: 1,
        serving: true,
        retry_lands: true,
        rebases: false,
    },
    CommitFaultRoute {
        name: "sync.commit",
        phase: "before_rebase",
        remote_seq: 2,
        serving: true,
        retry_lands: true,
        rebases: true,
    },
    CommitFaultRoute {
        name: "sync.commit",
        phase: "after_rebase",
        remote_seq: 2,
        serving: true,
        retry_lands: true,
        rebases: true,
    },
    CommitFaultRoute {
        name: "sync.commit",
        phase: "landed_readback",
        remote_seq: 2,
        serving: true,
        retry_lands: true,
        rebases: false,
    },
    CommitFaultRoute {
        name: "sync.commit",
        phase: "landed_refresh",
        remote_seq: 2,
        serving: false,
        retry_lands: false,
        rebases: false,
    },
    CommitFaultRoute {
        name: "sync.commit",
        phase: "before_replace",
        remote_seq: 2,
        serving: true,
        retry_lands: true,
        rebases: false,
    },
];

pub(super) fn check_commit_fault_coverage(executed: &[(&str, &str)]) -> Result<(), &'static str> {
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        std::path::PathBuf::from,
    );
    check_commit_fault_coverage_at(
        executed,
        &[
            manifest.join("src/sync/engine/commit.rs"),
            manifest.join("src/sync/engine/commit/driver.rs"),
            manifest.join("src/writable_store/sync_engine.rs"),
        ],
    )
}

fn check_commit_fault_coverage_at(
    executed: &[(&str, &str)],
    sources: &[std::path::PathBuf],
) -> Result<(), &'static str> {
    let mut texts = Vec::new();
    for path in sources {
        texts.push(
            std::fs::read_to_string(path).map_err(|_| "cannot read commit-lane fault points")?,
        );
    }
    let required: std::collections::BTreeSet<_> = texts
        .iter()
        .flat_map(|text| engine_fault_points(text, "sync.commit"))
        .collect();
    if required.is_empty() {
        return Err("cannot read commit-lane fault points");
    }
    let actual: std::collections::BTreeSet<_> = executed.iter().copied().collect();
    if actual != required {
        return Err("commit fault routes skipped a commit-lane point");
    }
    if executed.len() != COMMIT_FAULT_ROUTES.len() {
        return Err("commit fault routes skipped a required route");
    }
    for (actual, expected) in executed.iter().zip(COMMIT_FAULT_ROUTES.iter()) {
        if *actual != (expected.name, expected.phase) {
            return Err("commit fault routes skipped a required route");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InterruptSettlement {
    pub(super) pending_at_signal: bool,
    pub(super) pending_after_interrupt_enosys: bool,
    pub(super) caller_errno: Option<i32>,
    pub(super) engine_settled_at_caller_return: bool,
    pub(super) engine_outcome: (u64, u64),
    pub(super) terminal_outcomes: Vec<(Callback, CallbackOutcome)>,
}

pub(super) fn check_interrupt_settlement(
    sample: &InterruptSettlement,
    expect_engine_ok: bool,
) -> Result<(), &'static str> {
    if !sample.pending_at_signal || !sample.pending_after_interrupt_enosys {
        return Err("interrupt acknowledged original sync request before engine settlement");
    }
    let (expected_engine, expected_outcome) = if expect_engine_ok {
        ((1, 0), CallbackOutcome::Ok)
    } else {
        (
            (0, 1),
            CallbackOutcome::Failed(granary_fuse::MountError::Io),
        )
    };
    if sample.engine_outcome != expected_engine {
        return Err("interrupted sync did not settle with expected engine outcome");
    }
    if sample.terminal_outcomes != [(Callback::Fsync, expected_outcome)] {
        return Err("interrupted sync did not emit exactly one terminal original reply");
    }
    if expect_engine_ok {
        match sample.caller_errno {
            None => {
                if !sample.engine_settled_at_caller_return {
                    return Err(
                        "interrupt acknowledged original sync request before engine settlement",
                    );
                }
            }
            Some(4) => {}
            _ => return Err("unexpected caller errno on successful interrupted sync arm"),
        }
    } else if !matches!(sample.caller_errno, Some(4 | 5)) {
        return Err("failed interrupted sync arm acknowledged caller or returned wrong errno");
    }
    Ok(())
}

pub(super) fn sync_metric_counts(prometheus: &str) -> (u64, u64) {
    let parse = |label: &str| {
        let prefix = format!("granary_client_syncs_total{{outcome=\"{label}\"}} ");
        prometheus
            .lines()
            .find_map(|line| line.strip_prefix(&prefix)?.trim().parse::<u64>().ok())
            .unwrap_or(0)
    };
    (parse("ok"), parse("failed"))
}

pub(super) fn at_caller_return<T>(
    metrics: &crate::ClientMetrics,
    wait_terminal: impl FnOnce() -> T,
) -> (bool, T) {
    let rendered = metrics.snapshot().unwrap().render_prometheus().unwrap();
    let counts = sync_metric_counts(&rendered);
    let settled = counts.0 + counts.1 == 1;
    let terminal = wait_terminal();
    (settled, terminal)
}

#[test]
fn caller_return_samples_engine_before_terminal_wait() {
    let metrics = crate::ClientMetrics::new(&mut super::Entropy(35));
    metrics.set_available(crate::MetricsGroup::Sync, true);
    let (settled, terminal) = at_caller_return(&metrics, || {
        metrics.record_sync(crate::observe::Outcome::Ok);
        sync_metric_counts(&metrics.snapshot().unwrap().render_prometheus().unwrap())
    });
    assert_eq!(
        (settled, terminal),
        (false, (1, 0)),
        "late engine sampling hides an early caller acknowledgement"
    );
    assert!(at_caller_return(&metrics, || ()).0);
}

pub(super) fn file_synced_marks(records: &[granary_core::overlay_journal::Record]) -> usize {
    records
        .iter()
        .filter(|record| {
            matches!(
                record,
                granary_core::overlay_journal::Record::FileSynced { .. }
            )
        })
        .count()
}

#[test]
fn sync_fault_matrix_catalogue_and_tuple_controls_discriminate() {
    let head = (GrainId::of(b"base"), 1);
    let mut executed = Vec::new();
    let mut cases = 0;
    for route in &SYNC_FAULT_MATRIX_ROUTES {
        executed.push((route.name, route.phase));
        let event = crate::SyncFaultEvent {
            name: route.name,
            phase: route.phase,
            occurrence: 1,
            capture: u64::from(!matches!(
                route.name,
                "fuse.sync.view" | "fuse.sync.rename_directory" | "sync.floor" | "fuse.sync.reply"
            )),
            request: (matches!(
                route.name,
                "fuse.sync.view" | "sync.registration" | "sync.reply"
            ))
            .then(|| GrainId::of(b"req")),
            object_kind: match route.name {
                "fuse.sync.rename_directory" => "directory",
                "sync.upload" => "bin",
                "sync.node_upload" => "manifest",
                _ => "none",
            },
            rename_directory: (route.name == "fuse.sync.rename_directory").then_some(
                crate::RenameDirectoryFaultContext {
                    journal_cursor: 2,
                    directory_inode: None,
                },
            ),
        };
        let expected_callback = if route.name == "sync.floor" {
            Callback::Setattr
        } else if route.directory {
            Callback::Fsyncdir
        } else {
            Callback::Fsync
        };
        let valid = SyncFaultSample {
            syscall_errno: Err(Some(route.expected_errno)),
            engine_outcome: route.engine_outcome,
            acknowledged: route.acknowledged,
            prepared_bytes: b"bytes".to_vec(),
            published_head: head,
            terminal_outcomes: if route.name == "sync.floor" {
                vec![
                    (expected_callback, route.expected_outcome),
                    (Callback::Fsync, CallbackOutcome::Ok),
                ]
            } else {
                vec![(expected_callback, route.expected_outcome)]
            },
            fired: vec![event],
        };
        assert_eq!(
            check_sync_fault_route(route, &valid, b"bytes", head),
            Ok(())
        );
        let mut no_event = valid.clone();
        no_event.fired.clear();
        assert_eq!(
            check_sync_fault_route(route, &no_event, b"bytes", head),
            Err("fault route did not record exactly one SyncFaultEvent")
        );
        let mut wrong_phase = valid.clone();
        wrong_phase.fired[0].phase = "other";
        assert_eq!(
            check_sync_fault_route(route, &wrong_phase, b"bytes", head),
            Err("fired SyncFaultEvent did not match armed route identity")
        );
        let mut bad_ctx = valid.clone();
        bad_ctx.fired[0].object_kind = "invalid";
        assert_eq!(
            check_sync_fault_route(route, &bad_ctx, b"bytes", head),
            Err("fired SyncFaultEvent carried invalid context for route")
        );
        let mut bad_tuple = valid;
        bad_tuple.syscall_errno = Ok(());
        assert_eq!(
            check_sync_fault_route(route, &bad_tuple, b"bytes", head),
            Err("fault route tuple mismatched expected 6-tuple")
        );
        cases += 1;
    }
    assert_eq!(check_sync_fault_matrix_coverage(&executed), Ok(()));

    assert_eq!(cases, 13);
}

#[test]
fn sync_fault_matrix_coverage_refuses_missing_points_and_unreadable_source() {
    let executed: Vec<_> = SYNC_FAULT_MATRIX_ROUTES
        .iter()
        .map(|route| (route.name, route.phase))
        .collect();
    assert_eq!(check_sync_fault_matrix_coverage(&executed), Ok(()));
    assert_eq!(
        check_sync_fault_matrix_coverage(&executed[..executed.len() - 1]),
        Err("sync fault matrix skipped a required route")
    );
    let without_floor: Vec<_> = executed
        .iter()
        .copied()
        .filter(|(name, _)| *name != "sync.floor")
        .collect();
    assert_eq!(
        check_sync_fault_matrix_coverage(&without_floor),
        Err("sync fault matrix skipped an engine sync-path point")
    );
    assert_eq!(
        check_engine_fault_coverage("", &executed),
        Err("cannot read engine sync fault points")
    );
    assert_eq!(
        check_sync_fault_matrix_at(
            &executed,
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sync/absent-engine.rs")
        ),
        Err("cannot read engine sync fault points")
    );
    assert_eq!(executed.len(), 13);
}

#[test]
fn commit_fault_coverage_refuses_missing_points_order_and_unreadable_sources() {
    let executed: Vec<_> = COMMIT_FAULT_ROUTES
        .iter()
        .map(|route| (route.name, route.phase))
        .collect();
    assert_eq!(check_commit_fault_coverage(&executed), Ok(()));
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let commit = manifest.join("src/sync/engine/commit.rs");
    let driver = manifest.join("src/sync/engine/commit/driver.rs");
    let store = manifest.join("src/writable_store/sync_engine.rs");
    let scratch = super::Paths::new();
    let empty = scratch.scratch.join("no-fault-points.rs");
    std::fs::write(&empty, "fn nothing() {}\n").unwrap();
    let reversed: Vec<_> = executed.iter().rev().copied().collect();
    let mut cases = 0;
    for (executed, sources, refusal) in [
        (
            &executed[..executed.len() - 1],
            vec![commit.clone(), driver.clone(), store.clone()],
            "commit fault routes skipped a commit-lane point",
        ),
        (
            // The driver's points are only found if its file is read.
            &executed[..],
            vec![commit.clone(), store.clone()],
            "commit fault routes skipped a commit-lane point",
        ),
        (
            // The store's point is only found if its file is read.
            &executed[..],
            vec![commit.clone(), driver.clone()],
            "commit fault routes skipped a commit-lane point",
        ),
        (
            &reversed[..],
            vec![commit.clone(), driver.clone(), store.clone()],
            "commit fault routes skipped a required route",
        ),
        (
            &executed[..],
            vec![commit.clone(), scratch.scratch.join("absent.rs")],
            "cannot read commit-lane fault points",
        ),
        (
            &executed[..],
            vec![empty],
            "cannot read commit-lane fault points",
        ),
    ] {
        assert_eq!(
            check_commit_fault_coverage_at(executed, &sources),
            Err(refusal),
            "sources={sources:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 6);
    assert_eq!(executed.len(), 9);
}

#[test]
fn interrupt_settlement_refuses_early_acknowledgement_before_engine() {
    let valid_ok = InterruptSettlement {
        pending_at_signal: true,
        pending_after_interrupt_enosys: true,
        caller_errno: None,
        engine_settled_at_caller_return: true,
        engine_outcome: (1, 0),
        terminal_outcomes: vec![(Callback::Fsync, CallbackOutcome::Ok)],
    };
    assert_eq!(check_interrupt_settlement(&valid_ok, true), Ok(()));

    let valid_eintr = InterruptSettlement {
        caller_errno: Some(4),
        engine_settled_at_caller_return: false,
        ..valid_ok.clone()
    };
    assert_eq!(check_interrupt_settlement(&valid_eintr, true), Ok(()));

    let valid_err = InterruptSettlement {
        pending_at_signal: true,
        pending_after_interrupt_enosys: true,
        caller_errno: Some(5),
        engine_settled_at_caller_return: true,
        engine_outcome: (0, 1),
        terminal_outcomes: vec![(
            Callback::Fsync,
            CallbackOutcome::Failed(granary_fuse::MountError::Io),
        )],
    };
    assert_eq!(check_interrupt_settlement(&valid_err, false), Ok(()));

    let mut cases = 0;
    for (bad, expect_ok, refusal) in [
        (
            InterruptSettlement {
                pending_at_signal: false,
                ..valid_ok.clone()
            },
            true,
            "interrupt acknowledged original sync request before engine settlement",
        ),
        (
            InterruptSettlement {
                pending_after_interrupt_enosys: false,
                ..valid_ok.clone()
            },
            true,
            "interrupt acknowledged original sync request before engine settlement",
        ),
        (
            InterruptSettlement {
                engine_settled_at_caller_return: false,
                ..valid_ok.clone()
            },
            true,
            "interrupt acknowledged original sync request before engine settlement",
        ),
        (
            InterruptSettlement {
                engine_outcome: (0, 0),
                ..valid_ok.clone()
            },
            true,
            "interrupted sync did not settle with expected engine outcome",
        ),
        (
            InterruptSettlement {
                terminal_outcomes: vec![(Callback::Fsync, CallbackOutcome::Ok); 2],
                ..valid_ok
            },
            true,
            "interrupted sync did not emit exactly one terminal original reply",
        ),
        (
            InterruptSettlement {
                caller_errno: None,
                ..valid_err
            },
            false,
            "failed interrupted sync arm acknowledged caller or returned wrong errno",
        ),
    ] {
        assert_eq!(check_interrupt_settlement(&bad, expect_ok), Err(refusal));
        cases += 1;
    }
    assert_eq!(cases, 6);
}

pub(super) fn wait_owned_child(
    child: &mut std::process::Child,
    bound: std::time::Duration,
) -> io::Result<std::process::ExitStatus> {
    let deadline = crate::TokioSyncRuntime.now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if crate::TokioSyncRuntime.now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(result.err().unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "owned child did not exit before deadline",
                    )
                }));
            }
        }
    }
}

pub(super) fn bounded_output(
    mut command: Command,
    scratch: &Path,
    label: &str,
    bound: std::time::Duration,
) -> io::Result<std::process::Output> {
    let stdout_path = scratch.join(format!("{label}.stdout"));
    let stderr_path = scratch.join(format!("{label}.stderr"));
    command.stdout(std::fs::File::create(&stdout_path)?);
    command.stderr(std::fs::File::create(&stderr_path)?);
    let mut child = command.spawn()?;
    let status = wait_owned_child(&mut child, bound)?;
    Ok(std::process::Output {
        status,
        stdout: std::fs::read(stdout_path)?,
        stderr: std::fs::read(stderr_path)?,
    })
}

#[test]
fn wire_child_deadline_refuses_stalled_process() {
    let paths = super::Paths::new();
    let mut cases = 0;
    for (script, bound, expected) in [
        (
            "print('WIRE_CHILD_OK')",
            std::time::Duration::from_secs(1),
            None,
        ),
        (
            "import time; time.sleep(10)",
            std::time::Duration::from_millis(50),
            Some(io::ErrorKind::TimedOut),
        ),
    ] {
        let mut command = Command::new("python3");
        command.args(["-c", script]);
        let result = bounded_output(command, &paths.scratch, "wire-child", bound);
        match (result, expected) {
            (Ok(output), None) => assert_eq!(
                (output.status.success(), output.stdout, output.stderr),
                (true, b"WIRE_CHILD_OK\n".to_vec(), vec![])
            ),
            (Err(error), Some(kind)) => assert_eq!(
                (error.kind(), error.to_string()),
                (kind, "owned child did not exit before deadline".to_owned())
            ),
            (actual, expected) => {
                panic!("unexpected owned child result: {actual:?}, expected {expected:?}")
            }
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
}
