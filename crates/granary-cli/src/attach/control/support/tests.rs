// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use super::*;
use crate::attach::control::testkit::{Script, ScriptedListener, ScriptedStream};
use granary_client::{
    BundleHistory, ClientEvent, ClientMetrics, CorrelationId, FailureClass, LocalConflictStatus,
    LogFormat, LogPaths, OperationKind, RecordWriter,
};
use granary_core::{
    hash::GrainId,
    mount_control::MountKey,
    secure_random::{EntropyUnavailable, SecureRandom},
    sheaf::Timestamp,
    support::{
        BundleCache, BundleConfiguration, BundleEntryStatus, BundleFailures, BundleKind,
        BundleLogs, BundleMetrics, BundleOverlay, BundleRefusal,
    },
};
use std::{
    cell::Cell,
    collections::VecDeque,
    path::Path,
    sync::{Arc, Mutex, mpsc},
    task::Poll,
};
use tracing_subscriber::EnvFilter;

fn frame(body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(body.len()).unwrap().to_be_bytes();
    [length.as_slice(), body].concat()
}

fn script(input: Vec<u8>, peer: Option<u32>) -> (ScriptedStream, Arc<Mutex<Script>>) {
    let (stream, script) = ScriptedStream::new(input);
    script.lock().unwrap().peer = peer;
    (stream, script)
}

fn deadline() -> tokio::time::Instant {
    TokioSyncRuntime.now() + Duration::from_secs(2)
}

fn wake(script: &Arc<Mutex<Script>>) {
    if let Some(wake) = script.lock().unwrap().wake.take() {
        wake.wake();
    }
}

struct FaultListener {
    arrivals: Mutex<VecDeque<io::Result<ScriptedStream>>>,
    polls: Cell<usize>,
}
impl Listener for FaultListener {
    type Stream = ScriptedStream;
    fn poll_accept(&self, _: &mut std::task::Context<'_>) -> Poll<io::Result<Self::Stream>> {
        self.polls.set(self.polls.get() + 1);
        self.arrivals
            .lock()
            .unwrap()
            .pop_front()
            .map_or(Poll::Pending, Poll::Ready)
    }
}

struct PanicListener;
impl Listener for PanicListener {
    type Stream = ScriptedStream;
    fn poll_accept(&self, _: &mut std::task::Context<'_>) -> Poll<io::Result<Self::Stream>> {
        panic!("injected support loop panic");
    }
}

struct BlockingDrop {
    entered: Option<mpsc::Sender<()>>,
    release: mpsc::Receiver<()>,
}
impl Drop for BlockingDrop {
    fn drop(&mut self) {
        if let Some(entered) = self.entered.take() {
            let _ = entered.send(());
        }
        let _ = self.release.recv();
    }
}

fn blocking_drop() -> (BlockingDrop, mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (entered, entering) = mpsc::channel();
    let (release, released) = mpsc::channel();
    (
        BlockingDrop {
            entered: Some(entered),
            release: released,
        },
        entering,
        release,
    )
}

#[derive(Clone, Default)]
struct Discard;

impl RecordWriter for Discard {
    fn write_record(&self, _: &granary_client::LogRecord) {}
}

#[derive(Clone)]
struct StalledWriter {
    entered: mpsc::SyncSender<()>,
    release: Arc<Mutex<mpsc::Receiver<()>>>,
}

impl RecordWriter for StalledWriter {
    fn write_record(&self, _: &granary_client::LogRecord) {
        let _ = self.entered.send(());
        let _ = self.release.lock().unwrap().recv();
    }
}

struct Seed;

impl SecureRandom for Seed {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyUnavailable> {
        destination.fill(42);
        Ok(())
    }
}

fn configuration() -> BundleConfiguration {
    let pin = crate::tests::a_pin();
    let key = crate::tests::root_key_str();
    let mut args = crate::attach::parse_mount(
        [
            "vol",
            "/mnt",
            "--endpoint",
            "https://h",
            "--pin",
            &pin,
            "--root-key",
            &key,
            "--cache-dir",
            "cache",
        ]
        .map(std::ffi::OsString::from)
        .as_slice(),
    )
    .unwrap();
    args.key_seed = Some(std::path::PathBuf::from("PRIVATE_KEY_SEED_SENTINEL"));
    let settings = crate::logging::resolve(
        &crate::logging::Flags::default(),
        &|_| None,
        &|_| unreachable!(),
    )
    .unwrap();
    args.bundle_configuration(&settings).unwrap()
}

fn overlay() -> BundleOverlay {
    BundleOverlay {
        readiness: 3,
        commit_state: 2,
        namespace_entries: 1,
        free_entries: 2,
        cap: 3,
        staged_files: 4,
        journal_records: 5,
        charged_bytes: 6,
        reserved_bytes: 7,
        orphan_bytes: 8,
        captured_bytes: 9,
        swept_files: 10,
        swept_bytes: 11,
        journal_bytes: 12,
        commit_requested: true,
    }
}

fn layout(mount: wire::MountState) -> wire::SourceLayout {
    wire::SourceLayout {
        mount,
        roots: vec![wire::SourceRoot {
            role: wire::RootRole::Cache,
            path: b"/private/cache".to_vec(),
            dev: 41,
            ino: 42,
        }],
    }
}

fn mounted() -> wire::MountState {
    wire::MountState::Mounted {
        mountpoint: (31, 32),
        key: MountKey {
            namespace_dev: 33,
            namespace_ino: 34,
            mount_id: 35,
            fuse_major: 0,
            fuse_minor: 36,
        },
    }
}

fn emit_history(
    history: &BundleHistory,
    writer: impl RecordWriter + Clone + Send + Sync + 'static,
    format: LogFormat,
    filter: &str,
) {
    let subscriber = granary_client::closed_subscriber_with_paths(
        format,
        EnvFilter::new(filter),
        writer,
        LogPaths::Full,
        history.clone(),
    );
    tracing::subscriber::with_default(subscriber, || {
        let id = CorrelationId::draw(&mut Seed).unwrap();
        LocalConflictStatus::new(Path::new("S3CR3T"), id)
            .unwrap()
            .emit_telemetry();
        ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
    });
}

fn test_owners(
    history: BundleHistory,
    overlay: Option<Arc<dyn Fn() -> Result<BundleOverlay, BundleRefusal> + Send + Sync>>,
) -> crate::support_bundle::LiveOwners {
    let metrics = ClientMetrics::new(&mut Seed);
    metrics.record_rebase_conflict();
    crate::support_bundle::LiveOwners {
        configuration: Ok(configuration()),
        history,
        metrics: Some(metrics),
        overlay,
    }
}

fn cache() -> BundleCache {
    BundleCache::Writer {
        quota_bytes: 13,
        total_bytes: 14,
        live_objects: 15,
        journal_bytes: 16,
    }
}

fn status(archive: &BundleArchive, kind: BundleKind) -> BundleEntryStatus {
    archive
        .manifest
        .entries
        .iter()
        .find(|entry| entry.kind == kind)
        .unwrap()
        .status
}

fn live_collection(format: LogFormat, filter: &str) -> (BundleArchive, Vec<String>) {
    let history = BundleHistory::default();
    emit_history(&history, Discard, format, filter);
    let expected = history
        .try_snapshot()
        .unwrap()
        .records()
        .iter()
        .map(|record| record.as_str().to_owned())
        .collect();
    let owners = test_owners(history, Some(Arc::new(|| Ok(overlay()))));
    let archive = owners
        .collect(Timestamp { secs: 7, nanos: 8 }, Ok(cache()))
        .unwrap();
    (archive, expected)
}

#[tokio::test]
async fn support_uid_agreement_is_required_on_both_ends() {
    let reply = frame(&wire::encode_header(&wire::Header::Unavailable).unwrap());
    let mut cases = 0;
    for (peer, owner, admitted) in [(None, 7, 7), (Some(8), 7, 7), (Some(7), 7, 8)] {
        let (stream, server) = script(wire::request().to_vec(), peer);
        let error = answer(
            stream,
            owner,
            admitted,
            &Producer::unavailable(),
            &TokioSyncRuntime,
        )
        .await
        .unwrap_err();
        assert_eq!(
            (error.to_string(), server.lock().unwrap().output.clone()),
            (
                "refusing: support peer uid mismatch or unavailable".to_owned(),
                Vec::<u8>::new()
            )
        );
        let (stream, client) = script(reply.clone(), peer);
        let error = request(stream, owner, admitted, deadline(), &TokioSyncRuntime)
            .await
            .unwrap_err();
        assert_eq!(
            (error.to_string(), client.lock().unwrap().output.clone()),
            ("support producer unavailable".to_owned(), Vec::<u8>::new())
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[tokio::test(start_paused = true)]
async fn support_stalled_peers_reach_the_shared_two_second_deadline() {
    let mut cases = 0;
    let started = TokioSyncRuntime.now();
    let (stream, server) = script(Vec::new(), Some(0));
    assert_eq!(
        answer(stream, 0, 0, &Producer::unavailable(), &TokioSyncRuntime)
            .await
            .unwrap_err()
            .to_string(),
        "support producer unavailable"
    );
    assert_eq!(TokioSyncRuntime.now() - started, Duration::from_secs(2));
    assert!(server.lock().unwrap().closed);
    cases += 1;

    let started = TokioSyncRuntime.now();
    let (stream, client) = script(Vec::new(), Some(0));
    assert_eq!(
        request(stream, 0, 0, deadline(), &TokioSyncRuntime)
            .await
            .unwrap_err()
            .to_string(),
        "support producer unavailable"
    );
    assert_eq!(TokioSyncRuntime.now() - started, Duration::from_secs(2));
    assert_eq!(client.lock().unwrap().output, wire::request());
    cases += 1;
    assert_eq!(cases, 2);
}

#[test]
fn support_frame_caps_are_checked_before_allocation() {
    let mut cases = 0;
    for (frame_kind, bound) in [
        (Frame::Header, wire::HEADER_MAX),
        (Frame::Bundle, wire::BUNDLE_MAX),
    ] {
        let allocated = std::cell::RefCell::new(Vec::new());
        let valid = u32::try_from(bound).unwrap().to_be_bytes();
        assert!(
            allocate_frame(valid, frame_kind, |length| {
                allocated.borrow_mut().push(length);
                Vec::new()
            })
            .is_ok()
        );
        assert_eq!(allocated.take(), vec![bound]);

        let over = u32::try_from(bound + 1).unwrap().to_be_bytes();
        let error = allocate_frame(over, frame_kind, |length| {
            allocated.borrow_mut().push(length);
            Vec::new()
        })
        .unwrap_err();
        assert_eq!(
            (error.to_string(), allocated.take()),
            ("support size bound".to_owned(), Vec::<usize>::new())
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[tokio::test]
async fn support_unavailable_reply_uses_support_trigger_framing() {
    let encoded = wire::encode_header(&wire::Header::Unavailable).unwrap();
    let (stream, server) = script(wire::request().to_vec(), Some(0));
    server.lock().unwrap().eof = true;
    answer(stream, 0, 0, &Producer::unavailable(), &TokioSyncRuntime)
        .await
        .unwrap();
    assert_eq!(server.lock().unwrap().output, frame(&encoded));

    let (stream, client) = script(frame(&encoded), Some(0));
    client.lock().unwrap().eof = true;
    assert_eq!(
        request(stream, 0, 0, deadline(), &TokioSyncRuntime)
            .await
            .unwrap(),
        (wire::Header::Unavailable, None)
    );
    assert_eq!(client.lock().unwrap().output, wire::request());
}

#[tokio::test]
async fn live_collection_exports_all_members_without_reusing_telemetry_paths() {
    let mut cases = 0;
    for (format, filter) in [
        (LogFormat::Text, "trace"),
        (LogFormat::Json, "trace"),
        (LogFormat::Text, "off"),
        (LogFormat::Json, "off"),
    ] {
        let (archive, expected_logs) = live_collection(format, filter);
        let expected_archive = archive.clone();
        let source_layout = layout(mounted());
        let producer = Producer::new(source_layout.clone(), move || Ok(archive.clone()));
        let (stream, server) = script(wire::request().to_vec(), Some(0));
        server.lock().unwrap().eof = true;
        answer(stream, 0, 0, &producer, &TokioSyncRuntime)
            .await
            .unwrap();
        let reply = server.lock().unwrap().output.clone();
        let (stream, client) = script(reply, Some(0));
        client.lock().unwrap().eof = true;
        let (header, decoded) = request(stream, 0, 0, deadline(), &TokioSyncRuntime)
            .await
            .unwrap();
        assert_eq!(
            (header.clone(), decoded.is_some()),
            (wire::Header::Layout(source_layout.clone()), true),
            "mounted producer did not send the layout and bundle frames"
        );
        let decoded = decoded.unwrap();
        let statuses = decoded
            .manifest
            .entries
            .iter()
            .map(|entry| (entry.kind, entry.status))
            .collect::<Vec<_>>();
        let logs = BundleLogs::decode(decoded.members.get(&BundleKind::Logs).unwrap()).unwrap();
        let failures =
            BundleFailures::decode(decoded.members.get(&BundleKind::Failures).unwrap()).unwrap();
        let metrics =
            BundleMetrics::decode(decoded.members.get(&BundleKind::Metrics).unwrap()).unwrap();
        let cache = BundleCache::decode(decoded.members.get(&BundleKind::Cache).unwrap()).unwrap();
        let overlay =
            BundleOverlay::decode(decoded.members.get(&BundleKind::Overlay).unwrap()).unwrap();
        let encoded = decoded.encode().unwrap();
        assert_eq!(
            (
                header == wire::Header::Layout(source_layout),
                decoded == expected_archive,
                statuses
                    .iter()
                    .filter(|(_, status)| matches!(status, BundleEntryStatus::Exported { .. }))
                    .count(),
                logs.records,
                !failures.entries.is_empty(),
                metrics.conflicts,
                cache,
                overlay.namespace_entries,
                encoded
                    .windows(b"S3CR3T".len())
                    .any(|window| window == b"S3CR3T"),
                encoded
                    .windows(b"PRIVATE_KEY_SEED_SENTINEL".len())
                    .any(|window| window == b"PRIVATE_KEY_SEED_SENTINEL"),
            ),
            (
                true,
                true,
                7,
                expected_logs,
                true,
                1,
                BundleCache::Writer {
                    quota_bytes: 13,
                    total_bytes: 14,
                    live_objects: 15,
                    journal_bytes: 16,
                },
                1,
                false,
                false,
            ),
            "live reply lost a member, a positive control, equality, or redaction: {statuses:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 4, "telemetry-format/filter controls did not run");
}

#[test]
fn collector_equality_and_leak_oracle_rejects_reframed_raw_path() {
    let (mut archive, expected_logs) = live_collection(LogFormat::Json, "trace");
    let collected = BundleArchive::decode(&archive.encode().unwrap()).unwrap();
    let logs = collected.members.get(&BundleKind::Logs).unwrap();
    let mut logs = BundleLogs::decode(logs).unwrap();
    let replacement = "S3CR3T";
    assert_eq!(
        (
            &logs.records,
            logs.records
                .iter()
                .any(|record| record.contains(replacement)),
        ),
        (&expected_logs, false),
        "collector changed or leaked the retained redacted records"
    );
    let record = logs
        .records
        .iter_mut()
        .find(|record| record.contains("<file>"))
        .expect("allowed path event must be present");
    *record = record.replace("<file>", replacement);
    let bytes = logs.encode().unwrap();
    archive.members.insert(BundleKind::Logs, bytes.clone());
    let entry = archive
        .manifest
        .entries
        .iter_mut()
        .find(|entry| entry.kind == BundleKind::Logs)
        .unwrap();
    entry.status = BundleEntryStatus::Exported {
        length: u32::try_from(bytes.len()).unwrap(),
        digest: *GrainId::of(&bytes).digest(),
    };
    let encoded = archive.encode().unwrap();
    let decoded = BundleArchive::decode(&encoded).unwrap();
    let mutated = BundleLogs::decode(decoded.members.get(&BundleKind::Logs).unwrap()).unwrap();
    assert_eq!(
        (
            mutated.records == expected_logs,
            encoded
                .windows(replacement.len())
                .any(|window| window == replacement.as_bytes()),
            mutated.records.len(),
        ),
        (false, true, expected_logs.len()),
        "recomputed framing bypassed the collector equality/leak oracle"
    );
}

#[tokio::test]
async fn producer_absence_keeps_members_collectable() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let archive = live_collection(LogFormat::Json, "off").0;
    let expected = archive.clone();
    let producer = Producer::new(layout(mounted()), move || {
        observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(archive.clone())
    });
    producer.mark_absent();
    let (stream, server) = script(wire::request().to_vec(), Some(0));
    server.lock().unwrap().eof = true;
    answer(stream, 0, 0, &producer, &TokioSyncRuntime)
        .await
        .unwrap();
    let reply = server.lock().unwrap().output.clone();
    let (stream, client) = script(reply, Some(0));
    client.lock().unwrap().eof = true;
    let (header, bundle) = request(stream, 0, 0, deadline(), &TokioSyncRuntime)
        .await
        .unwrap();
    assert_eq!(
        (
            header,
            bundle == Some(expected),
            calls.load(std::sync::atomic::Ordering::Relaxed),
        ),
        (
            wire::Header::Layout(layout(wire::MountState::Absent)),
            true,
            1,
        ),
        "production absence did not preserve the collectable members"
    );
}

#[tokio::test]
async fn producer_mount_state_changes_only_after_verified_unmount() {
    let mut cases = 0;
    for (unmount, detach, listed, expected) in [
        (Ok(()), None, Some(false), wire::MountState::Absent),
        (
            Err(io::Error::from_raw_os_error(libc::EBUSY)),
            Some(Ok(())),
            Some(false),
            wire::MountState::Absent,
        ),
        (
            Err(io::Error::from_raw_os_error(libc::EBUSY)),
            Some(Err(FailureClass::Refused)),
            Some(false),
            mounted(),
        ),
        (Ok(()), None, Some(true), mounted()),
        (Ok(()), None, None, mounted()),
    ] {
        let archive = live_collection(LogFormat::Json, "off").0;
        let producer = Producer::new(layout(mounted()), move || Ok(archive.clone()));
        let observed = || {
            listed.map_or_else(
                || Err(io::Error::other("injected mount-table read failure")),
                Ok,
            )
        };
        let unmount = crate::attach::support_absence_after(Some(&producer), || unmount, observed);
        let detach = if unmount.is_err() {
            detach.map(|result| {
                crate::attach::support_absence_after(Some(&producer), || result, observed)
            })
        } else {
            None
        };
        let (stream, server) = script(wire::request().to_vec(), Some(0));
        server.lock().unwrap().eof = true;
        answer(stream, 0, 0, &producer, &TokioSyncRuntime)
            .await
            .unwrap();
        let reply = server.lock().unwrap().output.clone();
        let (stream, client) = script(reply, Some(0));
        client.lock().unwrap().eof = true;
        let (header, bundle) = request(stream, 0, 0, deadline(), &TokioSyncRuntime)
            .await
            .unwrap();
        let wire::Header::Layout(layout) = header else {
            panic!("support producer did not return its layout");
        };
        let verified_absent =
            matches!(listed, Some(false)) && (unmount.is_ok() || matches!(detach, Some(Ok(()))));
        assert_eq!(
            (verified_absent, listed, layout.mount, bundle.is_some(),),
            (expected == wire::MountState::Absent, listed, expected, true,),
            "(verified absent, mount-table result, advertised state, collectable bundle)"
        );
        cases += 1;
    }
    assert_eq!(cases, 5, "mount-table outcome controls did not run");
}

#[tokio::test]
async fn collector_failure_reports_one_closed_local_diagnostic() {
    let producer = Producer::new(layout(mounted()), || {
        Err(io::Error::other("private collector detail"))
    });
    let diagnostics = Mutex::new(Vec::new());
    let report = |message: std::fmt::Arguments<'_>| {
        diagnostics.lock().unwrap().push(message.to_string());
    };
    let (stream, server) = script(wire::request().to_vec(), Some(0));
    server.lock().unwrap().eof = true;
    answer_with_report(stream, 0, 0, &producer, &report, &TokioSyncRuntime)
        .await
        .unwrap();
    let unavailable = wire::encode_header(&wire::Header::Unavailable).unwrap();
    assert_eq!(
        (
            server.lock().unwrap().output.clone(),
            diagnostics.lock().unwrap().clone(),
        ),
        (
            frame(&unavailable),
            vec!["gran mount: support producer unavailable".to_owned()],
        ),
        "collector failure did not stay closed on the wire and locally"
    );
}

#[cfg(feature = "overlay-fault-tests")]
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one contention matrix keeps exact refusal and unaffected-sibling tuples together"
)]
fn live_collection_refuses_busy_owners_without_waiting_and_keeps_siblings() {
    let history = BundleHistory::default();
    emit_history(&history, Discard, LogFormat::Json, "off");
    let owners = test_owners(history.clone(), Some(Arc::new(|| Ok(overlay()))));
    let held = history.hold_log_lock_for_test();
    let (send, receive) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            send.send(owners.collect(Timestamp { secs: 1, nanos: 0 }, Ok(cache())))
                .unwrap();
        });
        let observed = receive.recv_timeout(Duration::from_millis(200));
        drop(held);
        let archive = observed
            .unwrap_or_else(|error| panic!("history lock blocked collection: {error}"))
            .unwrap();
        assert_eq!(
            (
                status(&archive, BundleKind::Logs),
                matches!(
                    status(&archive, BundleKind::Failures),
                    BundleEntryStatus::Exported { .. }
                ),
                archive.members.len(),
            ),
            (
                BundleEntryStatus::Refused(BundleRefusal::Unavailable),
                true,
                6,
            ),
            "history refusal changed an unaffected sibling"
        );
    });

    let owners = test_owners(history.clone(), Some(Arc::new(|| Ok(overlay()))));
    let held = history.hold_failure_ring_for_test();
    let (send, receive) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            send.send(owners.collect(Timestamp { secs: 2, nanos: 0 }, Ok(cache())))
                .unwrap();
        });
        let observed = receive.recv_timeout(Duration::from_millis(200));
        drop(held);
        let archive = observed
            .unwrap_or_else(|error| panic!("failure lock blocked collection: {error}"))
            .unwrap();
        assert_eq!(
            (
                status(&archive, BundleKind::Failures),
                matches!(
                    status(&archive, BundleKind::Logs),
                    BundleEntryStatus::Exported { .. }
                ),
                archive.members.len(),
            ),
            (
                BundleEntryStatus::Refused(BundleRefusal::Unavailable),
                true,
                6,
            ),
            "failure refusal changed an unaffected sibling"
        );
    });

    let state = Arc::new(Mutex::new(overlay()));
    let projected = Arc::clone(&state);
    let projection = Arc::new(move || {
        projected
            .try_lock()
            .map(|value| *value)
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => BundleRefusal::TimedOut,
                std::sync::TryLockError::Poisoned(_) => BundleRefusal::Unavailable,
            })
    });
    let owners = test_owners(history.clone(), Some(projection));
    let held = state.lock().unwrap();
    let (send, receive) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            send.send(owners.collect(Timestamp { secs: 3, nanos: 0 }, Ok(cache())))
                .unwrap();
        });
        let observed = receive.recv_timeout(Duration::from_millis(200));
        drop(held);
        let archive = observed
            .unwrap_or_else(|error| panic!("overlay lock blocked collection: {error}"))
            .unwrap();
        assert_eq!(
            (
                status(&archive, BundleKind::Overlay),
                matches!(
                    status(&archive, BundleKind::Cache),
                    BundleEntryStatus::Exported { .. }
                ),
            ),
            (BundleEntryStatus::Refused(BundleRefusal::TimedOut), true,),
            "overlay refusal changed the cache sibling"
        );
    });

    let owners = test_owners(
        history.clone(),
        Some(Arc::new(|| Err(BundleRefusal::Unreadable))),
    );
    let open_failure = owners
        .collect(Timestamp { secs: 4, nanos: 0 }, Ok(cache()))
        .unwrap();
    let cache_busy = owners
        .collect(
            Timestamp { secs: 5, nanos: 0 },
            Err(BundleRefusal::TimedOut),
        )
        .unwrap();
    assert_eq!(
        (
            status(&open_failure, BundleKind::Overlay),
            status(&cache_busy, BundleKind::Cache),
            matches!(
                status(&cache_busy, BundleKind::Logs),
                BundleEntryStatus::Exported { .. }
            ),
        ),
        (
            BundleEntryStatus::Refused(BundleRefusal::Unreadable),
            BundleEntryStatus::Refused(BundleRefusal::TimedOut),
            true,
        ),
        "open failure or cache-busy mapping changed an unaffected sibling"
    );
}

#[test]
fn live_collection_does_not_wait_for_a_stalled_telemetry_sink() {
    let history = BundleHistory::default();
    let (entered, wait_entered) = mpsc::sync_channel(1);
    let (release, wait_release) = mpsc::channel();
    let writer = StalledWriter {
        entered,
        release: Arc::new(Mutex::new(wait_release)),
    };
    let worker_history = history.clone();
    let worker = std::thread::spawn(move || {
        let subscriber = granary_client::closed_subscriber_with_paths(
            LogFormat::Json,
            EnvFilter::new("trace"),
            writer,
            LogPaths::Full,
            worker_history,
        );
        tracing::subscriber::with_default(subscriber, || {
            ClientEvent::op_failed(OperationKind::Commit, FailureClass::Io).emit();
        });
    });
    wait_entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let owners = test_owners(history, Some(Arc::new(|| Ok(overlay()))));
    let (send, receive) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            send.send(owners.collect(Timestamp { secs: 6, nanos: 0 }, Ok(cache())))
                .unwrap();
        });
        let observed = receive.recv_timeout(Duration::from_millis(200));
        release.send(()).unwrap();
        let archive = observed
            .unwrap_or_else(|error| panic!("sink drain blocked collection: {error}"))
            .unwrap();
        assert!(matches!(
            status(&archive, BundleKind::Logs),
            BundleEntryStatus::Exported { .. }
        ));
    });
    worker.join().unwrap();
}

#[tokio::test]
async fn support_malformed_request_and_reply_refuse() {
    let mut bad_request = wire::request();
    bad_request[9] = 9;
    let (stream, server) = script(bad_request.to_vec(), Some(0));
    assert_eq!(
        answer(stream, 0, 0, &Producer::unavailable(), &TokioSyncRuntime)
            .await
            .unwrap_err()
            .to_string(),
        "malformed support request"
    );
    assert!(server.lock().unwrap().output.is_empty());

    let (stream, client) = script(frame(b"not-a-support-header"), Some(0));
    client.lock().unwrap().eof = true;
    assert_eq!(
        request_live_with(
            async { Ok(stream) },
            || Ok(()),
            0,
            deadline(),
            &TokioSyncRuntime,
        )
        .await
        .unwrap_err()
        .to_string(),
        "malformed support reply"
    );
    assert_eq!(client.lock().unwrap().output, wire::request());

    let (stream, client) = script(Vec::new(), Some(0));
    client.lock().unwrap().eof = true;
    assert_eq!(
        request_live_with(
            async { Ok(stream) },
            || Ok(()),
            0,
            deadline(),
            &TokioSyncRuntime,
        )
        .await
        .unwrap_err(),
        RequestFailure::Unavailable
    );
}

#[tokio::test(start_paused = true)]
async fn support_transient_accept_error_retries_and_answers() {
    let encoded = wire::encode_header(&wire::Header::Unavailable).unwrap();
    let (stream, script) = script(wire::request().to_vec(), Some(0));
    script.lock().unwrap().eof = true;
    let listener = FaultListener {
        arrivals: Mutex::new(VecDeque::from([
            Err(io::Error::from_raw_os_error(libc::EMFILE)),
            Ok(stream),
        ])),
        polls: Cell::new(0),
    };
    let (closing, state) = watch::channel(false);
    let mut service = pin!(serve(
        &listener,
        state,
        0,
        Producer::unavailable(),
        &TokioSyncRuntime
    ));
    let first = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
    assert!(matches!(first, Poll::Pending), "transient accept={first:?}");
    assert_eq!(listener.polls.get(), 1);
    tokio::time::advance(Duration::from_millis(99)).await;
    let before = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
    assert!(matches!(before, Poll::Pending), "early retry={before:?}");
    assert_eq!(listener.polls.get(), 1);
    tokio::time::advance(Duration::from_millis(1)).await;
    let answered = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
    assert!(
        matches!(answered, Poll::Pending),
        "answer result={answered:?}"
    );
    assert_eq!(
        (listener.polls.get(), script.lock().unwrap().output.clone()),
        (3, frame(&encoded))
    );
    closing.send_replace(true);
    service.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn support_fatal_accept_error_ends_the_producer() {
    let listener = FaultListener {
        arrivals: Mutex::new(VecDeque::from([Err(io::Error::from_raw_os_error(
            libc::EBADF,
        ))])),
        polls: Cell::new(0),
    };
    let (closing, state) = watch::channel(false);
    let mut service = pin!(serve(
        &listener,
        state,
        0,
        Producer::unavailable(),
        &TokioSyncRuntime,
    ));
    let observed = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
    drop(closing);
    assert!(
        matches!(observed, Poll::Ready(Err(ref error)) if error.raw_os_error() == Some(libc::EBADF))
            && listener.polls.get() == 1,
        "fatal accept error was retried or wrapped"
    );
}

#[tokio::test(start_paused = true)]
async fn support_serve_serializes_answers_and_closing_cancels() {
    let encoded = wire::encode_header(&wire::Header::Unavailable).unwrap();
    let (stalled, first) = script(Vec::new(), Some(0));
    let (valid, second) = script(wire::request().to_vec(), Some(0));
    second.lock().unwrap().eof = true;
    let listener = ScriptedListener {
        streams: Mutex::new(VecDeque::from([stalled, valid])),
    };
    let (closing, state) = watch::channel(false);
    let mut service = pin!(serve(
        &listener,
        state,
        0,
        Producer::unavailable(),
        &TokioSyncRuntime
    ));
    let initial = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
    assert!(
        matches!(initial, Poll::Pending),
        "initial service={initial:?}"
    );
    assert_eq!(
        (
            listener.streams.lock().unwrap().len(),
            second.lock().unwrap().output.clone()
        ),
        (1, Vec::<u8>::new()),
        "second exchange started before the first completed"
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    let answered = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
    assert!(
        matches!(answered, Poll::Pending),
        "answer result={answered:?}"
    );
    assert_eq!(second.lock().unwrap().output, frame(&encoded));
    assert!(first.lock().unwrap().closed);
    closing.send_replace(true);
    service.await.unwrap();

    let (stalled, script) = script(Vec::new(), Some(0));
    let listener = ScriptedListener {
        streams: Mutex::new(VecDeque::from([stalled])),
    };
    let (closing, state) = watch::channel(false);
    let mut service = pin!(serve(
        &listener,
        state,
        0,
        Producer::unavailable(),
        &TokioSyncRuntime
    ));
    let initial = poll_fn(|cx| Poll::Ready(service.as_mut().poll(cx))).await;
    assert!(
        matches!(initial, Poll::Pending),
        "closing setup={initial:?}"
    );
    closing.send_replace(true);
    service.await.unwrap();
    assert!(script.lock().unwrap().closed);
}

#[tokio::test(start_paused = true)]
async fn support_request_uses_the_callers_deadline() {
    let cutoff = deadline();
    tokio::time::advance(Duration::from_millis(1500)).await;
    let (stream, _) = script(Vec::new(), Some(0));
    let mut exchange = pin!(request(stream, 0, 0, cutoff, &TokioSyncRuntime));
    let initial = poll_fn(|cx| Poll::Ready(exchange.as_mut().poll(cx))).await;
    assert!(
        matches!(initial, Poll::Pending),
        "initial request={initial:?}"
    );
    tokio::time::advance(Duration::from_millis(499)).await;
    let before = poll_fn(|cx| Poll::Ready(exchange.as_mut().poll(cx))).await;
    assert!(matches!(before, Poll::Pending), "early deadline={before:?}");
    tokio::time::advance(Duration::from_millis(1)).await;
    let at = poll_fn(|cx| Poll::Ready(exchange.as_mut().poll(cx))).await;
    assert!(
        matches!(at, Poll::Ready(Err(ref error)) if error.to_string() == "support producer unavailable"),
        "caller deadline={at:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn support_connect_uses_the_original_shared_deadline() {
    let started = TokioSyncRuntime.now();
    let cutoff = started + Duration::from_secs(2);
    tokio::time::advance(Duration::from_millis(1500)).await;
    let rechecked = Cell::new(false);
    let connect = std::future::pending::<io::Result<ScriptedStream>>();
    let mut connection = pin!(connect_until(
        connect,
        || {
            rechecked.set(true);
            Ok(())
        },
        cutoff,
        &TokioSyncRuntime,
    ));
    let initial = poll_fn(|cx| Poll::Ready(connection.as_mut().poll(cx))).await;
    assert!(matches!(initial, Poll::Pending), "connect completed early");
    tokio::time::advance(Duration::from_millis(499)).await;
    let before = poll_fn(|cx| Poll::Ready(connection.as_mut().poll(cx))).await;
    assert!(
        matches!(before, Poll::Pending),
        "connect deadline fired early"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    let at = poll_fn(|cx| Poll::Ready(connection.as_mut().poll(cx))).await;
    assert!(
        matches!(at, Poll::Ready(Err(RequestFailure::Unavailable)))
            && !rechecked.get()
            && TokioSyncRuntime.now() - started == Duration::from_secs(2),
        "stalled connect received a fresh deadline: ready={}, rechecked={}, elapsed={:?}",
        matches!(at, Poll::Ready(_)),
        rechecked.get(),
        TokioSyncRuntime.now() - started,
    );
}

#[tokio::test(start_paused = true)]
async fn support_slow_trickle_shares_one_absolute_deadline() {
    let header = wire::encode_header(&wire::Header::Layout(wire::SourceLayout {
        mount: wire::MountState::Absent,
        roots: Vec::new(),
    }))
    .unwrap();
    let framed = frame(&header);
    let (stream, script) = script(Vec::new(), Some(0));
    script.lock().unwrap().blocked = true;
    let started = TokioSyncRuntime.now();
    let cutoff = started + Duration::from_secs(2);
    let mut exchange = pin!(request(stream, 0, 0, cutoff, &TokioSyncRuntime));
    let initial = poll_fn(|cx| Poll::Ready(exchange.as_mut().poll(cx))).await;
    assert!(
        matches!(initial, Poll::Pending),
        "initial trickle={initial:?}"
    );

    tokio::time::advance(Duration::from_millis(500)).await;
    script.lock().unwrap().blocked = false;
    wake(&script);
    let request_sent = poll_fn(|cx| Poll::Ready(exchange.as_mut().poll(cx))).await;
    assert!(
        matches!(request_sent, Poll::Pending),
        "request stage={request_sent:?}"
    );
    assert_eq!(script.lock().unwrap().output, wire::request());

    tokio::time::advance(Duration::from_millis(500)).await;
    script.lock().unwrap().input.extend(&framed[..4]);
    wake(&script);
    let prefix = poll_fn(|cx| Poll::Ready(exchange.as_mut().poll(cx))).await;
    assert!(matches!(prefix, Poll::Pending), "prefix stage={prefix:?}");

    tokio::time::advance(Duration::from_millis(500)).await;
    script.lock().unwrap().input.extend(&framed[4..]);
    wake(&script);
    let header = poll_fn(|cx| Poll::Ready(exchange.as_mut().poll(cx))).await;
    assert!(matches!(header, Poll::Pending), "header stage={header:?}");

    tokio::time::advance(Duration::from_millis(499)).await;
    let before = poll_fn(|cx| Poll::Ready(exchange.as_mut().poll(cx))).await;
    assert!(matches!(before, Poll::Pending), "early cutoff={before:?}");
    tokio::time::advance(Duration::from_millis(1)).await;
    let at = poll_fn(|cx| Poll::Ready(exchange.as_mut().poll(cx))).await;
    assert!(
        matches!(at, Poll::Ready(Err(ref error)) if error.to_string() == "support producer unavailable"),
        "shared cutoff={at:?}"
    );
    assert_eq!(TokioSyncRuntime.now() - started, Duration::from_secs(2));
}

#[tokio::test]
async fn support_both_peers_refuse_trailing_bytes() {
    let mut request_bytes = wire::request().to_vec();
    request_bytes.extend_from_slice(b"trailing");
    let (stream, server) = script(request_bytes, Some(0));
    server.lock().unwrap().eof = true;
    assert_eq!(
        answer(stream, 0, 0, &Producer::unavailable(), &TokioSyncRuntime)
            .await
            .unwrap_err()
            .to_string(),
        "malformed support request"
    );
    assert!(server.lock().unwrap().output.is_empty());

    let encoded = wire::encode_header(&wire::Header::Unavailable).unwrap();
    let mut reply = frame(&encoded);
    reply.extend_from_slice(b"trailing");
    let (stream, client) = script(reply, Some(0));
    client.lock().unwrap().eof = true;
    assert_eq!(
        request(stream, 0, 0, deadline(), &TokioSyncRuntime)
            .await
            .unwrap_err()
            .to_string(),
        "malformed support reply"
    );
    assert_eq!(client.lock().unwrap().output, wire::request());
}

#[test]
fn support_shutdown_and_startup_error_join_the_producer() {
    let (endpoint, entered, release) = blocking_drop();
    let support = Support::start_with_listener(0, endpoint, Producer::unavailable(), |_| {
        Ok(ScriptedListener::default())
    })
    .unwrap();
    let (returned, return_state) = mpsc::channel();
    let dropper = std::thread::spawn(move || {
        drop(support);
        let _ = returned.send(());
    });
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        return_state.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    release.send(()).unwrap();
    return_state.recv_timeout(Duration::from_secs(2)).unwrap();
    dropper.join().unwrap();

    let (endpoint, entered, release) = blocking_drop();
    let (returned, return_state) = mpsc::channel();
    let starter = std::thread::spawn(move || {
        let result = Support::start_with_listener::<_, ScriptedListener>(
            0,
            endpoint,
            Producer::unavailable(),
            |_| Err(io::Error::other("injected detail")),
        );
        let _ = returned.send(result.err().map(|error| error.to_string()));
    });
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        return_state.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    release.send(()).unwrap();
    assert_eq!(
        return_state.recv_timeout(Duration::from_secs(2)).unwrap(),
        Some("support service startup failed or timed out".to_owned())
    );
    starter.join().unwrap();

    let (endpoint, entered, release) = blocking_drop();
    let support =
        Support::start_with_listener(0, endpoint, Producer::unavailable(), |_| Ok(PanicListener))
            .unwrap();
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(support.done.try_recv(), Err(mpsc::TryRecvError::Empty));
    release.send(()).unwrap();
    drop(support);
}

#[test]
fn support_service_startup_is_separate_and_fixed_on_failure() {
    let (stalled, _) = script(Vec::new(), Some(0));
    let listener = ScriptedListener {
        streams: Mutex::new(VecDeque::from([stalled])),
    };
    let support =
        Support::start_with_listener(0, (), Producer::unavailable(), |()| Ok(listener)).unwrap();
    drop(support);

    let error = Support::start_with_listener::<(), ScriptedListener>(
        0,
        (),
        Producer::unavailable(),
        |()| Err(io::Error::other("injected detail")),
    )
    .err()
    .unwrap();
    assert_eq!(
        error.to_string(),
        "support service startup failed or timed out"
    );
}
