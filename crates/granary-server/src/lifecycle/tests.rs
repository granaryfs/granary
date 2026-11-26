// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::future::Future;
use std::os::unix::fs::PermissionsExt as _;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use granary_core::authlog::{EPOCH_LEN, Envelope, Epoch, encode_envelope};
use granary_core::decisionlog::MarkerRead;
use granary_core::runmarker::{BootId, decode_marker};
use granary_core::secure_random::EntropyUnavailable;
use granary_core::testkit::DecisionLogFixture;
use granary_sim::decision_log::LogFaults;
use granary_sim::fakes::Sim;
use granary_sim::rng::Rng;

use super::*;

fn block<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1000 {
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            return result;
        }
    }
    panic!("the bounded lifecycle future did not finish");
}

struct Random {
    fail: bool,
    calls: usize,
    probe: Option<PathBuf>,
}
impl SecureRandom for Random {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        self.calls += 1;
        if let Some(state) = &self.probe {
            let start = FileLog::new(state, true);
            assert!(
                matches!(
                    start,
                    Err(crate::authority::FileLogConfigError::Locked { .. })
                ),
                "starting server entered read->create: {start:?}"
            );
        }
        if self.fail {
            return Err(EntropyUnavailable);
        }
        dest.fill(7);
        Ok(())
    }
}
fn random() -> Random {
    Random {
        fail: false,
        calls: 0,
        probe: None,
    }
}
fn volume() -> VolumeName {
    VolumeName::new("vol-a".into()).unwrap()
}
fn envelope() -> Vec<u8> {
    encode_envelope(&Envelope::new(volume(), Epoch::from_bytes([7; EPOCH_LEN])))
        .as_bytes()
        .to_vec()
}
fn times() -> StateTimes {
    StateTimes {
        files: vec![(100, 0)],
        directories: vec![(100, 0)],
    }
}

fn refused_bytes(bytes: Vec<u8>, refusal_text: &str) {
    let sim = Sim::new();
    let log = sim.decision_log(1, LogFaults::none());
    block(log.seed_bytes(&volume(), bytes.clone()));
    block(log.seed_marker_bytes(encode_marker(&RunMarker::Clean).as_bytes()));
    let mut random = random();
    let result = block(initialise_log(
        &log,
        &volume(),
        &mut random,
        BootId::from_bytes([1; 16]),
    ));
    let text = result.unwrap_err().to_string();
    assert!(text.contains(refusal_text), "refusal: {text}");
    assert_eq!(
        (random.calls, block(log.read(&volume())).unwrap()),
        (0, Some(bytes))
    );
}

#[test]
fn simulator_initialise_refuses_no_envelope() {
    refused_bytes(vec![], "holds no envelope");
}
#[test]
fn simulator_initialise_refuses_damage() {
    let bytes = encode_envelope(&Envelope::new(
        VolumeName::new("other-volume".into()).unwrap(),
        Epoch::from_bytes([7; EPOCH_LEN]),
    ))
    .as_bytes()
    .to_vec();
    let error = granary_core::authlog::classify(&bytes, &volume()).unwrap_err();
    refused_bytes(bytes, &error.to_string());
}

#[test]
fn simulator_initialise_missing_draws_and_kept_never_draws() {
    let sim = Sim::new();
    let log = sim.decision_log(1, LogFaults::none());
    block(log.write_marker(&encode_marker(&RunMarker::Clean))).unwrap();
    let before = block(log.read_marker()).unwrap();
    let mut random = random();
    assert_eq!(
        block(initialise_log(
            &log,
            &volume(),
            &mut random,
            BootId::from_bytes([1; 16])
        ))
        .unwrap(),
        Initialised::Created {
            epoch: Epoch::from_bytes([7; EPOCH_LEN])
        }
    );
    random.fail = true;
    assert_eq!(
        block(initialise_log(
            &log,
            &volume(),
            &mut random,
            BootId::from_bytes([1; 16])
        ))
        .unwrap(),
        Initialised::Kept {
            epoch: Epoch::from_bytes([7; EPOCH_LEN])
        }
    );
    assert_eq!(
        (random.calls, block(log.read_marker()).unwrap()),
        (1, before)
    );
    assert!(log.violations().is_empty(), "{:?}", log.violations());
}

#[test]
fn simulator_entropy_refusal_keeps_log_missing() {
    let sim = Sim::new();
    let log = sim.decision_log(1, LogFaults::none());
    let mut random = random();
    random.fail = true;
    let result = block(initialise_log(
        &log,
        &volume(),
        &mut random,
        BootId::from_bytes([1; 16]),
    ))
    .unwrap_err();
    assert!(result.to_string().contains("no randomness"), "{result}");
    assert_eq!(
        (random.calls, block(log.read(&volume())).unwrap()),
        (1, None)
    );
    assert!(log.violations().is_empty(), "{:?}", log.violations());
}

#[test]
fn simulator_unfence_same_boot_restart_refuses_even_with_missing_malformed_or_other_boot_marker() {
    for marker in [
        None,
        Some(vec![0; 40]),
        Some(
            encode_marker(&RunMarker::Running(BootId::from_bytes([2; 16])))
                .as_bytes()
                .to_vec(),
        ),
    ] {
        let sim = Sim::new();
        let log = sim.decision_log(1, LogFaults::none());
        block(log.seed_empty_state_dir());
        if let Some(bytes) = marker {
            block(log.seed_marker_bytes(&bytes));
        }
        log.restart_process();
        let before = block(log.read_marker()).unwrap();
        let result = block(unfence_log(
            &log,
            100,
            &times(),
            BootId::from_bytes([1; 16]),
        ))
        .unwrap_err();
        assert!(
            result.to_string().contains("requires a host reboot"),
            "{result}"
        );
        assert_eq!(block(log.read_marker()).unwrap(), before);
        log.crash_host(&mut Rng::seeded(1, 2));
        block(unfence_log(
            &log,
            101,
            &times(),
            BootId::from_bytes([1; 16]),
        ))
        .unwrap();
        let MarkerRead::Present(bytes) = block(log.read_marker()).unwrap() else {
            panic!("no clean marker");
        };
        assert_eq!(decode_marker(&bytes).unwrap(), RunMarker::Clean);
        crate::authority::tests::assert_operator_start_admitted(log);
    }
}

#[test]
fn reboot_rule_checks_files_nested_directories_boundary_and_nonempty_root() {
    for times in [
        StateTimes::default(),
        StateTimes {
            files: vec![(101, 0)],
            directories: vec![(99, 0)],
        },
        StateTimes {
            files: vec![(99, 0)],
            directories: vec![(99, 0), (100, 0)],
        },
    ] {
        assert!(times.check(100).is_err(), "accepted {times:?}");
    }
    assert!(
        StateTimes {
            files: vec![(99, 999_999_999)],
            directories: vec![(99, 999_999_999)]
        }
        .check(100)
        .is_ok()
    );
}

pub(super) struct State(PathBuf);
impl State {
    pub(super) fn new() -> Self {
        Self::prepare(Self::next_path()).unwrap()
    }

    fn next_path() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        #[expect(
            clippy::disallowed_methods,
            reason = "the process id identifies a scratch path; it enters no hashed or signed value"
        )]
        let pid = std::process::id();
        std::env::temp_dir().canonicalize().unwrap().join(format!(
            "granary-lifecycle-{pid}-{}-{}",
            NEXT.fetch_add(1, Ordering::Relaxed),
            std::thread::current().name().unwrap_or("lifecycle")
        ))
    }

    fn prepare(path: PathBuf) -> io::Result<Self> {
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("cannot remove stale lifecycle fixture: {error}"),
                ));
            }
        }
        std::fs::create_dir(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
}
impl Drop for State {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cli(
    state: &std::path::Path,
    verb: &str,
    accept: bool,
    random: &mut Random,
    boot: i64,
) -> (i32, String, String) {
    let mut args = vec![
        OsString::from(verb),
        OsString::from("--state-dir"),
        state.as_os_str().to_owned(),
    ];
    if verb == "initialise" {
        args.extend([OsString::from("--volume"), OsString::from("vol-a")]);
    }
    if accept {
        args.push("--accept-unsupported-filesystem".into());
    }
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run_lifecycle_command_line(
        &args,
        random,
        || Ok(boot),
        || Ok(BootId::from_bytes([1; 16])),
        &mut out,
        &mut err,
    );
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn real_server_lock_refuses_both_verbs_and_lock_spans_read_to_create() {
    let state = State::new();
    let server = FileLog::new(&state.0, true).unwrap();
    for verb in ["initialise", "unfence"] {
        let (code, out, err) = cli(&state.0, verb, true, &mut random(), i64::MAX);
        assert_eq!(
            (
                code,
                out.is_empty(),
                err.contains("locked by another process")
            ),
            (65, true, true),
            "{err}"
        );
    }
    drop(server);
    let mut random = random();
    random.probe = Some(state.0.clone());
    let (code, out, err) = cli(&state.0, "initialise", true, &mut random, 1);
    assert_eq!(
        (code, out),
        (0, "created vol-a 07070707070707070707070707070707\n".into()),
        "{err}"
    );
    let (code, out, err) = cli(&state.0, "initialise", true, &mut random, 1);
    assert_eq!(
        (code, out, random.calls),
        (0, "kept vol-a 07070707070707070707070707070707\n".into(), 1),
        "{err}"
    );
    assert_eq!(
        decode_marker(&std::fs::read(state.0.join("MARKER")).unwrap()).unwrap(),
        RunMarker::Clean
    );
}

#[test]
fn real_walk_refuses_symlink() {
    let state = State::new();
    let link = state.0.with_extension("link");
    std::os::unix::fs::symlink(&state.0, &link).unwrap();
    let (code, _, err) = cli(&link, "initialise", true, &mut random(), 1);
    std::fs::remove_file(link).unwrap();
    assert_eq!(
        (
            code,
            err.contains("symbolic link") || err.contains("not a directory")
        ),
        (65, true),
        "{err}"
    );
    assert_eq!(cli(&state.0, "initialise", true, &mut random(), 1).0, 0);
}

#[test]
fn real_walk_refuses_accessible_mode() {
    let state = State::new();
    std::fs::set_permissions(&state.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (code, _, err) = cli(&state.0, "initialise", true, &mut random(), 1);
    assert_eq!((code, err.contains("0700")), (65, true), "{err}");
    std::fs::set_permissions(&state.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(cli(&state.0, "initialise", true, &mut random(), 1).0, 0);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn real_walk_requires_type_acknowledgement() {
    let state = State::new();
    for verb in ["initialise", "unfence"] {
        let (code, _, err) = cli(&state.0, verb, false, &mut random(), i64::MAX);
        assert_eq!(
            (code, err.contains("no filesystem type table")),
            (65, true),
            "{err}"
        );
        assert_eq!(cli(&state.0, verb, true, &mut random(), i64::MAX).0, 0);
    }
}

#[test]
fn real_unfence_walks_nested_entries_and_repairs_marker_through_boot_seam() {
    let state = State::new();
    std::fs::create_dir(state.0.join("nested")).unwrap();
    std::fs::write(state.0.join("nested/data"), b"data").unwrap();
    std::fs::write(state.0.join("MARKER"), b"malformed").unwrap();
    let (code, _, err) = cli(&state.0, "unfence", true, &mut random(), 1);
    assert_eq!(
        (code, err.contains("requires a host reboot")),
        (65, true),
        "{err}"
    );
    assert_eq!(std::fs::read(state.0.join("MARKER")).unwrap(), b"malformed");
    let (code, out, err) = cli(&state.0, "unfence", true, &mut random(), i64::MAX);
    assert_eq!((code, out), (0, "clean\n".into()), "{err}");
    assert_eq!(
        decode_marker(&std::fs::read(state.0.join("MARKER")).unwrap()).unwrap(),
        RunMarker::Clean
    );
    std::os::unix::fs::symlink("missing", state.0.join("nested/link")).unwrap();
    assert_eq!(
        cli(&state.0, "unfence", true, &mut random(), i64::MAX).0,
        65
    );
}

#[test]
fn usage_refuses_duplicates_relative_paths_and_wrong_flags() {
    for args in [
        vec!["initialise"],
        vec!["unfence", "--state-dir", "relative"],
        vec!["unfence", "--state-dir", "/state", "--volume", "v"],
        vec![
            "initialise",
            "--state-dir",
            "/state",
            "--volume",
            "v",
            "--volume",
            "v",
        ],
    ] {
        let args: Vec<_> = args.into_iter().map(OsString::from).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            run_lifecycle_command_line(
                &args,
                &mut random(),
                || Ok(1),
                || Ok(BootId::from_bytes([1; 16])),
                &mut out,
                &mut err
            ),
            64
        );
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("usage: granary-server initialise")
        );
    }
}

fn records_bytes() -> Vec<u8> {
    use granary_core::authlog::{
        Operation, Principal, Record, RecordBody, RootBytes, SubmissionIdentity, Tenant,
        encode_append,
    };
    use granary_core::hash::GrainId;
    use granary_core::root::{RootDoc, RootSig, encode_root};
    let root = encode_root(&RootDoc {
        volume: volume(),
        seq: 1,
        parent: None,
        writer_uuid: [1; 16],
        epoch: 1,
        timestamp: granary_core::sheaf::Timestamp { secs: 1, nanos: 0 },
        chunker_spec: "test".into(),
        manifest_root: GrainId::of(b"manifest"),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![RootSig {
            key_id: [1; 32],
            sig: [2; 64],
        }],
    })
    .unwrap();
    let id = GrainId::of(&root);
    let record = Record::new(
        1,
        RecordBody::Decision {
            identity: SubmissionIdentity::new(
                Tenant::new(vec![1]).unwrap(),
                Principal::new(vec![2]).unwrap(),
                Operation::new(vec![3]).unwrap(),
                id,
            ),
            root_seq: 1,
            base: None,
            decided_at: granary_core::sheaf::Timestamp { secs: 1, nanos: 0 },
            candidate: RootBytes::new(root).unwrap(),
        },
    )
    .unwrap();
    let append = encode_append(
        &Envelope::new(volume(), Epoch::from_bytes([7; EPOCH_LEN])),
        &record,
    )
    .unwrap();
    let mut bytes = envelope();
    bytes.extend_from_slice(append.record());
    bytes.extend_from_slice(append.mark());
    let classified = granary_core::authlog::classify(&bytes, &volume());
    assert!(
        matches!(&classified, Ok(granary_core::authlog::Classified::Log { records, .. }) if records.len() == 1),
        "fixture classification: {classified:?}"
    );
    bytes
}

#[test]
fn simulator_initialise_records_refusal_keeps_bytes_and_never_draws() {
    let sim = Sim::new();
    let log = sim.decision_log(1, LogFaults::none());
    let bytes = records_bytes();
    block(log.seed_bytes(&volume(), bytes.clone()));
    block(log.seed_marker_bytes(encode_marker(&RunMarker::Clean).as_bytes()));
    let mut random = random();
    let result = block(initialise_log(
        &log,
        &volume(),
        &mut random,
        BootId::from_bytes([1; 16]),
    ))
    .unwrap_err();
    assert!(
        result.to_string().contains("holds committed records"),
        "{result}"
    );
    assert_eq!(
        (random.calls, block(log.read(&volume())).unwrap()),
        (0, Some(bytes))
    );
}

struct FaultLog<L> {
    inner: L,
    temporary: bool,
    read: bool,
    mutation: bool,
    probe: Option<PathBuf>,
}
impl<L> FaultLog<L> {
    fn probe(&self) {
        if let Some(state) = &self.probe {
            let server = FileLog::new(state, true);
            assert!(
                matches!(
                    server,
                    Err(crate::authority::FileLogConfigError::Locked { .. })
                ),
                "lock released before publication: {server:?}"
            );
        }
    }
}
impl<L: DecisionLog> DecisionLog for FaultLog<L> {
    async fn read_marker(&self) -> Result<MarkerRead, LogIoError> {
        self.inner.read_marker().await
    }
    async fn write_marker(
        &self,
        marker: &granary_core::runmarker::EncodedMarker,
    ) -> Result<(), LogIoError> {
        self.probe();
        if self.mutation {
            return Err(LogIoError::SyncFailed);
        }
        self.inner.write_marker(marker).await
    }
    async fn read(&self, volume: &VolumeName) -> Result<Option<Vec<u8>>, LogIoError> {
        if self.read {
            return Err(LogIoError::Io(
                granary_core::decisionlog::IoErrorKind::PermissionDenied,
            ));
        }
        self.inner.read(volume).await
    }
    async fn remove_temporary(&self, volume: &VolumeName) -> Result<bool, LogIoError> {
        if self.temporary {
            return Err(LogIoError::Io(
                granary_core::decisionlog::IoErrorKind::PermissionDenied,
            ));
        }
        self.inner.remove_temporary(volume).await
    }
    async fn initialise(
        &self,
        envelope: &granary_core::authlog::EncodedEnvelope,
    ) -> Result<(), LogIoError> {
        self.probe();
        if self.mutation {
            return Err(LogIoError::SyncFailed);
        }
        self.inner.initialise(envelope).await
    }
    async fn complete_namespace(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.probe();
        if self.mutation {
            return Err(LogIoError::SyncFailed);
        }
        self.inner.complete_namespace(volume).await
    }
    async fn append(&self, append: &granary_core::authlog::Append) -> Result<(), LogIoError> {
        self.inner.append(append).await
    }
    async fn truncate(&self, volume: &VolumeName, len: u64) -> Result<(), LogIoError> {
        self.probe();
        if self.mutation {
            return Err(LogIoError::SyncFailed);
        }
        self.inner.truncate(volume, len).await
    }
    async fn resync(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.inner.resync(volume).await
    }
}

fn prewrite_refusal(temporary: bool, read: bool, text: &str) {
    let sim = Sim::new();
    let log = FaultLog {
        inner: sim.decision_log(1, LogFaults::none()),
        temporary,
        read,
        mutation: false,
        probe: None,
    };
    let mut random = random();
    let result = block(initialise_log(
        &log,
        &volume(),
        &mut random,
        BootId::from_bytes([1; 16]),
    ))
    .unwrap_err();
    assert!(result.to_string().contains(text), "{result}");
    assert_eq!(
        (random.calls, block(log.inner.read(&volume())).unwrap()),
        (0, None)
    );
    assert!(
        log.inner.violations().is_empty(),
        "{:?}",
        log.inner.violations()
    );
}
#[test]
fn simulator_temporary_refusal() {
    prewrite_refusal(true, false, "leftover temporary was not removed");
}
#[test]
fn simulator_unreadable_refusal() {
    prewrite_refusal(false, true, "log could not be read");
}

#[test]
fn publishing_sync_faults_are_uncertain_for_running_and_unfence() {
    for bytes in [
        None,
        Some(envelope()),
        Some({
            let mut bytes = envelope();
            bytes.extend_from_slice(b"tail");
            bytes
        }),
    ] {
        let sim = Sim::new();
        let log = FaultLog {
            inner: sim.decision_log(1, LogFaults::none()),
            temporary: false,
            read: false,
            mutation: true,
            probe: None,
        };
        if let Some(bytes) = bytes {
            block(log.inner.seed_bytes(&volume(), bytes));
            block(
                log.inner
                    .seed_marker_bytes(encode_marker(&RunMarker::Clean).as_bytes()),
            );
        }
        assert!(matches!(
            block(initialise_log(
                &log,
                &volume(),
                &mut random(),
                BootId::from_bytes([1; 16])
            )),
            Err(LifecycleError::Publishing(LogIoError::SyncFailed))
        ));
        assert!(matches!(
            block(unfence_log(
                &log,
                101,
                &times(),
                BootId::from_bytes([1; 16])
            )),
            Err(LifecycleError::Publishing(LogIoError::SyncFailed))
        ));
    }
}

#[test]
fn real_link_never_replaces_a_name_planted_at_the_entropy_draw() {
    struct Plant<'a>(&'a std::path::Path);
    impl SecureRandom for Plant<'_> {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
            std::fs::write(self.0.join("vol-a.log"), b"racer").unwrap();
            dest.fill(9);
            Ok(())
        }
    }
    let state = State::new();
    let log = FileLog::for_verb(&state.0, true).unwrap();
    let result = block(initialise_log(
        &log,
        &volume(),
        &mut Plant(&state.0),
        BootId::from_bytes([1; 16]),
    ));
    assert_eq!(
        (
            matches!(
                &result,
                Err(LifecycleError::Publishing(LogIoError::AlreadyExists))
            ),
            std::fs::read(state.0.join("vol-a.log")).unwrap()
        ),
        (true, b"racer".to_vec()),
        "{result:?}"
    );
}

#[test]
fn real_concurrent_start_and_verb_have_exactly_one_lock_winner() {
    let state = State::new();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let start = barrier.clone();
    let path = state.0.clone();
    let server = std::thread::spawn(move || {
        start.wait();
        let result = FileLog::new(path, true);
        start.wait();
        result
    });
    barrier.wait();
    let verb = FileLog::for_verb(&state.0, true);
    barrier.wait();
    let server = server.join().unwrap();
    assert_eq!(
        (server.is_ok(), verb.is_ok()),
        (server.is_ok(), server.is_err()),
        "server={server:?}, verb={verb:?}"
    );
    let probe = FileLog::new(&state.0, true);
    assert!(
        matches!(
            probe,
            Err(crate::authority::FileLogConfigError::Locked { .. })
        ),
        "race winner released its lock: {probe:?}"
    );
    let loser = match server {
        Ok(_server) => verb.unwrap_err(),
        Err(error) => error,
    };
    assert!(
        matches!(loser, crate::authority::FileLogConfigError::Locked { .. }),
        "{loser:?}"
    );
}

#[test]
fn real_replaced_directory_name_refuses_mutation() {
    let state = State::new();
    let log = FileLog::for_verb(&state.0, true).unwrap();
    let moved = state.0.with_extension("moved");
    std::fs::rename(&state.0, &moved).unwrap();
    std::fs::create_dir(&state.0).unwrap();
    std::fs::set_permissions(&state.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let result = block(initialise_log(
        &log,
        &volume(),
        &mut random(),
        BootId::from_bytes([1; 16]),
    ));
    assert!(
        matches!(result, Err(LifecycleError::Refused(_))),
        "{result:?}"
    );
    assert!(!moved.join("vol-a.log").exists());
    std::fs::remove_dir(moved).unwrap();
}

mod venue;

#[test]
fn real_lock_spans_kept_tail_and_marker_publish() {
    for tail in [false, true] {
        let state = State::new();
        let mut bytes = envelope();
        if tail {
            bytes.extend_from_slice(b"tail");
        }
        std::fs::write(state.0.join("vol-a.log"), bytes).unwrap();
        std::fs::write(
            state.0.join("MARKER"),
            encode_marker(&RunMarker::Clean).as_bytes(),
        )
        .unwrap();
        let log = FaultLog {
            inner: FileLog::for_verb(&state.0, true).unwrap(),
            temporary: false,
            read: false,
            mutation: false,
            probe: Some(state.0.clone()),
        };
        block(initialise_log(
            &log,
            &volume(),
            &mut random(),
            BootId::from_bytes([1; 16]),
        ))
        .unwrap();
        block(unfence_log(
            &log,
            i64::MAX,
            &times(),
            BootId::from_bytes([1; 16]),
        ))
        .unwrap();
    }
}

#[test]
fn real_walk_refuses_ancestor_symlink() {
    let root = State::new();
    let parent = root.0.join("parent");
    let state = parent.join("state");
    std::fs::create_dir(&parent).unwrap();
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = root.0.join("alias");
    std::os::unix::fs::symlink(&parent, &link).unwrap();
    let (code, _, err) = cli(&link.join("state"), "initialise", true, &mut random(), 1);
    assert_eq!(
        (
            code,
            err.contains("symbolic link") || err.contains("not a directory"),
            state.join("vol-a.log").exists()
        ),
        (65, true, false),
        "{err}"
    );
    assert_eq!(cli(&state, "initialise", true, &mut random(), 1).0, 0);
}

#[test]
fn real_boot_reader_failure_leaves_marker_unchanged() {
    let state = State::new();
    std::fs::write(state.0.join("MARKER"), b"damaged").unwrap();
    let args = vec![
        "unfence".into(),
        "--state-dir".into(),
        state.0.as_os_str().to_owned(),
        "--accept-unsupported-filesystem".into(),
    ];
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run_lifecycle_command_line(
        &args,
        &mut random(),
        || {
            let server = FileLog::new(&state.0, true);
            assert!(
                matches!(
                    server,
                    Err(crate::authority::FileLogConfigError::Locked { .. })
                ),
                "unfence lost its lock: {server:?}"
            );
            Err(io::Error::other("boot source unavailable"))
        },
        || Ok(BootId::from_bytes([1; 16])),
        &mut out,
        &mut err,
    );
    assert_eq!(
        (
            code,
            String::from_utf8(err)
                .unwrap()
                .contains("boot source unavailable"),
            std::fs::read(state.0.join("MARKER")).unwrap()
        ),
        (65, true, b"damaged".to_vec())
    );
}

#[test]
fn signed_unix_times_are_compared_to_boot_without_an_epoch_floor() {
    let times = StateTimes {
        files: vec![(-1, 999_999_999)],
        directories: vec![(-1, 999_999_999)],
    };
    assert!(
        times.check(0).is_ok(),
        "valid before-boot times refused: {:?}",
        times.check(0)
    );
}

mod marker;

#[test]
fn unfence_boot_id_failure_leaves_marker_unchanged() {
    let state = State::new();
    std::fs::write(state.0.join("MARKER"), b"damaged").unwrap();
    let args = vec![
        "unfence".into(),
        "--state-dir".into(),
        state.0.as_os_str().to_owned(),
        "--accept-unsupported-filesystem".into(),
    ];
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run_lifecycle_command_line(
        &args,
        &mut random(),
        || Ok(i64::MAX),
        || Err(io::Error::other("boot identity unavailable")),
        &mut out,
        &mut err,
    );
    let text = String::from_utf8(err).unwrap();
    assert_eq!(
        (
            code,
            text.contains("boot identity unavailable"),
            std::fs::read(state.0.join("MARKER")).unwrap()
        ),
        (65, true, b"damaged".to_vec()),
        "boot reader: {text}"
    );
}

#[test]
fn state_fixture_path_contains_live_process_id() {
    #[expect(
        clippy::disallowed_methods,
        reason = "the process id identifies a scratch path; it enters no hashed or signed value"
    )]
    let pid = std::process::id();
    let paths = [State::next_path(), State::next_path()];
    let [first, second] = &paths;
    assert_ne!(first, second);
    let mut checked = 0;
    for path in paths {
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(
            name.starts_with(&format!("granary-lifecycle-{pid}-")),
            "fixture name lacks this process id: {name}"
        );
        assert_eq!(
            path.parent().unwrap(),
            std::env::temp_dir().canonicalize().unwrap()
        );
        checked += 1;
    }
    assert_eq!(checked, 2);
}

#[test]
fn state_fixture_replaces_a_stale_directory() {
    let mut checked = 0;
    for stale in [false, true] {
        let path = State::next_path();
        if stale {
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("leftover"), b"stale").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let result = State::prepare(path.clone());
        assert_eq!(
            (
                result.is_ok(),
                path.join("leftover").exists(),
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777
            ),
            (true, false, 0o700),
            "stale={stale}: {:?}",
            result.as_ref().err()
        );
        drop(result);
        checked += 1;
    }
    assert_eq!(checked, 2);
}

#[test]
fn state_fixture_refuses_a_file_at_its_directory_path() {
    let mut checked = 0;
    let fresh = State::prepare(State::next_path()).unwrap();
    assert!(fresh.0.is_dir());
    checked += 1;
    let path = State::next_path();
    std::fs::write(&path, b"keep").unwrap();
    let result = State::prepare(path.clone());
    assert_eq!(
        (
            result.as_ref().err().is_some_and(|e| e
                .to_string()
                .contains("cannot remove stale lifecycle fixture")),
            std::fs::read(&path).unwrap()
        ),
        (true, b"keep".to_vec()),
        "file counterpart: {:?}",
        result.as_ref().err()
    );
    checked += 1;
    assert_eq!(checked, 2);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn round1_offline_initialise_creates_and_rebinds_intent_snapshot() {
    use crate::authority::intent::{codec, tests as intent_fixture};
    let state = State::new();
    assert_eq!(cli(&state.0, "initialise", true, &mut random(), 1).0, 0);
    let bytes =
        std::fs::read(state.0.join("vol-a.intent")).expect("offline initialise provisions intents");
    let decoded = codec::decode(
        bytes.as_slice(),
        &volume(),
        Some(Epoch::from_bytes([7; 16])),
        &intent_fixture::keys(),
    )
    .unwrap();
    assert!(decoded.principals.is_empty());
    std::fs::remove_file(state.0.join("vol-a.log")).unwrap();
    let mut prior = intent_fixture::snapshot(intent_fixture::owned(1));
    prior.volume = volume();
    let request = granary_core::intent::encode_register(
        &[1; 16],
        1,
        &[2; 16],
        1,
        &intent_fixture::root(3, &volume()),
    )
    .unwrap();
    let next = crate::authority::intent::transition(
        prior.principals.values().next(),
        crate::authority::IntentOperation::Register,
        &request,
        &volume(),
        &intent_fixture::keys(),
        intent_fixture::now(),
    )
    .next
    .unwrap();
    *prior.principals.values_mut().next().unwrap() = next;
    let mut encoded = Vec::new();
    codec::encode(&prior, &mut encoded).unwrap();
    std::fs::write(state.0.join("vol-a.intent"), encoded).unwrap();
    assert_eq!(cli(&state.0, "initialise", true, &mut random(), 2).0, 0);
    let bytes = std::fs::read(state.0.join("vol-a.intent")).unwrap();
    let rebound = codec::decode(
        bytes.as_slice(),
        &volume(),
        Some(Epoch::from_bytes([7; 16])),
        &intent_fixture::keys(),
    )
    .unwrap();
    assert_eq!(rebound.principals, prior.principals);
}

#[test]
fn round1_offline_rebind_refuses_corrupt_or_unsafe_snapshot_without_log_creation() {
    for link in [false, true] {
        let state = State::new();
        if link {
            std::os::unix::fs::symlink("evidence", state.0.join("vol-a.intent")).unwrap();
        } else {
            std::fs::write(state.0.join("vol-a.intent"), b"broken allocator").unwrap();
        }
        std::fs::write(
            state.0.join("MARKER"),
            encode_marker(&RunMarker::Clean).as_bytes(),
        )
        .unwrap();
        let (code, _, _) = cli(&state.0, "initialise", true, &mut random(), 1);
        assert_eq!(code, 65);
        assert!(!state.0.join("vol-a.log").exists());
        assert!(state.0.join("vol-a.intent").symlink_metadata().is_ok());
        assert_eq!(
            decode_marker(&std::fs::read(state.0.join("MARKER")).unwrap()).unwrap(),
            RunMarker::Clean
        );
    }
}

#[test]
fn kept_offline_initialise_does_not_create_or_repair_intent_snapshot() {
    use crate::authority::intent::{codec, tests as intent_fixture};
    for mismatch in [false, true] {
        let state = State::new();
        assert_eq!(cli(&state.0, "initialise", true, &mut random(), 1).0, 0);
        let snapshot = state.0.join("vol-a.intent");
        std::fs::remove_file(&snapshot).unwrap();
        if mismatch {
            let mut old = intent_fixture::snapshot(intent_fixture::owned(1));
            old.volume = volume();
            let mut bytes = Vec::new();
            codec::encode(&old, &mut bytes).unwrap();
            std::fs::write(&snapshot, bytes).unwrap();
        }
        let before = std::fs::read(&snapshot).ok();
        assert_eq!(cli(&state.0, "initialise", true, &mut random(), 2).0, 0);
        assert_eq!(std::fs::read(&snapshot).ok(), before);
    }
}

#[cfg(feature = "crash-points")]
#[test]
fn split_round1_offline_initialise_has_one_snapshot_cut() {
    use crate::authority::crash::{self, Plan};
    for prior in [false, true] {
        let state = State::new();
        if prior {
            assert_eq!(cli(&state.0, "initialise", true, &mut random(), 1).0, 0);
            std::fs::remove_file(state.0.join("vol-a.log")).unwrap();
        }
        let pipe = state.0.join("points");
        // A report file occupies the directory: install a clean marker first.
        let log = crate::authority::FileLog::new(&state.0, true).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(log.write_marker(&encode_marker(&RunMarker::Clean)))
            .unwrap();
        drop(log);
        crash::install(&pipe, Plan::List).unwrap();
        assert_eq!(cli(&state.0, "initialise", true, &mut random(), 2).0, 0);
        let points = std::fs::read_to_string(pipe).unwrap();
        assert_eq!(
            points
                .lines()
                .filter(|line| line.starts_with("HIT IntentProvisioned "))
                .count(),
            1
        );
        assert!(
            !points.contains("IntentRebound"),
            "offline initialise duplicated its snapshot cut: {points}"
        );
    }
}
