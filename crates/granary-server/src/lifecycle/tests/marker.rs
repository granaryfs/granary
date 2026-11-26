// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::Mutex;

use granary_core::decisionlog::{IoErrorKind, StateDirectory};
use granary_core::runmarker::EncodedMarker;
use granary_sim::decision_log::SimDecisionLog;

use super::*;

fn boot() -> BootId {
    BootId::from_bytes([1; 16])
}

fn invoke(
    log: &impl DecisionLog,
    random: &mut impl SecureRandom,
) -> Result<Initialised, LifecycleError> {
    block(initialise_log(log, &volume(), random, boot()))
}

fn marker(log: &impl DecisionLog) -> Option<RunMarker> {
    match block(log.read_marker()).unwrap() {
        MarkerRead::Present(bytes) => Some(decode_marker(&bytes).unwrap()),
        MarkerRead::Missing { .. } => None,
    }
}

/// Records the call boundary and injects failure before the inner call changes
/// anything. Even a failed running write therefore leaves its pre-write state.
struct Recorded {
    inner: SimDecisionLog,
    calls: Mutex<Vec<&'static str>>,
    fault: Option<(&'static str, LogIoError)>,
}
impl Recorded {
    fn new(sim: &Sim) -> Self {
        Self {
            inner: sim.decision_log(1, LogFaults::none()),
            calls: Mutex::new(Vec::new()),
            fault: None,
        }
    }
    fn call(&self, name: &'static str) -> Result<(), LogIoError> {
        self.calls.lock().unwrap().push(name);
        match self.fault {
            Some((at, error)) if at == name => Err(error),
            _ => Ok(()),
        }
    }
    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}
impl DecisionLog for Recorded {
    async fn read_marker(&self) -> Result<MarkerRead, LogIoError> {
        self.call("marker-read")?;
        self.inner.read_marker().await
    }
    async fn write_marker(&self, value: &EncodedMarker) -> Result<(), LogIoError> {
        self.call(match decode_marker(value.as_bytes()).unwrap() {
            RunMarker::Running(_) => "running",
            RunMarker::Clean => "clean",
        })?;
        self.inner.write_marker(value).await
    }
    async fn remove_temporary(&self, volume: &VolumeName) -> Result<bool, LogIoError> {
        self.call("remove")?;
        self.inner.remove_temporary(volume).await
    }
    async fn read(&self, volume: &VolumeName) -> Result<Option<Vec<u8>>, LogIoError> {
        self.call("read")?;
        self.inner.read(volume).await
    }
    async fn initialise(
        &self,
        value: &granary_core::authlog::EncodedEnvelope,
    ) -> Result<(), LogIoError> {
        self.call("create")?;
        self.inner.initialise(value).await
    }
    async fn truncate(&self, volume: &VolumeName, len: u64) -> Result<(), LogIoError> {
        self.call("truncate")?;
        self.inner.truncate(volume, len).await
    }
    async fn complete_namespace(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.call("namespace")?;
        self.inner.complete_namespace(volume).await
    }
    async fn append(&self, value: &granary_core::authlog::Append) -> Result<(), LogIoError> {
        self.inner.append(value).await
    }
    async fn resync(&self, volume: &VolumeName) -> Result<(), LogIoError> {
        self.inner.resync(volume).await
    }
}

fn refusing_marker_row(row: usize) {
    for (seed, occupied, text) in [
        (
            Some(b"malformed".to_vec()),
            false,
            "run marker is malformed",
        ),
        (
            Some(
                encode_marker(&RunMarker::Running(boot()))
                    .as_bytes()
                    .to_vec(),
            ),
            false,
            "running in this boot",
        ),
        (None, true, "state directory is not empty"),
    ]
    .into_iter()
    .skip(row)
    .take(1)
    {
        let sim = Sim::new();
        let log = Recorded::new(&sim);
        if let Some(bytes) = seed {
            block(log.inner.seed_marker_bytes(&bytes));
        }
        if occupied {
            block(log.inner.seed_bytes(&volume(), envelope()));
        }
        let before = block(log.inner.read_marker()).unwrap();
        let result = invoke(&log, &mut random());
        assert_eq!(
            (
                matches!(&result, Err(LifecycleError::Refused(e)) if e.contains(text)),
                log.calls(),
                block(log.inner.read_marker()).unwrap()
            ),
            (true, vec!["marker-read"], before),
            "gate row {text}: {result:?}"
        );
    }
}

#[test]
fn unreadable_marker_makes_no_log_call_or_write() {
    let sim = Sim::new();
    let mut log = Recorded::new(&sim);
    log.fault = Some(("marker-read", LogIoError::Io(IoErrorKind::PermissionDenied)));
    let result = invoke(&log, &mut random());
    assert_eq!(
        (
            matches!(&result, Err(LifecycleError::Refused(e)) if e.contains("run marker could not be read")),
            log.calls()
        ),
        (true, vec!["marker-read"]),
        "{result:?}"
    );
}

fn real_gate_row(row: usize) {
    for (seed, text) in [
        (Some(b"malformed".to_vec()), "run marker is malformed"),
        (
            Some(
                encode_marker(&RunMarker::Running(boot()))
                    .as_bytes()
                    .to_vec(),
            ),
            "running in this boot",
        ),
        (None, "state directory is not empty"),
    ]
    .into_iter()
    .skip(row)
    .take(1)
    {
        let state = State::new();
        if let Some(bytes) = &seed {
            std::fs::write(state.0.join("MARKER"), bytes).unwrap();
        }
        std::fs::write(state.0.join("vol-a.log.tmp"), b"untouched").unwrap();
        let (code, out, err) = cli(&state.0, "initialise", true, &mut random(), 1);
        assert_eq!(
            (
                code,
                out.is_empty(),
                err.contains(text),
                std::fs::read(state.0.join("vol-a.log.tmp")).ok(),
                std::fs::read(state.0.join("MARKER")).ok(),
                state.0.join("vol-a.log").exists()
            ),
            (65, true, true, Some(b"untouched".to_vec()), seed, false),
            "row {text}: {err}"
        );
    }
}

#[test]
fn real_initialise_clean_marker_admits_start_and_another_volume() {
    let state = State::new();
    let (code, _, err) = cli(&state.0, "initialise", true, &mut random(), 1);
    let log = FileLog::for_verb(&state.0, true).unwrap();
    let read = block(log.read_marker()).unwrap();
    assert_eq!(
        (
            code,
            marker(&log),
            block(log.read(&volume())).unwrap(),
            crate::authority::marker_admits(read, boot())
        ),
        (0, Some(RunMarker::Clean), Some(envelope()), Ok(())),
        "{err}"
    );
    let other = VolumeName::new("vol-b".into()).unwrap();
    let result = block(initialise_log(&log, &other, &mut random(), boot()));
    assert_eq!(
        (result.is_ok(), marker(&log)),
        (true, Some(RunMarker::Clean)),
        "{result:?}"
    );
}

fn admitted_refusal(row: usize) {
    for (bytes, entropy, text) in [
        (Some(records_bytes()), false, "holds committed records"),
        (None, true, "no randomness"),
        (Some(b"damaged".to_vec()), false, "holds no envelope"),
        (
            Some(
                encode_envelope(&Envelope::new(
                    VolumeName::new("other".into()).unwrap(),
                    Epoch::from_bytes([7; EPOCH_LEN]),
                ))
                .as_bytes()
                .to_vec(),
            ),
            false,
            "different volume",
        ),
    ]
    .into_iter()
    .skip(row)
    .take(1)
    {
        let state = State::new();
        std::fs::write(
            state.0.join("MARKER"),
            encode_marker(&RunMarker::Running(BootId::from_bytes([2; 16]))).as_bytes(),
        )
        .unwrap();
        if let Some(bytes) = &bytes {
            std::fs::write(state.0.join("vol-a.log"), bytes).unwrap();
        }
        let mut random = random();
        random.fail = entropy;
        let (code, _, err) = cli(&state.0, "initialise", true, &mut random, 1);
        let log = FileLog::for_verb(&state.0, true).unwrap();
        assert_eq!(
            (
                code,
                err.contains(text),
                marker(&log),
                block(log.read(&volume())).unwrap()
            ),
            (65, true, Some(RunMarker::Clean), bytes),
            "refusal {text}: {err}"
        );
    }
}

#[test]
fn temporary_and_read_refusals_clean_the_marker() {
    for (at, text) in [
        ("remove", "leftover temporary was not removed"),
        ("read", "log could not be read"),
    ] {
        let sim = Sim::new();
        let mut log = Recorded::new(&sim);
        log.fault = Some((at, LogIoError::Io(IoErrorKind::PermissionDenied)));
        let result = invoke(&log, &mut random());
        assert_eq!(
            (
                matches!(&result, Err(LifecycleError::Refused(e)) if e.contains(text)),
                marker(&log.inner),
                log.calls().last().copied()
            ),
            (true, Some(RunMarker::Clean), Some("clean")),
            "{result:?}"
        );
    }
}

fn publishing_failure(row: usize) {
    for (at, bytes, expected) in [
        ("running", None, vec!["marker-read", "running"]),
        (
            "create",
            None,
            vec!["marker-read", "running", "remove", "read", "create"],
        ),
        (
            "truncate",
            Some([envelope(), b"tail".to_vec()].concat()),
            vec!["marker-read", "running", "remove", "read", "truncate"],
        ),
        (
            "namespace",
            Some(envelope()),
            vec!["marker-read", "running", "remove", "read", "namespace"],
        ),
        (
            "clean",
            None,
            vec![
                "marker-read",
                "running",
                "remove",
                "read",
                "create",
                "clean",
            ],
        ),
        (
            "clean",
            Some(records_bytes()),
            vec!["marker-read", "running", "remove", "read", "clean"],
        ),
    ]
    .into_iter()
    .skip(row)
    .take(1)
    {
        let sim = Sim::new();
        let mut log = Recorded::new(&sim);
        // Existing logs need an admitted marker; a failed running write keeps it.
        if let Some(bytes) = bytes {
            block(log.inner.seed_bytes(&volume(), bytes));
        }
        block(
            log.inner
                .seed_marker_bytes(encode_marker(&RunMarker::Clean).as_bytes()),
        );
        log.fault = Some((at, LogIoError::SyncFailed));
        let result = invoke(&log, &mut random());
        assert_eq!(
            (
                result.as_ref().err().map(LifecycleError::exit_code),
                if row == 5 {
                    matches!(
                        &result,
                        Err(LifecycleError::RefusalCleanFailed {
                            source: LogIoError::SyncFailed,
                            ..
                        })
                    )
                } else {
                    matches!(
                        &result,
                        Err(LifecycleError::Publishing(LogIoError::SyncFailed))
                    )
                },
                log.calls(),
                marker(&log.inner)
            ),
            (
                Some(74),
                true,
                expected,
                Some(if at == "running" {
                    RunMarker::Clean
                } else {
                    RunMarker::Running(boot())
                })
            ),
            "fault at {at}: {result:?}"
        );
    }
}

#[test]
fn running_temporary_taken_refuses_without_any_later_call() {
    let sim = Sim::new();
    let mut log = Recorded::new(&sim);
    let before = block(log.inner.read_marker()).unwrap();
    assert_eq!(
        before,
        MarkerRead::Missing {
            state_dir: StateDirectory::Absent
        }
    );
    log.fault = Some(("running", LogIoError::AlreadyExists));
    let result = invoke(&log, &mut random());
    assert_eq!(
        (
            result.as_ref().err().map(LifecycleError::exit_code),
            matches!(&result, Err(LifecycleError::Refused(e)) if e.contains("temporary name is taken")),
            log.calls(),
            block(log.inner.read_marker()).unwrap()
        ),
        (Some(65), true, vec!["marker-read", "running"], before),
        "{result:?}"
    );
}

#[test]
fn running_is_durable_before_any_log_call() {
    let sim = Sim::new();
    let log = Recorded::new(&sim);
    let result = invoke(&log, &mut random());
    assert_eq!(
        (
            result.is_ok(),
            log.calls(),
            marker(&log.inner),
            log.inner.violations()
        ),
        (
            true,
            vec![
                "marker-read",
                "running",
                "remove",
                "read",
                "create",
                "clean"
            ],
            Some(RunMarker::Clean),
            vec![]
        ),
        "{result:?}"
    );
}

macro_rules! row_test {
    ($name:ident, $function:ident, $row:expr) => {
        #[test]
        fn $name() {
            $function($row);
        }
    };
}
row_test!(malformed_gate_has_no_writes, refusing_marker_row, 0);
row_test!(same_boot_gate_has_no_writes, refusing_marker_row, 1);
row_test!(occupied_gate_has_no_writes, refusing_marker_row, 2);
row_test!(real_malformed_gate_exits_65, real_gate_row, 0);
row_test!(real_same_boot_gate_exits_65, real_gate_row, 1);
row_test!(real_occupied_gate_exits_65, real_gate_row, 2);
row_test!(records_refusal_exits_65_clean, admitted_refusal, 0);
row_test!(entropy_refusal_exits_65_clean, admitted_refusal, 1);
row_test!(no_envelope_refusal_exits_65_clean, admitted_refusal, 2);
row_test!(damage_refusal_exits_65_clean, admitted_refusal, 3);
row_test!(running_sync_failure_stops, publishing_failure, 0);
row_test!(create_sync_failure_stops, publishing_failure, 1);
row_test!(truncate_sync_failure_stops, publishing_failure, 2);
row_test!(namespace_sync_failure_stops, publishing_failure, 3);
row_test!(final_clean_sync_failure_stops, publishing_failure, 4);
row_test!(refusal_clean_sync_failure_stops, publishing_failure, 5);

#[test]
fn boot_id_reader_refusal_precedes_any_write() {
    let state = State::new();
    let args = vec![
        "initialise".into(),
        "--state-dir".into(),
        state.0.as_os_str().to_owned(),
        "--volume".into(),
        "vol-a".into(),
        "--accept-unsupported-filesystem".into(),
    ];
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run_lifecycle_command_line(
        &args,
        &mut random(),
        || panic!("initialise read boot start"),
        || Err(io::Error::other("boot id unavailable")),
        &mut out,
        &mut err,
    );
    assert_eq!(
        (
            code,
            out.is_empty(),
            String::from_utf8(err)
                .unwrap()
                .contains("boot id unavailable"),
            std::fs::read_dir(&state.0).unwrap().count()
        ),
        (65, true, true, 0)
    );
}

#[test]
fn cli_publishing_failure_leaves_injected_boot_running_and_exits_74() {
    struct Plant(PathBuf);
    impl SecureRandom for Plant {
        fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
            std::fs::write(self.0.join("vol-a.log"), b"racer").unwrap();
            dest.fill(9);
            Ok(())
        }
    }
    let state = State::new();
    let args = vec![
        "initialise".into(),
        "--state-dir".into(),
        state.0.as_os_str().to_owned(),
        "--volume".into(),
        "vol-a".into(),
        "--accept-unsupported-filesystem".into(),
    ];
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let injected = BootId::from_bytes([9; 16]);
    let code = run_lifecycle_command_line(
        &args,
        &mut Plant(state.0.clone()),
        || panic!("initialise read boot start"),
        || Ok(injected),
        &mut out,
        &mut err,
    );
    let log = FileLog::for_verb(&state.0, true).unwrap();
    assert_eq!(
        (
            code,
            out.is_empty(),
            marker(&log),
            block(log.read(&volume())).unwrap()
        ),
        (
            74,
            true,
            Some(RunMarker::Running(injected)),
            Some(b"racer".to_vec())
        ),
        "{}",
        String::from_utf8(err).unwrap()
    );
}

#[test]
fn unfence_forward_clock_does_not_clear_current_boot() {
    let sim = Sim::new();
    let log = Recorded::new(&sim);
    let running = encode_marker(&RunMarker::Running(boot()));
    block(log.inner.seed_marker_bytes(running.as_bytes()));
    let before = block(log.inner.read_marker()).unwrap();
    let result = block(unfence_log(&log, i64::MAX, &times(), boot()));
    assert_eq!(
        (
            result.as_ref().err().map(LifecycleError::exit_code),
            result
                .as_ref()
                .err()
                .is_some_and(|e| e.to_string().contains("running in this boot")),
            log.calls(),
            block(log.inner.read_marker()).unwrap()
        ),
        (Some(65), true, vec!["marker-read"], before),
        "forward clock: {result:?}"
    );
}

#[test]
fn unfence_taken_temporary_is_refusal() {
    let sim = Sim::new();
    let mut log = Recorded::new(&sim);
    block(log.inner.seed_marker_bytes(
        encode_marker(&RunMarker::Running(BootId::from_bytes([2; 16]))).as_bytes(),
    ));
    let before = block(log.inner.read_marker()).unwrap();
    log.fault = Some(("clean", LogIoError::AlreadyExists));
    let result = block(unfence_log(&log, i64::MAX, &times(), boot()));
    assert_eq!(
        (
            result.as_ref().err().map(LifecycleError::exit_code),
            result
                .as_ref()
                .err()
                .is_some_and(|e| e.to_string() == StartRefused::MarkerTemporaryTaken.to_string()),
            block(log.inner.read_marker()).unwrap()
        ),
        (Some(65), true, before),
        "taken temporary: {result:?}"
    );
}

#[test]
fn refusal_and_failed_clean_are_both_reported() {
    let sim = Sim::new();
    let mut log = Recorded::new(&sim);
    block(log.inner.seed_bytes(&volume(), records_bytes()));
    block(
        log.inner
            .seed_marker_bytes(encode_marker(&RunMarker::Clean).as_bytes()),
    );
    log.fault = Some(("clean", LogIoError::SyncFailed));
    let result = invoke(&log, &mut random());
    let text = result
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default();
    let refusal = InitialiseError::LogHasRecords.to_string();
    assert_eq!(
        (
            result.as_ref().err().map(LifecycleError::exit_code),
            text.starts_with(&refusal)
                && text.contains("clean write failed")
                && text.contains("durability is uncertain"),
            log.calls(),
            marker(&log.inner)
        ),
        (
            Some(74),
            true,
            vec!["marker-read", "running", "remove", "read", "clean"],
            Some(RunMarker::Running(boot()))
        ),
        "refusal context: {text}"
    );
}
