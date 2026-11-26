// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The engine over the adapter and the recording double, on one timeline
//! with the store's PUTs and the engine's replies: answers only after
//! what they report is committed on disk; a failed sync at every index
//! of a workload, and nothing after it; restarts on crafted files; the
//! run marker's table.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use granary_core::authlog::{Append, Classified, EncodedEnvelope, classify};
use granary_core::decisionlog::{DecisionLog, LogIoError, MarkerRead};
use granary_core::hash::GrainId;
use granary_core::root::VolumeName;
use granary_core::rootstore::{HintRead, HintToken, RootStore, RootStoreError};
use granary_core::runmarker::{EncodedMarker, RunMarker, decode_marker, encode_marker};
use granary_sim::fakes::{Faults, Sim};
use granary_sim::rng::Rng as SimRng;
use granary_sim::sched::{Scheduler, Task};
use granary_sim::secure_random::SeededSecureRandom;

use super::super::super::tests::{
    FixedClock, Reply, TestStore, YieldPause, attestation, block, boot, configs, good_root,
    log_bytes, rng, secure, submission, submission_at,
};
use super::super::super::{
    Answer, AuthorityHandle, AuthorityParts, InitialiseError, Initialised, RunEnd, StartRefused,
    VolumeRefusal, start,
};
use super::super::FileLogOn;
use super::recording::{Plant, Recording, Tap};
use super::{decision, envelope, state_dir, vol};

fn a() -> VolumeName {
    vol("vol-a")
}

fn b() -> VolumeName {
    vol("vol-b")
}

/// The adapter over the double, noting on the timeline, after every
/// append, the records the log commits on disk.
struct Observed {
    log: FileLogOn<Recording>,
    ops: Tap,
    state: PathBuf,
}

impl Observed {
    fn note_committed(&self, volume: &VolumeName) {
        let Ok(bytes) = std::fs::read(self.state.join(format!("{}.log", volume.as_str()))) else {
            return;
        };
        if let Ok(Classified::Log { records, .. }) = classify(&bytes, volume) {
            let list: Vec<String> = records
                .iter()
                .map(|r| format!("{}:{}", r.seq(), tag(r)))
                .collect();
            self.ops.shared.event(
                "committed",
                format!("{} {}", volume.as_str(), list.join(",")),
            );
        }
    }
}

impl DecisionLog for Observed {
    fn read_marker(&self) -> impl Future<Output = Result<MarkerRead, LogIoError>> + Send {
        self.log.read_marker()
    }
    fn write_marker(
        &self,
        marker: &EncodedMarker,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.log.write_marker(marker)
    }
    fn read(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, LogIoError>> + Send {
        self.log.read(volume)
    }
    fn remove_temporary(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<bool, LogIoError>> + Send {
        self.log.remove_temporary(volume)
    }
    fn initialise(
        &self,
        envelope: &EncodedEnvelope,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.log.initialise(envelope)
    }
    fn complete_namespace(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.log.complete_namespace(volume)
    }
    async fn append(&self, append: &Append) -> Result<(), LogIoError> {
        let out = self.log.append(append).await;
        if out.is_ok() {
            self.note_committed(append.volume());
        }
        out
    }
    fn truncate(
        &self,
        volume: &VolumeName,
        len: u64,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.log.truncate(volume, len)
    }
    fn resync(&self, volume: &VolumeName) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.log.resync(volume)
    }
}

/// A record's tag: 1 decision, 2 attestation, 3 landed, 4 lost.
const fn tag(record: &granary_core::authlog::Record) -> u8 {
    use granary_core::authlog::RecordBody;
    match record.body() {
        RecordBody::Decision { .. } => 1,
        RecordBody::Attestation { .. } => 2,
        RecordBody::Landed { .. } => 3,
        RecordBody::Lost { .. } => 4,
    }
}

/// The simulator's store, noting every PUT on the double's timeline.
struct TimedStore {
    inner: TestStore,
    ops: Tap,
}

impl RootStore for TimedStore {
    fn put_root(
        &self,
        volume: &str,
        seq: u64,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<(), RootStoreError>> + Send {
        self.ops
            .shared
            .event("put", format!("{volume} {seq} {:?}", GrainId::of(&bytes)));
        self.inner.put_root(volume, seq, bytes)
    }
    fn get_root(
        &self,
        volume: &str,
        seq: u64,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, RootStoreError>> + Send {
        self.inner.get_root(volume, seq)
    }
    fn read_hint(
        &self,
        volume: &str,
        cached: Option<&HintToken>,
    ) -> impl Future<Output = Result<HintRead, RootStoreError>> + Send {
        self.inner.read_hint(volume, cached)
    }
    fn write_hint(
        &self,
        volume: &str,
        seq: u64,
    ) -> impl Future<Output = Result<(), RootStoreError>> + Send {
        self.inner.write_hint(volume, seq)
    }
    fn max_seq(
        &self,
        volume: &str,
    ) -> impl Future<Output = Result<Option<u64>, RootStoreError>> + Send {
        self.inner.max_seq(volume)
    }

    fn max_seq_above(
        &self,
        volume: &str,
        floor: u64,
    ) -> impl Future<Output = Result<Option<u64>, RootStoreError>> + Send {
        self.inner.max_seq_above(volume, floor)
    }
}

/// One process of a test: an adapter over a fresh double on `state`, and
/// the store on `sim`. The adapter holds the state directory's lock until
/// the process's run ends; the test keeps only the double's [`Tap`].
pub(super) struct Process {
    pub(super) ops: Tap,
    parts: AuthorityParts<Observed, TimedStore, FixedClock, SimRng, SeededSecureRandom, YieldPause>,
}

pub(super) fn process(sim: &Sim, state: &Path, script: impl FnOnce(&Tap)) -> Process {
    process_over(sim, Recording::new(state), state, script)
}

/// [`process`] over a double already built on `state`.
pub(super) fn process_over(
    sim: &Sim,
    recording: Recording,
    state: &Path,
    script: impl FnOnce(&Tap),
) -> Process {
    let ops = recording.tap();
    script(&ops);
    let log = FileLogOn::with_ops(recording);
    Process {
        parts: AuthorityParts {
            admission: crate::Admission::chain_fixture(),
            log: Observed {
                log,
                ops: ops.clone(),
                state: state.to_path_buf(),
            },
            store: TimedStore {
                inner: TestStore::new(sim.node(1, Faults::none())),
                ops: ops.clone(),
            },
            clock: FixedClock,
            rng: rng(1),
            secure_random: secure(1),
            pause: YieldPause,
        },
        ops,
    }
}

/// What one of [`run`]'s two tasks ended with.
enum Done<T> {
    Run(RunEnd),
    Client(T),
}

/// Start `p` under boot `n`, and run `client` beside the driver: the
/// start's refusal, or the run's end and the client's result. Every reply
/// is noted on the timeline.
pub(super) fn run<T: 'static, F: Future<Output = T> + 'static>(
    p: Process,
    n: u8,
    client: impl FnOnce(AuthorityHandle) -> F,
) -> Result<(RunEnd, T), StartRefused> {
    let Process { ops, parts } = p;
    let volumes = configs(&[a(), b()]);
    let (handle, driver) = block(async move { start(parts, boot(n), volumes).await })?;
    let shared = Arc::clone(&ops.shared);
    handle
        .inner
        .shared
        .replies
        .set(Arc::new(move |volume: &VolumeName, reply: Reply| {
            shared.event("emit", format!("{} {reply:?}", volume.as_str()));
        }));
    let client = client(handle);
    let tasks: Vec<Task<Done<T>>> = vec![
        Box::pin(async move { Done::Run(driver.run().await) }),
        Box::pin(async move { Done::Client(client.await) }),
    ];
    let mut out = Scheduler::new(0).run(tasks).into_iter();
    match (out.next(), out.next()) {
        (Some(Done::Run(end)), Some(Done::Client(value))) => Ok((end, value)),
        _ => panic!("the scheduler returns results in task order"),
    }
}

/// The workload: initialise both volumes, publish one root on A to its
/// landing, then stop.
pub(super) async fn workload(handle: AuthorityHandle) -> Vec<Answer> {
    let mut answers = Vec::new();
    let mut epochs = std::collections::BTreeMap::new();
    for v in [a(), b()] {
        match handle.initialise(&v).await {
            Ok(Initialised::Created { epoch } | Initialised::Kept { epoch }) => {
                epochs.insert(v, epoch);
            }
            Err(InitialiseError::Fenced) => return answers,
            other => panic!("initialise {v:?}: {other:?}"),
        }
    }
    let c1 = good_root(&a(), 1, None, 1);
    let sub = submission_at(epochs[&a()], &a(), 1, &c1);
    // Submit until the candidate's publication closes: `Accepted` and
    // `Open` both mean it has not yet.
    for _ in 0..10_000 {
        let answer = handle.submit(sub.clone()).await;
        match answer {
            Answer::Accepted { .. } | Answer::Open { .. } => {
                granary_sim::sched::yield_once().await;
            }
            other => {
                answers.push(other);
                break;
            }
        }
    }
    let _ = handle.stop().await;
    answers
}

/// The marker's value on disk, if it decodes.
pub(super) fn marker_on_disk(state: &Path) -> Option<RunMarker> {
    std::fs::read(state.join("MARKER"))
        .ok()
        .and_then(|bytes| decode_marker(&bytes).ok())
}

/// Every reply the engine gave, and every PUT it issued, follows the
/// commit on disk of the records it depends on: `Accepted` its decision,
/// `Landed` its outcome, a PUT its attestation. The run ends clean.
#[test]
fn every_answer_and_put_follows_its_records_commit_on_disk() {
    let sim = Sim::new();
    let state = state_dir();
    let p = process(&sim, &state, |_| {});
    let ops = p.ops.clone();
    let (end, answers) = run(p, 1, workload).unwrap();
    assert_eq!(end, RunEnd::Stopped);
    assert!(
        matches!(answers[..], [Answer::Landed { .. }]),
        "{answers:?}"
    );
    assert_eq!(marker_on_disk(&state), Some(RunMarker::Clean));
    let mut committed = String::new();
    let (mut accepted, mut landed, mut puts) = (0, 0, 0);
    for call in ops.shared.calls() {
        let note = call.note.clone().unwrap_or_default();
        match call.op {
            "committed" => committed = note,
            "emit" if note.contains("Accepted") => {
                assert!(
                    committed.contains("1:1"),
                    "accepted before its decision committed"
                );
                accepted += 1;
            }
            "emit" if note.contains("Landed") => {
                assert!(
                    committed.contains("1:3"),
                    "landed before its outcome committed"
                );
                landed += 1;
            }
            "put" => {
                assert!(
                    committed.contains("1:2"),
                    "a PUT before its attestation committed"
                );
                puts += 1;
            }
            _ => {}
        }
    }
    assert!(
        accepted > 0 && landed > 0 && puts > 0,
        "{accepted} {landed} {puts}"
    );
}

/// The mutating syscalls: after a failed sync none may follow.
pub(super) const MUTATING: [&str; 8] = [
    "pwrite",
    "sync_file",
    "sync_dir",
    "rename",
    "link",
    "unlink",
    "create_new",
    "truncate",
];

/// A failed sync at every sync index of the workload, one at a time: the
/// engine fences, and after the failing sync the timeline holds no
/// mutating syscall, no PUT, and no reply but `Fenced`. Then a restart
/// under the same boot answers by the marker's table: it refuses wherever
/// the marker says running under that boot, and otherwise the failure was
/// inside a marker write the table cannot see (spec §6.2's two cases).
#[test]
fn a_failed_sync_at_any_index_stops_everything_after_it() {
    let sim = Sim::new();
    let dry = state_dir();
    let p = process(&sim, &dry, |_| {});
    let dry_ops = p.ops.clone();
    run(p, 1, workload).unwrap();
    let syncs = dry_ops
        .shared
        .calls()
        .iter()
        .filter(|c| c.op == "sync_file" || c.op == "sync_dir")
        .count();
    assert!(syncs > 10, "{syncs}");
    let mut refused_restarts = 0;
    for index in 0..syncs {
        let sim = Sim::new();
        let state = state_dir();
        let p = process(&sim, &state, |ops| {
            ops.shared.script().fail_sync = Some(index);
        });
        let ops = p.ops.clone();
        let ended = run(p, 1, workload);
        let fenced = matches!(
            ended,
            Err(StartRefused::Fenced(_)) | Ok((RunEnd::Fenced(_), _))
        );
        assert!(fenced, "sync {index}: {ended:?}");
        let calls = ops.shared.calls();
        let failed = calls
            .iter()
            .position(|c| (c.op == "sync_file" || c.op == "sync_dir") && !c.ok)
            .unwrap_or_else(|| panic!("sync {index} never failed"));
        for call in &calls[failed + 1..] {
            assert!(
                !MUTATING.contains(&call.op),
                "sync {index}: {call:?} after the failure"
            );
            assert_ne!(call.op, "put", "sync {index}: a PUT after the failure");
            if call.op == "emit" {
                let note = call.note.clone().unwrap_or_default();
                assert!(note.contains("Fenced"), "sync {index}: {note}");
            }
        }
        // The same-boot restart.
        let restart = process(&sim, &state, |_| {});
        let marker = marker_on_disk(&state);
        match run(restart, 1, |h| async move { h.stop().await }) {
            Err(StartRefused::RunningInThisBoot) => {
                assert_eq!(marker, Some(RunMarker::Running(boot(1))));
                refused_restarts += 1;
            }
            Err(StartRefused::StateDirectoryOccupied) => {
                assert_eq!(marker, None, "sync {index}");
                refused_restarts += 1;
            }
            Ok(_) => assert_ne!(
                marker,
                Some(RunMarker::Running(boot(1))),
                "sync {index}: admitted under a running marker"
            ),
            Err(other) => panic!("sync {index}: {other:?}"),
        }
    }
    assert!(
        refused_restarts > syncs / 2,
        "{refused_restarts} of {syncs}"
    );
}

// --------------------------------------------------- crafted restarts

/// A state directory holding `logs` and a marker saying running under
/// boot 1: a host that crashed.
fn crashed(logs: &[(VolumeName, Vec<u8>)]) -> PathBuf {
    let state = state_dir();
    for (v, bytes) in logs {
        std::fs::write(state.join(format!("{}.log", v.as_str())), bytes).unwrap();
    }
    std::fs::write(
        state.join("MARKER"),
        encode_marker(&RunMarker::Running(boot(1))).as_bytes(),
    )
    .unwrap();
    state
}

/// A row's marker state, planted in the state directory.
type MarkerState = Box<dyn Fn(&Path)>;

/// The index of the first `op` call on the timeline, if any.
fn first(ops: &Tap, op: &str) -> Option<usize> {
    ops.shared.calls().iter().position(|c| c.op == op)
}

/// A torn tail after a committed decision: the start truncates it and the
/// truncation's sync returns before the first reply; the owed attestation
/// then lands at the truncated end, and a second recovery keeps it.
#[test]
fn a_torn_tail_is_truncated_and_synced_before_the_first_reply() {
    let env = envelope(&a(), 7);
    let d = decision(&a(), 1);
    let mut bytes = log_bytes(&env, std::slice::from_ref(&d));
    let committed_len = bytes.len();
    bytes.extend_from_slice(b"half of the next record");
    let state = crashed(&[(a(), bytes)]);
    let sim = Sim::new();
    let p = process(&sim, &state, |_| {});
    let ops = p.ops.clone();
    let (end, answer) = run(p, 2, |h| async move {
        let answer = h
            .submit(submission_at(
                env.epoch(),
                &a(),
                9,
                &good_root(&a(), 1, None, 9),
            ))
            .await;
        h.stop().await;
        answer
    })
    .unwrap();
    assert_eq!(end, RunEnd::Stopped);
    assert!(matches!(answer, Answer::NotDecided { .. }), "{answer:?}");
    let calls = ops.shared.calls();
    let truncated = calls.iter().position(|c| c.op == "truncate").unwrap();
    assert_eq!(
        calls[truncated].at,
        Some((u64::try_from(committed_len).unwrap(), 0))
    );
    assert_eq!(
        calls[truncated + 1].op,
        "sync_file",
        "the truncation is synced"
    );
    assert!(first(&ops, "emit").unwrap() > truncated + 1);
    let second = process(&sim, &state, |_| {});
    let (_, ()) = run(second, 3, |h| async move {
        h.stop().await;
    })
    .unwrap();
    let on_disk = std::fs::read(state.join("vol-a.log")).unwrap();
    match classify(&on_disk, &a()).unwrap() {
        Classified::Log {
            records, tail_len, ..
        } => {
            assert_eq!(records[..2], [d.clone(), attestation(&d)]);
            assert_eq!(tail_len, 0);
        }
        Classified::NoEnvelope => panic!("no envelope"),
    }
}

/// A log whose records are all committed (the survivor's case, which the
/// disk cannot tell from an acknowledged one): the start re-syncs it
/// through its one description before the first reply.
#[test]
fn a_committed_log_is_resynced_before_the_first_reply() {
    let env = envelope(&a(), 7);
    let d = decision(&a(), 1);
    let state = crashed(&[(a(), log_bytes(&env, &[d.clone(), attestation(&d)]))]);
    let sim = Sim::new();
    let p = process(&sim, &state, |_| {});
    let ops = p.ops.clone();
    run(p, 2, |h| async move {
        let _ = h
            .submit(submission_at(
                env.epoch(),
                &a(),
                9,
                &good_root(&a(), 1, None, 9),
            ))
            .await;
        h.stop().await;
    })
    .unwrap();
    let calls = ops.shared.calls();
    let opened = calls.iter().find(|c| c.op == "open_rw").unwrap().generation;
    let resync = calls
        .iter()
        .position(|c| c.op == "sync_file" && c.generation == opened)
        .unwrap();
    assert!(
        resync < first(&ops, "emit").unwrap(),
        "re-synced before the first reply"
    );
}

/// Committed history damaged (a byte flipped inside the first record,
/// its mark left valid): the start refuses, before any PUT, and writes
/// clean. A symbolic link at the log's name refuses the start too.
#[test]
fn damage_or_a_link_at_a_log_refuses_the_start() {
    let env = envelope(&a(), 7);
    let d = decision(&a(), 1);
    let mut bytes = log_bytes(&env, &[d.clone(), attestation(&d)]);
    let at = encode_envelope_len(&env) + 20;
    bytes[at] ^= 0xFF;
    let state = crashed(&[(a(), bytes)]);
    let sim = Sim::new();
    let p = process(&sim, &state, |_| {});
    let ops = p.ops.clone();
    let refused = run(p, 2, |h| async move { h.stop().await });
    assert!(
        matches!(&refused, Err(StartRefused::Volume { volume, reason: VolumeRefusal::Damaged(_) }) if *volume == a()),
        "{refused:?}"
    );
    assert_eq!(first(&ops, "put"), None);
    assert_eq!(marker_on_disk(&state), Some(RunMarker::Clean));

    let state = crashed(&[]);
    let target = state.parent().unwrap().join("elsewhere.log");
    std::fs::write(&target, log_bytes(&env, &[])).unwrap();
    std::os::unix::fs::symlink(&target, state.join("vol-a.log")).unwrap();
    let p = process(&sim, &state, |_| {});
    let refused = run(p, 2, |h| async move { h.stop().await });
    assert!(
        matches!(
            &refused,
            Err(StartRefused::Volume {
                reason: VolumeRefusal::Unreadable(_),
                ..
            })
        ),
        "{refused:?}"
    );
}

fn encode_envelope_len(env: &granary_core::authlog::Envelope) -> usize {
    granary_core::authlog::encode_envelope(env).as_bytes().len()
}

/// A volume whose log is missing answers "no log" while another volume
/// is served.
#[test]
fn a_missing_log_answers_no_log_while_another_volume_serves() {
    let env = envelope(&a(), 7);
    let state = crashed(&[(a(), log_bytes(&env, &[]))]);
    let sim = Sim::new();
    let p = process(&sim, &state, |_| {});
    let (end, (on_b, on_a)) = run(p, 2, |h| async move {
        let on_b = h
            .submit(submission(&b(), 1, &good_root(&b(), 1, None, 1)))
            .await;
        let on_a = h
            .submit(submission_at(
                env.epoch(),
                &a(),
                1,
                &good_root(&a(), 1, None, 1),
            ))
            .await;
        h.stop().await;
        (on_b, on_a)
    })
    .unwrap();
    assert_eq!(end, RunEnd::Stopped);
    assert_eq!(on_b, Answer::NoLog);
    assert!(matches!(on_a, Answer::Accepted { .. }), "{on_a:?}");
}

// ---------------------------------------------------- the marker (O6)

/// Each row of spec §6.2's table, through the adapter: malformed and
/// linked markers refuse, running under this boot refuses, running under
/// another boot and clean admit, a missing marker admits over the
/// provisioned empty directory and refuses over an occupied one. A refused start
/// leaves the marker's bytes as they were; an admitted one that then
/// refuses (a damaged log) writes clean.
#[test]
fn the_marker_table_row_by_row() {
    let sim = Sim::new();
    let cases: Vec<(&str, MarkerState, bool)> = vec![
        (
            "malformed",
            Box::new(|s: &Path| std::fs::write(s.join("MARKER"), b"torn").unwrap()),
            false,
        ),
        (
            "running here",
            Box::new(|s: &Path| {
                std::fs::write(
                    s.join("MARKER"),
                    encode_marker(&RunMarker::Running(boot(1))).as_bytes(),
                )
                .unwrap();
            }),
            false,
        ),
        (
            "running elsewhere",
            Box::new(|s: &Path| {
                std::fs::write(
                    s.join("MARKER"),
                    encode_marker(&RunMarker::Running(boot(9))).as_bytes(),
                )
                .unwrap();
            }),
            true,
        ),
        (
            "clean",
            Box::new(|s: &Path| {
                std::fs::write(
                    s.join("MARKER"),
                    encode_marker(&RunMarker::Clean).as_bytes(),
                )
                .unwrap();
            }),
            true,
        ),
        ("empty directory", Box::new(|_: &Path| {}), true),
        (
            "occupied directory",
            Box::new(|s: &Path| std::fs::write(s.join("stray"), b"x").unwrap()),
            false,
        ),
        (
            "linked marker",
            Box::new(|s: &Path| {
                let target = s.parent().unwrap().join("m");
                std::fs::write(&target, encode_marker(&RunMarker::Clean).as_bytes()).unwrap();
                std::os::unix::fs::symlink(&target, s.join("MARKER")).unwrap();
            }),
            false,
        ),
    ];
    for (name, plant, admitted) in cases {
        let state = state_dir();
        plant(&state);
        let before = std::fs::read(state.join("MARKER")).ok();
        let p = process(&sim, &state, |_| {});
        let ended = run(p, 1, |h| async move { h.stop().await });
        assert_eq!(ended.is_ok(), admitted, "{name}: {:?}", ended.err());
        if admitted {
            assert_eq!(marker_on_disk(&state), Some(RunMarker::Clean), "{name}");
        } else {
            assert_eq!(
                std::fs::read(state.join("MARKER")).ok(),
                before,
                "{name}: unchanged"
            );
        }
    }
    // Admitted, then refused by a damaged log: clean is written.
    let state = crashed(&[(
        a(),
        b"not a log at all, and longer than an envelope could be".repeat(8),
    )]);
    std::fs::write(
        state.join("MARKER"),
        encode_marker(&RunMarker::Clean).as_bytes(),
    )
    .unwrap();
    let refused = run(process(&sim, &state, |_| {}), 1, |h| async move {
        h.stop().await
    });
    assert!(
        matches!(refused, Err(StartRefused::Volume { .. })),
        "{refused:?}"
    );
    assert_eq!(marker_on_disk(&state), Some(RunMarker::Clean));
}

/// A file or a link planted at the marker's temporary after the leftover
/// removal: the start refuses as the temporary taken, without a fence;
/// the marker is unchanged and the link's target unwritten; a same-boot
/// restart is then admitted.
#[test]
fn a_planted_marker_temporary_refuses_without_a_fence() {
    for link in [false, true] {
        let sim = Sim::new();
        let state = state_dir();
        std::fs::write(
            state.join("MARKER"),
            encode_marker(&RunMarker::Clean).as_bytes(),
        )
        .unwrap();
        let target = state.parent().unwrap().join("target");
        std::fs::write(&target, b"untouched").unwrap();
        let plant = if link {
            Plant::Symlink(target.clone())
        } else {
            Plant::File
        };
        let tmp = state.join("MARKER.tmp");
        let p = process(&sim, &state, |ops| {
            ops.shared.script().plant = Some((tmp.clone(), plant));
        });
        let refused = run(p, 1, |h| async move { h.stop().await });
        assert_eq!(
            refused.err(),
            Some(StartRefused::MarkerTemporaryTaken),
            "link {link}"
        );
        assert_eq!(marker_on_disk(&state), Some(RunMarker::Clean));
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        let _ = std::fs::remove_file(&tmp);
        let again = run(process(&sim, &state, |_| {}), 1, |h| async move {
            h.stop().await
        });
        assert!(again.is_ok(), "link {link}: {:?}", again.err());
    }
}

/// A process cut at each call of a first start's marker write and its
/// initialise of A (the page cache kept, as a kill leaves it): a restart
/// under the same boot refuses wherever the marker says running there,
/// and one under a new boot either refuses by the table (the first marker
/// write's orphaned temporary) or recovers, removing a leftover log
/// temporary, and initialises A again.
#[test]
fn a_cut_at_each_step_of_a_first_start_and_initialise_recovers_after_a_reboot() {
    let sim = Sim::new();
    let dry = state_dir();
    let p = process(&sim, &dry, |_| {});
    let dry_ops = p.ops.clone();
    run(p, 1, |h| async move {
        let _ = h.initialise(&a()).await;
        h.stop().await;
    })
    .unwrap();
    let calls = dry_ops.shared.calls().len();
    let (mut recovered, mut refused) = (0, 0);
    for cut in 0..calls {
        let state = state_dir();
        let p = process(&sim, &state, |ops| ops.shared.script().cut_at = Some(cut));
        let _ = run(p, 1, |h| async move {
            let _ = h.initialise(&a()).await;
            h.stop().await;
        });
        let same_boot = run(process(&sim, &state, |_| {}), 1, |h| async move {
            h.stop().await
        });
        if marker_on_disk(&state) == Some(RunMarker::Running(boot(1))) {
            assert_eq!(
                same_boot.err(),
                Some(StartRefused::RunningInThisBoot),
                "cut {cut}"
            );
        }
        let rebooted = run(process(&sim, &state, |_| {}), 2, |h| async move {
            let answer = h.initialise(&a()).await;
            h.stop().await;
            answer
        });
        match rebooted {
            Ok((RunEnd::Stopped, answer)) => {
                assert!(
                    matches!(
                        answer,
                        Ok(Initialised::Created { .. } | Initialised::Kept { .. })
                            | Err(InitialiseError::LogHasRecords)
                    ),
                    "cut {cut}: {answer:?}"
                );
                assert!(
                    !state.join("vol-a.log.tmp").exists(),
                    "cut {cut}: a leftover temporary"
                );
                recovered += 1;
            }
            Err(StartRefused::StateDirectoryOccupied) => {
                assert!(!state.join("vol-a.log").exists(), "cut {cut}");
                refused += 1;
            }
            other => panic!("cut {cut}: {other:?}"),
        }
    }
    assert!(
        recovered > 5 && refused > 0,
        "recovered {recovered}, refused {refused}"
    );
}
