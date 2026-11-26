// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The production log adapter, over the real file operations and over the
//! recording double: the seam's conformance body; each call's exact
//! syscalls in order; every call complete on its first poll; one
//! description per log; the tracked length across a truncation; short,
//! interrupted and failing writes; links refused; the marker's temporary
//! taken by a planted file or link. The state directory itself: provisioned
//! (an absent one refused), its mode, its lock, the re-check of its name,
//! and the rule each opened file is held to ([`held`]).
//!
//! Scratch directories are canonical (on macOS `/var` is a symbolic link,
//! which the protection walk refuses), and the walk is told the filesystem
//! type is acknowledged except in the venue's runs, since macOS has no
//! type table.
//!
//! Every adapter call in these tests goes through [`now`], which polls the
//! call's future once and fails the test if it is not ready.

mod engine;
mod held;
mod recording;
mod venue;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use granary_core::authlog::{
    EPOCH_LEN, Envelope, Epoch, Record, RecordBody, SubmissionIdentity, encode_append,
    encode_envelope,
};
use granary_core::decisionlog::{DecisionLog, IoErrorKind, LogIoError, MarkerRead, StateDirectory};
use granary_core::root::VolumeName;
use granary_core::runmarker::{BootId, RunMarker, encode_marker};
use granary_core::testkit::DecisionLogFixture;

use super::{FileLogConfigError, FileLogOn, StdFileOps};
use crate::protected_dir::ProtectionError;
use recording::{Plant, Recording, Tap, Write};

/// A scratch directory for one test, canonical: the anchor, to hold the
/// state directory `state`. Under `TMPDIR`, which the Linux venue points
/// at an ext4 filesystem.
pub(super) fn scratch() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    #[expect(
        clippy::disallowed_methods,
        reason = "`std::process::id` is banned as ambient input to a hashed or signed value. Here it \
                  names a scratch directory and nothing else, so two test binaries running at once \
                  do not share one; nothing under test reads it"
    )]
    let pid = std::process::id();
    let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "granary-file-log-{pid}-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A provisioned state directory, `state` in a fresh scratch directory:
/// empty, mode `0o700`, as the operator provisions it.
pub(super) fn state_dir() -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let state = scratch().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    state
}

/// Remove everything in `dir`, keeping the directory itself (the held
/// descriptor's).
fn empty(dir: &Path) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() && !path.is_symlink() {
            std::fs::remove_dir_all(&path).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
    }
}

/// Poll `future` once, and require it ready: every adapter call completes
/// in the poll that calls it.
pub(super) fn now<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("an adapter call suspended"),
    }
}

pub(super) fn vol(name: &str) -> VolumeName {
    VolumeName::new(name.to_owned()).unwrap()
}

pub(super) fn envelope(volume: &VolumeName, epoch: u8) -> Envelope {
    Envelope::new(volume.clone(), Epoch::from_bytes([epoch; EPOCH_LEN]))
}

/// A decision at position `seq` for a root of `volume` at seq 1.
pub(super) fn decision(volume: &VolumeName, seq: u64) -> Record {
    let candidate = super::super::tests::good_root(volume, 1, None, 1);
    Record::new(
        seq,
        RecordBody::Decision {
            identity: SubmissionIdentity::new(
                granary_core::authlog::Tenant::new(vec![1]).unwrap(),
                granary_core::authlog::Principal::new(vec![2]).unwrap(),
                granary_core::authlog::Operation::new(vec![3]).unwrap(),
                granary_core::hash::GrainId::of(&candidate),
            ),
            root_seq: 1,
            base: None,
            decided_at: granary_core::sheaf::Timestamp { secs: 1, nanos: 0 },
            candidate: granary_core::authlog::RootBytes::new(candidate).unwrap(),
        },
    )
    .unwrap()
}

// --------------------------------------------------------- conformance

/// The adapter over the real calls, with the conformance body's fixture
/// hooks writing the scratch directory directly.
struct Conform {
    log: FileLogOn<StdFileOps>,
    state: PathBuf,
}

impl Conform {
    fn new() -> Self {
        let state = state_dir();
        Self {
            log: FileLogOn::with_ops(StdFileOps::open(&state, true).unwrap()),
            state,
        }
    }
}

impl DecisionLog for Conform {
    fn read_marker(&self) -> impl Future<Output = Result<MarkerRead, LogIoError>> + Send {
        self.log.read_marker()
    }
    fn write_marker(
        &self,
        marker: &granary_core::runmarker::EncodedMarker,
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
        envelope: &granary_core::authlog::EncodedEnvelope,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.log.initialise(envelope)
    }
    fn complete_namespace(
        &self,
        volume: &VolumeName,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.log.complete_namespace(volume)
    }
    fn append(
        &self,
        append: &granary_core::authlog::Append,
    ) -> impl Future<Output = Result<(), LogIoError>> + Send {
        self.log.append(append)
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

/// The state directory is provisioned, so the fixture's hooks write into
/// it and empty it, and never remove it: the adapter holds its descriptor.
impl DecisionLogFixture for Conform {
    async fn seed_bytes(&self, volume: &VolumeName, bytes: Vec<u8>) {
        std::fs::write(self.state.join(format!("{}.log", volume.as_str())), bytes).unwrap();
        self.log.forget_open_logs();
    }

    async fn seed_marker_bytes(&self, bytes: &[u8]) {
        std::fs::write(self.state.join("MARKER"), bytes).unwrap();
    }

    async fn seed_empty_state_dir(&self) {
        empty(&self.state);
        self.log.forget_open_logs();
    }

    async fn seed_temporary(&self, volume: &VolumeName) {
        std::fs::write(self.state.join(format!("{}.log.tmp", volume.as_str())), b"").unwrap();
    }

    fn state_dir_provisioned(&self) -> bool {
        true
    }

    async fn reset(&self) {
        empty(&self.state);
        self.log.forget_open_logs();
    }
}

/// The state directory's path goes through the protection walk: a bare
/// root, a relative path and one with a `..` component are refused before
/// anything is opened.
#[test]
fn a_state_path_the_walk_cannot_take_is_refused() {
    for (path, want) in [
        ("/", "NoComponent"),
        ("state", "NotAbsolute"),
        ("/srv/a/state/..", "DotComponent"),
    ] {
        let got = match super::FileLog::new(path, true) {
            Err(FileLogConfigError::Directory(ProtectionError::NoComponent)) => "NoComponent",
            Err(FileLogConfigError::Directory(ProtectionError::NotAbsolute { .. })) => {
                "NotAbsolute"
            }
            Err(FileLogConfigError::Directory(ProtectionError::DotComponent { .. })) => {
                "DotComponent"
            }
            other => panic!("{path}: {other:?}"),
        };
        assert_eq!(got, want, "{path}");
    }
}

/// The adapter never creates the state directory (spec §6.2): an absent
/// one refuses the adapter, naming it, and leaves nothing behind.
#[test]
fn an_absent_state_directory_is_refused_and_not_created() {
    let state = scratch().join("state");
    match super::FileLog::new(&state, true) {
        Err(FileLogConfigError::Directory(ProtectionError::Missing { component })) => {
            assert_eq!(component, state);
        }
        other => panic!("{other:?}"),
    }
    assert!(!state.exists(), "the refusal created the directory");
}

/// The seam's conformance body, on the adapter over the real calls.
#[test]
fn the_seam_conformance_body_passes() {
    let log = Arc::new(Conform::new());
    let () = granary_sim::scenario::run(
        0,
        Box::pin(async move {
            granary_core::testkit::decisionlog_conformance(&*log).await;
        }),
    );
}

// ----------------------------------------------------- the exact calls

/// An adapter over the recording double on a fresh provisioned state
/// directory: the adapter, the double's record and script, and the state
/// directory.
fn recorded() -> (FileLogOn<Recording>, Tap, PathBuf) {
    let state = state_dir();
    let ops = Recording::new(&state);
    let tap = ops.tap();
    (FileLogOn::with_ops(ops), tap, state)
}

/// Each recorded call as `op name`, the name being the name in the state
/// directory it named (`state` for the state directory's own name, its
/// check and its sync, and `anchor` for its parent's sync) or `#g` for a
/// description's generation, with `!` when it failed.
fn shape(ops: &Tap, from: usize) -> Vec<String> {
    ops.shared.calls()[from..]
        .iter()
        .map(|call| {
            let name = match (&call.path, call.generation) {
                (Some(p), _) => p.to_string_lossy().into_owned(),
                (None, Some(g)) => format!("#{g}"),
                (None, None) => String::new(),
            };
            let bang = if call.ok { "" } else { " !" };
            format!("{} {name}{bang}", call.op)
        })
        .collect()
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

/// The first marker write, in the provisioned empty directory: the state
/// directory's name checked, the temporary written and synced, renamed,
/// then the state directory and the anchor synced through their held
/// descriptors, in that order. A second write, with a marker there, syncs
/// the state directory and not the anchor.
#[test]
fn a_marker_write_makes_exactly_its_calls_in_order() {
    let (log, ops, _state) = recorded();
    let running = encode_marker(&RunMarker::Running(BootId::from_bytes([1; 16])));
    now(log.write_marker(&running)).unwrap();
    assert_eq!(
        shape(&ops, 0),
        strings(&[
            "fstatat state",
            "fstatat MARKER",
            "unlink MARKER.tmp !",
            "create_new MARKER.tmp",
            "pwrite #1",
            "sync_file #1",
            "rename MARKER",
            "sync_dir state",
            "sync_dir anchor",
        ])
    );
    let from = ops.shared.calls().len();
    now(log.write_marker(&encode_marker(&RunMarker::Clean))).unwrap();
    assert_eq!(
        shape(&ops, from),
        strings(&[
            "fstatat state",
            "fstatat MARKER",
            "unlink MARKER.tmp !",
            "create_new MARKER.tmp",
            "pwrite #2",
            "sync_file #2",
            "rename MARKER",
            "sync_dir state",
        ])
    );
    assert_eq!(
        now(log.read_marker()).unwrap(),
        MarkerRead::Present(encode_marker(&RunMarker::Clean).as_bytes().to_vec())
    );
}

/// Initialise: the temporary written and synced before its link, the
/// temporary unlinked, then the state directory and the anchor synced; an
/// append then writes the record, syncs, writes the mark, syncs, all
/// through initialise's own description, at the envelope's end.
#[test]
fn initialise_and_append_make_exactly_their_calls_through_one_description() {
    let (log, ops, _state) = recorded();
    let v = vol("vol-a");
    let env = envelope(&v, 7);
    let encoded = encode_envelope(&env);
    now(log.initialise(&encoded)).unwrap();
    assert_eq!(
        shape(&ops, 0),
        strings(&[
            "fstatat state",
            "unlink vol-a.log.tmp !",
            "create_new vol-a.log.tmp",
            "pwrite #1",
            "sync_file #1",
            "link vol-a.log",
            "unlink vol-a.log.tmp",
            "sync_dir state",
            "sync_dir anchor",
        ])
    );
    let from = ops.shared.calls().len();
    let append = encode_append(&env, &decision(&v, 1)).unwrap();
    now(log.append(&append)).unwrap();
    assert_eq!(
        shape(&ops, from),
        strings(&[
            "fstatat state",
            "pwrite #1",
            "sync_file #1",
            "pwrite #1",
            "sync_file #1"
        ])
    );
    let calls = ops.shared.calls();
    let env_len = u64::try_from(encoded.as_bytes().len()).unwrap();
    let rec_len = append.record().len();
    assert_eq!(
        calls[from + 1].at,
        Some((env_len, rec_len)),
        "the record at the envelope's end"
    );
    assert_eq!(
        calls[from + 3].at,
        Some((
            env_len + u64::try_from(rec_len).unwrap(),
            append.mark().len()
        )),
        "the mark after the record"
    );
    let mut expected = encoded.as_bytes().to_vec();
    expected.extend_from_slice(append.record());
    expected.extend_from_slice(append.mark());
    assert_eq!(now(log.read(&v)).unwrap(), Some(expected));
    assert!(
        ops.shared.calls().iter().all(|c| c.op != "open_rw"),
        "the log is never opened again"
    );
}

/// A log first met by `read` (a restart) is opened once, and every later
/// call on it goes through that one description.
#[test]
fn a_read_log_is_opened_once_and_used_for_everything_after() {
    let (log, ops, state) = recorded();
    let v = vol("vol-a");
    let env = envelope(&v, 7);
    std::fs::write(state.join("vol-a.log"), encode_envelope(&env).as_bytes()).unwrap();
    now(log.read(&v)).unwrap().unwrap();
    now(log.append(&encode_append(&env, &decision(&v, 1)).unwrap())).unwrap();
    now(log.resync(&v)).unwrap();
    now(log.read(&v)).unwrap().unwrap();
    let calls = ops.shared.calls();
    let opens: Vec<_> = calls.iter().filter(|c| c.op == "open_rw").collect();
    assert_eq!(opens.len(), 1, "{calls:?}");
    let generation = opens[0].generation;
    assert!(
        calls
            .iter()
            .filter(|c| matches!(c.op, "pwrite" | "sync_file" | "read_all" | "truncate"))
            .all(|c| c.generation == generation),
        "every call on the log through the one description: {calls:?}"
    );
}

/// A truncation moves the tracked length: the append after it lands at
/// the truncated end, and a second read classifies both the kept records
/// and the new one, with no gap and no tail.
#[test]
fn an_append_after_a_truncation_lands_at_the_truncated_end() {
    let (log, _ops, state) = recorded();
    let v = vol("vol-a");
    let env = envelope(&v, 7);
    let committed = super::super::tests::log_bytes(&env, &[decision(&v, 1)]);
    let mut torn = committed.clone();
    torn.extend_from_slice(b"half a record");
    std::fs::write(state.join("vol-a.log"), &torn).unwrap();
    now(log.read(&v)).unwrap().unwrap();
    now(log.truncate(&v, u64::try_from(committed.len()).unwrap())).unwrap();
    let attest = super::super::tests::attestation(&decision(&v, 1));
    now(log.append(&encode_append(&env, &attest).unwrap())).unwrap();
    let bytes = std::fs::read(state.join("vol-a.log")).unwrap();
    match granary_core::authlog::classify(&bytes, &v).unwrap() {
        granary_core::authlog::Classified::Log {
            records, tail_len, ..
        } => {
            assert_eq!(records, vec![decision(&v, 1), attest]);
            assert_eq!(tail_len, 0);
        }
        other @ granary_core::authlog::Classified::NoEnvelope => panic!("{other:?}"),
    }
}

/// A truncation past the tracked length is `OutOfRange`, and changes
/// nothing: the one call is the state directory's check.
#[test]
fn a_truncation_past_the_end_is_out_of_range() {
    let (log, ops, _state) = recorded();
    let v = vol("vol-a");
    now(log.initialise(&encode_envelope(&envelope(&v, 7)))).unwrap();
    let before = ops.shared.calls().len();
    assert_eq!(
        now(log.truncate(&v, 1_000_000)),
        Err(LogIoError::OutOfRange)
    );
    let after: Vec<_> = ops.shared.calls()[before..].iter().map(|c| c.op).collect();
    assert_eq!(
        after,
        ["fstatat"],
        "no syscall but the state directory's check"
    );
}

// ------------------------------------------------------------ writes

/// Short, interrupted and zero-length writes: a short write continues from
/// its count at the advanced offset (never re-appending), an interrupted
/// one retries the same offset, and the bytes on disk are exactly the
/// record and the mark. A zero-length write and a failing one are errors,
/// after which the tracked length has not moved.
#[test]
fn short_and_interrupted_writes_continue_at_the_advanced_offset() {
    let (log, ops, state) = recorded();
    let v = vol("vol-a");
    let env = envelope(&v, 7);
    let encoded = encode_envelope(&env);
    now(log.initialise(&encoded)).unwrap();
    let append = encode_append(&env, &decision(&v, 1)).unwrap();
    {
        let mut script = ops.shared.script();
        script
            .writes
            .extend([Write::Short(5), Write::Interrupted, Write::Short(3)]);
    }
    let from = ops.shared.calls().len();
    now(log.append(&append)).unwrap();
    let env_len = u64::try_from(encoded.as_bytes().len()).unwrap();
    let rec = append.record().len();
    let writes: Vec<(u64, usize)> = ops.shared.calls()[from..]
        .iter()
        .filter(|c| c.op == "pwrite")
        .map(|c| c.at.unwrap())
        .collect();
    assert_eq!(
        &writes[..4],
        &[
            (env_len, rec),
            (env_len + 5, rec - 5),
            (env_len + 5, rec - 5),
            (env_len + 8, rec - 8),
        ],
        "continued from each count, the interrupted one at the same offset"
    );
    let mut expected = encoded.as_bytes().to_vec();
    expected.extend_from_slice(append.record());
    expected.extend_from_slice(append.mark());
    assert_eq!(std::fs::read(state.join("vol-a.log")).unwrap(), expected);
    let sync_after_record = ops.shared.calls()[from..]
        .iter()
        .position(|c| c.op == "sync_file")
        .unwrap();
    let first_mark_write = ops.shared.calls()[from..]
        .iter()
        .position(|c| c.op == "pwrite" && c.at.unwrap().0 == env_len + u64::try_from(rec).unwrap())
        .unwrap();
    assert!(
        sync_after_record < first_mark_write,
        "no mark before the record's sync"
    );

    for scripted in [Write::Zero, Write::Fail] {
        let next =
            encode_append(&env, &super::super::tests::attestation(&decision(&v, 1))).unwrap();
        ops.shared.script().writes.push_back(scripted);
        assert!(now(log.append(&next)).is_err(), "{scripted:?}");
    }
    // The failed appends did not move the tracked length: a truncation to
    // the end of the one landed append succeeds, one byte past it is out of
    // range.
    let end = u64::try_from(expected.len()).unwrap();
    assert_eq!(now(log.truncate(&v, end + 1)), Err(LogIoError::OutOfRange));
    now(log.truncate(&v, end)).unwrap();
}

// ------------------------------------------------------------- links

/// A symbolic link at the state directory's name refuses the adapter; one
/// swapped in after it was built refuses every call before any file under
/// it is touched; and one at a log's name refuses `read`.
#[test]
fn a_link_at_the_state_directory_or_a_log_is_refused() {
    let anchor = scratch();
    let elsewhere = anchor.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, anchor.join("state")).unwrap();
    assert!(
        matches!(
            super::FileLog::new(anchor.join("state"), true),
            Err(FileLogConfigError::Directory(
                ProtectionError::LinkOrNotDirectory { .. }
            ))
        ),
        "a link at the name refuses the adapter"
    );

    let (log, ops, state) = recorded();
    let elsewhere = state.parent().unwrap().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::rename(&state, state.parent().unwrap().join("held")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &state).unwrap();
    let v = vol("vol-a");
    assert_eq!(
        now(log.read_marker()),
        Err(LogIoError::Io(IoErrorKind::Other))
    );
    assert_eq!(
        now(log.write_marker(&encode_marker(&RunMarker::Clean))),
        Err(LogIoError::Io(IoErrorKind::Other))
    );
    assert_eq!(
        now(log.initialise(&encode_envelope(&envelope(&v, 7)))),
        Err(LogIoError::Io(IoErrorKind::Other))
    );
    assert_eq!(now(log.read(&v)), Err(LogIoError::Io(IoErrorKind::Other)));
    assert_eq!(
        std::fs::read_dir(&elsewhere).unwrap().count(),
        0,
        "nothing written through the link"
    );
    assert_eq!(
        shape(&ops, 0),
        strings(&["fstatat state !"; 4]),
        "only the state directory's name was looked at"
    );

    let (log, _ops, state) = recorded();
    let target = state.parent().unwrap().join("target.log");
    std::fs::write(&target, b"not a log").unwrap();
    std::os::unix::fs::symlink(&target, state.join("vol-a.log")).unwrap();
    assert_eq!(now(log.read(&v)), Err(LogIoError::Io(IoErrorKind::Other)));
}

/// A link swapped in at the state directory's name after a log was opened
/// refuses that log's calls too: the open description is no licence to
/// keep serving a directory the spec refuses.
#[test]
fn a_link_at_the_state_directory_refuses_an_already_open_log() {
    let (log, _ops, state) = recorded();
    let v = vol("vol-a");
    let env = envelope(&v, 7);
    now(log.initialise(&encode_envelope(&env))).unwrap();
    let moved = state.parent().unwrap().join("moved");
    std::fs::rename(&state, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &state).unwrap();
    let refused = Err(LogIoError::Io(IoErrorKind::Other));
    assert_eq!(
        now(log.append(&encode_append(&env, &decision(&v, 1)).unwrap())),
        refused
    );
    assert_eq!(now(log.truncate(&v, 0)), refused);
    assert_eq!(now(log.resync(&v)), refused);
    assert_eq!(now(log.read(&v)).map(|_| ()), refused);
    assert_eq!(
        std::fs::read(moved.join("vol-a.log")).unwrap(),
        encode_envelope(&env).as_bytes(),
        "nothing written through the link"
    );
}

/// The marker's temporary's name taken after its leftover's removal (a
/// planted file, then a planted link): the write answers `AlreadyExists`
/// with the marker unchanged and the link's target unwritten.
#[test]
fn a_taken_marker_temporary_is_already_exists_and_writes_nothing() {
    for link in [false, true] {
        let (log, ops, state) = recorded();
        now(log.write_marker(&encode_marker(&RunMarker::Clean))).unwrap();
        let target = state.parent().unwrap().join("target");
        std::fs::write(&target, b"untouched").unwrap();
        let plant = if link {
            Plant::Symlink(target.clone())
        } else {
            Plant::File
        };
        ops.shared.script().plant = Some((state.join("MARKER.tmp"), plant));
        let running = encode_marker(&RunMarker::Running(BootId::from_bytes([2; 16])));
        assert_eq!(
            now(log.write_marker(&running)),
            Err(LogIoError::AlreadyExists)
        );
        assert_eq!(
            now(log.read_marker()).unwrap(),
            MarkerRead::Present(encode_marker(&RunMarker::Clean).as_bytes().to_vec()),
            "the marker is unchanged"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
    }
}

/// The marker's rows the adapter reports: a link at the marker is an
/// error; a missing marker with only a leftover temporary is `Occupied`.
#[test]
fn a_linked_marker_is_an_error_and_a_lone_temporary_occupies_the_directory() {
    let (log, _ops, state) = recorded();
    std::fs::write(state.join("MARKER.tmp"), b"half").unwrap();
    assert_eq!(
        now(log.read_marker()).unwrap(),
        MarkerRead::Missing {
            state_dir: StateDirectory::Occupied
        }
    );
    let target = state.parent().unwrap().join("m");
    std::fs::write(&target, encode_marker(&RunMarker::Clean).as_bytes()).unwrap();
    std::os::unix::fs::symlink(&target, state.join("MARKER")).unwrap();
    assert_eq!(
        now(log.read_marker()),
        Err(LogIoError::Io(IoErrorKind::Other))
    );
}

/// A truncation cuts the file through the log's one description and
/// syncs it through the same, in that order and nothing else.
#[test]
fn a_truncation_makes_exactly_its_calls() {
    let (log, ops, _state) = recorded();
    let v = vol("vol-a");
    let env = envelope(&v, 7);
    now(log.initialise(&encode_envelope(&env))).unwrap();
    now(log.append(&encode_append(&env, &decision(&v, 1)).unwrap())).unwrap();
    let len = u64::try_from(encode_envelope(&env).as_bytes().len()).unwrap();
    let from = ops.shared.calls().len();
    now(log.truncate(&v, len)).unwrap();
    assert_eq!(
        shape(&ops, from),
        strings(&["fstatat state", "truncate #1", "sync_file #1"])
    );
}

/// The namespace barrier alone: the leftover temporary removed, then the
/// state directory and the anchor synced, in that order.
#[test]
fn a_namespace_completion_makes_exactly_its_calls() {
    let (log, ops, _state) = recorded();
    let v = vol("vol-a");
    now(log.initialise(&encode_envelope(&envelope(&v, 7)))).unwrap();
    let from = ops.shared.calls().len();
    now(log.complete_namespace(&v)).unwrap();
    assert_eq!(
        shape(&ops, from),
        strings(&[
            "fstatat state",
            "fstatat vol-a.log",
            "unlink vol-a.log.tmp !",
            "sync_dir state",
            "sync_dir anchor",
        ])
    );
}
