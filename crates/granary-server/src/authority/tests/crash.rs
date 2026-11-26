// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The SIGKILL crash harness: the engine over the production adapter in a
//! real state directory, killed at every crash site a workload and its
//! recoveries reach, and what each kill leaves checked against the
//! durability properties a kill can show.
//!
//! - The **driver** ([`driver`]) is this test binary re-executed: the
//!   engine over `FileLog` and a directory store ([`store`]), a scripted
//!   workload, every crash site reporting to a pipe file, and one of them,
//!   when a plan names it, stopping the process dead. Everything runs on
//!   one thread, so a stopped site stops the engine at that instant.
//! - The **harness** ([`the_kill_holds_at_every_point`]) discovers every
//!   site the workload reaches, then for each: runs a driver to it, kills
//!   and reaps it, copies what it left, and checks the copy (write order,
//!   the marker's lifecycle), the restarts' answers (the marker table), the
//!   recovered state (an independent [`model`]), the truncation on disk,
//!   and the continued workload's answers and store.
//!
//! A kill shows what was written, never what was synced: the page cache
//! outlives the process. Nothing here claims sync order.

mod model;
mod store;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use granary_core::authlog::{Epoch, RecordBody, encode_append, encode_envelope};
use granary_core::hash::GrainId;
use granary_core::root::VolumeName;
use granary_core::rootstore::RootStore;
use granary_sim::sched::{Scheduler, Task, yield_once};
use granary_sim::secure_random::SeededSecureRandom;

use super::super::crash::{self, Plan, Site};
use super::super::file_log::FileLog;
use super::super::join::{JoinAll, Joined};
use super::super::{Answer, AuthorityHandle, AuthorityParts, RunEnd, start};
use super::{FixedClock, YieldPause, block, boot, configs, good_root, rng, submission_at, vol};
use model::{Log, Table};
use store::DirStore;

/// The driver's state directory.
const STATE_ENV: &str = "GRANARY_CRASH_STATE";
/// The driver's store directory.
const STORE_ENV: &str = "GRANARY_CRASH_STORE";
/// The driver's pipe file.
const PIPE_ENV: &str = "GRANARY_CRASH_PIPE";
/// The driver's boot id, a byte.
const BOOT_ENV: &str = "GRANARY_CRASH_BOOT";
/// The driver's plan: `list`, or `kill <site> <k>`.
const PLAN_ENV: &str = "GRANARY_CRASH_PLAN";
/// The driver's incarnation on its copy: how many drivers ran on the copy's
/// history before it, plus one. With the boot it keys the driver's
/// cryptographic-randomness stream, so the stream is a function of what the
/// run is, and a point re-run alone draws what it drew in the sweep.
const INCARNATION_ENV: &str = "GRANARY_CRASH_INCARNATION";
/// A directory the harness writes its coverage table to, for the evidence
/// a PR records. The crate's sources write to no standard stream.
const COVERAGE_ENV: &str = "GRANARY_CRASH_COVERAGE";

/// A scratch directory for one run of the harness.
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
    // Canonical: the protection walk refuses a symbolic link at any
    // component (macOS's `/var`).
    let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "granary-crash-{pid}-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn a() -> VolumeName {
    vol("vol-a")
}

fn b() -> VolumeName {
    vol("vol-b")
}

/// The workload's roots, each publisher-signed for its volume.
struct Roots {
    c1: Vec<u8>,
    c2: Vec<u8>,
    f3: Vec<u8>,
    c3: Vec<u8>,
    c3p: Vec<u8>,
    d1: Vec<u8>,
    /// A second candidate under `c1`'s operation, once it has landed.
    x: Vec<u8>,
}

impl Roots {
    fn new() -> Self {
        let c1 = good_root(&a(), 1, None, 1);
        let c2 = good_root(&a(), 2, Some(GrainId::of(&c1)), 1);
        let f3 = good_root(&a(), 3, Some(GrainId::of(&c2)), 0xF3);
        let c3 = good_root(&a(), 3, Some(GrainId::of(&c2)), 1);
        let c3p = good_root(&a(), 4, Some(GrainId::of(&f3)), 1);
        let d1 = good_root(&b(), 1, None, 1);
        let x = good_root(&a(), 1, None, 2);
        Self {
            c1,
            c2,
            f3,
            c3,
            c3p,
            d1,
            x,
        }
    }
}

const OP_C1: u8 = 1;
const OP_C2: u8 = 2;
const OP_D1: u8 = 3;
const OP_C3: u8 = 4;

// ------------------------------------------------------------- the driver

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is unset: the crash harness runs this"))
}

/// One process of the harness's workload (module docs). It reads its
/// configuration from the environment and panics without it, so no run
/// but the harness's counts it.
#[test]
#[ignore = "a process the crash harness runs"]
fn driver() {
    let state = PathBuf::from(env(STATE_ENV));
    let store = PathBuf::from(env(STORE_ENV));
    let pipe = PathBuf::from(env(PIPE_ENV));
    let boot_byte: u8 = env(BOOT_ENV).parse().unwrap();
    let incarnation: u32 = env(INCARNATION_ENV).parse().unwrap();
    let plan = parse_plan(&env(PLAN_ENV)).unwrap();
    crash::install(&pipe, plan).unwrap();
    crash::note(&format!("START {boot_byte}"));
    let roots = Roots::new();
    let parts = AuthorityParts {
        admission: crate::Admission::chain_fixture(),
        // The harness's subject is the kill, not the filesystem's type.
        log: FileLog::new(&state, true).unwrap(),
        store: DirStore::new(&store, Some(("vol-a".to_owned(), 3, roots.f3.clone()))),
        clock: FixedClock,
        rng: rng(1),
        // Its own stream per process on a copy's history: a restart that
        // drew the previous incarnation's epoch again could answer
        // `Created` where `Kept` was owed and still match the envelope on
        // disk. Two copies with the same history draw the same streams, so
        // identical crash states stay identical.
        secure_random: SeededSecureRandom::for_incarnation(u64::from(boot_byte), incarnation),
        pause: YieldPause,
    };
    let volumes = configs(&[a(), b()]);
    let started = block(async move { start(parts, boot(boot_byte), volumes).await });
    let (handle, driver) = match started {
        Ok(started) => started,
        Err(refused) => {
            crash::note(&format!("REFUSED {refused:?}"));
            return;
        }
    };
    for line in driver.recovered() {
        crash::note(&line);
    }
    let epochs = driver
        .workers
        .iter()
        .filter_map(|worker| {
            worker
                .state()
                .map(|state| (state.envelope().volume().clone(), state.envelope().epoch()))
        })
        .collect();
    crash_point!(Reported);
    let tasks: Vec<Task<Done>> = vec![
        Box::pin(async move { Done::Run(driver.run().await) }),
        Box::pin(async move {
            script(&handle, &roots, epochs).await;
            let _ = handle.stop().await;
            Done::Client
        }),
    ];
    for done in Scheduler::new(0).run(tasks) {
        if let Done::Run(end) = done {
            crash::note(&format!("END {end:?}"));
        }
    }
}

/// One valid genesis, backed by the bounded production reader while the
/// directory store and `FileLog` preserve publication and decision bytes.
#[tokio::test]
#[ignore = "a process the crash harness runs"]
async fn content_driver() {
    let state = PathBuf::from(env(STATE_ENV));
    let store = PathBuf::from(env(STORE_ENV));
    let pipe = PathBuf::from(env(PIPE_ENV));
    let boot_byte: u8 = env(BOOT_ENV).parse().unwrap();
    let plan_text = env(PLAN_ENV);
    let intake_plan = plan_text.strip_prefix("intake ");
    let plan = parse_plan(intake_plan.unwrap_or(&plan_text)).unwrap();
    crash::install(&pipe, plan).unwrap();
    crash::note(&format!("START {boot_byte}"));

    let memory = Arc::new(object_store::memory::InMemory::new());
    let contents = granary_store::backend::GranaryStore::new(memory.clone());
    let disk = DirStore::new(&store, None);
    let fixture = super::gateway::content::empty_tree_fixture;
    let mut prepared = fixture(&contents).await;
    if intake_plan.is_some() {
        let genesis = disk.get_root(a().as_str(), 1).await.unwrap().unwrap();
        contents.put_root(a().as_str(), 1, genesis).await.unwrap();
        prepared = fixture(&contents).await;
    }
    let limits = crate::ValidationLimits {
        reads: 8,
        ..crate::ValidationLimits::default()
    };
    let (handle, driver) = start(
        AuthorityParts {
            log: FileLog::new(&state, true).unwrap(),
            store: disk,
            admission: crate::Admission::memory(memory).with_limits(limits, 2),
            clock: FixedClock,
            rng: rng(1),
            secure_random: SeededSecureRandom::for_incarnation(u64::from(boot_byte), 1),
            pause: YieldPause,
        },
        boot(boot_byte),
        configs(&[a()]),
    )
    .await
    .unwrap();
    let epoch = driver
        .workers
        .first()
        .unwrap()
        .state()
        .map(|state| state.envelope().epoch());
    crash_point!(Reported);
    let client = async {
        let epoch = match epoch {
            Some(epoch) => epoch,
            None => match handle.initialise(&a()).await.unwrap() {
                super::super::Initialised::Created { epoch } => epoch,
                other @ super::super::Initialised::Kept { .. } => panic!("initialise: {other:?}"),
            },
        };
        let op = if intake_plan.is_some() { OP_C2 } else { OP_C1 };
        let answer = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let answer = settle(&handle, epoch, &a(), op, &prepared).await;
                if answer != Answer::Validation(crate::ValidationError::Unavailable) {
                    break answer;
                }
                yield_once().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(answer, Answer::Landed { .. }), "{answer:?}");
        crash::note("CONTENT-LANDED");
        let _ = handle.stop().await;
    };
    let run = async { assert_eq!(driver.run().await, RunEnd::Stopped) };
    let tasks: [Joined<'_>; 2] = [Box::pin(run), Box::pin(client)];
    JoinAll::new(tasks).await;
}

/// What one of the driver's two tasks ended with.
enum Done {
    Run(RunEnd),
    Client,
}

fn parse_plan(text: &str) -> Option<Plan> {
    let mut parts = text.split_whitespace();
    match parts.next()? {
        "list" => Some(Plan::List),
        "kill" => Some(Plan::Kill {
            site: Site::parse(parts.next()?)?,
            k: parts.next()?.parse().ok()?,
        }),
        _ => None,
    }
}

/// The workload: idempotent, so a restarted driver continues where the
/// recovered state is. A step whose answer is wrong writes `SCRIPT-FAIL`.
async fn script(handle: &AuthorityHandle, r: &Roots, mut epochs: BTreeMap<VolumeName, Epoch>) {
    for volume in [a(), b()] {
        let answer = handle.initialise(&volume).await;
        if let Ok(
            super::super::Initialised::Created { epoch }
            | super::super::Initialised::Kept { epoch },
        ) = &answer
        {
            epochs.insert(volume.clone(), *epoch);
        }
        if answer.is_err() && !matches!(answer, Err(super::super::InitialiseError::LogHasRecords)) {
            crash::note(&format!("SCRIPT-FAIL initialise {answer:?}"));
            return;
        }
    }
    let steps: [(&VolumeName, u8, &[u8], &str); 5] = [
        (&a(), OP_C1, &r.c1, "Landed"),
        (&a(), OP_C2, &r.c2, "Landed"),
        (&b(), OP_D1, &r.d1, "Landed"),
        (&a(), OP_C3, &r.c3, "Lost"),
        (&a(), OP_C3, &r.c3p, "Landed"),
    ];
    for (volume, op, candidate, want) in steps {
        let answer = settle(handle, epochs[volume], volume, op, candidate).await;
        let rendered = format!("{answer:?}");
        if !rendered.starts_with(want) {
            crash::note(&format!(
                "SCRIPT-FAIL {} op {op}: {rendered}",
                volume.as_str()
            ));
            return;
        }
        if want == "Lost" && !rendered.contains(&format!("occupant: {:?}", GrainId::of(&r.f3))) {
            crash::note(&format!("SCRIPT-FAIL lost to another occupant: {rendered}"));
            return;
        }
    }
    // A duplicate gets its recorded answer; a different candidate under
    // the landed operation is refused with its outcome.
    let dup = handle
        .submit(submission_at(epochs[&a()], &a(), OP_C1, &r.c1))
        .await;
    if !matches!(dup, Answer::Landed { .. }) {
        crash::note(&format!("SCRIPT-FAIL duplicate: {dup:?}"));
    }
    let bound = handle
        .submit(submission_at(epochs[&a()], &a(), OP_C1, &r.x))
        .await;
    if !matches!(
        bound,
        Answer::OperationBound(super::super::Bound::Landed(_))
    ) {
        crash::note(&format!("SCRIPT-FAIL bound: {bound:?}"));
    }
}

/// Submit until the answer is no longer `Accepted` or `Open`.
async fn settle(
    handle: &AuthorityHandle,
    epoch: Epoch,
    volume: &VolumeName,
    op: u8,
    candidate: &[u8],
) -> Answer {
    let sub = submission_at(epoch, volume, op, candidate);
    for _ in 0..10_000 {
        match handle.submit(sub.clone()).await {
            Answer::Accepted { .. } | Answer::Open { .. } => yield_once().await,
            other => return other,
        }
    }
    Answer::Stopped
}

/// The power-loss attempt's check (the Linux venue runs it after the
/// remount): every record the pipe shows acknowledged, both its syncs
/// returned, is committed in the log that survived. An unacknowledged
/// record may or may not have survived; nothing is claimed about it.
#[test]
#[ignore = "the Linux venue's power-loss attempt runs this"]
fn every_acknowledged_record_survives_the_power_loss() {
    let state = PathBuf::from(env(STATE_ENV));
    let pipe = std::fs::read_to_string(env(PIPE_ENV)).unwrap();
    let mut acked = 0;
    for line in pipe.lines().filter(|l| l.starts_with("ACK ")) {
        let mut parts = line.split_whitespace().skip(1);
        let volume = vol(parts.next().unwrap());
        let end: usize = parts.nth(1).unwrap().parse().unwrap();
        let committed = model::read_log(&state, &volume).map_or(0, |log| log.committed_len);
        assert!(
            end <= committed,
            "lost after the power cut: {line} (committed {committed})"
        );
        acked += 1;
    }
    assert!(
        acked > 0,
        "no record was acknowledged before the cut: the attempt is vacuous"
    );
}

// ---------------------------------------------------------- running one

/// One run's directory: the anchor holding the provisioned state
/// directory, the store, and the pipe.
#[derive(Debug)]
struct Base(PathBuf);

impl Drop for Base {
    /// A run leaves nothing behind: thousands of copies would fill the
    /// venue's filesystem.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Base {
    fn fresh() -> Self {
        let dir = scratch();
        let state = dir.join("anchor").join("state");
        std::fs::create_dir_all(&state).unwrap();
        // The protection walk takes a state directory no one else can
        // enter.
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir_all(dir.join("store")).unwrap();
        Self(dir)
    }

    fn state(&self) -> PathBuf {
        self.0.join("anchor").join("state")
    }

    fn store(&self) -> PathBuf {
        self.0.join("store")
    }

    fn pipe(&self) -> PathBuf {
        self.0.join("pipe")
    }

    /// A copy of everything: the anchor, the store and the pipe.
    fn copy(&self) -> Self {
        let to = scratch();
        copy_tree(&self.0, &to);
        Self(to)
    }

    fn log(&self, volume: &VolumeName) -> Option<Log> {
        model::read_log(&self.state(), volume)
    }

    fn pipe_lines(&self) -> Vec<String> {
        std::fs::read_to_string(self.pipe())
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// Copy `from` to `to`, each directory keeping its mode (the state
/// directory's `0o700` above all).
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    std::fs::set_permissions(to, std::fs::metadata(from).unwrap().permissions()).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Every file under `dir` and its bytes: what a crash left, as one value.
fn digest_tree(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            for (path, bytes) in digest_tree(&entry.path()) {
                out.insert(PathBuf::from(entry.file_name()).join(path), bytes);
            }
        } else {
            out.insert(
                PathBuf::from(entry.file_name()),
                std::fs::read(entry.path()).unwrap(),
            );
        }
    }
    out
}

/// How a driver process ended, and the pipe lines it wrote.
#[derive(Debug)]
enum Ran {
    /// It stopped at its planned site and was killed and reaped.
    Killed(Vec<String>),
    /// It exited on its own.
    Exited(Vec<String>),
}

impl Ran {
    fn lines(&self) -> &[String] {
        match self {
            Self::Killed(lines) | Self::Exited(lines) => lines,
        }
    }
}

/// How many polls (each about a millisecond apart) a driver process gets
/// before the harness calls it wedged: far beyond any run's length.
const DEADLINE_POLLS: u32 = 120_000;

/// Run one driver process over `base` under boot `boot_byte` with `plan`;
/// kill it when it reports reaching its site. A process that neither
/// reaches its site nor exits by the deadline is killed and fails the
/// harness, naming its plan.
fn run(base: &Base, boot_byte: u8, plan: &str) -> Ran {
    // Every driver notes `START` first, and a copy carries its pipe, so
    // the count is the restarts this copy's history has seen.
    let starts = base
        .pipe_lines()
        .iter()
        .filter(|line| line.starts_with("START "))
        .count();
    let incarnation = u32::try_from(starts).unwrap() + 1;
    let before = std::fs::metadata(base.pipe()).map_or(0, |m| m.len());
    let (test, plan) = match plan.strip_prefix("content ") {
        Some(plan) => ("authority::tests::crash::content_driver", plan),
        None => ("authority::tests::crash::driver", plan),
    };
    let mut child: Child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--include-ignored", "--test-threads=1"])
        .env(STATE_ENV, base.state())
        .env(STORE_ENV, base.store())
        .env(PIPE_ENV, base.pipe())
        .env(BOOT_ENV, boot_byte.to_string())
        .env(PLAN_ENV, plan)
        .env(INCARNATION_ENV, incarnation.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let new_lines = |base: &Base| -> Vec<String> {
        // The driver creates the pipe; it may not have yet.
        let pipe_contents = std::fs::read_to_string(base.pipe()).unwrap_or_default();
        pipe_contents
            .get(usize::try_from(before).unwrap()..)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    };
    for _ in 0..DEADLINE_POLLS {
        if let Some(status) = child.try_wait().unwrap() {
            let lines = new_lines(base);
            if !status.success() {
                let mut err = String::new();
                if let Some(mut stderr) = child.stderr.take() {
                    let _ = stderr.read_to_string(&mut err);
                }
                panic!("the driver failed ({status}): {err}\n{lines:#?}");
            }
            return Ran::Exited(lines);
        }
        let lines = new_lines(base);
        if lines.iter().any(|l| l.starts_with("REACHED ")) {
            child.kill().unwrap();
            child.wait().unwrap();
            return Ran::Killed(new_lines(base));
        }
        pause();
    }
    let _ = child.kill();
    let _ = child.wait();
    let lines = new_lines(base);
    panic!(
        "the driver (boot {boot_byte}, plan {plan}) was wedged: it neither reached its site nor \
         exited; its last lines: {:#?}",
        lines.iter().rev().take(10).collect::<Vec<_>>()
    );
}

#[expect(
    clippy::disallowed_methods,
    reason = "the harness polls a child process's pipe file; wall time orders nothing under test"
)]
fn pause() {
    std::thread::sleep(std::time::Duration::from_millis(1));
}

/// The `(site, k)` of each `HIT` line, in order, up to (not including) the
/// first `HIT` of `until`, if given.
fn points(lines: &[String], until: Option<Site>) -> Vec<(Site, u32)> {
    let mut out = Vec::new();
    for line in lines {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("HIT") {
            continue;
        }
        let site = Site::parse(parts.next().unwrap()).unwrap();
        let k: u32 = parts.next().unwrap().parse().unwrap();
        if Some(site) == until {
            break;
        }
        out.push((site, k));
    }
    out
}

fn kill_plan((site, k): (Site, u32)) -> String {
    format!("kill {} {k}", site.name())
}

// ------------------------------------------------------------- the checks

/// Failures found, each naming the point it was found at.
#[derive(Debug, Default)]
struct Found(Vec<String>);

impl Found {
    fn fail(&mut self, at: &str, what: impl std::fmt::Display) {
        self.0.push(format!("{at}: {what}"));
    }
}

/// Write order on a copy (module docs): every sent reply's and issued
/// PUT's dependency is committed in the copy.
fn write_order(copy: &Base, lines: &[String], at: &str, found: &mut Found) {
    let logs: BTreeMap<String, Option<Log>> = [a(), b()]
        .iter()
        .map(|v| (v.as_str().to_owned(), copy.log(v)))
        .collect();
    for line in lines {
        let mut parts = line.splitn(3, ' ');
        match (parts.next(), parts.next(), parts.next()) {
            (Some("REPLY"), Some(volume), Some(rendered)) => match model::needs(rendered) {
                Err(unread) => found.fail(at, unread),
                Ok(Some(need))
                    if !model::holds(
                        logs.get(volume).and_then(Option::as_ref),
                        &need,
                        rendered,
                    ) =>
                {
                    found.fail(
                        at,
                        format!("a reply before its {need:?} was committed: {line}"),
                    );
                }
                Ok(_) => {}
            },
            (Some("PUT"), Some(volume), Some(rest)) => {
                let mut rest = rest.split(' ');
                let seq: u64 = rest.next().unwrap().parse().unwrap();
                let id = rest.next().unwrap();
                let attested = logs
                    .get(volume)
                    .and_then(Option::as_ref)
                    .is_some_and(|log| {
                        log.records.iter().any(|r| {
                            model::attested(log, r.seq()).is_some_and(|(root_seq, sid)| {
                                root_seq == seq && format!("{sid:?}") == id
                            })
                        })
                    });
                if !attested {
                    found.fail(
                        at,
                        format!("a PUT before its attestation was committed: {line}"),
                    );
                }
            }
            _ => {}
        }
    }
}

/// The marker's lifecycle on one process's lines (module docs): no
/// state-directory mutation before its running marker's rename; no clean
/// write before its last mutation; and no clean write before the driver
/// first runs the engine (its `Reported` site), except by a start that the
/// table admitted and that then refused, which writes clean and reports
/// `REFUSED`.
fn lifecycle(lines: &[String], at: &str, found: &mut Found) {
    const MUTATIONS: [&str; 11] = [
        "LogLeftoverRemoved",
        "InitTempCreated",
        "InitTempWritten",
        "InitLinked",
        "InitUnlinked",
        "RecordWritten",
        "MarkWritten",
        "Truncated",
        "NamespaceUnlinked",
        "Resynced",
        "TruncateSynced",
    ];
    let running = lines.iter().position(|l| l == "MARKER running renamed");
    let mut last_mutation = None;
    for (i, line) in lines.iter().enumerate() {
        let mut parts = line.split_whitespace();
        if let (Some("HIT" | "REACHED"), Some(site)) = (parts.next(), parts.next())
            && MUTATIONS.contains(&site)
        {
            if running.is_none_or(|r| i < r) {
                found.fail(
                    at,
                    format!("a log mutation before the running marker: {line}"),
                );
            }
            last_mutation = Some(i);
        }
    }
    let Some(clean) = lines.iter().position(|l| l.starts_with("MARKER clean ")) else {
        return;
    };
    if last_mutation.is_some_and(|m| clean < m) {
        found.fail(at, "a clean marker write before the last log mutation");
    }
    let reported = lines
        .iter()
        .position(|l| l == "HIT Reported 1" || l == "REACHED Reported 1");
    let refused = lines.iter().any(|l| l.starts_with("REFUSED "));
    if reported.is_none_or(|r| clean < r) && !refused {
        found.fail(
            at,
            "a clean marker write before the engine ran, by a start that did not refuse",
        );
    }
}

/// A restart's answer against the marker table read from the directory it
/// starts on.
fn restart_answer(ran: &Ran, expected: Table, at: &str, found: &mut Found) -> bool {
    let refused = ran.lines().iter().find(|l| l.starts_with("REFUSED "));
    match (expected.refusal(), refused) {
        (None, None) => true,
        (Some(kind), Some(line)) if line.contains(kind) => false,
        (want, got) => {
            found.fail(
                at,
                format!("the table says {want:?}, the start said {got:?}"),
            );
            false
        }
    }
}

/// Recovery's state and bytes (module docs): `STATE` equals the model of
/// the first copy, and each log on disk is that copy's committed prefix.
fn recovered(first: &Base, after: &Base, lines: &[String], at: &str, found: &mut Found) {
    let reported: Vec<&String> = lines.iter().filter(|l| l.starts_with("STATE ")).collect();
    let mut want = Vec::new();
    for volume in [a(), b()] {
        let log = first.log(&volume);
        want.extend(model::model(&volume, log.as_ref()));
        if let Some(log) = log {
            let now = std::fs::read(after.state().join(format!("{}.log", volume.as_str())))
                .unwrap_or_default();
            if now.as_slice() != log.bytes.get(..log.committed_len).unwrap_or_default() {
                found.fail(
                    at,
                    format!(
                        "{}: after recovery the log is {} bytes, its committed prefix {}",
                        volume.as_str(),
                        now.len(),
                        log.committed_len
                    ),
                );
            }
        }
    }
    let reported: Vec<String> = reported.into_iter().cloned().collect();
    if reported != want {
        found.fail(at, format!("recovered {reported:#?}\nexpected {want:#?}"));
    }
}

/// Every record the killed process acknowledged is committed in the copy.
fn acknowledged(copy: &Base, lines: &[String], at: &str, found: &mut Found) {
    for line in lines {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("ACK") {
            continue;
        }
        let volume = vol(parts.next().unwrap());
        let end: usize = parts.nth(1).unwrap().parse().unwrap();
        if copy.log(&volume).is_none_or(|log| end > log.committed_len) {
            found.fail(
                at,
                format!("an acknowledged record is not committed: {line}"),
            );
        }
    }
}

/// The byte offset each record of `log` ends at, in record order.
fn record_ends(log: &Log) -> Vec<usize> {
    let mut at = encode_envelope(&log.envelope).as_bytes().len();
    log.records
        .iter()
        .map(|record| {
            let append = encode_append(&log.envelope, record).unwrap();
            at += append.record().len() + append.mark().len();
            at
        })
        .collect()
}

/// O2, O3 and O5 over the final directory and every line the run wrote.
fn final_checks(base: &Base, lines: &[String], at: &str, found: &mut Found) {
    if lines.iter().any(|l| l.starts_with("SCRIPT-FAIL")) {
        found.fail(at, format!("the workload failed: {lines:#?}"));
    }
    for volume in [a(), b()] {
        // O2: `classify` accepts the whole log (positions, the grammar).
        let Some(log) = base.log(&volume) else {
            found.fail(at, format!("{}: no log at the end", volume.as_str()));
            continue;
        };
        if log.committed_len != log.bytes.len() {
            found.fail(at, format!("{}: a tail at the end", volume.as_str()));
        }
        let ends = record_ends(&log);
        for (record, end) in log.records.iter().zip(ends) {
            let seq = record.seq();
            let claim = match record.body() {
                RecordBody::Landed { .. } => model::attested(&log, seq).map(|(_, id)| id),
                RecordBody::Lost { occupant_id, .. } => Some(*occupant_id),
                _ => continue,
            };
            let root_seq = model::attested(&log, seq).map(|(root_seq, _)| root_seq);
            // O5: a GET of the seq, whose answer gives the outcome, after
            // the entry's last PUT before the outcome's acknowledgement (or
            // before the end, for an outcome recovery adopted unacknowledged).
            // So a read by an earlier process, before a re-issue, does not
            // count for an outcome a later process recorded.
            let bound = lines
                .iter()
                .rposition(|l| {
                    l.starts_with(&format!("ACK {} ", volume.as_str()))
                        && l.ends_with(&format!(" {end}"))
                })
                .unwrap_or(lines.len());
            let get = format!(
                "GET {} {} {:?}",
                volume.as_str(),
                root_seq.unwrap_or_default(),
                claim.unwrap_or(GrainId::of(b""))
            );
            let put = format!("PUT {} {} ", volume.as_str(), root_seq.unwrap_or_default());
            let before = lines.get(..bound).unwrap_or_default();
            let read_after_put = before
                .iter()
                .rposition(|l| l.starts_with(&put))
                .is_some_and(|p| before.get(p + 1..).unwrap_or_default().contains(&get));
            if !read_after_put {
                found.fail(
                    at,
                    format!(
                        "{}: an outcome at {seq} without its read after the entry's last PUT ({get})",
                        volume.as_str()
                    ),
                );
            }
        }
        // O3: every PUT carried its attestation's volume, seq and id.
        for line in lines
            .iter()
            .filter(|l| l.starts_with(&format!("PUT {} ", volume.as_str())))
        {
            let mut parts = line.split(' ').skip(2);
            let seq: u64 = parts.next().unwrap().parse().unwrap();
            let id = parts.next().unwrap();
            let matches = log.records.iter().any(|r| {
                model::attested(&log, r.seq())
                    .is_some_and(|(root_seq, sid)| root_seq == seq && format!("{sid:?}") == id)
            });
            if !matches {
                found.fail(at, format!("a PUT no attestation records: {line}"));
            }
        }
    }
}

// ------------------------------------------------------------ the harness

/// The sites a discovery reached, by name.
fn sites_reached(lines: &[String]) -> BTreeSet<Site> {
    points(lines, None)
        .into_iter()
        .map(|(site, _)| site)
        .collect()
}

/// Sites no workload reaches without an injected failure, with why.
const UNREACHED: [(Site, &str); 19] = [
    (Site::IntakeSlice, "covered by the intake crash matrix"),
    (
        Site::IntakeBeforeRecheck,
        "covered by the intake crash matrix",
    ),
    (
        Site::ValidatedDecisionCommitted,
        "covered by the content crash matrix",
    ),
    (
        Site::ValidationBinRead,
        "covered by the content crash matrix",
    ),
    (
        Site::ValidatedBeforeAppend,
        "covered by the content crash matrix",
    ),
    (
        Site::IntentPartialWrite,
        "covered by the intent crash matrix",
    ),
    (
        Site::IntentBeforeTemporary,
        "covered by the intent crash matrix",
    ),
    (
        Site::IntentTemporaryCreated,
        "covered by the intent crash matrix",
    ),
    (
        Site::IntentTemporaryWritten,
        "covered by the intent crash matrix",
    ),
    (Site::IntentFileSynced, "covered by the intent crash matrix"),
    (Site::IntentRenamed, "covered by the intent crash matrix"),
    (
        Site::IntentDirectorySynced,
        "covered by the intent crash matrix",
    ),
    (
        Site::IntentStateInstalled,
        "covered by the intent crash matrix",
    ),
    (
        Site::IntentBeforeReply,
        "covered by the intent crash matrix",
    ),
    (Site::IntentReplySent, "covered by the intent crash matrix"),
    (
        Site::IntentProvisioned,
        "this sweep has no intent store configured; covered by explicit worker/offline initialise crash matrices",
    ),
    (
        Site::IntentProvisionLogSynced,
        "this sweep has no intent store configured; covered by explicit worker/offline initialise crash matrices",
    ),
    (Site::IntentRebound, "covered by the intent crash matrix"),
    (Site::IntentEvicted, "covered by the intent crash matrix"),
];

/// What the harness reached, for its evidence and its floors.
#[derive(Debug, Default)]
struct Coverage {
    /// The first process's points, each killed at.
    first_points: usize,
    /// Kills whose same-boot restart the table refused.
    same_boot_refused: usize,
    /// Kills whose same-boot restart the table admitted.
    same_boot_admitted: usize,
    /// Kills whose new-boot restart recovered, and was checked.
    recovered: usize,
    /// Kills whose new-boot restart the table refused (an operator's).
    new_boot_refused: usize,
    /// Distinct states a kill left that a recovery started from.
    recovery_states: usize,
    /// Points inside those recoveries, each killed at.
    recovery_points: usize,
    /// Points per site, over every discovery.
    per_site: BTreeMap<String, usize>,
}

/// A state a kill left that a recovery started from, by its anchor's
/// files and bytes: the point that left it, and its copy.
type Recoveries = BTreeMap<BTreeMap<PathBuf, Vec<u8>>, (String, Base)>;

/// At one point of the first process (module docs): the kill; the copy's
/// write order and the process's marker lifecycle; each restart's answer
/// against the table, and its lifecycle; the recovery's state and bytes; and
/// the continued workload to its end. A copy a recovery started from is
/// kept, once per distinct state, for the kills inside recovery.
fn kill_first(
    point: (Site, u32),
    first_points: &[(Site, u32)],
    recoveries: &mut Recoveries,
    coverage: &mut Coverage,
    found: &mut Found,
) {
    let at = format!("{} {}", point.0.name(), point.1);
    let base = Base::fresh();
    let killed = run(&base, 1, &kill_plan(point));
    let Ran::Killed(lines) = &killed else {
        found.fail(&at, "never reached");
        return;
    };
    // The same instant as the discovery's.
    let reached_points = points(lines, None);
    if first_points.get(..reached_points.len()) != Some(reached_points.as_slice()) {
        found.fail(&at, "the run's sites differ from the discovery's");
    }
    let copy = base.copy();
    write_order(&copy, lines, &at, found);
    lifecycle(lines, &at, found);

    // The restarts' answers, each on its own copy: the same boot, then a
    // new one, which recovers when the table admits it.
    let mut recovered_from = false;
    for (probe_boot, which) in [(1, "same boot"), (2, "new boot")] {
        let probe = copy.copy();
        let expected = model::table(&probe.state(), boot(probe_boot));
        let ran = run(&probe, probe_boot, "kill Reported 1");
        let label = format!("{at} {which}");
        let admitted = restart_answer(&ran, expected, &label, found);
        lifecycle(ran.lines(), &label, found);
        match (probe_boot, admitted) {
            (1, true) => coverage.same_boot_admitted += 1,
            (1, false) => coverage.same_boot_refused += 1,
            (_, true) => coverage.recovered += 1,
            (_, false) => coverage.new_boot_refused += 1,
        }
        if admitted && probe_boot == 2 {
            // Recovery: the state it rebuilt and the bytes it left.
            recovered(&copy, &probe, ran.lines(), &format!("{at} recovery"), found);
            acknowledged(&copy, lines, &at, found);
            // The continued workload to its end, under a third boot.
            let end = run(&probe, 3, "list");
            let all = probe.pipe_lines();
            lifecycle(end.lines(), &format!("{at} continued"), found);
            final_checks(&probe, &all, &format!("{at} continued"), found);
            recovered_from = true;
        }
    }
    if recovered_from {
        recoveries
            .entry(digest_tree(&copy.0.join("anchor")))
            .or_insert((at, copy));
    }
}

/// Inside the recovery from `copy`, the state the kill at `at` left (module
/// docs): every point of that recovery, killed at; then the same-boot
/// answer, and a recovery under a new boot, whose state and bytes are the
/// copy's; the lifecycle of each process.
fn kill_recovery(
    at: &str,
    copy: &Base,
    reached: &mut BTreeSet<Site>,
    coverage: &mut Coverage,
    found: &mut Found,
) {
    let listing = copy.copy();
    let discovery = run(&listing, 2, "list");
    reached.extend(sites_reached(discovery.lines()));
    for inner in points(discovery.lines(), Some(Site::Reported)) {
        coverage.recovery_points += 1;
        *coverage
            .per_site
            .entry(format!("recovery {}", inner.0.name()))
            .or_default() += 1;
        let at = format!("{at} then recovery {} {}", inner.0.name(), inner.1);
        let second = copy.copy();
        let killed = run(&second, 2, &kill_plan(inner));
        let Ran::Killed(lines) = &killed else {
            found.fail(&at, "never reached");
            continue;
        };
        lifecycle(lines, &at, found);
        let same = second.copy();
        let expected = model::table(&same.state(), boot(2));
        let ran = run(&same, 2, "kill Reported 1");
        let _ = restart_answer(&ran, expected, &at, found);
        lifecycle(ran.lines(), &format!("{at} same boot"), found);
        let third = second.copy();
        let expected = model::table(&third.state(), boot(3));
        let ran = run(&third, 3, "kill Reported 1");
        lifecycle(ran.lines(), &format!("{at} new boot"), found);
        if restart_answer(&ran, expected, &at, found) {
            recovered(copy, &third, ran.lines(), &format!("{at} recovery"), found);
        }
    }
}

#[test]
fn content_crash_cuts_converge_on_one_decision() {
    for (site, expected) in [
        (Site::ValidationBinRead, 0),
        (Site::ValidatedBeforeAppend, 0),
        (Site::RecordWritten, 0),
        (Site::ValidatedDecisionCommitted, 1),
        (Site::PutSent, 1),
    ] {
        let base = Base::fresh();
        let cut = run(&base, 1, &format!("content kill {} 1", site.name()));
        assert!(matches!(cut, Ran::Killed(_)), "{site:?}");
        let count = |log: &Log| {
            log.records
                .iter()
                .filter(|record| matches!(record.body(), RecordBody::Decision { .. }))
                .count()
        };
        let before = base.log(&a()).unwrap();
        assert_eq!(count(&before), expected, "{site:?}");
        if matches!(site, Site::ValidationBinRead | Site::ValidatedBeforeAppend) {
            assert_eq!(before.bytes.len(), before.committed_len, "{site:?}");
            assert!(before.records.is_empty(), "{site:?}");
        }

        let restart = run(&base, 2, "content list");
        assert!(matches!(restart, Ran::Exited(_)), "{site:?}");
        assert!(
            restart.lines().iter().any(|line| line == "CONTENT-LANDED"),
            "{site:?}"
        );
        let after = base.log(&a()).unwrap();
        assert_eq!(count(&after), 1, "{site:?}");
        assert!(
            after
                .bytes
                .starts_with(&before.bytes[..before.committed_len]),
            "{site:?}"
        );
        assert!(
            after
                .records
                .iter()
                .any(|r| matches!(r.body(), RecordBody::Landed { .. }))
        );
    }
}

#[test]
fn intake_crash_cuts_leave_no_new_decision_and_restart_rebuilds_the_proof() {
    let genesis = Base::fresh();
    assert!(matches!(run(&genesis, 1, "content list"), Ran::Exited(_)));
    let before = genesis.log(&a()).unwrap().bytes;
    for site in [Site::IntakeSlice, Site::IntakeBeforeRecheck] {
        let base = genesis.copy();
        let cut = run(&base, 2, &format!("content intake kill {} 1", site.name()));
        assert!(matches!(cut, Ran::Killed(_)), "{site:?}");
        assert_eq!(base.log(&a()).unwrap().bytes, before, "{site:?}");
        let restarted = run(&base, 3, "content intake list");
        assert!(matches!(restarted, Ran::Exited(_)), "{site:?}");
        assert!(
            restarted
                .lines()
                .iter()
                .any(|line| line == "CONTENT-LANDED")
        );
        let after = base.log(&a()).unwrap();
        assert_eq!(
            after
                .records
                .iter()
                .filter(|r| matches!(r.body(), RecordBody::Decision { .. }))
                .count(),
            2
        );
        assert!(after.bytes.starts_with(&before));
    }
}

/// The harness (module docs).
#[test]
fn the_kill_holds_at_every_point() {
    let mut found = Found::default();
    let mut reached = BTreeSet::new();
    let mut coverage = Coverage::default();

    // Discovery: the first process, to its end.
    let base = Base::fresh();
    let discovery = run(&base, 1, "list");
    assert!(
        matches!(discovery, Ran::Exited(_)),
        "the discovery was killed"
    );
    let first_points = points(discovery.lines(), None);
    coverage.first_points = first_points.len();
    for (site, _) in &first_points {
        *coverage.per_site.entry(site.name()).or_default() += 1;
    }
    reached.extend(sites_reached(discovery.lines()));
    lifecycle(discovery.lines(), "discovery", &mut found);
    final_checks(&base, discovery.lines(), "discovery", &mut found);
    assert!(found.0.is_empty(), "{:#?}", found.0);

    let mut recoveries = Recoveries::new();
    for point in &first_points {
        kill_first(
            *point,
            &first_points,
            &mut recoveries,
            &mut coverage,
            &mut found,
        );
    }

    // Kills inside recovery, once per distinct state a kill left.
    coverage.recovery_states = recoveries.len();
    for (at, copy) in recoveries.values() {
        kill_recovery(at, copy, &mut reached, &mut coverage, &mut found);
    }

    if let Ok(dir) = std::env::var(COVERAGE_ENV) {
        std::fs::write(
            Path::new(&dir).join("crash-coverage.txt"),
            format!("{coverage:#?}\n"),
        )
        .unwrap();
    }
    // Floors: the run did the work (each kind of restart was met).
    for (what, n) in [
        ("first points", coverage.first_points),
        ("same-boot refusals", coverage.same_boot_refused),
        ("recoveries checked", coverage.recovered),
        ("recovery states", coverage.recovery_states),
        ("recovery points", coverage.recovery_points),
    ] {
        if n == 0 {
            found.fail("coverage", format!("no {what}"));
        }
    }
    // Coverage: every site reached, or excluded with its reason.
    for site in Site::ALL {
        if !reached.contains(&site) && !UNREACHED.iter().any(|(s, _)| *s == site) {
            found.fail("coverage", format!("{site:?} was never reached"));
        }
    }
    assert!(
        found.0.is_empty(),
        "{} failures:\n{}",
        found.0.len(),
        found.0.join("\n")
    );
}
