// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One point of the sweep, run: its processes, the two restarts after a
//! crash or a fence, the crashes, and what the oracle reads afterwards.
//!
//! **Scheduling.** Process 1 runs under the sweep's scheduler seed, so up
//! to its injection it is identical to the sweep's dry run and every
//! index the dry run discovered names the same step. Later processes take
//! a seed derived from the point's first injection and draw alone, never
//! from its recovery injection, so the recovery runs of one first point
//! share a schedule and the recovery steps their discovery found.

use std::fmt;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use granary_core::decisionlog::{DecisionLog, MarkerRead, StateDirectory};
use granary_core::root::VolumeName;
use granary_core::runmarker::{RunMarker, decode_marker};
use granary_sim::decision_log::{CrashReport, LogFault, LogFaults, SimDecisionLog};
use granary_sim::fakes::{Fault, Faults, Sim, SimStore};
use granary_sim::rng::Rng as SimRng;
use granary_sim::sched::{Scheduler, Task};
use granary_sim::secure_random::SeededSecureRandom;
use granary_sim::trace::{LogOp, LogPath, LogViolation, Op, Outcome, Trace};

use super::super::{
    AuthorityParts, FixedClock, RunEnd, StartRefused, YieldPause, block, boot, configs, rng, start,
};
use super::harness::{
    Cut, Ev, Hooks, Kill, Mortal, OpClaim, StoreOp, SweepLog, SweepStore, Timeline, observer,
};
use super::workload::{Client, Roots, Script};
use super::{a, b};

/// An injection into one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Inject {
    None,
    /// The process dies at this log step.
    LogCrash(u32),
    /// The sync at this log step fails.
    LogFail(u32),
    /// The process dies at this store operation of process 1.
    Store(u32, Cut),
}

impl fmt::Display for Inject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::LogCrash(s) => write!(f, "crash@{s}"),
            Self::LogFail(s) => write!(f, "fail@{s}"),
            Self::Store(k, Cut::Before) => write!(f, "store-before@{k}"),
            Self::Store(k, Cut::After) => write!(f, "store-after@{k}"),
        }
    }
}

/// The kind of one log step's op: what [`OpLabel::Log`] names, ignoring
/// the path, length or digest a build might spell differently while
/// still doing the same step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum LogKind {
    Read,
    Write,
    FileSync,
    DirSync,
    Create,
    Mkdir,
    Link,
    Unlink,
    Rename,
    Truncate,
}

impl From<&LogOp> for LogKind {
    /// A log step's op is always one written by hand to a file or synced
    /// or renamed within one (`decision_log::Step::op`); the aggregate
    /// kinds (`Call`, `Restart`, `Crash`, `Draw`, `Row`, `File`,
    /// `StateDir`, `Damage`) describe other trace entries, never a step.
    fn from(op: &LogOp) -> Self {
        match op {
            LogOp::Read { .. } => Self::Read,
            LogOp::Write { .. } => Self::Write,
            LogOp::FileSync { .. } => Self::FileSync,
            LogOp::DirSync { .. } => Self::DirSync,
            LogOp::Create { .. } => Self::Create,
            LogOp::Mkdir { .. } => Self::Mkdir,
            LogOp::Link { .. } => Self::Link,
            LogOp::Unlink { .. } => Self::Unlink,
            LogOp::Rename { .. } => Self::Rename,
            LogOp::Truncate { .. } => Self::Truncate,
            other => unreachable!("a log step is never {other:?}"),
        }
    }
}

impl fmt::Display for LogKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::FileSync => "file-sync",
            Self::DirSync => "dir-sync",
            Self::Create => "create",
            Self::Mkdir => "mkdir",
            Self::Link => "link",
            Self::Unlink => "unlink",
            Self::Rename => "rename",
            Self::Truncate => "truncate",
        })
    }
}

impl LogKind {
    /// The kind `Self`'s [`Display`] names, or `None`: the inverse.
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "read" => Self::Read,
            "write" => Self::Write,
            "file-sync" => Self::FileSync,
            "dir-sync" => Self::DirSync,
            "create" => Self::Create,
            "mkdir" => Self::Mkdir,
            "link" => Self::Link,
            "unlink" => Self::Unlink,
            "rename" => Self::Rename,
            "truncate" => Self::Truncate,
            _ => return None,
        })
    }
}

/// A short, stable label of the operation a dry run found at one of a
/// point's indices: a log step's op kind, or a store operation's kind
/// and what it addressed. What a labelled point id names beside each
/// index it uses, and what a fresh run checks it still finds there
/// before trusting a point discovered on another build (`sweep.rs`'s
/// `verify_labels`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum OpLabel {
    Log(LogKind),
    Store(StoreOp),
}

impl fmt::Display for OpLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Log(kind) => write!(f, "{kind}"),
            Self::Store(op) => write!(f, "{op}"),
        }
    }
}

/// Why [`Point::parse`] refused a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PointParseError {
    /// The string does not have a point id's shape.
    Malformed,
    /// An index names no label: the old, unlabelled point id. The same
    /// index can name a different operation on another build, so a
    /// label is required at every index a point uses — never silently
    /// accepted without one.
    Unlabelled,
    /// A store cut named in the recovery field. A cut always applies to
    /// process 1's store (`run.rs`'s `Runner::process` reads the cut only
    /// from `point.first`), never process 2's, which is what the
    /// recovery field injects into; a run with no process 2 then has no
    /// store to index there at all.
    RecoveryStoreCut,
}

impl fmt::Display for PointParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "not a point id",
            Self::Unlabelled => {
                "point ids must label every index they use; the old, unlabelled \
                 form is refused because the same index can name a different \
                 operation on another build"
            }
            Self::RecoveryStoreCut => {
                "a store cut names no recovery: a cut always targets process 1's \
                 store, never process 2's, which is what the recovery field injects into"
            }
        })
    }
}

/// Which field [`parse_inject`] is parsing: whether a store cut belongs
/// there. A store cut always targets process 1's own store, so it is
/// never valid in the recovery field (process 2's injection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectField {
    First,
    Recovery,
}

/// Parse the `first` or `recovery` field of a labelled point id: `none`,
/// or `<kind>@<index>=<label>`. The old `<kind>@<index>` form, with no
/// label, refuses; a store cut in the recovery field refuses too (a cut
/// is always process 1's).
fn parse_inject(s: &str, slot: InjectField) -> Result<(Inject, Option<OpLabel>), PointParseError> {
    if s == "none" {
        return Ok((Inject::None, None));
    }
    let (kind, rest) = s.split_once('@').ok_or(PointParseError::Malformed)?;
    if slot == InjectField::Recovery && matches!(kind, "store-before" | "store-after") {
        return Err(PointParseError::RecoveryStoreCut);
    }
    let (at, label) = rest.split_once('=').ok_or(PointParseError::Unlabelled)?;
    let at: u32 = at.parse().map_err(|_| PointParseError::Malformed)?;
    match kind {
        "crash" => {
            let label = LogKind::parse(label).ok_or(PointParseError::Malformed)?;
            Ok((Inject::LogCrash(at), Some(OpLabel::Log(label))))
        }
        "fail" => {
            let label = LogKind::parse(label).ok_or(PointParseError::Malformed)?;
            Ok((Inject::LogFail(at), Some(OpLabel::Log(label))))
        }
        "store-before" => {
            let label = StoreOp::parse(label).ok_or(PointParseError::Malformed)?;
            Ok((Inject::Store(at, Cut::Before), Some(OpLabel::Store(label))))
        }
        "store-after" => {
            let label = StoreOp::parse(label).ok_or(PointParseError::Malformed)?;
            Ok((Inject::Store(at, Cut::After), Some(OpLabel::Store(label))))
        }
        _ => Err(PointParseError::Malformed),
    }
}

/// Parse the `defer` field of a labelled point id: `none`, or
/// `<index>=<label>`. The old, unlabelled `<index>` form refuses.
fn parse_defer(s: &str) -> Result<(Option<u32>, Option<OpLabel>), PointParseError> {
    if s == "none" {
        return Ok((None, None));
    }
    let (at, label) = s.split_once('=').ok_or(PointParseError::Unlabelled)?;
    let at: u32 = at.parse().map_err(|_| PointParseError::Malformed)?;
    let label = StoreOp::parse(label).ok_or(PointParseError::Malformed)?;
    Ok((Some(at), Some(OpLabel::Store(label))))
}

/// A required field of a `/`-separated point id.
fn field<'a>(parts: &mut impl Iterator<Item = &'a str>) -> Result<&'a str, PointParseError> {
    parts.next().ok_or(PointParseError::Malformed)
}

/// One point: the sweep's scheduler seed, where the deferred PUT is, the
/// first injection and the draw of the host crash after it, and an
/// injection into the first recovery and the draw of the crash after
/// that. The two draws are separate so a recovery's draws can be varied
/// without changing the crash that recovery recovers from.
///
/// **A point id is labelled.** Beside every index it uses (the deferred
/// PUT's, and an injection's), the id names the operation this build's
/// dry run found there. Re-run elsewhere, the same index can mean a
/// different operation; a label lets a fresh run recognise that and
/// refuse by name (`sweep.rs`'s `verify_labels`) instead of silently
/// running whatever is at that index now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct Point {
    pub(super) sched: u64,
    pub(super) defer_at: Option<u32>,
    pub(super) defer_label: Option<OpLabel>,
    pub(super) first: Inject,
    pub(super) first_label: Option<OpLabel>,
    pub(super) draw: u64,
    pub(super) recovery: Inject,
    pub(super) recovery_label: Option<OpLabel>,
    pub(super) recovery_draw: u64,
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let defer = match (self.defer_at, self.defer_label) {
            (None, _) => "none".to_owned(),
            (Some(k), Some(label)) => format!("{k}={label}"),
            (Some(k), None) => k.to_string(),
        };
        let first = labelled_inject(self.first, self.first_label);
        let recovery = labelled_inject(self.recovery, self.recovery_label);
        write!(
            f,
            "{}/{defer}/{first}/{}/{recovery}/{}",
            self.sched, self.draw, self.recovery_draw
        )
    }
}

/// `inject` with `label` appended, when there is one: what a labelled
/// point id shows for its first or recovery field.
fn labelled_inject(inject: Inject, label: Option<OpLabel>) -> String {
    label.map_or_else(|| inject.to_string(), |label| format!("{inject}={label}"))
}

impl Point {
    /// The point a labelled id names: the inverse of [`Display`]. Every
    /// index the id uses must carry the label its dry run found there;
    /// the old, unlabelled form refuses with
    /// [`PointParseError::Unlabelled`] rather than being accepted as if
    /// it still named the same operation.
    pub(super) fn parse(s: &str) -> Result<Self, PointParseError> {
        let mut parts = s.split('/');
        let sched = field(&mut parts)?
            .parse()
            .map_err(|_| PointParseError::Malformed)?;
        let (defer_at, defer_label) = parse_defer(field(&mut parts)?)?;
        let (first, first_label) = parse_inject(field(&mut parts)?, InjectField::First)?;
        let draw = field(&mut parts)?
            .parse()
            .map_err(|_| PointParseError::Malformed)?;
        let (recovery, recovery_label) = parse_inject(field(&mut parts)?, InjectField::Recovery)?;
        let recovery_draw = field(&mut parts)?
            .parse()
            .map_err(|_| PointParseError::Malformed)?;
        if parts.next().is_some() {
            return Err(PointParseError::Malformed);
        }
        Ok(Self {
            sched,
            defer_at,
            defer_label,
            first,
            first_label,
            draw,
            recovery,
            recovery_label,
            recovery_draw,
        })
    }

    /// The scheduler seed of process `process`.
    fn seed(&self, process: u32) -> u64 {
        if process == 1 {
            return self.sched;
        }
        let first = match self.first {
            Inject::None => 0,
            Inject::LogCrash(s) => u64::from(s),
            Inject::LogFail(s) => (1 << 32) | u64::from(s),
            Inject::Store(k, Cut::Before) => (2 << 32) | u64::from(k),
            Inject::Store(k, Cut::After) => (3 << 32) | u64::from(k),
        };
        self.sched
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(first.wrapping_mul(0xBF58_476D_1CE4_E5B9))
            .wrapping_add(self.draw.wrapping_mul(0x94D0_49BB_1331_11EB))
            .wrapping_add(u64::from(process))
    }
}

/// How a same-boot restart answered, against what the table expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Restart {
    /// The process that ended.
    pub(super) process: u32,
    /// What the marker table says for the state the restart found.
    pub(super) expected: Table,
    /// Whether the start was admitted.
    pub(super) admitted: bool,
    /// Marker renames the ended process made (0, 1 or 2).
    pub(super) renames: usize,
    /// The violations the fake recorded during the restart itself.
    pub(super) violations: Vec<LogViolation>,
}

/// Spec §6.2's marker table, the harness's own copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Table {
    Admit,
    RunningInThisBoot,
    StateDirectoryOccupied,
    Malformed,
}

pub(super) fn table(read: &MarkerRead, boot_id: u8) -> Table {
    match read {
        MarkerRead::Present(bytes) => match decode_marker(bytes) {
            Err(_) => Table::Malformed,
            Ok(RunMarker::Running(running)) if running == boot(boot_id) => Table::RunningInThisBoot,
            Ok(_) => Table::Admit,
        },
        MarkerRead::Missing {
            state_dir: StateDirectory::Occupied,
        } => Table::StateDirectoryOccupied,
        MarkerRead::Missing { .. } => Table::Admit,
    }
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum End {
    /// The script finished and the engine stopped cleanly.
    Clean,
    /// A start under a new boot refused by the table: the first marker
    /// write left an orphaned temporary, and only an operator unfence
    /// (through the local lifecycle verb) would admit a start.
    SafeRefusal,
}

/// Everything the oracle reads of one run.
pub(super) struct Run {
    pub(super) point: Point,
    pub(super) sim: Sim,
    pub(super) log: Arc<SimDecisionLog>,
    pub(super) timeline: Vec<(u32, Ev)>,
    /// Each host crash: the process it ended, and what it drew.
    pub(super) crashes: Vec<(u32, CrashReport)>,
    pub(super) restarts: Vec<Restart>,
    pub(super) end: End,
    pub(super) script: Script,
    pub(super) roots: Roots,
    /// How many processes the run had.
    pub(super) processes: u32,
    /// How many store operations each process's engine issued.
    pub(super) store_ops: Vec<u32>,
    /// Each process's store operations, as it claimed their indices.
    pub(super) claims: Vec<Vec<OpClaim>>,
    /// The global log step each process began at.
    pub(super) first_steps: Vec<u32>,
    /// The global log step count when each process ended.
    pub(super) last_steps: Vec<u32>,
    /// What each host crash left: the medium's files, the client's and
    /// the hooks' progress, and the store's roots, as one string. Two
    /// crashes that leave the same state recover the same way but for
    /// the schedule.
    pub(super) crash_states: Vec<String>,
}

/// The most processes a run has: the first, the first recovery, and the
/// recovery after a crash inside it.
const MAX_PROCESSES: u32 = 3;

/// The random stream every draw of a run takes its seed from.
const DRAW_STREAM: u64 = 0xD4A7;

/// The simulator node of process `process`'s store, and of a restart's.
const fn store_node(process: u32, restart: bool) -> u32 {
    if restart { 100 + process } else { process }
}

/// What the processes of one run share: the world, and what the oracle
/// will read of it.
struct Runner {
    point: Point,
    sim: Sim,
    log: Arc<SimDecisionLog>,
    timeline: Arc<Timeline>,
    roots: Roots,
    hooks: Arc<Mutex<Hooks>>,
    script: Arc<Mutex<Script>>,
    oracle: Arc<SimStore>,
    crashes: Vec<(u32, CrashReport)>,
    restarts: Vec<Restart>,
    store_ops: Vec<u32>,
    claims: Vec<Vec<OpClaim>>,
    first_steps: Vec<u32>,
    last_steps: Vec<u32>,
    crash_states: Vec<String>,
}

/// How one process ended.
enum ProcessEnd {
    /// The script finished and the engine stopped unfenced.
    Clean,
    /// Killed, or fenced: the two restarts follow.
    Down,
    /// A new boot's start refused by the table.
    SafeRefusal,
}

impl Runner {
    fn new(point: Point) -> Self {
        let sim = Sim::new();
        let mut log_faults = LogFaults::none();
        for inject in [point.first, point.recovery] {
            log_faults = match inject {
                Inject::LogCrash(s) => log_faults.with(LogFault::CrashAt(s)),
                Inject::LogFail(s) => log_faults.with(LogFault::FailSync { at: s }),
                Inject::None | Inject::Store(..) => log_faults,
            };
        }
        let log = Arc::new(sim.decision_log(0, log_faults));
        let roots = Roots::new();
        let hooks = Arc::new(Mutex::new(roots.hooks()));
        let oracle = Arc::new(sim.oracle());
        Self {
            point,
            sim,
            log,
            timeline: Timeline::new(),
            roots,
            hooks,
            script: Arc::new(Mutex::new(Script::default())),
            oracle,
            crashes: Vec::new(),
            restarts: Vec::new(),
            store_ops: Vec::new(),
            claims: Vec::new(),
            first_steps: Vec::new(),
            last_steps: Vec::new(),
            crash_states: Vec::new(),
        }
    }

    /// Run process `process` (under boot `process`) to its end.
    fn process(&mut self, process: u32) -> ProcessEnd {
        let point = self.point;
        self.timeline.start(process);
        self.first_steps.push(self.log.steps());
        let boot_id = u8::try_from(process).unwrap();
        let kill = Kill::new();
        let faults = match (process, point.defer_at) {
            (1, Some(at)) => Faults::just(Fault::DeferPut {
                at,
                release_after: 3,
            }),
            _ => Faults::none(),
        };
        let cut = match (process, point.first) {
            (1, Inject::Store(k, cut)) => Some((k, cut)),
            _ => None,
        };
        let store = SweepStore::new(
            self.sim.node(store_node(process, false), faults),
            self.sim.admin(),
            &kill,
            &self.timeline,
            &self.hooks,
            cut,
        );
        let ops = store.counter();
        let claims = store.claims();
        let parts = AuthorityParts {
            admission: crate::Admission::chain_fixture(),
            log: SweepLog::new(&self.log, &kill, &self.timeline),
            store,
            clock: FixedClock,
            rng: rng(point.seed(process)),
            // Each simulated process lifetime draws its own stream, keyed
            // by the point's replay seed and the process's index, so the
            // printed point id fixes every epoch the run draws.
            secure_random: SeededSecureRandom::for_incarnation(point.sched, process),
            pause: YieldPause,
        };
        let volumes = configs(&[a(), b()]);
        let started = block(Mortal::new(&kill, async move {
            start(parts, boot(boot_id), volumes).await
        }));
        let fenced = match started {
            None => false,
            Some(Err(StartRefused::Fenced(_))) => true,
            Some(Err(refused)) => {
                // Only a new boot's start over an orphaned marker
                // temporary refuses by the table (the restart checks
                // every other refusal).
                assert!(
                    process > 1 && refused == StartRefused::StateDirectoryOccupied,
                    "{point}: process {process} refused: {refused:?}"
                );
                self.store_ops.push(ops.load(Ordering::SeqCst));
                self.claims.push(claims.lock().unwrap().clone());
                self.last_steps.push(self.log.steps());
                return ProcessEnd::SafeRefusal;
            }
            Some(Ok((handle, driver))) => {
                handle
                    .inner
                    .shared
                    .replies
                    .set(observer(&kill, &self.timeline));
                let client = Client {
                    roots: self.roots.clone(),
                    script: Arc::clone(&self.script),
                    hooks: Arc::clone(&self.hooks),
                    oracle: Arc::clone(&self.oracle),
                    admin: self.sim.admin(),
                    timeline: Arc::clone(&self.timeline),
                };
                let tasks: Vec<Task<Option<Option<RunEnd>>>> = vec![
                    Box::pin(Mortal::new(&kill, async move { Some(driver.run().await) })),
                    Box::pin(Mortal::new(&kill, async move {
                        client.run(handle).await;
                        None
                    })),
                ];
                let ends = Scheduler::new(point.seed(process)).run(tasks);
                matches!(ends.first(), Some(Some(Some(RunEnd::Fenced(_)))))
            }
        };
        self.store_ops.push(ops.load(Ordering::SeqCst));
        self.claims.push(claims.lock().unwrap().clone());
        self.last_steps.push(self.log.steps());
        if kill.is_dead() || fenced {
            ProcessEnd::Down
        } else {
            ProcessEnd::Clean
        }
    }

    /// After a kill or a fence: the same-boot restart, then the host
    /// crash under the process's draw.
    fn restart_and_crash(&mut self, process: u32) {
        let boot_id = u8::try_from(process).unwrap();
        self.restarts
            .push(same_boot_restart(&self.sim, &self.log, process, boot_id));
        let draw = if process == 1 {
            self.point.draw
        } else {
            self.point.recovery_draw
        };
        let mut draws = SimRng::seeded(
            draw.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_5A5A_C3C3_3C3C,
            DRAW_STREAM.wrapping_add(u64::from(process)),
        );
        let report = self.log.crash_host(&mut draws);
        self.crash_states
            .push(state_after_crash(&self.sim, &self.script, &self.hooks));
        self.crashes.push((process, report));
    }
}

/// Run `point` to its end.
///
/// # Panics
/// If a run needs more processes than it can have: the injections are
/// two, and a third process always runs to its end or refuses.
pub(super) fn run(point: Point) -> Run {
    let mut runner = Runner::new(point);
    let mut process = 1;
    let end = loop {
        assert!(process <= MAX_PROCESSES, "{point}: a run with no end");
        match runner.process(process) {
            ProcessEnd::Clean => break End::Clean,
            ProcessEnd::SafeRefusal => break End::SafeRefusal,
            ProcessEnd::Down => runner.restart_and_crash(process),
        }
        process += 1;
    };
    let script = std::mem::take(&mut *runner.script.lock().unwrap());
    Run {
        point,
        sim: runner.sim,
        log: runner.log,
        timeline: runner.timeline.events(),
        crashes: runner.crashes,
        restarts: runner.restarts,
        end,
        script,
        roots: runner.roots,
        processes: process,
        store_ops: runner.store_ops,
        claims: runner.claims,
        first_steps: runner.first_steps,
        last_steps: runner.last_steps,
        crash_states: runner.crash_states,
    }
}

/// The state a host crash just left (see [`Run::crash_states`]).
fn state_after_crash(sim: &Sim, script: &Arc<Mutex<Script>>, hooks: &Arc<Mutex<Hooks>>) -> String {
    use granary_core::rootstore::RootStore as _;
    use std::fmt::Write as _;
    let trace = sim.trace();
    let entries = trace.entries();
    let since = entries
        .iter()
        .rposition(|e| matches!(e.op, Op::Log(LogOp::Crash { .. })))
        .unwrap_or(0);
    let mut state = String::new();
    for entry in &entries[since..] {
        if let Op::Log(op @ (LogOp::File { .. } | LogOp::StateDir { .. })) = &entry.op {
            let _ = writeln!(state, "{op}");
        }
    }
    let released = entries
        .iter()
        .filter(|e| matches!(e.op, Op::ReleaseRoot { .. }))
        .count();
    // A deferred PUT the store holds is state too: it lands after a
    // count of later store operations, so how many have passed since it
    // was held is part of what the crash left.
    let deferred = entries.iter().rposition(|e| {
        matches!(e.op, Op::PutRoot { .. })
            && e.outcome == Outcome::Failed(granary_sim::trace::TraceError::Deferred)
    });
    let held = match deferred {
        Some(at) if released == 0 => entries[at + 1..]
            .iter()
            .filter(|e| {
                e.node != Sim::ORACLE_NODE
                    && e.node != Sim::ADMIN_NODE
                    && matches!(
                        e.op,
                        Op::PutRoot { .. }
                            | Op::GetRoot { .. }
                            | Op::MaxSeq { .. }
                            | Op::ReadHint { .. }
                            | Op::WriteHint { .. }
                    )
            })
            .count()
            .to_string(),
        Some(_) => "released".to_owned(),
        None => "none".to_owned(),
    };
    {
        let script = script.lock().unwrap();
        let _ = writeln!(
            state,
            "ahead={} stale={} removed={:?} created={:?} released={released} held={held}",
            script.ahead_probed, script.stale_probed, script.removed, script.created
        );
    }
    let _ = writeln!(state, "{:?}", hooks.lock().unwrap());
    let oracle = sim.oracle();
    for volume in [a(), b()] {
        for seq in 1..=6 {
            let name = volume.as_str().to_owned();
            let oracle = &oracle;
            let got = super::oracle::block_ref(async move { oracle.get_root(&name, seq).await });
            if let Ok(Some(bytes)) = got {
                let _ = writeln!(
                    state,
                    "{}/{seq}={:?}",
                    volume.as_str(),
                    granary_core::hash::GrainId::of(&bytes)
                );
            }
        }
    }
    state
}

/// The marker renames the process that just ended made: the trace since
/// the last restart or host crash.
fn marker_renames(trace: &Trace) -> usize {
    let entries = trace.entries();
    let since = entries
        .iter()
        .rposition(|e| matches!(e.op, Op::Log(LogOp::Restart | LogOp::Crash { .. })))
        .map_or(0, |i| i + 1);
    entries[since..]
        .iter()
        .filter(|e| {
            matches!(&e.op, Op::Log(LogOp::Rename { to, .. }) if *to == LogPath::Marker)
                && e.outcome == Outcome::Ok
        })
        .count()
}

/// The first restart after a crash or a fence: the same boot. Its answer
/// must be the table's for the state it finds; an admitted start is
/// dropped unrun.
fn same_boot_restart(sim: &Sim, log: &Arc<SimDecisionLog>, process: u32, boot_id: u8) -> Restart {
    let renames = marker_renames(&sim.trace());
    let violations_before = log.violations().len();
    log.restart_process();
    let reader = Arc::clone(log);
    let read = block(async move { reader.read_marker().await }).unwrap();
    let expected = table(&read, boot_id);
    let kill = Kill::new();
    let timeline = Timeline::new();
    let hooks = Arc::new(Mutex::new(super::harness::Hooks::default()));
    let store = SweepStore::new(
        sim.node(store_node(process, true), Faults::none()),
        sim.admin(),
        &kill,
        &timeline,
        &hooks,
        None,
    );
    let store_ops = store.counter();
    let parts = AuthorityParts {
        admission: crate::Admission::chain_fixture(),
        log: SweepLog::new(log, &kill, &timeline),
        store,
        clock: FixedClock,
        rng: rng(0),
        // Dropped unrun, so it never draws; its own stream all the same.
        secure_random: SeededSecureRandom::for_incarnation(0, process),
        pause: YieldPause,
    };
    let volumes = configs(&[a(), b()]);
    let steps_before = log.steps();
    let started = block(async move { start(parts, boot(boot_id), volumes).await });
    let steps_taken = log.steps() - steps_before;
    let admitted = started.is_ok();
    let refused_as = started.err();
    match expected {
        Table::Admit => assert!(admitted, "a same-boot restart refused: {refused_as:?}"),
        Table::RunningInThisBoot => {
            assert_eq!(refused_as, Some(StartRefused::RunningInThisBoot));
        }
        Table::StateDirectoryOccupied => {
            assert_eq!(refused_as, Some(StartRefused::StateDirectoryOccupied));
        }
        Table::Malformed => assert!(
            matches!(refused_as, Some(StartRefused::MarkerMalformed(_))),
            "{refused_as:?}"
        ),
    }
    // A refused start reads the marker and nothing else: one step, and
    // the marker's bytes as they were.
    if !admitted {
        assert_eq!(log.violations().len(), violations_before);
        assert_eq!(
            steps_taken, 1,
            "a refused same-boot start took {steps_taken} steps"
        );
        assert_eq!(
            store_ops.load(Ordering::SeqCst),
            0,
            "a refused same-boot start touched the store"
        );
        let reader = Arc::clone(log);
        let after = block(async move { reader.read_marker().await }).unwrap();
        assert_eq!(after, read, "a refused same-boot start changed the marker");
    }
    Restart {
        process,
        expected,
        admitted,
        renames,
        violations: log.violations()[violations_before..].to_vec(),
    }
}

/// `volume`'s whole log as the current process reads it, or `None`.
///
/// # Errors
/// The read's error.
pub(super) fn read_log(
    log: &Arc<SimDecisionLog>,
    volume: &VolumeName,
) -> Result<Option<Vec<u8>>, granary_core::decisionlog::LogIoError> {
    let log = Arc::clone(log);
    let volume = volume.clone();
    block(async move { log.read(&volume).await })
}
