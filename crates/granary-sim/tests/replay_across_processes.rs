// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The S2 meta-test, and it CROSSES A PROCESS BOUNDARY.
//!
//! One seed, two processes, one artifact: `sim-replay` runs the
//! two-publisher race at a seed and writes
//! [`granary_sim::trace::Trace::render`]'s bytes to stdout; this spawns
//! it twice and compares. Seeds with the top bit set run the same race
//! with one publisher's `put_root` deferred, its release point derived
//! from the seed, so the replayed seed space covers a held write landing
//! late as well as the plain race. A seed with bit 62 set selects the
//! scripted decision-log crash-and-recovery run instead, its fault, target
//! step and crash draws decoded from the seed's low bits; a seed with both
//! bits set is a usage error. A pinned sample of bit-62-clear seeds
//! renders the digests below.
//!
//! # Why a subprocess and not two runs in this one
//!
//! Within one process every ambient value a run could capture — the pid
//! above all — is CONSTANT, so an in-process comparison is green while
//! cross-process replay is broken. That is not
//! hypothetical: `writer_uuid` mixed `std::process::id()` into a signed
//! field until the writer identity replaced it.
//! Spawning the compiled binary through
//! `env!("CARGO_BIN_EXE_…")` is the determinism fixture's pattern
//! (`granary-cli/tests/determinism_fixture.rs`) and the only shape
//! that varies the pid at all.
//!
//! # The three ways this test could be green while proving nothing
//!
//! Each has an assertion of its own below, because each has been a real
//! defect somewhere in this project:
//!
//! 1. **Empty against empty.** Two vacuous artifacts compare equal
//!    forever, whatever the code does.
//!    [`granary_sim::trace::Trace::is_empty`] exists for this and
//!    `the_artifact_is_neither_empty_nor_addressless` is the guard.
//! 2. **An artifact with no CONTENT ADDRESS in it.** `writer_uuid`
//!    affects exactly one thing — the bytes of the signed root — so a
//!    log of operation kind + volume + seq renders byte-identically with
//!    and without an ambient pid in the preimage, so the negative proof
//!    that the pid is gone would pass while proving nothing
//!    (`granary_sim::trace`'s rule 1). A `put-root` line
//!    and its full 64-hex address are asserted, not merely
//!    non-emptiness.
//! 3. **A binary that died before printing**, or that ignores its seed.
//!    A crash produces two identical empty outputs; a constant program
//!    produces two identical non-empty ones. Exit status is asserted for
//!    the first, and a seed that schedules differently for the second.

use std::ffi::OsStr;
use std::process::{Command, Output};

/// The compiled runner. `env!` resolves at COMPILE time, so cargo has
/// already built the binary by the time this test runs — there is no
/// window in which the path names something stale.
const RUNNER: &str = env!("CARGO_BIN_EXE_sim-replay");

/// A seed whose schedule contends: both publishers attempt the same seq,
/// so the artifact carries two `put-root` lines at one seq with distinct
/// addresses. Measured, not assumed — `the_pinned_seeds_are_still_the`
/// `_ones_this_test_needs` re-measures it on every run.
const SEED: u64 = 3;

/// A seed measured to schedule DIFFERENTLY from [`SEED`]. Two seeds can
/// legitimately produce one schedule, so this is a measured pin rather
/// than an arbitrary second number.
const OTHER_SEED: u64 = 0;

/// A seed in the DEFERRED half of the runner's seed space
/// ([`granary_sim::scenario::DEFERRED_SEEDS`] set): node 0's `put_root`
/// is held and released later, at a point derived from the seed.
/// Measured to release it as LANDED — the held write reaches the store
/// before node 1's `put_root`, which is then refused.
const DEFERRED_SEED: u64 = (1 << 63) | 3;

/// A deferred seed measured to release its held write as REFUSED: node 1
/// claims the seq first, and the late write finds it taken. Pinned
/// beside [`DEFERRED_SEED`] so both fates of a held write are replayed
/// across a process boundary, not only the one that lands — and at a
/// different release point (`9 % 4 = 1` later operations against
/// `3 % 4 = 3`), so the pair varies the release as well as the schedule.
const DEFERRED_REFUSED_SEED: u64 = (1 << 63) | 9;

/// Spawn the runner and collect its whole output.
fn run<S: AsRef<OsStr>>(args: &[S]) -> Output {
    Command::new(RUNNER)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {RUNNER}: {e}"))
}

/// The runner's stdout, with its exit status asserted successful — a
/// binary that dies before printing yields an empty stdout that would
/// compare equal to another empty stdout.
fn artifact(seed: u64) -> String {
    let seed = seed.to_string();
    let out = run(&[&seed]);
    assert!(
        out.status.success(),
        "sim-replay {seed} exited {:?}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap_or_else(|e| panic!("the artifact must be UTF-8, and is not: {e}"))
}

/// Every `put-root` attempt the artifact carries: the seq it aimed at,
/// the content address of the bytes it tried to write, and whether the
/// write WON the seq.
///
/// The whole 64 hex digits or nothing: a truncated address would let two
/// distinct roots render the same, which is the failure this test's
/// signal depends on NOT happening.
///
/// **The seq travels with the address, and it has to.** Two attempts
/// carrying distinct addresses are not a contended race unless both
/// aimed at the SAME seq — several seeds schedule the publishers so that
/// one takes seq 1 and the other seq 2, which renders exactly two
/// `put-root` lines with two distinct addresses and no contention at
/// all. An address-only reading calls that schedule contended.
///
/// **`won` counts a landed release as a winning write.** A HELD
/// `put_root` renders `failed(deferred)`, and if its `release-root` line
/// (same node, seq and address) later ends `-> ok`, the store holds its
/// bytes at that seq exactly as if the PUT had succeeded.
fn put_root_attempts(artifact: &str) -> Vec<(&str, &str, bool)> {
    /// `(node, seq, addr, outcome)` of one root-writing line, the
    /// address kept only when it is the whole 64 hex digits.
    fn fields(line: &str) -> Option<(&str, &str, &str, &str)> {
        let node = line.split(' ').next()?;
        let seq = line.split(" seq=").nth(1)?.split(' ').next()?;
        let addr = line.split(" addr=").nth(1)?.split(' ').next()?;
        let outcome = line.split(" -> ").nth(1)?;
        let whole = addr.len() == 64
            && addr
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
        whole.then_some((node, seq, addr, outcome))
    }
    let landed: Vec<(&str, &str, &str)> = artifact
        .lines()
        .filter(|line| line.contains(" release-root "))
        .filter_map(fields)
        .filter(|(.., outcome)| *outcome == "ok")
        .map(|(node, seq, addr, _)| (node, seq, addr))
        .collect();
    artifact
        .lines()
        .filter(|line| line.contains(" put-root "))
        .filter_map(fields)
        .map(|(node, seq, addr, outcome)| {
            let won = outcome == "ok"
                || (outcome == "failed(deferred)" && landed.contains(&(node, seq, addr)));
            (seq, addr, won)
        })
        .collect()
}

/// **The property.** One seed, two processes, byte-identical artifacts.
///
/// *Breaks if:* anything ambient to the process re-enters a hashed or
/// signed value the artifact records — which is precisely what
/// `std::process::id()` in `writer_uuid`'s preimage was. Re-introducing
/// it turns exactly this assertion red, and nothing else in the sim
/// suite: it reaches only the two `put-root` lines.
#[test]
fn the_same_seed_renders_the_same_artifact_in_two_processes() {
    let first = artifact(SEED);
    let second = artifact(SEED);
    // Compared as whole strings: a length-only or prefix-only comparison
    // would miss a divergence in the last address on the last line.
    assert_eq!(
        first, second,
        "two processes at seed {SEED} rendered DIFFERENT artifacts, so the run is not \
         reproducible across a process boundary"
    );
}

/// **The anti-vacuity guard, and it is the reason this file is not a
/// tautology.** Two empty artifacts are equal, and so are two artifacts
/// that record no content address — and an artifact with no address
/// would be identical with and without an ambient pid in the root
/// preimage, so the test above would stay green over exactly the defect
/// it exists to catch.
///
/// *Breaks if:* the runner stops printing, or the trace stops recording
/// what a PUT wrote.
#[test]
fn the_artifact_is_neither_empty_nor_addressless() {
    let rendered = artifact(SEED);
    assert!(
        !rendered.is_empty(),
        "the artifact is EMPTY, so the cross-process comparison compares nothing"
    );
    let addresses = put_root_attempts(&rendered);
    assert!(
        !addresses.is_empty(),
        "the artifact records no put-root content address, so it would render identically \
         with and without an ambient value in the signed root's preimage: {rendered}"
    );
}

/// The runner is a function OF ITS SEED. A program that ignored its
/// argument and printed a constant would satisfy every assertion above,
/// so one pair of seeds that schedule differently is pinned here.
///
/// This also re-measures the pins the file rests on: [`SEED`] must still
/// CONTEND (two `put-root` attempts, distinct addresses, one seq) or the
/// artifact stops being the interesting one.
#[test]
fn the_pinned_seeds_are_still_the_ones_this_test_needs() {
    let rendered = artifact(SEED);
    let contended = put_root_attempts(&rendered);
    assert_eq!(
        contended.len(),
        2,
        "seed {SEED} no longer produces two put-root attempts, so the artifact it renders is \
         not the contended race this file pins"
    );
    let seqs: Vec<&str> = contended.iter().map(|(seq, ..)| *seq).collect();
    assert_eq!(
        seqs.first(),
        seqs.last(),
        "seed {SEED} no longer CONTENDS: the two publishers put roots at seqs {seqs:?}, so one \
         of them observed the other's root and moved on rather than racing it. Two distinct \
         addresses at two DIFFERENT seqs is the uncontended schedule"
    );
    let addrs: Vec<&str> = contended.iter().map(|(_, addr, _)| *addr).collect();
    assert_ne!(
        addrs.first(),
        addrs.last(),
        "the two publishers attempted IDENTICAL root bytes at seed {SEED} — they share a \
         writer identity, and a cross-process divergence in one of them could hide in the \
         other"
    );
    assert_ne!(
        artifact(SEED),
        artifact(OTHER_SEED),
        "seeds {SEED} and {OTHER_SEED} render the same artifact, so this test cannot tell a \
         seeded run from a constant one"
    );
}

/// Argv is untrusted input: every refusal is an exit status and a
/// message, never a panic. A panicking runner would still exit non-zero,
/// so the stderr check is what separates "refused" from "crashed".
#[test]
fn a_bad_argument_is_refused_without_panicking() {
    for args in [
        vec![],
        vec!["1", "2"],
        vec![""],
        vec!["-1"],
        vec!["18446744073709551616"], // u64::MAX + 1
        vec!["0x10"],
        vec!["1 "],
        vec!["٣"], // ARABIC-INDIC THREE: `char::is_numeric`, not a digit
    ] {
        assert_refused(&run(&args), &format!("{args:?}"));
    }
}

/// The argument [`std::env::args`] would PANIC on, and the reason the
/// runner reads [`std::env::args_os`] instead: bytes that are not UTF-8
/// at all. Unix-only because that is where an argument is bytes rather
/// than UTF-16 — and where a non-UTF-8 argv can be constructed at all.
#[cfg(unix)]
#[test]
fn a_non_utf8_argument_is_refused_without_panicking() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    // A lone 0x80 continuation byte: valid in an OS string, never valid
    // UTF-8.
    let arg = OsString::from_vec(vec![0x80]);
    assert_refused(&run(&[arg]), "a lone 0x80 byte");
}

/// A refusal is an exit status plus a message that names the call — not
/// a panic, and never a partial artifact on stdout.
fn assert_refused(out: &Output, what: &str) {
    assert!(
        !out.status.success(),
        "sim-replay {what} exited SUCCESSFULLY on an argument it cannot honour"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panicked"),
        "sim-replay {what} PANICKED rather than refusing: {stderr}"
    );
    assert!(
        stderr.contains("usage: sim-replay"),
        "sim-replay {what} refused without saying how to call it: {stderr}"
    );
    assert!(
        out.stdout.is_empty(),
        "sim-replay {what} wrote to stdout on a refused argument"
    );
}

/// The held write's two lines — its `put-root` recorded as
/// `failed(deferred)` and its `release-root` — each with its seq and
/// full 64-hex address, as `(word, seq, addr, outcome)`.
fn deferred_lines(artifact: &str) -> Vec<(&str, &str, &str, &str)> {
    artifact
        .lines()
        .filter(|line| {
            line.contains(" release-root ")
                || (line.contains(" put-root ") && line.ends_with("-> failed(deferred)"))
        })
        .filter_map(|line| {
            let word = line.split(' ').nth(1)?;
            let seq = line.split(" seq=").nth(1)?.split(' ').next()?;
            let addr = line.split(" addr=").nth(1)?.split(' ').next()?;
            let outcome = line.split(" -> ").nth(1)?;
            Some((word, seq, addr, outcome))
        })
        .filter(|(_, _, addr, _)| {
            addr.len() == 64
                && addr
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        })
        .collect()
}

/// **The property, for a run with a deferred PUT.** The release point is
/// a count of store operations under a seeded schedule, so it must replay
/// exactly: same seed, two processes, byte-identical artifacts — for a
/// held write that lands and for one that is refused.
///
/// *Breaks if:* the release point depends on anything but the fault
/// schedule and the seed — a timer, an ambient counter, iteration order
/// over an unordered collection of held writes.
#[test]
fn a_deferred_put_renders_the_same_artifact_in_two_processes() {
    for seed in [DEFERRED_SEED, DEFERRED_REFUSED_SEED] {
        let first = artifact(seed);
        let second = artifact(seed);
        assert_eq!(
            first, second,
            "two processes at deferred seed {seed} rendered DIFFERENT artifacts"
        );
    }
}

/// The anti-vacuity guard for the deferred half, and the re-measurement
/// of its two pins. Each pinned seed's artifact must carry the held
/// write AND its release, at one seq and one address — an artifact with
/// no release line would compare equal across processes while replaying
/// nothing about WHEN the write landed — and the two pins must reach the
/// two different fates.
#[test]
fn the_deferred_seeds_carry_the_held_write_and_its_fate() {
    let fate_of = |seed: u64| -> String {
        let rendered = artifact(seed);
        let lines = deferred_lines(&rendered);
        let words: Vec<&str> = lines.iter().map(|(w, ..)| *w).collect();
        assert_eq!(
            words,
            ["put-root", "release-root"],
            "deferred seed {seed} does not render one held put-root followed by its release: \
             {rendered}"
        );
        let keys: Vec<(&str, &str)> = lines
            .iter()
            .map(|(_, seq, addr, _)| (*seq, *addr))
            .collect();
        assert_eq!(
            keys.first(),
            keys.last(),
            "deferred seed {seed}: the release is not the held write's seq and address: {lines:?}"
        );
        lines
            .last()
            .map(|(.., outcome)| (*outcome).to_owned())
            .unwrap_or_default()
    };
    // Whichever fate, each seq attempted has exactly ONE winning root
    // write — a landed release counts as one, so a landed held write
    // beside a successful PUT at the same seq would read as two.
    for seed in [DEFERRED_SEED, DEFERRED_REFUSED_SEED] {
        let rendered = artifact(seed);
        let attempts = put_root_attempts(&rendered);
        let mut seqs: Vec<&str> = attempts.iter().map(|(seq, ..)| *seq).collect();
        seqs.sort_unstable();
        seqs.dedup();
        for seq in seqs {
            let winners = attempts
                .iter()
                .filter(|(s, _, won)| *s == seq && *won)
                .count();
            assert_eq!(
                winners, 1,
                "deferred seed {seed}: seq {seq} has {winners} winning root writes: {attempts:?}"
            );
        }
    }
    assert_eq!(
        (fate_of(DEFERRED_SEED), fate_of(DEFERRED_REFUSED_SEED)),
        ("ok".to_owned(), "failed(already-exists)".to_owned()),
        "the pinned deferred seeds do not reach one landed and one refused release"
    );
    assert_ne!(
        artifact(DEFERRED_SEED),
        artifact(SEED),
        "the deferred bit changes nothing: seed {DEFERRED_SEED} renders the plain race"
    );
}

/// The deferral reaches node 0's `put_root` at seeds FAR outside the
/// swept range too: the deferred index is read off the fault-free race
/// at the same seed, so no seed can aim it at another operation — and a
/// deferred run that held nothing would be refused, not printed. Two
/// seeds well past any sweep, each rendering its held write and its
/// release.
#[test]
fn a_deferred_seed_far_outside_the_sweep_still_holds_its_put_root() {
    for inner in [1_000_003_u64, (1 << 40) + 17] {
        let seed = (1 << 63) | inner;
        let rendered = artifact(seed);
        let words: Vec<&str> = deferred_lines(&rendered).iter().map(|(w, ..)| *w).collect();
        assert_eq!(
            words,
            ["put-root", "release-root"],
            "deferred seed {seed} did not hold and release its put_root: {rendered}"
        );
    }
}

// ------------------------------------------------- the decision-log seeds

/// The selector bit of the decision-log seed space
/// ([`granary_sim::scenario::DECISION_LOG_SEEDS`]).
const LOG: u64 = granary_sim::scenario::DECISION_LOG_SEEDS;

/// The selector bit of the deferred seed space.
const DEFERRED: u64 = granary_sim::scenario::DEFERRED_SEEDS;

/// What an artifact of a decision-log run says happened, read off its
/// lines and never assumed from the seed: the guards below rest on it.
#[derive(Debug, Default)]
struct LogFacts {
    /// The `row=` of every `log-row` line.
    rows: Vec<String>,
    /// The `row=` of every `log-row` line the first host crash drew.
    first_crash_rows: Vec<String>,
    /// Syncs that returned `failed(sync-failed)`.
    failed_syncs: usize,
    /// A host crash cut the first process: a step was refused as
    /// `failed(injected)` before the first `log-crash`.
    cut_first_process: bool,
    /// A truncation returned and the very next step, its sync, was
    /// refused by a crash.
    crash_between_truncate_and_sync: bool,
    /// The `kind=` of every `log-damage` line that flipped bytes.
    damage: Vec<String>,
    /// The `reason=` of every verdict that refused.
    refusals: Vec<String>,
    /// Verdicts that classified a log, and how many of them found a tail.
    logs: usize,
    tails: usize,
    /// Host crashes.
    crashes: usize,
    /// The `trunc=` of every `log-draw` line.
    truncations: Vec<String>,
    /// A `resync` call returned after a `survivor` row.
    resynced_survivor: bool,
}

fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.split(' ')
        .find_map(|word| word.strip_prefix(name))
        .and_then(|rest| rest.strip_prefix('='))
}

fn log_facts(artifact: &str) -> LogFacts {
    let mut facts = LogFacts::default();
    let mut survivor_seen = false;
    let mut truncated = false;
    for line in artifact.lines() {
        let outcome = line.split(" -> ").nth(1).unwrap_or_default();
        let word = line.split(' ').nth(1).unwrap_or_default();
        if !matches!(word, "log-call" | "log-crash") && outcome == "failed(injected)" {
            facts.cut_first_process |= facts.crashes == 0;
        }
        // Step lines follow one another; a call's line follows its steps.
        let step = matches!(
            word,
            "log-write"
                | "log-file-sync"
                | "log-dir-sync"
                | "log-create"
                | "log-mkdir"
                | "log-link"
                | "log-unlink"
                | "log-rename"
                | "log-truncate"
                | "log-read"
        );
        if step {
            facts.crash_between_truncate_and_sync |=
                truncated && word == "log-file-sync" && outcome == "failed(injected)";
            truncated = word == "log-truncate" && outcome == "ok";
        }
        match word {
            "log-row" => {
                let row = field(line, "row").unwrap_or_default();
                survivor_seen |= row == "survivor";
                facts.rows.push(row.to_owned());
                if facts.crashes == 1 {
                    facts.first_crash_rows.push(row.to_owned());
                }
            }
            "log-file-sync" | "log-dir-sync" if outcome == "failed(sync-failed)" => {
                facts.failed_syncs += 1;
            }
            "log-damage" if outcome == "ok" => {
                facts
                    .damage
                    .push(field(line, "kind").unwrap_or_default().to_owned());
            }
            "log-verdict" => match field(line, "result") {
                Some("refused") => facts
                    .refusals
                    .push(field(line, "reason").unwrap_or_default().to_owned()),
                Some("log") => {
                    facts.logs += 1;
                    facts.tails += usize::from(field(line, "tail") != Some("0"));
                }
                _ => {}
            },
            "log-crash" => facts.crashes += 1,
            "log-draw" => facts
                .truncations
                .push(field(line, "trunc").unwrap_or_default().to_owned()),
            "log-call" => {
                facts.resynced_survivor |=
                    survivor_seen && field(line, "call") == Some("resync") && outcome == "ok";
            }
            _ => {}
        }
    }
    facts
}

/// One pinned decision-log seed: the outcome it is pinned for, what its
/// plan must decode to, and the artifact evidence that the run reached
/// that outcome.
struct LogPin {
    what: &'static str,
    seed: u64,
    kind: granary_sim::scenario::LogFaultKind,
    reached: fn(&LogFacts) -> bool,
}

fn has(rows: &[String], name: &str) -> bool {
    rows.iter().any(|r| r == name)
}

/// Every refusal the pinned run made was for damaged committed history.
fn only_damaged_history(facts: &LogFacts) -> bool {
    !facts.refusals.is_empty() && facts.refusals.iter().all(|r| r == "damaged-history")
}

fn log_pins() -> Vec<LogPin> {
    let mut pins = row_pins();
    pins.extend(fault_pins());
    pins
}

/// The `ROWS` crash-outcome rows (`decision_log_seeds.rs`): under a failed
/// sync, and through a host crash in the middle of the first process's
/// appends.
fn row_pins() -> Vec<LogPin> {
    use granary_sim::scenario::LogFaultKind::{FailSync, None};
    vec![
        LogPin {
            what: "row 1: record absent, under a failed sync",
            seed: LOG + 128,
            kind: FailSync,
            reached: |f| has(&f.rows, "record-absent") && f.failed_syncs == 1,
        },
        LogPin {
            what: "row 2: record torn, under a failed sync",
            seed: LOG + 108,
            kind: FailSync,
            reached: |f| has(&f.rows, "record-torn") && f.failed_syncs == 1,
        },
        LogPin {
            what: "row 2: record whole but unsynced, under a failed sync",
            seed: LOG + 5,
            kind: FailSync,
            reached: |f| has(&f.rows, "record-whole-unsynced") && f.failed_syncs == 1,
        },
        LogPin {
            what: "row 3: record synced, mark absent or torn, under a failed sync",
            seed: LOG + 80,
            kind: FailSync,
            reached: |f| has(&f.rows, "mark-absent-or-torn") && f.tails > 0 && f.failed_syncs == 1,
        },
        LogPin {
            what: "row 4: committed and unacknowledged, adopted and re-synced, under a failed sync",
            seed: LOG + 160,
            kind: FailSync,
            reached: |f| has(&f.rows, "survivor") && f.resynced_survivor && f.failed_syncs == 1,
        },
        LogPin {
            what: "row 1 via a crash mid-append",
            seed: LOG + 66,
            kind: None,
            reached: |f| f.cut_first_process && has(&f.first_crash_rows, "record-absent"),
        },
        LogPin {
            what: "row 2 (torn) via a crash mid-append",
            seed: LOG + 109,
            kind: None,
            reached: |f| f.cut_first_process && has(&f.first_crash_rows, "record-torn"),
        },
        LogPin {
            what: "row 2 (whole, unsynced) via a crash mid-append",
            seed: LOG + 116,
            kind: None,
            reached: |f| f.cut_first_process && has(&f.first_crash_rows, "record-whole-unsynced"),
        },
        LogPin {
            what: "row 3 via a crash mid-append",
            seed: LOG + 3,
            kind: None,
            reached: |f| f.cut_first_process && has(&f.first_crash_rows, "mark-absent-or-torn"),
        },
        LogPin {
            what: "row 4 via a crash mid-append",
            seed: LOG + 53,
            kind: None,
            reached: |f| {
                f.cut_first_process && has(&f.first_crash_rows, "survivor") && f.resynced_survivor
            },
        },
    ]
}

/// One seed per fault, and the crashes inside recovery.
fn fault_pins() -> Vec<LogPin> {
    use granary_sim::scenario::LogFaultKind::{
        AtBoundTail, CorruptDetectable, ForeignTail, None, OtherEpochTail, OversizeTail,
        ResidualLoss, WrongSeqTail,
    };
    vec![
        LogPin {
            what: "no fault: an honest crash, never refused",
            seed: LOG + 6,
            kind: None,
            reached: |f| f.crashes >= 1 && f.refusals.is_empty() && f.logs > 0,
        },
        LogPin {
            what: "corrupt-detectable: damage fired, recovery refused",
            seed: LOG,
            kind: CorruptDetectable,
            reached: |f| f.damage == ["detectable"] && only_damaged_history(f),
        },
        LogPin {
            what: "residual loss from a mark, inside the tail bound: discarded",
            seed: LOG + 36,
            kind: ResidualLoss,
            reached: |f| f.damage == ["residual"] && f.refusals.is_empty() && f.tails > 0,
        },
        LogPin {
            what: "residual loss from a mark, beyond the tail bound: refused",
            seed: LOG + 12,
            kind: ResidualLoss,
            reached: |f| f.damage == ["residual"] && only_damaged_history(f),
        },
        LogPin {
            what: "residual loss from inside a record, inside RECORD_V1_MAX: discarded",
            seed: LOG + 62,
            kind: ResidualLoss,
            reached: |f| f.damage == ["residual-into-record"] && f.refusals.is_empty(),
        },
        LogPin {
            what: "a tail from inside a record beyond RECORD_V1_MAX: refused",
            seed: LOG + 18,
            kind: OversizeTail,
            reached: |f| f.damage == ["oversize"] && only_damaged_history(f),
        },
        LogPin {
            what: "a tail from inside a record at exactly RECORD_V1_MAX: discarded",
            seed: LOG + 19,
            kind: AtBoundTail,
            reached: |f| f.damage == ["at-bound"] && f.refusals.is_empty() && f.tails > 0,
        },
        LogPin {
            what: "the legal next record under the wrong sequence number: refused",
            seed: LOG + 28,
            kind: WrongSeqTail,
            reached: |f| f.damage == ["wrong-seq-record"] && only_damaged_history(f),
        },
        LogPin {
            what: "a whole record of this epoch that is not the legal next: refused",
            seed: LOG + 1,
            kind: ForeignTail,
            reached: |f| f.damage == ["foreign-record"] && only_damaged_history(f),
        },
        LogPin {
            what: "a whole record of another epoch that would be illegal here: discarded",
            seed: LOG + 10,
            kind: OtherEpochTail,
            reached: |f| f.damage == ["other-epoch-record"] && f.refusals.is_empty() && f.tails > 0,
        },
        LogPin {
            what: "a crash between a truncation and its sync that keeps the truncation",
            seed: LOG + 4,
            kind: AtBoundTail,
            reached: |f| {
                f.crash_between_truncate_and_sync
                    && f.crashes >= 2
                    && f.truncations.iter().any(|t| t == "kept")
            },
        },
        LogPin {
            what: "a crash between a truncation and its sync that undoes the truncation",
            seed: LOG + 38,
            kind: OtherEpochTail,
            reached: |f| {
                f.crash_between_truncate_and_sync
                    && f.crashes >= 2
                    && f.truncations.iter().any(|t| t == "undone")
            },
        },
    ]
}

/// Whether the pinned fault fired, read off the artifact and counting
/// only the fault's own entries: a failed sync is a sync that returned a
/// failure, and a crash's refused step is not one.
fn fired(kind: granary_sim::scenario::LogFaultKind, facts: &LogFacts) -> bool {
    use granary_sim::scenario::LogFaultKind::{
        AtBoundTail, CorruptDetectable, FailSync, ForeignTail, None, OtherEpochTail, OversizeTail,
        ResidualLoss, WrongSeqTail,
    };
    let damaged = |names: &[&str]| facts.damage.iter().any(|d| names.contains(&d.as_str()));
    match kind {
        None => true,
        FailSync => facts.failed_syncs > 0,
        CorruptDetectable => damaged(&["detectable"]),
        ResidualLoss => damaged(&["residual", "residual-into-record"]),
        OversizeTail => damaged(&["oversize"]),
        AtBoundTail => damaged(&["at-bound"]),
        ForeignTail => damaged(&["foreign-record"]),
        WrongSeqTail => damaged(&["wrong-seq-record"]),
        OtherEpochTail => damaged(&["other-epoch-record"]),
    }
}

/// **The re-measurement of every pin.** Each pinned seed must still
/// decode to the fault kind it is pinned under, that fault must have
/// fired in its artifact, and the artifact must show the outcome it is
/// pinned for. A pin that drifts (the script or the decoding changed)
/// fails here naming the outcome, instead of leaving a replay check that
/// replays something else.
#[test]
fn the_pinned_log_seeds_are_still_the_ones_this_test_needs() {
    for pin in log_pins() {
        let text = artifact(pin.seed);
        let facts = log_facts(&text);
        assert_eq!(
            granary_sim::scenario::LogPlan::decode(pin.seed).kind,
            pin.kind,
            "seed {} ({}) no longer decodes to {}",
            pin.seed,
            pin.what,
            pin.kind
        );
        assert!(
            fired(pin.kind, &facts),
            "seed {} ({}): the {} fault did not fire: {facts:?}",
            pin.seed,
            pin.what,
            pin.kind
        );
        assert!(
            (pin.reached)(&facts),
            "seed {} no longer reaches its outcome ({}): {facts:?}\n{text}",
            pin.seed,
            pin.what
        );
    }
}

/// **The property, for the decision-log space.** Every pinned seed,
/// two processes, byte-identical artifacts; and the artifact is a
/// decision-log one, not the race a seed without the bit would run.
#[test]
fn a_decision_log_seed_renders_the_same_artifact_in_two_processes() {
    for pin in log_pins() {
        let first = artifact(pin.seed);
        assert!(
            !first.is_empty(),
            "seed {} ({}): empty artifact",
            pin.seed,
            pin.what
        );
        assert!(
            first.contains(" log-crash ") && first.contains(" log-verdict "),
            "seed {} ({}): no crash and no verdict in the artifact",
            pin.seed,
            pin.what
        );
        assert!(
            !first.contains(" put-root "),
            "seed {}: a race artifact",
            pin.seed
        );
        assert_eq!(
            first,
            artifact(pin.seed),
            "two processes at decision-log seed {} ({}) rendered DIFFERENT artifacts",
            pin.seed,
            pin.what
        );
    }
}

/// The runner is a function of its seed in this space too: the pinned
/// seeds, which differ in kind, row and step, all render their own
/// artifact. (A seed a step away from a pin can render the same one: an
/// honest crash with nothing in flight draws nothing.)
#[test]
fn different_decision_log_seeds_render_different_artifacts() {
    let mut seen = std::collections::BTreeMap::new();
    for pin in log_pins() {
        if let Some(other) = seen.insert(artifact(pin.seed), pin.seed) {
            panic!(
                "decision-log seeds {other} and {} render the same artifact",
                pin.seed
            );
        }
    }
    assert_eq!(seen.len(), log_pins().len());
}

/// A seed far outside any sweep, with high payload bits set, runs too.
#[test]
fn a_decision_log_seed_far_outside_the_sweep_still_runs() {
    for inner in [1_000_003_u64, (1 << 40) + 17, (1 << 61) | 5] {
        let text = artifact(LOG | inner);
        assert!(text.contains(" log-verdict "), "seed {inner}: {text}");
    }
}

/// The two selector bits are exclusive. A seed with both is a usage
/// error: the usage text, a non-zero exit, nothing on stdout, no panic.
#[test]
fn a_seed_with_both_selector_bits_is_a_usage_error() {
    let both = DEFERRED | LOG;
    for seed in [both, both | 7, u64::MAX] {
        let out = run(&[seed.to_string()]);
        assert_refused(&out, &format!("seed {seed}"));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("both selector bits") && stderr.contains(&seed.to_string()),
            "sim-replay {seed} refused without naming the two bits and the seed: {stderr}"
        );
    }
    // Either bit alone is a seed space, not a usage error.
    assert!(run(&[LOG.to_string()]).status.success());
    assert!(run(&[DEFERRED.to_string()]).status.success());
}

// -------------------------------- bit-62-clear seeds render pinned digests

/// The BLAKE3 digest of an artifact, as 64 hex digits.
fn digest(artifact: &str) -> String {
    granary_core::hash::GrainId::of(artifact.as_bytes()).digest_hex()
}

/// A pinned sample of bit-62-clear seeds and the BLAKE3 digest of each
/// one's whole `sim-replay` stdout: `(seed, digest)`. Each seed has
/// neither selector bit set, or only the deferred one.
const PINNED_DIGESTS: &[(u64, &str)] = &[
    (
        0,
        "793e25e9668aefb913c113f70d14db4014ded7b714d8b75d1054b739f55dce42",
    ),
    (
        3,
        "702d7d48be73016529870e42bc384b2cd08b0d49eff0cce304c5ae953fd6b667",
    ),
    (
        9,
        "d65f5a68482f58c5eceabbddeb16248a3f3ce3bb17951074ea828bb882452f84",
    ),
    (
        17,
        "4c548ebb94f95e543e5f53be6241da10adc317ccd85305decd8276943fffdcda",
    ),
    (
        1_000_003,
        "568c6dfb06471b947f2fbe80438829a9e94a589d285fde8fcb99a639d798999f",
    ),
    (
        (1 << 40) + 17,
        "e54af101f352a7ffe9075f2e28d00bdc6ade6e7e3bfeeaf596af507dbdc2e5d7",
    ),
    (
        DEFERRED | 3,
        "41bc8285a283ceb75c86a0e0f12e0a3993f1d7ede019469d3e9627d7dc798f31",
    ),
    (
        DEFERRED | 9,
        "74381f609cd7918ae3f390162c5d930c5419e74b78c65b132a2d324bcc2c3a05",
    ),
    (
        DEFERRED + 1001,
        "1f25dcf4b0c87059ee3542c3533b7a14e0ecd078b06cb8c154cc522995ab0742",
    ),
    (
        DEFERRED | ((1 << 40) + 17),
        "d5d07ac3a75e356edc7f138eb63fa8e7c823f450c56d94affabd068f4b49c905",
    ),
];

/// **The pinned sample of bit-62-clear seeds renders the digests above.**
/// A change to the race, the deferred race or the renderer that moves
/// any of these artifacts fails here.
#[test]
fn bit_62_clear_seeds_render_the_pinned_digests() {
    for (seed, expected) in PINNED_DIGESTS {
        let text = artifact(*seed);
        assert!(!text.is_empty(), "seed {seed}: empty artifact");
        assert_eq!(
            digest(&text),
            *expected,
            "seed {seed} does not render its pinned digest"
        );
    }
}

/// **A seed with bit 62 set selects the decision-log run.** `1 << 62 | x`
/// runs the decision-log crash-and-recovery run, never the plain race;
/// a seed with both selector bits set (`(1 << 63) | (1 << 62) | x`) is
/// refused.
#[test]
fn a_bit_62_seed_selects_the_decision_log_run() {
    let rendered = artifact(LOG | 3);
    assert!(
        rendered.contains(" log-verdict "),
        "1<<62|3 is a decision-log run"
    );
    assert!(!rendered.contains(" put-root "));
    let both = DEFERRED | LOG | 3;
    let out = run(&[both.to_string()]);
    assert!(!out.status.success(), "(1<<63)|(1<<62)|3 is refused");
    assert!(out.stdout.is_empty());
}
