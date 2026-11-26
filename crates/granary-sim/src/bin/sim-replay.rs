// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Runs ONE scenario at ONE seed and writes the trace artifact to
//! stdout. Nothing else reaches stdout, because the whole of stdout is
//! what `tests/replay_across_processes.rs` compares byte for byte
//! between two processes.
//!
//! # Why a binary exists at all
//!
//! The replay property is CROSS-PROCESS. Within
//! one process an ambient value like the pid is constant, so an
//! in-process comparison of two runs is green *while cross-process
//! replay is broken* — which is exactly the defect the seams were moved
//! for. A second process is the only thing that varies it.
//!
//! # What it runs, and why that scenario
//!
//! [`granary_sim::scenario::replay_run`] selects one of three seed
//! spaces, the same body the scenarios assert on and never a second copy
//! of it:
//!
//! - **A seed with no selector bit** runs the two-publisher race
//!   ([`granary_sim::scenario::race`]). Two reasons it is a good
//!   scenario: it drives the scheduler, so a replay divergence in the
//!   schedule shows up; and it MINTS ROOTS, so the artifact carries the
//!   content address of signed root bytes. That address is the whole
//!   signal — `writer_uuid` affects exactly one thing, the bytes of the
//!   signed root, so an artifact of operation kind plus volume plus seq
//!   would be byte-identical with and without an ambient pid in the
//!   preimage.
//! - **A seed with [`granary_sim::scenario::DEFERRED_SEEDS`] set** runs
//!   the race with one publisher's `put_root` deferred
//!   ([`granary_sim::scenario::deferred_race`]), its release point
//!   derived from the seed, so a held write's release is inside the
//!   replayed seed space too. A deferred seed whose run held no
//!   `put_root` is REFUSED, exit non-zero and nothing on stdout: its
//!   artifact would replay byte-identically while carrying no late write
//!   at all.
//! - **A seed with [`granary_sim::scenario::DECISION_LOG_SEEDS`] set**
//!   runs the scripted decision-log run
//!   ([`granary_sim::scenario::decision_log_run`]): a marker write, an
//!   `initialise`, appends, a host crash, recovery and a final
//!   classification, over the crash-consistency log fake and with no
//!   engine. The seed's low bits pick the fault, its target step and the
//!   crash draws, and the artifact carries every step, every draw, the
//!   digest of every file after it and every recovery verdict. A run
//!   that fails its durability oracle, or whose fault never fired, is
//!   REFUSED like a deferred run that held nothing.
//!
//! The two selector bits are exclusive: a seed with both set is a usage
//! error, refused with the usage text and a non-zero exit.
//!
//! A seed with bit 62 set selects the decision-log run; a pinned sample
//! of bit-62-clear seeds renders the digests in
//! `tests/replay_across_processes.rs`.
//!
//! # Argv is untrusted input
//!
//! Every argument path returns an exit status; none of them panics.
//! [`std::env::args`] itself panics on a non-UTF-8 argument, so this
//! reads [`std::env::args_os`] and refuses what it cannot decode.

use std::ffi::OsString;
use std::io::{self, Write as _};
use std::process::ExitCode;

use granary_sim::scenario;

/// How to call it, printed with every argument refusal.
const USAGE: &str = "usage: sim-replay [recovery] <seed>\n\
                     runs a scenario at <seed> (a decimal u64) and writes the trace \
                     artifact to stdout. The top two bits select the scenario: with \
                     neither set, the two-publisher race; bit 63 set, the race with one \
                     publisher's put_root deferred; bit 62 set, the scripted \
                     decision-log crash-and-recovery run. Setting both bits is refused. The explicit recovery argument runs the publication-recovery scenario at that seed";

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1).peekable();
    let recovery = args.peek().is_some_and(|a| a == "recovery");
    if recovery {
        args.next();
    }
    let seed = match parse_seed(args) {
        Ok(seed) => seed,
        Err(why) => return refuse(why),
    };
    let artifact = if recovery {
        match granary_sim::recovery::recovery_run(seed) {
            Ok(run) => run.render(),
            Err(why) => return refuse(&why.to_string()),
        }
    } else {
        let sim = match scenario::replay_run(seed) {
            Ok(sim) => sim,
            Err(why) => return refuse(&why.to_string()),
        };
        sim.trace().render()
    };
    let mut out = io::stdout().lock();
    match out
        .write_all(artifact.as_bytes())
        .and_then(|()| out.flush())
    {
        Ok(()) => ExitCode::SUCCESS,
        // A partly written artifact must never look like a whole one.
        Err(_) => refuse("the artifact could not be written to stdout"),
    }
}

/// The one argument, or why it was refused.
///
/// # Errors
/// A message naming what was wrong — never a panic, whatever bytes the
/// caller passed.
fn parse_seed(mut args: impl Iterator<Item = OsString>) -> Result<u64, &'static str> {
    let Some(raw) = args.next() else {
        return Err("a seed is required");
    };
    if args.next().is_some() {
        return Err("exactly one argument is expected");
    }
    let Some(text) = raw.to_str() else {
        return Err("the seed is not valid UTF-8");
    };
    text.parse::<u64>()
        .map_err(|_| "the seed must be a decimal u64")
}

/// Name the refusal on stderr and exit non-zero.
///
/// Writes with [`writeln!`] rather than [`eprintln!`]: the macro panics
/// if stderr is closed, and a program whose job is to be spawned should
/// not die differently depending on what its parent left open.
fn refuse(why: &str) -> ExitCode {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "sim-replay: {why}");
    let _ = writeln!(err, "{USAGE}");
    ExitCode::FAILURE
}
