// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The only mechanical link between `scripts/bench/gen-w3.py` and the
//! Rust constants W3's file sizes are justified against.
//!
//! The generator is Python and cannot import `granary_core`, so it
//! re-declares `MIN_GRAIN` (and the sweep grid's coarsest `min`) as
//! literals. That duplication is exactly the drift the house rule
//! "constants live in code ONCE and are imported" exists to prevent —
//! and here it cannot be imported, so it is tripwired instead: this
//! test reads the generator's own source, extracts the declared
//! literals, and fails if either disagrees with its Rust source of
//! truth. Without it, a future change to `thresh::MIN_GRAIN` or to
//! `SWEEP_AVGS` leaves the generator sizing a corpus against a floor
//! that no longer exists, and W3's counter-case silently becomes
//! vacuous at the shipped tuple: below the floor every arm cuts whole-file
//! grains, which is how W1's comparison went at its 512 KiB floor.
//! `gen-w3.py` once contained no assertion at all, and nothing in the repo
//! referenced it. This tripwire did its job at the format event: it went red
//! the moment `thresh::MIN_GRAIN` moved to 128 KiB and stayed red until the
//! generator's literal followed.

use std::fs;
use std::path::PathBuf;

use granary_bench::tuple::{GrainTuple, SWEEP_AVGS};
use granary_core::thresh::MIN_GRAIN;

/// `scripts/bench/gen-w3.py`, from this crate's manifest directory.
fn generator_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join("bench")
        .join("gen-w3.py")
}

/// Every top-level `NAME = …` right-hand side in `src`, comments
/// stripped. More than one is an error at the call site: Python takes
/// the last, a reader takes the first.
fn declarations<'a>(src: &'a str, name: &str) -> Vec<&'a str> {
    src.lines()
        .filter_map(|line| {
            let code = line.split('#').next().unwrap_or("");
            let (lhs, rhs) = code.split_once('=')?;
            (lhs.trim() == name).then_some(rhs.trim())
        })
        .collect()
}

/// Evaluates the integer-literal products the generator uses
/// (`131072`, `128 * 1024`, `1024 * 1024`). Anything else is `None` —
/// an unparseable declaration must fail the test, not be skipped.
fn eval_product(rhs: &str) -> Option<usize> {
    rhs.split('*').try_fold(1usize, |acc, term| {
        term.trim()
            .replace('_', "")
            .parse::<usize>()
            .ok()
            .and_then(|v| acc.checked_mul(v))
    })
}

/// Reads one constant, requiring exactly one parseable declaration.
fn declared(src: &str, name: &str) -> usize {
    let found = declarations(src, name);
    let [rhs] = found.as_slice() else {
        panic!(
            "gen-w3.py must declare {name} exactly once, found {}: {found:?}",
            found.len()
        )
    };
    eval_product(rhs)
        .unwrap_or_else(|| panic!("gen-w3.py: {name} = {rhs:?} is not a product of integers"))
}

#[test]
fn gen_w3_min_grain_matches_granary_core() {
    let path = generator_path();
    let src = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_eq!(
        declared(&src, "MIN_GRAIN"),
        MIN_GRAIN,
        "scripts/bench/gen-w3.py's MIN_GRAIN has drifted from \
         granary_core::thresh::MIN_GRAIN — W3's file sizes are asserted \
         against a floor that is no longer granary's"
    );
}

#[test]
fn gen_w3_sweep_coarsest_min_matches_the_grid() {
    let path = generator_path();
    let src = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    // The grid's own policy (`GrainTuple::from_avg`), not a copy of it.
    let coarsest = SWEEP_AVGS
        .iter()
        .map(|avg| {
            GrainTuple::from_avg(*avg)
                .unwrap_or_else(|e| panic!("SWEEP_AVGS member {avg} is not shippable: {e}"))
                .min
        })
        .max()
        .expect("SWEEP_AVGS is non-empty");
    assert_eq!(
        declared(&src, "SWEEP_COARSEST_MIN"),
        coarsest,
        "scripts/bench/gen-w3.py's SWEEP_COARSEST_MIN has drifted from the \
         pre-registered sweep grid — W3's files may be single-grain at the \
         coarsest grid point while the generator's assertions still pass"
    );
}
