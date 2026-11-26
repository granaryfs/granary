// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

// This file uses `granary_store::{codec, verify, fuzz_probe}`, none
// of which exist without the `codec` feature — the same reason
// tests/frame_golden.rs carries this line.
#![cfg(feature = "codec")]

//! Stable-toolchain replay of the committed ingest fuzz corpus — the
//! granary-STORE twin of `granary-core/tests/fuzz_corpus_replay.rs`. PR
//! CI runs no nightly; the scheduled `fuzz` lane does the open-ended
//! fuzzing. Same probe body as the libFuzzer target.
//!
//! Fails CLOSED: the registry below must stay in 4-way set equality with
//! `fuzz/fuzz_targets/*.rs`, the fuzz `Cargo.toml` `[[bin]]` list, the
//! corpus directories, and `fuzz.yml`'s run lines **for this crate**.
//!
//! **Each crate's test is directory-SCOPED and must stay so.** One workflow
//! carries several crates' `cargo fuzz run` lines, and an unscoped
//! collector reads the other crate's targets as unregistered ones —
//! which is exactly what core's test would do without its
//! `cd crates/granary-core` filter, which prevents it.

#![expect(clippy::unwrap_used, reason = "test code (standards rule 3)")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use granary_core::binfmt::{
    PackedFrame, decode_bin, decode_frame_header, encode_bin, encode_frame_header, frame_bytes,
};
use granary_core::hash::GrainId;
use granary_core::manifest::GRAIN_UNPACKED_MAX;
use granary_core::testkit;
use granary_store::codec::GrainCodec;
use granary_store::fuzz_probe::{
    HeaderWalk, PROBE_SUM_MAX, bin_ingest_probe, walk_declared_headers,
};
use granary_store::verify::{BinVerifyError, verify_bin};

/// One registered probe body (also keeps `REGISTRY` below
/// `clippy::type_complexity`-clean).
type Probe = fn(&[u8]);

/// The ONE list. Probe bodies are the same `fuzz_probe` functions the
/// libFuzzer targets call — keep that invariant when adding entries.
const REGISTRY: &[(&str, Probe)] = &[("bin_ingest", granary_store::fuzz_probe::bin_ingest_probe)];

/// The package name in `fuzz/Cargo.toml`, which is a `name = "…"` line
/// like every `[[bin]]` and must be filtered back out of the bin set.
const FUZZ_PACKAGE: &str = "granary-store-fuzz";

/// How this crate's `cargo fuzz run` lines are told apart from the other
/// fuzz workspaces' in the ONE shared workflow. `cargo fuzz` resolves
/// its workspace from the working directory, so the `cd` IS the scope —
/// there is no per-line manifest flag to key on instead.
const RUN_LINE_SCOPE: &str = "cd crates/granary-store";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz")
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn registry_names() -> BTreeSet<String> {
    REGISTRY.iter().map(|(n, _)| (*n).to_owned()).collect()
}

fn dir_stems(dir: &Path, want_ext: Option<&str>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
    {
        let path = entry.unwrap().path();
        match want_ext {
            Some(ext) => {
                if path.extension().and_then(|e| e.to_str()) == Some(ext) {
                    out.insert(path.file_stem().unwrap().to_str().unwrap().to_owned());
                }
            }
            None => {
                if path.is_dir() {
                    out.insert(path.file_name().unwrap().to_str().unwrap().to_owned());
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------- gate 1

#[test]
fn registry_matches_fuzz_targets_bins_and_corpus() {
    let registry = registry_names();
    // POSITIVE CONTROL, and it is not decoration: `assert_eq!` between
    // four EMPTY sets passes. A registry emptied by a bad merge, a
    // `fuzz_targets/` that lost its files and a `corpus/` that lost its
    // directories agree perfectly with each other, and this gate would
    // report the closure intact over a fuzz workspace that no longer
    // exists. Naming the target rather than only counting it also
    // catches a rename that moved all four together.
    assert!(
        registry.contains("bin_ingest"),
        "the registry must name bin_ingest — four empty sets are equal, so an \
         emptied registry makes every assertion below vacuous"
    );

    let target_files = dir_stems(&fuzz_dir().join("fuzz_targets"), Some("rs"));
    let corpus_dirs = dir_stems(&fuzz_dir().join("corpus"), None);
    let manifest = std::fs::read_to_string(fuzz_dir().join("Cargo.toml")).unwrap();
    let bins: BTreeSet<String> = manifest
        .lines()
        .filter_map(|l| l.trim().strip_prefix("name = \""))
        .filter_map(|l| l.strip_suffix('"'))
        .map(str::to_owned)
        .filter(|n| n != FUZZ_PACKAGE)
        .collect();
    assert_eq!(registry, target_files, "registry vs fuzz_targets/*.rs");
    assert_eq!(registry, bins, "registry vs fuzz/Cargo.toml [[bin]] names");
    assert_eq!(registry, corpus_dirs, "registry vs fuzz/corpus/ dirs");

    // ONE BODY, checked rather than agreed. Every set equality above is
    // satisfied by a target file that exists; none of them says what
    // that file CALLS. A target carrying its own inlined pipeline would
    // pass all three and fuzz something the replay never runs — and a
    // shared corpus is exactly what cannot survive the two drifting
    // apart, because then a committed crash input no longer reproduces
    // the crash. So: the target names the registered probe, and names
    // nothing else from this crate.
    for (name, _) in REGISTRY {
        let path = fuzz_dir().join("fuzz_targets").join(format!("{name}.rs"));
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let call = format!("granary_store::fuzz_probe::{name}_probe(");
        assert!(
            src.contains(&call),
            "{name}.rs must call `{call}` — the replay test calls that body, and a target \
             calling anything else fuzzes code the corpus does not replay"
        );
        assert_eq!(
            src.matches("granary_store::").count(),
            1,
            "{name}.rs must reach into granary_store exactly once, through its probe"
        );
    }
}

// ---------------------------------------------------------------- gate 2

/// Every `cargo fuzz run` line in the workflow, whole, in file order.
fn run_lines(workflow: &str) -> Vec<String> {
    workflow
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter(|l| l.contains("cargo fuzz run "))
        .map(str::to_owned)
        .collect()
}

fn target_of(line: &str) -> String {
    let i = line.find("cargo fuzz run ").unwrap();
    line[i + "cargo fuzz run ".len()..]
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

#[test]
fn fuzz_workflow_runs_every_registered_target() {
    let workflow = read(".github/workflows/fuzz.yml");
    let all = run_lines(&workflow);
    let (ours, theirs): (Vec<String>, Vec<String>) = all
        .iter()
        .cloned()
        .partition(|l| l.contains(RUN_LINE_SCOPE));

    // POSITIVE CONTROL for the SCOPE itself. This filter exists to stop
    // one crate's targets being read as another's; a filter that
    // excluded nothing would be doing no scoping, and the day the other
    // workspace's lines were spelled differently this gate would go on
    // reporting green while both twins silently claimed each other's
    // targets. Assert the exclusion happened AND that what was excluded
    // is the other workspace.
    assert!(
        !theirs.is_empty(),
        "the `{RUN_LINE_SCOPE}` filter excluded none of the {} run lines in fuzz.yml, so \
         it is scoping nothing. Either a sibling fuzz workspace was removed — then this \
         control has no subject left and should go — or the `cd` spelling moved and both \
         twins are now claiming each other's targets",
        all.len()
    );

    let ran: BTreeSet<String> = ours.iter().map(|l| target_of(l)).collect();
    assert_eq!(
        registry_names(),
        ran,
        "fuzz.yml `{RUN_LINE_SCOPE}` run lines vs registry"
    );
}

/// What the lane spends on things that are not fuzzing: installing the
/// nightly toolchain and cargo-fuzz, then one sanitizer build per fuzz
/// workspace. Comparing fuzzing time against the job timeout ALONE
/// models those at zero, and a gate that models the build at zero
/// approves a schedule that is cancelled mid-run.
///
/// An estimate, and labelled one — the exit battery's `workflow_dispatch`
/// run is what measures it. Erring high is the safe direction: it costs
/// a target slot, where erring low costs the whole lane.
const BUILD_RESERVE_SECS: u64 = 20 * 60;

/// The lane's own arithmetic: the time budgets it hands libFuzzer must
/// fit inside the timeout GitHub will kill the job at, or every run ends
/// cancelled — a red weekly lane that reports nothing about the code.
///
/// Whole-file scoped on purpose, unlike the two gates above: the budget
/// is shared by every fuzz workspace, so no crate's twin can check
/// it from its own half. Stated here rather than discovered later.
#[test]
fn the_fuzz_lane_fits_inside_its_own_job_timeout() {
    let workflow = read(".github/workflows/fuzz.yml");
    // Every run line, whichever workspace it belongs to, has the form the
    // rest of these gates read (`cd crates/<workspace> && cargo fuzz run`) and
    // the flags the lane needs. `--target` explicit because cargo-fuzz
    // otherwise builds for its own binary's triple and taiki-e's prebuilt is
    // musl-static, which sanitizers reject; the literal `--` because
    // everything after it is libFuzzer's and without it cargo-fuzz eats the
    // arguments; `-max_len` to bound the input; `-max_total_time` because a
    // target with no time budget runs until the job timeout kills it.
    for line in &run_lines(&workflow) {
        assert!(
            line.starts_with("- run: cd crates/") && line.contains(" && cargo fuzz run "),
            "a run line in another form escapes the per-workspace gates: {line}"
        );
        assert!(
            line.contains("--target x86_64-unknown-linux-gnu"),
            "run line must pin the sanitizer triple: {line}"
        );
        let (_, libfuzzer_args) = line.split_once(" -- ").unwrap_or_else(|| {
            panic!("run line must separate libFuzzer args with a literal `--`: {line}")
        });
        assert!(
            libfuzzer_args.contains("-max_len=") && libfuzzer_args.contains("-max_total_time="),
            "run line must bound the input length and carry a time budget: {line}"
        );
    }
    let budget: u64 = run_lines(&workflow)
        .iter()
        .map(|l| {
            let i = l.find("-max_total_time=").unwrap_or_else(|| {
                panic!("every run line needs a time budget for this sum to mean anything: {l}")
            });
            l[i + "-max_total_time=".len()..]
                .split_whitespace()
                .next()
                .unwrap()
                .parse::<u64>()
                .unwrap()
        })
        .sum();
    // SCOPED by being unambiguous: `find_map` would silently read some
    // other job's timeout if one were ever added above `fuzz:`, which is
    // the same whole-file blindness the two gates above were just fixed
    // for. One job, one number — and a second one reds this rather than
    // being quietly preferred.
    let timeouts: Vec<u64> = workflow
        .lines()
        .filter_map(|l| l.trim().strip_prefix("timeout-minutes:"))
        .map(|v| v.trim().parse().unwrap())
        .collect();
    assert_eq!(
        timeouts.len(),
        1,
        "fuzz.yml has {} jobs with a timeout; this gate can no longer tell which one \
         bounds the fuzz targets — scope it to the fuzz job",
        timeouts.len()
    );
    let timeout = *timeouts.first().unwrap();
    assert_eq!(
        (budget, timeout),
        (8_460, 170),
        "fuzz schedule arithmetic changed"
    );
    assert!(
        budget > 0 && timeout > 0,
        "a zero on either side makes this comparison vacuous"
    );
    assert!(
        budget + BUILD_RESERVE_SECS < timeout * 60,
        "the fuzz targets ask for {budget}s of fuzzing plus {BUILD_RESERVE_SECS}s of \
         builds inside a {timeout}-minute job — the job is cancelled before the last \
         targets run, and a cancelled job runs no `if: failure()` upload step"
    );
}

// ---------------------------------------------------------------- gate 3

#[test]
fn replay_committed_corpus() {
    for (target, probe) in REGISTRY {
        let dir = fuzz_dir().join("corpus").join(target);
        let mut n = 0usize;
        for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.unwrap().path();
            probe(&std::fs::read(&path).unwrap());
            n += 1;
        }
        assert!(
            n > 0,
            "empty corpus for {target} — replay would be vacuously green"
        );
    }
}

// -------------------------------------------------- the corpus is real

/// The four seeds, and what each one is FOR. `replay_committed_corpus`
/// above only proves the probe survives whatever is in the directory:
/// four files of `b"x"` satisfy it completely, and every one of them
/// dies in `decode_bin`'s first length check having exercised nothing.
/// This is the control that makes that impossible.
const SEEDS: [&str; 4] = [
    "seed-bin-single",
    "seed-bin-multi",
    "seed-bomb",
    "seed-empty-blocks",
];

fn corpus_dir() -> PathBuf {
    fuzz_dir().join("corpus").join("bin_ingest")
}

fn corpus_path(name: &str) -> PathBuf {
    corpus_dir().join(name)
}

fn seed(name: &str) -> Vec<u8> {
    let path = corpus_path(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "read {} (regenerate with GRANARY_REGEN_VECTORS=1): {e}",
            path.display()
        )
    })
}

fn codec() -> GrainCodec {
    GrainCodec::new().unwrap_or_else(|e| panic!("{e}"))
}

/// A bin a conforming packer emits: every frame addressed by the id its
/// own bytes hash to.
fn honest_bin(grains: &[Vec<u8>]) -> Vec<u8> {
    let mut codec = codec();
    let frames: Vec<PackedFrame> = grains
        .iter()
        .map(|grain| PackedFrame {
            id: GrainId::of(grain),
            frame: codec
                .compress_grain(grain)
                .unwrap_or_else(|e| panic!("{e}")),
        })
        .collect();
    encode_bin(&frames).unwrap_or_else(|e| panic!("{e}"))
}

/// Deterministic, seeded, HIGHLY compressible bytes — a 64-byte pattern
/// repeated. `testkit::fill`'s xorshift stream is the opposite by
/// design, and a bomb built from it would be 24 MiB of upload rather
/// than the ~kilobyte an amplification witness has to be.
fn compressible(seed: u8, len: usize) -> Vec<u8> {
    let mut pattern = [0u8; 64];
    let mut byte = seed;
    for b in &mut pattern {
        byte = byte.wrapping_mul(31).wrapping_add(seed);
        *b = byte;
    }
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        out.extend_from_slice(&pattern);
    }
    out.truncate(len);
    out
}

/// A structurally legal zstd frame of `blocks` ZERO-LENGTH raw blocks
/// followed by one 1-byte raw block: `6 + 3·blocks + 4` bytes of input
/// that declare, and produce, exactly one byte.
///
/// This frame demonstrates the scan cost independently of the hash cost. The declared
/// sum bounds the HASH term of verification; it says nothing at all
/// about the cost of WALKING a frame's block structure, which is what
/// `find_frame_compressed_size` pays before a byte is produced. The
/// second half of that bound is `BIN_MAX_BYTES`, and this frame is the
/// input that makes the difference between the two visible.
fn empty_block_frame(blocks: usize) -> Vec<u8> {
    let mut frame = Vec::with_capacity(6 + 3 * blocks + 4);
    frame.extend_from_slice(&0xFD2F_B528_u32.to_le_bytes()); // zstd magic
    // Frame_Header_Descriptor: FCS_flag 0 + Single_Segment_flag set, so
    // there is no Window_Descriptor and the content size is one byte
    // wide. Window_Size then equals the content size (1), which is all
    // the room these blocks need.
    frame.push(0x20);
    frame.push(0x01); // Frame_Content_Size = 1
    // Block_Header is 3 bytes LE: bit 0 Last_Block, bits 1-2 Block_Type
    // (0 = Raw), bits 3-23 Block_Size. Zero is therefore "a raw block of
    // no bytes that is not the last one".
    frame.resize(frame.len() + 3 * blocks, 0);
    // (1 << 3) | 1 = a last raw block of one byte, then its content.
    frame.extend_from_slice(&[9, 0, 0, 0]);
    frame
}

/// The witness wrapped as a bin: one frame, declaring one byte, holding
/// the id that one byte hashes to — so it VERIFIES, which is the
/// uncomfortable half. The expensive input is not a rejected one.
fn empty_block_bin(blocks: usize) -> Vec<u8> {
    let mut frame = encode_frame_header(1).unwrap().to_vec();
    frame.extend_from_slice(&empty_block_frame(blocks));
    encode_bin(&[PackedFrame {
        id: GrainId::of(&[0u8]),
        frame,
    }])
    .unwrap_or_else(|e| panic!("{e}"))
}

/// 2.7M blocks — the measured scan-cost witness size, and it lands well under
/// both `FRAME_COMP_MAX` (8 421 385) and the lane's `-max_len`.
const WITNESS_BLOCKS: usize = 2_700_000;

fn generate(name: &str) -> Vec<u8> {
    match name {
        "seed-bin-single" => honest_bin(&[testkit::fill(1, 4096)]),
        "seed-bin-multi" => honest_bin(
            &(1..=4u64)
                .map(|i| testkit::fill(i, 4096))
                .collect::<Vec<_>>(),
        ),
        // Three MAXIMAL grains against a two-maximal-grain ceiling: the
        // smallest bin that crosses `PROBE_SUM_MAX`, and it crosses at
        // the third frame rather than the first, so the seed exercises
        // the sum RUNNING rather than a single oversized declaration.
        "seed-bomb" => honest_bin(
            &(1..=3u8)
                .map(|i| compressible(i, GRAIN_UNPACKED_MAX as usize))
                .collect::<Vec<_>>(),
        ),
        "seed-empty-blocks" => empty_block_bin(WITNESS_BLOCKS),
        other => panic!("no generator for {other}"),
    }
}

/// The committed corpus is the four shapes it is named for — and the
/// generator that produced it is committed beside it, so a seed is
/// never a blob nobody can rebuild.
///
/// Regenerate DELIBERATELY (the `tests/frame_golden.rs` idiom):
/// `GRANARY_REGEN_VECTORS=1 cargo nextest run -p granary-store -E
/// 'binary(fuzz_corpus_replay)'`
#[test]
fn the_committed_seeds_are_the_four_shapes_they_are_named_for() {
    if std::env::var_os("GRANARY_REGEN_VECTORS").is_some() {
        assert!(
            std::env::var_os("CI").is_none(),
            "refusing to regenerate the fuzz corpus under CI — a seed is committed input, \
             and a lane that rewrites it can never find it wrong"
        );
        for name in SEEDS {
            let path = corpus_path(name);
            std::fs::write(&path, generate(name))
                .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
            eprintln!("regenerated {}", path.display());
        }
    }

    // SUPERSET, deliberately, and NOT set equality. This directory is
    // libFuzzer's working corpus: `cargo fuzz run bin_ingest` writes
    // every newly interesting input straight into it, and the standard
    // response to a weekly-lane crash is to commit the reproducer here
    // as a regression seed. Set equality would turn both of those —
    // the two things this committed corpus exists to enable — into a red test
    // suite. What must hold is that the four described seeds are still
    // present and still their described shapes; extra files are the
    // fuzzer working as intended, and `replay_committed_corpus` drives
    // them through the probe like any other input.
    let names: BTreeSet<String> = std::fs::read_dir(corpus_dir())
        .unwrap_or_else(|e| panic!("{}: {e}", corpus_dir().display()))
        .map(|e| e.unwrap().file_name().to_str().unwrap().to_owned())
        .collect();
    let described: BTreeSet<String> = SEEDS.iter().map(|s| (*s).to_owned()).collect();
    assert!(
        names.is_superset(&described),
        "the corpus is missing described seeds {:?}",
        described.difference(&names).collect::<Vec<_>>()
    );

    // THE GENERATOR IS COMPARED TO THE CORPUS, not merely committed
    // beside it. Without this, `generate()` can drift until it no longer
    // reproduces any committed seed and every assertion below still
    // passes on the old bytes — the regeneration path would be dead
    // code claiming to be a rebuild recipe.
    //
    // Byte equality is affordable HERE and nowhere else in this file:
    // `tests/frame_golden.rs` already pins `compress_grain`'s exact
    // output across macOS and Linux, so these bytes are as reproducible
    // as that gate is. A libzstd change reds both, which is the deliberate
    // format event it should be.
    for name in SEEDS {
        assert_eq!(
            seed(name),
            generate(name),
            "the committed {name} is not what its generator now produces — regenerate \
             DELIBERATELY (GRANARY_REGEN_VECTORS=1) and treat a zstd change as a deliberate format change"
        );
    }

    // -- seed-bin-single: one real grain, verifies end to end ----------
    let single = seed("seed-bin-single");
    let entries = decode_bin(&single).unwrap_or_else(|e| panic!("not a bin: {e}"));
    assert_eq!(entries.len(), 1);
    verify_bin(&single, PROBE_SUM_MAX).unwrap_or_else(|e| panic!("must verify: {e}"));

    // -- seed-bin-multi: several grains, verifies end to end -----------
    let multi = seed("seed-bin-multi");
    let entries = decode_bin(&multi).unwrap_or_else(|e| panic!("not a bin: {e}"));
    assert!(entries.len() > 1, "a multi-grain seed needs several grains");
    verify_bin(&multi, PROBE_SUM_MAX).unwrap_or_else(|e| panic!("must verify: {e}"));

    // -- seed-bomb: declares past the ceiling, from a tiny upload ------
    let bomb = seed("seed-bomb");
    let entries = decode_bin(&bomb).unwrap_or_else(|e| panic!("not a bin: {e}"));
    let declared: u64 = entries
        .iter()
        .map(|e| {
            u64::from(
                decode_frame_header(frame_bytes(&bomb, e).unwrap())
                    .unwrap()
                    .unpacked_len,
            )
        })
        .sum();
    assert!(
        declared > PROBE_SUM_MAX,
        "the bomb declares {declared} bytes, which does not reach the {PROBE_SUM_MAX}-byte \
         ceiling it exists to cross"
    );
    // The amplification is the point: a bomb the size of an honest bin
    // would be a bomb nobody would send.
    assert!(
        declared / bomb.len() as u64 > 1000,
        "{} bytes of upload declaring {declared} is not an amplification witness",
        bomb.len()
    );
    assert!(matches!(
        verify_bin(&bomb, PROBE_SUM_MAX),
        Err(BinVerifyError::DecompressedSumExceeded { .. })
    ));

    // -- seed-empty-blocks: the scan-cost witness ----------------------
    // Megabytes of input, one declared byte, and it VERIFIES: the
    // declared sum bounds hashing work, while `BIN_MAX_BYTES` bounds
    // block-scanning work; neither alone bounds verification CPU.
    let witness = seed("seed-empty-blocks");
    let entries = decode_bin(&witness).unwrap_or_else(|e| panic!("not a bin: {e}"));
    assert_eq!(entries.len(), 1);
    let frame = frame_bytes(&witness, entries.first().unwrap()).unwrap();
    let declared = decode_frame_header(frame).unwrap().unpacked_len;
    assert_eq!(declared, 1, "the witness declares one byte");
    assert!(
        frame.len() > 4 * 1024 * 1024,
        "{} bytes of frame is not the scan-cost witness — the whole point is \
         megabytes of block structure behind a one-byte declaration",
        frame.len()
    );
    verify_bin(&witness, PROBE_SUM_MAX).unwrap_or_else(|e| {
        panic!("the witness must VERIFY, that is what makes it a witness: {e}")
    });
}

// ------------------------------------------------- the bound, observed

/// **Refused BEFORE any frame is decompressed**, asserted the only way a
/// caller outside this crate can: with a bin whose frames could not
/// possibly expand.
///
/// The honest bomb below cannot prove this on its own. Its frames are
/// real, so a `verify_bin` that decompressed first and charged
/// afterwards would refuse it for the same limit with the same message
/// — the verdict does not discriminate. The garbage-payload bomb does:
/// its frames declare 8 MiB behind bytes that are not zstd at all, so
/// reaching decompression is OBSERVABLE as `GrainInvalid`. Under the
/// probe's ceiling it must still be `DecompressedSumExceeded`, and the
/// same bytes under NO ceiling must be `GrainInvalid` — which is the
/// positive control proving the discriminator works rather than the
/// bytes simply being unreachable.
#[test]
fn the_declared_sum_bail_refuses_a_bomb_before_any_frame_is_decompressed() {
    let honest = honest_bin(
        &(1..=3u8)
            .map(|i| compressible(i, GRAIN_UNPACKED_MAX as usize))
            .collect::<Vec<_>>(),
    );
    assert!(matches!(
        verify_bin(&honest, PROBE_SUM_MAX),
        Err(BinVerifyError::DecompressedSumExceeded { .. })
    ));

    let mut garbage = Vec::new();
    for i in 1..=3u8 {
        let mut frame = encode_frame_header(GRAIN_UNPACKED_MAX).unwrap().to_vec();
        frame.extend_from_slice(&[i; 32]); // not a zstd frame, on purpose
        garbage.push(PackedFrame {
            id: GrainId::of(&[i]),
            frame,
        });
    }
    let garbage = encode_bin(&garbage).unwrap_or_else(|e| panic!("{e}"));

    // THE POSITIVE CONTROL: with the ceiling out of the way these bytes
    // reach decompression and fail there, visibly.
    assert!(
        matches!(
            verify_bin(&garbage, u64::MAX),
            Err(BinVerifyError::GrainInvalid { .. })
        ),
        "the discriminator is only meaningful if decompression CAN be reached"
    );
    // And under the probe's ceiling that never happens.
    assert!(
        matches!(
            verify_bin(&garbage, PROBE_SUM_MAX),
            Err(BinVerifyError::DecompressedSumExceeded { .. })
        ),
        "a GrainInvalid here would mean a frame was decompressed before the sum was charged"
    );

    bin_ingest_probe(&honest);
    bin_ingest_probe(&garbage);
}

/// The probe's independent header walk — the half of `bin_ingest_probe`
/// that holds `verify_bin` to an answer it did not supply. A walk that
/// silently returned `Within` for everything would disarm the probe's
/// only real assertion while every test above stayed green.
#[test]
fn the_probes_header_walk_finds_the_crossing_frame() {
    let under = honest_bin(&[testkit::fill(7, 4096), testkit::fill(8, 4096)]);
    let entries = decode_bin(&under).unwrap();
    assert_eq!(
        walk_declared_headers(&under, &entries, PROBE_SUM_MAX),
        HeaderWalk::Within(8192)
    );

    // The crossing is charged in index order and reported AT the frame
    // that crossed — two maximal grains fit exactly, the third does not.
    let over = honest_bin(
        &(1..=3u8)
            .map(|i| compressible(i, GRAIN_UNPACKED_MAX as usize))
            .collect::<Vec<_>>(),
    );
    let entries = decode_bin(&over).unwrap();
    assert_eq!(
        walk_declared_headers(&over, &entries, PROBE_SUM_MAX),
        HeaderWalk::Crossed(3 * u64::from(GRAIN_UNPACKED_MAX)),
        "the walk must report the RUNNING total at the crossing, not the bin's whole sum"
    );
    // Exactly at the limit is inside it — the same boundary `charge`
    // applies, restated here because a probe half a byte out would
    // manufacture crashes rather than find them.
    assert_eq!(
        walk_declared_headers(&over, &entries, 3 * u64::from(GRAIN_UNPACKED_MAX)),
        HeaderWalk::Within(3 * u64::from(GRAIN_UNPACKED_MAX))
    );
}

// ------------------------------------------- the wiring around the lane

/// Does `needle` appear on a line that is not commented out?
///
/// `body.contains(needle)` is the fail-open form and this file has
/// already been bitten by it once: a `#` line creates no annotation, no
/// workflow step and no gate command, so a gate that reads a
/// commented-out command as "present" reports green over a lane that
/// stopped running. Both files scanned here use `#` for comments.
fn contains_uncommented(body: &str, needle: &str) -> bool {
    body.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .any(|l| l.contains(needle))
}

/// The files outside this crate that a store crash's evidence
/// depends on. Each assertion carries the granary-CORE counterpart as
/// its positive control: if the core form is missing too, the pattern
/// or the file has moved and this gate is blind, not satisfied.
#[test]
fn the_store_fuzz_workspace_is_wired_into_ci_the_lane_and_reuse() {
    let fuzz_yml = read(".github/workflows/fuzz.yml");
    let ci_yml = read(".github/workflows/ci.yml");
    let reuse = read("REUSE.toml");

    for (file, body, core_form, store_form, why) in [
        (
            "fuzz.yml",
            &fuzz_yml,
            "crates/granary-core/fuzz -> target",
            "crates/granary-store/fuzz -> target",
            "rust-cache must know the second workspace or the lane rebuilds it every week",
        ),
        (
            "fuzz.yml",
            &fuzz_yml,
            "path: crates/granary-core/fuzz/artifacts/",
            "path: crates/granary-store/fuzz/artifacts/",
            "a store crash writes its reproducer under the STORE workspace; an upload \
             step pointed only at core's silently discards it",
        ),
        (
            "ci.yml",
            &ci_yml,
            "cargo clippy --manifest-path crates/granary-core/fuzz/Cargo.toml --all-targets \
             --locked",
            "cargo clippy --manifest-path crates/granary-store/fuzz/Cargo.toml --all-targets \
             --locked",
            "nothing else in PR CI builds the fuzz workspace, so a rename bitrots it \
             silently until the weekly lane runs — and it is CLIPPY, not `check`: a fuzz \
             crate compiling was never the question, and the nested clippy config that \
             governs granary-client's fuzz workspace only fires under the lint",
        ),
        (
            "REUSE.toml",
            &reuse,
            "crates/granary-core/fuzz/corpus/**",
            "crates/granary-store/fuzz/corpus/**",
            "binary corpus files carry no SPDX header",
        ),
        (
            "REUSE.toml",
            &reuse,
            "crates/granary-core/fuzz/Cargo.lock",
            "crates/granary-store/fuzz/Cargo.lock",
            "a lockfile carries no SPDX header",
        ),
        (
            "REUSE.toml",
            &reuse,
            "crates/granary-core/fuzz/.gitignore",
            "crates/granary-store/fuzz/.gitignore",
            "the fuzz .gitignore is not covered by the root one",
        ),
    ] {
        assert!(
            contains_uncommented(body, core_form),
            "POSITIVE CONTROL FAILED: {file} no longer carries the granary-core form \
             `{core_form}` on a live line, so this check is blind rather than satisfied"
        );
        assert!(
            contains_uncommented(body, store_form),
            "{file} is missing `{store_form}` on a live line — {why}"
        );
    }

    // Two upload steps, two artifact NAMES: actions/upload-artifact@v4
    // hard-fails on a duplicate name, so a copy-pasted step would take
    // down the very run that was trying to save a crash.
    assert!(
        contains_uncommented(&fuzz_yml, "name: fuzz-artifacts-store"),
        "the store upload step needs its own artifact name"
    );

    // A run step that cannot fail the job cannot trigger `if: failure()`
    // either, so a crash would be found, reported as a pass, and its
    // reproducer never uploaded. Nothing in this lane may carry it.
    assert!(
        !contains_uncommented(&fuzz_yml, "continue-on-error"),
        "a continue-on-error step in the fuzz lane would swallow a crash AND suppress \
         the artifact upload that saves its reproducer"
    );
    // One upload step per fuzz workspace the lane runs, at that workspace's
    // artifact path and under its own name: cargo-fuzz writes a reproducer
    // under the workspace that crashed, and a duplicate name hard-fails the
    // upload. The run lines' form is checked in the lane test below.
    let workspaces: BTreeSet<String> = run_lines(&fuzz_yml)
        .iter()
        .filter_map(|l| l.split("cd crates/").nth(1))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_owned)
        .collect();
    assert!(
        workspaces.contains("granary-core") && workspaces.contains("granary-store"),
        "POSITIVE CONTROL FAILED: the run lines do not name both known workspaces"
    );
    for ws in &workspaces {
        let path = format!("path: crates/{ws}/fuzz/artifacts/");
        assert!(
            contains_uncommented(&fuzz_yml, &path),
            "{ws} runs in the lane but no upload step saves its reproducers (`{path}`)"
        );
    }
    assert_eq!(
        fuzz_yml.matches("uses: actions/upload-artifact").count(),
        workspaces.len(),
        "one upload step per fuzz workspace"
    );
    let names: Vec<&str> = fuzz_yml
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("name: fuzz-artifacts"))
        .collect();
    let distinct: BTreeSet<&str> = names.iter().copied().collect();
    assert_eq!(
        (names.len(), distinct.len()),
        (workspaces.len(), workspaces.len()),
        "each upload step needs its own artifact name: {names:?}"
    );

    // NO WILDCARD in REUSE.toml. A `crates/*/fuzz/**` entry would cover
    // this crate and Apache-stamp a future granary-server fixture along
    // with it — the per-crate rule REUSE.toml's own comment states.
    //
    // Comments are stripped first, the way check-licence-boundary.sh
    // strips them before deciding: a `#` line creates no annotation, and
    // this assertion tripped on the very comment that explains why the
    // wildcard is refused.
    let annotations: String = reuse
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for wildcard in ["crates/*/fuzz", "crates/**/fuzz"] {
        assert!(
            !annotations.contains(wildcard),
            "REUSE.toml must name each crate's fuzz paths, never `{wildcard}`: a wildcard \
             silently Apache-stamps future AGPL-crate fixtures"
        );
    }
    // POSITIVE CONTROL for the strip: the annotation body must still
    // hold the per-crate entries, or the filter above removed the file.
    assert!(
        annotations.contains("crates/granary-store/fuzz/corpus/**"),
        "stripping comments removed the annotations themselves"
    );
}
