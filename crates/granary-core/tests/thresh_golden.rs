// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Chunker drift tripwire: committed cut points + grain hashes for fixed
//! deterministic inputs, verified through BOTH chunker APIs, diffed
//! across the 3-platform CI matrix every merge (this is also the
//! cross-SIMD blake3 tripwire — NEON vs x86 paths).
//!
//! Regenerate DELIBERATELY (format event, never a refactor side effect):
//! `GRANARY_REGEN_VECTORS=1 cargo test -p granary-core --test thresh_golden`

#![expect(clippy::unwrap_used, reason = "test code (standards rule 3)")]

use granary_core::hash::GrainId;
use granary_core::testkit;
use granary_core::thresh::{self, CHUNKER_SPEC, Grain};

mod common;
use std::fmt::Write as _;
use std::path::Path;

enum Pattern {
    Xorshift(u64),
    Zeros,
    Ff,
}

fn materialize(p: &Pattern, len: usize) -> Vec<u8> {
    match p {
        Pattern::Xorshift(seed) => testkit::fill(*seed, len),
        Pattern::Zeros => vec![0u8; len],
        Pattern::Ff => vec![0xFFu8; len],
    }
}

fn cases() -> Vec<(&'static str, Pattern, usize)> {
    const SEED: u64 = 0x9e37_79b9_7f4a_7c15;
    vec![
        ("empty", Pattern::Xorshift(SEED), 0),
        ("one-byte", Pattern::Xorshift(SEED), 1),
        (
            "min-minus-1",
            Pattern::Xorshift(SEED),
            thresh::MIN_GRAIN - 1,
        ),
        ("min-exact", Pattern::Xorshift(SEED), thresh::MIN_GRAIN),
        ("min-plus-1", Pattern::Xorshift(SEED), thresh::MIN_GRAIN + 1),
        ("avg-exact", Pattern::Xorshift(SEED), thresh::AVG_GRAIN),
        (
            "mid-odd",
            Pattern::Xorshift(0xdead_beef_cafe_f00d),
            3_500_000,
        ),
        (
            "multi",
            Pattern::Xorshift(0x0123_4567_89ab_cdef),
            20_000_000,
        ),
        ("zeros-16mib", Pattern::Zeros, 16 * 1024 * 1024),
        ("ff-2mib", Pattern::Ff, 2 * 1024 * 1024),
    ]
}

fn render() -> String {
    let mut out = String::new();
    writeln!(out, "# granary thresh golden vectors v1").unwrap();
    writeln!(out, "# chunker: {CHUNKER_SPEC}").unwrap();
    for (name, pattern, len) in cases() {
        let data = materialize(&pattern, len);
        let slice: Vec<Grain> = thresh::grains(&data).collect();
        // Both APIs must agree BEFORE anything is compared to disk.
        let stream: Vec<Grain> = thresh::grains_streaming(std::io::Cursor::new(&data))
            .map(|r| {
                let g = r.unwrap();
                Grain {
                    offset: usize::try_from(g.offset).unwrap(),
                    length: g.length,
                }
            })
            .collect();
        assert_eq!(slice, stream, "slice/stream cut divergence in case {name}");
        let tag = match pattern {
            Pattern::Xorshift(seed) => format!("xorshift:{seed:016x}"),
            Pattern::Zeros => "zeros".to_owned(),
            Pattern::Ff => "ff".to_owned(),
        };
        writeln!(out, "case {name} pattern={tag} len={len}").unwrap();
        for g in &slice {
            let id = GrainId::of(data.get(g.offset..g.offset + g.length).unwrap());
            writeln!(out, "grain {} {} {id}", g.offset, g.length).unwrap();
        }
    }
    out
}

#[test]
fn matches_committed_vectors() {
    let actual = render();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/thresh_v1.txt");
    common::assert_golden(&path, &actual);
}
