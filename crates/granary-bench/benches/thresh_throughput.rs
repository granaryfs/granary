// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! K4 gate measurement: single-core chunker throughput on the M4 Mac (gate
//! K4: below ~1 GB/s, investigate before a write path).
//! Settings chosen for a ~GB/s workload: flat sampling, small sample
//! count, long measurement window (no primary-source guidance exists —
//! deferred; revisit if numbers look noisy).
//! Run: cargo bench -p granary-bench

use criterion::{Criterion, SamplingMode, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

const LEN: usize = 256 * 1024 * 1024;
const SEED: u64 = 0x9e37_79b9_7f4a_7c15;

fn bench_thresh(c: &mut Criterion) {
    let data = granary_core::testkit::fill(SEED, LEN);
    let mut group = c.benchmark_group("thresh");
    group
        .throughput(Throughput::Bytes(LEN as u64))
        .sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .measurement_time(Duration::from_secs(20));
    group.bench_function("chunk_256mib", |b| {
        b.iter(|| {
            let covered: usize = granary_core::thresh::grains(black_box(&data))
                .map(|g| g.length)
                .sum();
            assert_eq!(
                covered, LEN,
                "chunker lost coverage — K4 number would be wrong"
            );
            black_box(covered)
        });
    });
    group.bench_function("chunk_hash_256mib", |b| {
        b.iter(|| {
            for g in granary_core::thresh::grains(black_box(&data)) {
                let Some(s) = data.get(g.offset..g.offset + g.length) else {
                    panic!("grain range escapes buffer");
                };
                black_box(granary_core::hash::GrainId::of(s));
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_thresh);
criterion_main!(benches);
