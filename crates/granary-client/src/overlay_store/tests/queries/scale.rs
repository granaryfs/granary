// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Fixed-directory query measurements exclude admission and exhaustive test walks.

use super::*;
use crate::overlay_store::work::{QueryWork, StorageWork};
use crate::sync::{InstantClock, MonotonicClock as _};

#[expect(
    clippy::too_many_lines,
    reason = "all query timings and complete clone accounting share the exact fixed-directory namespace fixture"
)]
fn namespace_scale(total: usize) {
    let mut base = vec![
        entry(vec![name("d")], OverlayKind::Directory),
        entry(vec![name("u")], OverlayKind::Directory),
    ];
    for number in 0..total - 2 {
        base.push(entry(
            vec![
                name(if number < 100 { "d" } else { "u" }),
                name(&format!("n{number:06}")),
            ],
            OverlayKind::File {
                content: Some(grain(1)),
            },
        ));
    }
    let mut f = Fixture::with_base(base, Source::default());
    assert_eq!(
        f.overlay.namespace.entries.len(),
        total,
        "actual primary cardinality"
    );
    let path = vec![name("d"), name("n000099")];
    let expected = f.overlay.namespace.entries.get(&path).unwrap().clone();
    let mut path_times = Vec::new();
    let mut inode_times = Vec::new();
    let mut listing_times = Vec::new();
    let mut cases = 0;
    let clock = InstantClock::default();
    for _ in 0..100 {
        let ((answer, elapsed), query, storage) = crate::overlay_store::work::measure(|| {
            let start = clock.start().unwrap();
            let answer = f.overlay.query_path(&f.store, &f.owner, &path);
            (answer, clock.elapsed(&start).unwrap().as_nanos())
        });
        assert_eq!(
            (found(answer.unwrap()).entry, query, storage),
            (
                Some(expected.clone()),
                QueryWork {
                    entry_copies: 1,
                    ..QueryWork::default()
                },
                StorageWork::default()
            ),
            "path answers, zero scans/copies and separate zero storage work: N={total}"
        );
        path_times.push(elapsed);
        let ((answer, elapsed), work) = measure_query(|| {
            let start = clock.start().unwrap();
            let answer = f.overlay.query_inode(&f.store, &f.owner, expected.inode);
            (answer, clock.elapsed(&start).unwrap().as_nanos())
        });
        assert_eq!(
            (found(answer.unwrap()).entry, work),
            (Some(expected.clone()), (0, 0, 1)),
            "inode answers/work: N={total}"
        );
        inode_times.push(elapsed);
        let ((rows, elapsed), work) = measure_query(|| {
            let start = clock.start().unwrap();
            let directory = found(
                f.overlay
                    .query_directory(&f.store, &f.owner, &[name("d")])
                    .unwrap(),
            );
            let page = found(
                f.overlay
                    .query_children(&f.store, &f.owner, &directory.cursor)
                    .unwrap(),
            );
            (
                (
                    directory.directory.nlink,
                    page.entries.len(),
                    page.next.is_none(),
                ),
                clock.elapsed(&start).unwrap().as_nanos(),
            )
        });
        assert_eq!(
            (rows, work),
            ((2, 100, true), (0, 0, 101)),
            "fixed D=100 listing answers/work: N={total}"
        );
        listing_times.push(elapsed);
        cases += 1;
    }
    let (_, query, storage) = crate::overlay_store::work::measure(|| f.overlay.namespace.clone());
    assert_eq!(
        (
            cases,
            query,
            storage.namespace_clones,
            storage.primary_rows,
            storage.inverse_rows,
            storage.parent_buckets,
            storage.parent_memberships,
            storage.parent_counts,
            storage.path_bytes
        ),
        (
            100,
            QueryWork::default(),
            1,
            total,
            total,
            3,
            total,
            3,
            if total == 10_000 { 389_934 } else { 3_899_934 }
        ),
        "nonempty complete storage accounting: N={total}, storage={storage:?}"
    );
    for (route, mut times) in [
        ("path", path_times),
        ("inode", inode_times),
        ("directory", listing_times),
    ] {
        times.sort_unstable();
        eprintln!(
            "namespace measurement: N={total}, D=100, H=0, route={route}, calls={}, p50_ns={}, p95_ns={}, exhaustive_checker=false, production_guards=true",
            times.len(),
            times[49],
            times[94]
        );
    }
    eprintln!("namespace clone measurement: N={total}, A={storage:?}");
}

#[test]
fn indexed_namespace_scale_10000_keeps_fixed_directory_query_work() {
    namespace_scale(10_000);
}

#[test]
fn indexed_namespace_scale_100000_keeps_fixed_directory_query_work() {
    namespace_scale(100_000);
}
