// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::read` — byte-offset read planning over
//! inline and spilled grain lists.
//!
//! Out-of-line: `granary-vfs`'s non-test artifact has
//! workspace consumers (`granary-client`, `granary-fuse`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)] mod
//! tests;` — the sibling-directory form. This file also
//! declares `probes`, the module's second conforming test
//! body: a leaf nested under `tests`, not a second sibling
//! declaration in the parent.

use crate::{AttrPolicy, GrainFetch, GrainUnavailable, ServeLimits, Snapshot};
use granary_core::encoding::{self, ObjectType};
use granary_core::hash::GrainId;
use granary_core::manifest::{
    FILE_INLINE_MAX_REFS, FileGrains, GrainListIndexChild, GrainRef, TreeStats, build_dir,
    build_grain_list, decode_grain_list_index, encode_grain_list_index, encode_grain_list_leaf,
};
use granary_core::sheaf::Timestamp;
use std::collections::BTreeMap;

struct MapFetch {
    grains: BTreeMap<GrainId, Vec<u8>>,
}

struct CountingFetch {
    id: GrainId,
    bytes: Vec<u8>,
    calls: usize,
}

impl GrainFetch for MapFetch {
    fn grain(&mut self, id: &GrainId, _unpacked_len: u32) -> Result<Vec<u8>, GrainUnavailable> {
        self.grains
            .get(id)
            .cloned()
            .ok_or_else(|| GrainUnavailable::new(format!("missing test grain {id}")))
    }
}

impl GrainFetch for CountingFetch {
    fn grain(&mut self, id: &GrainId, _unpacked_len: u32) -> Result<Vec<u8>, GrainUnavailable> {
        assert_eq!(*id, self.id, "fixture only serves its repeated id");
        self.calls = self.calls.saturating_add(1);
        Ok(self.bytes.clone())
    }
}

fn snapshot(extra_nodes: impl IntoIterator<Item = (GrainId, Vec<u8>)>) -> Snapshot {
    let dir = build_dir(&[]).expect("empty fixture directory builds");
    let mut nodes = dir.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(extra_nodes);
    Snapshot::new(
        nodes,
        dir.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        ServeLimits::UNBOUNDED,
    )
    .expect("fixture snapshot indexes")
}

fn inline_fixture() -> (Snapshot, FileGrains, MapFetch, Vec<u8>) {
    let contents = [
        (0_u8..10).collect::<Vec<_>>(),
        (10_u8..30).collect::<Vec<_>>(),
        (30_u8..60).collect::<Vec<_>>(),
    ];
    let refs = contents
        .iter()
        .map(|bytes| GrainRef {
            id: GrainId::of(bytes),
            unpacked_len: u32::try_from(bytes.len()).expect("fixture length fits"),
        })
        .collect::<Vec<_>>();
    let fetched = refs
        .iter()
        .zip(&contents)
        .map(|(grain_ref, bytes)| (grain_ref.id, bytes.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected = contents.concat();
    (
        snapshot([]),
        FileGrains::Inline(refs),
        MapFetch { grains: fetched },
        expected,
    )
}

#[test]
fn inline_read_sweep_matches_concatenation() {
    let (snapshot, grains, mut fetch, expected) = inline_fixture();

    for offset in 0_u64..=60 {
        for size in 0_u32..=61 {
            let got = snapshot
                .read_at(&mut fetch, &grains, 60, offset, size)
                .unwrap_or_else(|error| {
                    panic!("offset={offset}, size={size}: unexpected {error:?}")
                });
            let start = usize::try_from(offset).expect("fixture offset fits");
            let end = start
                .saturating_add(usize::try_from(size).expect("fixture size fits"))
                .min(expected.len());
            assert_eq!(got, expected[start..end], "offset={offset}, size={size}");
        }
    }
}

#[test]
fn spilled_read_sweep_matches_concatenation() {
    let count = FILE_INLINE_MAX_REFS
        .checked_add(2)
        .expect("fixture count fits");
    let expected = (0..count)
        .map(|number| u8::try_from(number % 251).expect("modulo fits"))
        .collect::<Vec<_>>();
    let refs = expected
        .iter()
        .map(|byte| {
            let bytes = [*byte];
            GrainRef {
                id: GrainId::of(&bytes),
                unpacked_len: 1,
            }
        })
        .collect::<Vec<_>>();
    let split = 30_usize;
    let (left_refs, right_refs) = refs.split_at(split);
    let left_bytes = encode_grain_list_leaf(left_refs).expect("left leaf encodes");
    let right_bytes = encode_grain_list_leaf(right_refs).expect("right leaf encodes");
    let left_id = GrainId::of(&left_bytes);
    let right_id = GrainId::of(&right_bytes);
    let root_bytes = encode_grain_list_index(&[
        GrainListIndexChild {
            child: left_id,
            cum_unpacked_len: u64::try_from(split).expect("split fits"),
            cum_ref_count: u64::try_from(split).expect("split fits"),
        },
        GrainListIndexChild {
            child: right_id,
            cum_unpacked_len: u64::from(count),
            cum_ref_count: u64::from(count),
        },
    ])
    .expect("index root encodes");
    let root = GrainId::of(&root_bytes);
    let (object_type, cursor) = encoding::open_envelope(&root_bytes).expect("root envelope");
    assert_eq!(object_type, ObjectType::GrainListIndex);
    let children = decode_grain_list_index(cursor).expect("index root decodes");
    assert!(
        children.len() > 1,
        "fixture must have multiple leaf children"
    );

    let snapshot = snapshot([
        (left_id, left_bytes),
        (right_id, right_bytes),
        (root, root_bytes),
    ]);
    let grains = FileGrains::Spill {
        grain_count: count,
        root,
    };
    let fetched = expected
        .iter()
        .map(|byte| {
            let bytes = vec![*byte];
            (GrainId::of(&bytes), bytes)
        })
        .collect::<BTreeMap<_, _>>();
    let mut fetch = MapFetch { grains: fetched };

    for offset in 0_u64..=60 {
        for size in 0_u32..=61 {
            let got = snapshot
                .read_at(&mut fetch, &grains, u64::from(count), offset, size)
                .unwrap_or_else(|error| {
                    panic!("offset={offset}, size={size}: unexpected {error:?}")
                });
            let start = usize::try_from(offset).expect("fixture offset fits");
            let end = start
                .saturating_add(usize::try_from(size).expect("fixture size fits"))
                .min(expected.len());
            assert_eq!(got, expected[start..end], "offset={offset}, size={size}");
        }
    }
}

#[test]
fn eof_and_zero_size_reads_are_empty() {
    let (snapshot, grains, mut fetch, _expected) = inline_fixture();

    assert_eq!(
        snapshot.read_at(&mut fetch, &grains, 60, 60, 5),
        Ok(Vec::new())
    );
    assert_eq!(
        snapshot.read_at(&mut fetch, &grains, 60, 61, 5),
        Ok(Vec::new())
    );
    assert_eq!(
        snapshot.read_at(&mut fetch, &grains, 60, 15, 0),
        Ok(Vec::new())
    );
}

#[test]
fn read_plan_trims_first_and_last_grain() {
    let (snapshot, grains, _fetch, _expected) = inline_fixture();

    let planned = snapshot.read_plan(&grains, 60, 5, 35);
    assert!(planned.is_ok(), "read plan must succeed: {planned:?}");
    let plan = planned.expect("asserted successful plan");
    assert_eq!(
        plan,
        vec![
            super::GrainSlice {
                id: GrainId::of(&(0_u8..10).collect::<Vec<_>>()),
                unpacked_len: 10,
                skip: 5,
                take: 5,
            },
            super::GrainSlice {
                id: GrainId::of(&(10_u8..30).collect::<Vec<_>>()),
                unpacked_len: 20,
                skip: 0,
                take: 20,
            },
            super::GrainSlice {
                id: GrainId::of(&(30_u8..60).collect::<Vec<_>>()),
                unpacked_len: 30,
                skip: 0,
                take: 10,
            },
        ]
    );
}

#[test]
fn duplicate_grain_positions_are_each_fetched_once() {
    let bytes = b"xy".to_vec();
    let id = GrainId::of(&bytes);
    let grain_ref = GrainRef {
        id,
        unpacked_len: 2,
    };
    let grains = FileGrains::Inline(vec![grain_ref; 3]);
    let snapshot = snapshot([]);
    let mut fetch = CountingFetch {
        id,
        bytes,
        calls: 0,
    };

    let got = snapshot.read_at(&mut fetch, &grains, 6, 0, 6);
    assert_eq!(got, Ok(b"xyxyxy".to_vec()));
    assert_eq!(fetch.calls, 3, "each position in the plan must fetch");
}

#[test]
fn short_fetched_grain_is_inconsistent() {
    let declared = b"0123456789".to_vec();
    let id = GrainId::of(&declared);
    let grains = FileGrains::Inline(vec![GrainRef {
        id,
        unpacked_len: 10,
    }]);
    let snapshot = snapshot([]);
    let mut fetch = CountingFetch {
        id,
        bytes: b"012345678".to_vec(),
        calls: 0,
    };

    assert_eq!(
        snapshot.read_at(&mut fetch, &grains, 10, 0, 10),
        Err(crate::ReaderError::Inconsistent)
    );
}

#[test]
fn declared_size_past_real_grain_end_is_inconsistent() {
    let bytes = b"12345".to_vec();
    let id = GrainId::of(&bytes);
    let grains = FileGrains::Inline(vec![GrainRef {
        id,
        unpacked_len: 5,
    }]);
    let snapshot = snapshot([]);
    let mut fetch = MapFetch {
        grains: [(id, bytes)].into_iter().collect(),
    };

    assert_eq!(
        snapshot.read_at(&mut fetch, &grains, 10, 5, 1),
        Err(crate::ReaderError::Inconsistent)
    );
}

#[test]
fn read_spanning_too_many_grains_is_refused() {
    let count = super::READ_MAX_GRAINS
        .checked_add(1)
        .expect("fixture count fits");
    let grain_ref = GrainRef {
        id: GrainId::of(b"x"),
        unpacked_len: 1,
    };
    let refs = vec![grain_ref; count];
    let built = build_grain_list(&refs).expect("spill fixture builds");
    let snapshot = snapshot(built.nodes.clone());
    let grains = FileGrains::Spill {
        grain_count: u32::try_from(count).expect("fixture count fits u32"),
        root: built.root,
    };

    let planned = snapshot.read_plan(
        &grains,
        u64::try_from(count).expect("fixture size fits u64"),
        0,
        u32::try_from(count).expect("fixture size fits u32"),
    );
    let summary = planned.as_ref().map(Vec::len);
    assert!(
        matches!(planned, Err(crate::ReaderError::ReadTooFragmented)),
        "expected ReadTooFragmented, got {summary:?}"
    );
}

#[test]
fn spilled_cumulative_overflow_and_narrowing_are_refused() {
    let grain_ref = GrainRef {
        id: GrainId::of(b"z"),
        unpacked_len: 1,
    };
    let leaf_bytes = encode_grain_list_leaf(&[grain_ref]).expect("leaf encodes");
    let leaf_id = GrainId::of(&leaf_bytes);
    let nested_bytes = encode_grain_list_index(&[
        GrainListIndexChild {
            child: leaf_id,
            cum_unpacked_len: u64::MAX - 1,
            cum_ref_count: 1,
        },
        GrainListIndexChild {
            child: leaf_id,
            cum_unpacked_len: u64::MAX,
            cum_ref_count: 2,
        },
    ])
    .expect("nested index with strictly increasing declarations encodes");
    let nested_id = GrainId::of(&nested_bytes);
    let root_bytes = encode_grain_list_index(&[
        GrainListIndexChild {
            child: leaf_id,
            cum_unpacked_len: 2,
            cum_ref_count: 1,
        },
        GrainListIndexChild {
            child: nested_id,
            cum_unpacked_len: u64::MAX,
            cum_ref_count: 3,
        },
    ])
    .expect("root index with strictly increasing declarations encodes");
    let root = GrainId::of(&root_bytes);
    let snapshot = snapshot([
        (leaf_id, leaf_bytes),
        (nested_id, nested_bytes),
        (root, root_bytes),
    ]);
    let grains = FileGrains::Spill {
        grain_count: 3,
        root,
    };

    assert_eq!(
        snapshot.read_plan(&grains, 4, 2, 1),
        Err(crate::ReaderError::Inconsistent),
        "nested base + declared cumulative total must not wrap"
    );
    assert_eq!(
        super::checked_u32(u64::from(u32::MAX) + 1),
        Err(crate::ReaderError::Inconsistent),
        "offset narrowing must be checked"
    );
}

mod probes;
