// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Quality-lane extension probes (from review, not committed by the implementer).
//! Each one exists because a degenerate construction survived the shipped suite.
//!
//! Out-of-line, because a module's second conforming test body
//! becomes a leaf under `tests`, declared by `read/tests.rs`'s
//! `mod probes;` rather than a second sibling declaration in
//! the parent (`read.rs`). Nesting one level deeper under
//! `tests` changes what the `super` keyword reaches here, so
//! every such path in this file carries one extra `super`
//! segment relative to the same body inline in the parent.

use crate::{AttrPolicy, GrainFetch, GrainUnavailable, ReaderError, ServeLimits, Snapshot};
use granary_core::hash::GrainId;
use granary_core::manifest::{
    DirEntry, EntryKind, FileGrains, GrainListIndexChild, GrainRef, Name, TreeStats, build_dir,
    encode_grain_list_index, encode_grain_list_leaf, validate_dir_tree,
};
use granary_core::sheaf::Timestamp;
use std::collections::BTreeMap;

struct MapFetch {
    grains: BTreeMap<GrainId, Vec<u8>>,
    pointers: Vec<usize>,
}

impl GrainFetch for MapFetch {
    fn grain(&mut self, id: &GrainId, _unpacked_len: u32) -> Result<Vec<u8>, GrainUnavailable> {
        let out = self
            .grains
            .get(id)
            .cloned()
            .ok_or_else(|| GrainUnavailable::new("missing"))?;
        self.pointers.push(out.as_ptr() as usize);
        Ok(out)
    }
}

/// Returns exactly one byte MORE than the manifest declares.
struct OverlongFetch {
    bytes: Vec<u8>,
}

impl GrainFetch for OverlongFetch {
    fn grain(&mut self, _id: &GrainId, _unpacked_len: u32) -> Result<Vec<u8>, GrainUnavailable> {
        Ok(self.bytes.clone())
    }
}

fn snap(extra: impl IntoIterator<Item = (GrainId, Vec<u8>)>) -> Snapshot {
    let dir = build_dir(&[]).expect("empty dir builds");
    let mut nodes = dir.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(extra);
    Snapshot::new(
        nodes,
        dir.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        ServeLimits::UNBOUNDED,
    )
    .expect("snapshot indexes")
}

fn leaf(refs: &[GrainRef]) -> (GrainId, Vec<u8>) {
    let bytes = encode_grain_list_leaf(refs).expect("leaf encodes");
    (GrainId::of(&bytes), bytes)
}

fn index(children: &[GrainListIndexChild]) -> (GrainId, Vec<u8>) {
    let bytes = encode_grain_list_index(children).expect("index encodes");
    (GrainId::of(&bytes), bytes)
}

fn one_byte_refs(bytes: &[u8]) -> Vec<GrainRef> {
    bytes
        .iter()
        .map(|b| GrainRef {
            id: GrainId::of(&[*b]),
            unpacked_len: 1,
        })
        .collect()
}

fn one_byte_fetch(bytes: &[u8]) -> MapFetch {
    MapFetch {
        grains: bytes
            .iter()
            .map(|b| (GrainId::of(&[*b]), vec![*b]))
            .collect(),
        pointers: Vec::new(),
    }
}

/// Q1 — a fetch returning MORE bytes than the manifest declares must be
/// A `size` beyond [`READ_MAX_BYTES`] is REFUSED, and refused BEFORE
/// anything is allocated.
///
/// `READ_MAX_GRAINS` bounds the grain COUNT and not the byte length, so
/// without this bound `read_at` sized a `Vec<u8>` directly from the
/// untrusted `u32` `size` — up to ~4 GiB, zeroed, before a single grain
/// was fetched. The refusal is `ReadTooLarge` and NOT a clamp: clamping
/// would answer the read short, and the kernel zero-fills the remainder.
#[test]
fn oversized_read_is_refused_before_allocating() {
    let id = GrainId::of(b"0123456789");
    let grains = FileGrains::Inline(vec![GrainRef {
        id,
        unpacked_len: 10,
    }]);
    let mut fetch = MapFetch {
        grains: [(id, b"0123456789".to_vec())].into_iter().collect(),
        pointers: Vec::new(),
    };

    // One byte over the bound is REFUSED, and refused before any fetch.
    let over = super::super::READ_MAX_BYTES
        .checked_add(1)
        .expect("bound + 1 fits");
    assert_eq!(
        snap([]).read_at(&mut fetch, &grains, 10, 0, over),
        Err(ReaderError::ReadTooLarge),
        "a size past READ_MAX_BYTES must be refused, not clamped"
    );
    assert!(
        fetch.pointers.is_empty(),
        "the refusal must come BEFORE any grain is fetched, got {} fetches",
        fetch.pointers.len()
    );

    // The bound itself is still servable: this is a bound, not an
    // off-by-one. The file is 10 bytes, so the read is EOF-clamped and
    // returns those 10 rather than allocating READ_MAX_BYTES.
    assert_eq!(
        snap([]).read_at(&mut fetch, &grains, 10, 0, super::super::READ_MAX_BYTES),
        Ok(b"0123456789".to_vec()),
        "exactly READ_MAX_BYTES must still be servable"
    );
}

/// `Inconsistent`. Kills M9 (dropping the `grain.len() != declared_len`
/// check), which the shipped suite does not notice.
#[test]
fn overlong_fetched_grain_is_inconsistent() {
    let id = GrainId::of(b"0123456789");
    let grains = FileGrains::Inline(vec![GrainRef {
        id,
        unpacked_len: 10,
    }]);
    let mut fetch = OverlongFetch {
        bytes: b"0123456789X".to_vec(),
    };
    assert_eq!(
        snap([]).read_at(&mut fetch, &grains, 10, 0, 10),
        Err(ReaderError::Inconsistent),
        "an implementor returning MORE than unpacked_len broke its contract"
    );
}

/// Q2 — the VALUE of `READ_MAX_GRAINS`, not just the mechanism. The shipped
/// test derives its fixture from the constant, so raising the constant to
/// `1_000_000` keeps it green. This pins both sides of the boundary.
#[test]
fn read_max_grains_boundary_is_exact() {
    assert_eq!(
        super::super::READ_MAX_GRAINS,
        4096,
        "the resource bound is a decision, not an implementation detail"
    );
    let content = vec![7_u8; 4097];
    let refs = one_byte_refs(&content);
    let at_cap = FileGrains::Inline(refs.clone());
    let over_cap = FileGrains::Inline(refs);
    let s = snap([]);
    let ok = s.read_plan(&at_cap, 4097, 0, 4096);
    assert_eq!(
        ok.as_ref().map(Vec::len),
        Ok(4096),
        "exactly READ_MAX_GRAINS slices must be allowed"
    );
    assert_eq!(
        s.read_plan(&over_cap, 4097, 0, 4097),
        Err(ReaderError::ReadTooFragmented),
        "one slice past the bound must be refused"
    );
}

/// Q3 — the seek must cost O(depth), not O(offset). The technique: a
/// `#[cfg(test)]` decode counter. Nothing in the shipped suite can see an
/// implementation that descends to the leftmost leaf and walks.
#[test]
fn spill_seek_decodes_depth_not_offset() {
    // 16 leaves of 8 one-byte grains, 4 mid indexes of 4 leaves, 1 root.
    // 21 nodes, depth 3, 128 bytes.
    let content = (0_u8..128).collect::<Vec<_>>();
    let mut nodes = Vec::new();
    let mut leaf_ids = Vec::new();
    for chunk in content.chunks(8) {
        let (id, bytes) = leaf(&one_byte_refs(chunk));
        leaf_ids.push(id);
        nodes.push((id, bytes));
    }
    let mut mid_ids = Vec::new();
    for group in leaf_ids.chunks(4) {
        let children = group
            .iter()
            .enumerate()
            .map(|(n, id)| GrainListIndexChild {
                child: *id,
                cum_unpacked_len: (u64::try_from(n).expect("fits") + 1) * 8,
                cum_ref_count: (u64::try_from(n).expect("fits") + 1) * 8,
            })
            .collect::<Vec<_>>();
        let (id, bytes) = index(&children);
        mid_ids.push(id);
        nodes.push((id, bytes));
    }
    let root_children = mid_ids
        .iter()
        .enumerate()
        .map(|(n, id)| GrainListIndexChild {
            child: *id,
            cum_unpacked_len: (u64::try_from(n).expect("fits") + 1) * 32,
            cum_ref_count: (u64::try_from(n).expect("fits") + 1) * 32,
        })
        .collect::<Vec<_>>();
    let (root, root_bytes) = index(&root_children);
    nodes.push((root, root_bytes));
    let s = snap(nodes);
    let grains = FileGrains::Spill {
        grain_count: 128,
        root,
    };
    let mut fetch = one_byte_fetch(&content);

    let mut samples = Vec::new();
    for offset in [0_u64, 40, 96, 127] {
        crate::snapshot::reset_decodes();
        let got = s
            .read_at(&mut fetch, &grains, 128, offset, 1)
            .expect("single-byte read succeeds");
        let want = usize::try_from(offset).expect("fits");
        assert_eq!(got, vec![content[want]], "offset={offset}");
        samples.push((offset, crate::snapshot::decodes()));
    }
    println!("Q3 decodes by offset: {samples:?}");
    let max = samples.iter().map(|(_, d)| *d).max().expect("nonempty");
    assert!(
        max <= 4,
        "seek must decode O(depth) nodes (depth 3, DEPTH_MAX 16), got {samples:?}"
    );
}

/// Q4 — an index node whose `cum_unpacked_len` OVERSTATES a child's real
/// content is refused, because the descent now compares each node's real
/// extent against the one its parent declared.
#[test]
fn overstated_cum_unpacked_len_is_refused() {
    let left = b"AAAAAAAAAA".to_vec(); // 10 bytes
    let right = b"BBBBBBBBBBBBBBBBBBBB".to_vec(); // 20 bytes
    let (left_id, left_bytes) = leaf(&one_byte_refs(&left));
    let (right_id, right_bytes) = leaf(&one_byte_refs(&right));
    // LIE: left is declared to end at 5, though it really holds 10 bytes.
    let (root, root_bytes) = index(&[
        GrainListIndexChild {
            child: left_id,
            cum_unpacked_len: 5,
            cum_ref_count: 10,
        },
        GrainListIndexChild {
            child: right_id,
            cum_unpacked_len: 30,
            cum_ref_count: 30,
        },
    ]);
    let s = snap([
        (left_id, left_bytes),
        (right_id, right_bytes),
        (root, root_bytes),
    ]);
    let grains = FileGrains::Spill {
        grain_count: 30,
        root,
    };
    let mut all = left.clone();
    all.extend_from_slice(&right);
    let mut fetch = one_byte_fetch(&all);
    let got = s.read_at(&mut fetch, &grains, 30, 7, 1);
    println!("Q4 overstated cum, read(offset=7,size=1) -> {got:?} (truth = b'A')");
    // The overstated cumulative extent must be refused, rather than
    // serving bytes from the next leaf.
    assert_eq!(
        got,
        Err(ReaderError::Inconsistent),
        "an overstated cum is refused rather than served"
    );
}

/// Q4b — the same lie confined to ONE leaf, so that no later base is
/// shifted and no contiguity check can fire. This isolates the extent
/// comparison itself: a single-leaf spill whose root declares more
/// content than the leaf holds.
#[test]
fn an_overstated_leaf_extent_is_refused_with_no_later_leaf_to_disagree() {
    let only = b"AAAAAAAAAA".to_vec(); // 10 real bytes
    let other = b"BBBBBBBBBB".to_vec();
    let (only_id, only_bytes) = leaf(&one_byte_refs(&only));
    let (other_id, other_bytes) = leaf(&one_byte_refs(&other));
    // LIE: the FIRST child is declared to hold 12, though it holds 10.
    // The second child's cumulative is consistent with that lie, so the
    // total is self-consistent and only the leaf itself disagrees.
    let (root, root_bytes) = index(&[
        GrainListIndexChild {
            child: only_id,
            cum_unpacked_len: 12,
            cum_ref_count: 10,
        },
        GrainListIndexChild {
            child: other_id,
            cum_unpacked_len: 22,
            cum_ref_count: 20,
        },
    ]);
    let s = snap([
        (only_id, only_bytes),
        (other_id, other_bytes),
        (root, root_bytes),
    ]);
    let grains = FileGrains::Spill {
        grain_count: 20,
        root,
    };
    let mut all = only.clone();
    all.extend_from_slice(&other);
    let mut fetch = one_byte_fetch(&all);
    // Entirely inside the first leaf: nothing advances, so the
    // `leaf_base != position` contiguity check never runs.
    let got = s.read_at(&mut fetch, &grains, 22, 0, 4);
    println!("Q4b single-leaf overstate, read(offset=0,size=4) -> {got:?}");
    assert_eq!(got, Err(ReaderError::Inconsistent));
}

/// Q4c — a NESTED index whose declared extent lies. Every leaf is
/// internally consistent, so the fixture isolates the index-level extent
/// comparison from the leaf-level check.
///
/// The root declares 25 bytes for a child index whose own children sum
/// to 20. Every LEAF below is internally honest, so the leaf comparison
/// cannot fire; only the index-level one can.
#[test]
fn a_nested_index_that_overstates_its_child_index_is_refused() {
    let first = b"AAAAAAAAAA".to_vec(); // 10
    let second = b"BBBBBBBBBB".to_vec(); // 10
    let third = b"CCCCCCCCCC".to_vec(); // 10
    let (l1, l1_bytes) = leaf(&one_byte_refs(&first));
    let (l2, l2_bytes) = leaf(&one_byte_refs(&second));
    let (l3, l3_bytes) = leaf(&one_byte_refs(&third));
    // The child index is internally consistent: 10 then 20.
    let (child, child_bytes) = index(&[
        GrainListIndexChild {
            child: l1,
            cum_unpacked_len: 10,
            cum_ref_count: 10,
        },
        GrainListIndexChild {
            child: l2,
            cum_unpacked_len: 20,
            cum_ref_count: 20,
        },
    ]);
    // LIE, and it is at the INDEX level: the root promises the child
    // index ends at 25, though that subtree really ends at 20.
    let (root, root_bytes) = index(&[
        GrainListIndexChild {
            child,
            cum_unpacked_len: 25,
            cum_ref_count: 20,
        },
        GrainListIndexChild {
            child: l3,
            cum_unpacked_len: 35,
            cum_ref_count: 30,
        },
    ]);
    let s = snap([
        (l1, l1_bytes),
        (l2, l2_bytes),
        (l3, l3_bytes),
        (child, child_bytes),
        (root, root_bytes),
    ]);
    let grains = FileGrains::Spill {
        grain_count: 30,
        root,
    };
    let mut all = first.clone();
    all.extend_from_slice(&second);
    all.extend_from_slice(&third);
    let mut fetch = one_byte_fetch(&all);
    let got = s.read_at(&mut fetch, &grains, 35, 0, 4);
    println!("Q4c nested-index overstate, read(offset=0,size=4) -> {got:?}");
    assert_eq!(got, Err(ReaderError::Inconsistent));
}

/// Q9 — a lie in a leaf reached by ADVANCING, not by seeking. Every
/// other negative in this file dies inside `seek`; nothing exercised
/// `descend_first`'s leaf comparison, so neutering it left the whole
/// suite green. The first leaf is honest, the read starts inside it and
/// runs past its end, and the SECOND leaf is the one that lies.
#[test]
fn a_lying_leaf_reached_by_advancing_is_refused() {
    let a = b"AAAAAAAAAA".to_vec(); // 10 real
    let b = b"BBBBBBBBBB".to_vec(); // 10 real, declared 15
    let c = b"CCCCCCCCCC".to_vec(); // 10 real
    let (l1, l1b) = leaf(&one_byte_refs(&a));
    let (l2, l2b) = leaf(&one_byte_refs(&b));
    let (l3, l3b) = leaf(&one_byte_refs(&c));
    let (root, rootb) = index(&[
        GrainListIndexChild {
            child: l1,
            cum_unpacked_len: 10,
            cum_ref_count: 10,
        },
        GrainListIndexChild {
            child: l2,
            cum_unpacked_len: 25, // LIE: l2 really ends at 20
            cum_ref_count: 20,
        },
        GrainListIndexChild {
            child: l3,
            cum_unpacked_len: 35,
            cum_ref_count: 30,
        },
    ]);
    let s = snap([(l1, l1b), (l2, l2b), (l3, l3b), (root, rootb)]);
    let grains = FileGrains::Spill {
        grain_count: 30,
        root,
    };
    let mut all = a.clone();
    all.extend_from_slice(&b);
    all.extend_from_slice(&c);
    let mut fetch = one_byte_fetch(&all);
    // Starts in l1 and crosses into l2, so l2 is reached by `advance_leaf`
    // -> `descend_first`, never by `seek`.
    let got = s.read_at(&mut fetch, &grains, 35, 5, 10);
    println!("Q9 advance-path leaf lie, read(offset=5,size=10) -> {got:?}");
    assert_eq!(got, Err(ReaderError::Inconsistent));
}

/// Q10 — the same, one level up: the node reached by advancing is a
/// nested INDEX that lies about its own total. This is the only test of
/// `descend_first`'s index comparison.
#[test]
fn a_lying_nested_index_reached_by_advancing_is_refused() {
    let a = b"AAAAAAAAAA".to_vec(); // 10 real
    let b = b"BBBBB".to_vec(); // 5 real
    let c = b"CCCCC".to_vec(); // 5 real
    let (l1, l1b) = leaf(&one_byte_refs(&a));
    let (l2, l2b) = leaf(&one_byte_refs(&b));
    let (l3, l3b) = leaf(&one_byte_refs(&c));
    // Internally honest: 5 then 10, matching its leaves exactly.
    let (child, childb) = index(&[
        GrainListIndexChild {
            child: l2,
            cum_unpacked_len: 5,
            cum_ref_count: 5,
        },
        GrainListIndexChild {
            child: l3,
            cum_unpacked_len: 10,
            cum_ref_count: 10,
        },
    ]);
    let (root, rootb) = index(&[
        GrainListIndexChild {
            child: l1,
            cum_unpacked_len: 10,
            cum_ref_count: 10,
        },
        GrainListIndexChild {
            child,
            cum_unpacked_len: 30, // LIE: that subtree really ends at 20
            cum_ref_count: 20,
        },
    ]);
    let s = snap([
        (l1, l1b),
        (l2, l2b),
        (l3, l3b),
        (child, childb),
        (root, rootb),
    ]);
    let grains = FileGrains::Spill {
        grain_count: 20,
        root,
    };
    let mut all = a.clone();
    all.extend_from_slice(&b);
    all.extend_from_slice(&c);
    let mut fetch = one_byte_fetch(&all);
    let got = s.read_at(&mut fetch, &grains, 30, 5, 10);
    println!("Q10 advance-path index lie, read(offset=5,size=10) -> {got:?}");
    assert_eq!(got, Err(ReaderError::Inconsistent));
}

/// Q11 — the spill ROOT is the one node with no parent, and the entry
/// that names it supplies the declaration instead. Without that anchor a
/// root under-running its declared size is caught only indirectly.
#[test]
fn a_spill_root_that_disagrees_with_the_declared_file_size_is_refused() {
    let a = b"AAAAAAAAAA".to_vec();
    let b = b"BBBBBBBBBB".to_vec();
    let (l1, l1b) = leaf(&one_byte_refs(&a));
    let (l2, l2b) = leaf(&one_byte_refs(&b));
    let (root, rootb) = index(&[
        GrainListIndexChild {
            child: l1,
            cum_unpacked_len: 10,
            cum_ref_count: 10,
        },
        GrainListIndexChild {
            child: l2,
            cum_unpacked_len: 20,
            cum_ref_count: 20,
        },
    ]);
    let s = snap([(l1, l1b), (l2, l2b), (root, rootb)]);
    let grains = FileGrains::Spill {
        grain_count: 20,
        root,
    };
    let mut all = a.clone();
    all.extend_from_slice(&b);
    let mut fetch = one_byte_fetch(&all);
    // The tree really holds 20 bytes; the entry declares 30.
    // `validate_dir_tree` makes "tree total == declared size" an
    // invariant, so this disagreement is the root's own lie.
    let got = s.read_at(&mut fetch, &grains, 30, 0, 4);
    println!("Q11 root vs declared size, read(offset=0,size=4) -> {got:?}");
    assert_eq!(got, Err(ReaderError::Inconsistent));
    // CONTROL: the same tree with an HONEST declared size still reads.
    let mut fetch = one_byte_fetch(&all);
    assert_eq!(
        s.read_at(&mut fetch, &grains, 20, 0, 4),
        Ok(b"AAAA".to_vec()),
        "the anchor must not refuse a truthful root"
    );
}

/// Q5 — the UNDERSTATED direction. The descent compares declared and
/// real extents; the planner also checks `leaf_base != position`.
/// Q4b isolates the extent comparison.
#[test]
fn understated_cum_unpacked_len_measured() {
    let left = b"AAAAAAAAAA".to_vec();
    let right = b"BBBBBBBBBBBBBBBBBBBB".to_vec();
    let (left_id, left_bytes) = leaf(&one_byte_refs(&left));
    let (right_id, right_bytes) = leaf(&one_byte_refs(&right));
    // LIE: left is declared to end at 15, though it really holds 10 bytes.
    let (root, root_bytes) = index(&[
        GrainListIndexChild {
            child: left_id,
            cum_unpacked_len: 15,
            cum_ref_count: 10,
        },
        GrainListIndexChild {
            child: right_id,
            cum_unpacked_len: 30,
            cum_ref_count: 30,
        },
    ]);
    let s = snap([
        (left_id, left_bytes),
        (right_id, right_bytes),
        (root, root_bytes),
    ]);
    let grains = FileGrains::Spill {
        grain_count: 30,
        root,
    };
    let mut all = left.clone();
    all.extend_from_slice(&right);
    let mut fetch = one_byte_fetch(&all);
    let got = s.read_at(&mut fetch, &grains, 30, 7, 20);
    println!("Q5 understated cum, read(offset=7,size=20) -> {got:?}");
    assert_eq!(
        got,
        Err(ReaderError::Inconsistent),
        "an understated cum is refused"
    );
}

/// Q6 — the one-grain-at-a-time memory contract. `unsafe_code = forbid`
/// rules out a counting global allocator, so this observes allocator BLOCK
/// REUSE: if each grain is dropped before the next is fetched, the same
/// distinctively-sized block comes back.
#[test]
fn at_most_one_grain_is_resident() {
    let grain_len = 70_001_u32;
    let refs = (0_u8..16)
        .map(|n| GrainRef {
            id: GrainId::of(&[n]),
            unpacked_len: grain_len,
        })
        .collect::<Vec<_>>();
    let grains = FileGrains::Inline(refs);
    let fetched = (0_u8..16)
        .map(|n| {
            (
                GrainId::of(&[n]),
                vec![n; usize::try_from(grain_len).expect("fits")],
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut fetch = MapFetch {
        grains: fetched,
        pointers: Vec::new(),
    };
    let total = u64::from(grain_len) * 16;
    let got = snap([]).read_at(
        &mut fetch,
        &grains,
        total,
        0,
        u32::try_from(total).expect("fits"),
    );
    assert!(got.is_ok(), "read succeeds: {:?}", got.map(|v| v.len()));
    let distinct = fetch
        .pointers
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    println!(
        "Q6 grain buffers handed out: {} calls, {} distinct addresses",
        fetch.pointers.len(),
        distinct.len()
    );
    assert_eq!(fetch.pointers.len(), 16, "sixteen grains fetched");
    assert!(
        distinct.len() <= 4,
        "each grain must be dropped before the next is fetched, so the \
         allocator hands back the same block; {} distinct addresses out of \
         16 fetches means grains were held at once",
        distinct.len()
    );
}

/// Q8 — a lying index node must not splice bytes from a later leaf into
/// the answer.
///
/// The fixture lies about the first leaf's extent. The assertion
/// requires `Inconsistent`, without claiming which guard catches it.
/// Deleting `cursor.leaf_base != position` from `exact_spill_plan` left
/// every test in this crate passing, this row included, when it was
/// measured: the contiguity check is a backstop no row pins.
#[test]
fn a_lying_index_node_does_not_splice_a_later_leaf_into_the_answer() {
    let left = b"AAAAAAAAAA".to_vec(); // 10 real bytes
    let right = b"BCDEFGHIJKLMNOPQRSTU".to_vec(); // 20 real bytes
    let (left_id, left_bytes) = leaf(&one_byte_refs(&left));
    let (right_id, right_bytes) = leaf(&one_byte_refs(&right));
    // LIE: left is declared to end at 5 though it holds 10 bytes.
    let (root, root_bytes) = index(&[
        GrainListIndexChild {
            child: left_id,
            cum_unpacked_len: 5,
            cum_ref_count: 10,
        },
        GrainListIndexChild {
            child: right_id,
            cum_unpacked_len: 30,
            cum_ref_count: 30,
        },
    ]);
    let s = snap([
        (left_id, left_bytes),
        (right_id, right_bytes),
        (root, root_bytes),
    ]);
    let grains = FileGrains::Spill {
        grain_count: 30,
        root,
    };
    let mut all = left.clone();
    all.extend_from_slice(&right);
    let mut fetch = one_byte_fetch(&all);
    let got = s.read_at(&mut fetch, &grains, 30, 0, 15);
    println!("Q8 read(0,15) over a lying index -> {got:?}");
    assert_eq!(
        got,
        Err(ReaderError::Inconsistent),
        "a lying index must be refused as Inconsistent, never read back as \
         a spliced buffer (AAAAAAAAAA + right[5..10])"
    );
}

/// Q7 — is the shipped spilled-sweep fixture a tree the whole-tree
/// validator would accept? MEASURED, not argued.
#[test]
fn shipped_spill_fixture_versus_validate_dir_tree() {
    let count = 130_u32;
    let content = (0..count)
        .map(|n| u8::try_from(n % 251).expect("fits"))
        .collect::<Vec<_>>();
    let refs = one_byte_refs(&content);
    let (left_id, left_bytes) = leaf(refs.get(..30).expect("split"));
    let (right_id, right_bytes) = leaf(refs.get(30..).expect("split"));
    let (root, root_bytes) = index(&[
        GrainListIndexChild {
            child: left_id,
            cum_unpacked_len: 30,
            cum_ref_count: 30,
        },
        GrainListIndexChild {
            child: right_id,
            cum_unpacked_len: u64::from(count),
            cum_ref_count: u64::from(count),
        },
    ]);
    let entry = DirEntry {
        name: Name::new(b"f".to_vec()).expect("valid name"),
        kind: EntryKind::File {
            exec: false,
            size: u64::from(count),
            grains: FileGrains::Spill {
                grain_count: count,
                root,
            },
        },
    };
    let dir = build_dir(&[entry]).expect("dir builds");
    let mut map = dir.nodes.iter().cloned().collect::<BTreeMap<_, _>>();
    map.insert(left_id, left_bytes);
    map.insert(right_id, right_bytes);
    map.insert(root, root_bytes);
    let verdict = validate_dir_tree(&dir.root, &|id| map.get(id).cloned());
    println!("Q7 validate_dir_tree on the shipped spilled-sweep fixture: {verdict:?}");
    assert!(
        verdict.is_err(),
        "MEASURED: the fixture is decoder-valid but NOT validator-valid"
    );
}
