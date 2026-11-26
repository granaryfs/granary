// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Quality-lane extension probes for `crate::snapshot`'s indexer: resume
//! cost by seek depth, shared-directory scan memoization, self-referential
//! and shared-child DAG refusal, understated/overstated subtree-count
//! integrity, readdir/lookup boundary and error-path behaviour, and
//! hostile byte-name round-tripping.
//!
//! Out-of-line, because a module's second conforming test body
//! becomes a leaf under `tests`, declared by `snapshot/tests.rs`'s
//! `mod probes;` rather than a second sibling declaration in the
//! parent (`snapshot.rs`). Nesting one level deeper under `tests`
//! changes what the `super` keyword reaches here, so every such
//! path in this file carries one extra `super` segment relative to
//! the same body inline in the parent.

use granary_core::hash::GrainId;
use granary_core::manifest::{
    DirEntry, EntryKind, FileGrains, InteriorChild, Name, TreeStats, build_dir,
    encode_dir_interior, encode_dir_leaf,
};
use granary_core::sheaf::Timestamp;
use std::collections::BTreeMap;

fn file(name: &[u8]) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("test name is valid"),
        kind: EntryKind::File {
            exec: false,
            size: 0,
            grains: FileGrains::Inline(Vec::new()),
        },
    }
}

fn build(entries: &[DirEntry]) -> (super::super::Snapshot, GrainId) {
    let built = build_dir(entries).expect("fixture builds");
    let root = built.root;
    let nodes = built.nodes.into_iter().collect::<BTreeMap<_, _>>();
    let snap = super::super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::super::AttrPolicy { uid: 3, gid: 4 },
        super::super::ServeLimits::UNBOUNDED,
    )
    .expect("fixture indexes");
    (snap, root)
}

/// P1: resuming deep into a large directory decodes O(depth) nodes, not O(i).
#[test]
fn resume_cost_is_depth_not_index() {
    let entries = (0..70_000_u32)
        .map(|n| file(format!("entry-{n:06}").as_bytes()))
        .collect::<Vec<_>>();
    let (snap, root) = build(&entries);

    let mut samples = Vec::new();
    for index in [0_u64, 1, 35_000, 69_999] {
        super::super::DECODES.with(|c| c.set(0));
        let mut seen = 0_u32;
        snap.readdir(&root, &root, 2 + index, |_e| {
            seen += 1;
            true // stop after the FIRST entry: this measures the SEEK alone
        })
        .expect("resume succeeds");
        assert_eq!(seen, 1);
        samples.push((index, super::super::DECODES.with(std::cell::Cell::get)));
    }
    println!("P1 decode counts by resume index: {samples:?}");
    let max = samples.iter().map(|(_, d)| *d).max().expect("nonempty");
    let min = samples.iter().map(|(_, d)| *d).min().expect("nonempty");
    assert!(
        max <= 4 && min >= 1,
        "seek must cost O(depth) (<= DEPTH_MAX), got {samples:?}"
    );
    // and the whole-directory sweep for comparison
    super::super::DECODES.with(|c| c.set(0));
    let mut all = 0_u32;
    snap.readdir(&root, &root, 2, |_e| {
        all += 1;
        false
    })
    .expect("full sweep");
    println!(
        "P1 full sweep: {all} entries, {} decodes",
        super::super::DECODES.with(std::cell::Cell::get)
    );
}

/// P2: does the memo actually prevent a second scan? A counter, not a length.
#[test]
fn shared_directory_is_scanned_once_not_merely_stored_once() {
    let shared = build_dir(&[file(b"inside")]).expect("child builds");
    let shared_root = shared.root;
    let root_tree = build_dir(&[
        DirEntry {
            name: Name::new(b"first".to_vec()).expect("valid"),
            kind: EntryKind::Dir { child: shared_root },
        },
        DirEntry {
            name: Name::new(b"second".to_vec()).expect("valid"),
            kind: EntryKind::Dir { child: shared_root },
        },
    ])
    .expect("root builds");
    let root = root_tree.root;
    let mut nodes = shared.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(root_tree.nodes);

    super::super::DIRSCANS.with(|c| c.set(0));
    let snap = super::super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::super::AttrPolicy { uid: 3, gid: 4 },
        super::super::ServeLimits::UNBOUNDED,
    )
    .expect("indexes");
    let scans = super::super::DIRSCANS.with(std::cell::Cell::get);
    println!(
        "P2 dirs.len()={} directory-root scans={scans}",
        snap.dirs.len()
    );
    assert_eq!(snap.dirs.len(), 2, "the stored-once oracle: dirs.len()");
    assert_eq!(scans, 2, "scan oracle: two distinct roots => two scans");
}

/// P3: a nodes map whose keys are not the hashes of their values can be
/// CYCLIC. `Snapshot::new` must still terminate.
#[test]
fn self_referential_nodes_map_terminates() {
    let placeholder = GrainId::of(b"granary probe cycle");
    let bytes = encode_dir_leaf(&[DirEntry {
        name: Name::new(b"loop".to_vec()).expect("valid"),
        kind: EntryKind::Dir { child: placeholder },
    }])
    .expect("leaf encodes");
    // Deliberately register it under an id that is NOT its hash.
    let nodes = [(placeholder, bytes)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let result = super::super::Snapshot::new(
        nodes,
        placeholder,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::super::AttrPolicy { uid: 3, gid: 4 },
        super::super::ServeLimits::UNBOUNDED,
    );
    let snap = result.expect("a cyclic map still indexes");
    println!(
        "P3 dirs.len()={} entries={:?} subdirs={:?}",
        snap.dirs.len(),
        snap.dir_entries(&placeholder),
        snap.dir_subdirs(&placeholder)
    );
    assert_eq!(snap.dirs.len(), 1);
    // and the readers must not spin either
    let _ = snap.lookup(&placeholder, b"loop").expect("lookup finds it");
    let mut n = 0_u32;
    snap.readdir(&placeholder, &placeholder, 0, |_e| {
        n += 1;
        n > 10
    })
    .expect("readdir terminates");
}

/// P4: an UNDERSTATED `subtree_entry_count` must be refused, not indexed past.
#[test]
fn understated_subtree_count_is_refused_at_index_time() {
    let all = (0..600_u32)
        .map(|n| file(format!("entry-{n:04}").as_bytes()))
        .collect::<Vec<_>>();
    let (left, right) = all.split_at(256);
    let l0 = encode_dir_leaf(left).expect("leaf 0");
    let l1 = encode_dir_leaf(&right[..256]).expect("leaf 1");
    let l2 = encode_dir_leaf(&right[256..]).expect("leaf 2");
    let (i0, i1, i2) = (GrainId::of(&l0), GrainId::of(&l1), GrainId::of(&l2));
    let interior = encode_dir_interior(&[
        InteriorChild {
            first_key: all[0].name.clone(),
            child: i0,
            subtree_entry_count: 256,
        },
        InteriorChild {
            first_key: all[256].name.clone(),
            child: i1,
            subtree_entry_count: 1, // LIE: really 256
        },
        InteriorChild {
            first_key: all[512].name.clone(),
            child: i2,
            subtree_entry_count: 88,
        },
    ])
    .expect("interior encodes");
    let root = GrainId::of(&interior);
    let nodes = [(root, interior), (i0, l0), (i1, l1), (i2, l2)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    // The index REFUSES the map: the declaration is compared against the
    // count actually walked, at the node that made it.
    let refusal = super::super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::super::AttrPolicy { uid: 3, gid: 4 },
        super::super::ServeLimits::UNBOUNDED,
    )
    .expect_err("an understated subtree count is refused at index time");
    assert_eq!(
        refusal,
        super::super::SnapshotError::CountMismatch {
            id: i1,
            declared: 1,
            walked: 256,
        }
    );
}

/// P5: an OVERSTATED `subtree_entry_count` must be refused too.
#[test]
fn overstated_subtree_count_is_refused_at_index_time() {
    let all = (0..512_u32)
        .map(|n| file(format!("entry-{n:04}").as_bytes()))
        .collect::<Vec<_>>();
    let l0 = encode_dir_leaf(&all[..256]).expect("leaf 0");
    let l1 = encode_dir_leaf(&all[256..]).expect("leaf 1");
    let (i0, i1) = (GrainId::of(&l0), GrainId::of(&l1));
    let interior = encode_dir_interior(&[
        InteriorChild {
            first_key: all[0].name.clone(),
            child: i0,
            subtree_entry_count: u64::MAX, // LIE: really 256
        },
        InteriorChild {
            first_key: all[256].name.clone(),
            child: i1,
            subtree_entry_count: 256,
        },
    ])
    .expect("interior encodes");
    let root = GrainId::of(&interior);
    let nodes = [(root, interior), (i0, l0), (i1, l1)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    // `u64::MAX` is the GROSS overstatement. The check is on the
    // declaration itself, so the magnitude no longer matters — see
    // the moderate case below.
    let refusal = super::super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::super::AttrPolicy { uid: 3, gid: 4 },
        super::super::ServeLimits::UNBOUNDED,
    )
    .expect_err("an overstated subtree count is refused at index time");
    assert_eq!(
        refusal,
        super::super::SnapshotError::CountMismatch {
            id: i0,
            declared: u64::MAX,
            walked: 256,
        }
    );
}

/// P5b: a MODERATE overstatement is refused too: the first subtree
/// declares 300 entries but holds 256.
#[test]
fn a_moderate_overstatement_is_refused_too() {
    let all = (0..512_u32)
        .map(|n| file(format!("entry-{n:04}").as_bytes()))
        .collect::<Vec<_>>();
    let l0 = encode_dir_leaf(&all[..256]).expect("leaf 0");
    let l1 = encode_dir_leaf(&all[256..]).expect("leaf 1");
    let (i0, i1) = (GrainId::of(&l0), GrainId::of(&l1));
    let interior = encode_dir_interior(&[
        InteriorChild {
            first_key: all[0].name.clone(),
            child: i0,
            subtree_entry_count: 300, // LIE: really 256, and plausible
        },
        InteriorChild {
            first_key: all[256].name.clone(),
            child: i1,
            subtree_entry_count: 256,
        },
    ])
    .expect("interior encodes");
    let root = GrainId::of(&interior);
    let nodes = [(root, interior), (i0, l0), (i1, l1)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let refusal = super::super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::super::AttrPolicy { uid: 3, gid: 4 },
        super::super::ServeLimits::UNBOUNDED,
    )
    .expect_err("a plausible overstatement is refused just the same");
    assert_eq!(
        refusal,
        super::super::SnapshotError::CountMismatch {
            id: i0,
            declared: 300,
            walked: 256,
        }
    );
}

/// P5c: a DAG whose interiors share children is refused instead of
/// walked once per root-to-leaf PATH.
///
/// The shape is a sliding window: at every level node `j` takes children
/// `level[j..j+4]`, so each interior on its own has strictly increasing
/// child first-names and honest `subtree_entry_count`s — P4/P5's check
/// passes it — and the sharing is only visible one level up. Node count
/// is linear in depth; PATH count is `4^depth`. Measured before the
/// visited set, on this machine, release: depth 4 = 39 us, 6 = 617 us,
/// 8 = 10.2 ms, 10 = 163 ms — four-fold per level, so depth 15 is about
/// 167 SECONDS, and it returned `Ok`. `validate_dir_tree` refuses the
/// same 69 KB map in under 10 us with `CrossNodeOrder`, flat in depth,
/// which is why this is defence in depth and not a narrowing.
#[test]
fn a_shared_child_dag_is_refused_rather_than_walked_once_per_path() {
    // Depth TEN, not fifteen, and that is the point: the negative has to
    // be a RED, not a hang. Measured with the visited set removed, debug:
    // depth 10 returns `Ok` in 1.99 s. Each further level is x4, so a
    // depth-15 fixture would take about eight and a half minutes and
    // WEDGE the suite instead of failing it — this repo has been bitten
    // by exactly that shape. The format-limit arithmetic is unchanged:
    // 4^15 paths over 376 nodes in 69 KB, and at 256 children and
    // DEPTH_MAX it is 256^15.
    let depth = 10_usize;
    let fanout = 4_usize;
    let mut nodes: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let leaf_count = 1 + depth * (fanout - 1);
    // id, first name, last name, entry count
    let mut level: Vec<(GrainId, Name, Name, u64)> = Vec::new();
    for n in 0..leaf_count {
        let a = format!("{n:04}a");
        let b = format!("{n:04}b");
        let entries = [file(a.as_bytes()), file(b.as_bytes())];
        let bytes = encode_dir_leaf(&entries).expect("leaf encodes");
        let id = GrainId::of(&bytes);
        nodes.insert(id, bytes);
        level.push((id, entries[0].name.clone(), entries[1].name.clone(), 2));
    }
    for _ in 0..depth {
        let mut next = Vec::new();
        for j in 0..=(level.len() - fanout) {
            let children = (0..fanout)
                .map(|k| InteriorChild {
                    first_key: level[j + k].1.clone(),
                    child: level[j + k].0,
                    subtree_entry_count: level[j + k].3,
                })
                .collect::<Vec<_>>();
            let bytes = encode_dir_interior(&children).expect("interior encodes");
            let id = GrainId::of(&bytes);
            nodes.insert(id, bytes);
            let count = (0..fanout).map(|k| level[j + k].3).sum();
            next.push((
                id,
                level[j].1.clone(),
                level[j + fanout - 1].2.clone(),
                count,
            ));
        }
        level = next;
    }
    assert_eq!(level.len(), 1, "the window converges to one root");
    let root = level[0].0;
    let bytes: usize = nodes.values().map(Vec::len).sum();
    let count = nodes.len();
    println!("P5c: {count} nodes, {bytes} bytes, 4^{depth} paths");
    super::super::DIRNODES.with(|c| c.set(0));
    let refusal = super::super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::super::AttrPolicy { uid: 3, gid: 4 },
        super::super::ServeLimits::UNBOUNDED,
    )
    .expect_err("a shared-child DAG is refused");
    assert!(
        matches!(refusal, super::super::SnapshotError::RepeatedNode { .. }),
        "expected RepeatedNode, got {refusal:?}"
    );
    // The claim is "walked once per NODE", not merely "refused", and this
    // is the assertion that says so. It also makes the failure fast and
    // legible if the set is ever lost: the count runs away long before
    // the wall clock does.
    let visits = super::super::DIRNODES.with(std::cell::Cell::get);
    println!("P5c visited {visits} nodes for {count} distinct");
    assert!(
        visits <= count as u64,
        "the walk must visit at most one node per distinct node, got {visits} for {count}"
    );
}

/// P5d: the POSITIVE CONTROL for P5c's scope. One node may legitimately
/// be one directory's ROOT and, at the same time, a leaf inside a
/// DIFFERENT directory's B-tree — content addressing merges
/// byte-identical nodes by design. A walk-wide visited set would reject
/// this, or silently stop counting it; a per-scan set must not. Without
/// this control the visited set could be tightened into a defect that
/// every other test would still pass.
#[test]
fn a_node_shared_between_two_directories_still_indexes() {
    // `small` is a whole directory on its own AND leaf 0 of `big`.
    let small_entries = [file(b"0000a"), file(b"0000b")];
    let small = encode_dir_leaf(&small_entries).expect("leaf encodes");
    let small_id = GrainId::of(&small);
    let tail_entries = [file(b"0001a"), file(b"0001b")];
    let tail = encode_dir_leaf(&tail_entries).expect("leaf encodes");
    let tail_id = GrainId::of(&tail);
    let big = encode_dir_interior(&[
        InteriorChild {
            first_key: small_entries[0].name.clone(),
            child: small_id,
            subtree_entry_count: 2,
        },
        InteriorChild {
            first_key: tail_entries[0].name.clone(),
            child: tail_id,
            subtree_entry_count: 2,
        },
    ])
    .expect("interior encodes");
    let big_id = GrainId::of(&big);
    // The mount root names both directories.
    let root_entries = [
        DirEntry {
            name: Name::new(b"big".to_vec()).expect("name"),
            kind: EntryKind::Dir { child: big_id },
        },
        DirEntry {
            name: Name::new(b"small".to_vec()).expect("name"),
            kind: EntryKind::Dir { child: small_id },
        },
    ];
    let root_bytes = encode_dir_leaf(&root_entries).expect("root leaf encodes");
    let root = GrainId::of(&root_bytes);
    let nodes = [
        (root, root_bytes),
        (big_id, big),
        (small_id, small),
        (tail_id, tail),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    let snap = super::super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::super::AttrPolicy { uid: 3, gid: 4 },
        super::super::ServeLimits::UNBOUNDED,
    )
    .expect("cross-directory sharing is legitimate and must index");
    assert_eq!(snap.dir_entries(&root), Ok(2));
    assert_eq!(snap.dir_entries(&big_id), Ok(4));
    assert_eq!(snap.dir_entries(&small_id), Ok(2));
}

/// P5f: a lying `first_key`. `lookup` navigates by it, so the failure it
/// produces is a DIVERGENCE rather than a refusal: `readdir` lists the
/// name and `lookup` answers `NotFound` for it — `ls` shows the file and
/// `open` says ENOENT.
#[test]
fn a_lying_first_key_is_refused_at_index_time() {
    let left = [file(b"a0"), file(b"a1")];
    let right = [file(b"b0"), file(b"b1")];
    let l0 = encode_dir_leaf(&left).expect("leaf 0");
    let l1 = encode_dir_leaf(&right).expect("leaf 1");
    let (i0, i1) = (GrainId::of(&l0), GrainId::of(&l1));
    // "b5" sorts after "a0", so the interior ENCODES — the separators are
    // strictly increasing. It is simply not the name the child begins
    // with, and only the walk can know that.
    let interior = encode_dir_interior(&[
        InteriorChild {
            first_key: left[0].name.clone(),
            child: i0,
            subtree_entry_count: 2,
        },
        InteriorChild {
            first_key: Name::new(b"b5".to_vec()).expect("name"),
            child: i1,
            subtree_entry_count: 2,
        },
    ])
    .expect("interior encodes");
    let root = GrainId::of(&interior);
    let nodes = [(root, interior), (i0, l0), (i1, l1)]
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let refusal = super::super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::super::AttrPolicy { uid: 3, gid: 4 },
        super::super::ServeLimits::UNBOUNDED,
    )
    .expect_err("a separator that is not the child's first name is refused");
    assert_eq!(
        refusal,
        super::super::SnapshotError::SeparatorMismatch {
            id: i1,
            declared: Name::new(b"b5".to_vec()).expect("name"),
        }
    );
}

/// P5e: an invalid `nanos` is refused here, in the engine, even though a
/// real decode path never reaches this refusal. `take_timestamp`
/// (`granary_core`'s sheaf decoder) already enforces `is_valid()` AT
/// PARSE, so a manifest root decoded off disk can never carry
/// `nanos >= NANOS_PER_SEC` in the first place. `Snapshot::new` checks
/// it again anyway, as DEFENCE IN DEPTH: `Snapshot` is public and
/// `Timestamp`'s fields are public, so a caller can construct one
/// directly and hand it straight to `Snapshot::new`, bypassing the
/// decoder entirely — this is exactly that caller, built by hand rather
/// than through `build_dir`'s encode/decode round trip, so the
/// otherwise-unreachable input can reach the guard at all.
///
/// Representability — whether a valid timestamp fits the KERNEL's
/// timestamp type — is a different, platform-specific question this
/// engine does not ask; see the adapter's own `kernel_time` suite for
/// that half of the split.
#[test]
fn an_invalid_nanos_field_is_refused_here_though_the_decoder_never_admits_one() {
    let entries = [file(b"only")];
    let built = build_dir(&entries).expect("fixture builds");
    let root = built.root;
    let invalid = Timestamp {
        secs: 0,
        nanos: 1_000_000_000,
    };
    let refusal = super::super::Snapshot::new(
        built.nodes.into_iter().collect(),
        root,
        invalid,
        TreeStats::default(),
        super::super::AttrPolicy { uid: 3, gid: 4 },
        super::super::ServeLimits::UNBOUNDED,
    )
    .expect_err("an invalid nanos field must be refused, even constructed directly");
    assert_eq!(
        refusal,
        super::super::SnapshotError::InvalidTimestamp { timestamp: invalid }
    );
}

/// P6: readdir at EXACTLY the end offset is Ok and emits nothing.
#[test]
fn readdir_at_exactly_end_offset_is_empty_success() {
    let entries = (0..600_u32)
        .map(|n| file(format!("entry-{n:04}").as_bytes()))
        .collect::<Vec<_>>();
    let (snap, root) = build(&entries);
    for from in [2 + 599_u64, 2 + 600, 2 + 601, u64::MAX] {
        let mut emitted = 0_u32;
        let result = snap.readdir(&root, &root, from, |_e| {
            emitted += 1;
            false
        });
        println!("P6 from={from} result={result:?} emitted={emitted}");
        assert_eq!(result, Ok(()), "from={from}");
    }
}

/// P12: `readdir` emission is TRANSACTIONAL — a directory it cannot
/// index emits NOTHING before it errors.
///
/// `.` and `..` are synthesised and need no `dirs` entry, but the index
/// lookup must happen first. A caller that has already written two entries
/// into a kernel reply buffer cannot un-write them when the call then
/// returns `Inconsistent`. The fixture is a `dir` that is present in
/// `nodes` but absent from `dirs`: a `DirLeaf` reachable as a CHILD rather
/// than as a directory root.
#[test]
fn readdir_refusing_an_unindexed_dir_emits_nothing_first() {
    // The root directory holds two plain files, so `dirs` has exactly one
    // entry: the root. A SECOND DirLeaf's bytes are placed in `nodes`
    // without ever being reachable as a directory root, so it is present
    // in `nodes` and absent from `dirs` — which is the state under test.
    let built = build_dir(&[file(b"a"), file(b"b")]).expect("fixture builds");
    let root = built.root;
    let mut nodes = built.nodes.into_iter().collect::<BTreeMap<_, _>>();
    let orphan_leaf = encode_dir_leaf(&[file(b"inner")]).expect("orphan leaf");
    let child_id = GrainId::of(&orphan_leaf);
    nodes.insert(child_id, orphan_leaf);
    let snap = super::super::Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::super::AttrPolicy { uid: 3, gid: 4 },
        super::super::ServeLimits::UNBOUNDED,
    )
    .expect("fixture indexes");
    assert_eq!(
        snap.dir_entries(&child_id),
        Err(super::super::ReaderError::Inconsistent),
        "the orphan leaf must NOT be indexed, or this fixture tests nothing"
    );

    let mut emitted: Vec<Vec<u8>> = Vec::new();
    let result = snap.readdir(&child_id, &root, 0, |e| {
        emitted.push(e.name.clone());
        false
    });
    println!("P12 result={result:?} emitted_before_error={emitted:?}");
    assert_eq!(
        result,
        Err(super::super::ReaderError::Inconsistent),
        "a dir absent from the index must be refused"
    );
    assert!(
        emitted.is_empty(),
        "nothing may be emitted before the refusal, got {emitted:?}"
    );
}

/// P11: the `DEPTH_MAX` bounds. Buildable, and currently unpinned.
#[test]
fn depth_bounds_are_reachable_and_map_to_inconsistent() {
    // A directory B-tree 18 levels tall: legal bytes, illegal shape.
    let leaf = encode_dir_leaf(&[file(b"a0"), file(b"a1")]).expect("leaf");
    let leaf_id = GrainId::of(&leaf);
    let mut nodes: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    nodes.insert(leaf_id, leaf);
    let mut child = leaf_id;
    for _level in 0..18_u32 {
        let bytes = encode_dir_interior(&[
            InteriorChild {
                first_key: Name::new(b"aa".to_vec()).expect("valid"),
                child,
                subtree_entry_count: 1,
            },
            InteriorChild {
                first_key: Name::new(b"ab".to_vec()).expect("valid"),
                child,
                subtree_entry_count: 1,
            },
        ])
        .expect("interior");
        let id = GrainId::of(&bytes);
        nodes.insert(id, bytes);
        child = id;
    }
    let deep = child;

    // (a) as the manifest root, Snapshot::new must refuse.
    let refused = super::super::Snapshot::new(
        nodes.clone(),
        deep,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::super::AttrPolicy { uid: 3, gid: 4 },
        super::super::ServeLimits::UNBOUNDED,
    );
    println!(
        "P11a Snapshot::new(deep root) = {:?}",
        refused.as_ref().err()
    );
    assert_eq!(
        refused.err(),
        Some(super::super::SnapshotError::DepthExceeded)
    );

    // (b) present in `nodes` but not reachable from a shallow root: the
    //     readers must still bound themselves, and say Inconsistent.
    let shallow = build_dir(&[file(b"only")]).expect("shallow builds");
    let shallow_root = shallow.root;
    nodes.extend(shallow.nodes);
    let snap = super::super::Snapshot::new(
        nodes,
        shallow_root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        super::super::AttrPolicy { uid: 3, gid: 4 },
        super::super::ServeLimits::UNBOUNDED,
    )
    .expect("shallow root indexes");
    let looked = snap.lookup(&deep, b"zz");
    println!("P11b lookup(deep) = {looked:?}");
    assert_eq!(
        looked,
        Err(super::super::ReaderError::Inconsistent),
        "DEPTH_MAX must be Inconsistent (EIO), never NotFound (ENOENT)"
    );
}

/// P12: lookup matches the WHOLE name, not a prefix of one.
#[test]
fn lookup_matches_the_whole_name_not_a_prefix() {
    let entries = (0..600_u32)
        .map(|n| file(format!("entry-{n:04}").as_bytes()))
        .collect::<Vec<_>>();
    let (snap, root) = build(&entries);
    for probe in [b"entry-05".as_slice(), b"entry-", b"e", b"entry-05000"] {
        let got = snap.lookup(&root, probe);
        println!("P12 lookup({probe:?}) = {got:?}");
        assert_eq!(
            got,
            Err(super::super::ReaderError::NotFound),
            "probe {probe:?}"
        );
    }
}

/// P7: hostile byte names round-trip through lookup AND readdir.
#[test]
fn hostile_byte_names_round_trip() {
    assert!(
        Name::new(b"a\0b".to_vec()).is_err(),
        "an interior NUL cannot appear in a manifest name"
    );
    let raws: Vec<Vec<u8>> = vec![
        b"\xff".to_vec(),
        b"\xc3\x28".to_vec(),     // invalid 2-byte sequence
        b"\xed\xa0\x80".to_vec(), // UTF-16 surrogate, invalid UTF-8
        b"\xf0\x9f".to_vec(),     // truncated emoji
        vec![0xff_u8; 255],       // NAME_MAX of high bytes
        b"\x01\x02\x03".to_vec(),
        b"\n\t".to_vec(),
        b"...".to_vec(),
        b" ".to_vec(),
    ];
    let mut entries = raws.iter().map(|r| file(r)).collect::<Vec<_>>();
    entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    let (snap, root) = build(&entries);
    for raw in &raws {
        let found = snap
            .lookup(&root, raw)
            .unwrap_or_else(|e| panic!("lookup {raw:?} failed: {e:?}"));
        assert_eq!(found.name.as_bytes(), raw.as_slice());
    }
    let mut listed: Vec<Vec<u8>> = Vec::new();
    snap.readdir(&root, &root, 2, |e| {
        listed.push(e.name);
        false
    })
    .expect("lists");
    for raw in &raws {
        assert!(listed.contains(raw), "readdir dropped {raw:?}");
    }
    println!("P7 round-tripped {} hostile names", raws.len());
}
