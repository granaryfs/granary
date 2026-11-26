// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Manifest encode/decode/build/validate properties. Seed+len idiom:
//! generate
//! (seed, len) pairs and fill deterministically rather than a direct
//! `Vec<u8>` strategy — cases stay fast and shrink usefully.

#![expect(
    clippy::unwrap_used,
    reason = "the reencode dispatch helper sits outside #[test] fns (test code, standards rule 3)"
)]

use std::collections::{BTreeMap, BTreeSet};

use granary_core::encoding::{self, ObjectType};
use granary_core::hash::GrainId;
use granary_core::manifest::{
    BuiltTree, DirEntry, EntryKind, FileGrains, GrainRef, Name, build_dir, decode_dir_interior,
    decode_dir_leaf, encode_dir_interior, encode_dir_leaf, validate_dir_tree,
};
use granary_core::testkit;
use proptest::prelude::*;

fn nm(s: &str) -> Name {
    Name::new(s.as_bytes().to_vec()).unwrap_or_else(|e| panic!("{e}"))
}

/// Decode one object by its envelope-declared type and re-encode it.
/// `build_dir` over inline-only files (every strategy below stays at or
/// under K=128 grains per file) never emits `GrainListLeaf`/`Index`
/// nodes, so those arms are unreachable for this file's inputs.
fn reencode(bytes: &[u8]) -> Vec<u8> {
    let (ty, cursor) = encoding::open_envelope(bytes).unwrap();
    match ty {
        ObjectType::DirLeaf => {
            let entries = decode_dir_leaf(cursor).unwrap();
            encode_dir_leaf(&entries).unwrap()
        }
        ObjectType::DirInterior => {
            let children = decode_dir_interior(cursor).unwrap();
            encode_dir_interior(&children).unwrap()
        }
        ObjectType::GrainListLeaf
        | ObjectType::GrainListIndex
        | ObjectType::Bin
        | ObjectType::BinmapIndex
        | ObjectType::BinTable
        | ObjectType::BinmapShard
        | ObjectType::Root
        | ObjectType::Sheaf => {
            unreachable!("manifest-node builders never produce these object types")
        }
    }
}

/// Build a small deterministic inline-file `DirEntry` for `name`, with
/// `grain_count` grains (0..=5) whose ids come from `testkit::fill`.
fn file_entry(name: Name, salt: u64, grain_count: u32) -> DirEntry {
    let refs: Vec<GrainRef> = (0..grain_count)
        .map(|j| {
            let seed = salt.wrapping_mul(1_000_003).wrapping_add(u64::from(j));
            GrainRef {
                id: GrainId::of(&testkit::fill(seed, 4)),
                unpacked_len: 1 + j,
            }
        })
        .collect();
    let size = refs.iter().map(|r| u64::from(r.unpacked_len)).sum();
    DirEntry {
        name,
        kind: EntryKind::File {
            exec: false,
            size,
            grains: FileGrains::Inline(refs),
        },
    }
}

/// xorshift64-driven Fisher-Yates — deterministic given `seed`, no
/// ambient entropy (not a determinism-seam violation: caller supplies
/// the seed, same discipline as `testkit::fill`).
fn seeded_shuffle<T>(items: &mut [T], seed: u64) {
    let mut state = if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    };
    for i in (1..items.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "i+1 <= items.len(), no overflow at test-relevant sizes"
        )]
        let idx = state % (i as u64 + 1);
        // idx <= i <= items.len(), always in usize range; the fallback
        // is unreachable, not a correctness hedge.
        let j = usize::try_from(idx).unwrap_or(i);
        items.swap(i, j);
    }
}

/// A generated directory TREE: this directory's own inline files
/// (name bytes, grain count) and its subdirectories, each a `DirSpec`
/// under a name. A flat single-directory strategy
/// cannot observe a CROSS-DIRECTORY cursor defect at all — the
/// walk never descends, so a mutation in `resume`'s worklist handling
/// leaves every case green. Nesting
/// is what gives the row its shrinker.
#[derive(Debug, Clone)]
struct DirSpec {
    files: Vec<(Vec<u8>, u32)>,
    subdirs: Vec<(Vec<u8>, DirSpec)>,
}

/// Directory trees at most 3 levels deep, at most 4 subdirectories and
/// at most 40 inline files per directory (0..=3 grains each). Small on
/// purpose: the row drives every case up to five times (a reference
/// walk plus two cursor drives over two residency policies), and the
/// shapes that matter here are structural, not wide.
fn dir_spec() -> impl Strategy<Value = DirSpec> {
    let files = || {
        proptest::collection::vec(
            (proptest::collection::vec(any::<u8>(), 1..=16), 0u32..=3),
            0..=40,
        )
    };
    files()
        .prop_map(|files| DirSpec {
            files,
            subdirs: Vec::new(),
        })
        .prop_recursive(3, 64, 4, move |inner| {
            (
                files(),
                proptest::collection::vec(
                    (proptest::collection::vec(any::<u8>(), 1..=16), inner),
                    0..=4,
                ),
            )
                .prop_map(|(files, subdirs)| DirSpec { files, subdirs })
        })
}

/// Build `spec` bottom-up (every child directory is built and stored
/// BEFORE the parent that names it, so the store holds every node),
/// returning the root id. Names that `Name::new` rejects are dropped;
/// a subdirectory wins a name collision with a file.
fn build_spec(
    spec: &DirSpec,
    salt: u64,
    counter: &mut u64,
    store: &mut BTreeMap<GrainId, Vec<u8>>,
) -> GrainId {
    let mut by_name: BTreeMap<Name, DirEntry> = BTreeMap::new();
    for (name_bytes, sub) in &spec.subdirs {
        let Ok(n) = Name::new(name_bytes.clone()) else {
            continue;
        };
        let child = build_spec(sub, salt, counter, store);
        by_name.insert(
            n.clone(),
            DirEntry {
                name: n,
                kind: EntryKind::Dir { child },
            },
        );
    }
    for (name_bytes, grain_count) in &spec.files {
        let Ok(n) = Name::new(name_bytes.clone()) else {
            continue;
        };
        *counter = counter.wrapping_add(1);
        let salt = salt.wrapping_add(*counter);
        by_name
            .entry(n.clone())
            .or_insert_with(|| file_entry(n, salt, *grain_count));
    }
    let entries: Vec<DirEntry> = by_name.into_values().collect();
    let built = build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    for (id, bytes) in &built.nodes {
        store.insert(*id, bytes.clone());
    }
    built.root
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Arbitrary valid entry vecs (<= 600 entries, names from a byte-
    /// string strategy filtered through `Name::new`, files <= 5 inline
    /// grains) -> build_dir -> every node's `encode(decode(bytes)) ==
    /// bytes`; `validate_dir_tree` (fetch from the node map) == Ok with
    /// a matching entry count.
    #[test]
    fn roundtrip_and_validates(
        raw in proptest::collection::vec(
            (proptest::collection::vec(any::<u8>(), 1..=16), 0u32..=5),
            0..=600,
        ),
        salt in any::<u64>(),
    ) {
        let mut by_name: BTreeMap<Name, u32> = BTreeMap::new();
        for (name_bytes, grain_count) in raw {
            if let Ok(n) = Name::new(name_bytes) {
                by_name.insert(n, grain_count);
            }
        }
        let entries: Vec<DirEntry> = by_name
            .into_iter()
            .enumerate()
            .map(|(i, (name, grain_count))| {
                file_entry(name, salt.wrapping_add(i as u64), grain_count)
            })
            .collect();
        let entry_count = entries.len() as u64;

        let built = build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
        for (id, bytes) in &built.nodes {
            prop_assert_eq!(&reencode(bytes), bytes);
            prop_assert_eq!(GrainId::of(bytes), *id);
        }

        let map: BTreeMap<GrainId, Vec<u8>> = built.nodes.iter().cloned().collect();
        let stats = validate_dir_tree(&built.root, &|id| map.get(id).cloned())
            .unwrap_or_else(|e| panic!("{e}"));
        prop_assert_eq!(stats.entries, entry_count);
    }

    /// Determinism: build twice from the same entries in two DIFFERENT
    /// insertion orders (each sorted before building) -> identical root
    /// id. Insertion-order independence of the bulk-load is true by
    /// construction (the encoder demands pre-sorted input) but pinned
    /// here as a regression guard.
    #[test]
    fn build_dir_is_independent_of_pre_sort_insertion_order(
        raw in proptest::collection::vec(
            (proptest::collection::vec(any::<u8>(), 1..=12), 0u32..=3),
            1..=200,
        ),
        salt in any::<u64>(),
        shuffle_seed in any::<u64>(),
    ) {
        let mut by_name: BTreeMap<Name, u32> = BTreeMap::new();
        for (name_bytes, grain_count) in raw {
            if let Ok(n) = Name::new(name_bytes) {
                by_name.insert(n, grain_count);
            }
        }
        let base: Vec<DirEntry> = by_name
            .into_iter()
            .enumerate()
            .map(|(i, (name, grain_count))| {
                file_entry(name, salt.wrapping_add(i as u64), grain_count)
            })
            .collect();
        prop_assume!(!base.is_empty());

        let mut order_a = base.clone();
        let mut order_b = base;
        seeded_shuffle(&mut order_b, shuffle_seed);
        order_a.sort_by(|x, y| x.name.cmp(&y.name));
        order_b.sort_by(|x, y| x.name.cmp(&y.name));

        let built_a = build_dir(&order_a).unwrap_or_else(|e| panic!("{e}"));
        let built_b = build_dir(&order_b).unwrap_or_else(|e| panic!("{e}"));
        prop_assert_eq!(built_a.root, built_b.root);
        prop_assert_eq!(built_a.nodes, built_b.nodes);
    }

    /// The content tree's pinned property: build a 3-level tree (dirs a/b/c with
    /// files), then rename the TOP-level dir key (re-parent the same
    /// child id under a new name) -> every descendant subtree id under
    /// "a" is UNCHANGED. `tree_a`/`tree_b`/`tree_c` are rebuilt fresh
    /// for each side from the same seed (not reused as one Rust value)
    /// so the equality below is a genuine cross-build check, not
    /// definitional reuse.
    #[test]
    fn rename_top_level_dir_preserves_descendant_subtree_ids(
        seed in any::<u64>(),
        old_name in "[a-z]{1,8}",
        new_name in "[a-z]{1,8}",
    ) {
        prop_assume!(old_name != new_name);

        let build_abc = |seed: u64| -> (BuiltTree, BuiltTree, BuiltTree) {
            let tree_c = build_dir(&[file_entry(nm("f"), seed, 2)]).unwrap_or_else(|e| panic!("{e}"));
            let tree_b = build_dir(&[DirEntry {
                name: nm("c"),
                kind: EntryKind::Dir { child: tree_c.root },
            }])
            .unwrap_or_else(|e| panic!("{e}"));
            let tree_a = build_dir(&[DirEntry {
                name: nm("b"),
                kind: EntryKind::Dir { child: tree_b.root },
            }])
            .unwrap_or_else(|e| panic!("{e}"));
            (tree_a, tree_b, tree_c)
        };

        let (tree_a_old, tree_b_old, tree_c_old) = build_abc(seed);
        let (tree_a_new, tree_b_new, tree_c_new) = build_abc(seed);

        // Purity/determinism: independent rebuilds from the same seed
        // agree. Because ids are a Merkle chain (a's leaf bytes embed
        // b's root id, b's embed c's), this single equality already
        // implies b and c matched too — any difference downstream
        // would have propagated up and broken it.
        prop_assert_eq!(tree_a_old.root, tree_a_new.root);

        let mut descendant_ids: BTreeSet<GrainId> = BTreeSet::new();
        for t in [&tree_a_old, &tree_b_old, &tree_c_old] {
            descendant_ids.extend(t.nodes.iter().map(|(id, _)| *id));
        }

        let root_old = build_dir(&[DirEntry {
            name: nm(&old_name),
            kind: EntryKind::Dir { child: tree_a_old.root },
        }])
        .unwrap_or_else(|e| panic!("{e}"));
        let root_new = build_dir(&[DirEntry {
            name: nm(&new_name),
            kind: EntryKind::Dir { child: tree_a_new.root },
        }])
        .unwrap_or_else(|e| panic!("{e}"));

        // The rename DID change the top node.
        prop_assert_ne!(root_old.root, root_new.root);

        let mut full_old: BTreeSet<GrainId> = root_old.nodes.iter().map(|(id, _)| *id).collect();
        full_old.extend(descendant_ids.iter().copied());
        let mut full_new: BTreeSet<GrainId> = root_new.nodes.iter().map(|(id, _)| *id).collect();
        full_new.extend(tree_a_new.nodes.iter().map(|(id, _)| *id));
        full_new.extend(tree_b_new.nodes.iter().map(|(id, _)| *id));
        full_new.extend(tree_c_new.nodes.iter().map(|(id, _)| *id));

        let intersection: BTreeSet<GrainId> = full_old.intersection(&full_new).copied().collect();
        prop_assert_eq!(intersection, descendant_ids);
    }

    /// The verdict is independent of the order objects become resident:
    /// an arbitrary valid directory TREE (nested, so a cross-directory
    /// defect is observable at all), an arbitrary initially-resident
    /// subset, and optionally one object deleted from the store, driven
    /// (a) one-shot over the store, (b) by the cursor fetching one `Need`
    /// per round, (c) by the cursor fetching every hint too — must agree
    /// exactly (`Ok(stats)` equal, or the same first error). The
    /// INDEPENDENT oracle (the pre-cursor walker) lives in granary-core's
    /// own tests; this row's value is the shrinker: a disagreeing tree
    /// comes back NESTED and small — not necessarily minimal. Measured
    /// under the skip-on-`Need` mutant: shrinking aborts at
    /// `PROPTEST_MAX_SHRINK_ITERS` (512) with files still attached.
    #[test]
    fn verdict_is_independent_of_residency_order(
        spec in dir_spec(),
        salt in any::<u64>(),
        resident_bits in proptest::collection::vec(any::<bool>(), 0..=64),
        delete_one in proptest::option::of(0usize..64),
    ) {
        use granary_core::manifest::{PREFETCH_HINT_MAX, Step, TreeCursor, ValidateError};
        use std::cell::RefCell;
        let mut store: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
        let mut counter = 0u64;
        let root = build_spec(&spec, salt, &mut counter, &mut store);
        let ids: Vec<GrainId> = store.keys().copied().collect();
        if let Some(k) = delete_one
            && let Some(victim) = ids.get(k % ids.len().max(1))
        {
            store.remove(victim);
        }
        let initial: BTreeMap<GrainId, Vec<u8>> = ids
            .iter()
            .zip(resident_bits.iter().chain(std::iter::repeat(&false)))
            .filter(|&(_, &keep)| keep)
            .filter_map(|(id, _)| store.get(id).map(|b| (*id, b.clone())))
            .collect();

        let reference = validate_dir_tree(&root, &|id| store.get(id).cloned());

        for hints in [false, true] {
            let resident = RefCell::new(initial.clone());
            let mut cursor = TreeCursor::new(root);
            let got = loop {
                let step = cursor.resume(&|id| resident.borrow().get(id).cloned());
                match step {
                    Err(e) => break Err(e),
                    Ok(Step::Done(stats)) => break Ok(stats),
                    Ok(Step::Need(id)) => match store.get(&id) {
                        Some(bytes) => {
                            // The in-tree drives and `manifest_walk_probe`
                            // both carry this. It matters MOST here:
                            // `.config/nextest.toml` gives no slow-timeout
                            // override to `granary-bench`, so a cursor that
                            // re-emits `Need` for a resident id spins until
                            // the CI job's own timeout rather than being
                            // terminated with a name.
                            prop_assert!(
                                !resident.borrow().contains_key(&id),
                                "a Need for a resident id is an unstable fetch"
                            );
                            resident.borrow_mut().insert(id, bytes.clone());
                            if hints {
                                let wanted = cursor.prefetch_hints(&|id| resident.borrow().get(id).cloned(), PREFETCH_HINT_MAX);
                                let mut r = resident.borrow_mut();
                                for h in wanted.entering.into_iter().chain(wanted.queued_roots) {
                                    if let Some(b) = store.get(&h) {
                                        r.entry(h).or_insert_with(|| b.clone());
                                    }
                                }
                            }
                        }
                        None => break Err(ValidateError::MissingObject { id }),
                    },
                }
            };
            prop_assert_eq!(&got, &reference, "hints={}", hints);
        }
    }
}
