// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::resolve::structure` — the bounded round
//! loop, the hint pass and its provenance, and the prefetch pool that
//! must never displace what the walk asked for.
//!
//! Out-of-line, one flat level under `structure`. The rows
//! here are the ones the item-to-test MAP assigns to this
//! child BY CALLER, never by a banner or a line range. Unlike
//! the emission cut, this partition has NO ambiguous rows:
//! not one surviving parent row both touches a structure item
//! and enters through a parent entry point, so nothing here
//! is widened to serve a row that stayed behind.
//!
//! **No `#![expect(clippy::disallowed_methods)]`**, measured the same
//! way as emission's: all twelve sites in the parent's `tests.rs` that
//! FULFIL that expectation sit in `scratch_cache` and five rows that
//! stay, and none is among these. A copied `#![expect]` with nothing
//! to fulfil it is `unfulfilled_lint_expectations`, which CI denies —
//! so `EXPECTED_LICENSED_SITES` is unchanged again.
#![cfg(test)]

use super::*;

// Fixtures SHARED with the parent's rows stay in the parent's `tests.rs` as
// `pub(super)` items, reached BY NAME — never by a glob of the parent's
// tests, which `wildcard_imports` would not catch and which is forbidden
// because it makes the bound set open.
use super::super::tests::{FakeSeam, dir_entry, fifo_leaf, seed_grain, unfetchable_entry};

// What these rows need beyond the child's own production imports.
use granary_core::manifest::{
    DirEntry, EntryKind as ManifestEntryKind, FILE_INLINE_MAX_REFS, FileGrains, GrainRef, Name,
    Step,
};
use granary_store::codec::GrainCodec;

use crate::fetcher::FetchState;
// Reached through the sibling module directly rather than a parent re-export:
// these two are named only by test code, so a `pub(crate) use` for them in
// `resolve.rs` would be `unused_imports` in a non-test build. `budget` is
// private to `resolve`, and this module is a descendant of `resolve`, so the
// path resolves without widening anything.
use super::super::budget::{METADATA_BUDGET_BYTES, NODE_COST_BYTES};

// PARENT PRODUCTION items these rows drive alongside the child's. The closed
// reach set declared in `structure.rs` bounds the child's PRODUCTION code —
// visibility is compiler-checked, dependencies reviewed — and says nothing about
// a test, which may legitimately drive several production functions at once.
// Reached BY NAME for the same reason the fixtures are: so the set stays
// bounded and an unused one is `unused_imports`.
use super::super::{check_reachable_grains, grain_refs};

/// A one-child chain of `nesting` single-entry directories, seeded
/// into its own `FakeSeam` — the shape of
/// `thousands_deep_nesting_emits_without_recursion` parameterised
/// by depth and stopped short of the binmap and head, because the
/// rows that use it call `fetch_tree_structure` DIRECTLY.
/// `d{nesting-2}` wraps … wraps `d0` wraps the innermost directory,
/// which holds one inline file. Every directory is ONE dir leaf and
/// the hint pass follows spill entries only, never a `Dir` entry,
/// so the walk's structure nodes are exactly `nesting` ids and none
/// of them is ever hinted: the cursor asks each node exactly twice
/// (once missing, once resident) and the root exactly twice, for
/// `2n` asks in total, where replaying from the root on every miss
/// would ask the root `n + 1` times and `n(n+3)/2` in total.
struct OneChildChain {
    seam: FakeSeam,
    entries: BTreeMap<GrainId, ShardEntry>,
    bins: [[u8; DIGEST_LEN]; 1],
    root: GrainId,
}

fn one_child_chain(nesting: usize) -> OneChildChain {
    assert!(nesting >= 1, "a chain has at least its innermost directory");
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x6c_u8; DIGEST_LEN];
    let mut entries: BTreeMap<GrainId, ShardEntry> = BTreeMap::new();

    let file_content = b"one child per level, all the way down".to_vec();
    let (file_id, file_entry) = seed_grain(&seam, &mut codec, bin_digest, &file_content);
    entries.insert(file_id, file_entry);
    let leaf = DirEntry {
        name: Name::new(b"leaf.txt".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: ManifestEntryKind::File {
            exec: false,
            size: u64::try_from(file_content.len()).unwrap_or_else(|e| panic!("{e}")),
            grains: FileGrains::Inline(vec![GrainRef {
                id: file_id,
                unpacked_len: u32::try_from(file_content.len()).unwrap_or_else(|e| panic!("{e}")),
            }]),
        },
    };
    let mut built = manifest::build_dir(&[leaf]).unwrap_or_else(|e| panic!("{e}"));
    for level in 0..nesting {
        assert_eq!(built.nodes.len(), 1, "a single-entry directory is ONE leaf");
        for (id, bytes) in &built.nodes {
            let (_, e) = seed_grain(&seam, &mut codec, bin_digest, bytes);
            assert_eq!(e.id, *id);
            entries.insert(e.id, e);
        }
        if level + 1 == nesting {
            break;
        }
        let name = Name::new(format!("d{level}").into_bytes()).unwrap_or_else(|e| panic!("{e}"));
        let wrapper = DirEntry {
            name,
            kind: ManifestEntryKind::Dir { child: built.root },
        };
        built = manifest::build_dir(&[wrapper]).unwrap_or_else(|e| panic!("{e}"));
    }
    OneChildChain {
        seam,
        entries,
        bins: [bin_digest],
        root: built.root,
    }
}

/// The linear-ask row, with exact ask counts: the cursor asks the
/// root at most twice (once to find it missing, once on the re-run)
/// and every node exactly twice on a one-child chain, so total asks
/// are 2n — where replaying from the root on every miss would ask the
/// root once per miss and n(n+3)/2 in total.
#[tokio::test]
async fn fetch_tree_structure_asks_linearly_not_triangularly() {
    let mut totals = Vec::new();
    for nesting in [200usize, 400] {
        let fixture = one_child_chain(nesting); // the seeded seam + entries + bins
        let mut visits = VisitCounter::default();
        let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
        let mut fetcher = Fetcher::new(&fixture.seam, &mut fetch_state);
        let mut budget = MetadataBudget::default();
        fetch_tree_structure(
            &mut fetcher,
            None,
            &fixture.entries,
            &fixture.bins,
            &fixture.root,
            &mut budget,
            Some(&mut visits),
        )
        .await
        .unwrap_or_else(|e| panic!("nesting={nesting}: {e}"));
        // BOTH counts in ONE assertion: asserted in sequence the
        // root-visit red hides the total, and today's pump moves
        // both — 201 and 20,300 at nesting 200.
        let expected = 2 * nesting as u64;
        assert!(
            visits.root_visits <= 2 && visits.total_visits == expected,
            "nesting={nesting}: root asked {} times, {} asks in total — \
             the walk restarted from the top (expected at most 2, and \
             exactly {expected})",
            visits.root_visits,
            visits.total_visits
        );
        totals.push(visits.total_visits);
    }
    // Integer arithmetic: `u64 as f64` is `cast_precision_loss`,
    // denied here. `2 * b <= 5 * a` is `b / a <= 2.5`.
    assert!(
        totals[1] * 2 <= totals[0] * 5,
        "doubling the chain should double the asks, not quadruple them: {totals:?}"
    );
}

/// **The charge site is pinned, not only the declaration.** The
/// budget is primed one byte short of admitting a full
/// `MANIFEST_NODE_MAX_BYTES` charge, so the very first structure
/// fetch must refuse with `attempted` EXACTLY one past the budget
/// plus the one node's modelled overhead — any other
/// charge basis (`MAX_GRAIN`, a dropped charge, a doubled
/// one, a dropped node overhead) moves `attempted` and reds this
/// row. A driven resolve cannot pin this (the sheaf's own
/// `META_MAX_BYTES` worst-case check guarantees more headroom than
/// one node's charge by the time the walk starts), so the pump is
/// called directly.
#[tokio::test]
async fn the_structure_walk_charge_is_the_manifest_node_ceiling() {
    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x0f_u8; DIGEST_LEN];

    let dir_built = manifest::build_dir(&[]).unwrap_or_else(|e| panic!("{e}"));
    let (root_id, root_bytes) = dir_built
        .nodes
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("one dir leaf"));
    let (_, root_entry) = seed_grain(&seam, &mut codec, bin_digest, &root_bytes);

    let mut entries: BTreeMap<GrainId, ShardEntry> = BTreeMap::new();
    entries.insert(root_id, root_entry);
    let bins = [bin_digest];

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let mut budget = MetadataBudget {
        retained_bytes: METADATA_BUDGET_BYTES - u64::from(MANIFEST_NODE_MAX_BYTES) + 1,
        entries_len: 0,
        retained_nodes: 0,
    };
    let err = fetch_tree_structure(
        &mut fetcher,
        None,
        &entries,
        &bins,
        &root_id,
        &mut budget,
        None,
    )
    .await
    .expect_err("one byte short of the ceiling's headroom must refuse the fetch");
    match err {
        ResolveError::MetadataBudgetExceeded { attempted } => assert_eq!(
            attempted,
            METADATA_BUDGET_BYTES + 1 + NODE_COST_BYTES,
            "the charge must be exactly MANIFEST_NODE_MAX_BYTES plus one node's overhead"
        ),
        other => panic!("expected MetadataBudgetExceeded, got {other:?}"),
    }
    assert_eq!(
        seam.bin_call_count(bin_digest, root_entry.offset),
        0,
        "refused BEFORE the wire call"
    );
}

/// The node counter on a real walk: a chain of three asked more than
/// three times in total (the premise, asserted as `total_visits > 3`,
/// so some node is asked more than once), where each node is charged
/// ONCE, on the fetch that made it resident; a
/// later ask answers from `nodes` without touching the budget.
#[tokio::test]
async fn a_node_asked_more_than_once_is_charged_once() {
    let fixture = one_child_chain(3);
    let mut visits = VisitCounter::default();
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&fixture.seam, &mut fetch_state);
    let mut budget = MetadataBudget::default();
    let (nodes, ..) = fetch_tree_structure(
        &mut fetcher,
        None,
        &fixture.entries,
        &fixture.bins,
        &fixture.root,
        &mut budget,
        Some(&mut visits),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        visits.total_visits > 3,
        "the premise: some node was asked more than once ({} asks over 3 nodes)",
        visits.total_visits
    );
    let bytes: u64 = nodes.values().map(|b| b.len() as u64).sum();
    assert_eq!(
        (budget.retained_nodes, budget.retained_bytes),
        (3, bytes),
        "three nodes, charged once each, at their actual bytes"
    );
}

/// One directory tree seeded into a `FakeSeam`: the binmap entries
/// and the single bin digest `fetch_tree_structure` needs, plus the
/// nodes' ids and byte lengths for the arithmetic the rows pin.
struct SeededTree {
    seam: FakeSeam,
    entries: BTreeMap<GrainId, ShardEntry>,
    bins: [[u8; DIGEST_LEN]; 1],
    root: GrainId,
    len: BTreeMap<GrainId, u64>,
}

impl SeededTree {
    fn new() -> Self {
        Self {
            seam: FakeSeam::default(),
            entries: BTreeMap::new(),
            bins: [[0x9c_u8; DIGEST_LEN]],
            root: GrainId::of(b""),
            len: BTreeMap::new(),
        }
    }

    /// Seed one object under its own id. Returns the id.
    fn seed(&mut self, codec: &mut GrainCodec, bytes: &[u8]) -> GrainId {
        let (id, entry) = seed_grain(&self.seam, codec, self.bins[0], bytes);
        self.entries.insert(id, entry);
        self.len.insert(id, bytes.len() as u64);
        id
    }

    fn seed_all(&mut self, codec: &mut GrainCodec, nodes: &[(GrainId, Vec<u8>)]) {
        for (_, bytes) in nodes {
            self.seed(codec, bytes);
        }
    }

    fn len_of(&self, id: &GrainId) -> u64 {
        *self.len.get(id).unwrap_or_else(|| panic!("unseeded {id}"))
    }

    fn calls(&self, id: &GrainId) -> usize {
        let entry = self
            .entries
            .get(id)
            .unwrap_or_else(|| panic!("unmapped {id}"));
        self.seam.bin_call_count(self.bins[0], entry.offset)
    }
}

/// A directory of `files` inline files, each carrying `refs` grain
/// references derived from `salt` — ONE dir leaf, whose byte length
/// is what the promotion arithmetic below is primed against.
fn one_leaf_dir(salt: u64, files: u32, refs: u32) -> (GrainId, Vec<u8>) {
    let entries: Vec<DirEntry> = (0..files)
        .map(|f| DirEntry {
            name: Name::new(format!("f{f:03}").into_bytes()).unwrap_or_else(|e| panic!("{e}")),
            kind: ManifestEntryKind::File {
                exec: false,
                size: u64::from(refs),
                grains: FileGrains::Inline(
                    (0..refs)
                        .map(|r| GrainRef {
                            id: GrainId::of(
                                &salt
                                    .wrapping_mul(1_000_003)
                                    .wrapping_add(u64::from(f) << 20)
                                    .wrapping_add(u64::from(r))
                                    .to_le_bytes(),
                            ),
                            unpacked_len: 1,
                        })
                        .collect(),
                ),
            },
        })
        .collect();
    let built = manifest::build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(built.nodes.len(), 1, "the fixture depends on ONE leaf");
    built
        .nodes
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("one node"))
}

/// The four subdirectory nodes of [`four_subdirs`], `n1` first.
type Subdirs = [(GrainId, Vec<u8>); 4];

/// A root leaf naming four subdirectories `n1..n4` built from
/// `salt`. `validate_one_dir` REVERSES its `todo` before returning
/// it and `resume` pops from the back, so the walk enters them in
/// NAME order: n1 (fetched on the need path, since the hint pass
/// cannot see a dir leaf's subdirectories), then n2, n3, n4 — all
/// three pooled by the hint pass at `Entering(n1)` and promoted in
/// ONE resume. `n4` is the BIG one (20 files × 128 refs, about
/// 95 kB): the walk promotes it LAST, hash order promotes it early.
fn four_subdirs(salt: u64) -> (GrainId, Subdirs, Vec<u8>) {
    let n1 = one_leaf_dir(salt, 1, 1);
    let n2 = one_leaf_dir(salt.wrapping_add(1), 1, 1);
    let n3 = one_leaf_dir(salt.wrapping_add(2), 1, 1);
    let n4 = one_leaf_dir(salt.wrapping_add(3), 20, FILE_INLINE_MAX_REFS);
    let root_entries: Vec<DirEntry> = [&n1, &n2, &n3, &n4]
        .into_iter()
        .enumerate()
        .map(|(i, (id, _))| DirEntry {
            name: Name::new(format!("n{}", i + 1).into_bytes()).unwrap_or_else(|e| panic!("{e}")),
            kind: ManifestEntryKind::Dir { child: *id },
        })
        .collect();
    let built = manifest::build_dir(&root_entries).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(built.nodes.len(), 1, "four entries is one leaf");
    let (root_id, root_bytes) = built
        .nodes
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("one node"));
    (root_id, [n1, n2, n3, n4], root_bytes)
}

/// THE ID SEARCH. The walk promotes `n2, n3, n4`; the mutant that
/// iterates `visited` (a `BTreeSet`) promotes them in `GrainId`
/// order. The two orders are only distinguishable when the hash
/// order INVERTS the walk order, so search `salt` for the first
/// value where `id(n4) < id(n3) < id(n2)` — a 1-in-6 shot per salt,
/// found in a handful of tries. Returned rather than hard-coded so
/// a change in the encoder re-derives it instead of silently
/// pinning a salt whose inversion no longer holds.
fn salt_inverting_promotion_order() -> u64 {
    for salt in 0..10_000u64 {
        let (_, subdirs, _) = four_subdirs(salt);
        if subdirs[3].0 < subdirs[2].0 && subdirs[2].0 < subdirs[1].0 {
            return salt;
        }
    }
    panic!("no salt in 10,000 inverts the promotion order");
}

/// Promotion iterates the walk's ASK order (`asked`), never the
/// `visited` set's hash order. Three pool nodes of unequal size are
/// promoted in one resume; the budget is primed so the ASK order's
/// prefix sums all admit and any order that promotes the big node
/// early crosses. RED against the `for id in visited.borrow().iter()`
/// mutant, which refuses a volume the walk accepts.
#[tokio::test]
async fn promotion_follows_the_walks_ask_order_not_hash_order() {
    let salt = salt_inverting_promotion_order();
    let (root_id, subdirs, root_bytes) = four_subdirs(salt);
    // The fixture's premise, asserted before anything else: hash
    // order is the REVERSE of the promotion order. Without this a
    // green run proves nothing — the two orders would agree.
    assert!(
        subdirs[3].0 < subdirs[2].0 && subdirs[2].0 < subdirs[1].0,
        "the id search must INVERT the walk order n2, n3, n4"
    );
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    tree.seed_all(&mut codec, &subdirs);
    tree.root = tree.seed(&mut codec, &root_bytes);
    assert_eq!(tree.root, root_id);

    let s_root = tree.len_of(&root_id);
    let s1 = tree.len_of(&subdirs[0].0);
    let s2 = tree.len_of(&subdirs[1].0);
    let s3 = tree.len_of(&subdirs[2].0);
    let s4 = tree.len_of(&subdirs[3].0);
    assert!(
        s4 > s2 + s3 + NODE_COST_BYTES,
        "n4 must dominate: {s4} vs {s2} + {s3}"
    );
    // THE PRIMING. Charges, in the walk's order: root and n1 through
    // the need path, then n2, n3, n4 promoted. Each charge is
    // `retained_bytes + retained_nodes * NODE_COST + NODE_COST +
    // MANIFEST_NODE_MAX_BYTES`, and each fold adds the node's ACTUAL
    // bytes and one node. The LAST walk-order charge is therefore
    //   R + s_root + s1 + s2 + s3 + 5 * NODE_COST + MAX,
    // and `R` is chosen to make that EXACTLY the budget — it admits
    // (only `> budget` refuses). The hash order promotes n4 FIRST,
    // so its SECOND charge is
    //   R + s_root + s1 + s4 + 4 * NODE_COST + MAX,
    // larger by `s4 - s2 - s3 - NODE_COST > 0` — it crosses.
    let r = METADATA_BUDGET_BYTES
        - u64::from(MANIFEST_NODE_MAX_BYTES)
        - 5 * NODE_COST_BYTES
        - (s_root + s1 + s2 + s3);
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut budget = MetadataBudget {
        retained_bytes: r,
        entries_len: 0,
        retained_nodes: 0,
    };
    let (nodes, stats, _visited) = fetch_tree_structure(
        &mut fetcher,
        None,
        &tree.entries,
        &tree.bins,
        &root_id,
        &mut budget,
        Some(&mut VisitCounter::default()),
    )
    .await
    .unwrap_or_else(|e| panic!("the walk order admits every node: {e}"));
    assert_eq!(stats.dirs, 5, "root plus four subdirectories");
    assert_eq!(nodes.len(), 5, "every node charged and retained");
    assert_eq!(budget.retained_nodes, 5);
    // The three pool nodes really were POOLED, not needed: a pooled
    // node is fetched once, speculatively, and never again.
    for (id, _) in &subdirs[1..] {
        assert_eq!(tree.calls(id), 1, "one speculative fetch for {id}");
    }
}

/// A pool node consumed on the resume that returns `Done` is
/// promoted BEFORE the outcome is dispatched — otherwise it never
/// enters `nodes`, and `check_reachable_grains` cannot see the
/// grains it names. The last subdirectory names an UNMAPPED grain;
/// the walk must refuse the volume. RED against the mutant that
/// promotes only on the `Need` arm, which returns `Ok`.
#[tokio::test]
async fn a_pool_node_consumed_on_the_final_resume_is_promoted_before_done() {
    let (root_id, subdirs, root_bytes) = four_subdirs(7);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    tree.seed_all(&mut codec, &subdirs);
    tree.root = tree.seed(&mut codec, &root_bytes);
    // Every grain of every subdirectory is mapped EXCEPT n4's — the
    // node the walk consumes LAST, from the pool, on the resume that
    // returns `Done`. n1 would prove nothing: it arrives on the NEED
    // path and is in `nodes` whatever promotion does.
    for (id, bytes) in &subdirs[..3] {
        for r in grain_refs(bytes).unwrap_or_else(|e| panic!("{e}")) {
            tree.entries.entry(r.id).or_insert(ShardEntry {
                id: r.id,
                bin_ordinal: 0,
                offset: 0,
                comp_len: 1,
            });
        }
        assert!(tree.entries.contains_key(id));
    }
    let unmapped = grain_refs(&subdirs[3].1)
        .unwrap_or_else(|e| panic!("{e}"))
        .first()
        .copied()
        .unwrap_or_else(|| panic!("n4 names grains"))
        .id;
    assert!(
        !tree.entries.contains_key(&unmapped),
        "n4's grain is unmapped"
    );

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut budget = MetadataBudget::default();
    let (nodes, _stats, visited) = fetch_tree_structure(
        &mut fetcher,
        None,
        &tree.entries,
        &tree.bins,
        &root_id,
        &mut budget,
        Some(&mut VisitCounter::default()),
    )
    .await
    .unwrap_or_else(|e| panic!("the structure walk itself is clean: {e}"));
    assert_eq!(tree.calls(&subdirs[3].0), 1, "n4 was POOLED, not needed");
    assert!(
        nodes.contains_key(&subdirs[3].0),
        "the pool node consumed on the final resume must be IN `nodes`"
    );
    let err = check_reachable_grains(&visited, &nodes, &tree.entries)
        .expect_err("n4's grain is unmapped");
    assert!(
        matches!(err, ResolveError::UnmappedGrain { id, node } if id == unmapped && node == subdirs[3].0),
        "{err:?}"
    );
}

/// A budget refusal on a pool node PRE-EMPTS a validation error the
/// same resume found later in walk order: promotion runs before the
/// outcome is dispatched, on every arm. RED against the
/// `cursor.resume(..)?` mutant, which surfaces `Tree` instead.
#[tokio::test]
async fn a_budget_refusal_on_a_pool_node_preempts_a_later_validation_error() {
    let (root_id, subdirs, root_bytes) = four_subdirs(11);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    // The FOURTH child (n4's slot) is a GRAIN-LIST leaf filed under the
    // id the root names as a DIRECTORY: the walk refuses it
    // `WrongObjectType`, three asks after n2 — the node whose
    // PROMOTION is primed to cross. (A hand-built `CrossNodeOrder`
    // interior is the same shape at three more nodes; the row is about
    // which error surfaces, not which variant.)
    let (fault_id, fault_bytes) = {
        let bytes = granary_core::manifest::encode_grain_list_leaf(&[GrainRef {
            id: GrainId::of(b"misfiled-leaf-grain"),
            unpacked_len: 1,
        }])
        .unwrap_or_else(|e| panic!("{e}"));
        (GrainId::of(&bytes), bytes)
    };
    let root_entries: Vec<DirEntry> = [
        (1u32, subdirs[0].0),
        (2, subdirs[1].0),
        (3, subdirs[2].0),
        (4, fault_id),
    ]
    .into_iter()
    .map(|(i, child)| DirEntry {
        name: Name::new(format!("n{i}").into_bytes()).unwrap_or_else(|e| panic!("{e}")),
        kind: ManifestEntryKind::Dir { child },
    })
    .collect();
    let built = manifest::build_dir(&root_entries).unwrap_or_else(|e| panic!("{e}"));
    let (root_id2, root_bytes2) = built
        .nodes
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("one node"));
    let _ = (root_id, root_bytes);
    tree.seed(&mut codec, &subdirs[0].1);
    tree.seed(&mut codec, &subdirs[1].1);
    tree.seed(&mut codec, &subdirs[2].1);
    tree.seed(&mut codec, &fault_bytes);
    tree.root = tree.seed(&mut codec, &root_bytes2);

    // The walk order is n1 (need), then n2, n3 and the FAULT from
    // the pool. Prime so the FIRST promotion — n2 — is one byte over
    // the budget, while the walk's own error is found three asks
    // later, at the fault. The refusal that surfaces says which of
    // the two ran first.
    let s_root = tree.len_of(&root_id2);
    let s1 = tree.len_of(&subdirs[0].0);
    let r = METADATA_BUDGET_BYTES - u64::from(MANIFEST_NODE_MAX_BYTES) - 3 * NODE_COST_BYTES + 1
        - (s_root + s1);
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut budget = MetadataBudget {
        retained_bytes: r,
        entries_len: 0,
        retained_nodes: 0,
    };
    let err = fetch_tree_structure(
        &mut fetcher,
        None,
        &tree.entries,
        &tree.bins,
        &root_id2,
        &mut budget,
        Some(&mut VisitCounter::default()),
    )
    .await
    .expect_err("the promotion charge crosses");
    assert!(
        matches!(err, ResolveError::MetadataBudgetExceeded { .. }),
        "the budget refusal must pre-empt the walk's own error: {err:?}"
    );
}

/// The round loop's speculative-pool state, so a row can drive
/// `prefetch_structure_nodes` one pass at a time and read what it
/// did.
#[derive(Default)]
struct PoolState {
    nodes: BTreeMap<GrainId, Vec<u8>>,
    pool: BTreeMap<GrainId, Vec<u8>>,
    used: u64,
    order: VecDeque<(GrainId, bool)>,
    tried: BTreeSet<GrainId>,
    /// The resolve's DEMOTED set — pooled ids some hint pass has
    /// reached through the directory being entered — held as a field
    /// for the same reason the four above are. Empty for every row
    /// that is not about the demotion, which is what the loop passes
    /// while no hint pass has reached a pooled node.
    demoted: BTreeSet<GrainId>,
}

impl PoolState {
    async fn pass<R: BinStore>(
        &mut self,
        fetcher: &mut Fetcher<'_, R>,
        tree: &SeededTree,
        hints: Vec<(GrainId, bool)>,
    ) {
        prefetch_structure_nodes(
            fetcher,
            None,
            &tree.entries,
            &tree.bins,
            &mut self.nodes,
            &mut self.pool,
            &mut self.used,
            &mut self.order,
            &mut self.tried,
            hints,
            &self.demoted,
        )
        .await;
    }
}

/// Speculation is bounded in BYTES: one hint pass admits at most
/// ⌊`POOL_CAP_BYTES` / `MANIFEST_NODE_MAX_BYTES`⌋ = 10 candidates,
/// because each is reserved at its WORST-CASE declaration. RED
/// against the mutant that drops the deferral, which fetches all
/// twelve.
#[tokio::test]
async fn the_pool_cap_bounds_speculation_in_bytes() {
    const CANDIDATES: usize = 12;
    let admitted =
        usize::try_from(POOL_CAP_BYTES / u64::from(MANIFEST_NODE_MAX_BYTES)).unwrap_or(0);
    assert_eq!(admitted, 10, "the cap admits ten max-declared wants");
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    let ids: Vec<GrainId> = (0..CANDIDATES)
        .map(|i| tree.seed(&mut codec, format!("pool-cap-node-{i}").as_bytes()))
        .collect();

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut state = PoolState::default();
    state
        .pass(
            &mut fetcher,
            &tree,
            ids.iter().map(|id| (*id, true)).collect(),
        )
        .await;
    assert_eq!(state.pool.len(), admitted, "exactly ten admitted");
    assert_eq!(state.order.len(), admitted);
    let expected: u64 = ids[..admitted].iter().map(|id| tree.len_of(id)).sum();
    assert_eq!(state.used, expected, "pool_used is the ACTUAL bytes held");
    for id in &ids[..admitted] {
        assert_eq!(tree.calls(id), 1, "admitted candidates are fetched once");
    }
    for id in &ids[admitted..] {
        assert_eq!(
            tree.calls(id),
            0,
            "deferred candidates never reach the wire"
        );
        assert!(
            !state.tried.contains(id),
            "a candidate deferred for CAPACITY was never attempted"
        );
    }
}

/// An entering-directory hint may evict a never-asked QUEUED ROOT to
/// make room — and the evicted root is REMEMBERED, so it is never
/// fetched speculatively a second time. The composition is asserted,
/// not just the count: call 1 is the speculative fetch that filled
/// the pool, call 2 is the need path. RED against the mutant that
/// drops `hint_tried.insert(victim)`, which shows a SECOND
/// speculative fetch (three calls).
#[tokio::test]
async fn entering_directory_hints_evict_only_queued_roots() {
    // Ten max-sized nodes fill the pool past `POOL_CAP_BYTES - worst`,
    // so one eviction — and exactly one — makes room for an
    // entering-directory hint. Nothing smaller can: the eviction
    // condition is in BYTES, and `worst` is the node ceiling.
    let big = usize::try_from(MANIFEST_NODE_MAX_BYTES).unwrap_or_else(|e| panic!("{e}"));
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    let roots: Vec<GrainId> = (0..10u8)
        .map(|i| {
            let mut payload = vec![0xC5_u8; big];
            if let Some(first) = payload.first_mut() {
                *first = i;
            }
            tree.seed(&mut codec, &payload)
        })
        .collect();
    let entering = tree.seed(&mut codec, b"entering-directory-hint");

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut state = PoolState::default();
    // Pass 1: the queued roots fill the pool.
    state
        .pass(
            &mut fetcher,
            &tree,
            roots.iter().map(|id| (*id, true)).collect(),
        )
        .await;
    assert_eq!(state.pool.len(), 10, "ten queued roots pooled");
    assert!(
        state.used + u64::from(MANIFEST_NODE_MAX_BYTES) > POOL_CAP_BYTES,
        "the pool must be full enough that the next hint needs room"
    );
    let victim = roots
        .first()
        .copied()
        .unwrap_or_else(|| panic!("ten roots"));
    // Pass 2: ONE entering-directory hint.
    state
        .pass(&mut fetcher, &tree, vec![(entering, false)])
        .await;
    assert!(
        state.pool.contains_key(&entering),
        "the entering hint was admitted"
    );
    assert!(
        !state.pool.contains_key(&victim),
        "the OLDEST queued root was evicted"
    );
    assert_eq!(state.pool.len(), 10, "one out, one in");
    let used_after_admit = state.used;
    let survivor = roots.get(1).copied().unwrap_or_else(|| panic!("ten roots"));
    // Pass 3: the SAME hint list again. The BEHAVIOUR is asserted
    // before the state that produces it — a row that only checked
    // `hint_tried` would be asserting the ban's presence, not its effect.
    state
        .pass(
            &mut fetcher,
            &tree,
            roots.iter().map(|id| (*id, true)).collect(),
        )
        .await;
    assert_eq!(
        tree.calls(&victim),
        1,
        "still ONE speculative fetch after a second pass named it again"
    );
    assert!(
        state.tried.contains(&victim),
        "and that is why: an evicted root is REMEMBERED"
    );
    // ...and the nine roots that were NOT evicted are skipped by the
    // pre-filter's `pool.contains_key` arm rather than re-fetched. Without
    // it a still-pooled id is admitted again every pass: the wire call
    // repeats and `pool_used` counts the same bytes twice, drifting upward
    // on a pool that never drains until admission refuses for the rest of
    // the resolve.
    assert_eq!(
        tree.calls(&survivor),
        1,
        "a still-pooled root is not re-fetched speculatively"
    );
    assert_eq!(
        state.pool.len(),
        10,
        "and it is not re-admitted: nine surviving roots plus the hint"
    );
    assert_eq!(
        state.used, used_after_admit,
        "so `pool_used` cannot double-count an id already pooled"
    );
    // The need path: the walk reaches the evicted root and fetches it.
    let mut budget = MetadataBudget::default();
    let bytes = fetch_one_need(
        &mut fetcher,
        None,
        &tree.entries,
        &tree.bins,
        &mut budget,
        &victim,
        victim,
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(bytes.len(), big);
    assert_eq!(
        tree.calls(&victim),
        2,
        "the composition is (speculative, need) — one of each, in that order"
    );
    assert_eq!(budget.retained_nodes, 1, "the need path charged it");
}

// ----------------------------- Pool eviction (the remaining rows)

/// A candidate that would not fit even against an EMPTY pool must
/// never evict anything: `chunk_worst` is the chunk's own worst-case
/// reservation, not pool-resident bytes, and no eviction can reduce
/// it. Twenty SMALL queued roots (≈ 1 kB each — nowhere near the
/// cap) are pooled first, then a pass of twelve ENTERING-directory
/// candidates: ten admit, two defer, and every one of the twenty
/// roots is still pooled and still absent from `hint_tried`. RED
/// against the guard's removal, which evicts all twenty and marks
/// each of them tried before deferring anyway.
#[tokio::test]
async fn a_full_chunk_never_evicts_the_pool() {
    let admitted =
        usize::try_from(POOL_CAP_BYTES / u64::from(MANIFEST_NODE_MAX_BYTES)).unwrap_or(0);
    assert_eq!(admitted, 10);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    let roots: Vec<GrainId> = (0..20u32)
        .map(|i| tree.seed(&mut codec, &vec![u8::try_from(i % 251).unwrap_or(0); 1024]))
        .collect();
    let entering: Vec<GrainId> = (0..12u32)
        .map(|i| tree.seed(&mut codec, format!("full-chunk-entering-{i}").as_bytes()))
        .collect();

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut state = PoolState::default();
    // Two passes of ten: one pass admits at most ⌊cap/worst⌋ = 10.
    for chunk in roots.chunks(admitted) {
        state
            .pass(
                &mut fetcher,
                &tree,
                chunk.iter().map(|id| (*id, true)).collect(),
            )
            .await;
    }
    assert_eq!(state.pool.len(), 20, "twenty small roots pooled");
    assert!(
        state.used < POOL_CAP_BYTES / 100,
        "the roots are nowhere near the cap: {}",
        state.used
    );
    let roots_used = state.used;

    state
        .pass(
            &mut fetcher,
            &tree,
            entering.iter().map(|id| (*id, false)).collect(),
        )
        .await;
    for id in &roots {
        assert!(
            state.pool.contains_key(id),
            "root {id} must still be pooled"
        );
        assert!(
            !state.tried.contains(id),
            "root {id} must not be marked tried: nothing was evicted"
        );
        assert_eq!(tree.calls(id), 1, "and it is never re-fetched");
    }
    assert_eq!(state.pool.len(), 20 + admitted, "ten of twelve admitted");
    assert_eq!(
        state.used,
        roots_used
            + entering[..admitted]
                .iter()
                .map(|id| tree.len_of(id))
                .sum::<u64>()
    );
    for id in &entering[admitted..] {
        assert_eq!(
            tree.calls(id),
            0,
            "deferred candidates never reach the wire"
        );
        assert!(!state.tried.contains(id), "deferred is not attempted");
    }
}

/// The pool is full of ENTERING-directory hints and holds no queued
/// root at all: the next entering candidate is DEFERRED, not
/// dropped — zero wire calls, absent from `hint_tried`, pool
/// unchanged. Entering hints never evict each other: admitting one
/// may evict only an eligible queued root.
#[tokio::test]
async fn an_entering_hint_with_no_root_victim_is_deferred_not_dropped() {
    let big = usize::try_from(MANIFEST_NODE_MAX_BYTES).unwrap_or_else(|e| panic!("{e}"));
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    let filled: Vec<GrainId> = (0..10u8)
        .map(|i| {
            let mut payload = vec![0x3B_u8; big];
            if let Some(first) = payload.first_mut() {
                *first = i;
            }
            tree.seed(&mut codec, &payload)
        })
        .collect();
    let next = tree.seed(&mut codec, b"the-deferred-entering-candidate");

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut state = PoolState::default();
    state
        .pass(
            &mut fetcher,
            &tree,
            filled.iter().map(|id| (*id, false)).collect(),
        )
        .await;
    assert_eq!(state.pool.len(), 10, "the pool is full of entering hints");
    assert!(
        state.order.iter().all(|(_, is_root)| !*is_root),
        "no queued root is available as a victim"
    );
    let before = state.used;
    state.pass(&mut fetcher, &tree, vec![(next, false)]).await;
    assert_eq!(state.pool.len(), 10, "pool unchanged");
    assert_eq!(state.used, before);
    assert_eq!(tree.calls(&next), 0, "deferred: never reached the wire");
    assert!(
        !state.tried.contains(&next),
        "a candidate deferred for CAPACITY was never attempted"
    );
}

/// Eviction is DESTRUCTIVE — a victim leaves the pool and is banned
/// in `hint_tried` for the rest of the resolve — so it must only
/// happen when the eligible victims are ENOUGH. A pool of ten
/// max-sized ENTERING hints (never evictable) plus ONE small queued
/// root cannot admit another max-sized candidate even after the root
/// goes: `cap - 10 * worst` is 2,883,444, far under `worst`. The
/// candidate must therefore be deferred with the root STILL POOLED.
/// Before the sufficiency test this loop evicted the root, banned
/// it, re-checked, and deferred anyway — the pool emptied for
/// nothing and a legitimate speculation lost for the resolve's life.
/// The first guard does not cover this: it only refuses a chunk that
/// could not fit against an EMPTY pool.
#[tokio::test]
async fn eviction_that_cannot_make_room_evicts_nothing() {
    let big = usize::try_from(MANIFEST_NODE_MAX_BYTES).unwrap_or_else(|e| panic!("{e}"));
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    let root = tree.seed(&mut codec, &vec![0x7E_u8; 2_000_000]);
    let filled: Vec<GrainId> = (0..10u8)
        .map(|i| {
            let mut payload = vec![0x4D_u8; big];
            if let Some(first) = payload.first_mut() {
                *first = i;
            }
            tree.seed(&mut codec, &payload)
        })
        .collect();
    let next = tree.seed(&mut codec, b"the-candidate-no-eviction-can-admit");

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut state = PoolState::default();
    // The queued root goes in FIRST, so it is the oldest entry and
    // would be the victim the eviction loop reaches for.
    state.pass(&mut fetcher, &tree, vec![(root, true)]).await;
    state
        .pass(
            &mut fetcher,
            &tree,
            filled.iter().map(|id| (*id, false)).collect(),
        )
        .await;
    assert_eq!(state.pool.len(), 11, "ten entering hints and one root");
    assert!(state.pool.contains_key(&root), "the root is pooled");
    // The premise, asserted: evicting EVERY eligible victim still
    // leaves the candidate unable to fit.
    let evictable: u64 = state
        .order
        .iter()
        .filter(|(_, is_root)| *is_root)
        .filter_map(|(id, _)| state.pool.get(id).map(|b| b.len() as u64))
        .sum();
    let need = state.used + u64::from(MANIFEST_NODE_MAX_BYTES);
    assert!(
        need > POOL_CAP_BYTES && need - evictable > POOL_CAP_BYTES,
        "the fixture must be one no eviction can rescue: need {need}, evictable {evictable}"
    );
    let before = state.used;

    state.pass(&mut fetcher, &tree, vec![(next, false)]).await;

    assert!(
        state.pool.contains_key(&root),
        "the root must NOT be evicted for an admission that cannot happen"
    );
    assert!(
        !state.tried.contains(&root),
        "and it must NOT be banned from speculation for the rest of the resolve"
    );
    assert_eq!(state.pool.len(), 11, "the pool is untouched");
    assert_eq!(state.used, before, "and so are its bytes");
    assert_eq!(
        tree.calls(&next),
        0,
        "the candidate is deferred, not fetched"
    );
    assert!(
        !state.tried.contains(&next),
        "a candidate deferred for CAPACITY was never attempted"
    );
}

/// `hints_with_provenance` assigns the admission provenance used by
/// the eviction policy, and no row drove it: every eviction row hands
/// `prefetch_structure_nodes` hand-built provenance, so swapping the
/// two booleans inverted the policy in the shipped loop with the
/// whole suite still green. This pins the mapping directly — a
/// queued root (`true`) is the ONLY entry eviction may take, an
/// `entering` id (`false`) is never a victim and is the only kind of
/// candidate that may CAUSE one, and entering ids come FIRST so the
/// pool's insertion order matches the walk's.
///
/// It also pins only the ADMISSION provenance. A
/// `true` entry is a victim only if `is_eviction_victim`
/// still says so; the overlap case is pinned by
/// `the_row_225_overlap_arrives_as_entering_and_evicts`,
/// which drives a real overlap through a live cursor
/// rather than a hand-built `Hints`.
///
/// It pins the mapping AS IMPLEMENTED, which is not the same as
/// blessing it: `Hints`'s dedup is one-directional, so an id
/// that is BOTH a queued root and reachable through the
/// entering directory appears only under `entering` and is
/// labelled `false` here — so it is never taken as a victim
/// even though it is one by role. That misclassification is
/// toward the SAFE side, costing pool availability rather than
/// correctness. The register row on `Hints` provenance was open
/// against it and is now DISCHARGED; this row exists to
/// stop an INVERSION, not to claim the partition is exact.
#[test]
fn hint_provenance_marks_roots_evictable_and_entering_not() {
    let e1 = GrainId::of(b"provenance-entering-1");
    let e2 = GrainId::of(b"provenance-entering-2");
    let r1 = GrainId::of(b"provenance-queued-root-1");
    let paired = hints_with_provenance(manifest::Hints {
        entering: vec![e1, e2],
        queued_roots: vec![r1],
    });
    assert_eq!(
        paired,
        vec![(e1, false), (e2, false), (r1, true)],
        "queued roots are the only victims; entering ids come first and are never taken"
    );
}

/// One candidate can need MORE THAN ONE victim. The eviction loop is
/// a `while`, not an `if`, and no row distinguished the two: every
/// other eviction fixture is built so exactly one eviction suffices,
/// because a max-sized victim frees exactly what a max-sized
/// candidate needs. Here the victims are SMALLER than the candidate
/// — nine max-sized entering hints plus four 1 MB queued roots —
/// so admitting one more max-sized hint needs TWO roots gone, and an
/// `if` would evict one, still not fit, and defer.
#[tokio::test]
async fn one_candidate_can_need_two_victims() {
    let big = usize::try_from(MANIFEST_NODE_MAX_BYTES).unwrap_or_else(|e| panic!("{e}"));
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    let roots: Vec<GrainId> = (0..4u8)
        .map(|i| {
            let mut payload = vec![0x2A_u8; 1_000_000];
            if let Some(first) = payload.first_mut() {
                *first = i;
            }
            tree.seed(&mut codec, &payload)
        })
        .collect();
    let filled: Vec<GrainId> = (0..9u8)
        .map(|i| {
            let mut payload = vec![0x6F_u8; big];
            if let Some(first) = payload.first_mut() {
                *first = i;
            }
            tree.seed(&mut codec, &payload)
        })
        .collect();
    let next = tree.seed(&mut codec, &vec![0x11_u8; big]);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut state = PoolState::default();
    state
        .pass(
            &mut fetcher,
            &tree,
            roots.iter().map(|id| (*id, true)).collect(),
        )
        .await;
    state
        .pass(
            &mut fetcher,
            &tree,
            filled.iter().map(|id| (*id, false)).collect(),
        )
        .await;
    assert_eq!(state.pool.len(), 13, "nine entering hints and four roots");
    // The premise, asserted as ONE tuple so the second fact still
    // prints when the first fails: one victim is not enough, two are.
    let one = state.used - 1_000_000 + u64::from(MANIFEST_NODE_MAX_BYTES);
    let two = state.used - 2_000_000 + u64::from(MANIFEST_NODE_MAX_BYTES);
    assert_eq!(
        (one > POOL_CAP_BYTES, two > POOL_CAP_BYTES),
        (true, false),
        "the fixture must need exactly two victims (used {})",
        state.used
    );

    state.pass(&mut fetcher, &tree, vec![(next, false)]).await;

    assert!(
        state.pool.contains_key(&next),
        "the candidate is admitted once TWO roots have gone"
    );
    let gone = roots
        .iter()
        .filter(|id| !state.pool.contains_key(id))
        .count();
    assert_eq!(
        gone, 2,
        "exactly two victims, oldest first — not one, not all"
    );
    for id in roots.iter().take(2) {
        assert!(state.tried.contains(id), "an evicted root is remembered");
    }
    for id in roots.iter().skip(2) {
        assert!(
            state.pool.contains_key(id),
            "a root beyond the need is untouched"
        );
        assert!(!state.tried.contains(id), "and is not banned");
    }
}

// -------------------------------------- the pool's provenance

/// The register-row-225 OVERLAP, driven to the state that produces
/// it. Root `A` names child directories `S1` and `X`; `S1` is an
/// interior whose second B-tree child IS `X`; `X` is absent from the
/// cursor's residency. Returns `X`'s id, its bytes, and the hints.
///
/// `S1` is deliberately NOT canonical — an interior over two
/// one-entry leaves. The walk stops at the absent `X` before
/// `check_fill_canonical` runs, so the hint pass is reached and the
/// exact walk would later refuse the shape. Stated rather than
/// hidden: this row is about hint PROVENANCE, and the canonical case
/// is `a_pooled_root_the_hint_pass_reached_is_not_evicted`.
fn row_225_overlap_hints() -> (GrainId, Vec<u8>, manifest::Hints) {
    let x = fifo_leaf(b"m");
    let x_id = GrainId::of(&x);
    let c1 = fifo_leaf(b"a");
    let c1_id = GrainId::of(&c1);
    let s1 = manifest::encode_dir_interior(&[
        manifest::InteriorChild {
            first_key: Name::new(b"a".to_vec()).unwrap_or_else(|e| panic!("{e}")),
            child: c1_id,
            subtree_entry_count: 1,
        },
        manifest::InteriorChild {
            first_key: Name::new(b"m".to_vec()).unwrap_or_else(|e| panic!("{e}")),
            child: x_id,
            subtree_entry_count: 1,
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let s1_id = GrainId::of(&s1);
    let a = manifest::encode_dir_leaf(&[dir_entry(b"d1", s1_id), dir_entry(b"d2", x_id)])
        .unwrap_or_else(|e| panic!("{e}"));
    let a_id = GrainId::of(&a);

    let mut resident: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    resident.insert(a_id, a);
    resident.insert(s1_id, s1);
    resident.insert(c1_id, c1);

    let mut cursor = manifest::TreeCursor::new(a_id);
    let step = cursor.resume(&|id| resident.get(id).cloned());
    assert!(
        matches!(&step, Ok(Step::Need(id)) if *id == x_id),
        "the walk of S1 stops on the absent overlapping child: {step:?}"
    );
    let hints = cursor.prefetch_hints(&|id| resident.get(id).cloned(), manifest::PREFETCH_HINT_MAX);
    (x_id, x, hints)
}

/// **Register row 225, on a REAL overlap.** `Hints`'s dedup is
/// ONE-DIRECTIONAL: `entering` is filled first into a shared `seen`,
/// and the frames loop drops a worklist child already in it. So an id
/// that is BOTH a queued root and reachable through the directory
/// being entered is reported ONLY under `entering`, and
/// `hints_with_provenance` labels a genuine queued root `false`.
///
/// This row does not bless that mapping — it pins the CONSEQUENCE the
/// register row asks for, driven by a real cursor rather than a
/// hand-built `Hints`: the overlapping id is admitted and CAUSES an
/// eviction, which is what "never a victim, and the only kind of
/// candidate that may cause one" means when it lands on an id that is
/// a queued root by role.
///
/// The premise is established by a POSITIVE CONTROL, not by
/// construction: `an_id_outside_the_entering_directory_is_a_queued_root`
/// builds the SAME `x_id` in the SAME worklist position with the
/// overlap removed and gets it back under `queued_roots`. Without it,
/// "it is under `entering`" would be equally consistent with `x_id`
/// never having been queued at all.
///
/// RED against two mutants, both EXECUTED. (i) `hints_with_provenance`
/// mapping `entering` to `true`: the candidate then computes
/// `evictable = 0` and defers, so it is never pooled — this row dies
/// at `pool.contains_key(&x_id)`. (ii) reversing the dedup in
/// `granary-core`, running the frames loop BEFORE `missing_in_dir_tree`
/// — the plausible "make the partition exact" change, which reports
/// the id under `queued_roots` and so makes a node the walk is about
/// to need an eviction VICTIM; this row dies at the fixture
/// assertion. Mutant (ii) is INVISIBLE to
/// `hint_provenance_marks_roots_evictable_and_entering_not`, which
/// stayed green under it (executed) because it drives a hand-built
/// `Hints` containing no overlap.
#[tokio::test]
async fn the_row_225_overlap_arrives_as_entering_and_evicts() {
    let (x_id, x, hints) = row_225_overlap_hints();
    // THE FIXTURE, ASSERTED, as ONE tuple so the second fact still
    // prints when the first fails. The second is the dedup, and it is
    // the half this row exists for.
    assert_eq!(
        (hints.entering.clone(), hints.queued_roots.clone()),
        (vec![x_id], Vec::new()),
        "the overlapping queued root is reported ONLY under `entering`"
    );

    // Ten max-sized queued roots fill the pool past
    // `POOL_CAP_BYTES - worst`, so admitting the overlapping
    // candidate needs one eviction — and exactly one.
    let big = usize::try_from(MANIFEST_NODE_MAX_BYTES).unwrap_or_else(|e| panic!("{e}"));
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    let fillers: Vec<GrainId> = (0..10u8)
        .map(|i| {
            let mut payload = vec![0x5C_u8; big];
            if let Some(first) = payload.first_mut() {
                *first = i;
            }
            tree.seed(&mut codec, &payload)
        })
        .collect();
    // `X` is on the WIRE even though the cursor could not see it:
    // that is exactly the state a real resolve is in.
    assert_eq!(
        tree.seed(&mut codec, &x),
        x_id,
        "the seeded object IS the hinted id"
    );

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut state = PoolState::default();
    state
        .pass(
            &mut fetcher,
            &tree,
            fillers.iter().map(|id| (*id, true)).collect(),
        )
        .await;
    assert_eq!(state.pool.len(), 10, "the pool is full of queued roots");
    let need = state.used + u64::from(MANIFEST_NODE_MAX_BYTES);
    assert_eq!(
        (
            need > POOL_CAP_BYTES,
            need.saturating_sub(tree.len_of(&fillers[0])) <= POOL_CAP_BYTES
        ),
        (true, true),
        "the premise: the candidate does not fit, and ONE victim is enough — need {need}"
    );

    state
        .pass(&mut fetcher, &tree, hints_with_provenance(hints))
        .await;

    assert!(
        state.pool.contains_key(&x_id),
        "the overlapping queued root arrived as an ENTERING hint and was admitted"
    );
    assert!(!state.tried.contains(&x_id), "and was never banned");
    assert_eq!(
        (
            state.tried.contains(&fillers[0]),
            state.pool.contains_key(&fillers[0]),
            state.tried.len(),
            state.pool.len()
        ),
        (true, false, 1, 10),
        "it CAUSED exactly one eviction, and the victim is the oldest queued root"
    );
}

/// The stale-provenance shape: a LEGAL, fully canonical manifest in
/// which `P` is BOTH the middle B-tree leaf of directory `S2` and a
/// child DIRECTORY of the root, so the worklist pools it before the
/// cursor ever enters `S2`.
///
/// `S2` is `build_dir` over 513 entries, whose canonical form is one
/// interior over three 171-entry leaves. `S1` names one further child
/// directory `T`, and that is LOAD-BEARING: without it the pool holds
/// eight fillers rather than ten, the deciding candidate fits with no
/// eviction at all, and the row's `P` assertion is green with or
/// without `demote_pooled_provenance`. Measured, not assumed — with
/// `T` removed the row dies at its own pressure assertion instead.
struct StaleShape {
    root: GrainId,
    c: GrainId,
    p: GrainId,
    d: GrainId,
    fillers: Vec<GrainId>,
}

fn stale_provenance_shape(codec: &mut GrainCodec, tree: &mut SeededTree) -> StaleShape {
    let big = usize::try_from(MANIFEST_NODE_MAX_BYTES).unwrap_or_else(|e| panic!("{e}"));
    let s2_entries: Vec<DirEntry> = (0..513u32)
        .map(|i| DirEntry {
            name: Name::new(format!("s2-{i:04}").into_bytes()).unwrap_or_else(|e| panic!("{e}")),
            kind: ManifestEntryKind::Fifo,
        })
        .collect();
    let s2 = manifest::build_dir(&s2_entries).unwrap_or_else(|e| panic!("{e:?}"));
    // The canonical shape, asserted before it is relied on.
    assert_eq!(
        (
            s2.nodes.len(),
            s2.nodes[3].0 == s2.root,
            s2.nodes[0].1.len(),
            s2.nodes[1].1.len(),
            s2.nodes[2].1.len()
        ),
        (4, true, 1553, 1553, 1553),
        "513 entries canonicalise to [171, 171, 171] under one interior, leaves first"
    );
    let (c, p, d) = (s2.nodes[0].0, s2.nodes[1].0, s2.nodes[2].0);

    let t = fifo_leaf(b"t-leaf");
    let t_id = GrainId::of(&t);
    let s1 = manifest::encode_dir_leaf(&[dir_entry(b"t", t_id)]).unwrap_or_else(|e| panic!("{e}"));
    let s1_id = GrainId::of(&s1);

    let fillers: Vec<GrainId> = (0..10u8)
        .map(|i| {
            let mut payload = vec![0x2D_u8; big];
            if let Some(first) = payload.first_mut() {
                *first = i;
            }
            tree.seed(codec, &payload)
        })
        .collect();

    let mut root_entries: Vec<DirEntry> = vec![
        dir_entry(b"a_s1", s1_id),
        dir_entry(b"b_s2", s2.root),
        dir_entry(b"c_p", p),
    ];
    for (i, f) in fillers.iter().enumerate() {
        root_entries.push(dir_entry(format!("d_f{i:02}").as_bytes(), *f));
    }
    let root = manifest::build_dir(&root_entries).unwrap_or_else(|e| panic!("{e:?}"));
    tree.seed_all(codec, &root.nodes);
    tree.seed_all(codec, &s2.nodes);
    tree.seed(codec, &s1);
    tree.seed(codec, &t);
    StaleShape {
        root: root.root,
        c,
        p,
        d,
        fillers,
    }
}

/// **The `reached` signal's EXACTNESS, pinned rather than argued.**
/// `hints_for_round` RECORDS which pooled ids the pass fetched and
/// returns them; `demote_pooled_provenance` folds that into `demoted`
/// and `is_eviction_victim` reads it. Nothing rewrites the boolean in
/// `pool_order` — it is immutable admission provenance — so "demoted"
/// throughout this row means "no longer a victim", not "flipped".
/// Both directions are one tuple: `P`, the middle B-tree leaf of the
/// directory being entered, stops being a victim; `Q`, a pooled QUEUED ROOT the entering
/// directory cannot reach, keeps `true` and stays available as an
/// eviction victim.
///
/// Sharing the closure with the frames loop does not itself record
/// every pooled queued root or starve the pool of victims.
/// `prefetch_hints` passes the SAME closure, but the frames loop
/// never invokes it: it calls no
/// `fetch` at all, reading only `memo`, `seen` and `todo`. This row
/// is the EXECUTED refutation, and it is RED against a `granary-core`
/// mutant that adds one `fetch(child)` call to that loop:
/// that extra fetch demotes `Q`, so this tuple's
/// second half fails. Nothing in the suite distinguished the two
/// before this row existed.
#[test]
fn hints_for_round_demotes_only_the_pooled_ids_the_pass_reached() {
    let s2_entries: Vec<DirEntry> = (0..513u32)
        .map(|i| DirEntry {
            name: Name::new(format!("s2-{i:04}").into_bytes()).unwrap_or_else(|e| panic!("{e}")),
            kind: ManifestEntryKind::Fifo,
        })
        .collect();
    let s2 = manifest::build_dir(&s2_entries).unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        (s2.nodes.len(), s2.nodes[3].0 == s2.root),
        (4, true),
        "three leaves then the interior root"
    );
    let (c_id, p_id) = (s2.nodes[0].0, s2.nodes[1].0);
    let q = fifo_leaf(b"q");
    let q_id = GrainId::of(&q);
    let root = manifest::build_dir(&[
        dir_entry(b"a_s2", s2.root),
        dir_entry(b"b_p", p_id),
        dir_entry(b"c_q", q_id),
    ])
    .unwrap_or_else(|e| panic!("{e:?}"));

    // `nodes` holds the root and the directory being entered; the
    // pool holds `P` (reachable through it) and `Q` (not). `C` is
    // absent, which is what stops the walk inside `S2` and leaves the
    // cursor sitting there.
    let mut nodes: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    for (id, bytes) in &root.nodes {
        nodes.insert(*id, bytes.clone());
    }
    nodes.insert(s2.root, s2.nodes[3].1.clone());
    let mut pool: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    pool.insert(p_id, s2.nodes[1].1.clone());
    pool.insert(q_id, q);

    let mut cursor = manifest::TreeCursor::new(root.root);
    let step = cursor.resume(&|id| nodes.get(id).or_else(|| pool.get(id)).cloned());
    assert!(
        matches!(&step, Ok(Step::Need(id)) if *id == c_id),
        "the walk stops inside S2 on its absent first leaf: {step:?}"
    );

    let pool_order: VecDeque<(GrainId, bool)> = VecDeque::from(vec![(q_id, true), (p_id, true)]);
    let (paired, reached) = hints_for_round(&cursor, &nodes, &pool);
    let mut demoted: BTreeSet<GrainId> = BTreeSet::new();
    demote_pooled_provenance(&mut demoted, reached);
    assert_eq!(
        pool_order
            .iter()
            .map(|entry| is_eviction_victim(entry, &demoted))
            .collect::<Vec<bool>>(),
        vec![true, false],
        "only the pooled id the pass FETCHED is demoted; a pooled queued root the \
         entering directory cannot reach keeps its provenance and stays a victim"
    );
    assert!(
        paired.iter().any(|(id, is_root)| *id == q_id && *is_root),
        "and Q is still emitted as a queued root: {paired:?}"
    );
}

/// **The demotion must OUTLIVE the round that made it, because the
/// hint pass is BUDGETED.** The tempting scope is per-round: the
/// cursor re-walks the entering directory on every round it is
/// stopped inside, so a node the walk still needs looks like it must
/// be reached again every round. It does not. `HINT_WORK_MAX` bounds
/// the pass, repeated children are charged before the dedup, and a
/// spill is not memoised until it validates — so a publisher can
/// build a directory whose hint pass spends its entire budget before
/// reaching an already-pooled node the walk still needs. Under a
/// per-round set that node loses protection for exactly that round,
/// is taken as the oldest victim, and is BANNED.
///
/// This row is that shape at the level the property lives at: `R` is
/// reached in one pass and NOT in the next, and the next pass is the
/// one under capacity pressure. It must still be un-evictable.
///
/// RED against a per-round demotion — clearing the set between
/// passes evicts `R` and bans it. A budget-exhaustion manifest was
/// constructed to reach this state through the real cursor;
/// this row pins the consequence without needing that manifest,
/// which is why it is a `PoolState` row and not an end-to-end one.
#[tokio::test]
async fn a_demotion_outlives_the_round_that_made_it() {
    let big = usize::try_from(MANIFEST_NODE_MAX_BYTES).unwrap_or_else(|e| panic!("{e}"));
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    let r = tree.seed(&mut codec, &vec![0x4E_u8; 6_000_000]);
    let filled: Vec<GrainId> = (0..9u8)
        .map(|i| {
            let mut payload = vec![0x4F_u8; big];
            if let Some(first) = payload.first_mut() {
                *first = i;
            }
            tree.seed(&mut codec, &payload)
        })
        .collect();
    let next = tree.seed(&mut codec, &vec![0x50_u8; big]);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut state = PoolState::default();
    // `R` goes in first, so it is the oldest entry and the victim
    // search reaches it before any other queued root.
    state.pass(&mut fetcher, &tree, vec![(r, true)]).await;
    state
        .pass(
            &mut fetcher,
            &tree,
            filled.iter().map(|id| (*id, false)).collect(),
        )
        .await;
    assert_eq!(state.pool.len(), 10, "nine entering hints and one root");

    // ROUND k: a hint pass reaches `R` in the pool.
    demote_pooled_provenance(&mut state.demoted, BTreeSet::from([r]));

    // ROUND k+1: the hint pass reaches NOTHING — its budget went
    // elsewhere — and THIS is the round under capacity pressure.
    demote_pooled_provenance(&mut state.demoted, BTreeSet::new());

    // The premise, asserted as ONE tuple: the candidate does not fit,
    // and `R` is the only entry eviction could otherwise take.
    let need = state.used + u64::from(MANIFEST_NODE_MAX_BYTES);
    assert_eq!(
        (
            need > POOL_CAP_BYTES,
            need.saturating_sub(tree.len_of(&r)) <= POOL_CAP_BYTES,
            state.order.iter().filter(|(_, root)| *root).count()
        ),
        (true, true, 1),
        "one victim would rescue the candidate, and there is exactly one candidate victim"
    );
    let before = state.used;

    state.pass(&mut fetcher, &tree, vec![(next, false)]).await;

    assert_eq!(
        (
            state.pool.contains_key(&r),
            state.tried.contains(&r),
            state.pool.len(),
            state.used
        ),
        (true, false, 10, before),
        "the demotion made in an EARLIER round still holds: R is not taken, not \
         banned, and the candidate defers instead"
    );
    assert_eq!(
        tree.calls(&next),
        0,
        "the candidate is deferred, not fetched"
    );
}

/// **The demotion must reach the SUFFICIENCY TEST, not just the victim
/// search.** `evictable` decides whether eviction can make room at
/// all, and eviction is ALL-OR-NOTHING precisely because a victim is
/// banned as well as removed. If the sum counts bytes held by entries
/// the demotion has made un-evictable, it over-states what can be
/// freed: the loop enters believing it can fit the candidate, evicts
/// and BANS every victim it actually may take, still cannot fit, and
/// defers — the pool spent for an admission that could never happen.
/// That is the defect `eviction_that_cannot_make_room_evicts_nothing`
/// exists for, reachable again through the sum.
///
/// Nine max-sized entering hints (never victims) plus two queued
/// roots: `R_reached`, 3 MB, which this round's hint pass reached,
/// and `R_free`, 1 MB, which it did not. One more max-sized entering
/// candidate needs 1,116,556 bytes more than the pool has. `R_free`
/// alone cannot rescue it, and `R_reached` may not be spent — so
/// nothing may be evicted at all.
///
/// RED against the mutant that filters the sum on the admission
/// provenance instead of the demoted one: it counts `R_reached`'s
/// 3 MB, decides eviction is sufficient, and takes `R_free` for
/// nothing. That mutant SURVIVED every other row in this file when it
/// was first run, which is why this one exists.
#[tokio::test]
async fn the_sufficiency_test_reads_the_demoted_provenance() {
    let big = usize::try_from(MANIFEST_NODE_MAX_BYTES).unwrap_or_else(|e| panic!("{e}"));
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    let r_reached = tree.seed(&mut codec, &vec![0x1A_u8; 3_000_000]);
    let r_free = tree.seed(&mut codec, &vec![0x1B_u8; 1_000_000]);
    let entering: Vec<GrainId> = (0..9u8)
        .map(|i| {
            let mut payload = vec![0x1C_u8; big];
            if let Some(first) = payload.first_mut() {
                *first = i;
            }
            tree.seed(&mut codec, &payload)
        })
        .collect();
    let next = tree.seed(&mut codec, &vec![0x1D_u8; big]);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut state = PoolState::default();
    // The two queued roots go in FIRST, so they are the oldest
    // entries and the victim search reaches them before anything.
    state
        .pass(&mut fetcher, &tree, vec![(r_reached, true), (r_free, true)])
        .await;
    state
        .pass(
            &mut fetcher,
            &tree,
            entering.iter().map(|id| (*id, false)).collect(),
        )
        .await;
    assert_eq!(state.pool.len(), 11, "nine entering hints and two roots");

    // THIS round's hint pass reached `R_reached` in the pool, so it is
    // a dependency of the directory being entered and may not be taken.
    demote_pooled_provenance(&mut state.demoted, BTreeSet::from([r_reached]));

    // The premise, asserted as ONE tuple: the candidate does not fit;
    // the victim that MAY be taken is not enough; and it would have
    // been enough had the one that may not be taken counted.
    let need = state.used + u64::from(MANIFEST_NODE_MAX_BYTES);
    let free_only = tree.len_of(&r_free);
    let both = free_only + tree.len_of(&r_reached);
    assert_eq!(
        (
            need > POOL_CAP_BYTES,
            need.saturating_sub(free_only) > POOL_CAP_BYTES,
            need.saturating_sub(both) <= POOL_CAP_BYTES
        ),
        (true, true, true),
        "the fixture must discriminate: need {need}, free {free_only}, both {both}"
    );
    let before = state.used;

    state.pass(&mut fetcher, &tree, vec![(next, false)]).await;

    assert_eq!(
        (
            state.pool.contains_key(&r_free),
            state.tried.contains(&r_free),
            state.pool.contains_key(&r_reached),
            state.tried.contains(&r_reached)
        ),
        (true, false, true, false),
        "nothing may be evicted: the only takeable victim cannot rescue the candidate, \
         and the one that would have is a dependency of the walk in progress"
    );
    assert_eq!(
        (state.pool.len(), state.used),
        (11, before),
        "the pool is untouched, bytes included"
    );
    assert_eq!(
        tree.calls(&next),
        0,
        "the candidate is deferred, not fetched"
    );
    assert!(
        !state.tried.contains(&next),
        "a candidate deferred for CAPACITY was never attempted"
    );
}

/// **The pool's provenance goes stale, and only the hint pass can see
/// it.** A node admitted as a QUEUED ROOT keeps `is_queued_root ==
/// true` for the life of its pool entry: `prefetch_structure_nodes`
/// skips an id already pooled, so the flag is never revised. When the
/// walk later ENTERS a directory whose own B-tree names that node, the
/// node has become a dependency of the walk in progress — and NO hint
/// can report THAT, because both walkers push to `entering` only in
/// the arm where their closure answered `None`, and a pooled id is
/// answered from the pool. (Nor under `queued_roots`: the walker puts
/// a reached id into the shared `seen` set before it fetches, and the
/// frames loop drops a worklist child already there. A DIFFERENT
/// pooled id the pass never reached CAN be listed there, and
/// `hints_for_round_demotes_only_the_pooled_ids_the_pass_reached`
/// asserts that pair on two distinct ids.) So it stays evictable, an
/// entering candidate in that same pass evicts it AND bans it in
/// `hint_tried`, and the very next resume pays a need-path round trip
/// for bytes the pool was holding.
///
/// `hints_for_round`'s closure records which POOLED ids the pass
/// reached, and `demote_pooled_provenance` makes them un-evictable
/// BEFORE the admission pass runs. RED without it: `P` is fetched
/// TWICE (speculative, then need) instead of once — executed, `left:
/// 2, right: 1`.
///
/// The fillers are junk bytes named as child directories: the walk
/// reaches them only after the observation, and refuses them.
#[tokio::test]
async fn a_pooled_root_the_hint_pass_reached_is_not_evicted() {
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    let shape = stale_provenance_shape(&mut codec, &mut tree);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut budget = MetadataBudget::default();
    let err = fetch_tree_structure(
        &mut fetcher,
        None,
        &tree.entries,
        &tree.bins,
        &shape.root,
        &mut budget,
        Some(&mut VisitCounter::default()),
    )
    .await
    .expect_err("a junk filler directory refuses");
    assert!(
        matches!(err, ResolveError::Tree { .. }),
        "the walk ends on the junk filler, not before: {err:?}"
    );

    // THE ASSERTION. `P` is speculatively fetched once as a queued
    // root. Without the demotion the deciding pass evicts and BANS
    // it, and the next resume fetches it again on the need path.
    assert_eq!(
        tree.calls(&shape.p),
        1,
        "P is fetched ONCE: the hint pass reached it in the pool, so the \
         admission that followed could not take it as a victim"
    );
    // The premises, so a green result cannot be vacuous: `C` and `D`
    // really were the other two leaves of the directory being
    // entered, and the deciding pass really was under pressure.
    assert_eq!(
        (tree.calls(&shape.c), tree.calls(&shape.d)),
        (1, 1),
        "C came down the need path and D the hint path, once each"
    );
    assert!(
        shape.fillers.iter().any(|f| tree.calls(f) == 2),
        "some filler WAS evicted and re-fetched — the pass was under real pressure"
    );
}

/// A root INTERIOR naming three children `(a, L), (b, M), (c, L)`:
/// `walk_dir` fetches `L`, `M`, then `L` AGAIN (the separator check
/// runs after the child's own walk returns), so ONE resume produces
/// the ask trace `root, L, M, L`. Promotion iterates first
/// occurrences only, so `L` is charged ONCE and the order is
/// `L, M` — the walk's, not the trace's multiplicity.
///
/// There are two mutation targets here, and only one is
/// distinguishable. Pushing every occurrence into `asked` is an
/// EQUIVALENT mutant: the promotion loop's own
/// `nodes.contains_key(&id)` guard already makes the second
/// occurrence a no-op. So is dropping that CLAUSE as well —
/// `!pool.contains_key(&id)` alone still skips an id already
/// promoted out of the pool, and the row passes (executed, with the
/// `debug_assert` dropped too). What this row kills is the loss of
/// the WHOLE compound guard: the first promotion then runs for the
/// ROOT, which round 1 has not yet made resident and which was never
/// pooled, so `pool.remove` answers `None`, `unwrap_or_default`
/// writes an EMPTY node under its id, and the dispatch's
/// unstable-fetch guard returns
/// `MissingObject` for the id it was about to need. The row reds at
/// its FIRST assertion, not at the charge pin below, and the
/// `debug_assert` never fires — the root is not in `nodes` yet when
/// the empty write happens.
#[tokio::test]
async fn a_repeated_ask_promotes_once() {
    let leaf_l = manifest::encode_dir_leaf(&[DirEntry {
        name: Name::new(b"a".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: ManifestEntryKind::Fifo,
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let l_id = GrainId::of(&leaf_l);
    let leaf_m = manifest::encode_dir_leaf(&[DirEntry {
        name: Name::new(b"b".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: ManifestEntryKind::Fifo,
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let m_id = GrainId::of(&leaf_m);
    let root_bytes = manifest::encode_dir_interior(&[
        manifest::InteriorChild {
            first_key: Name::new(b"a".to_vec()).unwrap_or_else(|e| panic!("{e}")),
            child: l_id,
            subtree_entry_count: 1,
        },
        manifest::InteriorChild {
            first_key: Name::new(b"b".to_vec()).unwrap_or_else(|e| panic!("{e}")),
            child: m_id,
            subtree_entry_count: 1,
        },
        manifest::InteriorChild {
            first_key: Name::new(b"c".to_vec()).unwrap_or_else(|e| panic!("{e}")),
            child: l_id,
            subtree_entry_count: 1,
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    tree.seed(&mut codec, &leaf_l);
    tree.seed(&mut codec, &leaf_m);
    let root_id = tree.seed(&mut codec, &root_bytes);

    let mut visits = VisitCounter::default();
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut budget = MetadataBudget::default();
    let err = fetch_tree_structure(
        &mut fetcher,
        None,
        &tree.entries,
        &tree.bins,
        &root_id,
        &mut budget,
        Some(&mut visits),
    )
    .await
    .expect_err("the third child's separator is wrong");
    assert!(
        matches!(
            err,
            ResolveError::Tree {
                source: ValidateError::SeparatorMismatch,
                ..
            }
        ),
        "{err:?}"
    );
    // The trace really did repeat: round 1 asks the root and stops;
    // round 2 asks root, L, M, L.
    assert_eq!(visits.total_visits, 5, "root, then root, L, M, L");
    assert_eq!(
        (budget.retained_nodes, budget.retained_bytes),
        (
            3,
            tree.len_of(&root_id) + tree.len_of(&l_id) + tree.len_of(&m_id)
        ),
        "L is charged ONCE, not once per occurrence"
    );
    assert_eq!(tree.calls(&l_id), 1, "and fetched once, speculatively");
}

/// Speculation never moves the budget. `prefetch_structure_nodes`
/// cannot touch it BY TYPE — the budget is not among its arguments,
/// which is the by-construction half of this guarantee. The half a
/// test can see is the arithmetic: after a run whose pool held MORE
/// than the walk promoted, the budget counts exactly what was
/// promoted or needed. The root names `n1`, a FAULT, `n3` and `n4`;
/// the walk needs `n1`, pools all three of the rest, errors on the
/// FAULT — so `n3` and `n4` sat in the pool, fetched and never
/// charged.
#[tokio::test]
async fn hints_never_move_the_budget() {
    let (_, subdirs, _) = four_subdirs(23);
    let fault_bytes = manifest::encode_grain_list_leaf(&[GrainRef {
        id: GrainId::of(b"hints-never-move-the-budget-grain"),
        unpacked_len: 1,
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let fault_id = GrainId::of(&fault_bytes);
    let root_entries: Vec<DirEntry> = [
        (1u32, subdirs[0].0),
        (2, fault_id),
        (3, subdirs[2].0),
        (4, subdirs[3].0),
    ]
    .into_iter()
    .map(|(i, child)| DirEntry {
        name: Name::new(format!("n{i}").into_bytes()).unwrap_or_else(|e| panic!("{e}")),
        kind: ManifestEntryKind::Dir { child },
    })
    .collect();
    let built = manifest::build_dir(&root_entries).unwrap_or_else(|e| panic!("{e}"));
    let (root_id, root_bytes) = built
        .nodes
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("one node"));
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    tree.seed(&mut codec, &subdirs[0].1);
    tree.seed(&mut codec, &fault_bytes);
    tree.seed(&mut codec, &subdirs[2].1);
    tree.seed(&mut codec, &subdirs[3].1);
    tree.root = tree.seed(&mut codec, &root_bytes);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut budget = MetadataBudget::default();
    let err = fetch_tree_structure(
        &mut fetcher,
        None,
        &tree.entries,
        &tree.bins,
        &root_id,
        &mut budget,
        Some(&mut VisitCounter::default()),
    )
    .await
    .expect_err("the second child is a grain-list leaf under a Dir entry");
    assert!(
        matches!(
            err,
            ResolveError::Tree {
                source: ValidateError::WrongObjectType { .. },
                ..
            }
        ),
        "{err:?}"
    );
    // n3 and n4 WERE speculated — one wire call each, no need path.
    assert_eq!(tree.calls(&subdirs[2].0), 1);
    assert_eq!(tree.calls(&subdirs[3].0), 1);
    // …and the budget counts only what was promoted or needed:
    // the root, n1, and the fault node the walk actually asked for.
    assert_eq!(
        (budget.retained_nodes, budget.retained_bytes),
        (
            3,
            tree.len_of(&root_id) + tree.len_of(&subdirs[0].0) + tree.len_of(&fault_id)
        ),
        "speculated-but-unpromoted nodes are not in the budget"
    );
}

/// A hint whose fetch FAILS is attempted exactly once
/// (`hint_tried`), and the need path that follows surfaces ITS
/// failure through `map_fetch_err` — for `NotFound`, exactly
/// `ResolveError::Missing { what: "manifest node", id }`. Two calls
/// at that extent: one speculative, one need.
///
/// The `Unavailable` half is MEASURED rather than assumed:
/// a shed answer is re-polled once by the
/// fetcher's own retry bound, and the re-poll succeeds, so the hint
/// LANDS and there is no need call at all — the count is 2, and the
/// id is NOT in `hint_tried`.
#[tokio::test]
async fn a_failed_hint_is_tried_once() {
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    // A node that is MAPPED but at an extent no bin serves.
    let missing_bytes = b"a-node-nothing-serves".to_vec();
    let missing_id = GrainId::of(&missing_bytes);
    tree.entries
        .insert(missing_id, unfetchable_entry(missing_id));
    tree.len.insert(missing_id, missing_bytes.len() as u64);
    // And one that is shed on its first read, then served.
    let shed_id = tree.seed(&mut codec, b"a-node-shed-once-then-served");
    let shed_entry = *tree
        .entries
        .get(&shed_id)
        .unwrap_or_else(|| panic!("seeded"));
    tree.seam.shed_extent(tree.bins[0], shed_entry.offset);

    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut state = PoolState::default();
    state
        .pass(
            &mut fetcher,
            &tree,
            vec![(missing_id, true), (shed_id, true)],
        )
        .await;
    assert!(!state.pool.contains_key(&missing_id), "the fetch failed");
    assert_eq!(tree.calls(&missing_id), 1);
    // BEHAVIOUR before state: a second pass naming it again must not
    // reach the wire. (Asserting `hint_tried` alone would be
    // asserting the mechanism's own presence.)
    state
        .pass(&mut fetcher, &tree, vec![(missing_id, true)])
        .await;
    assert_eq!(
        tree.calls(&missing_id),
        1,
        "one speculative attempt per id, however many passes name it"
    );
    assert!(
        state.tried.contains(&missing_id),
        "a failed hint is remembered — that is why"
    );
    // MEASURED: the shed want is re-polled once and then lands.
    assert!(state.pool.contains_key(&shed_id), "the retry served it");
    assert!(
        !state.tried.contains(&shed_id),
        "a hint that LANDED is not tried"
    );
    assert_eq!(
        tree.seam.bin_call_count(tree.bins[0], shed_entry.offset),
        2,
        "one shed + one re-poll"
    );

    // The need path for the failed hint, and its exact mapping.
    let mut budget = MetadataBudget::default();
    let err = fetch_one_need(
        &mut fetcher,
        None,
        &tree.entries,
        &tree.bins,
        &mut budget,
        &missing_id,
        missing_id,
    )
    .await
    .expect_err("nothing serves that extent");
    assert!(
        matches!(err, ResolveError::Missing { what: "manifest node", id } if id == missing_id),
        "{err:?}"
    );
    assert_eq!(tree.calls(&missing_id), 2, "one speculative, one need");
}

/// The documented invariant, on the 2,000-deep fixture and on `Ok`
/// only: every id the walk asked for is an id the pump holds. (On an
/// error the two differ by construction — the id the walk stopped on
/// was asked and never fetched.)
#[tokio::test]
async fn visited_equals_nodes_keys_on_ok() {
    let fixture = one_child_chain(2000);
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&fixture.seam, &mut fetch_state);
    let mut budget = MetadataBudget::default();
    let (nodes, stats, visited) = fetch_tree_structure(
        &mut fetcher,
        None,
        &fixture.entries,
        &fixture.bins,
        &fixture.root,
        &mut budget,
        Some(&mut VisitCounter::default()),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.dirs, 2000);
    let keys: BTreeSet<GrainId> = nodes.keys().copied().collect();
    assert_eq!(visited, keys, "visited == nodes.keys() on Ok");
    assert_eq!(visited.len(), 2000);
}

/// The ask-count observer on the same 2,000-deep fixture:
/// the root is asked at most twice and the walk's total asks
/// are at most `4 * nodes` — bounds held
/// with room to spare (the chain's exact figures are 2 and 2n).
#[tokio::test]
async fn the_walks_asks_stay_within_the_m7_observers_bounds() {
    let fixture = one_child_chain(2000);
    let mut visits = VisitCounter::default();
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&fixture.seam, &mut fetch_state);
    let mut budget = MetadataBudget::default();
    let (nodes, ..) = fetch_tree_structure(
        &mut fetcher,
        None,
        &fixture.entries,
        &fixture.bins,
        &fixture.root,
        &mut budget,
        Some(&mut visits),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    let n = nodes.len() as u64;
    assert!(
        visits.root_visits <= 2 && visits.total_visits <= 4 * n,
        "root asked {} times, {} asks over {n} nodes",
        visits.root_visits,
        visits.total_visits
    );
    assert_eq!(
        (visits.root_visits, visits.total_visits),
        (2, 2 * n),
        "the chain's exact figures, so a regression inside the bound still shows"
    );
}

/// THE INSTRUMENT: one INFO event per round from
/// `fetch_tree_structure`, cumulative counters, and a terminal
/// `outcome=done` line whose figures are complete — the line the
/// round-timing harness reads. On the four-subdirectory fixture the walk is
/// exactly three rounds: `Need(root)`; `Need(n1)` with n2, n3, n4
/// listed and pooled; `Done` with the three promoted. RED against
/// the removal of `log.emit` (zero events) and against a mutant that
/// emits after dispatch (two events, neither `done`); the exact
/// field text is asserted because the round-timing harness matches it.
#[tokio::test]
async fn the_round_loop_reports_every_round_and_a_complete_done_line() {
    use tracing_subscriber::layer::SubscriberExt as _;

    #[derive(Clone, Default)]
    struct EventCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    struct FieldVisitor(String);
    impl tracing::field::Visit for FieldVisitor {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() != "event" {
                use std::fmt::Write as _;
                let _ = write!(self.0, " {}={value}", field.name());
            }
        }
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EventCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::INFO
                && event.metadata().target() == "granary_client::resolve"
            {
                let mut visitor = FieldVisitor(String::new());
                event.record(&mut visitor);
                self.0
                    .lock()
                    .unwrap_or_else(|e| panic!("{e}"))
                    .push(visitor.0);
            }
        }
    }

    let (root_id, subdirs, root_bytes) = four_subdirs(31);
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let mut tree = SeededTree::new();
    tree.seed_all(&mut codec, &subdirs);
    tree.root = tree.seed(&mut codec, &root_bytes);

    let capture = EventCapture::default();
    let default_guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(capture.clone()));
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e:?}"));
    let mut fetcher = Fetcher::new(&tree.seam, &mut fetch_state);
    let mut budget = MetadataBudget::default();
    let (nodes, stats, _visited) = fetch_tree_structure(
        &mut fetcher,
        None,
        &tree.entries,
        &tree.bins,
        &root_id,
        &mut budget,
        Some(&mut VisitCounter::default()),
    )
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    drop(default_guard);
    assert_eq!((stats.dirs, nodes.len()), (5, 5));

    let events = capture.0.lock().unwrap_or_else(|e| panic!("{e}")).clone();
    // The count and the terminal line as ONE tuple: asserted apart, a
    // wrong count hides which line was last.
    let last = events.last().cloned().unwrap_or_default();
    assert_eq!(
        (events.len(), last.as_str()),
        (
            3,
            " message=structure walk round=3 outcome=done needs=2 hints=3 admits=3 \
             pool_len=0 pool_used=0"
        ),
        "three rounds, and the done line carries the complete totals: {events:?}"
    );
    // The two Need rounds report the counters BEFORE their own dispatch.
    assert_eq!(
        (events.first().cloned(), events.get(1).cloned()),
        (
            Some(
                " message=structure walk round=1 outcome=need needs=0 hints=0 admits=0 \
                 pool_len=0 pool_used=0"
                    .to_owned()
            ),
            Some(
                " message=structure walk round=2 outcome=need needs=1 hints=0 admits=0 \
                 pool_len=0 pool_used=0"
                    .to_owned()
            ),
        ),
        "{events:?}"
    );
}

// ------------------------------------------------- content streaming

/// The POSITIVE CONTROL for `the_row_225_overlap_arrives_as_entering_and_evicts`
/// (named rather than called "the row above": the split moved that row here
/// and this control had to follow it — a control's subject is the ROW it
/// controls, not the production item it happens to call):  the SAME `x_id`, in the
/// SAME worklist position, but NOT reachable through the directory
/// the cursor is entering — and it comes back under `queued_roots`.
/// This is what makes "reported only under `entering`" evidence of
/// the one-directional dedup rather than of `x_id` never having been
/// queued at all.
#[test]
fn an_id_outside_the_entering_directory_is_a_queued_root() {
    let x = fifo_leaf(b"m");
    let x_id = GrainId::of(&x);
    let absent_sub = GrainId::of(b"subdir-root-outside-the-entering-directory");
    let a = manifest::encode_dir_leaf(&[dir_entry(b"d1", absent_sub), dir_entry(b"d2", x_id)])
        .unwrap_or_else(|e| panic!("{e}"));
    let a_id = GrainId::of(&a);
    let mut resident: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    resident.insert(a_id, a);

    let mut cursor = manifest::TreeCursor::new(a_id);
    let step = cursor.resume(&|id| resident.get(id).cloned());
    assert!(
        matches!(&step, Ok(Step::Need(id)) if *id == absent_sub),
        "the cursor enters the FIRST child directory, which is absent: {step:?}"
    );
    let hints = cursor.prefetch_hints(&|id| resident.get(id).cloned(), manifest::PREFETCH_HINT_MAX);
    assert_eq!(
        (hints.entering, hints.queued_roots),
        (vec![absent_sub], vec![x_id]),
        "the same id, same worklist position: a QUEUED ROOT when the entering \
         directory cannot reach it"
    );
}
