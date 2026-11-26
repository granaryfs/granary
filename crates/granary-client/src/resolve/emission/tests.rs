// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::resolve::emission` — routing a resolved
//! target to the walk that serves it and streaming its grains in
//! manifest order, and the refusals that must land before any position
//! is walked.
//!
//! Out-of-line, one flat level under `emission`. The
//! rows here are the ones the item-to-test MAP assigns
//! to this child BY CALLER — never by a banner or a line
//! range, both of which have given this project a wrong
//! partition before. A row that drives the PARENT's
//! entry points (`resolve_at` and its siblings) stayed
//! with the parent even where its subject is emission's,
//! so that this file never reaches the parent's facade.
//!
//! **This file carries NO `#![expect(clippy::disallowed_methods)]`**,
//! and that is a measurement, not an oversight: all twelve sites in
//! the parent's `tests.rs` that FULFIL that expectation
//! (`std::fs::remove_dir_all` / `create_dir_all`, six pairs) sit in
//! rows and a fixture that stay with the parent. A copied `#![expect]`
//! with nothing to fulfil it is `unfulfilled_lint_expectations`, which
//! CI denies — so the licence staying put is what the caller map
//! decided, and the delta to `EXPECTED_LICENSED_SITES` is zero.
#![cfg(test)]

use super::*;

// Fixtures SHARED with the parent's rows stay in the parent's `tests.rs`
// as `pub(super)` items and are reached BY NAME — never by a glob of the
// parent's tests, which `wildcard_imports` would not catch and which
// is forbidden because it makes the bound set open.
use super::super::tests::{FakeSeam, routed_id, seed_grain};
// What these rows need beyond the child's own production imports. Named
// individually rather than widened: `use super::super::tests::*` would pull
// the parent's whole test surface in and make the bound set open;
// these dependencies must instead remain individually named.
use granary_core::manifest::{
    DirEntry, EntryKind as ManifestEntryKind, FILE_INLINE_MAX_REFS, GRAIN_UNPACKED_MAX,
    GRAINLIST_LEAF_MAX_REFS, GrainListIndexChild,
};
use granary_store::codec::GrainCodec;

use crate::fetcher::FetchState;

fn insert_grain_list_leaf(nodes: &mut BTreeMap<GrainId, Vec<u8>>, refs: &[GrainRef]) -> GrainId {
    let bytes = manifest::encode_grain_list_leaf(refs)
        .unwrap_or_else(|e| panic!("encode grain-list leaf: {e}"));
    let id = GrainId::of(&bytes);
    nodes.insert(id, bytes);
    id
}

fn insert_grain_list_index(
    nodes: &mut BTreeMap<GrainId, Vec<u8>>,
    children: &[GrainListIndexChild],
) -> GrainId {
    let bytes = manifest::encode_grain_list_index(children)
        .unwrap_or_else(|e| panic!("encode grain-list index: {e}"));
    let id = GrainId::of(&bytes);
    nodes.insert(id, bytes);
    id
}

fn assert_span_facts_match_positional_oracle(
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    manifest_root: &GrainId,
    grains: &FileGrains,
) {
    let facts = grain_span_facts(nodes, manifest_root, grains)
        .unwrap_or_else(|e| panic!("derive grain spans: {e}"));
    let declaring_node = GrainId::of(b"span oracle declaring node");
    let refs = flatten_grains(nodes, manifest_root, grains, declaring_node)
        .unwrap_or_else(|e| panic!("flatten oracle refs: {e}"));
    let streamed: Vec<(GrainRef, GrainId)> =
        grain_positions(nodes, manifest_root, grains, declaring_node)
            .collect::<Result<_, _>>()
            .unwrap_or_else(|e| panic!("stream positional refs: {e}"));
    assert_eq!(
        streamed, refs,
        "the streaming iterator must preserve every position and declaring node"
    );
    let oracle_facts = positional_grain_span_facts(&refs)
        .unwrap_or_else(|e| panic!("derive positional oracle spans: {e}"));
    assert_eq!(facts, oracle_facts, "the entire facts map must match");
    assert_eq!(
        duplicate_span_peak(&facts).to_be_bytes(),
        duplicate_span_peak_positional_oracle(&refs).to_be_bytes(),
        "the peak's exact u64 bytes must match the positional oracle"
    );
}

/// Bounded positional oracle for the edge-derived span tests. Production
/// emission uses [`grain_positions`] and never collects this sequence.
fn flatten_grains(
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    root: &GrainId,
    grains: &FileGrains,
    containing_dir_leaf: GrainId,
) -> Result<Vec<(GrainRef, GrainId)>, ResolveError> {
    match grains {
        FileGrains::Inline(refs) => Ok(refs.iter().map(|r| (*r, containing_dir_leaf)).collect()),
        FileGrains::Spill {
            root: spill_root, ..
        } => {
            let mut out = Vec::new();
            walk_grain_list_refs(nodes, root, spill_root, 1, &mut out)?;
            Ok(out)
        }
    }
}

/// One grain-list tree, pre-order left to right — which IS file order.
/// Depth-bounded for [`lookup_in_dir`]'s reason and by the same
/// constant; wrong-typed and over-depth nodes are the SAME internal
/// inconsistency [`lookup_in_dir`]'s own doc explains — the whole tree,
/// grain-list sub-trees included, already validated completely before
/// this walk ever runs.
fn walk_grain_list_refs(
    nodes: &BTreeMap<GrainId, Vec<u8>>,
    root: &GrainId,
    id: &GrainId,
    depth: u32,
    out: &mut Vec<(GrainRef, GrainId)>,
) -> Result<(), ResolveError> {
    if depth > DEPTH_MAX {
        return Err(ResolveError::Tree {
            root: *root,
            source: ValidateError::DepthExceeded,
        });
    }
    let bytes = node(nodes, root, id)?;
    let (ty, cursor) = encoding::open_envelope(bytes).map_err(decode_err("grain-list node"))?;
    match ty {
        ObjectType::GrainListLeaf => {
            out.extend(
                manifest::decode_grain_list_leaf(cursor)
                    .map_err(decode_err("grain-list leaf"))?
                    .into_iter()
                    .map(|r| (r, *id)),
            );
            Ok(())
        }
        ObjectType::GrainListIndex => {
            for ch in
                manifest::decode_grain_list_index(cursor).map_err(decode_err("grain-list index"))?
            {
                walk_grain_list_refs(nodes, root, &ch.child, depth + 1, out)?;
            }
            Ok(())
        }
        ObjectType::DirLeaf
        | ObjectType::DirInterior
        | ObjectType::Bin
        | ObjectType::BinmapIndex
        | ObjectType::BinTable
        | ObjectType::BinmapShard
        | ObjectType::Root
        | ObjectType::Sheaf => Err(ResolveError::Tree {
            root: *root,
            source: ValidateError::WrongObjectType { id: *id },
        }),
    }
}

fn max_declared_len(refs: &[(GrainRef, GrainId)]) -> BTreeMap<GrainId, u32> {
    let mut max_len: BTreeMap<GrainId, u32> = BTreeMap::new();
    for (r, _) in refs {
        max_len
            .entry(r.id)
            .and_modify(|len| *len = (*len).max(r.unpacked_len))
            .or_insert(r.unpacked_len);
    }
    max_len
}

fn positional_grain_span_facts(
    refs: &[(GrainRef, GrainId)],
) -> Result<BTreeMap<GrainId, GrainSpan>, ResolveError> {
    let mut facts = BTreeMap::new();
    for (position, (grain, declaring_node)) in refs.iter().enumerate() {
        let position = u32::try_from(position).map_err(|_| ResolveError::Tree {
            root: *declaring_node,
            source: ValidateError::CountMismatch,
        })?;
        facts
            .entry(grain.id)
            .and_modify(|span: &mut GrainSpan| {
                span.first = span.first.min(position);
                span.last = span.last.max(position);
                span.max_len = span.max_len.max(grain.unpacked_len);
            })
            .or_insert(GrainSpan {
                first: position,
                last: position,
                max_len: grain.unpacked_len,
            });
    }
    Ok(facts)
}

/// A bounded positional differential oracle for the edge-derived facts
/// and sweep. Tests never call it for position counts that are large
/// enough to make positional materialisation itself the subject.
fn duplicate_span_peak_positional_oracle(refs: &[(GrainRef, GrainId)]) -> u64 {
    let max_len = max_declared_len(refs);
    let mut spans: BTreeMap<GrainId, (usize, usize)> = BTreeMap::new();
    for (pos, (r, _)) in refs.iter().enumerate() {
        spans
            .entry(r.id)
            .and_modify(|(_, last)| *last = pos)
            .or_insert((pos, pos));
    }

    let mut events: BTreeMap<usize, i128> = BTreeMap::new();
    for (id, (first, last)) in &spans {
        if first == last {
            continue;
        }
        let len = i128::from(max_len.get(id).copied().unwrap_or(0));
        *events.entry(*first).or_insert(0) += len;
        *events.entry(*last + 1).or_insert(0) -= len;
    }

    let mut running: i128 = 0;
    let mut peak: u64 = 0;
    for delta in events.values() {
        running += delta;
        peak = peak.max(u64::try_from(running).unwrap_or(u64::MAX));
    }
    peak
}

#[test]
fn grain_span_value_layouts_are_twelve_bytes() {
    assert_eq!(std::mem::size_of::<GrainSpan>(), 12);
    assert_eq!(std::mem::size_of::<NodeReach>(), 12);
}

#[test]
fn path_target_has_no_positional_materialisation_before_emit_file() {
    const SOURCE: &str = include_str!("../emission.rs");
    let production = SOURCE
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or_default();
    let path_arm = production
        .split("ResolveTarget::Path(path) => {")
        .nth(1)
        .unwrap_or_default()
        .split("ResolveTarget::WholeTree => {")
        .next()
        .unwrap_or_default();

    assert!(
        path_arm.contains("lookup_in_dir("),
        "this row did not read the Path emission arm"
    );
    assert!(
        path_arm.contains("emit_file("),
        "the Path arm must still route a file through emit_file"
    );
    // `flatten_grains` lives in this test file, so it does not appear in the
    // production half AT ALL and a call to it here would not compile. That
    // leaves the ban naming a spelling the compiler already forbids, which is
    // not the class it exists to pin: a regression spelled any other way stays green. The
    // spelling-agnostic bans below are what actually hold the property.
    assert!(
        !path_arm.contains("flatten_grains("),
        "the Path arm must not materialise one tuple per declared position: {path_arm}"
    );
    assert!(
        !path_arm.contains(".collect::<Vec<_>>()")
            && !path_arm.contains("Vec::with_capacity(")
            && !path_arm.contains("Vec<Want>"),
        "the Path arm must not COLLECT a per-position sequence under any \
         spelling — the residency bound is what this pins, not one helper's \
         name: {path_arm}"
    );
}

#[test]
fn whole_tree_target_has_no_positional_file_or_combined_vectors() {
    const SOURCE: &str = include_str!("../emission.rs");
    let production = SOURCE
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or_default();
    let whole_tree_arm = production
        .split("ResolveTarget::WholeTree => {")
        .nth(1)
        .unwrap_or_default()
        .split("\n        }\n    }\n}")
        .next()
        .unwrap_or_default();

    assert!(
        whole_tree_arm.contains("walk_all_files("),
        "this row did not read the WholeTree emission arm"
    );
    assert!(
        whole_tree_arm.contains("emit_file("),
        "the WholeTree arm must still route every file through emit_file"
    );
    assert!(
        !whole_tree_arm.contains("combined: Vec<(GrainRef, GrainId)>")
            && !whole_tree_arm.contains("file.refs"),
        "WholeTree must not retain positional refs per file or in a combined vector: \
         {whole_tree_arm}"
    );

    let directory_walk = production
        .split("fn collect_dir_actions(")
        .nth(1)
        .unwrap_or_default()
        .split("fn duplicate_span_peak(")
        .next()
        .unwrap_or_default();
    assert!(
        directory_walk.contains("DirAction::EmitFile"),
        "this row did not read the directory file-action builder"
    );
    // Same as the Path arm above: `flatten_grains` is not in the
    // production half at all, so this ban names a spelling the compiler
    // already forbids. The spelling-agnostic pair is what holds the property.
    assert!(
        !directory_walk.contains("flatten_grains("),
        "DirAction::EmitFile must not materialise one tuple per declared position: \
         {directory_walk}"
    );
    assert!(
        !directory_walk.contains(".collect::<Vec<_>>()")
            && !directory_walk.contains("Vec::with_capacity("),
        "the directory file-action builder must not COLLECT a per-position \
         sequence under any spelling: {directory_walk}"
    );
}

#[test]
fn emit_file_has_no_positional_want_vector() {
    const SOURCE: &str = include_str!("../emission.rs");
    let production = SOURCE
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or_default();
    let emit_file = production
        .split("async fn emit_file<R: BinStore>(")
        .nth(1)
        .unwrap_or_default()
        .split("\n}")
        .next()
        .unwrap_or_default();

    assert!(
        emit_file.contains("duplicate_span_peak("),
        "this row did not read emit_file"
    );
    assert!(
        emit_file.contains("fetch_streaming("),
        "emit_file must still use the bounded streaming fetcher"
    );
    assert!(
        emit_file.contains("grain_positions(")
            && emit_file.contains(".map(|position|")
            && emit_file.contains("fetch_streaming(cache, wants"),
        "emit_file must map the positional iterator directly into fetch_streaming: \
         {emit_file}"
    );
    let order = (
        emit_file.find("let span_facts = grain_span_facts("),
        emit_file.find("residency_preflight("),
        emit_file.find("let peak = duplicate_span_peak("),
        emit_file.find("let wants ="),
        emit_file.find("grain_positions("),
    );
    assert!(
        matches!(
            order,
            (
                Some(facts),
                Some(preflight),
                Some(peak),
                Some(wants),
                Some(positions),
            ) if facts < preflight
                && preflight < peak
                && peak < wants
                && wants < positions
        ),
        "emit_file must derive facts, run degraded residency, gate the exact peak, and only \
         then walk streaming wants: {emit_file}"
    );
    assert!(
        !emit_file.contains("Vec<Want>") && !emit_file.contains("Vec::with_capacity(refs.len())"),
        "emit_file must pass a streaming want iterator instead of retaining one want per \
         position: {emit_file}"
    );
}

#[test]
fn merge_grain_span_keeps_extrema_when_a_later_merge_is_lower() {
    let id = GrainId::of(b"order-independent grain span");
    let grain = GrainRef {
        id,
        unpacked_len: 9,
    };
    let mut facts = BTreeMap::new();

    merge_grain_span(&mut facts, grain, 10, 20);
    merge_grain_span(&mut facts, grain, 3, 7);

    assert_eq!(
        facts,
        BTreeMap::from([(
            id,
            GrainSpan {
                first: 3,
                last: 20,
                max_len: 9,
            },
        )]),
        "merging a lower range later must keep both positional extrema"
    );
}

#[test]
fn grain_span_facts_match_the_oracle_for_a_shared_leaf() {
    let a = GrainId::of(b"shared-leaf a");
    let b = GrainId::of(b"shared-leaf b");
    let refs = [
        GrainRef {
            id: a,
            unpacked_len: 2,
        },
        GrainRef {
            id: b,
            unpacked_len: 3,
        },
    ];
    let mut nodes = BTreeMap::new();
    let leaf = insert_grain_list_leaf(&mut nodes, &refs);
    let root = insert_grain_list_index(
        &mut nodes,
        &[
            GrainListIndexChild {
                child: leaf,
                cum_unpacked_len: 5,
                cum_ref_count: 2,
            },
            GrainListIndexChild {
                child: leaf,
                cum_unpacked_len: 10,
                cum_ref_count: 4,
            },
        ],
    );
    let grains = FileGrains::Spill {
        grain_count: 4,
        root,
    };
    assert_span_facts_match_positional_oracle(&nodes, &root, &grains);
}

#[test]
fn grain_span_facts_match_the_oracle_for_a_shared_index() {
    let a = GrainId::of(b"shared-index a");
    let b = GrainId::of(b"shared-index b");
    let mut nodes = BTreeMap::new();
    let leaf_a = insert_grain_list_leaf(
        &mut nodes,
        &[GrainRef {
            id: a,
            unpacked_len: 2,
        }],
    );
    let leaf_b = insert_grain_list_leaf(
        &mut nodes,
        &[GrainRef {
            id: b,
            unpacked_len: 3,
        }],
    );
    let shared = insert_grain_list_index(
        &mut nodes,
        &[
            GrainListIndexChild {
                child: leaf_a,
                cum_unpacked_len: 2,
                cum_ref_count: 1,
            },
            GrainListIndexChild {
                child: leaf_b,
                cum_unpacked_len: 5,
                cum_ref_count: 2,
            },
        ],
    );
    let root = insert_grain_list_index(
        &mut nodes,
        &[
            GrainListIndexChild {
                child: shared,
                cum_unpacked_len: 5,
                cum_ref_count: 2,
            },
            GrainListIndexChild {
                child: shared,
                cum_unpacked_len: 10,
                cum_ref_count: 4,
            },
        ],
    );
    let grains = FileGrains::Spill {
        grain_count: 4,
        root,
    };
    assert_span_facts_match_positional_oracle(&nodes, &root, &grains);
}

#[test]
fn grain_span_facts_match_the_oracle_for_a_within_leaf_duplicate() {
    let repeated = GrainId::of(b"within-leaf duplicate");
    let refs: Vec<GrainRef> = (0..=FILE_INLINE_MAX_REFS)
        .map(|i| GrainRef {
            id: if i == 0 || i == FILE_INLINE_MAX_REFS {
                repeated
            } else {
                routed_id(0, 0, u64::from(i))
            },
            unpacked_len: 1,
        })
        .collect();
    let mut nodes = BTreeMap::new();
    let root = insert_grain_list_leaf(&mut nodes, &refs);
    let grains = FileGrains::Spill {
        grain_count: u32::try_from(refs.len()).unwrap_or(u32::MAX),
        root,
    };
    assert_span_facts_match_positional_oracle(&nodes, &root, &grains);
}

#[test]
fn grain_span_facts_match_the_oracle_for_conflicting_declared_lengths() {
    let repeated = GrainId::of(b"conflicting declared lengths");
    let refs: Vec<GrainRef> = (0..=FILE_INLINE_MAX_REFS)
        .map(|i| GrainRef {
            id: repeated,
            unpacked_len: if i == 0 { 7 } else { 1 },
        })
        .collect();
    let mut nodes = BTreeMap::new();
    let root = insert_grain_list_leaf(&mut nodes, &refs);
    let grain_count = u32::try_from(refs.len()).unwrap_or(u32::MAX);
    let grains = FileGrains::Spill { grain_count, root };
    let size = refs.iter().map(|r| u64::from(r.unpacked_len)).sum();
    let dir = manifest::build_dir(&[DirEntry {
        name: Name::new(b"conflicting-lengths.bin".to_vec())
            .unwrap_or_else(|e| panic!("build file name: {e}")),
        kind: ManifestEntryKind::File {
            exec: false,
            size,
            grains: grains.clone(),
        },
    }])
    .unwrap_or_else(|e| panic!("build validating directory: {e}"));
    nodes.extend(dir.nodes);
    manifest::validate_dir_tree(&dir.root, &|id| nodes.get(id).cloned())
        .unwrap_or_else(|e| panic!("conflicting per-id lengths must validate: {e}"));

    let facts = grain_span_facts(&nodes, &dir.root, &grains)
        .unwrap_or_else(|e| panic!("derive conflicting-length spans: {e}"));
    let declaring_node = GrainId::of(b"conflicting-length oracle declaring node");
    let positional_refs = flatten_grains(&nodes, &dir.root, &grains, declaring_node)
        .unwrap_or_else(|e| panic!("flatten conflicting-length oracle refs: {e}"));
    let oracle_facts = positional_grain_span_facts(&positional_refs)
        .unwrap_or_else(|e| panic!("derive conflicting-length oracle spans: {e}"));
    assert_eq!(facts, oracle_facts, "the entire facts map must match");
    assert_eq!(
        duplicate_span_peak(&facts),
        7,
        "the larger declaration must weight the repeated id's span"
    );
    assert_eq!(
        duplicate_span_peak_positional_oracle(&positional_refs),
        7,
        "the independent positional oracle must agree on the exact peak"
    );
}

#[test]
fn grain_span_facts_cover_the_repeated_leaf_file_in_closed_form() {
    const CHILDREN: u32 = 32_767;
    const LEAF_REFS: u32 = GRAINLIST_LEAF_MAX_REFS;

    let refs: Vec<GrainRef> = (0..LEAF_REFS)
        .map(|i| GrainRef {
            id: routed_id(0, 0, u64::from(i)),
            unpacked_len: 1,
        })
        .collect();
    let mut nodes = BTreeMap::new();
    let leaf = insert_grain_list_leaf(&mut nodes, &refs);
    let children: Vec<GrainListIndexChild> = (1..=CHILDREN)
        .map(|i| GrainListIndexChild {
            child: leaf,
            cum_unpacked_len: u64::from(i) * u64::from(LEAF_REFS),
            cum_ref_count: u64::from(i) * u64::from(LEAF_REFS),
        })
        .collect();
    let root = insert_grain_list_index(&mut nodes, &children);
    let grain_count = CHILDREN
        .checked_mul(LEAF_REFS)
        .unwrap_or_else(|| panic!("the accepted fixture's count must fit u32"));
    assert_eq!(grain_count, 4_294_836_224);

    let facts = grain_span_facts(&nodes, &root, &FileGrains::Spill { grain_count, root })
        .unwrap_or_else(|e| panic!("derive repeated-leaf spans: {e}"));
    assert_eq!(facts.len(), refs.len());
    let last_leaf_start = (CHILDREN - 1)
        .checked_mul(LEAF_REFS)
        .unwrap_or_else(|| panic!("the last leaf start must fit u32"));
    for (local_index, r) in (0_u32..).zip(&refs) {
        assert_eq!(
            facts.get(&r.id),
            Some(&GrainSpan {
                first: local_index,
                last: last_leaf_start
                    .checked_add(local_index)
                    .unwrap_or_else(|| panic!("the closed-form last position must fit u32")),
                max_len: 1,
            })
        );
    }
}

/// An ACCEPTED high-expansion spill supplies positions incrementally
/// and still completes emission. Eight references to one maximal
/// shared leaf produce 1,048,576 positions; consuming and abandoning
/// a short prefix must produce exactly that prefix, whereas collecting
/// the position stream first would produce all 1,048,576.
///
/// The sink count proves the iterator was consumed to the declared
/// end on the accepted emission path, rather than the prefix assertion
/// passing over an empty or refused stream. This proves incremental
/// position supply and guards `emit_file` against collecting either
/// positional walk; it does not prove sublinear time or a byte-level
/// allocation bound elsewhere in resolve.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one self-contained row keeps the large fixture, early-stop proof, and full-emission control together"
)]
async fn accepted_shared_leaf_position_supply_stops_at_demand_and_emits_fully() {
    const EXPANSION: u32 = 8;
    const EARLY_POSITIONS: u32 = 3;
    const LEAF_REFS: u32 = GRAINLIST_LEAF_MAX_REFS;

    const SOURCE: &str = include_str!("../emission.rs");
    let production = SOURCE
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or_default();
    // Kept in two bindings so the over-run guard below can compare them:
    // everything after the signature, then that truncated at the terminator.
    let after_signature = production
        .split("async fn emit_file<R: BinStore>(")
        .nth(1)
        .unwrap_or_default();
    let emit_file_source = after_signature.split("\n}").next().unwrap_or_default();
    // POSITIVE CONTROL, and it is the whole reason this row can be
    // trusted. The slice above is `.nth(1).unwrap_or_default()` — if
    // `emit_file` ever leaves this file, that is `""`, and
    // `!"".contains(...)` is `true`, so the ban below would pass VACUOUSLY
    // AND FOREVER while verifying nothing.
    //
    // **The split this control was written for HAS HAPPENED**: the
    // `emission` child landed and this reader now reads `../emission.rs`.
    // What it asserted was `emit_file_source.len() > 200` and nothing
    // else, which a surviving doc comment or a forwarding wrapper could
    // satisfy while the real body lived elsewhere — the gap found in
    // review. To close it, the control must assert a needle distinctive
    // of the BODY, not only a signature and a length.
    // `grain_positions(` is the
    // right needle because it is what PRODUCES the position stream the
    // ban below forbids collecting; if it is absent the ban has no
    // subject and its silence means nothing.
    assert!(
        emit_file_source.contains("grain_positions("),
        "the emit_file slice ({} bytes) does not contain `grain_positions(` \
         — this row read no body it can judge, so its ban below would pass \
         VACUOUSLY. Either `emit_file` has moved again (re-point the \
         include_str! at the module that now holds it) or it no longer \
         walks positions at all, which is a product change this row must \
         not silently accept.",
        emit_file_source.len()
    );
    // THE OVER-RUN GUARD, and it is NOT the `!contains("mod tests")` form
    // that readers 1 and 6 carry. That form cannot fail: `production` is by
    // construction everything BEFORE the sole `#[cfg(test)]\nmod tests`
    // marker, so no slice of it can contain that text — measured, zero
    // occurrences — and removing `emit_file`'s own terminator, the exact
    // failure it names, leaves it returning `true`. It is a control that
    // reads as one and is not one, and two more controls in this
    // file carry the same defect.
    //
    // What actually detects the over-run is whether the terminator was
    // FOUND: if `"\n}"` is absent, `.split(...).next()` hands back the whole
    // remainder, so the slice and the text after the signature are the same
    // length. Intact that is 10,906 vs 10,902; with the terminator removed
    // both are 10,904 and this fires.
    assert!(
        after_signature.len() > emit_file_source.len(),
        "the emit_file slice ({} bytes) ran to the end of the production \
         half — its closing `\n}}` terminator was not found, so the ban \
         below is judged over more than `emit_file`, which is a broader \
         assertion than this row makes",
        emit_file_source.len()
    );
    assert!(
        !emit_file_source.contains(".collect::<Vec<_>>()"),
        "emit_file must not collect a position stream before consuming it"
    );

    let seam = FakeSeam::default();
    let mut codec = GrainCodec::new().unwrap_or_else(|e| panic!("{e}"));
    let bin_digest = [0x1a_u8; DIGEST_LEN];
    let payload = [0x5a_u8];
    let (content_id, content_entry) = seed_grain(&seam, &mut codec, bin_digest, &payload);
    let grain = GrainRef {
        id: content_id,
        unpacked_len: 1,
    };
    let refs = vec![grain; usize::try_from(LEAF_REFS).unwrap_or(usize::MAX)];

    let mut nodes = BTreeMap::new();
    let leaf = insert_grain_list_leaf(&mut nodes, &refs);
    let children: Vec<GrainListIndexChild> = (1..=EXPANSION)
        .map(|i| GrainListIndexChild {
            child: leaf,
            cum_unpacked_len: u64::from(i) * u64::from(LEAF_REFS),
            cum_ref_count: u64::from(i) * u64::from(LEAF_REFS),
        })
        .collect();
    let spill_root = insert_grain_list_index(&mut nodes, &children);
    let grain_count = EXPANSION
        .checked_mul(LEAF_REFS)
        .unwrap_or_else(|| panic!("the bounded fixture count must fit u32"));
    assert_eq!(grain_count, 1_048_576);
    let grains = FileGrains::Spill {
        grain_count,
        root: spill_root,
    };

    let file_name = Name::new(b"accepted-shared-leaf.bin".to_vec())
        .unwrap_or_else(|e| panic!("build shared-leaf file name: {e}"));
    let dir = manifest::build_dir(&[DirEntry {
        name: file_name,
        kind: ManifestEntryKind::File {
            exec: false,
            size: u64::from(grain_count),
            grains: grains.clone(),
        },
    }])
    .unwrap_or_else(|e| panic!("build shared-leaf directory: {e}"));
    nodes.extend(dir.nodes);
    manifest::validate_dir_tree(&dir.root, &|id| nodes.get(id).cloned())
        .unwrap_or_else(|e| panic!("the shared-leaf manifest must validate: {e}"));

    let facts = grain_span_facts(&nodes, &dir.root, &grains)
        .unwrap_or_else(|e| panic!("derive shared-leaf spans: {e}"));
    assert_eq!(facts.len(), 1, "the fixture has one unique content grain");
    assert_eq!(
        duplicate_span_peak(&facts),
        1,
        "one shared one-byte grain must pass far below the 64 MiB peak gate"
    );

    let produced = std::cell::Cell::new(0_u32);
    assert!(
        EARLY_POSITIONS < grain_count / 1_000,
        "the abandoned prefix must be far smaller than the declared position count"
    );
    {
        let mut positions = grain_positions(&nodes, &dir.root, &grains, dir.root).inspect(|_| {
            produced.set(produced.get().saturating_add(1));
        });
        for expected in 0..EARLY_POSITIONS {
            let (position, declaring_node) = positions
                .next()
                .unwrap_or_else(|| panic!("position {expected} must exist"))
                .unwrap_or_else(|e| panic!("position {expected} must decode: {e}"));
            assert_eq!(position, grain);
            assert_eq!(declaring_node, leaf);
        }
    }
    assert_eq!(
        produced.get(),
        EARLY_POSITIONS,
        "abandoning the position stream must not produce its unconsumed tail"
    );

    let entries = BTreeMap::from([(content_id, content_entry)]);
    let bins = [bin_digest];
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("build fetcher: {e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let mut emitted = 0_u32;
    let mut sink = |id: GrainId, bytes: &[u8]| -> Result<(), String> {
        assert_eq!(id, content_id);
        assert_eq!(bytes, payload);
        emitted = emitted.saturating_add(1);
        Ok(())
    };

    let outcome = emit_file(
        &mut fetcher,
        None,
        &entries,
        &bins,
        &nodes,
        &dir.root,
        &grains,
        dir.root,
        &mut sink,
        None,
    )
    .await;

    outcome.unwrap_or_else(|e| panic!("accepted shared-leaf emission failed: {e}"));
    assert_eq!(
        emitted, grain_count,
        "the sink must observe every declared position"
    );
}

#[tokio::test]
async fn degraded_residency_error_precedes_duplicate_span_error() {
    const DISTINCT_GRAINS: u64 = 9;

    let first: Vec<GrainRef> = (0..DISTINCT_GRAINS)
        .map(|i| GrainRef {
            id: routed_id(0, 0, i),
            unpacked_len: GRAIN_UNPACKED_MAX,
        })
        .collect();
    let mut refs = first.clone();
    refs.extend(first.iter().copied());
    let grains = FileGrains::Inline(refs);
    let facts = grain_span_facts(&BTreeMap::new(), &GrainId::of(b"root"), &grains)
        .unwrap_or_else(|e| panic!("derive ordering fixture facts: {e}"));
    assert_eq!(
        duplicate_span_peak(&facts),
        72 * 1024 * 1024,
        "the later error must be the exact existing 72 MiB refusal"
    );

    let seam = FakeSeam::default();
    let mut fetch_state = FetchState::new().unwrap_or_else(|e| panic!("{e}"));
    let mut fetcher = Fetcher::new(&seam, &mut fetch_state);
    let source = RootStoreError::Unavailable {
        operation: "GET bin",
        status: 503,
    };
    let root = GrainId::of(b"root");
    let declaring_node = GrainId::of(b"declaring node");
    let mut sink_calls = 0_usize;
    let mut sink = |_id: GrainId, _bytes: &[u8]| -> Result<(), String> {
        sink_calls = sink_calls.saturating_add(1);
        Ok(())
    };
    let outcome = emit_file(
        &mut fetcher,
        None,
        &BTreeMap::new(),
        &[],
        &BTreeMap::new(),
        &root,
        &grains,
        declaring_node,
        &mut sink,
        Some(&source),
    )
    .await;
    match outcome {
        Err(ResolveError::Degraded {
            missing,
            source: got_source,
        }) => {
            assert_eq!(
                missing,
                format!("content grain {}", routed_id(0, 0, 0)),
                "the residency preflight must report the first missing position"
            );
            assert!(matches!(
                got_source,
                RootStoreError::Unavailable {
                    operation: "GET bin",
                    status: 503,
                }
            ));
        }
        other => {
            panic!("degraded residency must win before DuplicateSpanExceedsBudget, got {other:?}")
        }
    }
    assert_eq!(sink_calls, 0, "neither refusal may emit bytes");
}

/// What this row pins, exactly, and nothing wider.
///
/// 1. **The two PROJECT-OWNED inputs, to the integer.**
///    `FILE_INLINE_MAX_REFS` and [`WHOLE_TREE_PATH_BUDGET`] are this
///    project's own numbers; neither can drift by toolchain, and a
///    change to either is exactly what stales the hardcoded figures
///    in the constant's doc (the 128, the 5,200 B per emission, the
///    5.08 GiB ceiling, the 65x gap, the 8,192-file alternative).
///    Same form as `the_metadata_budget_constants_are_pinned` above:
///    the numbers, not a relation between them.
/// 2. **The layout-dependent product, to an ORDER OF MAGNITUDE
///    only.** `size_of` on a `repr(Rust)` type is not a stable
///    contract, so an exact assertion on it would red on a
///    toolchain bump that broke nothing. The window says the
///    constant's doc is right that the ceiling is measured in
///    GIGABYTES — the window is 4 GiB up to 16 GiB — not megabytes.
///
/// **What it does NOT pin: the arithmetic in general.** The window
/// is wide enough to stay green under a 2x move in any single input
/// (a 256-ref inline cap gives ~10.8 GB, a doubled budget ~10.9 GB,
/// a 48-byte `GrainRef` ~6.5 GB) while every hardcoded figure in the
/// doc goes stale. Pin 1 catches the two of those inputs this
/// project OWNS, exactly, which is why it is here and why it is
/// exact. It does NOT catch the layout-dependent ones: a compiler
/// that changed `FileEmission` or `GrainRef`'s size would stale the
/// doc's per-emission figure while both pins still pass and the
/// order-of-magnitude window still holds. That gap is deliberate —
/// `size_of` is not a stable contract for a `repr(Rust)` type, so
/// pinning it exactly would red on a toolchain bump that broke
/// nothing — but it is a gap, and it is stated rather than implied
/// away.
#[test]
fn the_whole_tree_path_budgets_retained_byte_ceiling_stays_gigabytes() {
    assert_eq!(FILE_INLINE_MAX_REFS, 128);
    assert_eq!(WHOLE_TREE_PATH_BUDGET, 1 << 20);

    // `u64` throughout, not `usize`: on a 32-bit target `4 << 30`
    // overflows `usize` and the product (~5.45e9) is past
    // `usize::MAX`, so a `usize` form is not portable arithmetic.
    let per_emission = size_of::<FileEmission>() as u64
        + u64::from(FILE_INLINE_MAX_REFS) * size_of::<GrainRef>() as u64;
    let ceiling = WHOLE_TREE_PATH_BUDGET as u64 * per_emission;
    assert!(
        (4_u64 << 30..16_u64 << 30).contains(&ceiling),
        "the budget's documented retained-byte ceiling is stated in \
         GIGABYTES; it is now {ceiling} bytes ({per_emission} per emission \
         over {WHOLE_TREE_PATH_BUDGET} actions), so the constant's doc and \
         the public `WholeTree` doc need re-deriving"
    );
}

// ------------------------------------------------- oracle hole 2

/// **`held` must actually EVICT a fully-drained id, not retain it
/// for the rest of the call.** A structural regression here reads
/// a completed position's bytes via `held.get` and never calls
/// `held.remove`, so every grain a file ever streamed stays
/// resident until the whole function returns: O(file size)
/// retained instead of O(one grain in flight at a time).
///
/// **Why this is a source scan and not a behavioural row.**
/// Retaining a byte buffer forever after it has already been
/// emitted changes nothing this process can observe from the
/// OUTSIDE of `emit_file`: the fetcher's own released /
/// in-flight-bytes bookkeeping is governed entirely by
/// `charged_unreleased`, a SEPARATE set that a stale `held` entry
/// never touches, and the emitted bytes themselves are identical
/// either way. This is the same call
/// `check_head_verifies_over_the_received_bytes_and_never_a_re_encoding`
/// (in `granary-store`) makes for a peer defect class, and for
/// the same reason: there is no honest behavioural instrument for
/// "retains forever", so the source is where the difference lives.
#[test]
fn an_emitted_grain_leaves_the_holdback() {
    const SOURCE: &str = include_str!("../emission.rs");
    const OPENS: &str = "async fn emit_file<R: BinStore>(";

    let production = SOURCE
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or_default();
    // Bound separately so the over-run guard below can compare the two: the
    // terminator was found iff truncating at it actually shortened the text.
    let after_signature = production.split(OPENS).nth(1).unwrap_or_default();
    // The raw slice is kept as its own binding, because the over-run guard
    // below must compare a length the COMMENT FILTER has not already shortened.
    let raw_slice = after_signature.split("\n}").next().unwrap_or_default();
    let body: String = raw_slice
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    // Positive control first: a gate that cannot tell "clean" from
    // "read nothing" is not a gate.
    assert!(
        body.contains("let mut held: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();"),
        "this row did not read the code it is judging"
    );
    // THE OVER-RUN GUARD, and it took FOUR forms. The first three could not
    // fail, each for a different reason, which is why the comparison here is
    // spelled against `raw_slice` and not against `body`:
    //   `!body.contains("mod tests")` — `production` ends at that marker, so
    //      no slice of it can hold the text.
    //   `body.len() < production.len()` — an over-run stops at the next
    //      terminator, not at the end of the file.
    //   `body.len() < after_signature.len()` — `body` has already had its
    //      COMMENT LINES removed (51 of them, ~3.4 KB here), so it is shorter
    //      than `after_signature` whatever the terminator did. Measured:
    //      intact 7,493 vs 10,906; with the terminator gone 7,495 vs 10,904,
    //      and the guard still passed. This form was written after measuring
    //      the SIBLING reader in this file, which has no comment filter — the
    //      mutation was executed there and the result attributed here.
    // What fires is the UNFILTERED slice against the text after the
    // signature: intact 10,902 vs 10,906; terminator gone, 10,904 vs 10,904.
    assert!(
        raw_slice.len() < after_signature.len(),
        "the emit_file slice is the WHOLE remainder after its signature — \
         the closing terminator was not found, so the checks below are \
         judging more than `emit_file`"
    );

    assert!(
        body.contains("held.remove(&want_id)"),
        "the drain loop must actually EVICT a fully-drained id from `held` \
         — reading it via `held.get` and never removing it retains every \
         grain a file ever streamed for the rest of the call: {body}"
    );
    // The removal must be GATED on the edge-derived LAST position,
    // not merely present somewhere unconditionally — an id
    // referenced more than once must survive until that exact
    // position, never only until its first.
    assert!(
        body.contains("last == next_pos") && body.contains("if at_last"),
        "eviction must be gated on equality with the edge-derived last position, \
         not unconditional on every drained position: {body}"
    );
}

/// A repeated-child DAG fixture — every level's
/// leaf has 8 entries all naming ONE child directory, 6 deep
/// (8^6 = 262,144 paths from 7 nodes) — refuses at the NINTH
/// path under a budget of 8, before the allocation grows.
#[test]
fn a_repeated_child_dag_refuses_past_the_path_budget_before_allocating() {
    let file_id = GrainId::of(b"repeated-dag-file");
    let mut nodes: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let leaf = manifest::build_dir(&[DirEntry {
        name: Name::new(b"f".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: ManifestEntryKind::File {
            exec: false,
            size: 7,
            grains: FileGrains::Inline(vec![GrainRef {
                id: file_id,
                unpacked_len: 7,
            }]),
        },
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let mut child = leaf.root;
    for (id, b) in leaf.nodes {
        nodes.insert(id, b);
    }
    for _level in 0..6 {
        let entries: Vec<DirEntry> = (0..8)
            .map(|i| DirEntry {
                name: Name::new(format!("d{i}").into_bytes()).unwrap_or_else(|e| panic!("{e}")),
                kind: ManifestEntryKind::Dir { child },
            })
            .collect();
        let built = manifest::build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
        child = built.root;
        for (id, b) in built.nodes {
            nodes.insert(id, b);
        }
    }
    assert_eq!(nodes.len(), 7, "seven nodes, 262,144 paths");
    let Err(err) = walk_all_files(&nodes, &child, 8) else {
        panic!("a 262,144-path DAG under a budget of 8 must refuse");
    };
    // Nine EXPANDED ACTIONS, not nine paths: six descents down to
    // the leaf directory, its one file emitted, one descent back
    // into the second branch, and the ninth action crosses. (Under
    // the emission-only charge this file's budget happened to give
    // the same number for a different reason — see the 300,000 case
    // below, where the two part company.)
    assert!(
        matches!(
            err,
            ResolveError::PathBudgetExceeded {
                attempted: 9,
                budget: 8
            }
        ),
        "refused at the ninth expanded action: {err:?}"
    );
    // The rendering names the budget this walk actually ran under,
    // not `WHOLE_TREE_PATH_BUDGET`: a message that reached for the
    // constant would report a bound of 1,048,576 beside an
    // `attempted` of 9 and contradict itself.
    assert_eq!(
        err.to_string(),
        "resolving the whole tree needs more than the 8 expanded actions (directory \
         descents and file emissions) it is allowed; refused at action 9",
        "the refusal must name the budget it was measured against, and must not present \
         the point of refusal as the tree's size"
    );
    // A budget that TELLS THE TWO CHARGES APART. This DAG emits
    // 8^6 = 262,144 files but takes 8 + 8² + … + 8⁶ = 299,592
    // descents on top of them, so a budget of 300,000 is comfortably
    // above the emission count and below the action count: charging
    // actions refuses, charging emissions returns `Ok` with every
    // file. (The two numbers above — 9 and 9 — happen to agree under
    // both charges; this one does not, and the all-empty DAG below
    // is the other half of the evidence.)
    let Err(err) = walk_all_files(&nodes, &child, 300_000) else {
        panic!("300,000 actions is under this DAG's 561,736: it must refuse");
    };
    assert!(
        matches!(
            err,
            ResolveError::PathBudgetExceeded {
                attempted: 300_001,
                budget: 300_000
            }
        ),
        "refused on an action past the 262,144 files an emission charge counts: {err:?}"
    );
    // THE TWO MARGINS ARE NOT THE SAME SIZE, and 300,000 is
    // load-bearing because of the smaller one. Against an
    // EMISSION-only charge the margin is 37,856 actions (262,144
    // emissions under a 300,000 budget, ~14%). Against a
    // DESCENT-only charge it is 408 (299,592 descents under the
    // same budget, 0.14%) — and the descent-only charge is what
    // this case kills by that thin margin, via the `else` panic
    // above rather than the assertion. One more level on this DAG
    // takes the descents alone to 2,396,744: a descent-only charge
    // would then refuse too, at the very same `attempted`, and this
    // case would go on passing while discriminating nothing.
    // Deepen the DAG and this budget has to move with it.
}

/// An emission-only charge left this gap: a
/// DAG whose directory entries all name one child, six levels deep,
/// whose innermost directory holds NO FILE AT ALL. `out.len()` never
/// leaves 0, so a budget on emissions is never consulted, while the
/// walk expands 8 + 8² + … + 8⁶ ≈ 299,592 directory actions. Charging
/// every expanded action refuses it at the budget; charging only
/// emissions returns `Ok(vec![])` after running the whole thing.
#[test]
fn an_empty_directory_dag_is_refused_by_the_descent_charge() {
    let mut nodes: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    // The innermost directory: one FIFO entry, so it yields NO
    // action at all — nothing to emit, nothing to descend into.
    let leaf = manifest::build_dir(&[DirEntry {
        name: Name::new(b"fifo".to_vec()).unwrap_or_else(|e| panic!("{e}")),
        kind: ManifestEntryKind::Fifo,
    }])
    .unwrap_or_else(|e| panic!("{e}"));
    let mut child = leaf.root;
    for (id, b) in leaf.nodes {
        nodes.insert(id, b);
    }
    for _level in 0..6 {
        let entries: Vec<DirEntry> = (0..8)
            .map(|i| DirEntry {
                name: Name::new(format!("d{i}").into_bytes()).unwrap_or_else(|e| panic!("{e}")),
                kind: ManifestEntryKind::Dir { child },
            })
            .collect();
        let built = manifest::build_dir(&entries).unwrap_or_else(|e| panic!("{e}"));
        child = built.root;
        for (id, b) in built.nodes {
            nodes.insert(id, b);
        }
    }
    assert_eq!(nodes.len(), 7, "seven nodes, and not one file among them");
    let Err(err) = walk_all_files(&nodes, &child, 8) else {
        panic!("an all-empty 8^6 directory DAG must refuse: nothing is ever emitted");
    };
    assert!(
        matches!(
            err,
            ResolveError::PathBudgetExceeded {
                attempted: 9,
                budget: 8
            }
        ),
        "refused on a DESCENT — no file was ever emitted: {err:?}"
    );
    // THE ADMIT SIDE, PINNED EXACTLY — this is what fixes the charge
    // WEIGHT, and both numbers are load-bearing. A refusal-side
    // assertion cannot do it: `attempted` is invariantly
    // `budget + 1`, and on a FILE-FREE DAG a walk charging TWO units
    // per descent simply steps by 2, lands exactly on the budget and
    // reports `budget + 1` anyway. Executed: 2-per-descent leaves
    // this row's every refusal assertion green, leaves the
    // entry-point row below green, and leaves the wide-budget `Ok`
    // call this pair replaced green too — 2 x 299,592 is well under
    // WHOLE_TREE_PATH_BUDGET, so a headroom budget pins nothing.
    // (The repeated-child row above does red, but incidentally: its
    // charges are MIXED, so it discriminates weight only for as long
    // as its emission-to-descent ratio happens to.) This tree needs
    // PRECISELY 8 + 8² + … + 8⁶ = 299,592 actions and emits nothing,
    // so at exactly that budget it must succeed with nothing to
    // spare, and at one less it must refuse on the very last action.
    let exact_actions: usize = 8 + 64 + 512 + 4096 + 32768 + 262_144;
    assert_eq!(exact_actions, 299_592, "8 + 8² + … + 8⁶");
    let all = walk_all_files(&nodes, &child, exact_actions).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        all.is_empty(),
        "no file anywhere in the DAG, and the budget was exactly its action count"
    );
    let Err(err) = walk_all_files(&nodes, &child, exact_actions - 1) else {
        panic!("one action short of the DAG's exact count must refuse");
    };
    assert!(
        matches!(
            err,
            ResolveError::PathBudgetExceeded {
                attempted: 299_592,
                budget: 299_591
            }
        ),
        "one unit per action, in both directions: {err:?}"
    );
}
