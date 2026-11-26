// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::publish` — `gran publish`, the
//! client path (frozen).
//!
//! Out-of-line: `granary-client`'s non-test artifact has other
//! workspace crates depending on it (`granary-sim`,
//! `granary-server`, `granary-cli`) and its own `tests/` directory
//! (`crates/granary-client/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

use granary_core::hash::GRAIN_ID_BINARY_LEN;
use granary_core::manifest::{
    BuiltTree, DirEntry, GrainListIndexChild, GrainRef, Name, SymlinkTarget, build_dir,
    encode_grain_list_index, encode_grain_list_leaf,
};
use granary_core::rootstore::filter_above;

// -------------------------------------------- choose_prefix_bits

/// The zero/zero base case: no entries, no floor, no shard target
/// pressure — width 0 (one shard).
#[test]
fn choose_prefix_bits_zero_entries_and_zero_floor_is_zero() {
    assert_eq!(choose_prefix_bits(0, 0), 0);
}

/// The floor is a MINIMUM, honoured even when the entry count alone
/// would need nothing wider than 0 — `prefix_bits` never narrows
/// per volume, and this is the only place that rule
/// is enforced.
#[test]
fn choose_prefix_bits_floor_is_never_narrowed_by_a_small_entry_count() {
    assert_eq!(choose_prefix_bits(0, 6), 6);
    assert_eq!(choose_prefix_bits(1, 6), 6);
}

/// The floor itself is clamped to `PREFIX_BITS_MAX`: a caller-passed
/// floor wider than the format allows must not be handed straight
/// to the loop range (which would then never execute, since `floor
/// ..= PREFIX_BITS_MAX` would be empty and the function would fall
/// through to the post-loop `PREFIX_BITS_MAX` anyway by luck, not by
/// the clamp being exercised) — assert the clamp directly with a
/// floor far past the max.
#[test]
fn choose_prefix_bits_floor_is_clamped_to_prefix_bits_max() {
    assert_eq!(choose_prefix_bits(0, 200), binmap::PREFIX_BITS_MAX);
    assert_eq!(choose_prefix_bits(0, u8::MAX), binmap::PREFIX_BITS_MAX);
}

/// The accept boundary at width 0: the widest entry count whose
/// shard still fits `SHARD_TARGET_BYTES` at zero routing bits.
/// `1_048_576 / 49 = 21398.49…`, so 21399 entries (1,048,551 bytes)
/// is the last count integer division still accepts at bits=0 —
/// every existing test returns on the loop's first iteration well
/// under this, so this boundary was reachable by no test at all
/// before this one.
#[test]
fn choose_prefix_bits_accepts_the_widest_entry_count_that_still_fits_bit_zero() {
    assert_eq!(
        21_399 * SHARD_ENTRY_LEN as u64,
        1_048_551,
        "the doc'd arithmetic"
    );
    assert_eq!(choose_prefix_bits(21_399, 0), 0);
}

/// One entry past that boundary (21,400: 1,048,600 bytes) no longer
/// fits at bits=0 and the loop must widen to bits=1, where it fits
/// (524,300 bytes) — the loop's SECOND iteration, unreached by any
/// prior test.
#[test]
fn choose_prefix_bits_refuses_one_entry_past_the_boundary_and_widens() {
    assert_eq!(
        21_400 * SHARD_ENTRY_LEN as u64,
        1_048_600,
        "the doc'd arithmetic"
    );
    assert_eq!(choose_prefix_bits(21_400, 0), 1);
}

/// A volume so large its expected shard size at the WIDEST legal
/// routing (`PREFIX_BITS_MAX`) still exceeds the target: `bits` is a
/// refuse cap, not a target, so the function must return
/// `PREFIX_BITS_MAX` anyway (bigger shards) rather than looping past
/// it or panicking.
#[test]
fn choose_prefix_bits_never_exceeds_the_max_even_when_the_target_is_unmet() {
    // At bits=12 (4096 shards): 100_000_000 * 49 / 4096 ≈ 1.196e6,
    // still past SHARD_TARGET_BYTES (1_048_576) — every narrower
    // width is worse, so no width in range satisfies the loop.
    assert_eq!(choose_prefix_bits(100_000_000, 0), binmap::PREFIX_BITS_MAX);
}

/// `entries.saturating_mul(SHARD_ENTRY_LEN)` must not panic on the
/// largest possible input — the saturated product stays "unmet" at
/// every width, landing on the same refuse cap as the case above.
#[test]
fn choose_prefix_bits_does_not_panic_on_u64_max_entries() {
    assert_eq!(choose_prefix_bits(u64::MAX, 0), binmap::PREFIX_BITS_MAX);
}

// -------------------------------------------------- writer_uuid

/// `cp3-vol` is part of the `writer_uuid` golden's preimage below, so its bytes
/// are pinned: renaming it re-blesses the golden.
fn test_volume() -> VolumeName {
    VolumeName::new("cp3-vol".to_owned()).unwrap_or_else(|e| panic!("{e}"))
}

fn test_identity() -> WriterIdentity {
    WriterIdentity::from_bytes(*b"granary-test-id!")
}

/// Never all-zero (catches a `writer_uuid` that degenerated into
/// returning a constant), and deterministic — with no ambient input
/// left in the preimage, "same inputs, same output" holds
/// unconditionally rather than only within one process.
#[test]
fn writer_uuid_is_deterministic_and_not_zeroed() {
    let vol = test_volume();
    let id = test_identity();
    let root = GrainId::of(b"writer-uuid-determinism");
    let now = Timestamp {
        secs: 1_760_000_000,
        nanos: 7,
    };
    let a = writer_uuid(now, &id, 3, &vol, &root);
    let b = writer_uuid(now, &id, 3, &vol, &root);
    assert_eq!(a, b, "same inputs — must be deterministic");
    assert_ne!(a, [0u8; WRITER_UUID_LEN], "must not degenerate to all-zero");
}

/// Every field that goes into the seed must actually change the
/// output — in particular `manifest_root`, whose accidental omission
/// from the seed is the mutation this is written against.
#[test]
fn writer_uuid_is_sensitive_to_every_seeded_field() {
    let vol = test_volume();
    let vol2 = VolumeName::new("other-vol".to_owned()).unwrap_or_else(|e| panic!("{e}"));
    let id = test_identity();
    let id2 = WriterIdentity::from_bytes(*b"granary-test-id?");
    let root = GrainId::of(b"root-a");
    let root2 = GrainId::of(b"root-b");
    let now = Timestamp {
        secs: 100,
        nanos: 0,
    };
    let base = writer_uuid(now, &id, 1, &vol, &root);
    assert_ne!(
        base,
        writer_uuid(Timestamp { secs: 101, ..now }, &id, 1, &vol, &root),
        "secs must matter"
    );
    assert_ne!(
        base,
        writer_uuid(Timestamp { nanos: 1, ..now }, &id, 1, &vol, &root),
        "nanos must matter"
    );
    // The identity is what tells writers apart: two writers
    // differing ONLY in who they are must not mint the same uuid.
    assert_ne!(
        base,
        writer_uuid(now, &id2, 1, &vol, &root),
        "the writer identity must matter"
    );
    assert_ne!(
        base,
        writer_uuid(now, &id, 2, &vol, &root),
        "seq must matter"
    );
    assert_ne!(
        base,
        writer_uuid(now, &id, 1, &vol2, &root),
        "volume must matter"
    );
    assert_ne!(
        base,
        writer_uuid(now, &id, 1, &vol, &root2),
        "manifest_root must matter — the mutation this test exists to catch"
    );
}

/// Pins the exact byte layout — domain separator, field order, and
/// the truncate-to-16-bytes step — as a LITERAL GOLDEN CONSTANT.
///
/// A literal is only possible because the derivation became pure:
/// while the preimage read `std::process::id()`, no constant could
/// be written down, and the test had to reconstruct the preimage
/// with the live pid — which meant it could only ever check the
/// derivation against itself, in the one process both happened to
/// share. The value below was computed OUTSIDE this program from
/// the byte layout as documented, so a run of this test is a
/// cross-process reproduction of a signed field's derivation, which
/// is the whole property replay depends on.
///
/// A changed domain separator is invisible to the sensitivity test
/// above (a fixed prefix on every call moves no pairwise
/// comparison) — this is what makes that mutation red. It is also
/// what keeps a separator move deliberate: a changed preimage
/// silently re-derived under an unchanged separator is exactly the
/// drift this test exists to catch.
#[test]
fn writer_uuid_derivation_matches_the_frozen_domain_separator_and_field_order() {
    let vol = test_volume();
    let id = test_identity();
    let root = GrainId::of(b"pin the derivation");
    let now = Timestamp {
        secs: 1_760_000_000,
        nanos: 42,
    };
    let seq: u64 = 7;

    // blake3(b"granary-writer-uuid-v2" || secs_be(8) || nanos_be(4)
    //        || identity(16) || seq_be(8) || "cp3-vol"
    //        || manifest_root.to_bytes()(33))[..16]
    let expected: [u8; WRITER_UUID_LEN] = [
        0x20, 0x64, 0x59, 0xfc, 0x8c, 0xc6, 0x96, 0x58, 0x15, 0x2e, 0xd0, 0x45, 0xb5, 0xee, 0x81,
        0x0d,
    ];

    assert_eq!(writer_uuid(now, &id, seq, &vol, &root), expected);
}

// -------------------------------- the publish emission ORDER

/// A minimal in-memory [`GrainSource`]: an ORDERED map keyed by the
/// id its bytes hash to. Ordered and not hashed on purpose — the
/// property under test is a SEQUENCE, and a fixture whose own
/// backing store could reorder anything would weaken the row it
/// feeds.
#[derive(Debug, Default)]
struct MapSource {
    objects: BTreeMap<GrainId, Vec<u8>>,
}

impl MapSource {
    /// Store one encoded node under its own id.
    fn put(&mut self, bytes: Vec<u8>) -> GrainId {
        let id = GrainId::of(&bytes);
        self.objects.insert(id, bytes);
        id
    }

    /// Store every node of a built tree, returning their ids in
    /// `build_dir`'s own emission order (leaves first, root LAST —
    /// its documented contract, asserted by the caller).
    fn put_tree(&mut self, built: BuiltTree) -> Vec<GrainId> {
        built
            .nodes
            .into_iter()
            .map(|(_, bytes)| self.put(bytes))
            .collect()
    }
}

impl GrainSource for MapSource {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.objects
            .get(id)
            .cloned()
            .ok_or(GrainSourceError::Missing(*id))
    }

    fn has(&self, id: &GrainId) -> bool {
        self.objects.contains_key(id)
    }
}

fn nm(s: &str) -> Name {
    Name::new(s.as_bytes().to_vec()).unwrap_or_else(|e| panic!("{e}"))
}

fn gref(seed: &str, len: u32) -> GrainRef {
    GrainRef {
        id: GrainId::of(seed.as_bytes()),
        unpacked_len: len,
    }
}

fn object_type(src: &MapSource, id: &GrainId) -> ObjectType {
    let bytes = src.get(id).unwrap_or_else(|e| panic!("{e}"));
    let (ty, _) = encoding::open_envelope(&bytes).unwrap_or_else(|e| panic!("{e:?}"));
    ty
}

/// blake3 over the emitted ids CONCATENATED IN ORDER, each in its
/// canonical 33-byte binary form (tag + digest). A set or a sorted
/// comparison would be worthless here: order is the property.
fn emission_digest(ids: &[GrainId]) -> GrainId {
    let mut preimage = Vec::with_capacity(ids.len() * GRAIN_ID_BINARY_LEN);
    for id in ids {
        preimage.extend_from_slice(&id.to_bytes());
    }
    GrainId::of(&preimage)
}

/// The four-arm fixture, and the emission order it must produce.
///
/// ```text
/// root  = dir INTERIOR over two dir LEAVES (257 entries -> [129, 128])
///   e000 -> dir  `sub`  = dir LEAF
///                          a -> file, 1 inline grain
///                          b -> dir  `empty` = the canonical empty LEAF
///   e001 -> file, 2 inline grains
///   e002..e128 -> symlinks (the arm that references nothing)
///   ---- leaf boundary ----
///   e129 -> file, SPILL -> grain-list INDEX
///                            -> grain-list LEAF (65 refs)
///                            -> grain-list LEAF (64 refs)
///   e130..e256 -> symlinks, except
///   e200 -> dir `sub` AGAIN (a second path to an already-emitted
///           subtree: `emitted` must emit it zero more times)
/// ```
///
/// All four `expand` arms are covered — `DirLeaf`, `DirInterior`,
/// `GrainListLeaf`, `GrainListIndex` — and the dir leaf interleaves
/// inline grains with subdirectory descents, which is the exact
/// shape a naive worklist reorders.
///
/// Two fixture facts that are deliberate, not accidental:
///
/// * **257 entries** is the smallest directory `build_dir` splits
///   into an interior over two leaves, so the `DirInterior` arm is
///   reached by the shipped builder rather than by hand.
/// * **The grain-list index is hand-encoded** over 129 refs. A
///   CANONICAL index needs 131 073 refs (`GRAINLIST_LEAF_MAX_REFS`),
///   and 129 is the smallest spill `encode_dir_leaf` accepts at all
///   (`SpillUnderK` at or below K = 128). The same hand-built 65/64
///   shape is what `manifest/tree.rs`'s own index fixtures use, and
///   the encoders doing the work are the shipped ones.
fn four_arm_publish_fixture() -> (MapSource, GrainId, Vec<GrainId>) {
    let mut src = MapSource::default();

    // The deepest node: the canonical EMPTY directory leaf.
    let empty_nodes = src.put_tree(build_dir(&[]).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(empty_nodes.len(), 1, "the empty dir is one canonical leaf");
    let empty = empty_nodes[0];

    // `sub`: an inline-grain file THEN a subdirectory, in that
    // order — the interleave a naive worklist reorders.
    // The `d58/…` grain labels are part of the fixture's pinned bytes: they
    // feed the emission digest asserted below, so renaming one re-blesses it.
    let sub_grain = gref("d58/sub/a", 9);
    let sub_nodes = src.put_tree(
        build_dir(&[
            DirEntry {
                name: nm("a"),
                kind: EntryKind::File {
                    exec: false,
                    size: 9,
                    grains: FileGrains::Inline(vec![sub_grain]),
                },
            },
            DirEntry {
                name: nm("b"),
                kind: EntryKind::Dir { child: empty },
            },
        ])
        .unwrap_or_else(|e| panic!("{e}")),
    );
    assert_eq!(sub_nodes.len(), 1, "two entries fit one leaf");
    let sub = sub_nodes[0];

    // The spill tree: one grain-list INDEX over two grain-list
    // LEAVES, 65 + 64 refs.
    let refs: Vec<GrainRef> = (0..129u32)
        .map(|i| gref(&format!("d58/g{i:03}"), 1))
        .collect();
    let (refs_a, refs_b) = refs.split_at(65);
    let leaf_a = src.put(encode_grain_list_leaf(refs_a).unwrap_or_else(|e| panic!("{e}")));
    let leaf_b = src.put(encode_grain_list_leaf(refs_b).unwrap_or_else(|e| panic!("{e}")));
    let index = src.put(
        encode_grain_list_index(&[
            GrainListIndexChild {
                child: leaf_a,
                cum_unpacked_len: 65,
                cum_ref_count: 65,
            },
            GrainListIndexChild {
                child: leaf_b,
                cum_unpacked_len: 129,
                cum_ref_count: 129,
            },
        ])
        .unwrap_or_else(|e| panic!("{e}")),
    );

    let inline = [gref("d58/i0", 5), gref("d58/i1", 7)];
    let entries: Vec<DirEntry> = (0..257u32)
        .map(|i| DirEntry {
            name: nm(&format!("e{i:03}")),
            kind: match i {
                0 | 200 => EntryKind::Dir { child: sub },
                1 => EntryKind::File {
                    exec: false,
                    size: 12,
                    grains: FileGrains::Inline(inline.to_vec()),
                },
                129 => EntryKind::File {
                    exec: false,
                    size: 129,
                    grains: FileGrains::Spill {
                        grain_count: 129,
                        root: index,
                    },
                },
                _ => EntryKind::Symlink {
                    target: SymlinkTarget::new(b"t".to_vec()).unwrap_or_else(|e| panic!("{e}")),
                },
            },
        })
        .collect();
    let root_nodes = src.put_tree(build_dir(&entries).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(
        root_nodes.len(),
        3,
        "257 entries: two leaves and an interior"
    );
    let (leaf0, leaf1, root) = (root_nodes[0], root_nodes[1], root_nodes[2]);
    // The oracle below reads `build_dir`'s "root LAST" contract off
    // its own output; assert the shape rather than trusting it.
    assert_eq!(object_type(&src, &leaf0), ObjectType::DirLeaf);
    assert_eq!(object_type(&src, &leaf1), ObjectType::DirLeaf);
    assert_eq!(object_type(&src, &root), ObjectType::DirInterior);

    // Depth-first preorder, written out from the fixture's own
    // shape — an oracle independent of the walk under test.
    let mut expected = vec![
        root,
        leaf0,
        sub,
        sub_grain.id,
        empty,
        inline[0].id,
        inline[1].id,
        leaf1,
        index,
        leaf_a,
    ];
    expected.extend(refs_a.iter().map(|r| r.id));
    expected.push(leaf_b);
    expected.extend(refs_b.iter().map(|r| r.id));
    (src, root, expected)
}

/// Pins the ORDER in which `collect_objects` emits the manifest
/// closure, over a fixture that reaches all four `expand` arms.
///
/// **Why the order and not just the set.** `out` is the v0 locality
/// order `binfmt::plan_bins` packs along (module doc): the same
/// content emitted in a different sequence lands in DIFFERENT bins,
/// so a reordering is a change in the bytes a publish uploads and
/// in what a republish can dedup against — invisible to any
/// set-based or sorted check, and invisible to every golden vector,
/// because no manifest object changes. The walk is an explicit
/// worklist, which is exactly where an order change hides:
/// items pop from the BACK, so each node's items must be pushed
/// REVERSED, and a dir leaf's inline grains must stay first-class
/// items interleaved with its subdirectory descents rather than
/// being drained separately.
///
/// This row pins a fully-described fixture (see
/// [`four_arm_publish_fixture`]) and the digest of the order it emits.
#[test]
fn collect_objects_emission_order_matches_its_pinned_digest() {
    let (src, root, expected) = four_arm_publish_fixture();
    let emitted = collect_objects(&src, &root).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        emitted, expected,
        "the publish set must be the manifest closure in depth-first preorder"
    );
    assert_eq!(emitted.len(), 140, "the fixture's closure size");
    let unique: BTreeSet<GrainId> = emitted.iter().copied().collect();
    assert_eq!(
        unique.len(),
        emitted.len(),
        "`e200` names an already-walked subtree: `emitted` must emit it zero more times"
    );

    // The digest of the fixture above's emission order.
    assert_eq!(
        emission_digest(&emitted).to_string(),
        "blake3:bb01ecf97f779e8257c685f68c8f5fe0cc2d4f392d92b9c33572a43347eec702",
        "the publish set's emission order moved"
    );
}

/// The COLLIDING-ID fixture, and the emission order it must produce.
///
/// ```text
/// root = dir LEAF, three entries in canonical name order
///   a -> file, ONE inline grain whose id IS `z`'s node id: the
///        file's bytes ARE `z`'s encoding, so ONE stored object
///        answers for both roles
///   m -> dir `z` = dir LEAF, THREE entries
///                    p -> file, 1 inline grain
///                    q -> dir = the canonical empty LEAF
///                    r -> file, 1 inline grain
///   w -> file, 1 inline grain (the TRAILING sibling)
/// ```
///
/// Three fixture facts are load-bearing, not incidental:
///
/// * **`a` sorts before `m`**, so the colliding id is met as a
///   GRAIN first and as a NODE second — the order in which one set
///   gating both emission AND expansion loses `z`'s whole subtree.
/// * **`z` holds THREE entries**, not one. A walk that re-opens a
///   colliding node only while it is small enough — one entry, two
///   — is still wrong, and a one-entry fixture cannot say so.
/// * **`w` trails `m`**, so `z`'s subtree must be emitted BEFORE
///   `w`. Recovering the missing objects by a post-hoc sweep that
///   appends whatever the closure still references produces the
///   right SET in the wrong ORDER, and only a trailing sibling
///   makes that observable.
fn colliding_id_publish_fixture() -> (MapSource, GrainId, Vec<GrainId>) {
    let mut src = MapSource::default();

    // The deepest node: the canonical EMPTY directory leaf.
    let empty_nodes = src.put_tree(build_dir(&[]).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(empty_nodes.len(), 1, "the empty dir is one canonical leaf");
    let empty = empty_nodes[0];

    // `z`: the directory node whose ENCODING is also a file's
    // content. Three entries, interleaving inline grains with a
    // subdirectory descent.
    // The `d58c/…` grain labels feed the emission digest asserted below;
    // renaming one re-blesses it.
    let zp = gref("d58c/z/p", 4);
    let zr = gref("d58c/z/r", 6);
    let z_built = build_dir(&[
        DirEntry {
            name: nm("p"),
            kind: EntryKind::File {
                exec: false,
                size: 4,
                grains: FileGrains::Inline(vec![zp]),
            },
        },
        DirEntry {
            name: nm("q"),
            kind: EntryKind::Dir { child: empty },
        },
        DirEntry {
            name: nm("r"),
            kind: EntryKind::File {
                exec: false,
                size: 6,
                grains: FileGrains::Inline(vec![zr]),
            },
        },
    ])
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(z_built.nodes.len(), 1, "three entries fit one leaf");
    let (_, z_bytes) = z_built
        .nodes
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("one node"));
    let z_len = u32::try_from(z_bytes.len()).unwrap_or_else(|e| panic!("{e}"));
    // The one object that serves both roles: stored under the id
    // its own bytes hash to, which is what `a` names as a grain.
    let z = src.put(z_bytes);
    assert_eq!(z, z_built.root, "the stored object is `z` itself");

    let w_grain = gref("d58c/w", 3);
    let root_nodes = src.put_tree(
        build_dir(&[
            DirEntry {
                name: nm("a"),
                kind: EntryKind::File {
                    exec: false,
                    size: u64::from(z_len),
                    grains: FileGrains::Inline(vec![GrainRef {
                        id: z,
                        unpacked_len: z_len,
                    }]),
                },
            },
            DirEntry {
                name: nm("m"),
                kind: EntryKind::Dir { child: z },
            },
            DirEntry {
                name: nm("w"),
                kind: EntryKind::File {
                    exec: false,
                    size: 3,
                    grains: FileGrains::Inline(vec![w_grain]),
                },
            },
        ])
        .unwrap_or_else(|e| panic!("{e}")),
    );
    assert_eq!(root_nodes.len(), 1, "three entries fit one leaf");
    let root = root_nodes[0];
    // Assert the collision FORMED before pinning anything about the
    // walk: a fixture where `a`'s grain id is NOT a directory node
    // would pass the order assertion for the wrong reason.
    assert_eq!(object_type(&src, &root), ObjectType::DirLeaf);
    assert_eq!(
        object_type(&src, &z),
        ObjectType::DirLeaf,
        "the id `a` names as its only grain must resolve to a directory node"
    );

    // Depth-first preorder, written out from the fixture's own
    // shape — an oracle independent of the walk under test. The
    // colliding id is emitted once, at the point `a` reaches it,
    // and its subtree follows immediately, ahead of `w`.
    let expected = vec![root, z, zp.id, empty, zr.id, w_grain.id];
    (src, root, expected)
}

/// Pins the emission ORDER on the COLLISION path: one id that is
/// both a file's only grain and a directory node.
///
/// **What this row pins that the four-arm row cannot.**
/// [`collect_objects_emission_order_matches_its_pinned_digest`]
/// pins the order over a fixture with no colliding id in it, so it
/// sees nothing on this path at all. Separating emission from
/// expansion restores the objects one combined set drops — but
/// WHERE they land in the sequence is a second, independent
/// property, and
/// every other row that touches the collision checks a SET (the
/// publish set holds them, the volume resolves) or a COUNT. A
/// repair that emits the same six ids in a different sequence is
/// invisible to all of them.
///
/// **Why the order is load-bearing.** `out` is the v0 locality
/// order `binfmt::plan_bins` packs along (module doc): the same
/// content emitted in a different sequence lands in DIFFERENT bins,
/// so a reordering changes the bytes a publish uploads and what a
/// republish can dedup against. No manifest object changes, so no
/// golden vector moves and no set-based or sorted check reacts.
#[test]
fn collect_objects_emission_order_on_a_colliding_id_matches_its_pinned_digest() {
    let (src, root, expected) = colliding_id_publish_fixture();
    let emitted = collect_objects(&src, &root).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        emitted, expected,
        "the colliding node's subtree belongs WHERE the walk reaches it — between \
         the colliding id and its trailing sibling, not appended after the walk"
    );
    assert_eq!(emitted.len(), 6, "the fixture's closure size");
    let unique: BTreeSet<GrainId> = emitted.iter().copied().collect();
    assert_eq!(
        unique.len(),
        emitted.len(),
        "one id in two roles is still one emission: `emitted` is the union's dedup"
    );

    // The digest of this fixture's emission order.
    assert_eq!(
        emission_digest(&emitted).to_string(),
        "blake3:a873f91d3d15e2dda0ecf0fa2d467dc973a5f5dd69312b174c07bb9abfe01c45",
        "the colliding publish set's emission order moved"
    );
}

/// A [`GrainSource`] that COUNTS reads, delegating to a
/// [`MapSource`]. `has` is not counted: the walk never calls it,
/// and counting it would blur the property.
struct CountingSource {
    inner: MapSource,
    gets: AtomicUsize,
}

impl CountingSource {
    fn new(inner: MapSource) -> Self {
        Self {
            inner,
            gets: AtomicUsize::new(0),
        }
    }

    fn gets(&self) -> usize {
        self.gets.load(Ordering::Relaxed)
    }
}

impl GrainSource for CountingSource {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.gets.fetch_add(1, Ordering::Relaxed);
        self.inner.get(id)
    }

    fn has(&self, id: &GrainId) -> bool {
        self.inner.has(id)
    }
}

/// A SHARING DAG `levels` deep: each level is one directory leaf
/// holding two entries that name the SAME child. Every level adds
/// exactly ONE node and DOUBLES the number of paths to the level
/// below, so paths outgrow nodes exponentially in depth while the
/// tree stays a handful of objects.
///
/// Returns the store, its root, and the number of DISTINCT nodes
/// (`levels` leaves plus the canonical empty leaf at the bottom).
fn sharing_dag_fixture(levels: usize) -> (MapSource, GrainId, usize) {
    let mut src = MapSource::default();
    let empty_nodes = src.put_tree(build_dir(&[]).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(empty_nodes.len(), 1, "the empty dir is one canonical leaf");
    let mut child = empty_nodes[0];
    for _ in 0..levels {
        let nodes = src.put_tree(
            build_dir(&[
                DirEntry {
                    name: nm("l"),
                    kind: EntryKind::Dir { child },
                },
                DirEntry {
                    name: nm("r"),
                    kind: EntryKind::Dir { child },
                },
            ])
            .unwrap_or_else(|e| panic!("{e}")),
        );
        assert_eq!(nodes.len(), 1, "two entries fit one leaf");
        child = nodes[0];
    }
    // OBSERVED off the store the fixture actually built, never
    // recomputed from `levels`: a returned constant makes every
    // downstream assertion a comparison between two arithmetic
    // expressions, decidable without the fixture existing at all.
    let distinct_nodes = src.objects.len();
    assert_eq!(
        distinct_nodes,
        levels + 1,
        "one leaf per level, plus the empty leaf they all share"
    );
    (src, child, distinct_nodes)
}

/// Pins ONCE-ONLY EXPANSION: `expanded` is a second question from
/// `emitted`, and dropping it changes no output at all — the same
/// ids in the same order — while making the walk re-read a shared
/// node once per PATH that reaches it.
///
/// **Why a counting source and not the return value.** Always
/// expanding is output-equivalent: the ids a re-expansion
/// rediscovers are already in `emitted`, so nothing is emitted
/// twice and the sequence is unchanged. What it costs is store
/// reads, and sharing is what makes that cost explode: on the DAG
/// below, paths to the deepest node double per level while the node
/// count grows by one, so an ungated walk is exponential in sharing
/// depth. Only a read counter can see it.
#[test]
fn collect_objects_opens_each_shared_node_exactly_once() {
    const LEVELS: usize = 5;
    let (src, root, distinct_nodes) = sharing_dag_fixture(LEVELS);
    // The sharing is OBSERVED, not asserted as arithmetic. A
    // `paths > nodes` guard compares two expressions over `LEVELS`
    // and stays green on a fixture edited into a CHAIN — where
    // reads equal nodes for every walk, gated or not, so the row
    // would pin nothing while still passing.
    let levels_below_root = LEVELS;
    // …and the sharing must be UNIFORM, at EVERY level, not just at
    // the root. The read count this row prints on failure is
    // `2^(LEVELS+1) - 1`, which is only the ungated walk's cost if
    // every level doubles; a fixture edited so that just the top
    // forks would keep a root-only guard green while that figure
    // silently became wrong. So walk the whole spine, and assert
    // the shape at each step rather than at a sampled one.
    let mut level = root;
    for depth in 0..levels_below_root {
        let items = expand(&src, &level).unwrap_or_else(|e| panic!("{e}"));
        let kids: Vec<GrainId> = items
            .iter()
            .filter_map(|item| match item {
                Item::Node(id) => Some(*id),
                Item::Grain(_) => None,
            })
            .collect();
        assert_eq!(
            kids.len(),
            2,
            "level {depth} must fork, or the printed read count is not this fixture's"
        );
        assert_eq!(
            kids[0], kids[1],
            "level {depth} must share one child, or the doubling this row prints is wrong"
        );
        level = kids[0];
    }

    let store = CountingSource::new(src);
    let emitted = collect_objects(&store, &root).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(
        emitted.len(),
        distinct_nodes,
        "every entry is a directory: the closure is exactly the distinct nodes"
    );
    assert_eq!(
        store.gets(),
        distinct_nodes,
        "each node must be READ once, not once per path that reaches it: \
         an ungated walk reads {} times here",
        (1usize << (LEVELS + 1)) - 1
    );
}

// --------------------------------------- ProbeUnresolved

/// A minimal [`RootStore`] whose `put_root` and `get_root` each
/// return a FIXED, DISTINCT error — everything `commit` needs to
/// reach the probe arm and nothing else: `write_hint`/`max_seq`/
/// `read_hint` are unreached on this path (the `ProbeUnresolved` arm
/// returns before either), so they answer inertly rather than
/// panicking on a call this test never makes.
struct StubRootStore {
    put_error: RootStoreError,
    probe_error: RootStoreError,
}

impl RootStore for StubRootStore {
    async fn put_root(
        &self,
        _volume: &str,
        _seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        Err(self.put_error.clone())
    }
    async fn get_root(&self, _volume: &str, _seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        Err(self.probe_error.clone())
    }
    async fn read_hint(
        &self,
        _volume: &str,
        _cached: Option<&granary_core::rootstore::HintToken>,
    ) -> Result<granary_core::rootstore::HintRead, RootStoreError> {
        Ok(granary_core::rootstore::HintRead::Missing)
    }
    async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
        Ok(())
    }
    async fn max_seq(&self, _volume: &str) -> Result<Option<u64>, RootStoreError> {
        Ok(None)
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

fn a_prepared(volume: &str, seq: u64) -> Prepared {
    Prepared {
        volume: VolumeName::new(volume.to_owned()).unwrap_or_else(|e| panic!("{e}")),
        seq,
        root_bytes: b"root bytes this attempt tried to write".to_vec(),
        summary: PublishSummary {
            seq,
            epoch: 1,
            novel_objects: 0,
            novel_bytes: 0,
            bins_planned: 0,
            bins_uploaded: 0,
            bin_bytes_uploaded: 0,
            shards_total: 1,
            shards_rewritten: 0,
            sheaf_uploaded: false,
            prefix_bits: 0,
            manifest_root: GrainId::of(b"manifest"),
            binmap_index: GrainId::of(b"binmap"),
            sheaf_head: GrainId::of(b"sheaf"),
            hint_written: false,
            harvest: HarvestStats::default(),
        },
    }
}

/// **`ProbeUnresolved` test 1.** The `Err(probe_error)` world:
/// `put_root` fails AND the one probe that would resolve it also fails.
/// Only the `Ok(None)` world surfaces `Unresolved { put_error }`; this
/// one must not — this asserts its own result,
/// `ProbeUnresolved`, carrying BOTH halves, and that
/// `Display` states both messages plus the outcome being unknown.
#[tokio::test]
async fn a_failed_probe_surfaces_probe_unresolved_with_both_errors() {
    let store = StubRootStore {
        put_error: RootStoreError::Backend("INJECTED put failure".to_owned()),
        probe_error: RootStoreError::Backend("INJECTED probe failure".to_owned()),
    };
    let prepared = a_prepared("failed-probe-vol", 2);

    let err = commit(&store, prepared)
        .await
        .err()
        .unwrap_or_else(|| panic!("a failed put whose probe also fails must be an error"));

    match &err {
        PublishError::ProbeUnresolved {
            put_error,
            probe_error,
        } => {
            assert_eq!(
                put_error,
                &RootStoreError::Backend("INJECTED put failure".to_owned()),
                "the put half must be the PUT's own error, not the probe's"
            );
            assert_eq!(
                probe_error,
                &RootStoreError::Backend("INJECTED probe failure".to_owned()),
                "the probe half must be the PROBE's own error, not the put's"
            );
        }
        other => panic!("expected ProbeUnresolved, got {other}"),
    }

    let rendered = err.to_string();
    assert!(
        rendered.contains("INJECTED put failure"),
        "Display must name the put error: {rendered}"
    );
    assert!(
        rendered.contains("INJECTED probe failure"),
        "Display must name the probe error: {rendered}"
    );
    assert!(
        rendered.to_lowercase().contains("unknown")
            || rendered.to_lowercase().contains("may have landed"),
        "Display must say the outcome is unresolved: {rendered}"
    );
}

// ----------------------- the amended ONE-PROBE RULE's settling arms

/// A `RootStore` whose `put_root` fails immediately with a fixed error
/// and whose `get_root` (the probe) answers a fixed result — the
/// minimal shape that drives every one of `commit`'s settling arms
/// directly, without a wedge or a real backend.
struct FixedProbe {
    put_error: RootStoreError,
    probe_answer: Result<Option<Vec<u8>>, RootStoreError>,
}

impl RootStore for FixedProbe {
    async fn put_root(
        &self,
        _volume: &str,
        _seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        Err(self.put_error.clone())
    }
    async fn get_root(&self, _volume: &str, _seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.probe_answer.clone()
    }
    async fn read_hint(
        &self,
        _volume: &str,
        _cached: Option<&granary_core::rootstore::HintToken>,
    ) -> Result<granary_core::rootstore::HintRead, RootStoreError> {
        Ok(granary_core::rootstore::HintRead::Missing)
    }
    async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
        Ok(())
    }
    async fn max_seq(&self, _volume: &str) -> Result<Option<u64>, RootStoreError> {
        Ok(None)
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

/// A framing refusal from the probe is UNRESOLVED, never a lost race.
/// Only `RefusalKind::OverCap` proves an occupant foreign; a framing
/// fault is a statement about the transport, and proves nothing about
/// what holds the seq.
#[tokio::test]
async fn a_framing_refusal_from_the_probe_is_unresolved() {
    let store = FixedProbe {
        put_error: RootStoreError::Backend("INJECTED put failure".to_owned()),
        probe_answer: Err(RootStoreError::RefusedResponse {
            reason: "response body sent more than one trailer frame".to_owned(),
            kind: RefusalKind::Framing,
        }),
    };
    let prepared = a_prepared("framing-vol", 2);

    let err = commit(&store, prepared)
        .await
        .err()
        .unwrap_or_else(|| panic!("a framing refusal from the probe must still be an error"));

    match &err {
        PublishError::ProbeUnresolved {
            probe_error: RootStoreError::RefusedResponse { kind, .. },
            ..
        } => {
            assert_eq!(*kind, RefusalKind::Framing);
        }
        other => panic!("expected ProbeUnresolved carrying the Framing refusal, got {other}"),
    }
}

/// A no-progress refusal from the probe is UNRESOLVED, never a lost
/// race — the same reasoning as the framing row: a work limit says
/// nothing about the occupant.
#[tokio::test]
async fn a_no_progress_refusal_from_the_probe_is_unresolved() {
    let store = FixedProbe {
        put_error: RootStoreError::Backend("INJECTED put failure".to_owned()),
        probe_answer: Err(RootStoreError::RefusedResponse {
            reason: "made no progress: more than 1024 zero-length chunks".to_owned(),
            kind: RefusalKind::NoProgress,
        }),
    };
    let prepared = a_prepared("no-progress-vol", 2);

    let err = commit(&store, prepared)
        .await
        .err()
        .unwrap_or_else(|| panic!("a no-progress refusal from the probe must still be an error"));

    match &err {
        PublishError::ProbeUnresolved {
            probe_error: RootStoreError::RefusedResponse { kind, .. },
            ..
        } => {
            assert_eq!(*kind, RefusalKind::NoProgress);
        }
        other => panic!("expected ProbeUnresolved carrying the NoProgress refusal, got {other}"),
    }
}

/// A non-`Elapsed` transport failure — the request MAY have been sent —
/// followed by an absent probe is UNRESOLVED, not the plain original
/// error. A connection reset mid-body is exactly a failure under which
/// the peer may already have received and acted on the request, and this
/// row is asserted separately from the `Elapsed` one below because
/// nothing about the `Ok(None)` arm's guard is specific to `Elapsed` —
/// any failure under which the request may still be in flight takes the
/// same path.
#[tokio::test]
async fn a_non_elapsed_transport_failure_then_an_absent_probe_is_unresolved() {
    let store = FixedProbe {
        put_error: RootStoreError::Backend("connection reset mid-body".to_owned()),
        probe_answer: Ok(None),
    };
    let prepared = a_prepared("transport-then-absent-vol", 3);

    let err = commit(&store, prepared).await.err().unwrap_or_else(|| {
        panic!("a transport failure followed by an absent probe must still be an error")
    });

    match &err {
        PublishError::Unresolved {
            put_error: RootStoreError::Backend(msg),
        } => {
            assert_eq!(msg, "connection reset mid-body");
        }
        other => panic!("expected Unresolved{{ put_error: Backend(..) }}, got {other}"),
    }
}

/// A TERMINAL-LOOKING put failure — `AlreadyExists`, the store's own
/// definitive answer — followed by an absent probe is STILL unresolved.
/// The ONE-PROBE RULE (`granary_core::rootstore`
/// module doc) surfaces the plain original error only when the failed
/// PUT's own answer was terminal AND known to be the only attempt sent —
/// and nothing in this workspace carries that second proof, not even for
/// a failure that looks as definitive as `AlreadyExists`, so `commit`
/// does not special-case it: this is the direct demonstration that the
/// terminal row stays unreached here.
#[tokio::test]
async fn a_terminal_looking_failure_then_an_absent_probe_is_still_unresolved() {
    let store = FixedProbe {
        put_error: RootStoreError::AlreadyExists,
        probe_answer: Ok(None),
    };
    let prepared = a_prepared("terminal-then-absent-vol", 4);

    let err = commit(&store, prepared).await.err().unwrap_or_else(|| {
        panic!("AlreadyExists followed by an absent probe must still be an error")
    });

    assert!(
        matches!(
            err,
            PublishError::Unresolved {
                put_error: RootStoreError::AlreadyExists
            }
        ),
        "expected Unresolved{{ put_error: AlreadyExists }} — row 1 is unreachable without a \
         single-attempt carrier; got {err}"
    );
}

/// A size-cap refusal from the probe is a lost race — the only refusal
/// kind that proves the occupant foreign.
#[tokio::test]
async fn an_over_cap_refusal_from_the_probe_is_still_a_lost_race() {
    let store = FixedProbe {
        put_error: RootStoreError::AlreadyExists,
        probe_answer: Err(RootStoreError::RefusedResponse {
            reason: "root at root/v/00000000000000000002 advertises 999999 bytes, over the \
                     65536-byte cap"
                .to_owned(),
            kind: RefusalKind::OverCap,
        }),
    };
    let prepared = a_prepared("overcap-vol", 2);

    let err = commit(&store, prepared)
        .await
        .err()
        .unwrap_or_else(|| panic!("an OverCap refusal from the probe must still be an error"));

    assert!(
        matches!(err, PublishError::LostRace { .. }),
        "an OverCap refusal proves the occupant foreign, exactly like differing bytes; got {err}"
    );
}

/// **`RootTooLarge`: refused before any `PUT`.** The fake store's
/// `put_root` panics if called at all, so a green run here is itself the
/// proof that no PUT was attempted — not merely that one failed
/// harmlessly.
#[tokio::test]
async fn an_oversized_candidate_is_refused_before_any_put() {
    struct PanicsOnPut;
    impl RootStore for PanicsOnPut {
        async fn put_root(
            &self,
            _volume: &str,
            _seq: u64,
            _bytes: Vec<u8>,
        ) -> Result<(), RootStoreError> {
            panic!("commit must refuse an oversized candidate BEFORE any PUT")
        }
        async fn get_root(
            &self,
            _volume: &str,
            _seq: u64,
        ) -> Result<Option<Vec<u8>>, RootStoreError> {
            panic!("commit must refuse an oversized candidate before ever probing")
        }
        async fn read_hint(
            &self,
            _volume: &str,
            _cached: Option<&granary_core::rootstore::HintToken>,
        ) -> Result<granary_core::rootstore::HintRead, RootStoreError> {
            panic!("unreached")
        }
        async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
            panic!("unreached")
        }
        async fn max_seq(&self, _volume: &str) -> Result<Option<u64>, RootStoreError> {
            panic!("unreached")
        }

        async fn max_seq_above(
            &self,
            volume: &str,
            floor: u64,
        ) -> Result<Option<u64>, RootStoreError> {
            Ok(filter_above(self.max_seq(volume).await?, floor))
        }
    }

    let mut prepared = a_prepared("too-large-vol", 1);
    let oversized = usize::try_from(granary_store::bounds::ROOT_MAX_BYTES)
        .unwrap_or_else(|e| panic!("{e}"))
        + 1;
    prepared.root_bytes = vec![0x5A; oversized];

    let err = commit(&PanicsOnPut, prepared)
        .await
        .err()
        .unwrap_or_else(|| panic!("an oversized candidate must be refused"));

    match err {
        PublishError::RootTooLarge { len, cap } => {
            assert_eq!(len, oversized);
            assert_eq!(cap, granary_store::bounds::ROOT_MAX_BYTES);
        }
        other => panic!("expected RootTooLarge, got {other}"),
    }
}

// ----------------------- DirectS3 per-call deadline / one-probe

/// A `RootStore` whose `put_root` never resolves (wedged) and whose
/// `get_root` answers whatever the test configures — the fixture
/// both one-probe outcomes below share.
///
/// `write_hint` IS reached on 4a's success path — `commit` calls it
/// unconditionally after a landed `put_root`, advisory-only (its
/// result feeds only `summary.hint_written`, never the returned
/// `Result`) — but 4b returns before it, on the probe-answered
/// `Ok(None)` arm. `max_seq`/`read_hint` are unreached by `commit`
/// on EITHER path: `commit` only calls `max_seq` from the
/// `LostRace` arm, which neither test's probe answer enters, and
/// never calls `read_hint` at all.
struct WedgedPutRoot {
    probe_answer: Result<Option<Vec<u8>>, RootStoreError>,
}

impl RootStore for WedgedPutRoot {
    async fn put_root(
        &self,
        _volume: &str,
        _seq: u64,
        _bytes: Vec<u8>,
    ) -> Result<(), RootStoreError> {
        std::future::pending().await
    }
    async fn get_root(&self, _volume: &str, _seq: u64) -> Result<Option<Vec<u8>>, RootStoreError> {
        self.probe_answer.clone()
    }
    async fn read_hint(
        &self,
        _volume: &str,
        _cached: Option<&granary_core::rootstore::HintToken>,
    ) -> Result<granary_core::rootstore::HintRead, RootStoreError> {
        Ok(granary_core::rootstore::HintRead::Missing)
    }
    async fn write_hint(&self, _volume: &str, _seq: u64) -> Result<(), RootStoreError> {
        Ok(())
    }
    async fn max_seq(&self, _volume: &str) -> Result<Option<u64>, RootStoreError> {
        Ok(None)
    }

    async fn max_seq_above(&self, volume: &str, floor: u64) -> Result<Option<u64>, RootStoreError> {
        Ok(filter_above(self.max_seq(volume).await?, floor))
    }
}

/// The elapsed `put_root` whose probe finds our OWN bytes: `get_root`
/// serves them back, so `commit` self-identifies the elapsed
/// `put_root` as landed rather than surfacing the timeout — proving
/// `Elapsed` enters the probe branch rather than bypassing it.
#[tokio::test(start_paused = true)]
async fn an_elapsed_put_root_whose_probe_finds_our_own_bytes_lands_the_publish() {
    let prepared = a_prepared("t-direct-vol", 3);
    let root_bytes = prepared.root_bytes.clone();
    let store = crate::DirectStoreDeadline::new(WedgedPutRoot {
        probe_answer: Ok(Some(root_bytes)),
    });

    let summary = commit(&store, prepared).await.unwrap_or_else(|e| {
        panic!("an elapsed put_root whose probe finds our own bytes must resolve as landed: {e}")
    });

    assert_eq!(summary.seq, 3);
}

/// The elapsed `put_root` whose probe observes NOTHING: `get_root`
/// answers `Ok(None)`, so `commit` reports `PublishError::Unresolved`,
/// carrying the elapsed `put_root` itself — the shape `main.rs`'s
/// `volume_state_is_open` already classifies `true` (every `Unresolved`
/// does), which is what puts the CLI's ambiguity note
/// on this outcome rather than a
/// silent "nothing happened." The ONE-PROBE RULE (`granary_core::rootstore`
/// module doc) treats "nothing there" as UNRESOLVED rather than as the
/// original failure restated, because no adapter this client uses can
/// prove the elapsed `put_root`'s own attempt was the only one sent.
#[tokio::test(start_paused = true)]
async fn an_elapsed_put_root_whose_probe_finds_nothing_is_unresolved() {
    let prepared = a_prepared("t-direct-vol-2", 5);
    let store = crate::DirectStoreDeadline::new(WedgedPutRoot {
        probe_answer: Ok(None),
    });

    let err = commit(&store, prepared).await.err().unwrap_or_else(|| {
        panic!("an elapsed put_root whose probe finds nothing must still be an error")
    });

    match &err {
        PublishError::Unresolved {
            put_error: RootStoreError::Elapsed { operation, after },
        } => {
            assert_eq!(*operation, "PUT root");
            assert_eq!(*after, crate::direct_deadline::DIRECT_STORE_CALL_DEADLINE);
        }
        other => panic!("expected Unresolved{{ put_error: Elapsed }}, got {other}"),
    }
}
