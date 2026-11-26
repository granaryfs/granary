// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::manifest_bytes` — the exact (not modelled)
//! manifest and index byte accounting.
//!
//! Out-of-line: `granary-bench`'s non-test artifact has its own
//! `[[bin]]` (`granary-bench`) and its own `tests/` directory
//! (`crates/granary-bench/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::*;

fn name(s: &str) -> Name {
    Name::new(s.as_bytes().to_vec()).expect("valid name")
}

fn gref(seed: u8, len: u32) -> GrainRef {
    GrainRef {
        id: GrainId::of(&[seed; 4]),
        unpacked_len: len,
    }
}

fn file(path: &[&str], grains: Vec<GrainRef>) -> Entry {
    let size = grains.iter().map(|g| u64::from(g.unpacked_len)).sum();
    Entry {
        components: path.iter().map(|p| name(p)).collect(),
        payload: Payload::File {
            exec: false,
            size,
            grains,
        },
    }
}

#[test]
fn a_flat_tree_encodes_to_real_bytes() {
    let m = build(&[file(&["a"], vec![gref(1, 10)])]).expect("build");
    assert!(!m.nodes.is_empty());
    // Pinned against the frozen encoder (measured, not modelled):
    // one dir-leaf node holding the single file entry.
    assert_eq!(m.total_bytes(), 66);
    assert!(m.nodes.contains_key(&m.root));
}

#[test]
fn identical_subtrees_are_counted_once() {
    let shared = vec![gref(2, 20)];
    let m = build(&[
        file(&["x", "same"], shared.clone()),
        file(&["y", "same"], shared),
    ])
    .expect("build");
    // `x/` and `y/` have byte-identical contents, so they ARE the
    // same content-addressed node: root + one shared leaf = 2.
    // This is why "novel manifest bytes" is a set difference over
    // node ids and not a per-directory sum. The exact total
    // (measured) is what catches a per-insertion accumulation bug
    // that leaves `nodes.len()` unchanged (still 2) but sums the
    // shared leaf's bytes twice: 155, not 224.
    assert_eq!(m.nodes.len(), 2, "{:?}", m.nodes);
    assert_eq!(m.total_bytes(), 155);
}

#[test]
fn an_empty_dir_alone_has_pinned_total_bytes() {
    // Isolates the empty-directory case (no sibling file) so an
    // accumulation bug OR a bug that drops the empty-dir's own
    // node from the map both show up here: root leaf (1 entry,
    // "empty-dir" -> child) + the empty-dir's own empty leaf = 2
    // nodes, and the total is exact, not merely nonzero.
    let m = build(&[Entry {
        components: vec![name("empty-dir")],
        payload: Payload::EmptyDir,
    }])
    .expect("build");
    assert_eq!(m.nodes.len(), 2, "{:?}", m.nodes);
    assert_eq!(m.total_bytes(), 72);
}

#[test]
fn empty_files_and_empty_dirs_encode() {
    let m = build(&[
        Entry {
            components: vec![name("empty-dir")],
            payload: Payload::EmptyDir,
        },
        Entry {
            components: vec![name("empty-file")],
            payload: Payload::File {
                exec: false,
                size: 0,
                grains: Vec::new(),
            },
        },
    ])
    .expect("build");
    assert_eq!(m.nodes.len(), 2, "{:?}", m.nodes);
    assert_eq!(m.total_bytes(), 96);
}

#[test]
fn over_k_grains_spill_and_the_spill_nodes_are_counted() {
    let refs: Vec<GrainRef> = (0..=FILE_INLINE_MAX_REFS)
        .map(|i| {
            GrainRef {
                // distinct ids so the list is a real tree
                id: GrainId::of(&i.to_be_bytes()),
                unpacked_len: 4096,
            }
        })
        .collect();
    let inline = build(&[file(&["small"], refs[..1].to_vec())]).expect("inline");
    let spilled = build(&[file(&["big"], refs.clone())]).expect("spilled");
    assert!(
        spilled.nodes.len() > inline.nodes.len(),
        "spill must add grain-list nodes"
    );
}

/// POSITIVE: a grain at EXACTLY `GRAIN_UNPACKED_MAX` builds. The
/// boundary is `>`, not `>=` -- unpinned, a core comparison flip
/// to `>=` would leave every other test in the repo (both crates)
/// green while at-cap files silently became "unrepresentable".
#[test]
fn a_grain_at_exactly_the_frozen_cap_builds() {
    let at_cap = GrainRef {
        id: GrainId::of(b"at-cap"),
        unpacked_len: granary_core::manifest::GRAIN_UNPACKED_MAX,
    };
    build(&[file(&["at-cap"], vec![at_cap])]).expect("at-cap grain must build");
}

/// NEGATIVE: the whole-file arm on a file above the frozen 8 MiB
/// grain cap is not representable — the sweep must report that,
/// not invent a number. The payload is pinned, not just the
/// variant shape, so the `>` vs `>=` boundary itself is covered
/// (paired with the at-cap positive case above).
#[test]
fn a_grain_over_the_frozen_cap_is_refused() {
    let over = GrainRef {
        id: GrainId::of(b"big"),
        unpacked_len: granary_core::manifest::GRAIN_UNPACKED_MAX + 1,
    };
    let err = build(&[file(&["huge"], vec![over])]).expect_err("must refuse");
    assert_eq!(
        err,
        ManifestError::Encode(EncodeNodeError::BadGrainLen {
            len: granary_core::manifest::GRAIN_UNPACKED_MAX + 1,
        })
    );
}

/// Cross-check against the FROZEN encoder itself, called through a
/// fully-qualified path so a local shadow of the imported
/// `build_dir`/`build_grain_list` names (same signature, no
/// call-site change) cannot leak into this comparison the way it
/// would if the test resolved the bare, shadowable name. This is
/// not a golden vector -- it is a same-run cross-check against code
/// already in the tree, and it also pins the root id (kills a
/// mutation that reports an arbitrary node id as root).
#[test]
fn totals_and_root_match_the_frozen_encoder_directly() {
    let refs = vec![gref(1, 10)];
    let m = build(&[file(&["a"], refs.clone())]).expect("build");
    let expect = granary_core::manifest::build_dir(&[DirEntry {
        name: name("a"),
        kind: EntryKind::File {
            exec: false,
            size: 10,
            grains: FileGrains::Inline(refs),
        },
    }])
    .expect("build_dir");
    let core_total: usize = expect.nodes.iter().map(|(_, b)| b.len()).sum();
    assert_eq!(m.total_bytes(), core_total as u64);
    assert_eq!(m.root, expect.root);
}

/// The tightest interesting point above `DIR_LEAF_MAX_ENTRIES`
/// (257): no committed fixture before this one was wide enough to
/// force a multi-node directory tree (interior node, balanced
/// split), so an encoder that is byte-correct below the leaf cap
/// but never splits would pass every other test in this file.
/// Cross-checked against the frozen encoder directly (same
/// rationale as `totals_and_root_match_the_frozen_encoder_directly`).
#[test]
fn a_wide_directory_matches_the_frozen_encoder_node_count_and_total() {
    let n = 257usize;
    let names: Vec<Name> = (0..n).map(|i| name(&format!("f{i:05}"))).collect();
    let entries: Vec<Entry> = names
        .iter()
        .map(|nm| Entry {
            components: vec![nm.clone()],
            payload: Payload::File {
                exec: false,
                size: 0,
                grains: Vec::new(),
            },
        })
        .collect();
    let m = build(&entries).expect("build");

    let dir_entries: Vec<DirEntry> = names
        .into_iter()
        .map(|nm| DirEntry {
            name: nm,
            kind: EntryKind::File {
                exec: false,
                size: 0,
                grains: FileGrains::Inline(Vec::new()),
            },
        })
        .collect();
    let expect = granary_core::manifest::build_dir(&dir_entries).expect("build_dir");

    // The fixture must actually exercise a split -- otherwise this
    // test would not be testing what it claims to.
    assert!(expect.nodes.len() > 1, "fixture must produce >1 node");
    assert_eq!(m.nodes.len(), expect.nodes.len());
    let core_total: usize = expect.nodes.iter().map(|(_, b)| b.len()).sum();
    assert_eq!(m.total_bytes(), core_total as u64);
    assert_eq!(m.root, expect.root);
}

/// A single-child directory chain 10 levels deep: no committed
/// fixture exercised more than 2 levels of nesting, so a bug that
/// only manifests across recursion (e.g. a group scan dropping an
/// entry) went unnoticed. Pinned against the harness's own
/// measured output.
#[test]
fn a_deep_single_child_chain_has_pinned_node_count_and_total() {
    let mut components: Vec<Name> = (0..9).map(|i| name(&format!("d{i}"))).collect();
    components.push(name("leaf"));
    let entry = Entry {
        components,
        payload: Payload::File {
            exec: false,
            size: 0,
            grains: Vec::new(),
        },
    };
    let m = build(&[entry]).expect("build");
    assert_eq!(m.nodes.len(), 10, "{:?}", m.nodes);
    assert_eq!(m.total_bytes(), 491);
}

/// The K boundary is EXACTLY-K, never exercised by the committed
/// 1-ref and K+1-ref fixtures: narrowing the inline test's `<= K`
/// to `< K` survives both, and under it a K-grain file spills
/// (`Err(SpillUnderK)`) instead of staying inline.
#[test]
fn exactly_k_grains_stay_inline() {
    let refs: Vec<GrainRef> = (0..FILE_INLINE_MAX_REFS)
        .map(|i| GrainRef {
            id: GrainId::of(&i.to_be_bytes()),
            unpacked_len: 4096,
        })
        .collect();
    let m = build(&[file(&["k"], refs)]).expect("K grains must stay inline, not spill");
    assert_eq!(m.nodes.len(), 1, "inline: no separate grain-list node");
}

/// `build` returns one error type for two very different things: "not
/// expressible in v1" (`Encode(BadGrainLen)`, also
/// `Encode(SizeMismatch)`) and "the harness fed the encoder garbage"
/// (`MisorderedInput`, `Encode(NotStrictlySorted)`). The harness MUST
/// branch on the specific variant when deciding a grid point is
/// "unrepresentable" -- matching bare `Err(_)` would silently discard
/// data on a corpus-ordering bug, not just a genuine over-cap file. These
/// four shapes of bad ordering all reach the encoder's OWN check
/// (`Encode(NotStrictlySorted)`), not `MisorderedInput` -- which this
/// harness reserves for entries with no components at all (see
/// `an_entry_with_no_components_is_refused`).
#[test]
fn misordered_inputs_are_not_strictly_sorted_not_misordered_input() {
    // Unsorted siblings.
    let err = build(&[
        file(&["b"], vec![gref(1, 1)]),
        file(&["a"], vec![gref(2, 1)]),
    ])
    .expect_err("must refuse");
    assert!(
        matches!(
            err,
            ManifestError::Encode(EncodeNodeError::NotStrictlySorted)
        ),
        "unsorted siblings: {err:?}"
    );

    // Duplicate path.
    let err = build(&[
        file(&["a"], vec![gref(1, 1)]),
        file(&["a"], vec![gref(2, 1)]),
    ])
    .expect_err("must refuse");
    assert!(
        matches!(
            err,
            ManifestError::Encode(EncodeNodeError::NotStrictlySorted)
        ),
        "duplicate path: {err:?}"
    );

    // A name that is both a file and a directory prefix.
    let err = build(&[
        file(&["a"], vec![gref(1, 1)]),
        file(&["a", "b"], vec![gref(2, 1)]),
    ])
    .expect_err("must refuse");
    assert!(
        matches!(
            err,
            ManifestError::Encode(EncodeNodeError::NotStrictlySorted)
        ),
        "file/dir name collision: {err:?}"
    );

    // Interleaved: two non-contiguous groups under the same name,
    // split by an unrelated sibling.
    let err = build(&[
        file(&["a", "x"], vec![gref(1, 1)]),
        file(&["b"], vec![gref(2, 1)]),
        file(&["a", "y"], vec![gref(3, 1)]),
    ])
    .expect_err("must refuse");
    assert!(
        matches!(
            err,
            ManifestError::Encode(EncodeNodeError::NotStrictlySorted)
        ),
        "interleaved groups: {err:?}"
    );
}

/// A symlink's target bytes must reach the byte count, not be
/// replaced with a fixed-size stub: the delta between two builds
/// differing ONLY in target length must equal the target-length
/// delta exactly (measured, both legs).
#[test]
fn symlink_target_length_reaches_the_byte_count() {
    let short = SymlinkTarget::new(vec![b'x'; 64]).expect("valid target");
    let long = SymlinkTarget::new(vec![b'x'; 200]).expect("valid target");
    let m_short = build(&[Entry {
        components: vec![name("link")],
        payload: Payload::Symlink(short),
    }])
    .expect("build");
    let m_long = build(&[Entry {
        components: vec![name("link")],
        payload: Payload::Symlink(long),
    }])
    .expect("build");
    assert_eq!(m_short.total_bytes(), 86);
    assert_eq!(m_long.total_bytes(), 222);
    assert_eq!(m_long.total_bytes() - m_short.total_bytes(), 200 - 64);
}

/// The exec bit is part of the entry tag, so it must perturb the node id --
/// an unnoticed dropped exec bit would collapse the cross-version set
/// difference the sweep computes onto the wrong nodes.
#[test]
fn exec_bit_changes_the_node_id() {
    let no_exec = build(&[file(&["f"], vec![gref(3, 5)])]).expect("build");
    let exec = build(&[Entry {
        components: vec![name("f")],
        payload: Payload::File {
            exec: true,
            size: 5,
            grains: vec![gref(3, 5)],
        },
    }])
    .expect("build");
    assert_ne!(no_exec.root, exec.root);
}

#[test]
fn an_entry_with_no_components_is_refused() {
    let err = build(&[Entry {
        components: Vec::new(),
        payload: Payload::EmptyDir,
    }])
    .expect_err("must refuse");
    assert_eq!(err, ManifestError::MisorderedInput);
}
