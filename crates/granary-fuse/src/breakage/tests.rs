// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::breakage` — the `conformance-breakage` feature's
//! should-fail variants.
//!
//! Out-of-line: `granary-fuse`'s non-test artifact
//! has a workspace consumer (`granary-client`), so
//! the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use std::collections::BTreeMap;

use granary_core::hash::GrainId;
use granary_core::manifest::{
    DirEntry, EntryKind, FileGrains, GrainRef, Name, SymlinkTarget, TreeStats, build_dir,
};
use granary_core::sheaf::Timestamp;

use crate::FUSE_SERVE_LIMITS;
use granary_vfs::{Attr, AttrPolicy, InodeTable, NodeKind, PathKey, Snapshot};

use super::{
    Breakage, DirPlusSink, SinkOutcome, bend_attr, follow_sibling, list_dir_plus_with_breakage,
};

// ---- fixtures ----------------------------------------------------

/// A `size`-byte file. `size == 0` gets an empty inline grain list
/// (the `listing.rs`/`filesystem.rs` fixtures' own convention); a
/// nonzero size gets exactly one inline `GrainRef` whose
/// `unpacked_len` matches, because `build_dir` refuses a declared
/// size that disagrees with the grain-length sum
/// (`EncodeNodeError::SizeMismatch`). No test in this module ever
/// fetches the grain's actual bytes, so the id itself is inert —
/// only its length is checked at construction.
fn file(name: &[u8], size: u64) -> DirEntry {
    let grains = if size == 0 {
        FileGrains::Inline(Vec::new())
    } else {
        FileGrains::Inline(vec![GrainRef {
            id: GrainId::of(name),
            unpacked_len: u32::try_from(size).expect("fixture size fits in u32"),
        }])
    };
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::File {
            exec: false,
            size,
            grains,
        },
    }
}

fn dir(name: &[u8], child: GrainId) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::Dir { child },
    }
}

fn symlink(name: &[u8], target: &[u8]) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::Symlink {
            target: SymlinkTarget::new(target.to_vec()).expect("fixture target is valid"),
        },
    }
}

fn snapshot(entries: &[DirEntry]) -> (Snapshot, GrainId) {
    let built = build_dir(entries).expect("fixture directory builds");
    let nodes = built.nodes.into_iter().collect::<BTreeMap<_, _>>();
    let snap = Snapshot::new(
        nodes,
        built.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("fixture snapshot indexes");
    (snap, built.root)
}

fn path(name: &[u8]) -> PathKey {
    vec![name.to_vec()]
}

// ---- Breakage::parse / name ---------------------------------------

#[test]
fn breakage_parse_round_trips_every_variant_through_its_name() {
    for variant in Breakage::ALL {
        assert_eq!(
            Breakage::parse(variant.name()),
            Some(variant),
            "variant {variant:?} did not round-trip through its own name"
        );
    }
}

#[test]
fn breakage_parse_refuses_an_unknown_name() {
    assert_eq!(Breakage::parse("not-a-real-variant"), None);
}

// ---- bend_attr ------------------------------------------------------

fn file_attr(size: u64, perm: u16) -> Attr {
    Attr {
        ino: 7,
        generation: 1,
        kind: NodeKind::File,
        perm,
        nlink: 1,
        uid: 0,
        gid: 0,
        size,
        blocks: 0,
        blksize: 4096,
        time: Timestamp { secs: 0, nanos: 0 },
    }
}

fn dir_attr(size: u64, perm: u16) -> Attr {
    Attr {
        kind: NodeKind::Dir,
        ..file_attr(size, perm)
    }
}

#[test]
fn bend_attr_exec_everywhere_sets_555_perm_on_a_file_only() {
    let mut f = file_attr(0, 0o444);
    bend_attr(Breakage::ExecEverywhere, &mut f);
    assert_eq!(f.perm, 0o555);

    let mut d = dir_attr(4096, 0o555);
    let before = d;
    bend_attr(Breakage::ExecEverywhere, &mut d);
    assert_eq!(
        d, before,
        "a directory's attr must not move under ExecEverywhere"
    );
}

#[test]
fn bend_attr_misreport_size_adds_one_to_a_file_size_only() {
    let mut f = file_attr(40, 0o444);
    bend_attr(Breakage::MisreportSize, &mut f);
    assert_eq!(f.size, 41);

    let mut d = dir_attr(4096, 0o555);
    let before = d;
    bend_attr(Breakage::MisreportSize, &mut d);
    assert_eq!(
        d, before,
        "a directory's size must not move under MisreportSize"
    );
}

#[test]
fn bend_attr_is_a_no_op_for_every_other_variant() {
    for variant in [
        Breakage::TruncateRead,
        Breakage::OmitEntry,
        Breakage::FollowSymlink,
        Breakage::MangleSymlinkTarget,
        Breakage::DirentTypeLie,
    ] {
        let mut f = file_attr(40, 0o444);
        let before = f;
        bend_attr(variant, &mut f);
        assert_eq!(f, before, "{variant:?} must not touch Attr at all");
    }
}

// ---- follow_sibling ---------------------------------------------

#[test]
fn follow_sibling_substitutes_a_sibling_symlink_to_a_regular_file() {
    let (snap, root) = snapshot(&[file(b"f", 4), symlink(b"s", b"f")]);
    let entry = snap.lookup(&root, b"s").expect("s looked up");
    let result = follow_sibling(&snap, &root, entry);
    assert!(
        matches!(result.kind, EntryKind::File { size: 4, .. }),
        "expected the referent's File entry, got {:?}",
        result.kind
    );
}

#[test]
fn follow_sibling_leaves_a_dangling_symlink_honest() {
    let (snap, root) = snapshot(&[symlink(b"broken", b"nope")]);
    let entry = snap.lookup(&root, b"broken").expect("broken looked up");
    let before = entry.clone();
    let result = follow_sibling(&snap, &root, entry);
    assert_eq!(result.kind, before.kind);
}

#[test]
fn follow_sibling_leaves_a_slash_containing_target_honest() {
    // EQUIVALENT MUTANT, named rather than chased:
    // this test cannot actually distinguish "the `contains(b'/')`
    // guard fired" from "the guard was never reached and
    // `Snapshot::lookup` failed naturally" — `Name::new`
    // rejects any manifest name containing `/` at construction, so
    // no entry could ever be stored under the literal name
    // "../x" regardless of whether `follow_sibling`'s own slash
    // check exists. Removing that check would still leave this
    // assertion green, via `lookup`'s `NotFound` instead. Kept
    // anyway: it documents the INTENDED behaviour (a `..`-containing
    // target must be reported honestly), even though this
    // particular fixture cannot isolate the guard from the
    // manifest's own, independent refusal of `/` in a name.
    let (snap, root) = snapshot(&[symlink(b"updir", b"../x")]);
    let entry = snap.lookup(&root, b"updir").expect("updir looked up");
    let before = entry.clone();
    let result = follow_sibling(&snap, &root, entry);
    assert_eq!(result.kind, before.kind);
}

#[test]
fn follow_sibling_leaves_a_symlink_to_a_directory_honest() {
    let child = build_dir(&[]).expect("empty child dir builds");
    let mut entries = vec![dir(b"d", child.root), symlink(b"s2", b"d")];
    entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    let built = build_dir(&entries).expect("fixture directory builds");
    let mut nodes = child.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(built.nodes);
    let snap = Snapshot::new(
        nodes,
        built.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("fixture snapshot indexes");
    let entry = snap.lookup(&built.root, b"s2").expect("s2 looked up");
    let before = entry.clone();
    let result = follow_sibling(&snap, &built.root, entry);
    assert_eq!(result.kind, before.kind);
}

#[test]
fn follow_sibling_is_a_no_op_on_a_non_symlink_entry() {
    let (snap, root) = snapshot(&[file(b"f", 4)]);
    let entry = snap.lookup(&root, b"f").expect("f looked up");
    let before = entry.clone();
    let result = follow_sibling(&snap, &root, entry);
    assert_eq!(result.kind, before.kind);
}

// ---- BreakageDirPlusSink / list_dir_plus_with_breakage -----------

struct RecordingSink {
    cap: usize,
    offered: Vec<(Attr, Vec<u8>)>,
}

impl DirPlusSink for RecordingSink {
    fn offer(&mut self, attr: Attr, name: &[u8], _next: u64) -> SinkOutcome {
        if self.offered.len() >= self.cap {
            return SinkOutcome::Full;
        }
        self.offered.push((attr, name.to_vec()));
        SinkOutcome::Added
    }
}

fn offered_names(sink: &RecordingSink) -> Vec<Vec<u8>> {
    sink.offered.iter().map(|(_, name)| name.clone()).collect()
}

#[test]
fn omit_entry_withholds_only_the_first_non_dot_entry() {
    let (snap, root) = snapshot(&[file(b"a", 0), file(b"b", 0)]);
    let mut table = InodeTable::new(root, 1, 1);
    let mut sink = RecordingSink {
        cap: usize::MAX,
        offered: Vec::new(),
    };
    list_dir_plus_with_breakage(Breakage::OmitEntry, &mut table, &snap, 1, 0, &mut sink)
        .expect("listing succeeds");
    assert_eq!(
        offered_names(&sink),
        vec![b".".to_vec(), b"..".to_vec(), b"b".to_vec()],
        "\"a\" (the first non-dot entry) must be withheld; \"b\" and both dot entries must \
         still be delegated"
    );
}

#[test]
fn list_dir_plus_with_breakage_drains_its_ledger_leaving_resident_count_unchanged() {
    let (snap, root) = snapshot(&[file(b"a", 0)]);
    let mut table = InodeTable::new(root, 1, 1);
    let baseline = table.resident_count();
    let mut sink = RecordingSink {
        cap: usize::MAX,
        offered: Vec::new(),
    };
    list_dir_plus_with_breakage(Breakage::OmitEntry, &mut table, &snap, 1, 0, &mut sink)
        .expect("listing succeeds");
    assert_eq!(
        table.resident_count(),
        baseline,
        "the withheld entry's credit must be fully repaid by the drain"
    );
}

#[test]
fn list_dir_plus_with_breakage_does_not_double_forget_a_full_rejected_entry() {
    let child = build_dir(&[]).expect("empty child dir builds");
    let entries = [dir(b"d", child.root)];
    let built = build_dir(&entries).expect("fixture directory builds");
    let mut nodes = child.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(built.nodes);
    let snap = Snapshot::new(
        nodes,
        built.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("fixture snapshot indexes");
    let mut table = InodeTable::new(built.root, 1, 1);

    // A LIVE reference from an earlier, unrelated kernel `lookup` on
    // this exact path — this is the credit the double-forget bug
    // would destroy.
    let (pre_ino, _gen) = table
        .lookup(path(b"d"), built.root, NodeKind::Dir)
        .expect("pre-credit lookup");

    // `cap: 2` accepts the two dot entries (which cost no credit,
    // list_dir_plus's own doc) and then answers `Full` for "d" —
    // `cap: 0` would reject the DOT entry first and never reach "d"
    // at all. The inner sink refusing "d" is what makes
    // `list_dir_plus` itself repay the ONE credit it just took for
    // it, via its own FULL arm.
    let mut sink = RecordingSink {
        cap: 2,
        offered: Vec::new(),
    };
    list_dir_plus_with_breakage(Breakage::DirentTypeLie, &mut table, &snap, 1, 0, &mut sink)
        .expect("listing succeeds even when every entry is rejected");

    assert_eq!(
        table.peek(&path(b"d")),
        Some(pre_ino),
        "the earlier lookup's credit must survive; a double-forget would reclaim it"
    );
}

#[test]
fn dirent_type_lie_zeroes_ino_and_lies_kind_for_a_directory_entry_only() {
    let child = build_dir(&[]).expect("empty child dir builds");
    let entries = [dir(b"d", child.root), file(b"f", 0)];
    let built = build_dir(&entries).expect("fixture directory builds");
    let mut nodes = child.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(built.nodes);
    let snap = Snapshot::new(
        nodes,
        built.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("fixture snapshot indexes");
    let mut table = InodeTable::new(built.root, 1, 1);
    let mut sink = RecordingSink {
        cap: usize::MAX,
        offered: Vec::new(),
    };
    list_dir_plus_with_breakage(Breakage::DirentTypeLie, &mut table, &snap, 1, 0, &mut sink)
        .expect("listing succeeds");

    let by_name = |name: &[u8]| {
        sink.offered
            .iter()
            .find(|(_, n)| n == name)
            .unwrap_or_else(|| panic!("{name:?} was not offered"))
    };
    let (d_attr, _) = by_name(b"d");
    assert_eq!(
        d_attr.kind,
        NodeKind::File,
        "the directory's dirent must lie as File"
    );
    assert_eq!(d_attr.ino, 0, "the directory's ino must be zeroed");
    let (f_attr, _) = by_name(b"f");
    assert_eq!(f_attr.kind, NodeKind::File);
    assert_ne!(f_attr.ino, 0, "an honest file's ino must not be touched");

    // The zeroed credit must have been drained: "d"'s row is gone,
    // "f"'s real credit (never withheld) is still resident.
    assert_eq!(table.peek(&path(b"d")), None);
    assert!(table.peek(&path(b"f")).is_some());
}

#[test]
fn exec_everywhere_and_misreport_size_are_not_the_wrappers_job_attrs_pass_through_honest() {
    // `ExecEverywhere`/`MisreportSize` moved
    // downstream of this wrapper — to `filesystem.rs`'s
    // `RealDirPlusSink::offer`, the only place that can mint the
    // `Bent` token `to_file_attr` now requires (see
    // `BreakageDirPlusSink`'s own doc). This wrapper's job for
    // these two variants is NOTHING: the entry passes through
    // exactly as `list_dir_plus` built it. A `RecordingSink` fake
    // has no `GranaryFs` and so cannot bend either — which is
    // exactly the point: if this wrapper still bent here too, a
    // real mount would double-apply the MisreportSize `+1`.
    let child = build_dir(&[]).expect("empty child dir builds");
    let entries = [dir(b"d", child.root), file(b"f", 10)];
    let built = build_dir(&entries).expect("fixture directory builds");
    let mut nodes = child.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(built.nodes);
    let snap = Snapshot::new(
        nodes,
        built.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("fixture snapshot indexes");

    let mut table = InodeTable::new(built.root, 1, 1);
    let mut sink = RecordingSink {
        cap: usize::MAX,
        offered: Vec::new(),
    };
    list_dir_plus_with_breakage(Breakage::MisreportSize, &mut table, &snap, 1, 0, &mut sink)
        .expect("listing succeeds");
    let by_name = |sink: &RecordingSink, name: &[u8]| {
        sink.offered
            .iter()
            .find(|(_, n)| n == name)
            .unwrap_or_else(|| panic!("{name:?} was not offered"))
            .0
    };
    assert_eq!(
        by_name(&sink, b"f").size,
        10,
        "the wrapper must NOT bend the file's size — that is RealDirPlusSink's job now"
    );
    assert_eq!(
        by_name(&sink, b"d").size,
        4096,
        "the directory's size must stay honest either way"
    );
}

#[test]
fn follow_symlink_at_the_wrapper_reports_the_referents_kind_and_size_under_the_links_own_ino() {
    let (snap, root) = snapshot(&[file(b"f", 4), symlink(b"s", b"f")]);
    let mut table = InodeTable::new(root, 1, 1);
    let mut sink = RecordingSink {
        cap: usize::MAX,
        offered: Vec::new(),
    };
    list_dir_plus_with_breakage(Breakage::FollowSymlink, &mut table, &snap, 1, 0, &mut sink)
        .expect("listing succeeds");
    let by_name = |sink: &RecordingSink, name: &[u8]| {
        sink.offered
            .iter()
            .find(|(_, n)| n == name)
            .unwrap_or_else(|| panic!("{name:?} was not offered"))
            .0
    };
    let s_attr = by_name(&sink, b"s");
    assert_eq!(
        s_attr.kind,
        NodeKind::File,
        "\"s\" must report as File once followed"
    );
    assert_eq!(s_attr.size, 4, "\"s\" must report f's size");
    let s_ino = table.peek(&path(b"s")).expect("s has its own ino row");
    let f_ino = table.peek(&path(b"f")).expect("f has its own ino row");
    assert_eq!(
        s_attr.ino, s_ino,
        "the substituted attr must keep the LINK's own ino"
    );
    assert_ne!(s_ino, f_ino, "s and f must never share an ino");
}
