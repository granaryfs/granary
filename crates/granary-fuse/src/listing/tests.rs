// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::listing` — the directory operation's testable core:
//! descent, the name-length rule, and `readdir`/`readdirplus`
//! behind a sink.
//!
//! Out-of-line: `granary-fuse`'s non-test artifact
//! has a workspace consumer (`granary-client`), so
//! the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use super::{
    DOT, DOT_DOT, DirPlusSink, DirSink, SinkOutcome, check_name_length, entry_file_type, list_dir,
    list_dir_plus,
};
use crate::FUSE_SERVE_LIMITS;
use granary_core::hash::GrainId;
use granary_core::manifest::{DirEntry, EntryKind, FileGrains, Name, TreeStats, build_dir};
use granary_core::sheaf::Timestamp;
use granary_vfs::{
    Attr, AttrPolicy, InodeTable, NodeKind, ReaderError, ReservedEntryKind, ServeLimits, Snapshot,
    SnapshotError, dir_and_parent,
};
use std::collections::BTreeMap;

fn file(name: &[u8]) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::File {
            exec: false,
            size: 0,
            grains: FileGrains::Inline(Vec::new()),
        },
    }
}

fn dir(name: &[u8], child: GrainId) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::Dir { child },
    }
}

fn snapshot(entries: &[DirEntry]) -> (Snapshot, GrainId) {
    let built = build_dir(entries).expect("fixture directory builds");
    let root = built.root;
    let nodes = built.nodes.into_iter().collect::<BTreeMap<_, _>>();
    let snapshot = Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        ServeLimits::UNBOUNDED,
    )
    .expect("fixture snapshot indexes");
    (snapshot, root)
}

// ---- name length -----------------------------------------------

#[test]
fn name_length_boundary_is_exact() {
    let at_cap = vec![b'a'; granary_core::manifest::name::NAME_MAX];
    let over_cap = vec![b'a'; granary_core::manifest::name::NAME_MAX + 1];
    assert_eq!(check_name_length(&at_cap), Ok(()));
    assert_eq!(
        check_name_length(&over_cap),
        Err(fuser::Errno::ENAMETOOLONG)
    );
}

// ---- entry_file_type ---------------------------------------------

#[test]
fn entry_file_type_covers_every_manifest_kind() {
    let cases = [
        (
            EntryKind::Dir {
                child: GrainId::of(b"d"),
            },
            fuser::FileType::Directory,
        ),
        (
            EntryKind::File {
                exec: false,
                size: 0,
                grains: FileGrains::Inline(Vec::new()),
            },
            fuser::FileType::RegularFile,
        ),
        (
            EntryKind::Symlink {
                target: granary_core::manifest::SymlinkTarget::new(b"t".to_vec())
                    .expect("fixture target valid"),
            },
            fuser::FileType::Symlink,
        ),
        (EntryKind::Fifo, fuser::FileType::NamedPipe),
        (EntryKind::Socket, fuser::FileType::Socket),
    ];
    for (kind, expected) in cases {
        assert_eq!(entry_file_type(&kind), expected);
    }
}

// ---- plain readdir -------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlainRecord {
    ino: u64,
    kind: fuser::FileType,
    name: Vec<u8>,
    next: u64,
}

struct CapPlainSink {
    cap: usize,
    entries: Vec<PlainRecord>,
}

impl DirSink for CapPlainSink {
    fn offer(&mut self, ino: u64, kind: fuser::FileType, name: &[u8], next: u64) -> SinkOutcome {
        if self.entries.len() >= self.cap {
            return SinkOutcome::Full;
        }
        self.entries.push(PlainRecord {
            ino,
            kind,
            name: name.to_vec(),
            next,
        });
        SinkOutcome::Added
    }
}

#[test]
fn plain_readdir_credits_nothing_at_all() {
    let (snap, root) = snapshot(&[file(b"only")]);
    let mut table = InodeTable::new(root, 1, 1);
    // Root already carries one credit from `InodeTable::new`. If plain
    // readdir credited anything, a single forget(1) would no longer be
    // enough to reclaim it (root is never reclaimed regardless, so use
    // a non-root fixture instead — see below for the real assertion).
    let (child_ino, _) = table
        .lookup(vec![b"only".to_vec()], root, NodeKind::File)
        .expect("pre-seed a credit for the file, independent of readdir");

    let mut sink = CapPlainSink {
        cap: 10,
        entries: Vec::new(),
    };
    list_dir(&table, &snap, 1, 0, &mut sink).expect("listing succeeds");
    list_dir(&table, &snap, 1, 0, &mut sink).expect("second listing succeeds");

    // The file's single pre-seeded credit must still be exactly one:
    // one forget(1) reclaims it.
    let mut mutable_table = table;
    mutable_table.forget(child_ino, 1);
    assert!(
        mutable_table.resolve(child_ino).is_err(),
        "two plain-readdir listings must not have added any credit"
    );
}

#[test]
fn plain_readdir_reports_peeked_ino_and_zero_for_unallocated() {
    let (snap, root) = snapshot(&[file(b"known"), file(b"unknown")]);
    let mut table = InodeTable::new(root, 1, 1);
    let (known_ino, _) = table
        .lookup(vec![b"known".to_vec()], root, NodeKind::File)
        .expect("pre-allocate one path");

    let mut sink = CapPlainSink {
        cap: 10,
        entries: Vec::new(),
    };
    list_dir(&table, &snap, 1, 0, &mut sink).expect("listing succeeds");

    let known = sink
        .entries
        .iter()
        .find(|e| e.name == b"known")
        .expect("known entry listed");
    assert_eq!(known.ino, known_ino);
    let unknown = sink
        .entries
        .iter()
        .find(|e| e.name == b"unknown")
        .expect("unknown entry listed");
    assert_eq!(
        unknown.ino, 0,
        "an unallocated path is reported as ino 0, best-effort"
    );

    assert_eq!(
        table.peek(&vec![b"unknown".to_vec()]),
        None,
        "plain readdir must not allocate a row for an entry it only listed"
    );
}

#[test]
fn plain_readdir_cookie_round_trip_across_a_filling_sink() {
    let names = (0_u32..9).map(|n| format!("e{n:02}")).collect::<Vec<_>>();
    let entries = names.iter().map(|n| file(n.as_bytes())).collect::<Vec<_>>();
    let (snap, root) = snapshot(&entries);
    let table = InodeTable::new(root, 1, 1);

    let mut collected: Vec<Vec<u8>> = Vec::new();
    let mut offset = 0_u64;
    let mut terminated = false;
    // Bounded, not `loop {}`: a cookie off-by-one that never empties
    // the sink does not fail -- it HANGS, and nextest's own
    // `terminate-after` (60s) reports that as a timeout rather than a
    // diff. 9 real entries + 2 dots at cap 3 needs at most 4 rounds;
    // 20 is a generous bound with headroom, and `terminated` makes a
    // non-terminating walk fail in milliseconds with a named assertion
    // instead of a wall-clock kill.
    for _ in 0..20 {
        let mut sink = CapPlainSink {
            cap: 3,
            entries: Vec::new(),
        };
        list_dir(&table, &snap, 1, offset, &mut sink).expect("listing succeeds");
        if sink.entries.is_empty() {
            terminated = true;
            break;
        }
        let last_next = sink.entries.last().expect("nonempty checked above").next;
        for record in &sink.entries {
            collected.push(record.name.clone());
        }
        offset = last_next;
    }
    assert!(
        terminated,
        "the resumed walk must terminate well within the iteration bound"
    );

    let mut expected = vec![b".".to_vec(), b"..".to_vec()];
    expected.extend(names.iter().map(|n| n.as_bytes().to_vec()));
    assert_eq!(
        collected, expected,
        "the resumed listing must be exact: no skip, no duplicate, in order"
    );
}

// ---- readdirplus -----------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlusRecord {
    attr: Attr,
    name: Vec<u8>,
    next: u64,
}

struct CapPlusSink {
    cap: usize,
    entries: Vec<PlusRecord>,
}

impl DirPlusSink for CapPlusSink {
    fn offer(&mut self, attr: Attr, name: &[u8], next: u64) -> SinkOutcome {
        if self.entries.len() >= self.cap {
            return SinkOutcome::Full;
        }
        self.entries.push(PlusRecord {
            attr,
            name: name.to_vec(),
            next,
        });
        SinkOutcome::Added
    }
}

fn three_entry_fixture() -> (Snapshot, GrainId) {
    // `build_dir` requires strict memcmp order: "alpha" < "bravo" <
    // "charlie".
    snapshot(&[file(b"alpha"), file(b"bravo"), file(b"charlie")])
}

#[test]
fn dot_and_dotdot_cost_no_lookup_credit_across_repeated_listings() {
    // root -> parent -> child (empty), so BOTH the listed directory's
    // own credit (".") and its PARENT's credit ("..") are independently
    // observable via forget/resolve. The root is never reclaimed (by
    // design), so testing against it directly could not observe an
    // over-credited root at all; using a non-root parent closes that
    // gap.
    let child = build_dir(&[]).expect("child builds");
    let parent_entries = [dir(b"child", child.root)];
    let parent = build_dir(&parent_entries).expect("parent builds");
    let root_entries = [dir(b"parent", parent.root)];
    let root_tree = build_dir(&root_entries).expect("root builds");
    let mut nodes = child.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(parent.nodes);
    nodes.extend(root_tree.nodes);
    let snap = Snapshot::new(
        nodes,
        root_tree.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("snapshot indexes");

    let mut table = InodeTable::new(root_tree.root, 1, 1);
    let (parent_ino, _) = table
        .lookup(vec![b"parent".to_vec()], root_tree.root, NodeKind::Dir)
        .expect("seed exactly one credit on parent");
    let (child_ino, _) = table
        .lookup(
            vec![b"parent".to_vec(), b"child".to_vec()],
            parent.root,
            NodeKind::Dir,
        )
        .expect("seed exactly one credit on child");

    // List `child` (which reports "." = child_ino and ".." =
    // parent_ino) several times. If dots were credited, either
    // inode's nlookup would grow past its single seeded credit.
    for _ in 0..5 {
        let mut sink = CapPlusSink {
            cap: 10,
            entries: Vec::new(),
        };
        list_dir_plus(&mut table, &snap, child_ino, 0, &mut sink).expect("listing succeeds");
    }

    table.forget(child_ino, 1);
    assert!(
        table.resolve(child_ino).is_err(),
        "five listings must not have credited '.' beyond the single seeded lookup"
    );
    table.forget(parent_ino, 1);
    assert!(
        table.resolve(parent_ino).is_err(),
        "five listings must not have credited '..' beyond the single seeded lookup"
    );
}

#[test]
fn a_full_sink_leaves_no_credit_for_the_rejected_entry() {
    // The test the whole wave is for: capacity 2 out of 3 real
    // entries (plus the two dots, which cost nothing and are offered
    // first), so the walk accepts the two dots and TWO real entries,
    // then FULLs on the third.
    let (snap, root) = three_entry_fixture();
    let mut table = InodeTable::new(root, 1, 1);
    let mut sink = CapPlusSink {
        cap: 4, // "." + ".." + two real entries
        entries: Vec::new(),
    };

    list_dir_plus(&mut table, &snap, 1, 0, &mut sink).expect("listing succeeds");
    assert_eq!(sink.entries.len(), 4);
    let accepted_names = sink
        .entries
        .iter()
        .map(|e| e.name.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        accepted_names,
        vec![
            b".".to_vec(),
            b"..".to_vec(),
            b"alpha".to_vec(),
            b"bravo".to_vec()
        ]
    );

    // The accepted real entries ARE credited (a row exists).
    assert!(table.peek(&vec![b"alpha".to_vec()]).is_some());
    assert!(table.peek(&vec![b"bravo".to_vec()]).is_some());
    // The REJECTED entry ("charlie") leaves no trace: the credit taken
    // to build its Attr was repaid, so no row survives it.
    assert_eq!(
        table.peek(&vec![b"charlie".to_vec()]),
        None,
        "a credit taken for an entry the sink rejected must be repaid"
    );

    // Listing repeatedly into the same small sink must not grow the
    // table without bound: "charlie" must never accumulate a row no
    // matter how many times this is repeated.
    let before = table.resident_count();
    for _ in 0..20 {
        let mut sink = CapPlusSink {
            cap: 4,
            entries: Vec::new(),
        };
        list_dir_plus(&mut table, &snap, 1, 0, &mut sink).expect("listing succeeds");
    }
    assert_eq!(
        table.peek(&vec![b"charlie".to_vec()]),
        None,
        "repeated truncated listings must not eventually allocate the rejected path"
    );
    assert_eq!(
        table.resident_count(),
        before,
        "the table must not grow across repeated truncated listings"
    );
}

#[test]
fn readdirplus_cookie_round_trip_across_a_filling_sink() {
    let names = (0_u32..9).map(|n| format!("e{n:02}")).collect::<Vec<_>>();
    let entries = names.iter().map(|n| file(n.as_bytes())).collect::<Vec<_>>();
    let (snap, root) = snapshot(&entries);
    let mut table = InodeTable::new(root, 1, 1);

    let mut collected: Vec<Vec<u8>> = Vec::new();
    let mut offset = 0_u64;
    let mut terminated = false;
    // Bounded for the same reason as plain readdir's twin above: a
    // cookie bug must fail fast with a named assertion, not hang for
    // nextest's 60s terminate-after.
    for _ in 0..20 {
        let mut sink = CapPlusSink {
            cap: 4,
            entries: Vec::new(),
        };
        list_dir_plus(&mut table, &snap, 1, offset, &mut sink).expect("listing succeeds");
        if sink.entries.is_empty() {
            terminated = true;
            break;
        }
        let last_next = sink.entries.last().expect("nonempty checked above").next;
        for record in &sink.entries {
            collected.push(record.name.clone());
            // The attr's own ino must agree with what a fresh peek
            // reports — proving the sink was handed the AUTHORITATIVE
            // value (trap T1's guard, structurally: there is only one
            // ino in this design, carried inside Attr).
            if record.name != DOT && record.name != DOT_DOT {
                assert_eq!(
                    table.peek(&vec![record.name.clone()]),
                    Some(record.attr.ino)
                );
            }
        }
        offset = last_next;
    }
    assert!(
        terminated,
        "the resumed walk must terminate well within the iteration bound"
    );

    let mut expected = vec![b".".to_vec(), b"..".to_vec()];
    expected.extend(names.iter().map(|n| n.as_bytes().to_vec()));
    assert_eq!(
        collected, expected,
        "the resumed listing must be exact: no skip, no duplicate, in order"
    );
}

/// A snapshot carrying a FIFO must not index. A reserved entry is a
/// decode-time refusal, and `Snapshot::new` enforces it at construction
/// (`SnapshotError::ReservedEntry`), so `list_dir_plus` never observes
/// such an entry — its own FIFO/socket branch is unreachable on a
/// successfully-constructed `Snapshot`, and fails the WHOLE operation
/// (`ReaderError::UnsupportedEntry`) as defence in depth, in case that
/// gate ever regresses. The alternative a reader might expect —
/// `list_dir_plus` silently skipping the entry rather than crediting or
/// offering it — is what that branch refuses to do, because it leaves
/// the entry invisible to `ls` while an explicit `stat` on its name
/// answers `EIO`. This test pins the construction refusal itself,
/// naming the entry.
#[test]
fn a_fifo_entry_is_refused_at_snapshot_construction_naming_the_entry() {
    let fifo_name = Name::new(b"pipe".to_vec()).expect("fixture name valid");
    let entries = [
        // `build_dir` requires strict memcmp order: "pipe" < "regular".
        DirEntry {
            name: fifo_name.clone(),
            kind: EntryKind::Fifo,
        },
        file(b"regular"),
    ];
    let built = build_dir(&entries).expect("fixture directory builds");
    let root = built.root;
    let nodes = built.nodes.into_iter().collect::<BTreeMap<_, _>>();

    let result = Snapshot::new(
        nodes,
        root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    );

    let refusal = result.expect_err("a snapshot carrying a FIFO must be refused, not indexed");
    assert_eq!(
        refusal,
        SnapshotError::ReservedEntry {
            dir: root,
            name: fifo_name,
            kind: ReservedEntryKind::Fifo,
        }
    );
}

// ---- the A29/A30 wiring tests: evidence for the listing path ---------

/// root -> {"childdir" (a real, empty directory), "plainfile" (a real
/// file)}. Used by the A29/A30 wiring tests: a listing that includes a
/// directory ENTRY (not just files) is what makes a constant-kind
/// mutation observable at all — a fixture of files only cannot
/// distinguish "reports the true kind" from "reports a constant".
fn root_with_a_real_subdirectory_and_a_file() -> (Snapshot, GrainId) {
    let child = build_dir(&[]).expect("child dir builds");
    // `build_dir` requires strict memcmp order: "childdir" < "plainfile".
    let entries = [dir(b"childdir", child.root), file(b"plainfile")];
    let built = build_dir(&entries).expect("fixture directory builds");
    let mut nodes = child.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(built.nodes);
    let snapshot = Snapshot::new(
        nodes,
        built.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("fixture snapshot indexes");
    (snapshot, built.root)
}

#[test]
fn plain_readdir_reports_the_true_file_type_per_entry_not_a_constant() {
    // A29: `entry_file_type(&entry.kind)` collapsed to a constant
    // `Directory` — `entry_file_type` itself is exhaustively unit
    // tested in isolation (`entry_file_type_covers_every_manifest_kind`
    // above), but nothing before this test asserted on its WIRING into
    // `list_dir`'s sink calls: the extracted helper got the test, the
    // call site kept the risk.
    let (snap, root) = root_with_a_real_subdirectory_and_a_file();
    let table = InodeTable::new(root, 1, 1);
    let mut sink = CapPlainSink {
        cap: 10,
        entries: Vec::new(),
    };
    list_dir(&table, &snap, 1, 0, &mut sink).expect("listing succeeds");

    let dir_record = sink
        .entries
        .iter()
        .find(|e| e.name == b"childdir")
        .expect("directory entry listed");
    assert_eq!(dir_record.kind, fuser::FileType::Directory);
    let file_record = sink
        .entries
        .iter()
        .find(|e| e.name == b"plainfile")
        .expect("file entry listed");
    assert_eq!(
        file_record.kind,
        fuser::FileType::RegularFile,
        "A29: the file entry's reported kind must be the TRUE kind, not a constant Directory"
    );
}

#[test]
fn plain_readdir_of_a_non_root_directory_maps_dot_and_dotdot_to_their_own_inos_not_swapped() {
    // Root cause 2: no test before this one ever listed a NON-ROOT
    // directory that has entries, so `dir` and `parent` were the same
    // value (root) in every existing test and a `.`/`..` path-mapping
    // swap (A21) was invisible. `top` here is listed directly, and it
    // has a real entry of its own ("leaf"), giving both halves of
    // root cause 2 one fixture.
    let top_entries = [file(b"leaf")];
    let top = build_dir(&top_entries).expect("top builds");
    let root_entries = [dir(b"top", top.root)];
    let root_tree = build_dir(&root_entries).expect("root builds");
    let mut nodes = top.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(root_tree.nodes);
    let snap = Snapshot::new(
        nodes,
        root_tree.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("snapshot indexes");

    let mut table = InodeTable::new(root_tree.root, 1, 1);
    let (top_ino, _) = table
        .lookup(vec![b"top".to_vec()], root_tree.root, NodeKind::Dir)
        .expect("top resolves");

    let mut sink = CapPlainSink {
        cap: 10,
        entries: Vec::new(),
    };
    list_dir(&table, &snap, top_ino, 0, &mut sink).expect("listing succeeds");

    let dot = sink
        .entries
        .iter()
        .find(|e| e.name == DOT)
        .expect(". listed");
    let dotdot = sink
        .entries
        .iter()
        .find(|e| e.name == DOT_DOT)
        .expect(".. listed");
    assert_eq!(
        dot.ino, top_ino,
        "A21: '.' must report the LISTED directory's own ino"
    );
    assert_eq!(
        dotdot.ino, 1,
        "A21: '..' must report the PARENT's ino (root), not the listed dir's own"
    );
    assert_ne!(
        dot.ino, dotdot.ino,
        "sanity: the fixture must make '.' and '..' distinguishable"
    );

    let leaf = sink
        .entries
        .iter()
        .find(|e| e.name == b"leaf")
        .expect("a real entry under the non-root directory must still be listed");
    assert_eq!(leaf.kind, fuser::FileType::RegularFile);
}

#[test]
fn qa_readdirplus_of_a_subdirectory_records_descendable_rows() {
    // root -> { "sub" (a DECOY dir), "top" }, and top -> { "plain",
    // "sub" -> "deep-only" }. Listing `top` allocates a row for
    // "top/sub"; that row's recorded node must be TOP's, not the
    // root's -- otherwise a later dir_and_parent silently descends
    // into the root's unrelated "sub" instead (trap T4's defect class,
    // reintroduced at ALLOCATION time rather than at descent time).
    let decoy = build_dir(&[file(b"decoy-only")]).expect("decoy builds");
    let deep = build_dir(&[file(b"deep-only")]).expect("deep builds");
    let top_entries = [file(b"plain"), dir(b"sub", deep.root)];
    let top = build_dir(&top_entries).expect("top builds");
    let root_entries = [dir(b"sub", decoy.root), dir(b"top", top.root)];
    let root_tree = build_dir(&root_entries).expect("root builds");
    let mut nodes = decoy.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(deep.nodes);
    nodes.extend(top.nodes);
    nodes.extend(root_tree.nodes);
    let snap = Snapshot::new(
        nodes,
        root_tree.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("snapshot indexes");

    let mut table = InodeTable::new(root_tree.root, 1, 1);
    let (top_ino, _) = table
        .lookup(vec![b"top".to_vec()], root_tree.root, NodeKind::Dir)
        .expect("top resolves");

    let mut sink = CapPlusSink {
        cap: 10,
        entries: Vec::new(),
    };
    list_dir_plus(&mut table, &snap, top_ino, 0, &mut sink).expect("listing succeeds");

    let sub_ino = table
        .peek(&vec![b"top".to_vec(), b"sub".to_vec()])
        .expect("readdirplus allocated a row for top/sub");
    assert_eq!(
        dir_and_parent(&table, &snap, sub_ino),
        Ok((deep.root, top.root)),
        "a row allocated by readdirplus must record the LISTED directory's node"
    );
    assert_ne!(
        dir_and_parent(&table, &snap, sub_ino),
        Ok((decoy.root, root_tree.root)),
        "it must not descend into the ROOT's unrelated 'sub'"
    );
}

#[test]
fn readdirplus_reports_the_true_attr_kind_per_entry_not_a_constant() {
    // A30: the fabricated `Entry`'s `kind: entry.kind.clone()` collapsed
    // to a constant `EntryKind::File { size: 0, .. }` -- every entry,
    // directories included, would then present as a 0-byte regular
    // file. Same lesson as A29, at the OTHER call site.
    let (snap, root) = root_with_a_real_subdirectory_and_a_file();
    let mut table = InodeTable::new(root, 1, 1);
    let mut sink = CapPlusSink {
        cap: 10,
        entries: Vec::new(),
    };
    list_dir_plus(&mut table, &snap, 1, 0, &mut sink).expect("listing succeeds");

    let dir_record = sink
        .entries
        .iter()
        .find(|e| e.name == b"childdir")
        .expect("directory entry listed");
    assert_eq!(
        dir_record.attr.kind,
        NodeKind::Dir,
        "A30: a directory entry's attr kind must be Dir, not a constant File"
    );
    assert_eq!(
        dir_record.attr.size, 4096,
        "a directory's attr must report DIRECTORY_SIZE, which a constant File{{size:0}} kind could not"
    );
    let file_record = sink
        .entries
        .iter()
        .find(|e| e.name == b"plainfile")
        .expect("file entry listed");
    assert_eq!(file_record.attr.kind, NodeKind::File);
}

#[test]
fn readdirplus_reports_the_tables_true_generation_not_a_constant_zero() {
    // A5: the `attr_for(..., generation)` argument collapsed to a
    // constant `0`. `lookup` would reply generation G for the same
    // inode while readdirplus replied 0 -- the kernel keys identity on
    // (nodeid, generation) and would treat that mismatch as a stale
    // inode. Use a generation that is neither 0 nor the default 1, so
    // the mutation cannot coincide with it by accident.
    let (snap, root) = three_entry_fixture();
    let mut table = InodeTable::new(root, 7, 1);
    let mut sink = CapPlusSink {
        cap: 10,
        entries: Vec::new(),
    };
    list_dir_plus(&mut table, &snap, 1, 0, &mut sink).expect("listing succeeds");

    let alpha = sink
        .entries
        .iter()
        .find(|e| e.name == b"alpha")
        .expect("real entry listed");
    assert_eq!(
        alpha.attr.generation, 7,
        "A5: readdirplus must report the table's TRUE generation, not a hardcoded 0"
    );
}

#[test]
fn readdirplus_dot_and_dotdot_report_their_own_true_inos_and_true_names() {
    // A7/A8: the `.`/`..` nodeid collapsed to a constant `0`. Also
    // guards the `placeholder_name` assumption: `attr_for` is safe to
    // call with a fabricated name ONLY because it never reads
    // `entry.name` (verified at `granary-vfs/src/attr.rs:58-88`); nothing enforces
    // that, so this asserts the SINK's `name` parameter is the real
    // "." / ".." from `ReaddirEntry`, never the "dot" placeholder that
    // only ever feeds `attr_for`'s fabricated `Entry`.
    let child = build_dir(&[]).expect("child builds");
    let parent_entries = [dir(b"child", child.root)];
    let parent = build_dir(&parent_entries).expect("parent builds");
    let root_entries = [dir(b"parent", parent.root)];
    let root_tree = build_dir(&root_entries).expect("root builds");
    let mut nodes = child.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(parent.nodes);
    nodes.extend(root_tree.nodes);
    let snap = Snapshot::new(
        nodes,
        root_tree.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("snapshot indexes");

    let mut table = InodeTable::new(root_tree.root, 1, 1);
    let (parent_ino, _) = table
        .lookup(vec![b"parent".to_vec()], root_tree.root, NodeKind::Dir)
        .expect("seed parent's row");
    let (child_ino, _) = table
        .lookup(
            vec![b"parent".to_vec(), b"child".to_vec()],
            parent.root,
            NodeKind::Dir,
        )
        .expect("seed child's row");

    let mut sink = CapPlusSink {
        cap: 10,
        entries: Vec::new(),
    };
    list_dir_plus(&mut table, &snap, child_ino, 0, &mut sink).expect("listing succeeds");

    // `.` and `..` are always emitted FIRST, in that order
    // (`Snapshot::readdir`) -- indexed by POSITION rather than found by
    // matching on `e.name`, so a name-corrupting mutation is caught by
    // the equality assertions below rather than by a `.find` that would
    // simply fail to locate the record at all.
    assert_eq!(sink.entries.len(), 2, "child has no entries of its own");
    let dot = &sink.entries[0];
    let dotdot = &sink.entries[1];
    assert_eq!(
        dot.attr.ino, child_ino,
        "A7: '.' must report the LISTED directory's own ino, not 0"
    );
    assert_eq!(
        dotdot.attr.ino, parent_ino,
        "A8: '..' must report the PARENT's true ino, not 0"
    );
    assert_eq!(
        dot.name,
        DOT.to_vec(),
        "the sink's name for the dot entry must be the true '.', never attr_for's placeholder"
    );
    assert_eq!(
        dotdot.name,
        DOT_DOT.to_vec(),
        "the sink's name for the dotdot entry must be the true '..', never attr_for's placeholder"
    );
}

#[test]
fn qa_readdirplus_propagates_a_mid_walk_failure_instead_of_swallowing_it() {
    // A20: the final `if let Some(error) = failure { return Err(error); }`
    // exit deleted. §G's own analysis says this exit is normally
    // UNREACHABLE on a successfully-constructed Snapshot -- so this
    // test does not corrupt a real manifest, it glues together an
    // InodeTable row and a Snapshot that DISAGREE with each other
    // (exactly the shape `dir_and_parent`'s other tests already use):
    // the row's recorded parent is a directory-leaf ("tree_b") that
    // decodes fine and is present in `nodes`, but was never linked
    // from the manifest root, so it is absent from the reachable
    // `dirs` index. `attr_for`'s `dir_subdirs` on that parent then
    // fails while building `..`'s Attr, MID-WALK, after `.` was
    // already offered to the sink -- exactly the partial-listing shape
    // §G's comment is about.
    let target = build_dir(&[]).expect("target builds");
    let tree_a = build_dir(&[dir(b"target", target.root)]).expect("tree_a builds");
    // Same child as `tree_a`'s "target", but a DIFFERENT directory
    // leaf (two entries instead of one), so its GrainId differs and
    // it is never reachable from `tree_a.root`.
    let tree_b = build_dir(&[dir(b"decoy", target.root), dir(b"target", target.root)])
        .expect("tree_b builds");

    let mut nodes = target.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(tree_a.nodes);
    nodes.extend(tree_b.nodes);
    let snap = Snapshot::new(
        nodes,
        tree_a.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect(
        "snapshot indexes: tree_b.root is present in `nodes` but unreachable from \
              tree_a.root, so it is absent from the `dirs` index by construction",
    );

    let mut table = InodeTable::new(tree_a.root, 1, 1);
    // Fabricate an inconsistent row: path "target", but its recorded
    // PARENT node is `tree_b.root` rather than `tree_a.root`.
    // `InodeTable::lookup` does not validate the `dir` it is given.
    let (bogus_ino, _) = table
        .lookup(vec![b"target".to_vec()], tree_b.root, NodeKind::Dir)
        .expect("lookup does not validate its dir argument");

    // `dir_and_parent` still resolves cleanly: `tree_b.root` decodes
    // fine and contains a "target" entry pointing at `target.root`,
    // which IS reachable/indexed.
    assert_eq!(
        dir_and_parent(&table, &snap, bogus_ino),
        Ok((target.root, tree_b.root))
    );

    let mut sink = CapPlusSink {
        cap: 10,
        entries: Vec::new(),
    };
    let result = list_dir_plus(&mut table, &snap, bogus_ino, 0, &mut sink);

    assert_eq!(
        sink.entries.len(),
        1,
        "'.' must have been offered before '..' fails -- this is a PARTIAL listing"
    );
    assert_eq!(sink.entries[0].name, DOT.to_vec());
    assert_eq!(
        result,
        Err(ReaderError::Inconsistent),
        "A20: a failure recorded mid-walk must propagate, not be silently reported as Ok(())"
    );
}

// ---- root cause 1: both test sinks were COUNT-capped; the real sink
// ---- is SIZE-capped, and Full is not sticky --------------------------

// fuser's own EntListBuf::push (fuser-0.18.0 src/ll/reply.rs:396-410)
// returns `true` when `buf.len() + entsize > max_size`, where entsize
// depends on the entry's NAME LENGTH. A long name can be refused while
// a shorter LATER entry still fits, so Full is NOT sticky. Both
// committed sinks were COUNT-capped, which makes Full sticky and blinds
// them to a walk that continues past a rejected entry.
struct ByteBudgetPlainSink {
    budget: usize,
    used: usize,
    entries: Vec<PlainRecord>,
}

impl DirSink for ByteBudgetPlainSink {
    fn offer(&mut self, ino: u64, kind: fuser::FileType, name: &[u8], next: u64) -> SinkOutcome {
        let cost = name.len() + 24;
        if self.used + cost > self.budget {
            return SinkOutcome::Full;
        }
        self.used += cost;
        self.entries.push(PlainRecord {
            ino,
            kind,
            name: name.to_vec(),
            next,
        });
        SinkOutcome::Added
    }
}

fn long_name_fixture() -> (Snapshot, GrainId, Vec<u8>) {
    let long = vec![b'l'; 200];
    // strict memcmp order: "aaa" < "lll..." < "z"
    let entries = [file(b"aaa"), file(&long), file(b"z")];
    let (snap, root) = snapshot(&entries);
    (snap, root, long)
}

#[test]
fn qa_plain_readdir_stops_at_a_rejected_entry_rather_than_skipping_it() {
    let (snap, root, long) = long_name_fixture();
    let table = InodeTable::new(root, 1, 1);
    // "." 25 + ".." 26 + "aaa" 27 = 78 used; the 200-byte name costs
    // 224 and cannot fit in 110, but "z" costs 25 and still would.
    let mut sink = ByteBudgetPlainSink {
        budget: 110,
        used: 0,
        entries: Vec::new(),
    };
    list_dir(&table, &snap, 1, 0, &mut sink).expect("listing succeeds");
    let names = sink
        .entries
        .iter()
        .map(|e| e.name.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![b".".to_vec(), b"..".to_vec(), b"aaa".to_vec()],
        "the walk must STOP at the rejected entry, never step past it"
    );
    assert!(
        !names.contains(&long),
        "sanity: the long entry was the rejected one"
    );
}

#[test]
fn qa_plain_readdir_resume_loses_no_entry_to_a_size_rejection() {
    let (snap, root, long) = long_name_fixture();
    let table = InodeTable::new(root, 1, 1);
    let mut collected: Vec<Vec<u8>> = Vec::new();
    let mut offset = 0_u64;
    for _ in 0..10 {
        let mut sink = ByteBudgetPlainSink {
            budget: 260,
            used: 0,
            entries: Vec::new(),
        };
        list_dir(&table, &snap, 1, offset, &mut sink).expect("listing succeeds");
        if sink.entries.is_empty() {
            break;
        }
        offset = sink.entries.last().expect("nonempty").next;
        for record in &sink.entries {
            collected.push(record.name.clone());
        }
    }
    assert_eq!(
        collected,
        vec![
            b".".to_vec(),
            b"..".to_vec(),
            b"aaa".to_vec(),
            long,
            b"z".to_vec()
        ],
        "a size-rejected entry must reappear on resume, not vanish from ls"
    );
}

// ---- the READDIRPLUS twin, and the more severe half, because
// ---- readdirplus is the only path the kernel reaches in production --

/// Models `fuser`'s `DirEntPlusList::push`, which pushes a fixed-size
/// `fuse_direntplus` header (`fuse_entry_out`, itself carrying a full
/// `fuse_attr`, followed by a `fuse_dirent`) plus the name, size-capped
/// like the plain sink above -- NOT bit-exact to fuser's wire layout
/// (that varies by target OS: macOS's `fuse_attr` carries extra
/// crtime/flags fields), only the SHAPE matters for what's under test:
/// a fixed per-entry header plus a NAME-LENGTH-dependent cost, checked
/// fresh on every entry rather than latching once full. 152 is the
/// non-macOS `fuse_direntplus` size: `fuse_entry_out` (8+8+8+8+4+4 = 40
/// header fields + an 88-byte `fuse_attr`) = 128, plus `fuse_dirent`'s
/// 24 (ino8+off8+namelen4+typ4) = 152.
const DIRENTPLUS_HEADER_COST: usize = 152;

struct ByteBudgetPlusSink {
    budget: usize,
    used: usize,
    entries: Vec<PlusRecord>,
}

impl DirPlusSink for ByteBudgetPlusSink {
    fn offer(&mut self, attr: Attr, name: &[u8], next: u64) -> SinkOutcome {
        let cost = name.len() + DIRENTPLUS_HEADER_COST;
        if self.used + cost > self.budget {
            return SinkOutcome::Full;
        }
        self.used += cost;
        self.entries.push(PlusRecord {
            attr,
            name: name.to_vec(),
            next,
        });
        SinkOutcome::Added
    }
}

#[test]
fn qa_readdirplus_stops_at_a_rejected_entry_rather_than_skipping_it() {
    // The readdirplus twin of `qa_plain_readdir_stops_at_a_rejected_entry_rather_than_skipping_it`,
    // and the more severe half --
    // readdirplus is the only path the kernel ever reaches in
    // production (trap T3: `init` requests `FUSE_DO_READDIRPLUS`, never
    // `FUSE_READDIRPLUS_AUTO`). "." 153 + ".." 154 + "aaa" 155 = 462
    // used; the 200-byte name costs 352 and cannot fit in the
    // remaining 238 of a 700 budget, but "z" costs 153 and still would
    // if the walk skipped past the rejection instead of stopping.
    let (snap, root, long) = long_name_fixture();
    let mut table = InodeTable::new(root, 1, 1);
    let mut sink = ByteBudgetPlusSink {
        budget: 700,
        used: 0,
        entries: Vec::new(),
    };
    list_dir_plus(&mut table, &snap, 1, 0, &mut sink).expect("listing succeeds");
    let names = sink
        .entries
        .iter()
        .map(|e| e.name.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![b".".to_vec(), b"..".to_vec(), b"aaa".to_vec()],
        "the walk must STOP at the rejected entry, never step past it"
    );
    assert!(
        !names.contains(&long),
        "sanity: the long entry was the rejected one"
    );
    assert_eq!(
        table.peek(&vec![long.clone()]),
        None,
        "the credit taken to build the rejected entry's Attr must be repaid"
    );
    assert_eq!(
        table.peek(&vec![b"z".to_vec()]),
        None,
        "an entry after the rejection must never even be looked up once the walk stops"
    );
}

#[test]
fn qa_readdirplus_resume_loses_no_entry_to_a_size_rejection() {
    let (snap, root, long) = long_name_fixture();
    let mut table = InodeTable::new(root, 1, 1);
    let mut collected: Vec<Vec<u8>> = Vec::new();
    let mut offset = 0_u64;
    for _ in 0..10 {
        let mut sink = ByteBudgetPlusSink {
            budget: 700,
            used: 0,
            entries: Vec::new(),
        };
        list_dir_plus(&mut table, &snap, 1, offset, &mut sink).expect("listing succeeds");
        if sink.entries.is_empty() {
            break;
        }
        offset = sink.entries.last().expect("nonempty").next;
        for record in &sink.entries {
            collected.push(record.name.clone());
        }
    }
    assert_eq!(
        collected,
        vec![
            b".".to_vec(),
            b"..".to_vec(),
            b"aaa".to_vec(),
            long,
            b"z".to_vec()
        ],
        "a size-rejected entry must reappear on resume, not vanish from ls"
    );
}
