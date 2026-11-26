// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::OverlayKind;
use granary_core::manifest::{self, DirEntry, EntryKind, FileGrains, GrainRef, SymlinkTarget};

fn path(text: &str) -> Vec<Name> {
    text.split('/')
        .map(|part| Name::new(part.as_bytes().to_vec()).unwrap())
        .collect()
}

fn entry(at: &str, kind: OverlayKind) -> OverlayEntry {
    OverlayEntry {
        path: path(at),
        inode: 0,
        kind,
        stage_id: None,
        size: 0,
        exec: false,
    }
}

fn dir(at: &str) -> OverlayEntry {
    entry(at, OverlayKind::Directory)
}

fn link(at: &str, target: &str) -> OverlayEntry {
    entry(
        at,
        OverlayKind::Symlink {
            target: SymlinkTarget::new(target.as_bytes().to_vec()).unwrap(),
        },
    )
}

fn conflict(at: &str) -> RebaseError {
    RebaseError::Conflict(RebaseConflict { path: path(at) })
}

#[derive(Default)]
struct Fixture {
    nodes: Roots,
    payloads: BTreeMap<GrainId, FileGrains>,
}

impl Fixture {
    fn file(&mut self, at: &str, bytes: &[u8]) -> OverlayEntry {
        let size = u64::try_from(bytes.len()).unwrap();
        let grains = if bytes.is_empty() {
            FileGrains::Inline(vec![])
        } else {
            FileGrains::Inline(vec![GrainRef {
                id: GrainId::of(bytes),
                unpacked_len: u32::try_from(size).unwrap(),
            }])
        };
        let content = GrainId::of(&manifest::node::file_payload(size, &grains).unwrap());
        self.payloads.insert(content, grains);
        let mut file = entry(
            at,
            OverlayKind::File {
                content: Some(content),
            },
        );
        file.size = size;
        file
    }

    fn manifest(&mut self, entries: &[OverlayEntry]) -> GrainId {
        let mut dirs: BTreeMap<Vec<Name>, Vec<DirEntry>> = BTreeMap::from([(vec![], vec![])]);
        for entry in entries {
            if matches!(entry.kind, OverlayKind::Directory) {
                dirs.insert(entry.path.clone(), vec![]);
            }
        }
        for entry in entries {
            let (name, parent) = entry.path.split_last().unwrap();
            let kind = match &entry.kind {
                OverlayKind::Directory => continue,
                OverlayKind::Symlink { target } => EntryKind::Symlink {
                    target: target.clone(),
                },
                OverlayKind::File {
                    content: Some(content),
                } => EntryKind::File {
                    exec: entry.exec,
                    size: entry.size,
                    grains: self.payloads[content].clone(),
                },
                OverlayKind::File { content: None } => {
                    panic!("fixture requires a materialized file")
                }
            };
            dirs.get_mut(parent).unwrap().push(DirEntry {
                name: name.clone(),
                kind,
            });
        }
        let mut paths: Vec<_> = dirs.keys().cloned().collect();
        paths.sort_by_key(|p| std::cmp::Reverse(p.len()));
        let mut root = None;
        for at in paths {
            let mut children = dirs.remove(&at).unwrap();
            children.sort_by(|a, b| a.name.cmp(&b.name));
            let built = manifest::build_dir(&children).unwrap();
            self.nodes.0.extend(built.nodes);
            if let Some((name, parent)) = at.split_last() {
                dirs.get_mut(parent).unwrap().push(DirEntry {
                    name: name.clone(),
                    kind: EntryKind::Dir { child: built.root },
                });
            } else {
                root = Some(built.root);
            }
        }
        root.unwrap()
    }

    fn run(&mut self, case: &Case) -> Result<Vec<OverlayEntry>, RebaseError> {
        let base = self.manifest(&case.base);
        let remote = self.manifest(&case.remote);
        merge_manifests(base, &case.local, &verified(remote), &self.nodes)
    }
}

fn verified(manifest: GrainId) -> VerifiedBase {
    let key = SigningKey::from_seed(&[9; 32]).unwrap();
    let keys = TrustedKeys::new([*key.public_key()]).unwrap();
    let mut doc = root::decode_root(&signed(1, None, 8, &key)).unwrap();
    doc.manifest_root = manifest;
    doc.sigs.clear();
    doc.sigs.push(RootSig {
        key_id: key.key_id(),
        sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
    });
    VerifiedBase::landed(
        root::encode_root(&doc).unwrap(),
        "rebase-test",
        &keys,
        &CommitWalk::new(manifest),
    )
    .unwrap()
}

struct Case {
    name: String,
    base: Vec<OverlayEntry>,
    local: Vec<OverlayEntry>,
    remote: Vec<OverlayEntry>,
    expected: Result<Vec<OverlayEntry>, RebaseError>,
}

fn case(
    name: impl Into<String>,
    base: &[OverlayEntry],
    local: &[OverlayEntry],
    remote: &[OverlayEntry],
    expected: Result<Vec<OverlayEntry>, RebaseError>,
) -> Case {
    Case {
        name: name.into(),
        base: base.to_vec(),
        local: local.to_vec(),
        remote: remote.to_vec(),
        expected,
    }
}

// Each row's expected outcome is explicit; all distinct file, directory and
// symlink values exercise the row across kind changes as well as content/chmod.
#[expect(
    clippy::too_many_lines,
    reason = "the complete per-name matrix shares one set of distinct values"
)]
fn per_name_cases(f: &mut Fixture) -> Vec<Case> {
    let file = f.file("p", b"base");
    let mut exec = file.clone();
    exec.exec = true;
    let values = [
        ("file", file),
        ("content", f.file("p", b"diff")),
        ("size", f.file("p", b"longer")),
        ("exec", exec),
        ("directory", dir("p")),
        ("symlink", link("p", "one")),
        ("target", link("p", "two")),
    ];
    let mut rows = vec![case("all absent", &[], &[], &[], Ok(vec![]))];
    for (name, value) in &values {
        let one = std::slice::from_ref(value);
        rows.push(case(
            format!("remote create {name}"),
            &[],
            &[],
            one,
            Ok(one.to_vec()),
        ));
        rows.push(case(
            format!("local create {name}"),
            &[],
            one,
            &[],
            Ok(one.to_vec()),
        ));
        rows.push(case(
            format!("unchanged {name}"),
            one,
            one,
            one,
            Ok(one.to_vec()),
        ));
        rows.push(case(
            format!("local delete {name}"),
            one,
            &[],
            one,
            Ok(vec![]),
        ));
        rows.push(case(
            format!("remote delete {name}"),
            one,
            one,
            &[],
            Ok(vec![]),
        ));
        rows.push(case(
            format!("concurrent delete {name}"),
            one,
            &[],
            &[],
            Ok(vec![]),
        ));
        for (other_name, other) in &values {
            let changed = std::slice::from_ref(other);
            let equal = name == other_name;
            rows.push(case(
                format!(
                    "{} create {name}/{other_name}",
                    if equal { "identical" } else { "conflicting" }
                ),
                &[],
                one,
                changed,
                if equal {
                    Ok(one.to_vec())
                } else {
                    Err(conflict("p"))
                },
            ));
            if name == other_name {
                continue;
            }
            rows.push(case(
                format!("remote change {name}->{other_name}"),
                one,
                one,
                changed,
                Ok(changed.to_vec()),
            ));
            rows.push(case(
                format!("local change {name}->{other_name}"),
                one,
                changed,
                one,
                Ok(changed.to_vec()),
            ));
            rows.push(case(
                format!("delete/change {name}->{other_name}"),
                one,
                &[],
                changed,
                Err(conflict("p")),
            ));
            rows.push(case(
                format!("change/delete {name}->{other_name}"),
                one,
                changed,
                &[],
                Err(conflict("p")),
            ));
            for (third_name, third) in &values {
                if name == third_name {
                    continue;
                }
                rows.push(case(
                    format!("concurrent change {name}->{other_name}/{third_name}"),
                    one,
                    changed,
                    std::slice::from_ref(third),
                    if other_name == third_name {
                        Ok(changed.to_vec())
                    } else {
                        Err(conflict("p"))
                    },
                ));
            }
        }
    }
    rows
}

#[expect(
    clippy::too_many_lines,
    reason = "symmetric ancestor and descendant cases share one tree fixture"
)]
fn ancestry_cases(f: &mut Fixture) -> Vec<Case> {
    let child = f.file("q/child", b"base");
    let modified = f.file("q/child", b"changed");
    let created = f.file("q/new", b"new");
    let base = vec![dir("q"), child.clone()];
    let mut rows = Vec::new();
    for (kind, replacement) in [
        ("file", f.file("q", b"replacement")),
        ("symlink", link("q", "target")),
    ] {
        for remote_replaces in [false, true] {
            let direction = if remote_replaces { "head" } else { "local" };
            let (local, remote) = if remote_replaces {
                (&base[..], std::slice::from_ref(&replacement))
            } else {
                (std::slice::from_ref(&replacement), &base[..])
            };
            rows.push(case(
                format!("unchanged descendant clean {direction} {kind}"),
                &base,
                local,
                remote,
                Ok(vec![replacement.clone()]),
            ));
            let changes = [
                ("created", vec![dir("q"), child.clone(), created.clone()]),
                ("modified", vec![dir("q"), modified.clone()]),
                ("type-changed", vec![dir("q"), link("q/child", "target")]),
                ("removed", vec![dir("q")]),
            ];
            for (change, other) in changes {
                let (local, remote) = if remote_replaces {
                    (&other[..], std::slice::from_ref(&replacement))
                } else {
                    (std::slice::from_ref(&replacement), &other[..])
                };
                rows.push(case(
                    format!("{direction} {kind} versus descendant {change}"),
                    &base,
                    local,
                    remote,
                    Err(conflict("q")),
                ));
            }
            // The unchanged non-directory side must not veto a one-sided
            // conversion to a directory with a newly created child.
            let (local, remote) = if remote_replaces {
                (std::slice::from_ref(&replacement), &base[..])
            } else {
                (&base[..], std::slice::from_ref(&replacement))
            };
            rows.push(case(
                format!("one-sided directory conversion {direction} {kind}"),
                std::slice::from_ref(&replacement),
                local,
                remote,
                Ok(base.clone()),
            ));
        }
    }
    rows.push(case(
        "identical directory replacement",
        &base,
        &[f.file("q", b"replacement")],
        &[f.file("q", b"replacement")],
        Ok(vec![f.file("q", b"replacement")]),
    ));
    rows.push(case(
        "identical directory deletion",
        &base,
        &[],
        &[],
        Ok(vec![]),
    ));
    rows.push(case(
        "local directory delete with unchanged descendants",
        &base,
        &[],
        &base,
        Ok(vec![]),
    ));
    rows.push(case(
        "remote directory delete with unchanged descendants",
        &base,
        &base,
        &[],
        Ok(vec![]),
    ));
    rows.push(case(
        "directory delete versus descendant create",
        &base,
        &[],
        &[dir("q"), child.clone(), created.clone()],
        Err(conflict("q")),
    ));
    rows.push(case(
        "descendant create versus directory delete",
        &base,
        &[dir("q"), child.clone(), created],
        &[],
        Err(conflict("q")),
    ));
    rows.push(case(
        "directory delete versus descendant modify",
        &base,
        &[],
        &[dir("q"), modified.clone()],
        Err(conflict("q")),
    ));
    rows.push(case(
        "descendant modify versus directory delete",
        &base,
        &[dir("q"), modified],
        &[],
        Err(conflict("q")),
    ));
    rows.push(case(
        "descendant deleted on both sides",
        &base,
        &[],
        &[dir("q")],
        Ok(vec![]),
    ));
    let a = f.file("q/a", b"a");
    let b = f.file("q/b", b"b");
    rows.push(case(
        "idempotent mkdir with disjoint children",
        &[],
        &[dir("q"), a.clone()],
        &[dir("q"), b.clone()],
        Ok(vec![dir("q"), a.clone(), b.clone()]),
    ));
    rows.push(case(
        "disjoint names under an unchanged directory",
        &[dir("q")],
        &[a.clone(), dir("q")],
        &[dir("q"), b.clone()],
        Ok(vec![dir("q"), a, b]),
    ));
    let other = f.file("qq/child", b"base");
    let changed_other = f.file("qq/child", b"changed");
    rows.push(case(
        "component boundary is not a byte prefix",
        &[dir("q"), dir("qq"), other.clone()],
        &[f.file("q", b"replacement"), dir("qq"), other],
        &[dir("q"), dir("qq"), changed_other.clone()],
        Ok(vec![f.file("q", b"replacement"), dir("qq"), changed_other]),
    ));
    let deep = f.file("q/middle/child", b"base");
    rows.push(case(
        "deeper changed descendant",
        &[dir("q"), dir("q/middle"), deep],
        &[f.file("q", b"replacement")],
        &[dir("q"), dir("q/middle"), link("q/middle/child", "target")],
        Err(conflict("q")),
    ));
    rows
}

fn rename_cases(f: &mut Fixture) -> Vec<Case> {
    let from = f.file("from", b"base");
    let to = f.file("to", b"base");
    let original = f.file("other", b"old");
    let changed = f.file("other", b"new");
    vec![
        case(
            "rename is delete plus create",
            &[from.clone(), original.clone()],
            &[to.clone(), original],
            &[from.clone(), changed.clone()],
            Ok(vec![changed, to.clone()]),
        ),
        case(
            "rename source conflicts with modify",
            std::slice::from_ref(&from),
            std::slice::from_ref(&to),
            &[f.file("from", b"changed")],
            Err(conflict("from")),
        ),
        case(
            "rename target agrees with identical create",
            std::slice::from_ref(&from),
            std::slice::from_ref(&to),
            &[from.clone(), to.clone()],
            Ok(vec![to.clone()]),
        ),
    ]
}

fn cases(f: &mut Fixture) -> Vec<Case> {
    let mut cases = per_name_cases(f);
    cases.extend(ancestry_cases(f));
    cases.extend(rename_cases(f));
    cases
}

#[test]
fn three_way_diff_all_fifteen_rows_and_ancestry_collisions() {
    let mut fixture = Fixture::default();
    let cases = cases(&mut fixture);
    assert!(!cases.is_empty(), "no named diff cases");
    eprintln!("checking {} named diff cases", cases.len());
    for row in cases {
        assert_eq!(fixture.run(&row), row.expected, "{}", row.name);
    }
}

#[test]
fn three_way_diff_refuses_every_overlapping_name_without_lww_fallback() {
    let mut fixture = Fixture::default();
    let cases = cases(&mut fixture);
    let conflicts: Vec<_> = cases.iter().filter(|row| row.expected.is_err()).collect();
    assert!(!conflicts.is_empty(), "no named conflict cases");
    eprintln!("checking {} named conflict cases", conflicts.len());
    for row in conflicts {
        assert_eq!(
            fixture.run(row),
            row.expected,
            "{}: conflict must not select a side",
            row.name
        );
    }
}

#[test]
fn three_way_diff_preserves_local_identity_without_allocating_remote_inodes() {
    let mut f = Fixture::default();
    let base = f.file("p", b"base");
    let mut local = base.clone();
    local.inode = 41;
    local.stage_id = Some(9);
    let mut changed = f.file("p", b"changed");
    changed.inode = 41;
    let added = f.file("new", b"new");
    let row = case(
        "remote modify and create",
        &[base],
        &[local],
        &[changed.clone(), added.clone()],
        Ok(vec![added, changed]),
    );
    assert_eq!(
        f.run(&row),
        row.expected,
        "remote value must retain the shared local inode and clear the stage"
    );
}

#[test]
fn three_way_diff_head_kind_change_does_not_inherit_local_inode() {
    let mut f = Fixture::default();
    let kinds = [
        ("file", f.file("p", b"base")),
        ("directory", dir("p")),
        ("symlink", link("p", "target")),
    ];
    for (base_kind, base) in &kinds {
        for (head_kind, head) in &kinds {
            if base_kind == head_kind {
                continue;
            }
            let mut local = base.clone();
            local.inode = 41;
            let row = case(
                format!("head-chosen {base_kind} to {head_kind}"),
                std::slice::from_ref(base),
                &[local],
                std::slice::from_ref(head),
                Ok(vec![head.clone()]),
            );
            assert_eq!(
                f.run(&row),
                row.expected,
                "{}: kind changes require a fresh inode",
                row.name
            );
        }
    }
}

#[test]
fn three_way_diff_refuses_unmaterialized_or_unverified_inputs() {
    let mut f = Fixture::default();
    let base = f.manifest(&[]);
    let file = f.file("p", b"base");
    let remote = f.manifest(std::slice::from_ref(&file));
    let head = verified(remote);
    let valid = (
        manifest::validate_dir_tree(&base, &|id| f.nodes.get(id).ok()),
        manifest::validate_dir_tree(&remote, &|id| f.nodes.get(id).ok()),
    );
    assert!(
        matches!(&valid, (Ok(_), Ok(_))),
        "fixture manifests must validate: {valid:?}"
    );
    let mut missing_base = Roots(f.nodes.0.clone());
    missing_base.0.remove(&base);
    let mut missing_head = Roots(f.nodes.0.clone());
    missing_head.0.remove(&remote);
    let mut corrupt = Roots(f.nodes.0.clone());
    corrupt.0.insert(base, b"wrong bytes".to_vec());
    for (row, source) in [
        ("missing base", missing_base),
        ("missing head", missing_head),
        ("wrong hash", corrupt),
    ] {
        assert_eq!(
            merge_manifests(base, &[], &head, &source),
            Err(RebaseError::InvalidManifest),
            "{row}"
        );
    }
    let bad = b"not a manifest".to_vec();
    let bad_id = GrainId::of(&bad);
    f.nodes.0.insert(bad_id, bad);
    assert_eq!(
        merge_manifests(bad_id, &[], &head, &f.nodes),
        Err(RebaseError::InvalidManifest),
        "hash-correct malformed node"
    );
    let mut empty_path = file.clone();
    empty_path.path.clear();
    let locals = [
        (
            "unresolved file",
            vec![entry("p", OverlayKind::File { content: None })],
        ),
        ("duplicate name", vec![file.clone(), file.clone()]),
        ("missing parent", vec![f.file("missing/child", b"x")]),
        (
            "non-directory parent",
            vec![file.clone(), f.file("p/child", b"x")],
        ),
        ("empty path", vec![empty_path]),
    ];
    for (row, local) in locals {
        assert_eq!(
            merge_manifests(base, &local, &head, &f.nodes),
            Err(RebaseError::InvalidManifest),
            "{row}"
        );
    }
    for kind in [EntryKind::Fifo, EntryKind::Socket] {
        let tree = manifest::build_dir(&[DirEntry {
            name: Name::new(b"reserved".to_vec()).unwrap(),
            kind,
        }])
        .unwrap();
        f.nodes.0.extend(tree.nodes);
        assert_eq!(
            merge_manifests(tree.root, &[], &head, &f.nodes),
            Err(RebaseError::InvalidManifest),
            "reserved kind"
        );
    }
    assert_eq!(
        merge_manifests(base, &[], &head, &f.nodes),
        Ok(vec![file]),
        "valid fixture"
    );
}

#[test]
fn three_way_diff_uses_the_validated_copy_when_the_source_changes() {
    struct Once {
        nodes: Roots,
        reads: std::sync::Mutex<BTreeMap<GrainId, usize>>,
    }
    impl GrainSource for Once {
        fn has(&self, id: &GrainId) -> bool {
            self.nodes.has(id)
        }
        fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
            let mut reads = self.reads.lock().unwrap();
            let count = reads.entry(*id).or_default();
            *count += 1;
            if *count == 1 {
                self.nodes.get(id)
            } else {
                Err(GrainSourceError::Corrupt(*id))
            }
        }
    }
    let mut f = Fixture::default();
    let base = f.manifest(&[]);
    let remote = f.file("q/child", b"base");
    let expected = vec![dir("q"), remote];
    let root = f.manifest(&expected);
    let source = Once {
        nodes: f.nodes,
        reads: std::sync::Mutex::default(),
    };
    let result = merge_manifests(base, &[], &verified(root), &source);
    let reads = source.reads.into_inner().unwrap();
    let expected_reads = source
        .nodes
        .0
        .keys()
        .map(|id| (*id, 1))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        (result, reads),
        (Ok(expected), expected_reads),
        "merge must use the exact validated nodes"
    );
}

#[test]
fn recovered_directory_deletion_requires_the_entire_selected_subtree() {
    let mut f = Fixture::default();
    let file = f.file("d/x", b"carried");
    let selected = vec![dir("d"), file];
    let ancestor = f.manifest(&selected);
    let head = f.manifest(&[]);
    assert_eq!(
        preserve_recovered_deletions(&selected, head, &[ancestor], &f.nodes),
        Ok(vec![])
    );
    let edited = vec![dir("d"), f.file("d/x", b"acknowledged later")];
    assert_eq!(
        preserve_recovered_deletions(&edited, head, &[ancestor], &f.nodes),
        Ok(edited)
    );
    let extended = vec![dir("d"), selected[1].clone(), f.file("d/y", b"novel")];
    assert_eq!(
        preserve_recovered_deletions(&extended, head, &[ancestor], &f.nodes),
        Ok(vec![dir("d"), extended[2].clone()])
    );
}
