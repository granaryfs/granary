// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::overlay_store::OverlayEntry;
use granary_core::hash::GrainId;
use granary_core::manifest::SymlinkTarget;
use granary_core::overlay_journal::{BindCause, CreateKind, DeleteKind, Location, Parent};

fn names(p: &str) -> Vec<Name> {
    p.split('/')
        .filter(|n| !n.is_empty())
        .map(|n| Name::new(n.as_bytes().to_vec()).unwrap())
        .collect()
}

#[test]
fn inode_installation_allocates_new_identities_for_kind_changes_and_remote_paths() {
    let entry = |path: &str, kind| OverlayEntry {
        path: names(path),
        inode: 0,
        kind,
        stage_id: None,
        size: 0,
        exec: false,
    };
    let file = OverlayKind::File {
        content: Some(GrainId::of(b"payload")),
    };
    let old = Namespace::base(&[
        entry("changed", OverlayKind::Directory),
        entry("shared", file.clone()),
    ])
    .unwrap();
    let next = old.next_inode;
    let mut landed = Namespace::base(&[
        entry("changed", file.clone()),
        entry("remote", file.clone()),
        entry("shared", file),
    ])
    .unwrap();
    landed.preserve_inodes(&old, &BTreeMap::new()).unwrap();
    assert_eq!(
        (
            landed.entries[&names("changed")].inode,
            landed.entries[&names("remote")].inode,
            landed.entries[&names("shared")].inode,
            landed.next_inode
        ),
        (
            next,
            next + 1,
            old.entries[&names("shared")].inode,
            next + 2
        )
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one old view, new view and capture cover every identity arm as one tuple"
)]
fn identity_preservation_gives_a_changed_identity_a_fresh_inode() {
    let file = |path: &str, content: &[u8], exec| OverlayEntry {
        path: names(path),
        inode: 0,
        kind: OverlayKind::File {
            content: Some(GrainId::of(content)),
        },
        stage_id: None,
        size: 1,
        exec,
    };
    let link = |path: &str, target: &[u8]| OverlayEntry {
        kind: OverlayKind::Symlink {
            target: SymlinkTarget::new(target.to_vec()).unwrap(),
        },
        ..file(path, b"", false)
    };
    let dir = |path: &str| OverlayEntry {
        kind: OverlayKind::Directory,
        ..file(path, b"", false)
    };
    let bind = |ns: &mut Namespace, path: &str, stage_id, content: &[u8]| {
        ns.fold(&Record::StageBind {
            at: at(path),
            cause: BindCause::CopyUp,
            stage_id,
            staged_size: 1,
            base_content: GrainId::of(content),
        })
        .unwrap();
    };
    let mut old = Namespace::base(&[
        file("same", b"a", false),
        file("changed", b"x", false),
        file("exec", b"e", false),
        link("link", b"a"),
        file("dirty", b"d0", false),
        file("closed", b"c0", false),
        file("renamed", b"r0", false),
        file("chmodded", b"m0", true),
        file("net_zero", b"n0", false),
        dir("d"),
        file("d/c", b"dc0", false),
    ])
    .unwrap();
    for (path, stage, content) in [
        ("dirty", 1, b"d0"),
        ("closed", 2, b"c0"),
        ("renamed", 3, b"r0"),
        ("chmodded", 4, b"m0"),
        ("net_zero", 5, b"n0"),
    ] {
        bind(&mut old, path, stage, content);
    }
    let mut new = Namespace::base(&[
        file("same", b"a", false),
        file("changed", b"y", false),
        file("exec", b"e", true),
        link("link", b"b"),
        file("dirty", b"d1", false),
        file("closed", b"c1", false),
        file("renamed", b"r1", false),
        file("chmodded", b"m1", true),
        file("net_zero", b"head", false),
        dir("d"),
        file("d/c", b"dc1", false),
    ])
    .unwrap();
    bind(&mut new, "dirty", 1, b"d1");
    // Each captured entry carries its capture-time inode. `renamed` was
    // captured at another path, and `chmodded` before its exec change.
    let inode = |path: &str| old.entries[&names(path)].inode;
    let captured = [
        OverlayEntry {
            inode: inode("closed"),
            ..file("closed", b"c1", false)
        },
        OverlayEntry {
            inode: inode("renamed"),
            ..file("renamed_from", b"r1", false)
        },
        OverlayEntry {
            inode: inode("chmodded"),
            ..file("chmodded", b"m1", false)
        },
        OverlayEntry {
            inode: inode("net_zero"),
            ..file("net_zero", b"n0", false)
        },
    ];
    let index = captured.iter().map(|e| (e.inode, e)).collect();
    let next = old.next_inode;
    let change = new.preserve_inodes(&old, &index).unwrap();
    let kept = ["same", "dirty", "closed", "renamed", "chmodded", "d"];
    let fresh = ["changed", "d/c", "exec", "link", "net_zero"];
    let actual = |paths: &[&str]| {
        paths
            .iter()
            .map(|p| new.entries[&names(p)].inode)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        (
            actual(&kept),
            actual(&fresh),
            change
                .paths
                .iter()
                .map(|c| (c.path.clone(), c.old, c.new))
                .collect::<Vec<_>>(),
            change.retired.keys().copied().collect::<Vec<_>>(),
            new.check_indexes(),
        ),
        (
            kept.iter().map(|p| inode(p)).collect(),
            (next..next + 5).collect(),
            fresh
                .iter()
                .zip(next..)
                .map(|(p, n)| (names(p), Some(inode(p)), Some(n)))
                .collect(),
            {
                let mut retired: Vec<_> = fresh.iter().map(|p| inode(p)).collect();
                retired.sort_unstable();
                retired
            },
            Ok(()),
        )
    );
}

fn at(p: &str) -> Location {
    let mut p = names(p);
    let name = p.pop().unwrap();
    Location {
        parent: Parent::new(p).unwrap(),
        name,
    }
}

fn create(p: &str, kind: CreateKind) -> Record {
    Record::Create { at: at(p), kind }
}

fn fixture() -> Namespace {
    Namespace::base(&[
        OverlayEntry {
            path: names("d"),
            inode: 0,
            kind: OverlayKind::Directory,
            stage_id: None,
            size: 0,
            exec: false,
        },
        OverlayEntry {
            path: names("d/f"),
            inode: 0,
            kind: OverlayKind::File {
                content: Some(GrainId::of(b"body")),
            },
            stage_id: None,
            size: 4,
            exec: false,
        },
        OverlayEntry {
            path: names("empty"),
            inode: 0,
            kind: OverlayKind::Directory,
            stage_id: None,
            size: 0,
            exec: false,
        },
    ])
    .unwrap()
}

#[test]
fn independent_oracle_names_missing_and_stale_children() {
    let ns = fixture();
    assert_eq!((ns.entries.len(), ns.check_indexes()), (3, Ok(())));
    let mut missing = ns.clone();
    missing
        .parents
        .get_mut(&names("d"))
        .unwrap()
        .children
        .remove(&Name::new(b"f".to_vec()).unwrap());
    assert_eq!(
        (missing.entries.len(), missing.check_indexes()),
        (3, Err("missing-child mismatch"))
    );
    let mut stale = ns;
    stale
        .parents
        .get_mut(&names("d"))
        .unwrap()
        .children
        .insert(Name::new(b"ghost".to_vec()).unwrap(), names("d/ghost"));
    assert_eq!(
        (stale.entries.len(), stale.check_indexes()),
        (3, Err("stale-child mismatch"))
    );
}

fn create_control(record: &Record, directory: bool) -> usize {
    let mut valid = fixture();
    let before = Transition::capture(&valid, record).unwrap();
    valid.fold_record(record).unwrap();
    before.validate(&valid).unwrap();
    assert_eq!(
        (
            valid.entries.len(),
            valid.parents[&names("d")].subdirectories
        ),
        (4, u32::from(directory))
    );
    let mut bad = fixture();
    let before = Transition::capture(&bad, record).unwrap();
    bad.fold_record(record).unwrap();
    let bucket = bad.parents.get_mut(&names("d")).unwrap();
    if directory {
        bucket.children.remove(&Name::new(b"sub".to_vec()).unwrap());
    } else {
        bucket.subdirectories += 1;
    }
    assert_eq!(
        (
            before.validate(&bad).err().map(|e| e.to_string()),
            bad.entries.len()
        ),
        (Some("overlay persistence poisoned".into()), 4)
    );
    1
}

#[test]
fn affected_publication_checks_refuse_omitted_directory_membership() {
    assert_eq!(create_control(&create("d/sub", CreateKind::Dir), true), 1);
}

#[test]
fn affected_publication_checks_refuse_erroneous_file_count() {
    assert_eq!(
        create_control(
            &create(
                "d/file",
                CreateKind::File {
                    exec: false,
                    stage_id: 1
                }
            ),
            false
        ),
        1
    );
}

#[test]
fn affected_publication_checks_refuse_erroneous_file_count_after_a_named_recreate() {
    let record = Record::RecreateFile {
        at: Some(at("d/file")),
        exec: false,
        stage_id: 1,
        anchor: None,
    };
    assert_eq!(create_control(&record, false), 1);
}

#[test]
fn affected_publication_checks_refuse_stale_delete_and_rmdir_associations() {
    let mut cases = 0;
    for (path, kind) in [
        ("d/f", DeleteKind::File { stage_id: None }),
        ("empty", DeleteKind::Dir),
    ] {
        for inverse in [true, false] {
            let mut valid = fixture();
            let record = Record::Delete {
                at: at(path),
                kind: kind.clone(),
            };
            let before = Transition::capture(&valid, &record).unwrap();
            let inode = valid.entries[&names(path)].inode;
            valid.fold_record(&record).unwrap();
            before.validate(&valid).unwrap();
            assert_eq!(
                (
                    valid.entries.len(),
                    valid.inverse.contains_key(&inode),
                    valid.check_indexes()
                ),
                (2, false, Ok(()))
            );
            let mut bad = fixture();
            let before = Transition::capture(&bad, &record).unwrap();
            bad.fold_record(&record).unwrap();
            if inverse {
                bad.inverse.insert(inode, names(path));
            } else {
                let (name, parent) = names(path)
                    .split_last()
                    .map(|(n, p)| (n.clone(), p.to_vec()))
                    .unwrap();
                bad.parents
                    .get_mut(&parent)
                    .unwrap()
                    .children
                    .insert(name, names(path));
            }
            assert_eq!(
                (
                    before.validate(&bad).err().map(|e| e.to_string()),
                    bad.entries.len()
                ),
                (Some("overlay persistence poisoned".into()), 2),
                "path={path}, inverse={inverse}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

#[test]
fn affected_publication_checks_refuse_stale_rename_and_replace_associations() {
    let mut cases = 0;
    for record in [
        Record::Move {
            from: at("d"),
            to: at("moved"),
        },
        Record::Replace {
            from: at("d"),
            to: at("empty"),
        },
    ] {
        for inverse in [true, false] {
            let mut valid = fixture();
            let before = Transition::capture(&valid, &record).unwrap();
            let inode = valid.entries[&names("d")].inode;
            valid.fold_record(&record).unwrap();
            before.validate(&valid).unwrap();
            assert_eq!(
                (
                    valid.entries.contains_key(&names("d")),
                    valid.check_indexes()
                ),
                (false, Ok(()))
            );
            let mut bad = fixture();
            let before = Transition::capture(&bad, &record).unwrap();
            bad.fold_record(&record).unwrap();
            if inverse {
                bad.inverse.insert(inode, names("d"));
            } else {
                bad.parents
                    .get_mut(&Vec::new())
                    .unwrap()
                    .children
                    .insert(Name::new(b"d".to_vec()).unwrap(), names("d"));
            }
            assert_eq!(
                (
                    before.validate(&bad).err().map(|e| e.to_string()),
                    bad.entries.len()
                ),
                (
                    Some("overlay persistence poisoned".into()),
                    if matches!(record, Record::Move { .. }) {
                        3
                    } else {
                        2
                    }
                ),
                "record={record:?}, inverse={inverse}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

#[test]
fn identity_preservation_rebuilds_from_assigned_primary_inodes() {
    let old = fixture();
    let mut new = Namespace::base(&[
        old.entries[&names("empty")].clone(),
        old.entries[&names("d")].clone(),
        old.entries[&names("d/f")].clone(),
    ])
    .unwrap();
    let changed = new
        .entries
        .iter()
        .filter(|(p, e)| e.inode != old.entries[*p].inode)
        .count();
    assert!(
        changed > 0,
        "changed IDs={changed}, old={:?}, new={:?}",
        old.entries,
        new.entries
    );
    new.preserve_inodes(&old, &BTreeMap::new()).unwrap();
    assert_eq!(
        (new.check_indexes(), new.inverse.clone()),
        (Ok(()), old.inverse.clone())
    );
    new.inverse.clear();
    assert_eq!(
        (new.entries.len(), new.check_indexes()),
        (3, Err("inverse association mismatch"))
    );
}

#[test]
fn assigned_inode_keeps_inverse_unique_and_future_allocation_above_it() {
    let mut ns = fixture();
    ns.assign_inode(&names("d"), 30).unwrap();
    ns.fold(&create("new", CreateKind::Dir)).unwrap();
    assert_eq!(
        (ns.entries[&names("new")].inode, ns.check_indexes()),
        (31, Ok(()))
    );
    let old = ns.inverse.clone();
    let refused = ns
        .assign_inode(&names("empty"), 30)
        .err()
        .is_some_and(|e| matches!(e, OverlayError::Poisoned));
    assert_eq!(
        (refused, ns.inverse.clone(), ns.check_indexes()),
        (true, old, Ok(()))
    );
}

#[test]
fn base_admission_assigns_every_inverse_and_parent_association() {
    let ns = fixture();
    assert_eq!(
        (
            ns.entries.len(),
            ns.inverse.len(),
            ns.parents.len(),
            ns.check_indexes()
        ),
        (3, 3, 3, Ok(()))
    );
}

#[test]
fn projection_base_restores_permuted_inodes_and_rejects_duplicates() {
    let ns = fixture();
    let mut entries: Vec<_> = ns.entries.values().cloned().collect();
    for (entry, inode) in entries.iter_mut().zip([3, 2, 1]) {
        entry.inode = inode;
    }
    let restored = Namespace::base_with_inodes(&entries).unwrap();
    assert_eq!(
        (
            restored.check_indexes(),
            restored
                .entries
                .values()
                .map(|e| e.inode)
                .collect::<Vec<_>>()
        ),
        (Ok(()), vec![3, 2, 1])
    );
    for entry in &mut entries {
        entry.inode = 1;
    }
    assert_eq!(
        (
            entries.len(),
            Namespace::base_with_inodes(&entries)
                .err()
                .is_some_and(|e| matches!(e, OverlayError::Poisoned))
        ),
        (3, true)
    );
}

#[test]
fn storage_clone_counts_inverse_buckets_memberships_and_path_bytes() {
    let ns = fixture();
    super::super::CLONED_ENTRIES.set(0);
    super::super::CLONED_INDEX_ROWS.set((0, 0, 0, 0));
    let cloned = ns.clone();
    assert_eq!(
        (
            super::super::CLONED_ENTRIES.get(),
            super::super::CLONED_INDEX_ROWS.get(),
            cloned.check_indexes()
        ),
        (3, (3, 3, 3, 45), Ok(()))
    );
}

#[test]
fn index_updates_refuse_duplicate_identity_missing_parent_and_count_overflow() {
    let record = create("new", CreateKind::Dir);
    let mut valid = fixture();
    valid.fold_record(&record).unwrap();
    assert_eq!((valid.entries.len(), valid.check_indexes()), (4, Ok(())));
    let mut cases = 0;
    for fault in 0..4 {
        let mut bad = fixture();
        match fault {
            0 => bad.next_inode = bad.entries[&names("d")].inode,
            1 => {
                bad.parents.remove(&Vec::new());
            }
            2 => bad.parents.get_mut(&Vec::new()).unwrap().subdirectories = u32::MAX,
            _ => bad.parents.get_mut(&Vec::new()).unwrap().subdirectories = u32::MAX - 2,
        }
        assert_eq!(
            bad.fold_record(&record).err().map(|e| e.to_string()),
            Some("overlay persistence poisoned".into()),
            "fault={fault}"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn index_removal_refuses_wrong_inverse_wrong_member_and_nonempty_bucket() {
    let record = Record::Delete {
        at: at("empty"),
        kind: DeleteKind::Dir,
    };
    let mut valid = fixture();
    valid.fold_record(&record).unwrap();
    assert_eq!((valid.entries.len(), valid.check_indexes()), (2, Ok(())));
    let mut cases = 0;
    for fault in 0..4 {
        let mut bad = fixture();
        let inode = bad.entries[&names("empty")].inode;
        match fault {
            0 => {
                bad.inverse.insert(inode, names("d"));
            }
            1 => {
                bad.parents
                    .get_mut(&Vec::new())
                    .unwrap()
                    .children
                    .insert(Name::new(b"empty".to_vec()).unwrap(), names("d"));
            }
            2 => bad.parents.get_mut(&Vec::new()).unwrap().subdirectories = 0,
            _ => {
                bad.parents
                    .get_mut(&names("empty"))
                    .unwrap()
                    .children
                    .insert(Name::new(b"ghost".to_vec()).unwrap(), names("empty/ghost"));
            }
        }
        assert_eq!(
            bad.fold_record(&record).err().map(|e| e.to_string()),
            Some("overlay persistence poisoned".into()),
            "fault={fault}"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn seeded_mutations_match_primary_oracle_and_preserve_file_count_invariance() {
    use granary_core::rng::{Rng as _, SeededRng};
    let mut cases = [0; 5];
    for seed in 1..=4 {
        let mut ns = Namespace::base(&[]).unwrap();
        let mut rng = SeededRng::new(seed);
        for i in 0..32 {
            let path = format!("entry{i}");
            let kind = match rng.below(3) {
                0 => CreateKind::Dir,
                1 => CreateKind::File {
                    stage_id: i + 1,
                    exec: false,
                },
                _ => CreateKind::Symlink {
                    target: SymlinkTarget::new(b"target".to_vec()).unwrap(),
                },
            };
            let count = ns.parents[&Vec::new()].subdirectories;
            let dir = matches!(kind, CreateKind::Dir);
            ns.fold(&create(&path, kind)).unwrap();
            assert_eq!(
                (ns.check_indexes(), ns.parents[&Vec::new()].subdirectories),
                (Ok(()), count + u32::from(dir))
            );
            cases[0] += 1;
            let to = format!("renamed{i}");
            ns.fold(&Record::Move {
                from: at(&path),
                to: at(&to),
            })
            .unwrap();
            assert_eq!(ns.check_indexes(), Ok(()));
            cases[1] += 1;
            if let Some(id) = ns.entries[&names(&to)].stage_id {
                for record in [
                    Record::Truncate {
                        stage_id: id,
                        new_size: 3,
                    },
                    Record::SetattrExec {
                        at: at(&to),
                        exec: true,
                    },
                ] {
                    ns.fold(&record).unwrap();
                    assert_eq!(
                        (ns.check_indexes(), ns.parents[&Vec::new()].subdirectories),
                        (Ok(()), count)
                    );
                    cases[2] += 1;
                }
            }
            let entry = &ns.entries[&names(&to)];
            let kind = match entry.kind {
                OverlayKind::Directory => DeleteKind::Dir,
                OverlayKind::File { .. } => DeleteKind::File {
                    stage_id: entry.stage_id,
                },
                OverlayKind::Symlink { .. } => DeleteKind::Symlink,
            };
            ns.fold(&Record::Delete { at: at(&to), kind }).unwrap();
            assert_eq!(
                (
                    ns.entries.len(),
                    ns.check_indexes(),
                    ns.parents[&Vec::new()].subdirectories
                ),
                (0, Ok(()), count)
            );
            cases[3] += 1;
            assert!(
                ns.fold(&Record::Delete {
                    at: at(&to),
                    kind: DeleteKind::Dir
                })
                .is_err()
            );
            assert_eq!(ns.check_indexes(), Ok(()));
            cases[4] += 1;
        }
    }
    assert!(cases.into_iter().all(|n| n > 0), "coverage={cases:?}");
}

// A namespace clone belongs to storage work even when a callback encloses it.
#[test]
fn storage_clone_does_not_charge_query_entry_copies() {
    let ns = fixture();
    assert_eq!(
        ns.entries.len(),
        3,
        "primary cardinality: {}",
        ns.entries.len()
    );
    super::super::CLONED_ENTRIES.set(0);
    super::super::CLONED_INDEX_ROWS.set((0, 0, 0, 0));
    let (cloned, query) = crate::overlay_store::measure_query(|| ns.clone());
    assert_eq!(
        (
            query,
            super::super::CLONED_ENTRIES.get(),
            super::super::CLONED_INDEX_ROWS.get()
        ),
        ((0, 0, 0), 3, (3, 3, 3, 45)),
        "query and complete storage clone accounting"
    );
    assert_eq!((cloned.entries.len(), cloned.check_indexes()), (3, Ok(())));
}

fn storage_accounting_verdict(
    actual: crate::overlay_store::work::StorageWork,
    expected: crate::overlay_store::work::StorageWork,
) -> Result<(), &'static str> {
    if actual == expected {
        Ok(())
    } else {
        Err("storage clone accounting mismatch")
    }
}

#[test]
fn storage_clone_accounts_every_map_and_rejects_omitted_charges() {
    use crate::overlay_store::work::{self, QueryWork, StorageWork};
    let ns = fixture();
    assert_eq!(
        ns.entries.len(),
        3,
        "primary cardinality: {}",
        ns.entries.len()
    );
    let (cloned, query, actual) = work::measure(|| ns.clone());
    let expected = StorageWork {
        namespace_clones: 1,
        entry_copies: 3,
        primary_rows: 3,
        inverse_rows: 3,
        parent_buckets: 3,
        parent_memberships: 3,
        parent_counts: 3,
        path_bytes: 45,
        primary_visits: 0,
    };
    assert_eq!(
        (query, actual, storage_accounting_verdict(actual, expected)),
        (QueryWork::default(), expected, Ok(())),
        "query and complete storage clone accounting"
    );
    assert_eq!((cloned.entries.len(), cloned.check_indexes()), (3, Ok(())));
    let mut cases = 0;
    for charge in [
        "primary",
        "inverse",
        "buckets",
        "memberships",
        "counts",
        "paths",
    ] {
        let mut omitted = actual;
        match charge {
            "primary" => omitted.primary_rows = 0,
            "inverse" => omitted.inverse_rows = 0,
            "buckets" => omitted.parent_buckets = 0,
            "memberships" => omitted.parent_memberships = 0,
            "counts" => omitted.parent_counts = 0,
            "paths" => omitted.path_bytes = 0,
            _ => unreachable!(),
        }
        assert_eq!(
            (
                storage_accounting_verdict(actual, expected),
                storage_accounting_verdict(omitted, expected)
            ),
            (Ok(()), Err("storage clone accounting mismatch")),
            "omitted {charge}: actual={actual:?}, malformed={omitted:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 6, "accounting paired-control cases: {cases}");
}

#[test]
fn nested_measurement_keeps_storage_work_in_enclosing_account() {
    use crate::overlay_store::work;
    let ns = fixture();
    assert_eq!(
        ns.entries.len(),
        3,
        "primary cardinality: {}",
        ns.entries.len()
    );
    let mut cases = 0;
    for nested in [false, true] {
        let ((cloned, inner), query, outer) = work::measure(|| {
            if nested {
                let (cloned, _, inner) = work::measure(|| ns.clone());
                (cloned, Some(inner))
            } else {
                (ns.clone(), None)
            }
        });
        assert_eq!(
            (
                query,
                outer.namespace_clones,
                outer.primary_rows,
                outer.entry_copies,
                inner.map(|work| (work.namespace_clones, work.primary_rows, work.entry_copies))
            ),
            (
                work::QueryWork::default(),
                1,
                3,
                3,
                nested.then_some((1, 3, 3))
            ),
            "nested={nested}, enclosing storage work={outer:?}"
        );
        assert_eq!((cloned.entries.len(), cloned.check_indexes()), (3, Ok(())));
        cases += 1;
    }
    assert_eq!(cases, 2, "nested accounting control cases: {cases}");
}

#[test]
fn storage_clone_counts_attached_stage_paths_without_charging_detached_paths() {
    use crate::overlay_store::work;
    let mut cases = 0;
    for attached in [true, false] {
        let mut ns = fixture();
        ns.fold_record(&create(
            "new",
            CreateKind::File {
                stage_id: 1,
                exec: false,
            },
        ))
        .unwrap();
        if !attached {
            ns.fold_record(&Record::Delete {
                at: at("new"),
                kind: DeleteKind::File { stage_id: Some(1) },
            })
            .unwrap();
        }
        assert_eq!((ns.stages.len(), ns.check_indexes()), (1, Ok(())));
        let (cloned, query, storage) = work::measure(|| ns.clone());
        let rows = if attached { 4 } else { 3 };
        let expected = work::StorageWork {
            namespace_clones: 1,
            entry_copies: rows,
            primary_rows: rows,
            inverse_rows: rows,
            parent_buckets: 3,
            parent_memberships: rows,
            parent_counts: 3,
            path_bytes: if attached { 63 } else { 45 },
            primary_visits: 0,
        };
        let mut omitted = storage;
        omitted.path_bytes = 0;
        assert_eq!(
            (
                query,
                storage,
                storage_accounting_verdict(storage, expected),
                storage_accounting_verdict(omitted, expected)
            ),
            (
                work::QueryWork::default(),
                expected,
                Ok(()),
                Err("storage clone accounting mismatch")
            ),
            "attached={attached}, primary cardinality={}, stage cardinality={}",
            ns.entries.len(),
            ns.stages.len()
        );
        assert_eq!(
            (cloned.entries.len(), cloned.check_indexes()),
            (rows, Ok(()))
        );
        cases += 1;
    }
    assert_eq!(cases, 2, "stage-path paired-control cases: {cases}");
}

fn no_primary_scan(work: crate::overlay_store::work::QueryWork) -> Result<(), &'static str> {
    if work.primary_visits == 0 {
        Ok(())
    } else {
        Err("query iterated the primary map")
    }
}

#[test]
fn borrowed_primary_scan_is_visible_without_entry_copies() {
    let ns = fixture();
    let cardinality = ns.entries.len();
    assert_eq!(
        cardinality, 3,
        "borrowed-scan fixture cardinality: {cardinality}"
    );
    let absent = names("missing");
    let (valid, valid_work, _) = crate::overlay_store::work::measure(|| ns.entries.get(&absent));
    let (malformed, scanned, _) = crate::overlay_store::work::measure(|| {
        ns.entries.values().find(|entry| entry.path == absent)
    });
    assert_eq!(
        (
            valid.is_none(),
            malformed.is_none(),
            (
                valid_work.namespace_copies,
                valid_work.primary_visits,
                valid_work.entry_copies
            ),
            (
                scanned.namespace_copies,
                scanned.primary_visits,
                scanned.entry_copies
            ),
            no_primary_scan(valid_work),
            no_primary_scan(scanned),
        ),
        (
            true,
            true,
            (0, 0, 0),
            (0, 3, 0),
            Ok(()),
            Err("query iterated the primary map")
        ),
        "a borrowed missing-key scan must fail the same work bound as a copied scan"
    );
}

#[test]
fn borrowed_primary_iterator_routes_count_yielded_rows() {
    let mut ns = fixture();
    let cardinality = ns.entries.len();
    assert_eq!(
        cardinality, 3,
        "iterator fixture cardinality: {cardinality}"
    );
    let absent = names("missing");
    let mut cases = 0;
    for route in [
        "iter",
        "keys",
        "range",
        "reverse",
        "iter_mut",
        "values_mut",
        "for",
    ] {
        let (missing, scanned, _) = crate::overlay_store::work::measure(|| match route {
            "iter" => ns
                .entries
                .iter()
                .find(|(path, _)| *path == &absent)
                .is_none(),
            "keys" => ns.entries.keys().find(|path| *path == &absent).is_none(),
            "range" => ns
                .entries
                .range::<Vec<Name>, _>(..)
                .find(|(path, _)| *path == &absent)
                .is_none(),
            "reverse" => ns
                .entries
                .values()
                .rev()
                .find(|entry| entry.path == absent)
                .is_none(),
            "iter_mut" => ns
                .entries
                .iter_mut()
                .find(|(path, _)| *path == &absent)
                .is_none(),
            "values_mut" => ns
                .entries
                .values_mut()
                .find(|entry| entry.path == absent)
                .is_none(),
            _ => {
                let mut missing = true;
                for (path, _) in &ns.entries {
                    missing &= path != &absent;
                }
                missing
            }
        });
        let (found, valid, _) = crate::overlay_store::work::measure(|| ns.entries.get(&names("d")));
        assert_eq!(
            (
                missing,
                found.is_some(),
                scanned.namespace_copies,
                scanned.primary_visits,
                scanned.entry_copies,
                no_primary_scan(valid),
                no_primary_scan(scanned)
            ),
            (
                true,
                true,
                0,
                3,
                0,
                Ok(()),
                Err("query iterated the primary map")
            ),
            "borrowed iterator route={route}, measured={scanned:?}"
        );
        cases += 1;
    }
    assert_eq!(
        cases, 7,
        "nonempty borrowed iterator paired controls: {cases}"
    );
}

#[test]
fn borrowed_primary_iterator_steps_count_consumed_rows() {
    let ns = fixture();
    let cardinality = ns.entries.len();
    assert_eq!(
        cardinality, 3,
        "iterator fixture cardinality: {cardinality}"
    );
    let mut cases = 0;
    for reverse in [false, true] {
        let (_, scanned, _) = crate::overlay_store::work::measure(|| {
            let mut rows = ns.entries.values();
            if reverse {
                (rows.next(), rows.next_back())
            } else {
                (rows.nth(2), None)
            }
        });
        let (_, valid, _) = crate::overlay_store::work::measure(|| ns.entries.get(&names("d")));
        assert_eq!(
            (
                scanned.namespace_copies,
                scanned.primary_visits,
                scanned.entry_copies,
                no_primary_scan(valid),
                no_primary_scan(scanned)
            ),
            (
                0,
                if reverse { 2 } else { 3 },
                0,
                Ok(()),
                Err("query iterated the primary map")
            ),
            "reverse={reverse}, measured={scanned:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2, "nonempty iterator step paired controls: {cases}");
}
