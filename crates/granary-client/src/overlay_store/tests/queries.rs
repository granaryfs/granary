// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::overlay_store::{OverlayQuery, OverlayQueryEntry};
use crate::overlay_store::{OverlayReadiness, measure_query};

mod scale;

fn found<T: std::fmt::Debug>(answer: OverlayQuery<T>) -> T {
    match answer {
        OverlayQuery::Found(value) => value,
        actual => panic!("expected a found query, got {actual:?}"),
    }
}

fn entry(path: Vec<Name>, kind: OverlayKind) -> OverlayEntry {
    OverlayEntry {
        path,
        inode: 0,
        kind,
        stage_id: None,
        size: 7,
        exec: false,
    }
}

fn fixture(children: usize, unrelated: usize) -> Fixture {
    let mut base = vec![
        entry(vec![name("d")], OverlayKind::Directory),
        entry(vec![name("empty")], OverlayKind::Directory),
        entry(
            vec![name("a")],
            OverlayKind::File {
                content: Some(grain(1)),
            },
        ),
        entry(
            vec![name("b")],
            OverlayKind::File {
                content: Some(grain(2)),
            },
        ),
    ];
    for i in 0..children {
        base.push(entry(
            vec![name("d"), name(&format!("child-{i:04}"))],
            if i % 7 == 0 {
                OverlayKind::Directory
            } else {
                OverlayKind::File {
                    content: Some(grain(1)),
                }
            },
        ));
    }
    for i in 0..unrelated {
        base.push(entry(
            vec![name(&format!("unrelated-{i:04}"))],
            OverlayKind::File {
                content: Some(grain(2)),
            },
        ));
    }
    Fixture::with_base(base, Source::default())
}

fn oracle_nlink(f: &Fixture, path: &[Name]) -> u32 {
    let directory = path.is_empty()
        || f.overlay
            .namespace
            .entries
            .get(path)
            .is_some_and(|e| matches!(e.kind, OverlayKind::Directory));
    if !directory {
        return 1;
    }
    2 + u32::try_from(
        f.overlay
            .namespace
            .entries
            .values()
            .filter(|e| {
                matches!(e.kind, OverlayKind::Directory)
                    && e.path.len() == path.len() + 1
                    && e.path.starts_with(path)
            })
            .count(),
    )
    .unwrap()
}

#[test]
fn indexed_queries_match_primary_oracle_and_all_pages() {
    let mut f = fixture(521, 3);
    let primary = f.overlay.namespace.entries.clone();
    assert_eq!(
        primary.len(),
        528,
        "primary fixture cardinality: {}",
        primary.len()
    );
    let mut routes = [0; 3];
    for (path, entry) in &primary {
        let expected = OverlayQueryEntry {
            entry: Some(entry.clone()),
            nlink: oracle_nlink(&f, path),
        };
        assert_eq!(
            f.overlay.query_path(&f.store, &f.owner, path).unwrap(),
            OverlayQuery::Found(expected.clone())
        );
        routes[0] += 1;
        assert_eq!(
            f.overlay
                .query_inode(&f.store, &f.owner, entry.inode)
                .unwrap(),
            OverlayQuery::Found(expected.clone())
        );
        routes[1] += 1;
        let (name, parent) = path.split_last().unwrap();
        assert_eq!(
            f.overlay
                .query_lookup(&f.store, &f.owner, parent, name)
                .unwrap(),
            OverlayQuery::Found(expected)
        );
        routes[2] += 1;
    }
    assert_eq!(routes, [528; 3], "query route counts: {routes:?}");
    for path in [
        vec![],
        vec![name("d")],
        vec![name("empty")],
        vec![name("d"), name("child-0000")],
    ] {
        let observation = found(
            f.overlay
                .query_directory(&f.store, &f.owner, &path)
                .unwrap(),
        );
        assert_eq!(observation.directory.nlink, oracle_nlink(&f, &path));
        let mut cursor = observation.cursor;
        let mut actual = Vec::new();
        let mut pages = 0;
        loop {
            let page = found(
                f.overlay
                    .query_children(&f.store, &f.owner, &cursor)
                    .unwrap(),
            );
            assert!(
                page.entries.len() <= 256,
                "page length: {}",
                page.entries.len()
            );
            actual.extend(page.entries.into_iter().map(|row| row.entry.unwrap()));
            pages += 1;
            let Some(next) = page.next else {
                break;
            };
            cursor = next;
        }
        let expected: Vec<_> = primary
            .values()
            .filter(|e| e.path.len() == path.len() + 1 && e.path.starts_with(&path))
            .cloned()
            .collect();
        assert_eq!((actual, pages > 0), (expected, true), "directory {path:?}");
    }
    assert_eq!(
        f.overlay
            .query_lookup(&f.store, &f.owner, &[name("a")], &name("child"))
            .unwrap(),
        OverlayQuery::NotDirectory
    );
    assert_eq!(
        f.overlay
            .query_path(&f.store, &f.owner, &[name("missing")])
            .unwrap(),
        OverlayQuery::Missing
    );
    assert_eq!(
        f.overlay.query_inode(&f.store, &f.owner, u64::MAX).unwrap(),
        OverlayQuery::Missing
    );
    assert_eq!(
        f.overlay
            .query_directory(&f.store, &f.owner, &[name("a")])
            .unwrap(),
        OverlayQuery::NotDirectory
    );
    let root = found(f.overlay.query_path(&f.store, &f.owner, &[]).unwrap());
    assert_eq!((root.entry, root.nlink), (None, 4));
}

#[test]
fn indexed_query_work_is_directory_local_and_bounded() {
    let mut cases = 0;
    for unrelated in [0, 10000] {
        let mut f = fixture(513, unrelated);
        let actual = f.overlay.namespace.entries.len();
        assert_eq!(actual, unrelated + 517, "fixture cardinality: {actual}");
        let path = vec![name("d"), name("child-0512")];
        let (answer, work) = measure_query(|| f.overlay.query_path(&f.store, &f.owner, &path));
        let answer = found(answer.unwrap());
        let inode = answer.entry.unwrap().inode;
        assert_eq!(work, (0, 0, 1));
        let (answer, work) = measure_query(|| f.overlay.query_inode(&f.store, &f.owner, inode));
        assert_eq!(
            (found(answer.unwrap()).entry.unwrap().path, work),
            (path.clone(), (0, 0, 1))
        );
        let (answer, work) = measure_query(|| {
            f.overlay
                .query_lookup(&f.store, &f.owner, &[name("d")], &name("child-0512"))
        });
        assert_eq!(
            (found(answer.unwrap()).entry.unwrap().path, work),
            (path, (0, 0, 1))
        );
        let (answer, work) =
            measure_query(|| f.overlay.query_directory(&f.store, &f.owner, &[name("d")]));
        let mut cursor = found(answer.unwrap()).cursor;
        assert_eq!(work, (0, 0, 1));
        for expected in [256, 256, 1] {
            let (answer, work) =
                measure_query(|| f.overlay.query_children(&f.store, &f.owner, &cursor));
            let page = found(answer.unwrap());
            assert_eq!(
                (page.entries.len(), work, page.next.is_some()),
                (expected, (0, 0, expected), expected == 256)
            );
            if let Some(next) = page.next {
                cursor = next;
            }
        }
        cases += 1;
    }
    assert_eq!(cases, 2, "nonempty work cases: {cases}");
}

#[test]
fn changed_page_context_is_retry_and_never_eof_or_poison() {
    let mut f = fixture(1, 0);
    let observed = found(f.overlay.query_directory(&f.store, &f.owner, &[]).unwrap());
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            granary_core::overlay_journal::Record::Create {
                at: at("new"),
                kind: granary_core::overlay_journal::CreateKind::Dir,
            },
        )
        .unwrap();
    let actual = f
        .overlay
        .query_children(&f.store, &f.owner, &observed.cursor)
        .unwrap();
    assert_eq!(
        (actual, f.overlay.readiness()),
        (OverlayQuery::Changed, OverlayReadiness::Ready)
    );
    let current = found(f.overlay.query_directory(&f.store, &f.owner, &[]).unwrap());
    let page = found(
        f.overlay
            .query_children(&f.store, &f.owner, &current.cursor)
            .unwrap(),
    );
    assert_eq!((page.entries.len(), page.next), (5, None));
    let mut cases = 0;
    for field in ["incarnation", "identity"] {
        let mut old = current.cursor.clone();
        if field == "incarnation" {
            old.change_incarnation();
        } else {
            old.change_identity();
        }
        assert_eq!(
            (
                f.overlay.query_children(&f.store, &f.owner, &old).unwrap(),
                f.overlay.readiness()
            ),
            (OverlayQuery::Changed, OverlayReadiness::Ready)
        );
        cases += 1;
    }
    assert_eq!(cases, 2, "context cases: {cases}");
}

#[test]
fn indexed_directory_emptiness_copies_no_entries_and_preserves_refusals() {
    let mut f = fixture(1, 0);
    let mut cases = 0;
    for (path, expected) in [
        (vec![], OverlayQuery::Found(true)),
        (vec![name("d")], OverlayQuery::Found(true)),
        (vec![name("empty")], OverlayQuery::Found(false)),
        (vec![name("absent")], OverlayQuery::Missing),
        (vec![name("a")], OverlayQuery::NotDirectory),
    ] {
        let (answer, work) =
            measure_query(|| f.overlay.query_has_children(&f.store, &f.owner, &path));
        assert_eq!(
            (answer.unwrap(), work),
            (expected, (0, 0, 0)),
            "path: {path:?}"
        );
        cases += 1;
    }
    assert_eq!((cases, f.overlay.namespace.entries.len()), (5, 5));
}

fn refusal<T>(f: &mut Fixture, answer: Result<OverlayQuery<T>, OverlayError>) {
    assert_eq!(
        (answer.err().map(|e| e.to_string()), f.overlay.readiness()),
        (
            Some("overlay persistence poisoned".into()),
            OverlayReadiness::Poisoned
        )
    );
    assert_eq!(
        f.overlay
            .query_path(&f.store, &f.owner, &[name("a")])
            .err()
            .map(|e| e.to_string()),
        Some("overlay persistence poisoned".into())
    );
}

#[test]
fn path_lookup_and_directory_faults_refuse_before_success() {
    let mut cases = 0;
    for route in ["path", "lookup", "directory"] {
        let mut f = fixture(1, 0);
        let valid = f
            .overlay
            .query_path(&f.store, &f.owner, &[name("d")])
            .unwrap();
        assert!(
            matches!(valid, OverlayQuery::Found(_)),
            "valid query: {valid:?}"
        );
        assert_eq!(f.overlay.namespace.entries.len(), 5);
        f.overlay
            .namespace
            .entries
            .get_mut(&vec![name("d")])
            .unwrap()
            .path = vec![name("wrong")];
        match route {
            "path" => {
                let (answer, _) =
                    measure_query(|| f.overlay.query_path(&f.store, &f.owner, &[name("d")]));
                refusal(&mut f, answer);
            }
            "lookup" => {
                let (answer, _) =
                    measure_query(|| f.overlay.query_lookup(&f.store, &f.owner, &[], &name("d")));
                refusal(&mut f, answer);
            }
            "directory" => {
                let (answer, _) =
                    measure_query(|| f.overlay.query_directory(&f.store, &f.owner, &[name("d")]));
                refusal(&mut f, answer);
            }
            _ => unreachable!(),
        }
        cases += 1;
    }
    assert_eq!(cases, 3, "fault route counts: {cases}");
}

#[test]
fn stale_inverse_query_refuses_instead_of_retargeting() {
    let mut f = fixture(1, 0);
    let inode = f.overlay.namespace.entries[&vec![name("a")]].inode;
    let valid = found(f.overlay.query_inode(&f.store, &f.owner, inode).unwrap());
    assert_eq!(
        (valid.entry.unwrap().path, f.overlay.namespace.entries.len()),
        (vec![name("a")], 5)
    );
    f.overlay
        .namespace
        .inject_inverse_reference(inode, vec![name("b")]);
    let (answer, _) = measure_query(|| f.overlay.query_inode(&f.store, &f.owner, inode));
    refusal(&mut f, answer);
}

#[test]
fn indexed_inode_change_compares_every_entry_field_without_unchanged_copies() {
    let mut f = fixture(1, 0);
    let expected = f
        .overlay
        .namespace
        .entries
        .get(&vec![name("a")])
        .unwrap()
        .clone();
    assert_eq!(
        f.overlay.namespace.entries.len(),
        5,
        "nonempty primary fixture"
    );
    let (answer, work) =
        measure_query(|| f.overlay.query_inode_change(&f.store, &f.owner, &expected));
    assert_eq!(
        (answer.unwrap(), work),
        (OverlayQuery::Found(None), (0, 0, 0))
    );
    let mut cases = 0;
    for field in ["path", "kind", "content", "stage", "size", "exec"] {
        let mut stale = expected.clone();
        match field {
            "path" => stale.path = vec![name("b")],
            "kind" => stale.kind = OverlayKind::Directory,
            "content" => {
                stale.kind = OverlayKind::File {
                    content: Some(grain(2)),
                }
            }
            "stage" => stale.stage_id = Some(1),
            "size" => stale.size += 1,
            "exec" => stale.exec = !stale.exec,
            _ => unreachable!(),
        }
        let (answer, work) =
            measure_query(|| f.overlay.query_inode_change(&f.store, &f.owner, &stale));
        assert_eq!(
            (answer.unwrap(), work),
            (OverlayQuery::Found(Some(expected.clone())), (0, 0, 1)),
            "a changed {field} must force owned replanning"
        );
        cases += 1;
    }
    let mut absent = expected;
    absent.inode = u64::MAX;
    let (answer, work) =
        measure_query(|| f.overlay.query_inode_change(&f.store, &f.owner, &absent));
    assert_eq!((answer.unwrap(), work), (OverlayQuery::Missing, (0, 0, 0)));
    assert_eq!(
        cases + 1,
        7,
        "entry-field cases including absent identity: {cases}"
    );
}

#[test]
fn indexed_inode_change_validates_references_before_accepting_unchanged_state() {
    let mut f = fixture(1, 0);
    let expected = f
        .overlay
        .namespace
        .entries
        .get(&vec![name("a")])
        .unwrap()
        .clone();
    let (answer, work) =
        measure_query(|| f.overlay.query_inode_change(&f.store, &f.owner, &expected));
    assert_eq!(
        (f.overlay.namespace.entries.len(), answer.unwrap(), work),
        (5, OverlayQuery::Found(None), (0, 0, 0)),
        "nonempty unchanged-identity control"
    );
    f.overlay
        .namespace
        .inject_inverse_reference(expected.inode, vec![name("b")]);
    let (answer, _) = measure_query(|| f.overlay.query_inode_change(&f.store, &f.owner, &expected));
    refusal(&mut f, answer);
}

#[test]
fn indexed_inode_change_retains_readiness_on_identical_input() {
    let mut f = fixture(1, 0);
    let expected = f
        .overlay
        .namespace
        .entries
        .get(&vec![name("a")])
        .unwrap()
        .clone();
    let (answer, work) =
        measure_query(|| f.overlay.query_inode_change(&f.store, &f.owner, &expected));
    assert_eq!(
        (f.overlay.namespace.entries.len(), answer.unwrap(), work),
        (5, OverlayQuery::Found(None), (0, 0, 0)),
        "nonempty unchanged-identity readiness control"
    );
    f.overlay.poison();
    let (answer, _) = measure_query(|| f.overlay.query_inode_change(&f.store, &f.owner, &expected));
    refusal(&mut f, answer);
}

#[test]
fn wrong_parent_page_reference_refuses_instead_of_false_rows() {
    let mut f = fixture(1, 0);
    let observation = found(
        f.overlay
            .query_directory(&f.store, &f.owner, &[name("d")])
            .unwrap(),
    );
    let valid = found(
        f.overlay
            .query_children(&f.store, &f.owner, &observation.cursor)
            .unwrap(),
    );
    assert_eq!(
        (valid.entries.len(), f.overlay.namespace.entries.len()),
        (1, 5)
    );
    f.overlay
        .namespace
        .inject_child_reference(&[name("d")], name("child-0000"), vec![name("b")])
        .unwrap();
    let (answer, _) = measure_query(|| {
        f.overlay
            .query_children(&f.store, &f.owner, &observation.cursor)
    });
    refusal(&mut f, answer);
}

#[test]
fn link_count_overflow_refuses_for_root_and_named_directory() {
    let mut cases = 0;
    for path in [vec![], vec![name("d")]] {
        let mut f = fixture(1, 0);
        let valid = found(f.overlay.query_path(&f.store, &f.owner, &path).unwrap());
        assert_eq!(
            (valid.nlink, f.overlay.namespace.entries.len()),
            (if path.is_empty() { 4 } else { 3 }, 5)
        );
        f.overlay
            .namespace
            .inject_subdirectory_count(&path, u32::MAX)
            .unwrap();
        let (answer, _) = measure_query(|| f.overlay.query_path(&f.store, &f.owner, &path));
        refusal(&mut f, answer);
        cases += 1;
    }
    assert_eq!(cases, 2, "overflow cases: {cases}");
}

/// Expected rows come only from the primary map, including absent index names.
fn primary_children(f: &Fixture, path: &[Name]) -> Vec<OverlayEntry> {
    f.overlay
        .namespace
        .entries
        .values()
        .filter(|e| e.path.len() == path.len() + 1 && e.path.starts_with(path))
        .cloned()
        .collect()
}

fn queried_children(f: &mut Fixture, path: &[Name]) -> Vec<OverlayEntry> {
    let (observed, _) = measure_query(|| {
        let observation = found(f.overlay.query_directory(&f.store, &f.owner, path).unwrap());
        let page = found(
            f.overlay
                .query_children(&f.store, &f.owner, &observation.cursor)
                .unwrap(),
        );
        page.entries
            .into_iter()
            .map(|row| row.entry.unwrap())
            .collect::<Vec<_>>()
    });
    observed
}

fn compare_child_answers(
    expected: &[OverlayEntry],
    observed: &[OverlayEntry],
) -> Result<(), &'static str> {
    if observed == expected {
        Ok(())
    } else {
        Err("missing-child mismatch")
    }
}

#[test]
fn primary_oracle_detects_omitted_page_child_without_query_checker() {
    let mut f = fixture(2, 0);
    let expected = primary_children(&f, &[name("d")]);
    let observed = queried_children(&mut f, &[name("d")]);
    assert_eq!(
        (
            compare_child_answers(&expected, &observed),
            f.overlay.namespace.entries.len()
        ),
        (Ok(()), 6)
    );
    f.overlay
        .namespace
        .remove_child_reference(&[name("d")], &name("child-0001"))
        .unwrap();
    let expected = primary_children(&f, &[name("d")]);
    let observed = queried_children(&mut f, &[name("d")]);
    assert_eq!(
        (
            compare_child_answers(&expected, &observed),
            f.overlay.namespace.entries.len()
        ),
        (Err("missing-child mismatch"), 6)
    );
}

fn mutation_work_verdict(
    query: crate::overlay_store::work::QueryWork,
    storage: crate::overlay_store::work::StorageWork,
) -> Result<(), &'static str> {
    if query == crate::overlay_store::work::QueryWork::default()
        && storage.namespace_clones == 1
        && storage.primary_rows == 14
        && storage.primary_visits > 0
    {
        Ok(())
    } else {
        Err("mutation work escaped storage accounting")
    }
}

#[test]
fn mutation_fold_visits_and_copies_are_charged_to_storage() {
    use crate::overlay_store::work;
    let mut f = fixture(3, 7);
    assert_eq!(
        f.overlay.namespace.entries.len(),
        14,
        "primary cardinality: {}",
        f.overlay.namespace.entries.len()
    );
    let (answer, query, storage) = work::measure(|| {
        f.overlay.namespace_record(
            &mut f.store,
            &f.owner,
            Record::Create {
                at: at("new-directory"),
                kind: codec::CreateKind::Dir,
            },
        )
    });
    assert_eq!(
        (
            answer.is_ok(),
            query,
            storage.namespace_clones,
            storage.primary_rows,
            mutation_work_verdict(query, storage)
        ),
        (true, work::QueryWork::default(), 1, 14, Ok(())),
        "accepted mutation, query/storage work: answer={answer:?}, storage={storage:?}"
    );
    let mut escaped_query = query;
    escaped_query.primary_visits += storage.primary_visits;
    let mut escaped_storage = storage;
    escaped_storage.primary_visits = 0;
    let cases = [
        (query, storage, Ok(())),
        (
            escaped_query,
            escaped_storage,
            Err("mutation work escaped storage accounting"),
        ),
    ];
    for (query, storage, expected) in cases {
        assert_eq!(
            mutation_work_verdict(query, storage),
            expected,
            "query={query:?}, storage={storage:?}"
        );
    }
    assert_eq!(
        cases.len(),
        2,
        "classification paired-control cases: {}",
        cases.len()
    );
    assert_eq!(f.overlay.namespace.check_indexes(), Ok(()));
}

fn stage_work_verdict(
    query: crate::overlay_store::work::QueryWork,
    storage: crate::overlay_store::work::StorageWork,
) -> Result<(), &'static str> {
    if query == crate::overlay_store::work::QueryWork::default()
        && storage.namespace_clones == 2
        && storage.primary_rows == 28
        && storage.primary_visits > 0
    {
        Ok(())
    } else {
        Err("stage preparation work escaped storage accounting")
    }
}

#[test]
fn stage_preparation_and_publication_keep_query_accounts_clear() {
    use crate::overlay_store::work;
    let mut f = fixture(3, 7);
    assert_eq!(
        f.overlay.namespace.entries.len(),
        14,
        "primary cardinality: {}",
        f.overlay.namespace.entries.len()
    );
    let (answer, query, storage) = work::measure(|| {
        f.overlay
            .create_file(&mut f.store, &f.owner, at("new-file"), false)
    });
    assert_eq!(
        (
            answer.is_ok(),
            query,
            storage.namespace_clones,
            storage.primary_rows,
            stage_work_verdict(query, storage)
        ),
        (true, work::QueryWork::default(), 2, 28, Ok(())),
        "prepared and published stage: answer={answer:?}, storage={storage:?}"
    );
    let mut escaped_query = query;
    escaped_query.primary_visits += storage.primary_visits;
    let mut escaped_storage = storage;
    escaped_storage.primary_visits = 0;
    let cases = [
        (query, storage, Ok(())),
        (
            escaped_query,
            escaped_storage,
            Err("stage preparation work escaped storage accounting"),
        ),
    ];
    for (query, storage, expected) in cases {
        assert_eq!(
            stage_work_verdict(query, storage),
            expected,
            "query={query:?}, storage={storage:?}"
        );
    }
    assert_eq!(
        cases.len(),
        2,
        "stage paired-control cases: {}",
        cases.len()
    );
    assert_eq!(f.overlay.namespace.check_indexes(), Ok(()));
}

#[test]
fn indexed_page_copy_bound_is_per_attempt_including_discarded_pages() {
    let mut cases = 0;
    for unrelated in [0, 10000] {
        let mut f = fixture(513, unrelated);
        let cardinality = f.overlay.namespace.entries.len();
        assert_eq!(
            cardinality,
            unrelated + 517,
            "page fixture cardinality: {cardinality}"
        );
        let mut total = 0;
        for attempt in 0..3 {
            let ((owned, next), work) = measure_query(|| {
                let directory = found(
                    f.overlay
                        .query_directory(&f.store, &f.owner, &[name("d")])
                        .unwrap(),
                );
                let page = found(
                    f.overlay
                        .query_children(&f.store, &f.owner, &directory.cursor)
                        .unwrap(),
                );
                (page.entries.len(), page.next)
            });
            assert_eq!(
                (
                    owned,
                    work,
                    next.is_some(),
                    work.2.saturating_sub(owned) <= 2
                ),
                (256, (0, 0, 257), true, true),
                "attempt={attempt}, unrelated={unrelated}: zero whole copies/primary iterations and at most 2 copies beyond this attempt's owned page"
            );
            total += work.2;
            f.overlay
                .namespace_record(
                    &mut f.store,
                    &f.owner,
                    granary_core::overlay_journal::Record::SetattrExec {
                        at: at("a"),
                        exec: attempt % 2 == 0,
                    },
                )
                .unwrap();
            let (changed, refused_work) =
                measure_query(|| f.overlay.query_children(&f.store, &f.owner, &next.unwrap()));
            assert_eq!(
                (changed.unwrap(), refused_work, f.overlay.readiness()),
                (OverlayQuery::Changed, (0, 0, 0), OverlayReadiness::Ready),
                "discarded page remains owned by its attempt; churn never becomes EOF or poison"
            );
            cases += 1;
        }
        assert_eq!(
            (total, total <= 774),
            (771, true),
            "3 owned pages of 256 plus at most 2 entries per attempt"
        );
        eprintln!(
            "unrelated={unrelated}, attempts=3, owned_rows=768, copied_entries={total}, whole_namespace_copies=0, primary_iterations=0"
        );
    }
    assert_eq!(cases, 6, "nonempty per-attempt page cases: {cases}");
}

#[test]
fn indexed_path_binding_copies_no_entries_and_preserves_absence_and_root() {
    let mut cases = 0;
    for unrelated in [0, 64] {
        let mut f = fixture(1, unrelated);
        let cardinality = f.overlay.namespace.entries.len();
        assert_eq!(
            cardinality,
            unrelated + 5,
            "actual primary rows: {cardinality}"
        );
        let inode = f
            .overlay
            .namespace
            .entries
            .get(&vec![name("a")])
            .unwrap()
            .inode;
        for (path, expected) in [
            (vec![name("a")], OverlayQuery::Found(Some(inode))),
            (vec![], OverlayQuery::Found(None)),
            (vec![name("absent")], OverlayQuery::Missing),
        ] {
            let (answer, work) =
                measure_query(|| f.overlay.query_path_inode(&f.store, &f.owner, &path));
            assert_eq!(
                (answer.unwrap(), work),
                (expected, (0, 0, 0)),
                "binding path={path:?}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 6, "nonempty binding cases: {cases}");
}

#[test]
fn indexed_path_binding_refuses_inconsistent_associations_and_sticky_poison() {
    let mut cases = 0;
    for fault in ["inverse", "parent", "poison"] {
        let mut f = fixture(1, 0);
        let path = vec![name("a")];
        let inode = f.overlay.namespace.entries.get(&path).unwrap().inode;
        let (valid, work) = measure_query(|| f.overlay.query_path_inode(&f.store, &f.owner, &path));
        assert_eq!(
            (f.overlay.namespace.entries.len(), valid.unwrap(), work),
            (5, OverlayQuery::Found(Some(inode)), (0, 0, 0)),
            "valid binding, fault={fault}"
        );
        match fault {
            "inverse" => f
                .overlay
                .namespace
                .inject_inverse_reference(inode, vec![name("b")]),
            "parent" => f
                .overlay
                .namespace
                .remove_child_reference(&[], &name("a"))
                .unwrap(),
            "poison" => f.overlay.poison(),
            _ => unreachable!(),
        }
        let (answer, _) = measure_query(|| f.overlay.query_path_inode(&f.store, &f.owner, &path));
        refusal(&mut f, answer);
        cases += 1;
    }
    assert_eq!(cases, 3, "nonempty path-binding fault routes: {cases}");
}

#[test]
fn indexed_path_binding_mandatory_admission_refuses_after_warming() {
    let mut f = fixture(1, 0);
    let path = vec![name("a")];
    let inode = f.overlay.namespace.entries.get(&path).unwrap().inode;
    let (valid, work) = measure_query(|| f.overlay.query_path_inode(&f.store, &f.owner, &path));
    assert_eq!(
        (f.overlay.namespace.entries.len(), valid.unwrap(), work),
        (5, OverlayQuery::Found(Some(inode)), (0, 0, 0)),
        "nonempty warmed binding"
    );
    f.overlay.poison();
    let (answer, _) = measure_query(|| f.overlay.query_path_inode(&f.store, &f.owner, &path));
    refusal(&mut f, answer);
}

#[test]
fn indexed_path_binding_root_refuses_overflowing_link_count() {
    let mut f = fixture(1, 0);
    let (valid, work) = measure_query(|| f.overlay.query_path_inode(&f.store, &f.owner, &[]));
    assert_eq!(
        (f.overlay.namespace.entries.len(), valid.unwrap(), work),
        (5, OverlayQuery::Found(None), (0, 0, 0)),
        "nonempty synthetic-root binding control"
    );
    f.overlay
        .namespace
        .inject_subdirectory_count(&[], u32::MAX)
        .unwrap();
    let (answer, _) = measure_query(|| f.overlay.query_path_inode(&f.store, &f.owner, &[]));
    refusal(&mut f, answer);
}

#[expect(
    clippy::too_many_lines,
    reason = "paired image rebuild routes keep the injected fold and sticky service refusal together"
)]
fn replacement_fold_fault(rejected: bool, install: bool) {
    let mut cases = 0;
    for fault in [false, true] {
        let mut f = Fixture::with_base(
            vec![entry(
                vec![name("a")],
                OverlayKind::File {
                    content: Some(grain(1)),
                },
            )],
            Source::default(),
        );
        let proof = f.boundary_proof();
        let proof = f.landing(proof);
        let plan = if !rejected && install {
            Some(
                f.overlay
                    .prepare_replacement(&mut f.store, &f.owner, proof.clone())
                    .unwrap(),
            )
        } else {
            None
        };
        // This retained metadata record reaches the rebuilt namespace fold.
        f.overlay
            .namespace_record(
                &mut f.store,
                &f.owner,
                Record::SetattrExec {
                    at: at("a"),
                    exec: true,
                },
            )
            .unwrap();
        if fault {
            super::super::replacement::FOLD_FAULT.set(Some(usize::from(rejected && install)));
        }
        let result = if rejected {
            // A rejected image retains the metadata record, but no landing records.
            let mut rejected_fixture =
                Fixture::with_base(f.overlay.base.clone(), Source::default());
            rejected_fixture
                .overlay
                .namespace_record(
                    &mut rejected_fixture.store,
                    &rejected_fixture.owner,
                    Record::SetattrExec {
                        at: at("a"),
                        exec: true,
                    },
                )
                .unwrap();
            let capture = rejected_fixture
                .overlay
                .capture_boundary(&mut rejected_fixture.store, &rejected_fixture.owner)
                .unwrap();
            let boundary = rejected_fixture
                .overlay
                .record_boundary(
                    &mut rejected_fixture.store,
                    &rejected_fixture.owner,
                    capture,
                    grain(3),
                    [7; 16],
                )
                .unwrap();
            let result = rejected_fixture.overlay.replace_rejected(
                &mut rejected_fixture.store,
                &rejected_fixture.owner,
                boundary,
                [7; 16],
            );
            f = rejected_fixture;
            result
        } else if let Some(plan) = plan {
            f.overlay
                .install_replacement(&mut f.store, &f.owner, plan)
                .map(|_| ())
        } else {
            f.overlay
                .prepare_replacement(&mut f.store, &f.owner, proof)
                .map(|_| ())
        };
        let fired = super::super::replacement::FOLD_FAULT.get();
        assert_eq!(
            (
                result.as_ref().err().map(ToString::to_string),
                f.overlay.readiness(),
                fired
            ),
            if fault {
                (
                    Some("overlay persistence poisoned".to_owned()),
                    OverlayReadiness::Poisoned,
                    None,
                )
            } else {
                (None, OverlayReadiness::Ready, None)
            },
            "rebuilt fold rejected={rejected}, install={install}, fault={fault}"
        );
        if fault {
            assert_eq!(
                f.overlay
                    .query_path(&f.store, &f.owner, &[name("a")])
                    .err()
                    .map(|e| e.to_string()),
                Some("overlay persistence poisoned".to_owned()),
                "sticky service refusal"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 2, "replacement fold paired routes: {cases}");
}

fn cursor_lifecycle(route: &str) {
    let mut cases = 0;
    {
        let mut f = fixture(2, 0);
        if route == "landed" {
            f.overlay
                .namespace_record(
                    &mut f.store,
                    &f.owner,
                    Record::SetattrExec {
                        at: at("a"),
                        exec: false,
                    },
                )
                .unwrap();
        }
        let before = found(f.overlay.query_directory(&f.store, &f.owner, &[]).unwrap());
        assert!(
            matches!(
                f.overlay.query_children(&f.store, &f.owner, &before.cursor),
                Ok(OverlayQuery::Found(_))
            ),
            "valid pre-transition cursor"
        );
        match route {
            "replay" => f
                .overlay
                .recover(&mut f.store, &f.owner, &mut f.source)
                .unwrap(),
            "landed" => {
                let proof = f.boundary_proof();
                let proof = f.landing(proof);
                f.overlay
                    .replace_landed(&mut f.store, &f.owner, proof)
                    .unwrap();
            }
            "rejected" => {
                let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
                let boundary = f
                    .overlay
                    .record_boundary(&mut f.store, &f.owner, capture, grain(3), [7; 16])
                    .unwrap();
                f.overlay
                    .replace_rejected(&mut f.store, &f.owner, boundary, [7; 16])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let after = found(f.overlay.query_directory(&f.store, &f.owner, &[]).unwrap());
        assert_eq!(
            before.cursor.revision_for_test(),
            after.cursor.revision_for_test(),
            "sequence reuse premise, route={route}"
        );
        let old = f
            .overlay
            .query_children(&f.store, &f.owner, &before.cursor)
            .unwrap();
        let fresh = f
            .overlay
            .query_children(&f.store, &f.owner, &after.cursor)
            .unwrap();
        assert_eq!(
            (
                old == OverlayQuery::Changed,
                matches!(fresh, OverlayQuery::Found(_))
            ),
            (true, true),
            "old/fresh cursor, route={route}: old={old:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 1, "live lifecycle cursor routes: {cases}");
}

#[test]
fn replacement_landed_build_fold_fault_poisons_service() {
    replacement_fold_fault(false, false);
}
#[test]
fn replacement_landed_install_fold_fault_poisons_service() {
    replacement_fold_fault(false, true);
}
#[test]
fn replacement_rejected_build_fold_fault_poisons_service() {
    replacement_fold_fault(true, false);
}
#[test]
fn replacement_rejected_install_fold_fault_poisons_service() {
    replacement_fold_fault(true, true);
}
#[test]
fn directory_cursor_refuses_replay_after_sequence_reuse() {
    cursor_lifecycle("replay");
}
#[test]
fn directory_cursor_refuses_landed_replacement_after_sequence_reuse() {
    cursor_lifecycle("landed");
}
#[test]
fn directory_cursor_refuses_rejected_replacement_after_sequence_reuse() {
    cursor_lifecycle("rejected");
}

fn replacement_fold_refusal(rejected: bool) {
    for faulty_image in [false, true] {
        let mut f = Fixture::with_base(
            vec![entry(
                vec![name("a")],
                OverlayKind::File {
                    content: Some(grain(1)),
                },
            )],
            Source::default(),
        );
        let proof = if rejected {
            None
        } else {
            let proof = f.boundary_proof();
            Some(f.landing(proof))
        };
        f.overlay
            .namespace_record(
                &mut f.store,
                &f.owner,
                Record::SetattrExec {
                    at: at("a"),
                    exec: true,
                },
            )
            .unwrap();
        let result = if let Some(mut proof) = proof {
            if faulty_image {
                proof.entries.first_mut().unwrap().kind = OverlayKind::Directory;
            }
            f.overlay
                .prepare_replacement(&mut f.store, &f.owner, proof)
                .map(|_| ())
        } else {
            let capture = f.overlay.capture_boundary(&mut f.store, &f.owner).unwrap();
            let boundary = f
                .overlay
                .record_boundary(&mut f.store, &f.owner, capture, grain(3), [7; 16])
                .unwrap();
            if faulty_image {
                f.overlay.base.first_mut().unwrap().kind = OverlayKind::Directory;
            }
            f.overlay
                .replace_rejected(&mut f.store, &f.owner, boundary, [7; 16])
        };
        assert_eq!(
            (
                result.err().map(|error| error.to_string()),
                f.overlay.readiness()
            ),
            if faulty_image && !rejected {
                (
                    Some("overlay namespace conflict".to_owned()),
                    OverlayReadiness::Ready,
                )
            } else if faulty_image {
                (
                    Some("overlay persistence poisoned".to_owned()),
                    OverlayReadiness::Poisoned,
                )
            } else {
                (None, OverlayReadiness::Ready)
            },
            "retained file metadata cannot fold into a directory: rejected={rejected}, faulty_image={faulty_image}"
        );
    }
}

#[test]
fn replacement_landed_suffix_anchor_conflict_preserves_service() {
    replacement_fold_refusal(false);
}
#[test]
fn replacement_rejected_fold_refusal_poisons_service() {
    replacement_fold_refusal(true);
}

#[test]
fn replacement_landed_prefix_fold_refusal_poisons_service() {
    for faulty_image in [false, true] {
        let mut f = Fixture::with_base(
            vec![entry(
                vec![name("a")],
                OverlayKind::File {
                    content: Some(grain(1)),
                },
            )],
            Source::default(),
        );
        f.overlay
            .namespace_record(
                &mut f.store,
                &f.owner,
                Record::SetattrExec {
                    at: at("a"),
                    exec: true,
                },
            )
            .unwrap();
        let proof = f.boundary_proof();
        let proof = f.landing(proof);
        if faulty_image {
            f.overlay.base.first_mut().unwrap().kind = OverlayKind::Directory;
        }
        let result = f.overlay.prepare_replacement(&mut f.store, &f.owner, proof);
        assert_eq!(
            (
                result.err().map(|error| error.to_string()),
                f.overlay.readiness()
            ),
            if faulty_image {
                (
                    Some("overlay persistence poisoned".to_owned()),
                    OverlayReadiness::Poisoned,
                )
            } else {
                (None, OverlayReadiness::Ready)
            },
            "prefix metadata cannot fold into a directory: faulty_image={faulty_image}"
        );
    }
}
