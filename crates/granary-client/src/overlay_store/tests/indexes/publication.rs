// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::oracle::{answers, directory, location, names};
use super::*;
use crate::overlay_store::OverlayQuery;

fn primary(f: &Fixture) -> Vec<OverlayEntry> {
    f.overlay.namespace.entries.values().cloned().collect()
}

fn attempt(f: &mut Fixture, action: impl FnOnce(&mut Fixture) -> Result<u64, OverlayError>) -> u64 {
    let before = primary(f);
    let bytes = f.io.bytes(&f.overlay.journal_path());
    let result = action(f);
    if let Err(error) = &result {
        let observed = (
            error.to_string(),
            f.overlay.readiness(),
            primary(f) == before,
            f.io.bytes(&f.overlay.journal_path()) == bytes,
        );
        assert_eq!(
            observed,
            (
                "overlay persistence poisoned".into(),
                OverlayReadiness::Poisoned,
                true,
                true
            ),
            "fault must refuse before primary/index publication and append"
        );
        assert_eq!(
            f.overlay
                .query_path(&f.store, &f.owner, &[])
                .err()
                .map(|e| e.to_string()),
            Some("overlay persistence poisoned".into()),
            "candidate fault stays poisoned"
        );
        eprintln!("candidate refusal={observed:?}; fault cases=1");
    }
    assert!(
        result.is_ok(),
        "valid publication required; actual={result:?}"
    );
    assert!(
        answers(f).is_ok(),
        "complete primary oracle after publication: {:?}",
        answers(f)
    );
    result.unwrap()
}

fn publish(f: &mut Fixture, record: Record) {
    attempt(f, |f| {
        f.overlay.namespace_record(&mut f.store, &f.owner, record)
    });
}

#[test]
fn directory_publication_adds_membership_and_one_link() {
    let mut f = Fixture::with_base(vec![directory("parent")], Source::default());
    let before = f.overlay.namespace.query_nlink(&names("parent")).unwrap();
    publish(
        &mut f,
        Record::Create {
            at: location("parent/new"),
            kind: codec::CreateKind::Dir,
        },
    );
    assert_eq!(
        (
            f.overlay.namespace.entries.len(),
            f.overlay.namespace.query_nlink(&names("parent")).unwrap()
        ),
        (2, before + 1)
    );
}

#[test]
fn file_publication_and_value_changes_preserve_directory_links() {
    let mut f = Fixture::with_base(vec![directory("parent")], Source::default());
    let id = attempt(&mut f, |f| {
        f.overlay
            .create_file(&mut f.store, &f.owner, location("parent/file"), false)
    });
    assert_eq!(
        (
            f.overlay.namespace.entries.len(),
            f.overlay.namespace.query_nlink(&names("parent")).unwrap()
        ),
        (2, 2)
    );
    f.write(id, b"body");
    assert_eq!(
        (
            answers(&mut f).is_ok(),
            f.overlay.namespace.query_nlink(&names("parent")).unwrap()
        ),
        (true, 2)
    );
    publish(
        &mut f,
        Record::SetattrExec {
            at: location("parent/file"),
            exec: true,
        },
    );
    f.overlay.truncate(&mut f.store, &f.owner, id, 2).unwrap();
    assert_eq!(
        (
            answers(&mut f).is_ok(),
            f.overlay.namespace.query_nlink(&names("parent")).unwrap()
        ),
        (true, 2)
    );
    let mut source = Source::default();
    source.0.insert(GrainId::of(b"body"), b"body".to_vec());
    let mut clean = directory("parent/clean");
    clean.kind = OverlayKind::File {
        content: Some(GrainId::of(b"body")),
    };
    clean.size = 4;
    let mut f = Fixture::with_base(vec![directory("parent"), clean], source);
    let stage = f
        .overlay
        .copy_up(
            &mut f.store,
            &f.owner,
            location("parent/clean"),
            &mut f.source,
        )
        .unwrap();
    assert_eq!(
        (
            answers(&mut f).is_ok(),
            f.overlay.namespace.query_nlink(&names("parent")).unwrap()
        ),
        (true, 2)
    );
    f.write(stage, b"next");
    assert_eq!(
        (
            answers(&mut f).is_ok(),
            f.overlay.namespace.query_nlink(&names("parent")).unwrap()
        ),
        (true, 2)
    );
    publish(
        &mut f,
        Record::SetattrExec {
            at: location("parent/clean"),
            exec: true,
        },
    );
    assert_eq!(
        (
            answers(&mut f).is_ok(),
            f.overlay.namespace.query_nlink(&names("parent")).unwrap()
        ),
        (true, 2)
    );
    eprintln!(
        "file publication count=1; link-invariance routes=StageBind/WriteExtent/SetattrExec/Truncate"
    );
}

#[test]
fn unlink_publication_detaches_held_stage_and_recreation_never_reattaches_it() {
    let mut f = Fixture::new();
    let id = f.create();
    f.write(id, b"held");
    let inode = f.overlay.namespace.entries.get(&names("f")).unwrap().inode;
    for _ in 0..2 {
        assert_eq!(
            f.overlay
                .open_stage(&mut f.store, &f.owner, &names("f"))
                .unwrap(),
            id
        );
    }
    publish(
        &mut f,
        Record::Delete {
            at: at("f"),
            kind: codec::DeleteKind::File { stage_id: Some(id) },
        },
    );
    assert_eq!(
        (
            f.overlay.namespace.stages.get(&id).unwrap().path.clone(),
            f.overlay
                .query_path(&f.store, &f.owner, &names("f"))
                .unwrap(),
            f.overlay.query_inode(&f.store, &f.owner, inode).unwrap()
        ),
        (None, OverlayQuery::Missing, OverlayQuery::Missing)
    );
    let new_id = f.create();
    f.write(new_id, b"new!");
    let new_inode = f.overlay.namespace.entries.get(&names("f")).unwrap().inode;
    assert_eq!(
        (
            f.overlay.namespace.stages.get(&id).unwrap().path.clone(),
            f.overlay.namespace.stages.get(&id).unwrap().handles,
            id != new_id,
            inode != new_inode,
            f.overlay
                .read_stage(&mut f.store, &f.owner, id, 0, 4)
                .unwrap()
        ),
        (None, 2, true, true, b"held".to_vec())
    );
    for _ in 0..2 {
        f.overlay.close_stage(&mut f.store, id).unwrap();
    }
    assert!(answers(&mut f).is_ok());
}

#[test]
fn rmdir_publication_removes_identity_membership_and_one_link() {
    let mut f = Fixture::with_base(
        vec![directory("parent"), directory("parent/empty")],
        Source::default(),
    );
    let inode = f
        .overlay
        .namespace
        .entries
        .get(&names("parent/empty"))
        .unwrap()
        .inode;
    assert_eq!(
        (
            f.overlay.namespace.entries.len(),
            f.overlay.namespace.query_nlink(&names("parent")).unwrap()
        ),
        (2, 3)
    );
    publish(
        &mut f,
        Record::Delete {
            at: location("parent/empty"),
            kind: codec::DeleteKind::Dir,
        },
    );
    assert_eq!(
        (
            f.overlay.query_inode(&f.store, &f.owner, inode).unwrap(),
            f.overlay
                .query_path(&f.store, &f.owner, &names("parent/empty"))
                .unwrap(),
            f.overlay.namespace.query_nlink(&names("parent")).unwrap()
        ),
        (OverlayQuery::Missing, OverlayQuery::Missing, 2)
    );
}

fn relocation(replace: bool) {
    let mut f = Fixture::with_base(
        vec![
            directory("source"),
            directory("source/child"),
            directory("target"),
        ],
        Source::default(),
    );
    let inode = f
        .overlay
        .namespace
        .entries
        .get(&names("source"))
        .unwrap()
        .inode;
    let displaced = f
        .overlay
        .namespace
        .entries
        .get(&names("target"))
        .unwrap()
        .inode;
    let record = if replace {
        Record::Replace {
            from: at("source"),
            to: at("target"),
        }
    } else {
        Record::Move {
            from: at("source"),
            to: at("moved"),
        }
    };
    publish(&mut f, record);
    let destination = if replace { "target" } else { "moved" };
    assert_eq!(
        (
            f.overlay
                .query_path(&f.store, &f.owner, &names("source"))
                .unwrap(),
            f.overlay
                .namespace
                .entries
                .get(&names(destination))
                .unwrap()
                .inode,
            f.overlay
                .namespace
                .entries
                .contains_key(&names(&format!("{destination}/child")))
        ),
        (OverlayQuery::Missing, inode, true)
    );
    if replace {
        assert_eq!(
            f.overlay
                .query_inode(&f.store, &f.owner, displaced)
                .unwrap(),
            OverlayQuery::Missing
        );
    }
}

#[test]
fn subtree_move_publication_keeps_new_identity_and_removes_old_name() {
    relocation(false);
}

#[test]
fn subtree_replace_publication_keeps_source_and_detaches_displaced_identity() {
    relocation(true);
}

fn append_fixture() -> Fixture {
    Fixture::with_base(vec![directory("retained")], Source::default())
}

#[test]
fn journal_append_faults_never_publish_candidate_indexes() {
    let mut cases = 0;
    for (phase, action) in [
        ("before", FaultAction::Fail),
        ("partial", FaultAction::Short(3)),
        ("after", FaultAction::Fail),
    ] {
        let mut valid = append_fixture();
        publish(
            &mut valid,
            Record::Create {
                at: at("new"),
                kind: codec::CreateKind::Dir,
            },
        );
        assert_eq!(
            (
                valid.overlay.namespace.entries.len(),
                valid.overlay.namespace.query_nlink(&[]).unwrap()
            ),
            (2, 4)
        );
        let mut f = append_fixture();
        let before = primary(&f);
        let bytes = f.io.bytes(&f.overlay.journal_path());
        let faults = f.overlay.fault_control();
        faults.arm("overlay.journal.append", phase, 1, action);
        let result = f.overlay.namespace_record(
            &mut f.store,
            &f.owner,
            Record::Create {
                at: at("new"),
                kind: codec::CreateKind::Dir,
            },
        );
        assert_eq!(
            (
                result.err().map(|e| e.to_string()),
                f.overlay.readiness(),
                primary(&f) == before,
                f.io.bytes(&f.overlay.journal_path()) == bytes,
                faults.fired().len()
            ),
            (
                Some(
                    if phase == "partial" {
                        "overlay I/O: overlay injected short write"
                    } else {
                        "overlay I/O: overlay injected fault"
                    }
                    .into()
                ),
                OverlayReadiness::Ready,
                true,
                true,
                1
            ),
            "phase={phase}"
        );
        assert_eq!(
            (
                answers(&mut f),
                f.overlay
                    .query_path(&f.store, &f.owner, &names("new"))
                    .unwrap()
            ),
            (Ok([1, 1, 1, 2, 2]), OverlayQuery::Missing)
        );
        f.reopen().unwrap();
        assert_eq!(
            (primary(&f), answers(&mut f)),
            (before, Ok([1, 1, 1, 2, 2]))
        );
        cases += 1;
    }
    assert_eq!(cases, 3, "nonzero fold/append/publication faults: {cases}");
    eprintln!("append refusal/rollback/reopen routes=3; candidate publications=0");
}

#[test]
fn uncertain_append_rollback_poisons_until_admitted_replay() {
    let mut cases = 0;
    for operation in ["resize", "sync"] {
        let mut f = append_fixture();
        let before = primary(&f);
        let faults = f.overlay.fault_control();
        faults.arm(
            "overlay.journal.append",
            "partial",
            1,
            FaultAction::Short(3),
        );
        f.io.0.lock().unwrap().fail = Some(operation);
        let result = f.overlay.namespace_record(
            &mut f.store,
            &f.owner,
            Record::Create {
                at: at("new"),
                kind: codec::CreateKind::Dir,
            },
        );
        assert_eq!(
            (
                result.err().map(|e| e.to_string()),
                f.overlay.readiness(),
                primary(&f) == before,
                faults.fired().len()
            ),
            (
                Some("overlay persistence poisoned".into()),
                OverlayReadiness::Poisoned,
                true,
                1
            ),
            "rollback operation={operation}"
        );
        assert_eq!(
            f.overlay
                .query_path(&f.store, &f.owner, &[])
                .err()
                .map(|e| e.to_string()),
            Some("overlay persistence poisoned".into())
        );
        f.reopen().unwrap();
        assert_eq!(
            (primary(&f), answers(&mut f)),
            (before, Ok([1, 1, 1, 2, 2]))
        );
        cases += 1;
    }
    assert_eq!(cases, 2, "nonzero uncertain rollback routes: {cases}");
    eprintln!("uncertain rollback routes=2; sticky refusals=2; admitted replay rebuilds=2");
}
