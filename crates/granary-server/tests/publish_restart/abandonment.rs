// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{continuation, support::*};
use granary_core::{
    authlog::Epoch,
    authority_answer::{self as answer, Head, VolumeStatus},
    retained_archive::ArchiveName,
    retained_submission::{self as retained, Phase, Role, Submission},
};
use std::{
    collections::BTreeSet, os::unix::fs::PermissionsExt as _, path::PathBuf, process::Command,
};
use tokio::io::AsyncWriteExt as _;

fn abandon(fx: &Fixture, old: &Submission) -> Command {
    let mut cmd = fx.command(true);
    cmd.args([
        "--abandon",
        &hex(&old.publication_id),
        "--acknowledge-may-land",
    ]);
    cmd
}

fn archive_path(fx: &Fixture, old: &Submission) -> PathBuf {
    fx.store
        .join("publications")
        .join(old.scope.digest().unwrap())
        .join(
            ArchiveName {
                settled: false,
                volume: old.volume.clone(),
                publication_id: old.publication_id,
            }
            .file_name(),
        )
}

#[test]
fn c9_pending_retired_fixture_preserves_checked_open_and_uncertainty() {
    let mut pending = retained::decode(include_bytes!(
        "../../../granary-core/tests/vectors/retained-submission/ready.bin"
    ))
    .unwrap();
    let c = &mut pending.candidates[0];
    c.evidence = retained::Evidence {
        started: 2,
        last_answered_attempt: 2,
        proved_no_write: 0,
        decision_seen: true,
    };
    pending.last_response = Some(retained::LastResponse {
        candidate: c.number,
        attempt: 2,
        status: 202,
        token: Vec::new(),
        answer: answer::encode(answer::PublishAnswer::Open {
            position: answer::Position {
                epoch: Epoch::from_bytes(c.request.epoch),
                entry_seq: 1,
            },
            candidate_id: c.id,
        })
        .unwrap(),
    });
    pending.phase = Phase::Ready;
    retained::validate(&pending).unwrap();
    let with_history = with_retired_slot(pending.clone());
    assert_eq!(with_history.candidates[0], pending.candidates[0]);
    assert_eq!(with_history.last_response, pending.last_response);
    assert_eq!(with_history.candidates[1].role, Role::Retired);
    assert!(!with_history.candidates[1].evidence.never_decided());
    assert_eq!(
        retained::decode(&retained::encode(&with_history).unwrap()).unwrap(),
        with_history
    );
    observe(
        "abandonment::c9_pending_retired_fixture_preserves_checked_open_and_uncertainty",
        &[],
    );
}

async fn fixture(fx: &Fixture, capacity: bool) -> Submission {
    let old = if capacity {
        let old = continuation::capacity_fixture(fx).await;
        let mut cmd = fx.command(true);
        cmd.args(["--recover", &hex(&old.publication_id)]);
        let json = run(&mut cmd, 5).await;
        assert!(
            json.contains("candidate capacity exhausted")
                && json.contains("\"outcome\":\"unresolved\""),
            "{json}"
        );
        assert_eq!(fx.transcript(), live_barrier([probe(None)], None));
        fx.record().unwrap()
    } else {
        let old = continuation::uncertain(fx).await;
        let foreign = continuation::foreign(fx, &old);
        fx.peer
            .lock()
            .unwrap()
            .replies
            .push_back(continuation::answer_reply("open", &old, &foreign));
        let json = run(&mut fx.command(true), 3).await;
        assert!(
            json.contains("possible wedge") && json.contains("\"outcome\":\"pending\""),
            "{json}"
        );
        let pending = fx.record().unwrap();
        // Disclosed catalogue setup: add the existing validated retired-slot
        // fixture to a CLI-produced foreign/open Pending record. Abandonment
        // must preserve that history without probing or classifying its slot.
        let old = with_retired_slot(pending);
        fx.install(&old);
        old
    };
    assert!(
        old.candidates
            .iter()
            .any(|c| c.role == Role::Retired && !c.evidence.never_decided())
    );
    assert!(!old.is_complete());
    retained::validate(&old).unwrap();
    fx.reset_transcript();
    old
}

fn assert_evidence(old: &Submission, after: &Submission) {
    assert_catalogue(old, after);
    assert_eq!(old.phase, after.phase, "archival fabricated a destination");
}

fn assert_archive(fx: &Fixture, old: &Submission, generation: u64) -> (Submission, Vec<u8>) {
    assert!(fx.record().is_none(), "archival left a live target");
    let archives = fx.archives();
    assert_eq!(archives.len(), 1);
    let (path, bytes, record) = &archives[0];
    assert_eq!(*path, archive_path(fx, old));
    assert_evidence(old, record);
    assert_eq!(record.generation, generation);
    assert_eq!(retained::encode(record).unwrap(), *bytes);
    assert!(
        fx.transcript().is_empty(),
        "abandonment issued network work"
    );
    (record.clone(), bytes.clone())
}

async fn resume_archive(fx: &Fixture, old: &Submission, generation: u64) -> Vec<u8> {
    let json = run(&mut abandon(fx, old), 0).await;
    assert_abandoned_report(&json, old);
    let (_, bytes) = assert_archive(fx, old, generation);
    let json = run(&mut abandon(fx, old), 0).await;
    assert_abandoned_report(&json, old);
    assert_eq!(
        assert_archive(fx, old, generation).1,
        bytes,
        "retry rewrote archive"
    );
    for recover in [false, true] {
        let mut cmd = fx.command(true);
        if recover {
            cmd.args(["--recover", &hex(&old.publication_id)]);
        }
        let json = run(&mut cmd, 4).await;
        assert!(
            json.contains("\"outcome\":\"refused\"") && json.contains("archiv"),
            "{json}"
        );
        assert_eq!(assert_archive(fx, old, generation).1, bytes);
    }
    bytes
}

#[tokio::test]
async fn c9_abandonment_cuts_preserve_capacity_and_foreign_open_history() {
    let mut observed = Vec::new();
    for capacity in [true, false] {
        for name in [
            "abandon-save",
            "archive-rename",
            "archive-sync",
            "output-write",
        ] {
            for side in ["before", "after"] {
                let fx = Fixture::new().await;
                let old = fixture(&fx, capacity).await;
                let event = cut_command(&fx, &mut abandon(&fx, &old), name, side, 1).await;
                assert_eq!(event.id, hex(&old.publication_id));
                assert!(fx.transcript().is_empty());
                assert_eq!(event.generation, old.generation + 1);
                let moved = name == "archive-rename" && side == "after"
                    || name == "archive-sync"
                    || name == "output-write";
                let generation = if moved {
                    assert_archive(&fx, &old, old.generation + 1);
                    old.generation + 1
                } else {
                    assert!(fx.archives().is_empty());
                    let live = fx.record().unwrap();
                    assert_evidence(&old, &live);
                    let saved = name != "abandon-save" || side == "after";
                    assert_eq!(live.generation, old.generation + u64::from(saved));
                    live.generation + 1
                };
                resume_archive(&fx, &old, generation).await;
                observed.push(format!("{name}:{side}"));
            }
        }
    }
    observed.sort();
    observed.dedup();
    observe(
        "abandonment::c9_abandonment_cuts_preserve_capacity_and_foreign_open_history",
        &observed,
    );
}

#[tokio::test]
async fn c9_abandon_save_physical_cuts_keep_whole_catalogues() {
    let mut observed = Vec::new();
    for capacity in [true, false] {
        for name in physical_registry() {
            for side in ["before", "after"] {
                let fx = Fixture::new().await;
                let old = fixture(&fx, capacity).await;
                let event = cut_command(&fx, &mut abandon(&fx, &old), &name, side, 1).await;
                assert_eq!(event.id, hex(&old.publication_id));
                assert_eq!(event.generation, old.generation + 1);
                let new = name == "scope-sync" || name == "temporary-install" && side == "after";
                let mut expected = old.clone();
                expected.generation += u64::from(new);
                assert_eq!(
                    fx.record().unwrap(),
                    expected,
                    "abandonment physical cut {name}:{side}"
                );
                assert!(fx.archives().is_empty());
                assert!(fx.transcript().is_empty());
                resume_archive(&fx, &old, expected.generation + 1).await;
                observed.push(format!("abandon-save:{name}:{side}:1"));
            }
        }
    }
    observed.sort();
    observed.dedup();
    observe(
        "abandonment::c9_abandon_save_physical_cuts_keep_whole_catalogues",
        &observed,
    );
}

async fn injected_failure(fx: &Fixture, old: &Submission, name: &str, side: &str) {
    let mut cmd = abandon(fx, old);
    let rendezvous = Rendezvous::arm(&mut cmd, &fx.scratch.0, name, side, 1);
    let mut child = Process::spawn(&mut cmd);
    let (event, mut stream) = rendezvous.reached(&mut child).await.unwrap();
    event.matches(name, side, 1).unwrap();
    let live = fx.record();
    let archives = fx.archives();
    stream.write_all(b"fail\n").await.unwrap();
    let json = assert_exit(&child.output().await, 1);
    assert!(!json.contains("\"outcome\":\"abandoned\""), "{json}");
    assert_eq!(fx.record(), live);
    assert_eq!(fx.archives(), archives);
    if side == "after" {
        assert_archive(fx, old, old.generation + 1);
    }
    assert!(
        fx.transcript().is_empty(),
        "failed archive barrier allowed network"
    );
    println!("REFUSED injected archive failure at {name}:{side}");
}

#[tokio::test]
async fn c9_archive_resync_and_failure_controls() {
    let mut observed = Vec::new();
    for capacity in [true, false] {
        for name in archive_registry() {
            for side in ["before", "after"] {
                let fx = Fixture::new().await;
                let old = fixture(&fx, capacity).await;
                let json = run(&mut abandon(&fx, &old), 0).await;
                assert_abandoned_report(&json, &old);
                let (_, bytes) = assert_archive(&fx, &old, old.generation + 1);
                let event = cut_command(&fx, &mut abandon(&fx, &old), &name, side, 1).await;
                assert_eq!(event.id, hex(&old.publication_id));
                assert_eq!(event.generation, old.generation + 1);
                assert_eq!(assert_archive(&fx, &old, event.generation).1, bytes);
                injected_failure(&fx, &old, &name, side).await;
                assert_eq!(resume_archive(&fx, &old, event.generation).await, bytes);
                observed.push(format!("{name}:{side}"));
            }
        }
        for name in [
            "abandon-save",
            "temporary-sync",
            "scope-sync",
            "archive-rename",
            "archive-sync",
        ] {
            let fx = Fixture::new().await;
            let old = fixture(&fx, capacity).await;
            injected_failure(&fx, &old, name, "before").await;
            let generation = fx
                .record()
                .map_or(old.generation + 1, |live| live.generation + 1);
            resume_archive(&fx, &old, generation).await;
        }
    }
    observed.sort();
    observed.dedup();
    observe(
        "abandonment::c9_archive_resync_and_failure_controls",
        &observed,
    );
}

#[tokio::test]
async fn c9_no_replace_and_explicit_new_controls() {
    for capacity in [true, false] {
        let fx = Fixture::new().await;
        let old = fixture(&fx, capacity).await;
        let path = archive_path(&fx, &old);
        let mut collision = old.clone();
        collision.generation += 2;
        let bytes = retained::encode(&collision).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let json = run(&mut abandon(&fx, &old), 1).await;
        assert!(!json.contains("\"outcome\":\"abandoned\""), "{json}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "archival overwrote a collision"
        );
        assert_eq!(fx.record().unwrap(), old);
        assert!(fx.transcript().is_empty());
        std::fs::remove_file(&path).unwrap();
        let archived = resume_archive(&fx, &old, old.generation + 1).await;
        // --new is itself the explicit acknowledgement. The separate
        // acknowledgement flag is reserved for --abandon.
        let mut invalid = fx.command(false);
        invalid.args(["--new", "--acknowledge-may-land"]);
        let json = run(&mut invalid, 2).await;
        assert!(
            json.contains("--acknowledge-may-land requires --abandon"),
            "{json}"
        );
        assert!(fx.transcript().is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), archived);
        let previous: BTreeSet<_> = fx.peer.lock().unwrap().objects.keys().cloned().collect();
        let base = fx.peer.lock().unwrap().roots.get(ROOT_PATH).cloned();
        let mut new = fx.command(false);
        new.arg("--new");
        cut_command(&fx, &mut new, "begin", "after", 1).await;
        let new = fx.record().unwrap();
        assert_ne!(new.publication_id, old.publication_id);
        assert!(
            old.candidates
                .iter()
                .all(|c| c.request.operation != new.current.unwrap().operation)
        );
        let status = answer::encode_status(VolumeStatus {
            epoch: Epoch::from_bytes(EPOCH),
            head: Some(Head::new(None)),
            open: None,
        })
        .unwrap();
        let mut expected = vec![
            request(
                "GET",
                "/volume/alpha/status",
                Vec::new(),
                200,
                status.clone(),
            ),
            request("GET", "/volume/alpha/status", Vec::new(), 200, status),
        ];
        expected.extend(continuation::preparation(
            &fx,
            &new,
            &previous,
            base.as_deref(),
        ));
        assert_eq!(fx.transcript(), expected);
        fx.reset_transcript();
        let json = run(&mut fx.command(true), 0).await;
        assert_landed_report(&json, &new);
        let candidate = &new.candidates[0];
        let head = base.as_ref().map(|_| old.candidates[0].seq);
        let mut expected = live_barrier(
            [request(
                "GET",
                &format!("/volume/alpha/root/{:020}", candidate.seq),
                Vec::new(),
                404,
                Vec::new(),
            )],
            head,
        );
        expected.extend([
            post(&new),
            request(
                "PUT",
                "/volume/alpha/hint",
                format!("{:020}", candidate.seq).into_bytes(),
                204,
                Vec::new(),
            ),
        ]);
        assert_eq!(fx.transcript(), expected);
        assert_eq!(fx.peer.lock().unwrap().landings, 1);
        assert_eq!(std::fs::read(&path).unwrap(), archived);
        assert_eq!(fx.archives().len(), 1);
        if let Some(base) = base {
            assert_eq!(fx.peer.lock().unwrap().roots[ROOT_PATH], base);
        }
        assert!(matches!(fx.record().unwrap().phase, Phase::Complete(_)));
    }
    observe("abandonment::c9_no_replace_and_explicit_new_controls", &[]);
}
