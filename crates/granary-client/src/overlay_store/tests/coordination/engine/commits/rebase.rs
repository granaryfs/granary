// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_core::{
    retained_submission::{self as retained, Candidate, Evidence, Role, Submission},
    root,
};

mod stages;

pub(super) fn load(fixture: &Fixture) -> Submission {
    let mut local = fixture.store.lock().unwrap();
    let scope = local.snapshot().scope.clone();
    let volume = local.snapshot().volume.clone();
    local
        .publication_transaction(|j| j.load(&scope, &volume))
        .unwrap()
        .unwrap()
}

pub(super) fn signed(mut doc: root::RootDoc) -> Vec<u8> {
    let key = SigningKey::from_seed(&[39; 32]).unwrap();
    doc.sigs.clear();
    doc.sigs.push(granary_core::root::RootSig {
        key_id: key.key_id(),
        sig: key.sign(&root::signing_prefix_of(&doc).unwrap()),
    });
    root::encode_root(&doc).unwrap()
}

pub(super) async fn foreign_head(fixture: &Fixture, path: &str) -> Vec<u8> {
    foreign_heads(fixture, &[path]).await
}

pub(super) async fn foreign_heads(fixture: &Fixture, paths: &[&str]) -> Vec<u8> {
    let tree = manifest::build_dir(
        &paths
            .iter()
            .map(|path| manifest::DirEntry {
                name: granary_core::manifest::Name::new(path.as_bytes().to_vec()).unwrap(),
                kind: EntryKind::File {
                    exec: false,
                    size: 0,
                    grains: FileGrains::Inline(vec![]),
                },
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    for (id, bytes) in tree.nodes {
        fixture.content.put_object(id, &bytes).unwrap();
    }
    let initial = root::decode_root(&load(fixture).frozen.initial_root).unwrap();
    let prepared = crate::prepare_from_manifest(
        fixture.remote.as_ref(),
        fixture.content.as_ref(),
        tree.root,
        crate::HarvestStats::default(),
        &initial.volume,
        &SigningKey::from_seed(&[39; 32]).unwrap(),
        &granary_core::identity::WriterIdentity::from_bytes([77; 16]),
        initial.timestamp,
        crate::Policy::default(),
    )
    .await
    .unwrap();
    fixture.remote.published.lock().unwrap().insert(
        root::decode_root(&prepared.root_bytes).unwrap().seq,
        prepared.root_bytes.clone(),
    );
    prepared.root_bytes
}

#[tokio::test]
async fn overlapping_merge_is_a_typed_conflict_and_fences_dispatch() {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let head = foreign_head(&fixture, "local").await;
    let record = load(&fixture);
    let error = fixture
        .engine
        .rebase_commit_manifest(&lane, &record.frozen, Some(GrainId::of(&head)), 3)
        .await
        .unwrap_err();
    assert_eq!(
        (error.kind, error.reason.as_str()),
        (
            crate::PublicationStoreErrorKind::Conflict,
            "overlay namespace conflict"
        )
    );
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .push_back(PublishPlan::StaleCurrent);
    let error = Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap_err();
    assert!(
        matches!(error, CoordinationError::Fenced { .. }),
        "{error:?}"
    );
    assert_eq!(
        crate::writable_start::sync_mount_error(&error),
        granary_fuse::MountSyncError::Backend(granary_fuse::MountError::Stale)
    );
    assert_eq!(fixture.remote.publication_sends.lock().unwrap().len(), 0);
}

/// A projected lane's rebase refuses as a conflict, before any candidate is
/// dispatched, when the merged base differs from the projection where its
/// residual replays: here a file created after the boundary that the remote
/// head also creates. A disjoint remote file merges, although the head lacks
/// the selected file the residual re-binds for its later truncate; the merged
/// base still has it.
#[tokio::test]
async fn a_projected_rebase_refuses_a_remote_change_at_a_residual_path() {
    use granary_core::overlay_journal::ProjectedSelection;
    let mut outcomes = Vec::new();
    for remote in ["z", "y"] {
        let fixture = Fixture::new().await;
        let stage = fixture.create("x", b"captured");
        fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        // After the boundary, with no staging bytes a restart could lose.
        fixture.create("y", b"");
        fixture
            .store
            .lock()
            .unwrap()
            .overlay_transaction(|t| t.truncate(stage, 4))
            .unwrap();
        {
            let mut model = fixture.io.0.lock().unwrap();
            let id = *model
                .names
                .iter()
                .find(|(path, _)| path.file_name().unwrap() == "journal")
                .unwrap()
                .1;
            let file = model.files.get_mut(&id).unwrap();
            file.1 = file.0.clone();
        }
        let fixture = fixture.restart().await;
        let captured = fixture
            .content
            .payloads
            .lock()
            .unwrap()
            .iter()
            .find_map(|(id, (size, _))| (*size == 8).then_some(*id))
            .unwrap();
        project_durable_boundaries(
            &fixture.io,
            Some(ProjectedSelection {
                stage_id: stage,
                content: captured,
                size: 8,
            }),
            None,
        );
        let lane = fixture
            .engine
            .recover_commit(SyncOptions::default())
            .unwrap();
        let head = foreign_head(&fixture, remote).await;
        let record = load(&fixture);
        let result = fixture
            .engine
            .rebase_commit_manifest(&lane, &record.frozen, Some(GrainId::of(&head)), 3)
            .await;
        outcomes.push((
            remote,
            result.map(|_| ()).map_err(|e| (e.kind, e.reason)),
            fixture.remote.publication_sends.lock().unwrap().len(),
        ));
    }
    assert_eq!(
        outcomes,
        [
            ("z", Ok(()), 0),
            (
                "y",
                Err((
                    crate::PublicationStoreErrorKind::Conflict,
                    "overlay namespace conflict".to_owned()
                )),
                0
            ),
        ]
    );
}

#[tokio::test]
async fn remote_rebase_failures_are_unavailable_without_publication() {
    for case in ["missing root", "untrusted head", "unavailable source"] {
        let fixture = Fixture::new().await;
        fixture.create("local", b"sealed");
        let lane = fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        let head = foreign_head(&fixture, "remote").await;
        let record = load(&fixture);
        match case {
            "missing root" => {
                fixture.remote.published.lock().unwrap().remove(&2);
            }
            "untrusted head" => {
                let mut doc = root::decode_root(&head).unwrap();
                doc.sigs.first_mut().unwrap().sig = [0; 64];
                fixture
                    .remote
                    .published
                    .lock()
                    .unwrap()
                    .insert(2, root::encode_root(&doc).unwrap());
            }
            _ => fixture.content.unavailable.store(true, Ordering::Relaxed),
        }
        let error = fixture
            .engine
            .rebase_commit_manifest(&lane, &record.frozen, Some(GrainId::of(&head)), 3)
            .await
            .unwrap_err();
        assert_eq!(
            (
                error.kind,
                error.reason.as_str(),
                fixture.remote.publication_sends.lock().unwrap().len()
            ),
            (
                crate::PublicationStoreErrorKind::Unavailable,
                "intent refused: SyncCommitRebaseUnavailable",
                0
            ),
            "{case}"
        );
    }
}

#[tokio::test]
async fn unavailable_reads_during_recomputation_remain_unavailable() {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let head = foreign_head(&fixture, "remote").await;
    let record = load(&fixture);
    let before = fixture.content.gets.load(Ordering::Relaxed);
    fixture
        .engine
        .rebase_commit_manifest(&lane, &record.frozen, Some(GrainId::of(&head)), 3)
        .await
        .unwrap();
    let reads = fixture.content.gets.load(Ordering::Relaxed) - before;
    assert!(reads > 0, "successful recomputation read count: {reads}");
    for offset in 1..=reads {
        fixture.content.fail_get.store(
            fixture.content.gets.load(Ordering::Relaxed) + offset,
            Ordering::Relaxed,
        );
        let result = fixture
            .engine
            .rebase_commit_manifest(&lane, &record.frozen, Some(GrainId::of(&head)), 3)
            .await;
        assert_eq!(
            (
                result.as_ref().err().map(|error| error.kind),
                fixture.remote.publication_sends.lock().unwrap().len()
            ),
            (Some(crate::PublicationStoreErrorKind::Unavailable), 0),
            "read {offset}/{reads}: {result:?}"
        );
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one suffix collision compares its loud refusal and all retained acknowledgement evidence"
)]
async fn landed_suffix_conflict_fences_without_replacing_acknowledged_work() {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    for _ in 0..3 {
        fixture
            .store
            .lock()
            .unwrap()
            .observe_commit(crate::CommitResult::Ok);
    }
    foreign_head(&fixture, "remote").await;
    let stage = fixture.create("remote", b"acknowledged suffix");
    let stages = || {
        let model = fixture.io.0.lock().unwrap();
        model
            .names
            .iter()
            .filter(|(p, _)| {
                p.parent().and_then(std::path::Path::file_name)
                    == Some(std::ffi::OsStr::new("staging"))
            })
            .map(|(p, id)| (p.clone(), model.files.get(id).unwrap().0.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let before = stages();
    let journal = fixture
        .io
        .0
        .lock()
        .unwrap()
        .names
        .keys()
        .find(|p| p.file_name() == Some(std::ffi::OsStr::new("journal")))
        .unwrap()
        .clone();
    let old = fixture.io.bytes(&journal);
    fixture
        .remote
        .publication_plan
        .lock()
        .unwrap()
        .extend([PublishPlan::StaleCurrent, PublishPlan::Land]);
    let log = TimingLog::default();
    let guard = tracing::subscriber::set_default(crate::observe::subscriber(
        crate::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("trace"),
        log.clone(),
    ));
    let error = Box::pin(fixture.engine.drive_commit(
        &lane,
        &mut Entropy(80),
        &mut Delay,
        RecoveryIntent::Continue,
        SyncOptions::default(),
    ))
    .await
    .unwrap_err();
    assert!(
        matches!(error, CoordinationError::Fenced { .. }),
        "{error:?}"
    );
    assert_eq!(
        (
            super::reporting::counter(
                &fixture,
                "granary_client_commits_total{result=\"conflict\"}"
            ),
            fixture
                .metrics()
                .contains("granary_client_contention_flag 1\n")
        ),
        (1, true),
        "same-path suffix outcome: {}",
        fixture.metrics()
    );
    drop(guard);
    let text = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    let conflicts: Vec<_> = text
        .lines()
        .filter(|line| line.contains("\"event\":\"op.conflict\""))
        .collect();
    assert_eq!(
        (
            conflicts.len(),
            conflicts
                .iter()
                .all(|line| line.contains("\"path\":\"<file>\"")),
            text.contains("remote")
        ),
        (1, true, false),
        "suffix conflict path: {text}"
    );
    let after = fixture.io.bytes(&journal);
    let root = GrainId::of(fixture.remote.published.lock().unwrap().get(&3).unwrap());
    let mut landed = false;
    granary_core::overlay_journal::scan_journal_with(&after, |_, record| {
        if matches!(record, granary_core::overlay_journal::Record::LandedCommit { landed_root, landed_seq: 3, .. } if *landed_root == root) {
            landed = true;
        }
    }).unwrap();
    assert_eq!(
        (
            after.starts_with(&old),
            stages(),
            landed,
            fixture.remote.publication_sends.lock().unwrap().len()
        ),
        (true, before, true, 2)
    );
    let error = fixture
        .store
        .lock()
        .unwrap()
        .overlay_transaction(|t| t.write(stage, 0, b"later"))
        .unwrap_err();
    assert!(
        matches!(error, CoordinationError::Fenced { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn unmoved_remote_keeps_the_frozen_manifest_without_a_merge_walk() {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let mut record = load(&fixture);
    let initial = root::decode_root(&record.frozen.initial_root).unwrap();
    fixture.remote.offline.store(true, Ordering::Relaxed);
    let before = fixture.remote.root_reads.load(Ordering::Relaxed);
    let result = fixture
        .engine
        .rebase_commit_manifest(&lane, &record.frozen, initial.parent, initial.seq)
        .await;
    assert_eq!(
        (
            result.as_ref().ok().copied(),
            fixture.remote.root_reads.load(Ordering::Relaxed) - before
        ),
        (Some(initial.manifest_root), 0),
        "unmoved preparation: {result:?}"
    );
    record.candidates.first_mut().unwrap().number = 2;
    retained::validate(&record).unwrap();
}

#[tokio::test]
async fn offline_rebased_restart_reconstructs_a_pending_lane_before_dispatch_verification() {
    for forged in [false, true] {
        let fixture = Fixture::new().await;
        fixture.create("local", b"sealed");
        let lane = fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        let record = replacement(&fixture, forged).await;
        fixture
            .store
            .lock()
            .unwrap()
            .publication_transaction(|j| j.replace(record.generation - 1, &record))
            .unwrap();
        drop(lane);
        let fixture = fixture.restart().await;
        fixture.remote.offline.store(true, Ordering::Relaxed);
        let before = fixture.remote.root_reads.load(Ordering::Relaxed);
        let recovered = fixture.engine.recover_commit(SyncOptions::default());
        assert_eq!(
            (
                recovered.is_ok(),
                fixture.remote.root_reads.load(Ordering::Relaxed) - before
            ),
            (true, 0),
            "offline recovery, forged={forged}: {recovered:?}"
        );
        let lane = recovered.unwrap();
        assert_eq!(load(&fixture).phase, retained::Phase::Ready);
        assert!(!fixture.store.lock().unwrap().sync_admission_open().unwrap());
        if forged {
            fixture.remote.offline.store(false, Ordering::Relaxed);
            let error = Box::pin(fixture.engine.drive_commit(
                &lane,
                &mut Entropy(80),
                &mut Delay,
                RecoveryIntent::Continue,
                SyncOptions::default(),
            ))
            .await
            .unwrap_err();
            assert_eq!(
                (
                    error.to_string(),
                    fixture.remote.publication_sends.lock().unwrap().len()
                ),
                ("intent refused: SyncCommitRebaseManifest".to_owned(), 0)
            );
        }
    }
}

async fn cheap_landing_refusal(completed: bool) {
    let fixture = Fixture::new().await;
    fixture.create("local", b"sealed");
    let lane = fixture
        .engine
        .construct_commit(SyncOptions::default(), &mut Entropy(70))
        .await
        .unwrap();
    let mut record = replacement(&fixture, false).await;
    let candidate = record.candidates.last().unwrap();
    let done = retained::Completion {
        seq: candidate.seq,
        id: candidate.id,
        root: candidate.root.clone(),
        receipt: None,
    };
    if completed {
        record.phase = retained::Phase::Complete(done.clone());
        record.current = None;
    }
    retained::validate(&record).unwrap();
    fixture
        .store
        .lock()
        .unwrap()
        .publication_transaction(|j| j.replace(record.generation - 1, &record))
        .unwrap();
    fixture.remote.offline.store(true, Ordering::Relaxed);
    let before = fixture.remote.root_reads.load(Ordering::Relaxed);
    let error = fixture
        .engine
        .finish_landed_commit(
            &lane,
            crate::LandedProof {
                boundary_seq: lane.boundary_seq() + 1,
                landed_root: done.id,
                landed_seq: done.seq,
                captured_entries: vec![],
                entries: vec![],
            },
            SyncOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (
            error.to_string(),
            fixture.remote.root_reads.load(Ordering::Relaxed) - before
        ),
        (
            if completed {
                "intent refused: SyncCommitLandingBinding"
            } else {
                "intent refused: SyncCommitUnresolved"
            }
            .to_owned(),
            0
        )
    );
}

#[tokio::test]
async fn unresolved_landing_refuses_before_remote_verification() {
    cheap_landing_refusal(false).await;
}
#[tokio::test]
async fn unbound_landing_refuses_before_remote_verification() {
    cheap_landing_refusal(true).await;
}

async fn replacement(fixture: &Fixture, forged: bool) -> Submission {
    let mut record = load(fixture);
    let initial = root::decode_root(&record.frozen.initial_root).unwrap();
    let base = fixture
        .remote
        .published
        .lock()
        .unwrap()
        .get(&1)
        .unwrap()
        .clone();
    let base = root::decode_root(&base).unwrap();
    let prepared = crate::prepare_from_manifest(
        fixture.remote.as_ref(),
        &fixture
            .remote
            .objects
            .read_objects(base.binmap_index)
            .unwrap(),
        base.manifest_root,
        crate::HarvestStats::default(),
        &base.volume,
        &SigningKey::from_seed(&[39; 32]).unwrap(),
        &granary_core::identity::WriterIdentity::from_bytes([77; 16]),
        base.timestamp,
        crate::Policy::default(),
    )
    .await
    .unwrap();
    let parent = prepared.root_bytes;
    fixture
        .remote
        .published
        .lock()
        .unwrap()
        .insert(2, parent.clone());
    let mut doc = initial.clone();
    doc.seq = 3;
    doc.parent = Some(GrainId::of(&parent));
    if forged {
        doc.manifest_root = base.manifest_root;
    }
    let bytes = signed(doc);
    record.generation += 1;
    for candidate in &mut record.candidates {
        candidate.role = Role::History;
    }
    record.candidates.push(Candidate {
        number: 2,
        role: Role::Active,
        request: record.current.unwrap(),
        seq: 3,
        id: GrainId::of(&bytes),
        root: bytes,
        evidence: Evidence::default(),
    });
    retained::validate(&record)
        .unwrap_or_else(|error| panic!("structurally valid replacement refused: {error}"));
    record
}

#[tokio::test]
async fn rebased_candidate_manifest_recomputation_guard_catches_unverified_manifest() {
    for forged in [false, true] {
        let fixture = Fixture::new().await;
        fixture.create("local", b"sealed bytes");
        let lane = fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        let record = replacement(&fixture, forged).await;
        let generation = record.generation - 1;
        let result = fixture
            .engine
            .replace_commit_record(&lane, generation, &record)
            .await;
        if forged {
            let error =
                result.expect_err("a signed, structurally valid but incorrect merge was retained");
            assert_eq!(
                (error.kind, error.reason.as_str()),
                (
                    crate::PublicationStoreErrorKind::Corrupt,
                    "intent refused: SyncCommitRebaseManifest"
                )
            );
            // Inject exact tampered durable bytes beneath the publication adapter.
            fixture
                .store
                .lock()
                .unwrap()
                .publication_transaction(|j| j.replace(generation, &record))
                .unwrap();
            let driven = Box::pin(fixture.engine.drive_commit(
                &lane,
                &mut Entropy(80),
                &mut Delay,
                RecoveryIntent::Continue,
                SyncOptions::default(),
            ))
            .await
            .unwrap_err();
            assert_eq!(
                (driven.to_string(), crate::sync::failure_class(&driven)),
                (
                    "intent refused: SyncCommitRebaseManifest".to_owned(),
                    crate::observe::FailureClass::Corrupt
                )
            );
        } else {
            result.unwrap();
        }
        drop(lane);
        // Keep only the mount base warm: immutable frozen content must come
        // back from its signed binmap rather than the mutable staging file.
        let base_manifest =
            root::decode_root(fixture.remote.published.lock().unwrap().get(&1).unwrap())
                .unwrap()
                .manifest_root;
        fixture
            .content
            .objects
            .lock()
            .unwrap()
            .retain(|id, _| *id == base_manifest);
        fixture.content.payloads.lock().unwrap().clear();
        let fixture = fixture.restart().await;
        let recovered = fixture
            .engine
            .recover_commit(SyncOptions::default())
            .unwrap();
        if forged {
            let error = Box::pin(fixture.engine.drive_commit(
                &recovered,
                &mut Entropy(80),
                &mut Delay,
                RecoveryIntent::Continue,
                SyncOptions::default(),
            ))
            .await
            .unwrap_err();
            assert_eq!(
                (error.to_string(), crate::sync::failure_class(&error)),
                (
                    "intent refused: SyncCommitRebaseManifest".to_owned(),
                    crate::observe::FailureClass::Corrupt
                )
            );
        }
        assert_eq!(
            fixture.remote.publication_sends.lock().unwrap().len(),
            0,
            "recomputation must precede publication, forged={forged}"
        );
    }
}

#[tokio::test]
async fn retained_merge_is_checked_before_initial_record_admission() {
    for forged in [false, true] {
        let donor = Fixture::new().await;
        donor.create("local", b"sealed bytes");
        let lane = donor
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        let mut record = replacement(&donor, forged).await;
        donor.remote.published.lock().unwrap().remove(&2);
        let head = foreign_head(&donor, "remote").await;
        let manifest = donor
            .engine
            .rebase_commit_manifest(&lane, &record.frozen, Some(GrainId::of(&head)), 3)
            .await
            .unwrap();
        let merged =
            crate::writable_store::capture::entries(donor.content.as_ref(), manifest, 1).unwrap();
        assert_eq!(
            merged
                .iter()
                .map(|entry| entry.name.as_bytes())
                .collect::<Vec<_>>(),
            vec![b"local".as_slice(), b"remote".as_slice()]
        );
        let candidate = record.candidates.last_mut().unwrap();
        let mut doc = root::decode_root(&candidate.root).unwrap();
        doc.parent = Some(GrainId::of(&head));
        if !forged {
            doc.manifest_root = manifest;
        }
        candidate.root = signed(doc);
        candidate.id = GrainId::of(&candidate.root);
        retained::validate(&record).unwrap();
        let fixture = Fixture::new().await;
        fixture.create("local", b"sealed bytes");
        fixture
            .content
            .objects
            .lock()
            .unwrap()
            .extend(donor.content.objects.lock().unwrap().clone());
        fixture
            .content
            .payloads
            .lock()
            .unwrap()
            .extend(donor.content.payloads.lock().unwrap().clone());
        let head = donor
            .remote
            .published
            .lock()
            .unwrap()
            .get(&2)
            .unwrap()
            .clone();
        fixture.remote.published.lock().unwrap().insert(2, head);
        fixture.remote.objects.restore(donor.remote.objects.dump());
        let capture = fixture
            .engine
            .begin_commit(SyncOptions::default())
            .await
            .unwrap();
        let error = fixture
            .engine
            .retain_commit(capture, &record)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            if forged {
                "intent refused: SyncCommitRebaseManifest"
            } else {
                "intent refused: SyncCommitCandidateBinding"
            },
            "forged={forged}"
        );
        assert!(fixture.remote.publication_sends.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn retained_merge_authenticates_parent_identity_and_ancestry() {
    for broken in ["candidate parent", "head ancestry", "missing head"] {
        let fixture = Fixture::new().await;
        fixture.create("local", b"sealed bytes");
        let lane = fixture
            .engine
            .construct_commit(SyncOptions::default(), &mut Entropy(70))
            .await
            .unwrap();
        let mut record = replacement(&fixture, false).await;
        let candidate = record.candidates.last_mut().unwrap();
        let mut doc = root::decode_root(&candidate.root).unwrap();
        if broken == "candidate parent" {
            doc.parent = Some(GrainId::of(b"substituted parent"));
        } else if broken == "head ancestry" {
            let head = fixture
                .remote
                .published
                .lock()
                .unwrap()
                .get(&2)
                .unwrap()
                .clone();
            let mut head = root::decode_root(&head).unwrap();
            head.parent = Some(GrainId::of(b"substituted ancestor"));
            let head = signed(head);
            doc.parent = Some(GrainId::of(&head));
            fixture.remote.published.lock().unwrap().insert(2, head);
        } else {
            fixture.remote.published.lock().unwrap().remove(&2);
        }
        candidate.root = signed(doc);
        candidate.id = GrainId::of(&candidate.root);
        retained::validate(&record).unwrap();
        let error = fixture
            .engine
            .replace_commit_record(&lane, record.generation - 1, &record)
            .await
            .unwrap_err();
        assert_eq!(
            (error.kind, error.reason.as_str()),
            (
                crate::PublicationStoreErrorKind::Unavailable,
                "intent refused: SyncCommitRebaseUnavailable"
            ),
            "{broken}"
        );
        assert!(fixture.remote.publication_sends.lock().unwrap().is_empty());
    }
}
