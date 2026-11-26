// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_core::{manifest::Name, retained_submission as submission};
use granary_fuse::OverlayMutation as M;
use object_store::ObjectStoreExt as _;

mod archive_rows;

fn sealed(advanced: bool, bytes: &[u8], empty_files: usize) -> Stopped {
    let (cut, stopped) = recorded_landing(
        crate::SyncProfile::DurablePrepared,
        if advanced { &["remote.txt"] } else { &[] },
        bytes,
        empty_files,
    );
    let input = input(&stopped.tree, &stopped.paths);
    let (header, mut records) = captured_records(&stopped.paths, &input);
    let landed = records.iter().find_map(|r| match r {
        Record::LandedCommit {
            boundary_seq,
            landed_root,
            landed_seq,
        } => Some((*boundary_seq, *landed_root, *landed_seq)),
        _ => None,
    });
    assert_eq!(
        (cut, landed.is_some()),
        (
            Outcome::Incomplete(Cause::Failed(crate::FailureClass::Io)),
            true
        ),
        "{records:?}"
    );
    let (boundary_seq, landed_root, landed_seq) = landed.unwrap();
    let publication_id = records
        .iter()
        .find_map(|r| match r {
            Record::CommitBoundary { publication_id, .. } => Some(*publication_id),
            _ => None,
        })
        .unwrap();
    records.push(Record::ResidualDisposition(journal::ResidualDisposition {
        boundary_seq,
        publication_id,
        landed_root,
        landed_seq,
        source_end: records.len() as u64,
        disposition: journal::ResidualMode::KeepLocal,
        collision_count: 1,
        inventory_check: [3; 32],
    }));
    std::fs::write(
        overlay_area(&stopped.paths, &input).join("journal"),
        journal::encode_journal(&header, &records).unwrap(),
    )
    .unwrap();
    let scope = stopped
        .paths
        .store
        .join("publications")
        .join(input.scope.as_ref().unwrap().digest().unwrap());
    let temporary = scope.join(format!("{}.sub.tmp-777", input.volume.as_str()));
    std::fs::write(&temporary, b"retained temporary").unwrap();
    std::fs::set_permissions(temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (content, _) = captured_payload(&stopped);
    let path = object_path(&stopped, content);
    if path.exists() {
        std::fs::remove_file(path).unwrap();
    }
    stopped
}

/// Snapshot every store file, including publication temporaries and CAS objects.
fn store_bytes(root: &Path) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            result.extend(store_bytes(&path));
        } else {
            result.insert(path.clone(), std::fs::read(path).unwrap());
        }
    }
    result
}

#[test]
fn residual_preflight_preserves_every_store_file_at_both_entries() {
    assert_ending(|| sealed(false, DIRTY, 0), "RecoveryResidualInventoryCount");
}

fn submission_path(stopped: &Stopped) -> std::path::PathBuf {
    let input = input(&stopped.tree, &stopped.paths);
    stopped
        .paths
        .store
        .join("publications")
        .join(input.scope.as_ref().unwrap().digest().unwrap())
        .join(format!("{}.sub", input.volume.as_str()))
}

fn retained(stopped: &Stopped) -> submission::Submission {
    submission::decode(&std::fs::read(submission_path(stopped)).unwrap()).unwrap()
}

fn object_path(stopped: &Stopped, id: GrainId) -> std::path::PathBuf {
    let hex = id.digest_hex();
    stopped
        .paths
        .store
        .join("objects")
        .join(&hex[..2])
        .join(hex)
}

fn captured_payload(stopped: &Stopped) -> (GrainId, Vec<u8>) {
    let record = retained(stopped);
    let root = root::decode_root(&record.frozen.initial_root).unwrap();
    let store = Store::open(&stopped.paths.store).unwrap();
    let entries = crate::writable_store::capture::entries(&store, root.manifest_root, 1).unwrap();
    let entry = entries
        .iter()
        .find(|entry| entry.name.as_bytes() == b"a")
        .unwrap();
    let EntryKind::File { size, grains, .. } = &entry.kind else {
        panic!("{entry:?}");
    };
    let bytes = manifest::node::file_payload(*size, grains).unwrap();
    (GrainId::of(&bytes), bytes)
}

#[expect(
    clippy::too_many_lines,
    reason = "the source fault table keeps authentication premises and both preservation assertions together"
)]
fn source_refusal(case: &str, expected: &str) {
    assert_ending(
        || {
            let stopped = sealed(false, DIRTY, 0);
            let mut record = retained(&stopped);
            match case {
                "missing" => std::fs::remove_file(submission_path(&stopped)).unwrap(),
                "changed" => {
                    record.publication_id = [99; 16];
                    std::fs::write(
                        submission_path(&stopped),
                        submission::encode(&record).unwrap(),
                    )
                    .unwrap();
                }
                "frozen" => {
                    let mut doc = root::decode_root(&record.frozen.initial_root).unwrap();
                    doc.timestamp.secs += 1;
                    let (seq, parent) = (doc.seq, doc.parent);
                    record.frozen.initial_root =
                        super::super::carry_forward::signed(&stopped.tree.key, doc, seq, parent);
                    std::fs::write(
                        submission_path(&stopped),
                        submission::encode(&record).unwrap(),
                    )
                    .unwrap();
                }
                "signature" => {
                    {
                        let mut local = super::recovery::local_store(&stopped);
                        let remote =
                            Authority::new(&stopped.tree, &stopped.state).with_publication();
                        let keys = granary_store::crypto::TrustedKeys::new([*stopped
                            .tree
                            .key
                            .public_key()])
                        .unwrap();
                        let root = root::decode_root(&record.frozen.initial_root).unwrap();
                        let objects = runtime()
                            .block_on(crate::recovery::read_closure(
                                &remote,
                                local.recovery_store(),
                                &keys,
                                &record.volume,
                                root.manifest_root,
                                Some(&record.frozen),
                            ))
                            .unwrap();
                        let mut journal = crate::RecoveryJournal::new(&mut local, &remote, &keys);
                        for (id, bytes) in objects.retained {
                            crate::PublicationJournal::put_recovered(&mut journal, &id, &bytes)
                                .unwrap();
                        }
                    }
                    let mut doc = root::decode_root(&record.frozen.initial_root).unwrap();
                    doc.sigs.first_mut().unwrap().sig[0] ^= 1;
                    record.frozen.initial_root = root::encode_root(&doc).unwrap();
                    std::fs::write(
                        submission_path(&stopped),
                        submission::encode(&record).unwrap(),
                    )
                    .unwrap();
                    let input = input(&stopped.tree, &stopped.paths);
                    let (header, mut records) = captured_records(&stopped.paths, &input);
                    for record_in_journal in &mut records {
                        if let Record::CommitBoundary { candidate, .. } = record_in_journal {
                            *candidate = GrainId::of(&record.frozen.initial_root);
                        }
                    }
                    std::fs::write(
                        overlay_area(&stopped.paths, &input).join("journal"),
                        journal::encode_journal(&header, &records).unwrap(),
                    )
                    .unwrap();
                }
                "landing" => {
                    let submission::Phase::Complete(done) = &record.phase else {
                        panic!("{record:?}");
                    };
                    let mut doc = root::decode_root(&done.root).unwrap();
                    doc.timestamp.secs += 1;
                    let (seq, parent) = (doc.seq, doc.parent);
                    let bytes =
                        super::super::carry_forward::signed(&stopped.tree.key, doc, seq, parent);
                    let path = object_store::path::Path::from(format!(
                        "root/{}/{}",
                        record.volume.as_str(),
                        granary_core::rootstore::format_hint_body(seq)
                    ));
                    runtime()
                        .block_on(stopped.tree.mem.put(&path, bytes.into()))
                        .unwrap();
                    // The preflight must catch the stored substitution independently of a cached-head check.
                    std::fs::remove_dir_all(&stopped.paths.cache).unwrap();
                }
                "closure" => {
                    let path = object_path(&stopped, GrainId::of(DIRTY));
                    assert!(path.is_file(), "missing fixture grain: {path:?}");
                    std::fs::remove_file(&path).unwrap();
                    std::fs::create_dir(&path).unwrap();
                }
                _ => panic!("unknown fixture case {case}"),
            }
            stopped
        },
        expected,
    );
}

#[test]
fn residual_preflight_refuses_same_sequence_landing_substitution() {
    source_refusal("landing", "RecoveryResidualLandingChanged");
}
#[test]
fn residual_preflight_refuses_changed_capture() {
    source_refusal("changed", "RecoveryResidualCaptureChanged");
}
#[test]
fn residual_preflight_refuses_missing_capture() {
    source_refusal("missing", "RecoveryResidualCaptureMissing");
}
#[test]
fn residual_preflight_refuses_unsigned_capture() {
    source_refusal("signature", "RecoveryResidualCaptureSignature");
}
#[test]
fn residual_preflight_refuses_failed_closure_read() {
    source_refusal("closure", "RecoveryResidualClosure");
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table binds exact sources and distinct namespaces across complete and projected records"
)]
fn residual_authenticated_bundle_binds_both_namespaces_and_journal_base() {
    let mut cases = 0;
    for complete in [false, true] {
        for projected in [false, true] {
            let stopped = sealed(true, DIRTY, 0);
            let mut record = retained(&stopped);
            if !complete {
                record.phase = submission::Phase::Ready;
                record.current = Some(record.candidates.last().unwrap().request);
                std::fs::write(
                    submission_path(&stopped),
                    submission::encode(&record).unwrap(),
                )
                .unwrap();
            }
            let input = input(&stopped.tree, &stopped.paths);
            let path = overlay_area(&stopped.paths, &input).join("journal");
            let (header, mut records) = captured_records(&stopped.paths, &input);
            let (content, _) = captured_payload(&stopped);
            if projected {
                project_records(&stopped, &mut records);
                std::fs::write(&path, journal::encode_journal(&header, &records).unwrap()).unwrap();
            }
            let Record::ResidualDisposition(choice) = records.last().unwrap() else {
                panic!("{records:?}");
            };
            let source = std::fs::read(path).unwrap();
            let before = store_bytes(&stopped.paths.store);
            let rt = runtime();
            let mut local = super::recovery::local_store(&stopped);
            assert_ne!(
                GrainId::of(&local.snapshot().root),
                header.base_root,
                "carrier must differ from journal base: {:?}",
                local.snapshot()
            );
            let opened = local.open_overlay_local(
                header,
                vec![],
                OverlayDisk::new(&stopped.paths.store, input.euid),
                false,
            );
            assert_eq!(
                (
                    opened.as_ref().map_err(ToString::to_string),
                    local
                        .recovery_commits()
                        .err()
                        .map(|error| error.to_string())
                ),
                (
                    Ok(&()),
                    Some("overlay pending ownership reconciliation".to_owned())
                ),
                "complete={complete}, projected={projected}"
            );
            let remote = Authority::new(&stopped.tree, &stopped.state).with_publication();
            let keys =
                granary_store::crypto::TrustedKeys::new([*stopped.tree.key.public_key()]).unwrap();
            let sources = local.residual_sources().unwrap().unwrap();
            let result = rt.block_on(crate::recovery::authenticate_residual_sources(
                &mut local,
                &remote,
                &keys,
                crate::SyncOptions::default().workspace_bytes,
                sources,
            ));
            assert!(
                result.is_ok(),
                "complete={complete}, projected={projected}: {:?}",
                result.as_ref().map(|_| ())
            );
            let evidence = result.unwrap();
            let paths = |entries: &[crate::OverlayEntry]| {
                entries
                    .iter()
                    .map(|entry| {
                        entry
                            .path
                            .iter()
                            .map(|name| String::from_utf8(name.as_bytes().to_vec()).unwrap())
                            .collect::<Vec<_>>()
                            .join("/")
                    })
                    .collect::<Vec<_>>()
            };
            let file = evidence
                .proof
                .captured_entries
                .iter()
                .find(|entry| entry.path == handler_path(b"a"))
                .unwrap();
            let base = rt
                .block_on(
                    stopped
                        .tree
                        .remote
                        .get_root(stopped.tree.volume.as_str(), header.base_seq),
                )
                .unwrap()
                .unwrap();
            assert_eq!(
                (
                    evidence.header,
                    evidence.journal.clone(),
                    evidence.disposition,
                    evidence.base.clone(),
                    evidence.proof.boundary_seq,
                    evidence.proof.landed_root,
                    evidence.proof.landed_seq,
                    paths(&evidence.proof.captured_entries),
                    paths(&evidence.proof.entries),
                    (&file.kind, file.size, file.exec, file.stage_id),
                    store_bytes(&stopped.paths.store) == before
                ),
                (
                    header,
                    source[..source.len()
                        - (4 + granary_core::overlay_journal::LEN_MIN as usize + 110)]
                        .to_vec(),
                    *choice,
                    base,
                    choice.boundary_seq,
                    choice.landed_root,
                    choice.landed_seq,
                    vec!["a", "empty", "f.txt", "original-link", "sub", "sub/g.txt"]
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                    vec![
                        "a",
                        "empty",
                        "f.txt",
                        "original-link",
                        "remote.txt",
                        "sub",
                        "sub/g.txt"
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                    (
                        &crate::OverlayKind::File {
                            content: Some(content)
                        },
                        DIRTY.len() as u64,
                        false,
                        None
                    ),
                    true
                ),
                "complete={complete}, projected={projected}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

#[test]
fn residual_preflight_refuses_changed_frozen_root() {
    source_refusal("frozen", "RecoveryResidualCaptureChanged");
}

#[test]
fn residual_stalled_read_obeys_both_entry_deadlines() {
    let mut rows = Vec::new();
    for explicit in [false, true] {
        let stopped = sealed(false, DIRTY, 0);
        let before = store_bytes(&stopped.paths.store);
        let sends_before = sends(&stopped);
        {
            let mut state = stopped.state.lock().unwrap();
            state.probe_waits = 0;
            // Writable discovery reads one head before residual admission.
            state.probe_limit = Some(state.probes + usize::from(!explicit));
        }
        let state = stopped.state.clone();
        // A watchdog releases the read so an absent deadline fails an assertion.
        let watchdog = std::thread::spawn(move || {
            let start = crate::SyncRuntime::now(&crate::TokioSyncRuntime);
            while state.lock().unwrap().probe_waits == 0 {
                assert!(
                    crate::SyncRuntime::now(&crate::TokioSyncRuntime) - start
                        < std::time::Duration::from_secs(10)
                );
                crate::overlay_test_support::block_for_test(std::time::Duration::from_millis(5));
            }
            let entered = crate::SyncRuntime::now(&crate::TokioSyncRuntime);
            crate::overlay_test_support::block_for_test(std::time::Duration::from_millis(600));
            state.lock().unwrap().probe_limit = None;
            entered
        });
        let bound = std::time::Duration::from_millis(250);
        let result = if explicit {
            super::recovery::recover_with_paused_finish_delays(
                &stopped,
                Default::default(),
                crate::SyncOptions::default().workspace_bytes,
            )
            .0
            .map(|_| ())
            .map_err(|e| e.to_string())
        } else {
            finish_hooks_for_test(FinishHooks {
                bound: Some(bound),
                ..Default::default()
            });
            let result = restart(&stopped, &Events::default())
                .map(|_| ())
                .map_err(|e| e.to_string());
            finish_hooks_for_test(FinishHooks::default());
            result
        };
        let ended = crate::SyncRuntime::now(&crate::TokioSyncRuntime);
        let entered = watchdog.join().unwrap();
        rows.push((
            explicit,
            result,
            explicit
                || ended.saturating_duration_since(entered)
                    <= bound + std::time::Duration::from_millis(250),
            store_bytes(&stopped.paths.store) == before,
            sends(&stopped) == sends_before,
        ));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &[false, true]
                .map(|explicit| (
                    explicit,
                    Err(if explicit {
                        "intent refused: SyncDeadline"
                    } else {
                        "SyncDeadline"
                    }
                    .to_owned()),
                    true,
                    true,
                    true
                ))
                .to_vec(),
            2
        )
    );
}

fn authenticate(
    stopped: &Stopped,
    remote: &Authority,
    workspace: u64,
    validate: bool,
) -> Result<Option<usize>, String> {
    let before = store_bytes(&stopped.paths.store);
    let mut local = super::recovery::local_store(stopped);
    let keys = granary_store::crypto::TrustedKeys::new([*stopped.tree.key.public_key()]).unwrap();
    let sources = local.residual_sources().unwrap().unwrap();
    let result = runtime()
        .block_on(crate::recovery::authenticate_residual_sources(
            &mut local, remote, &keys, workspace, sources,
        ))
        .and_then(|evidence| {
            if validate {
                local.validate_residual_sources(&evidence, || Ok(()))?;
            }
            Ok(Some(evidence.proof.entries.len()))
        })
        .map_err(|e| e.to_string());
    assert_eq!(store_bytes(&stopped.paths.store), before);
    result
}

#[test]
fn residual_landing_unavailable_is_distinct_from_mismatch() {
    let mut rows = Vec::new();
    for case in [
        "transport",
        "behind",
        "valid",
        "incomplete-transport",
        "incomplete-missing",
        "chain-missing",
    ] {
        let mut stopped = sealed(false, DIRTY, 0);
        let mut record = retained(&stopped);
        let seq = record.candidates.last().unwrap().seq;
        if case.starts_with("incomplete-") {
            record.phase = submission::Phase::Ready;
            record.current = Some(record.candidates.last().unwrap().request);
            std::fs::write(
                submission_path(&stopped),
                submission::encode(&record).unwrap(),
            )
            .unwrap();
        }
        if case == "chain-missing" {
            stopped.tree.seq = seq;
            disjoint_head(&stopped.tree, &runtime());
        }
        if matches!(case, "incomplete-missing" | "chain-missing") {
            runtime()
                .block_on(
                    stopped
                        .tree
                        .mem
                        .delete(&object_store::path::Path::from(format!(
                            "root/{}/{}",
                            record.volume.as_str(),
                            granary_core::rootstore::format_hint_body(seq)
                        ))),
                )
                .unwrap();
        }
        let remote = if case == "behind" {
            Authority::with_scope_and_rule(&stopped.tree, None, &stopped.state, "no_head")
        } else {
            Authority::new(&stopped.tree, &stopped.state)
        }
        .with_publication();
        if case == "incomplete-transport" {
            stopped.state.lock().unwrap().root_fault.insert(
                seq,
                granary_core::rootstore::RootStoreError::Unavailable {
                    operation: "GET root",
                    status: 503,
                },
            );
        }
        if case == "transport" {
            stopped.state.lock().unwrap().probe_fault =
                Some(granary_core::rootstore::RootStoreError::Unavailable {
                    operation: "GET root",
                    status: 503,
                });
        }
        rows.push((case, authenticate(&stopped, &remote, 16_777_216, false)));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (
                    "transport",
                    Err("intent refused: RecoveryResidualUnavailable".into())
                ),
                (
                    "behind",
                    Err("intent refused: RecoveryResidualUnavailable".into())
                ),
                ("valid", Ok(Some(6))),
                (
                    "incomplete-transport",
                    Err("intent refused: RecoveryResidualUnavailable".into())
                ),
                (
                    "incomplete-missing",
                    Err("intent refused: RecoveryResidualUnavailable".into())
                ),
                (
                    "chain-missing",
                    Err("intent refused: RecoveryResidualUnavailable".into())
                ),
            ],
            6
        )
    );
}

#[test]
fn residual_closure_unavailable_is_distinct_from_corruption() {
    let mut rows = Vec::new();
    for corrupt in [false, true] {
        let stopped = sealed(false, DIRTY, 0);
        std::fs::remove_file(object_path(&stopped, GrainId::of(DIRTY))).unwrap();
        stopped.state.lock().unwrap().next_range_fault = Some(if corrupt {
            crate::overlay_test_support::RangeFault::Corrupt
        } else {
            crate::overlay_test_support::RangeFault::Unavailable
        });
        rows.push((
            corrupt,
            authenticate(
                &stopped,
                &Authority::new(&stopped.tree, &stopped.state).with_publication(),
                16_777_216,
                false,
            ),
        ));
        assert!(!stopped.state.lock().unwrap().ranges.is_empty());
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (
                    false,
                    Err("intent refused: RecoveryResidualUnavailable".into())
                ),
                (true, Err("intent refused: RecoveryResidualClosure".into())),
            ],
            2
        )
    );
}

#[test]
fn residual_disposition_cannot_select_another_completed_landing() {
    let stopped = sealed(false, DIRTY, 0);
    let input = input(&stopped.tree, &stopped.paths);
    let (header, mut records) = captured_records(&stopped.paths, &input);
    let record = retained(&stopped);
    let submission::Phase::Complete(done) = &record.phase else {
        panic!("{record:?}")
    };
    let alien = GrainId::of(b"another sealed landing");
    for record in &mut records {
        match record {
            Record::LandedCommit { landed_root, .. } => *landed_root = alien,
            Record::IntentRegistered {
                prepared_root,
                cause: journal::IntentCause::LandedRefresh,
                ..
            } => *prepared_root = alien,
            Record::ResidualDisposition(disposition) => disposition.landed_root = alien,
            _ => (),
        }
    }
    assert_ne!(alien, done.id);
    std::fs::write(
        overlay_area(&stopped.paths, &input).join("journal"),
        journal::encode_journal(&header, &records).unwrap(),
    )
    .unwrap();
    assert_eq!(
        authenticate(
            &stopped,
            &Authority::new(&stopped.tree, &stopped.state).with_publication(),
            16_777_216,
            false
        ),
        Err("intent refused: RecoveryResidualLandingChanged".into())
    );
}

#[test]
fn residual_namespace_charges_recovered_bytes_end_to_end() {
    let bytes = vec![7; 65_536];
    let mut rows = Vec::new();
    for missing in [false, true] {
        let stopped = sealed(false, &bytes, 0);
        let path = object_path(&stopped, GrainId::of(&bytes));
        assert!(path.is_file(), "grain absent before recovery: {path:?}");
        if missing {
            std::fs::remove_file(path).unwrap();
        }
        let remote = Authority::new(&stopped.tree, &stopped.state).with_publication();
        rows.push((missing, authenticate(&stopped, &remote, 131_072, false)));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (false, Ok(Some(6))),
                (
                    true,
                    Err("intent refused: RecoveryResidualWorkspace".into())
                ),
            ],
            2
        )
    );
}

#[test]
fn residual_workspace_accounts_for_all_three_entry_graphs() {
    let stopped = sealed(false, DIRTY, 4);
    let remote = Authority::new(&stopped.tree, &stopped.state).with_publication();
    let rows = [16_384, 32_768, 65_536, 131_072]
        .map(|workspace| (workspace, authenticate(&stopped, &remote, workspace, false)));
    assert_eq!(
        (&rows, rows.len()),
        (
            &[
                (
                    16_384,
                    Err("intent refused: RecoveryResidualWorkspace".into())
                ),
                (
                    32_768,
                    Err("intent refused: RecoveryResidualWorkspace".into())
                ),
                (
                    65_536,
                    Err("intent refused: RecoveryResidualWorkspace".into())
                ),
                (131_072, Ok(Some(10))),
            ],
            4
        )
    );
}

#[test]
fn unsealed_preflight_never_enters_runtime_or_consults_deadline() {
    let (_, stopped) = recorded_landing(crate::SyncProfile::DurablePrepared, &[], DIRTY, 0);
    let before = store_bytes(&stopped.paths.store);
    let sent = sends(&stopped);
    let mut local = super::recovery::local_store(&stopped);
    let remote = Authority::new(&stopped.tree, &stopped.state).with_publication();
    let keys = granary_store::crypto::TrustedKeys::new([*stopped.tree.key.public_key()]).unwrap();
    let rt = runtime();
    let calls = std::cell::Cell::new(0);
    let result = rt.block_on(async {
        tokio::task::yield_now().await;
        crate::recovery::preflight_residual(&mut local, &remote, &keys, &rt, || {
            calls.set(calls.get() + 1);
            Err(crate::sync::refused("SyncDeadline"))
        })
    });
    assert_eq!(
        (
            result.map_err(|e| e.to_string()),
            calls.get(),
            store_bytes(&stopped.paths.store) == before,
            sends(&stopped) == sent
        ),
        (Ok(()), 0, true, true)
    );
}

fn project_records(stopped: &Stopped, records: &mut [Record]) {
    let (content, _) = captured_payload(stopped);
    for journal_record in records {
        if let Record::CommitBoundary {
            candidate,
            through_seq,
            publication_id,
        } = journal_record
        {
            *journal_record = Record::ProjectedBoundary {
                candidate: *candidate,
                through_seq: *through_seq,
                publication_id: *publication_id,
                selection: Some(journal::ProjectedSelection {
                    stage_id: 1,
                    content,
                    size: DIRTY.len() as u64,
                }),
            };
        }
    }
}

/// Local stages collide with independently landed files; one stage stays unrelated.
#[expect(
    clippy::too_many_lines,
    reason = "one fault fixture binds journal records, inventory and stage bytes before either entry path runs"
)]
fn collision_disposition(case: &str) -> Stopped {
    let (_, stopped) = recorded_landing(
        crate::SyncProfile::DurablePrepared,
        if case == "parent" {
            &["new-parent/remote-one", "new-parent/remote-two"]
        } else if case == "coupled-parent" {
            &["empty/remote-one", "empty/remote-two"]
        } else if case == "kind" {
            &["remote-one/child", "remote-two"]
        } else if case == "gone-parent" {
            &["remote-one", "remote-two", "!empty"]
        } else if case == "subtree" {
            &["remote-one", "remote-two", "sub/remote-file"]
        } else {
            &["remote-one", "remote-two"]
        },
        DIRTY,
        0,
    );
    let input = input(&stopped.tree, &stopped.paths);
    let area = overlay_area(&stopped.paths, &input);
    let (header, mut records) = captured_records(&stopped.paths, &input);
    if case == "extra-lane" {
        for record in &mut records {
            match record {
                Record::CommitBoundary { through_seq, .. } => *through_seq += 2,
                Record::LandedCommit { boundary_seq, .. }
                | Record::CommitAttempt { boundary_seq, .. }
                | Record::CommitFence { boundary_seq, .. } => *boundary_seq += 2,
                _ => {}
            }
        }
        records.splice(
            0..0,
            [
                Record::CommitBoundary {
                    through_seq: 0,
                    candidate: GrainId::of(b"other capture"),
                    publication_id: [55; 16],
                },
                Record::LandedCommit {
                    boundary_seq: 1,
                    landed_root: GrainId::of(b"other landing"),
                    landed_seq: header.base_seq + 1,
                },
            ],
        );
    }
    if case == "capture-shape" {
        for record in &mut records {
            match record {
                Record::WriteExtent {
                    stage_id: 1,
                    length,
                    check,
                    ..
                } => {
                    *length -= 1;
                    *check =
                        journal::extent_check(1, 0, &DIRTY[..usize::try_from(*length).unwrap()]);
                }
                Record::FileSynced {
                    stage_id: 1,
                    synced_size,
                    ..
                } => *synced_size -= 1,
                _ => {}
            }
        }
    }
    let scan = journal::scan_journal(&journal::encode_journal(&header, &records).unwrap()).unwrap();
    let first = scan.state.next_stage_id();
    let suffix_start = records.len();
    let parent = if matches!(case, "parent" | "coupled-parent") {
        vec![
            Name::new(if case == "parent" {
                b"new-parent".to_vec()
            } else {
                b"empty".to_vec()
            })
            .unwrap(),
        ]
    } else {
        vec![]
    };
    if case == "coupled-parent" {
        records.push(Record::Delete {
            at: Location {
                parent: Parent::new(vec![]).unwrap(),
                name: parent[0].clone(),
            },
            kind: journal::DeleteKind::Dir,
        });
    }
    if matches!(case, "parent" | "coupled-parent") {
        records.push(Record::Create {
            at: Location {
                parent: Parent::new(vec![]).unwrap(),
                name: parent[0].clone(),
            },
            kind: journal::CreateKind::Dir,
        });
    }
    let mut files = Vec::new();
    for (index, name) in ["remote-one", "remote-two", "unrelated"]
        .into_iter()
        .enumerate()
    {
        let stage_id = first + index as u64;
        let at = Location {
            parent: Parent::new(if case == "gone-parent" && name == "unrelated" {
                vec![Name::new(b"empty".to_vec()).unwrap()]
            } else {
                parent.clone()
            })
            .unwrap(),
            name: Name::new(name.as_bytes().to_vec()).unwrap(),
        };
        records.push(Record::Create {
            at: at.clone(),
            kind: journal::CreateKind::File {
                stage_id,
                exec: false,
            },
        });
        records.push(Record::WriteExtent {
            stage_id,
            offset: 0,
            length: DIRTY.len() as u64,
            check: journal::extent_check(stage_id, 0, DIRTY),
        });
        let mut bytes = StagingHeader {
            writer: header.writer,
            stage_id,
            mark: MarkState::Absent,
        }
        .encode()
        .unwrap();
        bytes.extend_from_slice(DIRTY);
        let path = area.join("staging").join(format!("{stage_id:016x}"));
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        if index < 2 {
            let mut hash = journal::ResidualPayloadHasher::new(stage_id, DIRTY.len() as u64);
            hash.update(DIRTY);
            files.push(journal::ResidualFile {
                stage_id,
                at,
                exec: false,
                local_size: DIRTY.len() as u64,
                payload_check: hash.finalize(),
            });
        }
    }
    if case == "subtree" {
        records.push(Record::Move {
            from: Location {
                parent: Parent::new(vec![]).unwrap(),
                name: Name::new(b"sub".to_vec()).unwrap(),
            },
            to: Location {
                parent: Parent::new(vec![]).unwrap(),
                name: Name::new(b"moved-sub".to_vec()).unwrap(),
            },
        });
    }
    if case == "move" {
        records.push(Record::Move {
            from: files[0].at.clone(),
            to: Location {
                parent: Parent::new(vec![]).unwrap(),
                name: Name::new(b"moved".to_vec()).unwrap(),
            },
        });
        files.remove(0);
    }
    if case == "projected-omitted" {
        let mut omitted = records.split_off(suffix_start);
        omitted.push(Record::Move {
            from: Location {
                parent: Parent::new(vec![]).unwrap(),
                name: Name::new(b"unrelated".to_vec()).unwrap(),
            },
            to: Location {
                parent: Parent::new(vec![]).unwrap(),
                name: Name::new(b"other".to_vec()).unwrap(),
            },
        });
        let added = omitted.len() as u64;
        let boundary = records
            .iter()
            .position(|record| matches!(record, Record::CommitBoundary { .. }))
            .unwrap();
        records.splice(boundary..boundary, omitted);
        for record in &mut records {
            match record {
                Record::CommitBoundary { through_seq, .. } => {
                    *through_seq = boundary as u64 + added;
                }
                Record::LandedCommit { boundary_seq, .. }
                | Record::CommitAttempt { boundary_seq, .. }
                | Record::CommitFence { boundary_seq, .. } => *boundary_seq += added,
                _ => {}
            }
        }
    }
    if case.starts_with("projected") {
        project_records(&stopped, &mut records);
    }
    let (boundary_seq, landed_root, landed_seq) = records
        .iter()
        .rev()
        .find_map(|record| match record {
            Record::LandedCommit {
                boundary_seq,
                landed_root,
                landed_seq,
            } => Some((*boundary_seq, *landed_root, *landed_seq)),
            _ => None,
        })
        .unwrap();
    let publication_id = retained(&stopped).publication_id;
    if case == "forged" {
        files[1].at.name = Name::new(b"forged".to_vec()).unwrap();
    }
    let inventory_check = journal::residual_inventory_check(if case == "partial" {
        &files[..1]
    } else {
        &files
    })
    .unwrap();
    records.push(Record::ResidualDisposition(journal::ResidualDisposition {
        boundary_seq,
        publication_id,
        landed_root,
        landed_seq,
        source_end: records.len() as u64,
        disposition: journal::ResidualMode::KeepLocal,
        collision_count: if matches!(case, "count" | "partial" | "move") {
            1
        } else {
            2
        },
        inventory_check,
    }));
    std::fs::write(
        area.join("journal"),
        journal::encode_journal(&header, &records).unwrap(),
    )
    .unwrap();
    let path = area.join("staging").join(format!("{:016x}", first + 1));
    let mut bytes = std::fs::read(&path).unwrap();
    match case {
        "byte" => bytes[160] ^= 1,
        "length" => {
            bytes.push(0);
        }
        "header" => bytes[0] ^= 1,
        "writer" | "id" | "mark" => {
            let mut staged = StagingHeader::decode(&bytes[..160]).unwrap();
            match case {
                "writer" => staged.writer[0] ^= 1,
                "id" => staged.stage_id += 1,
                "mark" => {
                    staged.mark = MarkState::Present(SyncedMark {
                        synced_size: DIRTY.len() as u64,
                        content: GrainId::of(DIRTY),
                        generation: 1,
                    });
                }
                _ => unreachable!(),
            }
            bytes[..160].copy_from_slice(&staged.encode().unwrap());
            let decoded = StagingHeader::decode(&bytes[..160]).unwrap();
            assert_eq!(
                (
                    bytes.len(),
                    decoded.check_binding(&header.writer, first + 1).is_err()
                ),
                (160 + DIRTY.len(), case != "mark"),
                "case={case}, decoded={decoded:?}"
            );
        }
        "missing" => {
            std::fs::remove_file(&path).unwrap();
            return stopped;
        }
        _ => {}
    }
    std::fs::write(path, bytes).unwrap();
    stopped
}

fn restart_or_recover(stopped: &Stopped, explicit: bool) -> Result<(), String> {
    if explicit {
        recover_stopped(stopped, crate::FaultControl::default()).map_err(|error| error.to_string())
    } else {
        restart(stopped, &Events::default())
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

fn assert_ending(mut fixture: impl FnMut() -> Stopped, expected: &str) {
    let mut rows = Vec::new();
    for explicit in [false, true] {
        let stopped = fixture();
        let before = store_bytes(&stopped.paths.store);
        let sent = sends(&stopped);
        let result = restart_or_recover(&stopped, explicit);
        rows.push((
            explicit,
            result,
            store_bytes(&stopped.paths.store) == before,
            sends(&stopped) == sent,
        ));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &[false, true]
                .map(|explicit| (
                    explicit,
                    Err(if explicit {
                        format!("intent refused: {expected}")
                    } else {
                        expected.to_owned()
                    }),
                    true,
                    true
                ))
                .to_vec(),
            2
        ),
        "ending={expected}"
    );
}

fn add_rich_b5_stages(fixture: &mut EngineMount) {
    create(
        fixture.ready.backend_for_test(),
        "gone",
        b"detached payload has another size\n",
    );
    let gone = handler_path(b"gone");
    fixture
        .ready
        .backend_for_test()
        .prepare_detach(&gone)
        .unwrap();
    fixture
        .ready
        .backend_for_test()
        .overlay_mutate(M::Remove {
            path: &gone,
            directory: false,
        })
        .unwrap();
    create(
        fixture.ready.backend_for_test(),
        "move-from",
        b"moved payload\n",
    );
    fixture
        .ready
        .backend_for_test()
        .overlay_mutate(M::Rename {
            from: &handler_path(b"move-from"),
            to: &handler_path(b"move-to"),
            no_replace: false,
        })
        .unwrap();
    create(
        fixture.ready.backend_for_test(),
        "replace-target",
        b"replaced payload remains detached!\n",
    );
    create(
        fixture.ready.backend_for_test(),
        "replacement-source",
        b"replacement bytes\n",
    );
    let replace_target = handler_path(b"replace-target");
    fixture
        .ready
        .backend_for_test()
        .prepare_detach(&replace_target)
        .unwrap();
    fixture
        .ready
        .backend_for_test()
        .overlay_mutate(M::Rename {
            from: &handler_path(b"replacement-source"),
            to: &replace_target,
            no_replace: false,
        })
        .unwrap();
    create(
        fixture.ready.backend_for_test(),
        "<detached>",
        b"named sentinel payload\n",
    );
}

fn b5_without_record() -> Stopped {
    let mut fixture = fixture_with(crate::SyncProfile::DurablePrepared);
    create(
        fixture.ready.backend_for_test(),
        "a",
        b"captured and landed\n",
    );
    let lane = construct_commit(&fixture.engine, &fixture.runtime, 70).unwrap();
    publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
        std::fs::write(source.join("remote-one"), FOREIGN_CONTENT).unwrap();
        std::fs::write(source.join("remote-two"), FOREIGN_CONTENT).unwrap();
    });
    create(
        fixture.ready.backend_for_test(),
        "remote-one",
        b"one local\n",
    );
    create(
        fixture.ready.backend_for_test(),
        "remote-two",
        b"second local payload\n",
    );
    add_rich_b5_stages(&mut fixture);
    let result = drive_commit(&fixture.engine, &fixture.runtime, &lane, 80);
    assert!(
        matches!(result, Err(crate::CoordinationError::Fenced { .. })),
        "premise: the landed residual collision fences: {result:?}"
    );
    let stopped = stop(fixture);
    let input = input(&stopped.tree, &stopped.paths);
    let (_, records) = captured_records(&stopped.paths, &input);
    assert!(
        records
            .iter()
            .any(|record| matches!(record, Record::LandedCommit { .. })),
        "premise: the remote landing is recorded"
    );
    assert!(
        !records
            .iter()
            .any(|record| matches!(record, Record::ResidualDisposition(_))),
        "premise: no residual disposition is recorded"
    );
    stopped
}

fn b5_journal(stopped: &Stopped) -> Vec<u8> {
    let input = input(&stopped.tree, &stopped.paths);
    std::fs::read(overlay_area(&stopped.paths, &input).join("journal")).unwrap()
}

fn b5_stage_hashes(stopped: &Stopped) -> BTreeMap<std::ffi::OsString, (usize, GrainId)> {
    let input = input(&stopped.tree, &stopped.paths);
    std::fs::read_dir(overlay_area(&stopped.paths, &input).join("staging"))
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let bytes = std::fs::read(entry.path()).unwrap();
            (entry.file_name(), (bytes.len(), GrainId::of(&bytes)))
        })
        .collect()
}

fn b5_landed_root(journal: &[u8]) -> GrainId {
    let mut landed_root = None;
    journal::scan_journal_with(journal, |_, record| {
        if let Record::LandedCommit {
            landed_root: root, ..
        } = record
        {
            landed_root = Some(*root);
        }
    })
    .unwrap();
    landed_root.unwrap()
}

fn assert_b5_append(before: &[u8], after: &[u8], landed_root: GrainId) -> (usize, usize) {
    assert!(after.starts_with(before), "journal prefix changed");
    let records = |bytes: &[u8]| {
        let mut records = Vec::new();
        journal::scan_journal_with(bytes, |_, record| records.push(record.clone())).unwrap();
        records
    };
    let before_records = records(before);
    let after_records = records(after);
    let appended = after_records.get(before_records.len()..).unwrap();
    assert_eq!(appended.len(), 1, "appended records: {appended:?}");
    assert!(
        matches!(appended,
            [Record::IntentRegistered { generation: 2, prepared_root, cause: journal::IntentCause::LandedRefresh }]
                if *prepared_root == landed_root),
        "appended records: {appended:?}"
    );
    assert_eq!(after.len() - before.len(), 87);
    (before.len(), after.len())
}

fn assert_generation_barrier(
    before: &submission::Submission,
    after: &submission::Submission,
) -> (u64, u64) {
    let mut expected = after.clone();
    expected.generation = before.generation;
    assert_eq!(
        before, &expected,
        "retained fields other than generation changed"
    );
    assert_eq!(after.generation, before.generation.checked_add(7).unwrap());
    (before.generation, after.generation)
}

fn assert_three_growth(rows: &[(usize, usize, u64, u64)]) {
    let first = rows.first().unwrap();
    assert_eq!(first.1 - first.0, 87);
    assert_eq!((first.2, first.3), (15, 22));
    let (journal, generation) = (first.0, first.2);
    assert_eq!(
        rows,
        &(0..3)
            .map(|attempt| {
                let attempt = usize::try_from(attempt).unwrap();
                (
                    journal + attempt * 87,
                    journal + (attempt + 1) * 87,
                    generation + u64::try_from(attempt).unwrap() * 7,
                    generation + u64::try_from(attempt + 1).unwrap() * 7,
                )
            })
            .collect::<Vec<_>>()
    );
}

type B5Inventory = BTreeMap<u64, (Option<Vec<Vec<u8>>>, u64)>;
type ExpectedB5Stages = BTreeMap<u64, (Option<Vec<Vec<u8>>>, &'static [u8])>;

fn expected_b5_stages() -> ExpectedB5Stages {
    [
        (
            1,
            (
                Some(vec![b"a".to_vec()]),
                b"captured and landed\n".as_slice(),
            ),
        ),
        (
            2,
            (
                Some(vec![b"remote-one".to_vec()]),
                b"one local\n".as_slice(),
            ),
        ),
        (
            3,
            (
                Some(vec![b"remote-two".to_vec()]),
                b"second local payload\n".as_slice(),
            ),
        ),
        (4, (None, b"detached payload has another size\n".as_slice())),
        (
            5,
            (
                Some(vec![b"move-to".to_vec()]),
                b"moved payload\n".as_slice(),
            ),
        ),
        (
            6,
            (None, b"replaced payload remains detached!\n".as_slice()),
        ),
        (
            7,
            (
                Some(vec![b"replace-target".to_vec()]),
                b"replacement bytes\n".as_slice(),
            ),
        ),
        (
            8,
            (
                Some(vec![b"<detached>".to_vec()]),
                b"named sentinel payload\n".as_slice(),
            ),
        ),
    ]
    .into_iter()
    .collect()
}

fn b5_inventory(error: &crate::RecoveryCommandError) -> B5Inventory {
    error
        .conflict_inventory()
        .unwrap()
        .stages()
        .iter()
        .map(|stage| {
            (
                stage.id(),
                (
                    stage.path().map(|path| {
                        path.iter()
                            .map(|name| name.as_bytes().to_vec())
                            .collect::<Vec<_>>()
                    }),
                    stage.size(),
                ),
            )
        })
        .collect()
}

fn b5_payloads(stopped: &Stopped) -> BTreeMap<u64, Vec<u8>> {
    let input = input(&stopped.tree, &stopped.paths);
    std::fs::read_dir(overlay_area(&stopped.paths, &input).join("staging"))
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let id = u64::from_str_radix(entry.file_name().to_str().unwrap(), 16).unwrap();
            let bytes = std::fs::read(entry.path()).unwrap();
            (id, bytes.get(160..).unwrap().to_vec())
        })
        .collect()
}

fn checked_b5_inventory(stopped: &Stopped, error: &crate::RecoveryCommandError) -> B5Inventory {
    let input = input(&stopped.tree, &stopped.paths);
    assert_eq!(
        error.conflict_inventory().unwrap().scope(),
        input.scope.as_ref().unwrap().digest().unwrap()
    );
    let inventory = b5_inventory(error);
    let payloads = b5_payloads(stopped);
    let expected = expected_b5_stages();
    assert_eq!(inventory.len(), expected.len());
    assert_eq!(payloads.len(), expected.len());
    let mut sizes = BTreeSet::new();
    for (id, (expected_path, expected_payload)) in expected {
        let (path, size) = inventory.get(&id).unwrap();
        let payload = payloads.get(&id).unwrap();
        assert_eq!(path, &expected_path, "stage={id:016x}");
        assert_eq!(payload, expected_payload, "stage={id:016x}");
        assert_eq!(*size, expected_payload.len() as u64, "stage={id:016x}");
        assert!(sizes.insert(*size), "duplicate stage size {size}");
    }
    inventory
}

fn assert_complete_b5_inventory(stopped: &Stopped, error: &crate::RecoveryCommandError) {
    let inventory = checked_b5_inventory(stopped, error);
    assert_eq!(
        inventory
            .values()
            .filter(|(path, _)| path.is_none())
            .count(),
        2
    );
    for expected in [b"move-to".as_slice(), b"<detached>".as_slice()] {
        assert!(inventory.values().any(|(path, _)| {
            path.as_ref()
                .is_some_and(|path| path.as_slice() == [expected.to_vec()])
        }));
    }
}

fn b5_guide_block() -> String {
    let guide = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/operating-disk-loss-recovery.md"),
    )
    .unwrap();
    guide
        .split_once("Choose an absent `$RECOVERY_DIR`, then run this complete fenced block:")
        .unwrap()
        .1
        .split_once("```sh\n")
        .unwrap()
        .1
        .lines()
        .take_while(|line| line.trim() != "```")
        .map(|line| line.strip_prefix("   ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_b5_guide_extracts_store(stopped: &Stopped, error: &crate::RecoveryCommandError) {
    let input = input(&stopped.tree, &stopped.paths);
    let root = stopped.paths.store.parent().unwrap();
    let list = root.join("b5-stages.tsv");
    let recovered = root.join("b5-recovered");
    std::fs::write(
        &list,
        error
            .conflict_inventory()
            .unwrap()
            .stdout_bytes(crate::LogPaths::Full)
            .unwrap(),
    )
    .unwrap();
    let output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(b5_guide_block())
        .env("OLD_STORE", &stopped.paths.store)
        .env("VOLUME", input.volume.as_str())
        .env("STAGE_LIST", &list)
        .env("RECOVERY_DIR", &recovered)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(
        std::fs::metadata(&recovered).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for (id, payload) in b5_payloads(stopped) {
        let recovered_file = recovered.join(format!("{id:016x}"));
        assert_eq!(
            std::fs::read(&recovered_file).unwrap(),
            payload,
            "stage={id:016x}"
        );
        assert_eq!(
            std::fs::metadata(recovered_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn b5_start_without_record_refuses() {
    let stopped = b5_without_record();
    let landed_root = b5_landed_root(&b5_journal(&stopped));
    let mut growth = Vec::new();
    for attempt in 0..3 {
        let journal_before = b5_journal(&stopped);
        let retained_before = retained(&stopped);
        let stages = b5_stage_hashes(&stopped);
        let publications_before = publications(&stopped);
        let events = Events::default();
        let result = restart(&stopped, &events);
        let text = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
        let journal_after = b5_journal(&stopped);
        let journal_growth = assert_b5_append(&journal_before, &journal_after, landed_root);
        let generation_growth = assert_generation_barrier(&retained_before, &retained(&stopped));
        assert_eq!(b5_stage_hashes(&stopped), stages, "attempt={attempt}");
        assert_eq!(
            publications(&stopped),
            publications_before,
            "attempt={attempt}"
        );
        assert_eq!(
            result.err().map(|error| error.to_string()),
            Some("IntentFenced (ESTALE)".to_owned()),
            "attempt={attempt}"
        );
        assert_eq!(
            text.lines()
                .filter(|line| line.contains("\"event\":\"op.conflict\"")
                    && line.contains("\"path\":\"<file>\""))
                .count(),
            1,
            "attempt={attempt}: {text}"
        );
        assert!(!text.contains("remote-one") && !text.contains("remote-two"));
        assert!(!text.contains("finished"), "attempt={attempt}: {text}");
        growth.push((
            journal_growth.0,
            journal_growth.1,
            generation_growth.0,
            generation_growth.1,
        ));
    }
    assert_three_growth(&growth);
}

#[test]
fn b5_default_refuses_all_paths() {
    let stopped = b5_without_record();
    let landed_root = b5_landed_root(&b5_journal(&stopped));
    let mut growth = Vec::new();
    for attempt in 0..3 {
        let journal_before = b5_journal(&stopped);
        let retained_before = retained(&stopped);
        let stages = b5_stage_hashes(&stopped);
        let publications_before = publications(&stopped);
        let events = Events::default();
        let _guard =
            tracing::subscriber::set_default(crate::observe::closed_subscriber_with_paths(
                crate::LogFormat::Json,
                tracing_subscriber::EnvFilter::new("trace"),
                events.clone(),
                crate::LogPaths::Full,
                crate::BundleHistory::default(),
            ));
        let result = recover_stopped(&stopped, crate::FaultControl::default());
        let text = String::from_utf8(events.0.lock().unwrap().clone()).unwrap();
        let journal_after = b5_journal(&stopped);
        let journal_growth = assert_b5_append(&journal_before, &journal_after, landed_root);
        let generation_growth = assert_generation_barrier(&retained_before, &retained(&stopped));
        assert_eq!(b5_stage_hashes(&stopped), stages, "attempt={attempt}");
        assert_eq!(
            publications(&stopped),
            publications_before,
            "attempt={attempt}"
        );
        let error = result.unwrap_err();
        assert_eq!(
            error.to_string(),
            "intent refused: RecoveryConflict",
            "attempt={attempt}"
        );
        assert_complete_b5_inventory(&stopped, &error);
        if attempt == 0 {
            assert_b5_guide_extracts_store(&stopped, &error);
        }
        let conflicts = text
            .lines()
            .filter(|line| line.contains("\"event\":\"op.conflict\""))
            .collect::<Vec<_>>();
        assert_eq!(conflicts.len(), 1, "attempt={attempt}: {text}");
        assert!(
            conflicts
                .first()
                .is_some_and(|line| line.contains("\"path\":\"remote-one\""))
        );
        assert!(!text.contains("remote-two"));
        assert!(!text.contains("finished"), "attempt={attempt}: {text}");
        growth.push((
            journal_growth.0,
            journal_growth.1,
            generation_growth.0,
            generation_growth.1,
        ));
    }
    assert_three_growth(&growth);
}

#[test]
fn b5_projected_boundary_reports_the_original_complete_stage_table() {
    let stopped = b5_without_record();
    let input = input(&stopped.tree, &stopped.paths);
    let area = overlay_area(&stopped.paths, &input);
    let (header, mut records) = captured_records(&stopped.paths, &input);
    project_records(&stopped, &mut records);
    for record in &mut records {
        if let Record::ProjectedBoundary { selection, .. } = record {
            *selection = None;
        }
    }
    std::fs::write(
        area.join("journal"),
        journal::encode_journal(&header, &records).unwrap(),
    )
    .unwrap();
    let stages = b5_stage_hashes(&stopped);
    let error = recover_stopped(&stopped, crate::FaultControl::default()).unwrap_err();
    assert_eq!(error.to_string(), "intent refused: RecoveryConflict");
    assert_complete_b5_inventory(&stopped, &error);
    assert_eq!(b5_stage_hashes(&stopped), stages);
}

#[test]
fn residual_validation_refuses_forged_self_consistent_inventory() {
    assert_ending(
        || collision_disposition("forged"),
        "RecoveryResidualInventoryCheck",
    );
}
#[test]
fn residual_validation_refuses_partial_inventory() {
    assert_ending(
        || collision_disposition("partial"),
        "RecoveryResidualInventoryCount",
    );
}
#[test]
fn residual_validation_checks_count_independently_of_inventory_hash() {
    assert_ending(
        || collision_disposition("count"),
        "RecoveryResidualInventoryCount",
    );
}
#[test]
fn residual_validation_refuses_changed_payload_byte() {
    assert_ending(
        || collision_disposition("byte"),
        "RecoveryResidualInventoryCheck",
    );
}
#[test]
fn residual_validation_refuses_changed_payload_length() {
    assert_ending(
        || collision_disposition("length"),
        "RecoveryResidualPayloadLength",
    );
}
#[test]
fn residual_validation_refuses_changed_payload_header() {
    assert_ending(
        || collision_disposition("header"),
        "RecoveryResidualPayloadHeader",
    );
}
#[test]
fn residual_validation_refuses_missing_payload() {
    assert_ending(
        || collision_disposition("missing"),
        "RecoveryResidualPayloadLength",
    );
}
#[test]
fn residual_validation_accepts_two_collisions_and_excludes_unrelated_residual() {
    assert_ending(
        || collision_disposition("valid"),
        "RecoveryResidualValidatedAwaitingExecution",
    );
}

#[test]
fn residual_validation_refuses_reencoded_writer_binding() {
    assert_ending(
        || collision_disposition("writer"),
        "RecoveryResidualPayloadHeader",
    );
}
#[test]
fn residual_validation_refuses_reencoded_stage_binding() {
    assert_ending(
        || collision_disposition("id"),
        "RecoveryResidualPayloadHeader",
    );
}
#[test]
fn residual_validation_refuses_changed_parent_support() {
    assert_ending(
        || collision_disposition("parent"),
        "RecoveryResidualUnrepresentable",
    );
}
#[test]
fn residual_validation_refuses_colliding_move_support() {
    assert_ending(
        || collision_disposition("move"),
        "RecoveryResidualUnrepresentable",
    );
}
#[test]
fn residual_validation_accepts_projected_capture() {
    assert_ending(
        || collision_disposition("projected"),
        "RecoveryResidualValidatedAwaitingExecution",
    );
}
#[test]
fn residual_validation_accepts_projected_omissions_and_dependencies() {
    assert_ending(
        || collision_disposition("projected-omitted"),
        "RecoveryResidualValidatedAwaitingExecution",
    );
}

#[test]
fn residual_validation_refuses_recreated_parent_support() {
    assert_ending(
        || collision_disposition("coupled-parent"),
        "RecoveryResidualUnrepresentable",
    );
}

#[test]
fn residual_workspace_is_shared_across_three_traversals() {
    let stopped = collision_disposition("valid");
    let remote = Authority::new(&stopped.tree, &stopped.state).with_publication();
    let rows = [49_152, 1_048_576]
        .map(|workspace| (workspace, authenticate(&stopped, &remote, workspace, false)));
    assert_eq!(
        (&rows, rows.len()),
        (
            &[
                (
                    49_152,
                    Err("intent refused: RecoveryResidualWorkspace".into())
                ),
                (1_048_576, Ok(Some(8)))
            ],
            2
        )
    );
}

#[test]
fn residual_workspace_includes_streamed_payloads() {
    let stopped = collision_disposition("valid");
    let remote = Authority::new(&stopped.tree, &stopped.state).with_publication();
    let (mut low, mut high) = (0, 1_048_576);
    assert_eq!(
        authenticate(&stopped, &remote, high, false),
        Ok(Some(8)),
        "workspace premise at {high}"
    );
    while high - low > 1 {
        let mid = low + (high - low) / 2;
        if authenticate(&stopped, &remote, mid, false).is_ok() {
            high = mid;
        } else {
            low = mid;
        }
    }
    let scratch = u64::try_from(
        (65_536 + std::mem::size_of::<granary_core::hash::GrainIdHasher>()) * 8 + 1024,
    )
    .unwrap();
    let rows = [high, high + scratch].map(|workspace| {
        (
            workspace - high,
            authenticate(&stopped, &remote, workspace, true),
        )
    });
    assert_eq!(
        (&rows, rows.len()),
        (
            &[
                (0, Err("intent refused: RecoveryResidualWorkspace".into())),
                (scratch, Ok(Some(8)))
            ],
            2
        ),
        "authenticated graphs require {high} bytes"
    );
}

#[test]
fn residual_validation_refuses_changed_header_mark() {
    assert_ending(
        || collision_disposition("mark"),
        "RecoveryResidualPayloadHeader",
    );
}

#[test]
fn residual_validation_refuses_non_file_landing_support() {
    assert_ending(
        || collision_disposition("kind"),
        "RecoveryResidualUnrepresentable",
    );
}
#[test]
fn residual_validation_refuses_extra_lane_support() {
    assert_ending(
        || collision_disposition("extra-lane"),
        "RecoveryResidualUnrepresentable",
    );
}
#[test]
fn residual_validation_refuses_capture_shape_from_sealed_journal() {
    assert_ending(
        || collision_disposition("capture-shape"),
        "RecoveryResidualCaptureChanged",
    );
}

#[test]
fn residual_validation_refuses_changed_subtree_support() {
    assert_ending(
        || collision_disposition("subtree"),
        "RecoveryResidualUnrepresentable",
    );
}

#[test]
fn residual_validation_refuses_payload_only_create_under_removed_parent() {
    assert_ending(
        || collision_disposition("gone-parent"),
        "RecoveryResidualUnrepresentable",
    );
}

fn padded_disposition(pairs: usize) -> Stopped {
    let stopped = collision_disposition("valid");
    let input = input(&stopped.tree, &stopped.paths);
    let (header, mut records) = captured_records(&stopped.paths, &input);
    let Some(Record::ResidualDisposition(mut choice)) = records.pop() else {
        panic!("missing disposition: {records:?}");
    };
    let at = Location {
        parent: Parent::new(vec![]).unwrap(),
        name: Name::new(vec![b'p'; 200]).unwrap(),
    };
    for _ in 0..pairs {
        records.push(Record::Create {
            at: at.clone(),
            kind: journal::CreateKind::Dir,
        });
        records.push(Record::Delete {
            at: at.clone(),
            kind: journal::DeleteKind::Dir,
        });
    }
    choice.source_end = records.len() as u64;
    records.push(Record::ResidualDisposition(choice));
    std::fs::write(
        overlay_area(&stopped.paths, &input).join("journal"),
        journal::encode_journal(&header, &records).unwrap(),
    )
    .unwrap();
    stopped
}

#[test]
fn residual_validation_accepts_large_sealed_journal() {
    assert_ending(
        || {
            let stopped = padded_disposition(4700);
            let input = input(&stopped.tree, &stopped.paths);
            let (_, records) = captured_records(&stopped.paths, &input);
            let length = std::fs::read(overlay_area(&stopped.paths, &input).join("journal"))
                .unwrap()
                .len();
            assert!(
                length >= 2_411_725,
                "sealed length={length}, records={}",
                records.len()
            );
            stopped
        },
        "RecoveryResidualValidatedAwaitingExecution",
    );
}

#[test]
fn residual_sealed_journal_refuses_actual_workspace_exhaustion() {
    let stopped = padded_disposition(4700);
    let input = input(&stopped.tree, &stopped.paths);
    let length = std::fs::read(overlay_area(&stopped.paths, &input).join("journal"))
        .unwrap()
        .len() as u64;
    let remote = Authority::new(&stopped.tree, &stopped.state).with_publication();
    let rows = [length - 1, 16_777_216]
        .map(|workspace| (workspace, authenticate(&stopped, &remote, workspace, true)));
    assert_eq!(
        (&rows, rows.len()),
        (
            &[
                (
                    length - 1,
                    Err("intent refused: RecoveryResidualWorkspace".into())
                ),
                (16_777_216, Ok(Some(8)))
            ],
            2
        )
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "one table keeps expiry injection, both entries and preservation assertions together"
)]
fn residual_expiry_on_entries(expirations: &[usize]) {
    let mut rows = Vec::new();
    for &expire_at in expirations {
        for explicit in [false, true] {
            let stopped = collision_disposition("valid");
            let before = store_bytes(&stopped.paths.store);
            let paths: Vec<_> = before.keys().cloned().collect();
            let modified = std::rc::Rc::new(std::cell::RefCell::new(None));
            let at_entry = modified.clone();
            let sent = sends(&stopped);
            let calls = std::rc::Rc::new(std::cell::Cell::new(0));
            let counted = calls.clone();
            crate::recovery::RESIDUAL_CHECK.set(Some(Box::new(move || {
                let n = counted.get() + 1;
                counted.set(n);
                if n == 1 {
                    *at_entry.borrow_mut() = Some(
                        paths
                            .iter()
                            .map(|path| {
                                (
                                    path.clone(),
                                    std::fs::metadata(path).unwrap().modified().unwrap(),
                                )
                            })
                            .collect::<Vec<_>>(),
                    );
                }
                if expire_at == 0 {
                    if n == 1 {
                        tokio::time::pause();
                        let before = crate::SyncRuntime::now(&crate::TokioSyncRuntime);
                        let mut advance = std::pin::pin!(tokio::time::advance(
                            std::time::Duration::from_secs(31)
                        ));
                        let _ = std::future::Future::poll(
                            advance.as_mut(),
                            &mut std::task::Context::from_waker(std::task::Waker::noop()),
                        );
                        assert_eq!(
                            std::future::Future::poll(
                                advance.as_mut(),
                                &mut std::task::Context::from_waker(std::task::Waker::noop()),
                            ),
                            std::task::Poll::Ready(())
                        );
                        assert_eq!(
                            crate::SyncRuntime::now(&crate::TokioSyncRuntime) - before,
                            std::time::Duration::from_secs(31)
                        );
                        tokio::time::resume();
                        let elapsed = crate::SyncRuntime::now(&crate::TokioSyncRuntime) - before;
                        assert!(
                            elapsed >= std::time::Duration::from_secs(31),
                            "clock advanced by {elapsed:?}"
                        );
                    }
                    Ok(())
                } else if n >= expire_at {
                    Err(crate::sync::refused("SyncDeadline"))
                } else {
                    Ok(())
                }
            })));
            let result = restart_or_recover(&stopped, explicit);
            crate::recovery::RESIDUAL_CHECK.set(None);
            let preserved = store_bytes(&stopped.paths.store) == before;
            let no_writes = modified.borrow().as_ref().is_some_and(|modified| {
                modified.iter().all(|(path, time)| {
                    std::fs::metadata(path).unwrap().modified().unwrap() == *time
                })
            });
            rows.push((
                expire_at,
                explicit,
                result,
                calls.get(),
                preserved,
                no_writes,
                sends(&stopped) == sent,
            ));
        }
    }
    let expected: Vec<_> = expirations
        .iter()
        .flat_map(|&expire_at| {
            [false, true].map(move |explicit| {
                let ending = if expire_at <= 7 {
                    "SyncDeadline"
                } else {
                    "RecoveryResidualValidatedAwaitingExecution"
                };
                (
                    expire_at,
                    explicit,
                    Err(if explicit {
                        format!("intent refused: {ending}")
                    } else {
                        ending.to_owned()
                    }),
                    if expire_at == 0 { 1 } else { expire_at.min(7) },
                    true,
                    true,
                    true,
                )
            })
        })
        .collect();
    assert_eq!((&rows, rows.len()), (&expected, expirations.len() * 2));
    assert!(!rows.is_empty(), "no expiry cases ran: {rows:?}");
}

#[test]
fn residual_expiry_before_metadata_preserves_both_entries() {
    residual_expiry_on_entries(&[2, 3, 5, 6]);
}

#[test]
fn residual_expiry_before_chunks_preserves_both_entries() {
    residual_expiry_on_entries(&[4, 7]);
}

#[test]
fn residual_expiry_on_entry_and_valid_control_preserve_both_entries() {
    residual_expiry_on_entries(&[1, 8]);
}

#[test]
fn residual_runtime_deadline_is_rechecked_after_authentication() {
    // Zero advances the runtime clock while the injected check returns Ok.
    residual_expiry_on_entries(&[0]);
}
