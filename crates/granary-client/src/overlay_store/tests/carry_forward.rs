// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A clean journal on an older base carried, header-only, to the opened
//! header's base before replay: what counts as clean, a temporary left
//! beside the journal, and a crash at every step of the rewrite.

use super::*;
use crate::overlay_store::replacement::{adoption_clean, clean_record};

/// A head above the fixture's base, as a start would discover it.
fn head() -> JournalHeader {
    JournalHeader {
        base_root: grain(9),
        base_seq: 2,
        ..header()
    }
}

fn intent() -> Record {
    Record::IntentRegistered {
        generation: 1,
        prepared_root: grain(2),
        cause: codec::IntentCause::DirectorySync,
    }
}

fn boundary() -> Record {
    Record::CommitBoundary {
        candidate: grain(3),
        through_seq: 1,
        publication_id: [7; 16],
    }
}

/// The records and the completion fold of a real journal of `records` on the
/// fixture's header.
fn scanned(records: &[Record]) -> (Vec<Record>, CompletionReserve) {
    let bytes = codec::encode_journal(&header(), records).unwrap();
    let mut seen = Vec::new();
    let mut completion = CompletionReserve::default();
    codec::scan_journal_with(&bytes, |index, record| {
        completion.fold(index, record).unwrap();
        seen.push(record.clone());
    })
    .unwrap();
    (seen, completion)
}

/// The fixture's journal as a clean start leaves it: one intent registration
/// on its base.
fn registered() -> Fixture {
    let mut f = Fixture::new();
    f.overlay
        .record_intent_registered(
            &mut f.store,
            &f.owner,
            1,
            grain(2),
            codec::IntentCause::DirectorySync,
        )
        .unwrap();
    f
}

/// Open the fixture's area on [`head`] with the carry enabled.
fn carry(f: &mut Fixture, faults: FaultControl) -> Result<(), OverlayError> {
    f.overlay = OverlayStore::open_shared(
        &f.store,
        f.overlay.config.clone(),
        head(),
        f.overlay.base.clone(),
        &f.owner,
        &mut f.source,
        f.io.clone(),
        faults,
        true,
    )?;
    Ok(())
}

fn temporary(f: &Fixture) -> PathBuf {
    f.overlay.area.join("journal.next")
}

/// Whether a temporary sits beside the journal.
fn has_temporary(f: &Fixture) -> bool {
    f.io.clone().length(&temporary(f)).unwrap().is_some()
}

/// Leave `bytes` at the temporary's name, durably.
fn plant_temporary(f: &Fixture, bytes: &[u8]) {
    let mut io = f.io.clone();
    io.create(&temporary(f)).unwrap();
    io.write_at(&temporary(f), 0, bytes).unwrap();
    io.sync(&temporary(f)).unwrap();
    io.sync_directory(&f.overlay.area).unwrap();
}

/// What a restart after the carry left: ready, the journal scanning clean,
/// its base, and whether a temporary remains.
fn restarted(f: &Fixture) -> (OverlayReadiness, bool, (GrainId, u64), bool) {
    let scan = codec::scan_journal(&f.io.bytes(&f.overlay.journal_path())).unwrap();
    (
        f.overlay.readiness(),
        scan.end == codec::JournalEnd::Clean,
        (scan.header.base_root, scan.header.base_seq),
        has_temporary(f),
    )
}

/// Each namespace or stage record kind alone is not clean; intent and commit
/// bookkeeping alone is, for the record half of the test. A lone extent,
/// truncate or sync names a stage no record created: these are values, not
/// a scanned journal.
#[test]
fn clean_records_refuses_every_namespace_and_stage_record_kind() {
    let forbidden = [
        Record::Create {
            at: at("a"),
            kind: codec::CreateKind::Dir,
        },
        Record::StageBind {
            at: at("a"),
            cause: codec::BindCause::CopyUp,
            stage_id: 1,
            staged_size: 0,
            base_content: grain(5),
        },
        Record::WriteExtent {
            stage_id: 1,
            offset: 0,
            length: 1,
            check: codec::extent_check(1, 0, b"x"),
        },
        Record::Truncate {
            stage_id: 1,
            new_size: 0,
        },
        Record::Move {
            from: at("a"),
            to: at("b"),
        },
        Record::Replace {
            from: at("a"),
            to: at("b"),
        },
        Record::Delete {
            at: at("a"),
            kind: codec::DeleteKind::Dir,
        },
        Record::SetattrExec {
            at: at("a"),
            exec: true,
        },
        Record::FileSynced {
            stage_id: 1,
            synced_size: 0,
            content: grain(5),
            generation: 1,
            prepared_root: grain(2),
        },
        Record::RecreateFile {
            at: None,
            exec: false,
            stage_id: 1,
            anchor: None,
        },
    ];
    let refused: Vec<_> = forbidden
        .iter()
        .map(|record| (record, clean_record(record)))
        .collect();
    let expected: Vec<_> = forbidden.iter().map(|record| (record, false)).collect();
    assert_eq!(refused, expected, "each kind alone is local work");
    let mut cases = refused.len();
    let bookkeeping = [
        intent(),
        boundary(),
        Record::CommitAttempt {
            boundary_seq: 2,
            publication_id: [7; 16],
            attempt: 1,
        },
        Record::CommitFence {
            boundary_seq: 2,
            publication_id: [7; 16],
        },
        Record::LandedCommit {
            boundary_seq: 2,
            landed_root: grain(4),
            landed_seq: 2,
        },
        Record::ProjectedBoundary {
            candidate: grain(3),
            through_seq: 1,
            publication_id: [8; 16],
            selection: None,
        },
    ];
    assert!(
        bookkeeping.iter().all(clean_record),
        "control: bookkeeping only"
    );
    cases += 1;
    assert_eq!(cases, 11);
}

/// A journal holding any boundary is not clean, through the completion slot
/// the boundary leaves, although none of its records is local work: an open
/// boundary, one with a dispatch attempt pending, and one that landed. A
/// journal of one intent registration, as a landing's replacement leaves
/// it, is clean.
#[test]
fn adoption_clean_refuses_a_journal_holding_any_boundary() {
    let mut refused = Vec::new();
    for (case, records) in [
        ("open", vec![intent(), boundary()]),
        (
            "pending",
            vec![
                intent(),
                boundary(),
                Record::CommitAttempt {
                    boundary_seq: 2,
                    publication_id: [7; 16],
                    attempt: 1,
                },
            ],
        ),
        (
            "landed",
            vec![
                intent(),
                boundary(),
                Record::LandedCommit {
                    boundary_seq: 2,
                    landed_root: grain(4),
                    landed_seq: 2,
                },
            ],
        ),
    ] {
        let (records, completion) = scanned(&records);
        let records_clean = records.iter().all(clean_record);
        refused.push((
            case,
            records_clean,
            adoption_clean(records_clean, &completion),
        ));
    }
    assert_eq!(
        refused,
        [
            ("open", true, false),
            ("pending", true, false),
            ("landed", true, false)
        ],
        "the record half passes; the completion slot refuses"
    );
    let mut cases = refused.len();
    let (records, completion) = scanned(&[intent()]);
    assert!(
        adoption_clean(records.iter().all(clean_record), &completion),
        "control: a refresh registration alone"
    );
    cases += 1;
    assert_eq!(cases, 4);
}

/// A recorded choice is never disposable bookkeeping, even with no completion
/// slot held. Exercise the record/clean seam directly: a bookkeeping-only
/// journal with a nonzero collision count cannot pass the scan's stage bound.
#[test]
fn adoption_clean_refuses_a_recorded_residual_choice() {
    let completion = CompletionReserve::default();
    let mut count = 0;
    for mode in [
        codec::ResidualMode::KeepLocal,
        codec::ResidualMode::KeepRemote,
    ] {
        let choice = Record::ResidualDisposition(codec::ResidualDisposition {
            boundary_seq: 2,
            publication_id: [7; 16],
            landed_root: grain(4),
            landed_seq: 2,
            source_end: 4,
            disposition: mode,
            collision_count: 1,
            inventory_check: [3; 32],
        });
        let records = [intent(), choice];
        assert_eq!(
            (
                clean_record(&records[1]),
                adoption_clean(records.iter().all(clean_record), &completion),
                adoption_clean(clean_record(&records[0]), &completion),
            ),
            (false, false, true),
            "mode {mode:?}: {records:?}"
        );
        count += 1;
    }
    assert_eq!(count, 2);
}

/// A temporary left beside the journal, by a replacement's build or by an
/// earlier carry cut after its sync, is removed before the rewrite.
#[test]
fn a_leftover_temporary_does_not_block_the_carry() {
    let mut cases = 0;
    for case in ["adoption", "carry"] {
        let mut f = registered();
        if case == "adoption" {
            let image = codec::encode_journal(&head(), &[]).unwrap();
            plant_temporary(&f, &image[..image.len() / 2]);
        } else {
            let faults = FaultControl::default();
            faults.arm("overlay.journal.carry", "sync", 1, FaultAction::Crash);
            assert!(
                carry(&mut f, faults.clone()).is_err() && faults.fired().len() == 1,
                "fixture precondition: the carry is cut at its sync"
            );
        }
        assert!(has_temporary(&f), "{case}: fixture precondition");
        let result = carry(&mut f, FaultControl::default());
        assert_eq!(
            (result.is_ok(), restarted(&f)),
            (true, (OverlayReadiness::Ready, true, (grain(9), 2), false)),
            "{case}: {result:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A crash at any step of the carry restarts on the head: before the
/// leftover temporary is removed, after it is, and at every phase of the
/// rewrite's durable install. Each cut is followed by a crash of the model
/// filesystem, which keeps only what was synced.
#[test]
fn start_carry_forward_crash_points_restart_cleanly() {
    let mut cases = 0;
    for cut in [
        "before the temporary is removed",
        "after the temporary is removed",
        "build",
        "sync",
        "after_sync",
        "rename",
        "after_rename",
        "dir_sync",
        "after_dir_sync",
    ] {
        let mut f = registered();
        let faults = FaultControl::default();
        match cut {
            "before the temporary is removed" | "after the temporary is removed" => {
                let image = codec::encode_journal(&head(), &[]).unwrap();
                plant_temporary(&f, &image);
                f.io.0.lock().unwrap().fail = Some(if cut == "before the temporary is removed" {
                    "remove"
                } else {
                    "create"
                });
            }
            phase => faults.arm("overlay.journal.carry", phase, 1, FaultAction::Crash),
        }
        let first = carry(&mut f, faults.clone());
        let armed = !cut.ends_with("removed");
        assert_eq!(
            (
                first.is_err(),
                f.io.0.lock().unwrap().fail.is_none(),
                faults.fired().len()
            ),
            (true, true, usize::from(armed)),
            "{cut}: the carry is cut: {first:?}"
        );
        f.io.crash();
        let result = carry(&mut f, FaultControl::default());
        assert_eq!(
            (result.is_ok(), restarted(&f)),
            (true, (OverlayReadiness::Ready, true, (grain(9), 2), false)),
            "{cut}: {result:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 9);
}

#[test]
fn retry_settles_failed_carry_before_acknowledging_work() {
    let mut f = registered();
    let faults = FaultControl::default();
    faults.arm("overlay.journal.carry", "dir_sync", 1, FaultAction::Fail);
    let failed = carry(&mut f, faults.clone());
    assert_eq!(
        (
            matches!(failed, Err(OverlayError::Io(_))),
            faults.fired().len()
        ),
        (true, 1),
        "carry switch: {failed:?}, faults {:?}",
        faults.fired()
    );
    carry(&mut f, FaultControl::default()).unwrap();
    let id = f.create();
    f.write(id, b"accepted");
    f.sync(id, 2);
    f.io.crash();
    let read = carry(&mut f, FaultControl::default())
        .and_then(|()| f.overlay.read_stage(&mut f.store, &f.owner, id, 0, 8));
    assert_eq!(
        read.map_err(|error| error.to_string()).as_deref(),
        Ok(&b"accepted"[..])
    );
}

/// Every `overlay.recovery` outcome `log` holds, in order.
fn recovery_outcomes(log: &LogBytes) -> Vec<String> {
    String::from_utf8(log.0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter(|line| line.contains("\"event\":\"overlay.recovery\""))
        .map(|line| {
            let (_, rest) = line.split_once("\"outcome\":\"").unwrap();
            rest.split('"').next().unwrap().to_owned()
        })
        .collect()
}

/// A carry is reported once, by the replay that follows it: a later recovery
/// of the same component replays the carried journal and reports it clean.
#[test]
fn a_later_recovery_after_a_carry_reports_clean() {
    let mut f = registered();
    let log = LogBytes::default();
    let dispatch = observe::subscriber(
        observe::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("debug"),
        log.clone(),
    );
    let result = tracing::subscriber::with_default(dispatch, || {
        carry(&mut f, FaultControl::default())?;
        f.overlay.recover(&mut f.store, &f.owner, &mut f.source)
    });
    assert_eq!(
        (result.is_ok(), recovery_outcomes(&log)),
        (true, vec!["repaired".to_owned(), "clean".to_owned()]),
        "{result:?}"
    );
}

/// The carry belongs to the recovery the opener ran: a component opened with
/// the carry enabled while ownership was pending, and recovered later, does
/// not carry, and its base refusal leaves the journal as it was.
#[test]
fn a_carry_enabled_at_open_does_not_carry_at_a_later_recovery() {
    let mut f = registered();
    let before = f.io.bytes(&f.overlay.journal_path());
    let mut pending = OverlayStore::open_shared(
        &f.store,
        f.overlay.config.clone(),
        head(),
        f.overlay.base.clone(),
        &OwnershipStatus::PendingReconciliation,
        &mut f.source,
        f.io.clone(),
        FaultControl::default(),
        true,
    )
    .unwrap();
    assert_eq!(
        pending.readiness(),
        OverlayReadiness::PendingReconciliation,
        "fixture precondition: the open waits for ownership"
    );
    let result = pending.recover(&mut f.store, &f.owner, &mut f.source);
    assert_eq!(
        (
            result.as_ref().err().map(ToString::to_string),
            f.io.bytes(&f.overlay.journal_path()) == before,
            has_temporary(&f),
        ),
        (
            Some(OverlayError::refused("base root/sequence mismatch").to_string()),
            true,
            false
        )
    );
}

/// The fixture after a landing published `f` and an empty directory `d` and
/// retired the stage that held `f`: its journal holds the landing's refresh
/// registration alone, and `f`'s stage id is issued and unbound.
fn landed() -> Fixture {
    let mut f = Fixture::new();
    f.overlay
        .namespace_record(
            &mut f.store,
            &f.owner,
            Record::Create {
                at: at("d"),
                kind: codec::CreateKind::Dir,
            },
        )
        .unwrap();
    let id = f.create();
    f.write(id, b"landed");
    let proof = f.boundary_proof();
    let proof = f.landing(proof);
    f.overlay
        .replace_landed(&mut f.store, &f.owner, proof)
        .unwrap();
    f
}

/// A replacement onto an adopted head refuses a journal that holds local
/// work, before anything is written: one case per namespace or stage record
/// kind appended to a landed journal, each with only the record its kind
/// needs before it, and an open boundary. Each leaves the journal's bytes
/// and no temporary. A journal of the landing's bookkeeping alone is
/// replaced by the head's header. Case count 12.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table of the record kinds over the same landed fixture"
)]
fn replace_adopted_refuses_a_journal_with_unpublished_records() {
    let landed_content = GrainId::of(b"landed");
    let recreate = Record::RecreateFile {
        at: None,
        exec: false,
        stage_id: 1,
        anchor: Some(codec::RecreateAnchor {
            content: landed_content,
            size: 6,
        }),
    };
    let cases: Vec<(&str, Vec<Record>)> = vec![
        (
            "create",
            vec![Record::Create {
                at: at("n"),
                kind: codec::CreateKind::Dir,
            }],
        ),
        (
            "stage bind",
            vec![Record::StageBind {
                at: at("f"),
                cause: codec::BindCause::CopyUp,
                stage_id: 2,
                staged_size: 6,
                base_content: landed_content,
            }],
        ),
        (
            "write extent",
            vec![
                recreate.clone(),
                Record::WriteExtent {
                    stage_id: 1,
                    offset: 0,
                    length: 1,
                    check: codec::extent_check(1, 0, b"x"),
                },
            ],
        ),
        (
            "truncate",
            vec![
                recreate.clone(),
                Record::Truncate {
                    stage_id: 1,
                    new_size: 2,
                },
            ],
        ),
        (
            "move",
            vec![Record::Move {
                from: at("d"),
                to: at("e"),
            }],
        ),
        (
            "replace",
            vec![
                Record::Create {
                    at: at("e"),
                    kind: codec::CreateKind::Dir,
                },
                Record::Replace {
                    from: at("e"),
                    to: at("d"),
                },
            ],
        ),
        (
            "delete",
            vec![Record::Delete {
                at: at("d"),
                kind: codec::DeleteKind::Dir,
            }],
        ),
        (
            "setattr exec",
            vec![Record::SetattrExec {
                at: at("f"),
                exec: true,
            }],
        ),
        (
            "file synced",
            vec![
                recreate.clone(),
                Record::FileSynced {
                    stage_id: 1,
                    synced_size: 6,
                    content: landed_content,
                    generation: 21,
                    prepared_root: grain(2),
                },
            ],
        ),
        ("recreate file", vec![recreate.clone()]),
    ];
    let mut observed = Vec::new();
    for (case, records) in &cases {
        let mut f = landed();
        for record in records {
            f.overlay
                .append(record)
                .unwrap_or_else(|error| panic!("{case}: premise, {record:?} appends: {error}"));
        }
        let before = f.io.bytes(&f.overlay.journal_path());
        let base = f.overlay.base.clone();
        let result = f
            .overlay
            .replace_adopted(&mut f.store, &f.owner, grain(9), 3, base);
        observed.push((
            *case,
            result.err().map(|error| error.to_string()),
            f.io.bytes(&f.overlay.journal_path()) == before,
            has_temporary(&f),
        ));
    }
    {
        let mut f = landed();
        f.overlay
            .capture_boundary(&mut f.store, &f.owner)
            .and_then(|capture| {
                f.overlay
                    .record_boundary(&mut f.store, &f.owner, capture, grain(3), [7; 16])
            })
            .unwrap();
        let before = f.io.bytes(&f.overlay.journal_path());
        let base = f.overlay.base.clone();
        let result = f
            .overlay
            .replace_adopted(&mut f.store, &f.owner, grain(9), 3, base);
        observed.push((
            "open boundary",
            result.err().map(|error| error.to_string()),
            f.io.bytes(&f.overlay.journal_path()) == before,
            has_temporary(&f),
        ));
    }
    let refused = Some(OverlayError::refused("adoption journal not clean").to_string());
    let mut expected: Vec<_> = cases
        .iter()
        .map(|(case, _)| (*case, refused.clone(), true, false))
        .collect();
    expected.push(("open boundary", refused, true, false));
    assert_eq!(
        observed, expected,
        "(case, refusal, journal bytes unchanged, temporary left)"
    );
    let mut f = landed();
    let records = codec::scan_journal(&f.io.bytes(&f.overlay.journal_path())).unwrap();
    let base = f.overlay.base.clone();
    let result = f
        .overlay
        .replace_adopted(&mut f.store, &f.owner, grain(9), 3, base)
        .map(|change| change.paths.len())
        .map_err(|error| error.to_string());
    let after = codec::scan_journal(&f.io.bytes(&f.overlay.journal_path())).unwrap();
    assert_eq!(
        (
            result,
            (after.header.base_root, after.header.base_seq),
            after.state.next_seq(),
            (
                after.state.next_stage_id(),
                after.state.highest_generation()
            ),
            has_temporary(&f),
        ),
        (
            Ok(0),
            (grain(9), 3),
            1,
            (
                records.state.next_stage_id(),
                records.state.highest_generation()
            ),
            false,
        ),
        "control: bookkeeping alone is replaced by the head's header"
    );
    assert_eq!(observed.len() + 1, 12);
}
