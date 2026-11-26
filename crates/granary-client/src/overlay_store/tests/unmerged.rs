// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_core::support::BundleRefusal;

fn choice(id: u64, payload: &[u8]) -> (codec::UnmergedPath, Vec<u8>) {
    let mut hash = codec::ResidualPayloadHasher::new(id, payload.len() as u64);
    hash.update(payload);
    let file = codec::ResidualFile {
        stage_id: id,
        at: at("export"),
        exec: false,
        local_size: payload.len() as u64,
        payload_check: hash.finalize(),
    };
    let record = codec::ResidualDisposition {
        boundary_seq: 1,
        publication_id: [7; 16],
        landed_root: grain(8),
        landed_seq: 1,
        source_end: 1,
        disposition: codec::ResidualMode::KeepRemote,
        collision_count: 1,
        inventory_check: codec::residual_inventory_check(std::slice::from_ref(&file)).unwrap(),
    };
    let listing = codec::UnmergedPath {
        writer: header().writer,
        record,
        file,
    };
    let mut staged = StagingHeader {
        writer: header().writer,
        stage_id: id,
        mark: MarkState::Absent,
    }
    .encode()
    .unwrap();
    staged.extend_from_slice(payload);
    (listing, staged)
}

fn install_export(f: &mut Fixture, id: u64, payload: &[u8], paired: bool) -> u64 {
    let unmerged = f.overlay.area.join("unmerged");
    f.io.create_directory(&unmerged).unwrap();
    let (listing, staged) = choice(id, payload);
    let listing_bytes = listing.encode().unwrap();
    let listing_path = unmerged.join(format!("{id:016x}.path"));
    f.io.create(&listing_path).unwrap();
    f.io.write_at(&listing_path, 0, &listing_bytes).unwrap();
    let payload_path = unmerged.join(format!("{id:016x}"));
    if paired {
        let stage = f.overlay.area.join("staging").join(format!("{id:016x}"));
        f.io.create(&stage).unwrap();
        f.io.write_at(&stage, 0, &staged).unwrap();
        let mut model = f.io.0.lock().unwrap();
        let inode = model.names[&stage];
        model.names.insert(payload_path, inode);
    } else {
        f.io.create(&payload_path).unwrap();
        f.io.write_at(&payload_path, 0, &staged).unwrap();
    }
    staged.len() as u64 + listing_bytes.len() as u64
}

fn set_next_stage_id(f: &mut Fixture, next_stage_id: u64) {
    let mut journal_header = header();
    journal_header.next_stage_id = next_stage_id;
    let bytes = codec::encode_journal(&journal_header, &[]).unwrap();
    f.io.resize(&f.overlay.journal_path(), 0).unwrap();
    f.io.write_at(&f.overlay.journal_path(), 0, &bytes).unwrap();
}

fn hostable_prefix(f: &mut Fixture) -> (Vec<u8>, codec::ResidualDisposition) {
    let id = 99;
    let records = Vec::from([
        Record::Create {
            at: at("prefix"),
            kind: codec::CreateKind::File {
                exec: false,
                stage_id: 100,
            },
        },
        Record::CommitBoundary {
            candidate: grain(7),
            through_seq: 1,
            publication_id: [7; 16],
        },
        Record::LandedCommit {
            boundary_seq: 2,
            landed_root: grain(8),
            landed_seq: 2,
        },
        Record::IntentRegistered {
            generation: 1,
            prepared_root: grain(8),
            cause: codec::IntentCause::LandedRefresh,
        },
    ]);
    let mut journal_header = header();
    journal_header.next_stage_id = 100;
    let prefix = codec::encode_journal(&journal_header, &records).unwrap();
    let stage = f.overlay.area.join("staging/0000000000000064");
    let staged = StagingHeader {
        writer: journal_header.writer,
        stage_id: 100,
        mark: MarkState::Absent,
    }
    .encode()
    .unwrap();
    f.io.create(&stage).unwrap();
    f.io.write_at(&stage, 0, &staged).unwrap();
    let file = codec::ResidualFile {
        stage_id: id,
        at: at("f"),
        exec: false,
        local_size: 0,
        payload_check: codec::ResidualPayloadHasher::new(id, 0).finalize(),
    };
    let disposition = codec::ResidualDisposition {
        boundary_seq: 2,
        publication_id: [7; 16],
        landed_root: grain(8),
        landed_seq: 2,
        source_end: 4,
        disposition: codec::ResidualMode::KeepRemote,
        collision_count: 1,
        inventory_check: codec::residual_inventory_check(&[file]).unwrap(),
    };
    (prefix, disposition)
}

fn torn_after(f: &mut Fixture, prefix: &[u8], record: &Record) -> Vec<u8> {
    let mut bytes = prefix.to_vec();
    let scan = codec::scan_journal(prefix).unwrap();
    let mut frame = codec::encode_record(&scan.header, scan.state.next_seq(), record).unwrap();
    frame.pop();
    bytes.extend_from_slice(&frame);
    f.io.resize(&f.overlay.journal_path(), 0).unwrap();
    f.io.write_at(&f.overlay.journal_path(), 0, &bytes).unwrap();
    bytes
}

#[test]
fn delayed_replay_classifies_current_disposition_before_cutting_tail() {
    let mut rows = Vec::new();
    for evidence in [false, true] {
        let mut f = Fixture::new();
        let (prefix, disposition) = hostable_prefix(&mut f);
        let before = torn_after(&mut f, &prefix, &Record::ResidualDisposition(disposition));
        if evidence {
            f.io.create_directory(&f.overlay.area.join("unmerged"))
                .unwrap();
        }
        let mut pending = OverlayStore::open(
            &mut f.store,
            f.overlay.config.clone(),
            header(),
            vec![],
            &OwnershipStatus::PendingReconciliation,
            &mut f.source,
            f.io.clone(),
            FaultControl::default(),
        )
        .unwrap();
        let result = pending.recover(&mut f.store, &f.owner, &mut f.source);
        rows.push((
            evidence,
            result.map_err(|error| error.to_string()),
            f.io.bytes(&f.overlay.journal_path()) == if evidence { before } else { prefix },
        ));
    }
    assert_eq!(
        rows,
        [
            (false, Ok(()), true),
            (
                true,
                Err("overlay refused: unmerged current disposition evidence".into()),
                true
            ),
        ]
    );
}

#[test]
fn unmerged_prefix_discriminator() {
    let mut rows = Vec::new();
    for case in [
        "absent-current",
        "empty-current",
        "temporary-current",
        "installed-current",
        "installed-unrelated-tail",
        "wrong-kind",
        "wrong-seq",
    ] {
        let mut f = Fixture::new();
        let (prefix, disposition) = hostable_prefix(&mut f);
        let record = if case == "installed-unrelated-tail" {
            Record::Truncate {
                stage_id: 1,
                new_size: 0,
            }
        } else {
            Record::ResidualDisposition(disposition)
        };
        let mut before = torn_after(&mut f, &prefix, &record);
        if case == "wrong-kind" {
            before[prefix.len() + 4] = 16;
            f.io.resize(&f.overlay.journal_path(), 0).unwrap();
            f.io.write_at(&f.overlay.journal_path(), 0, &before)
                .unwrap();
        } else if case == "wrong-seq" {
            before[prefix.len() + 5..prefix.len() + 13].copy_from_slice(&6_u64.to_be_bytes());
            f.io.resize(&f.overlay.journal_path(), 0).unwrap();
            f.io.write_at(&f.overlay.journal_path(), 0, &before)
                .unwrap();
        }
        if case != "absent-current" {
            f.io.create_directory(&f.overlay.area.join("unmerged"))
                .unwrap();
        }
        if case == "temporary-current" {
            let unmerged = f.overlay.area.join("unmerged");
            let listing = codec::UnmergedPath {
                writer: header().writer,
                record: disposition,
                file: codec::ResidualFile {
                    stage_id: 1,
                    at: at("f"),
                    exec: false,
                    local_size: 0,
                    payload_check: codec::ResidualPayloadHasher::new(1, 0).finalize(),
                },
            };
            let path = unmerged.join("0000000000000001.path.next");
            f.io.create(&path).unwrap();
            f.io.write_at(&path, 0, &listing.encode().unwrap()).unwrap();
        }
        if matches!(case, "installed-current" | "installed-unrelated-tail") {
            install_export(&mut f, 99, b"old export", false);
        }
        let result = f.reopen().map_err(|error| error.to_string());
        rows.push((
            case,
            result,
            f.io.bytes(&f.overlay.journal_path())
                == if matches!(
                    case,
                    "absent-current" | "installed-unrelated-tail" | "wrong-kind" | "wrong-seq"
                ) {
                    prefix.clone()
                } else {
                    before
                },
        ));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                ("absent-current", Ok(()), true),
                (
                    "empty-current",
                    Err("overlay refused: unmerged current disposition evidence".to_owned()),
                    true,
                ),
                (
                    "temporary-current",
                    Err("overlay refused: unmerged current disposition evidence".to_owned()),
                    true,
                ),
                (
                    "installed-current",
                    Err("overlay refused: unmerged current disposition evidence".to_owned()),
                    true,
                ),
                ("installed-unrelated-tail", Ok(()), true),
                ("wrong-kind", Ok(()), true),
                ("wrong-seq", Ok(()), true),
            ],
            7,
        )
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the guard table keeps each malformed installed export beside its expected refusal"
)]
fn unmerged_installed_export_guard_rows() {
    let mut rows = Vec::new();
    for case in [
        "payload-check",
        "group-count",
        "named-history",
        "writer",
        "unresolved",
        "temporary-mismatch",
    ] {
        let mut f = Fixture::new();
        set_next_stage_id(&mut f, 100);
        install_export(&mut f, 99, b"guarded", false);
        let unmerged = f.overlay.area.join("unmerged");
        let listing_path = unmerged.join("0000000000000063.path");
        let mut listing = choice(99, b"guarded").0;
        match case {
            "payload-check" => {
                f.io.write_at(
                    &unmerged.join("0000000000000063"),
                    codec::STAGING_HEADER_LEN as u64,
                    b"X",
                )
                .unwrap();
            }
            "group-count" => listing.record.collision_count = 2,
            "named-history" => {
                let mut journal_header = header();
                journal_header.next_stage_id = 99;
                let journal = codec::encode_journal(
                    &journal_header,
                    &[Record::Create {
                        at: at("named"),
                        kind: codec::CreateKind::File {
                            exec: false,
                            stage_id: 99,
                        },
                    }],
                )
                .unwrap();
                f.io.resize(&f.overlay.journal_path(), 0).unwrap();
                f.io.write_at(&f.overlay.journal_path(), 0, &journal)
                    .unwrap();
            }
            "writer" => {
                listing.writer = [9; 16];
                let mut payload = StagingHeader {
                    writer: [9; 16],
                    stage_id: 99,
                    mark: MarkState::Absent,
                }
                .encode()
                .unwrap();
                payload.extend_from_slice(b"guarded");
                let path = unmerged.join("0000000000000063");
                f.io.resize(&path, 0).unwrap();
                f.io.write_at(&path, 0, &payload).unwrap();
            }
            "unresolved" => listing.record.landed_seq = 2,
            "temporary-mismatch" => {
                listing.file.at = at("different");
                let temporary = unmerged.join("0000000000000063.path.next");
                f.io.create(&temporary).unwrap();
                f.io.write_at(&temporary, 0, &listing.encode().unwrap())
                    .unwrap();
                listing = choice(99, b"guarded").0;
            }
            _ => {}
        }
        if case != "payload-check" && case != "named-history" {
            let bytes = listing.encode().unwrap();
            f.io.resize(&listing_path, 0).unwrap();
            f.io.write_at(&listing_path, 0, &bytes).unwrap();
        }
        rows.push((
            case,
            f.reopen()
                .map_or_else(|error| error.to_string(), |()| "Ok".to_owned()),
        ));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (
                    "payload-check",
                    "overlay refused: unmerged payload check".to_owned()
                ),
                (
                    "group-count",
                    "overlay refused: unmerged inventory binding".to_owned()
                ),
                (
                    "named-history",
                    "overlay refused: unmerged installed binding".to_owned()
                ),
                (
                    "writer",
                    "overlay refused: unmerged listing binding".to_owned()
                ),
                (
                    "unresolved",
                    "overlay refused: unmerged unresolved disposition".to_owned()
                ),
                (
                    "temporary-mismatch",
                    "overlay refused: unmerged temporary mismatch".to_owned()
                ),
            ],
            6,
        )
    );
}

#[test]
fn unmerged_installed_id_must_precede_next_stage_id() {
    let mut f = Fixture::new();
    install_export(&mut f, 1, b"unissued", false);
    let before = f.io.bytes(&f.overlay.journal_path());
    let trace = f.io.0.lock().unwrap().trace.len();
    let result = f.reopen().map_err(|error| error.to_string());
    assert_eq!(
        (
            result,
            f.io.bytes(&f.overlay.journal_path()) == before,
            f.persistence_since(trace)
        ),
        (
            Err("overlay refused: unmerged installed stage id".to_owned()),
            true,
            f.open_barriers().to_vec(),
        )
    );
}

#[test]
fn unmerged_lone_temporary_refuses_before_replay() {
    let mut f = Fixture::new();
    let mut journal_header = header();
    journal_header.next_stage_id = 100;
    let journal = codec::encode_journal(&journal_header, &[]).unwrap();
    f.io.resize(&f.overlay.journal_path(), 0).unwrap();
    f.io.write_at(&f.overlay.journal_path(), 0, &journal)
        .unwrap();
    let unmerged = f.overlay.area.join("unmerged");
    f.io.create_directory(&unmerged).unwrap();
    let listing = choice(99, b"stale").0.encode().unwrap();
    let temporary = unmerged.join("0000000000000063.path.next");
    f.io.create(&temporary).unwrap();
    f.io.write_at(&temporary, 0, &listing).unwrap();
    let before = f.io.bytes(&f.overlay.journal_path());
    assert_eq!(
        (
            f.reopen()
                .map_or_else(|error| error.to_string(), |()| "Ok".to_owned()),
            f.io.bytes(&f.overlay.journal_path()) == before,
        ),
        (
            "overlay refused: unmerged temporary missing final".to_owned(),
            true,
        )
    );
}

#[test]
fn pending_ownership_does_not_interpret_the_journal() {
    let mut rows = Vec::new();
    for pending in [true, false] {
        let mut f = Fixture::new();
        let journal = f.overlay.journal_path();
        f.io.resize(&journal, 0).unwrap();
        f.io.write_at(&journal, 0, b"unscannable journal").unwrap();
        let before = f.io.bytes(&journal);
        let ownership = if pending {
            OwnershipStatus::PendingReconciliation
        } else {
            f.owner.clone()
        };
        let result = OverlayStore::open(
            &mut f.store,
            f.overlay.config.clone(),
            header(),
            f.overlay.base.clone(),
            &ownership,
            &mut f.source,
            f.io.clone(),
            FaultControl::default(),
        );
        rows.push((
            pending,
            result
                .map(|overlay| overlay.readiness())
                .map_err(|error| error.to_string()),
            f.io.bytes(&journal) == before,
        ));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (true, Ok(OverlayReadiness::PendingReconciliation), true),
                (
                    false,
                    Err("overlay refused: journal fenced".to_owned()),
                    true,
                ),
            ],
            2,
        )
    );
}

#[test]
fn unmerged_pair_refuses_before_the_cut() {
    let mut f = Fixture::new();
    install_export(&mut f, 99, b"remote", true);
    let (prefix, _) = hostable_prefix(&mut f);
    let before = torn_after(
        &mut f,
        &prefix,
        &Record::Truncate {
            stage_id: 1,
            new_size: 0,
        },
    );
    let trace = f.io.0.lock().unwrap().trace.len();
    let result = f.reopen().map_err(|error| error.to_string());
    assert_eq!(
        (
            result,
            f.io.bytes(&f.overlay.journal_path()) == before,
            f.persistence_since(trace),
        ),
        (
            Err("overlay refused: unmerged pair pending retirement".to_owned()),
            true,
            f.open_barriers().to_vec(),
        )
    );
}

#[test]
fn unmerged_read_only_custody_accounting() {
    let mut f = Fixture::new();
    set_next_stage_id(&mut f, 100);
    let before = f.overlay.summary.charged_bytes;
    let added = install_export(&mut f, 99, b"remote", false);
    f.reopen().unwrap();
    let charged = f.overlay.summary.charged_bytes;
    let journal = f.io.bytes(&f.overlay.journal_path());
    let exact = super::super::unmerged::inventory(&mut f.io, &f.overlay.area, added)
        .and_then(|raw| super::super::unmerged::classify(raw, Some(&journal)));
    let over = super::super::unmerged::inventory(&mut f.io, &f.overlay.area, added - 1)
        .and_then(|raw| super::super::unmerged::classify(raw, Some(&journal)))
        .map_err(|error| error.to_string());
    let mut paired = Fixture::new();
    set_next_stage_id(&mut paired, 100);
    let paired_added = install_export(&mut paired, 99, b"remote", true);
    let raw = super::super::unmerged::inventory(
        &mut paired.io,
        &paired.overlay.area,
        paired.overlay.config.cap,
    )
    .unwrap();
    let lengths = super::super::unmerged::lengths(&raw);
    let mut accounted = super::super::accounting::Accounted::new(
        paired.io.clone(),
        paired.overlay.area.join("staging"),
        lengths,
    );
    accounted.inventory().unwrap();
    let pair_charge = accounted
        .unmerged()
        .values()
        .chain(accounted.stages().values())
        .try_fold(0_u64, |total, length| total.checked_add(*length));
    let listing = choice(99, b"remote").0.encode().unwrap().len() as u64;
    let payload = paired_added - listing;
    let expected_pair_charge = before
        .checked_add(listing)
        .and_then(|total| total.checked_add(payload.checked_mul(2)?));
    assert_eq!(
        (
            charged.checked_sub(before),
            exact.is_ok(),
            over,
            pair_charge,
        ),
        (
            Some(added),
            true,
            Err("overlay refused: unmerged capacity".to_owned()),
            expected_pair_charge.and_then(|total| total.checked_sub(before)),
        )
    );
}

#[test]
fn unmerged_accounting_reuses_classification_and_reinventories_on_open() {
    let mut f = Fixture::new();
    set_next_stage_id(&mut f, 100);
    install_export(&mut f, 99, b"remote", false);
    f.reopen().unwrap();
    let before =
        f.io.0
            .lock()
            .unwrap()
            .trace
            .iter()
            .filter(|(operation, _)| operation == "unmerged")
            .count();
    f.io.0.lock().unwrap().unmerged_error = Some(io::Error::other("model injected unmerged error"));
    let replay_inventory = f.overlay.io.inventory().is_ok();
    let retained = !f.overlay.io.unmerged().is_empty();
    let failed_open = f.reopen().unwrap_err().to_string();
    let retried = f.reopen().is_ok();
    let after =
        f.io.0
            .lock()
            .unwrap()
            .trace
            .iter()
            .filter(|(operation, _)| operation == "unmerged")
            .count();
    assert_eq!(
        (
            replay_inventory,
            retained,
            failed_open,
            retried,
            after - before
        ),
        (
            true,
            true,
            "overlay I/O: model injected unmerged error".to_owned(),
            true,
            2,
        )
    );
}

#[test]
fn unmerged_disk_io_classifies_unreadable() {
    let mut f = Fixture::new();
    let mut retained = f.overlay.bundle_projection();
    f.io.0.lock().unwrap().unmerged_error = Some(io::Error::from_raw_os_error(libc::EACCES));
    let error = super::super::unmerged::inventory(&mut f.io, &f.overlay.area, f.overlay.config.cap)
        .unwrap_err();
    let kind = match &error {
        OverlayError::Io(error) => Some(error.kind()),
        _ => None,
    };
    error.invalidate_bundle(&mut retained);
    assert_eq!(
        (kind, retained),
        (
            Some(io::ErrorKind::PermissionDenied),
            Err(BundleRefusal::Unreadable),
        )
    );
}

#[test]
fn unmerged_bounded_hash_deadline_refuses() {
    let mut f = Fixture::new();
    install_export(&mut f, 99, &vec![7; BUFFER * 2 + 1], false);
    f.io.0.lock().unwrap().unmerged_error = Some(io::Error::new(
        io::ErrorKind::TimedOut,
        "model injected unmerged error",
    ));
    assert_eq!(
        (
            f.reopen().unwrap_err().to_string(),
            super::super::unmerged::deadline_expired_for_test(None),
            super::super::unmerged::deadline_expired_for_test(Some(
                std::time::Duration::from_secs(30),
            )),
            super::super::unmerged::deadline_expired_for_test(Some(
                std::time::Duration::from_secs(31),
            )),
        ),
        (
            "overlay refused: unmerged custody deadline".to_owned(),
            false,
            false,
            true,
        )
    );
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "test-owned filesystem fixture measures descriptor read bounds"
)]
fn unmerged_disk_reads_are_bounded() {
    let (_scratch, mut disk, area, _) = disk_custody_fixture();
    let leaf = area.join("unmerged/0000000000000063");
    std::fs::write(&leaf, vec![7; BUFFER * 2 + 1]).unwrap();
    super::super::unmerged::reset_max_read_for_test();
    let accepted = disk.unmerged_inventory(&area, (BUFFER * 3) as u64).is_ok();
    let maximum = super::super::unmerged::max_read_for_test();
    assert_eq!(
        (accepted, maximum > 0, maximum <= BUFFER),
        (true, true, true)
    );
}

#[expect(
    clippy::disallowed_methods,
    reason = "test-owned filesystem fixture establishes descriptor custody inputs"
)]
fn disk_custody_fixture() -> (Scratch, OverlayDisk, PathBuf, u32) {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let config = config(&scratch.0);
    let mut disk = OverlayDisk::new(&scratch.0, config.euid);
    OverlayStore::establish_writer(
        &mut store,
        &config,
        &mut disk,
        &mut Fixed,
        &FaultControl::default(),
    )
    .unwrap();
    let area = scratch
        .0
        .join("overlay")
        .join(config.scope.digest().unwrap())
        .join("v");
    let unmerged = area.join("unmerged");
    std::fs::create_dir(&unmerged).unwrap();
    std::fs::set_permissions(&unmerged, std::fs::Permissions::from_mode(0o700)).unwrap();
    let leaf = unmerged.join("0000000000000063");
    std::fs::write(&leaf, b"fixture").unwrap();
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o600)).unwrap();
    (scratch, disk, area, config.euid)
}

#[expect(
    clippy::disallowed_methods,
    reason = "test-owned filesystem fixture establishes a complete installed export"
)]
fn disk_export_fixture() -> (Scratch, OverlayDisk, PathBuf, Vec<u8>) {
    let (scratch, disk, area, _) = disk_custody_fixture();
    let unmerged = area.join("unmerged");
    std::fs::remove_file(unmerged.join("0000000000000063")).unwrap();
    let (listing, staged) = choice(99, b"disk payload");
    let listing_path = unmerged.join("0000000000000063.path");
    let payload_path = unmerged.join("0000000000000063");
    std::fs::write(&listing_path, listing.encode().unwrap()).unwrap();
    std::fs::write(&payload_path, staged).unwrap();
    std::fs::set_permissions(&listing_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&payload_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut journal_header = header();
    journal_header.next_stage_id = 100;
    let journal = codec::encode_journal(&journal_header, &[]).unwrap();
    (scratch, disk, area, journal)
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "test-owned directories exercise the production entry-count bound"
)]
fn unmerged_disk_directory_count_is_bounded() {
    let mut rows = Vec::new();
    for over in [false, true] {
        let (_scratch, mut disk, area, _) = disk_custody_fixture();
        let directory = area.join("unmerged");
        let additions = super::super::unmerged::UNMERGED_ENTRY_MAX - usize::from(!over);
        for index in 0..additions {
            let path = directory.join(format!("extra-{index:08x}"));
            std::fs::write(&path, []).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut retained = Fixture::new().overlay.bundle_projection();
        let result = super::super::unmerged::inventory(&mut disk, &area, 1_048_576)
            .map(|_| ())
            .map_err(|error| {
                error.invalidate_bundle(&mut retained);
                error.to_string()
            });
        rows.push((over, result, retained.err()));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (false, Ok(()), None),
                (
                    true,
                    Err("overlay refused: unmerged capacity".to_owned()),
                    None,
                ),
            ],
            2,
        )
    );
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "test-owned symlink exercises the production custody refusal"
)]
fn unmerged_symlink_custody_latches_corrupt() {
    let (_scratch, mut disk, area, _) = disk_custody_fixture();
    let leaf = area.join("unmerged/0000000000000063");
    std::fs::remove_file(&leaf).unwrap();
    std::os::unix::fs::symlink(area.join("writer"), &leaf).unwrap();
    let mut retained = Fixture::new().overlay.bundle_projection();
    let error = super::super::unmerged::inventory(&mut disk, &area, 1_048_576).unwrap_err();
    error.invalidate_bundle(&mut retained);
    assert_eq!(
        (error.to_string(), retained),
        (
            "overlay refused: unmerged custody".to_owned(),
            Err(BundleRefusal::Corrupt),
        )
    );
}

#[test]
fn unmerged_disk_deadline_and_header_skip_rows() {
    let (_scratch, mut disk, area, journal) = disk_export_fixture();
    let raw = disk.unmerged_inventory(&area, 1_048_576).unwrap();
    let hash_pass = super::super::unmerged::classify(raw, Some(&journal)).is_ok();
    super::super::unmerged::expire_after_for_test(Some(4));
    let deadline = disk
        .unmerged_inventory(&area, 1_048_576)
        .map_or_else(|error| Some(error.kind()), |_| None);
    super::super::unmerged::expire_after_for_test(None);
    assert_eq!(
        (hash_pass, deadline, 2),
        (true, Some(io::ErrorKind::TimedOut), 2)
    );
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "test-owned filesystem adversaries exercise descriptor custody refusals"
)]
#[expect(
    clippy::too_many_lines,
    reason = "the custody table keeps each filesystem adversary beside its expected result"
)]
fn unmerged_disk_custody_adversarial_rows() {
    let mut rows = Vec::new();
    for case in [
        "valid",
        "owner",
        "mode",
        "directory-mode",
        "symlink",
        "swap",
        "grow",
        "pair-binding",
        "pair-identity",
        "listing-second-link",
        "third-link",
        "acl",
        "directory-acl",
    ] {
        let (_scratch, mut disk, area, uid) = disk_custody_fixture();
        let leaf = area.join("unmerged/0000000000000063");
        match case {
            "owner" => disk = OverlayDisk::new(disk.custody_root().0, uid + 1),
            "mode" => {
                std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o640)).unwrap();
            }
            "directory-mode" => std::fs::set_permissions(
                area.join("unmerged"),
                std::fs::Permissions::from_mode(0o750),
            )
            .unwrap(),
            "symlink" => {
                std::fs::remove_file(&leaf).unwrap();
                std::os::unix::fs::symlink(area.join("writer"), &leaf).unwrap();
            }
            "swap" => super::super::unmerged::swap_after_read_for_test(true),
            "grow" => super::super::unmerged::grow_after_read_for_test(true),
            "pair-binding" => {
                std::fs::hard_link(&leaf, area.join("unmerged/alias")).unwrap();
            }
            "pair-identity" => {
                std::fs::hard_link(&leaf, area.join("outside-payload-link")).unwrap();
                let stage = area.join("staging/0000000000000063");
                std::fs::write(&stage, b"distinct inode").unwrap();
                std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            "listing-second-link" => {
                let listing = area.join("unmerged/0000000000000063.path");
                std::fs::write(&listing, b"not required by inventory custody").unwrap();
                std::fs::set_permissions(&listing, std::fs::Permissions::from_mode(0o600)).unwrap();
                std::fs::hard_link(&listing, area.join("listing-outside-custody")).unwrap();
            }
            "third-link" => {
                let stage = area.join("staging/0000000000000063");
                std::fs::hard_link(&leaf, &stage).unwrap();
                std::fs::hard_link(&leaf, area.join("unmerged/alias")).unwrap();
            }
            "acl" => {
                #[cfg(target_vendor = "apple")]
                {
                    let output = std::process::Command::new("chmod")
                        .args(["+a", "everyone allow read"])
                        .arg(&leaf)
                        .output()
                        .unwrap();
                    assert!(output.status.success(), "ACL fixture: {output:?}");
                }
            }
            "directory-acl" => {
                #[cfg(target_vendor = "apple")]
                {
                    let output = std::process::Command::new("chmod")
                        .args(["+a", "everyone allow read"])
                        .arg(area.join("unmerged"))
                        .output()
                        .unwrap();
                    assert!(output.status.success(), "directory ACL fixture: {output:?}");
                }
            }
            _ => {}
        }
        let result = disk.unmerged_inventory(&area, 1024);
        rows.push((case, result.is_ok()));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                ("valid", true),
                ("owner", false),
                ("mode", false),
                ("directory-mode", false),
                ("symlink", false),
                ("swap", false),
                ("grow", false),
                ("pair-binding", false),
                ("pair-identity", false),
                ("listing-second-link", false),
                ("third-link", false),
                ("acl", cfg!(not(target_vendor = "apple"))),
                ("directory-acl", cfg!(not(target_vendor = "apple"))),
            ],
            13,
        )
    );
}
