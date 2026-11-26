// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::super::archive::{
    archive_read_error, durable_archive, move_archive, native_no_replace, remove_duplicate,
};
use super::*;
use granary_core::{hash::GrainId, retained_archive::ArchiveName};
use std::os::unix::ffi::OsStrExt as _;
mod vectors;

const ACK: MayLandAcknowledgement = MayLandAcknowledgement::Acknowledged;

#[test]
fn proof_acknowledgement_migration_repairs_only_identical_archive_aliases() {
    let mut cases = 0;
    for (linked, changed) in [(false, false), (true, false), (false, true)] {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.0).unwrap();
        let mut p = store.publications(scratch.uid()).unwrap();
        let mut record = fixture("ready");
        record.last_response = None;
        record.candidates[0].evidence = codec::Evidence::default();
        let proof = crate::RejectionProof::NoWrite(
            crate::NoWriteProof::from_submission(&record, 8).unwrap(),
        );
        let faults = crate::FaultControl::default();
        p.begin(&record).unwrap();
        let plain = p
            .abandon(&record.scope, &record.volume, record.publication_id, ACK)
            .unwrap()
            .archive
            .path;
        let settled = p
            .abandon(
                &record.scope,
                &record.volume,
                record.publication_id,
                AbandonAcknowledgement::Proven(&proof, &faults),
            )
            .unwrap()
            .archive;
        assert!(!plain.exists(), "migration left its source name");
        if linked {
            fs::hard_link(&settled.path, &plain).unwrap();
        } else if changed {
            let mut other = settled.submission.clone();
            other.generation += 1;
            put(&plain, &codec::encode(&other).unwrap());
        } else {
            fs::copy(&settled.path, &plain).unwrap();
        }
        let inspected = p
            .inspect_archive(
                &record.scope.digest().unwrap(),
                &record.volume,
                record.publication_id,
            )
            .map(|archive| archive.settled)
            .map_err(|error| error.reason);
        let result = p.abandon(
            &record.scope,
            &record.volume,
            record.publication_id,
            AbandonAcknowledgement::Proven(&proof, &faults),
        );
        let healthy = VolumeName::new("healthy".to_owned()).unwrap();
        let same_handle = p
            .inspect_selected(&record.scope, &healthy)
            .map(|record| record.is_none())
            .map_err(|e| e.reason);
        drop(p);
        let fresh_view = store
            .publications(scratch.uid())
            .and_then(|mut p| p.inspect_selected(&record.scope, &healthy))
            .map(|record| record.is_none())
            .map_err(|e| e.reason);
        assert_eq!(
            (
                result.err().map(|e| e.reason),
                inspected,
                plain.exists(),
                settled.path.exists(),
                same_handle,
                fresh_view
            ),
            (
                changed.then(|| "conflicting archive acknowledgement bytes".to_owned()),
                if changed {
                    Err("conflicting archive acknowledgement bytes".to_owned())
                } else {
                    Ok(true)
                },
                changed,
                true,
                Ok(true),
                Ok(true)
            ),
            "linked={linked}, changed={changed}"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
fn proof_settlement_acknowledges_only_its_archive_for_later_loads() {
    let mut cases = 0;
    for proven in [false, true] {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.0).unwrap();
        let mut p = store.publications(scratch.uid()).unwrap();
        let mut record = fixture("ready");
        record.last_response = None;
        record.candidates[0].evidence = codec::Evidence::default();
        let proof = crate::RejectionProof::NoWrite(
            crate::NoWriteProof::from_submission(&record, 8).unwrap(),
        );
        p.begin(&record).unwrap();
        let faults = crate::FaultControl::default();
        let ack = if proven {
            AbandonAcknowledgement::Proven(&proof, &faults)
        } else {
            ACK.into()
        };
        p.abandon(&record.scope, &record.volume, record.publication_id, ack)
            .unwrap();
        let loaded = p
            .load(&record.scope, &record.volume)
            .map(|r| r.is_none())
            .map_err(|e| (e.kind, e.reason));
        let inspected = p
            .inspect_selected(&record.scope, &record.volume)
            .map(|r| r.is_none())
            .map_err(|e| (e.kind, e.reason));
        let direct = p
            .select_direct(&record.volume, None)
            .map(|_| true)
            .map_err(|e| (e.kind, e.reason));
        let expected = if proven {
            Ok(true)
        } else {
            Err((
                PublicationStoreErrorKind::Abandoned,
                "abandoned publication; explicit new acknowledgement required".to_owned(),
            ))
        };
        assert_eq!(
            (loaded, inspected, direct),
            (expected.clone(), expected.clone(), expected),
            "proven={proven}: (load, inspect, direct)"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn proven_abandonment_checks_the_fresh_candidate_evidence_before_archival() {
    let mut cases = 0;
    for changed in [false, true] {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.0).unwrap();
        let mut p = store.publications(scratch.uid()).unwrap();
        let mut record = fixture("ready");
        record.last_response = None;
        record.candidates[0].evidence = codec::Evidence::default();
        let proof = crate::RejectionProof::NoWrite(
            crate::NoWriteProof::from_submission(&record, 8).unwrap(),
        );
        if changed {
            record.candidates[0].evidence.start().unwrap();
        }
        p.begin(&record).unwrap();
        let result = p.abandon(
            &record.scope,
            &record.volume,
            record.publication_id,
            AbandonAcknowledgement::Proven(&proof, &crate::FaultControl::default()),
        );
        if changed {
            assert_eq!(
                (
                    result.err().map(|e| e.reason),
                    p.observe(&record.scope, &record.volume).unwrap(),
                    p.archived(
                        &record.scope.digest().unwrap(),
                        &record.volume,
                        record.publication_id
                    )
                    .unwrap()
                ),
                (
                    Some("abandonment proof binding".to_owned()),
                    Some(record),
                    false
                )
            );
        } else {
            let archive = result.unwrap().archive;
            let bytes = fs::read(&archive.path).unwrap();
            let golden =
                include_bytes!("../../../tests/vectors/publication-archives/proof-no-write-v2.bin");
            let hash =
                include_str!("../../../tests/vectors/publication-archives/proof-no-write-v2.hash");
            assert_eq!(
                (bytes.as_slice(), GrainId::of(&bytes).to_string()),
                (golden.as_slice(), hash.trim().to_owned())
            );
            assert_eq!(GrainId::of(vectors::BYTES).to_string(), vectors::HASH);
            assert_eq!(
                codec::decode(vectors::BYTES),
                Ok(archive.submission.clone())
            );
            assert_eq!(codec::decode(&bytes), Ok(archive.submission.clone()));
            assert_eq!(
                codec::encode(&codec::decode(&bytes).unwrap()).unwrap(),
                bytes
            );
            assert_eq!(
                (
                    archive.submission.publication_id,
                    archive.uncertain,
                    p.observe(&record.scope, &record.volume).unwrap()
                ),
                (record.publication_id, false, None)
            );
            p.abandon(
                &record.scope,
                &record.volume,
                record.publication_id,
                AbandonAcknowledgement::Proven(&proof, &crate::FaultControl::default()),
            )
            .unwrap();
        }
        cases += 1;
    }
    assert_eq!(cases, 2);
}

fn archive_path(p: &PublicationStore<'_>, s: &Submission) -> PathBuf {
    p.root()
        .join("publications")
        .join(s.scope.digest().unwrap())
        .join(
            ArchiveName {
                settled: false,
                volume: s.volume.clone(),
                publication_id: s.publication_id,
            }
            .file_name(),
        )
}
fn put(path: &Path, bytes: &[u8]) {
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    fs::write(path, bytes).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn seeded_archive(p: &mut PublicationStore<'_>, s: &Submission) -> PathBuf {
    p.begin(s).unwrap();
    let live = p.path(&s.scope, &s.volume).unwrap();
    let archive = archive_path(p, s);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    fs::rename(live, &archive).unwrap();
    archive
}

#[test]
fn abandonment_requires_ack_exact_target_and_incomplete_phase() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let mut s = fixture("ready");
    p.begin(&s).unwrap();
    let live = p.path(&s.scope, &s.volume).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let before = fs::read(&live).unwrap();
    assert!(
        p.abandon(
            &s.scope,
            &s.volume,
            s.publication_id,
            MayLandAcknowledgement::Unacknowledged
        )
        .is_err()
    );
    assert!(p.abandon(&s.scope, &s.volume, [0xff; 16], ACK).is_err());
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(&live).unwrap();
    assert_eq!(observed, before);
    assert!(!p.poisoned);
    complete(&mut s);
    put(&live, &codec::encode(&s).unwrap());
    assert!(
        p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
            .unwrap_err()
            .reason
            .contains("complete")
    );
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = live.exists();
    assert!(observed);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = !archive_path(&p, &s).exists();
    assert!(observed);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    fs::remove_file(&live).unwrap();
    assert_eq!(
        p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
            .unwrap_err()
            .kind,
        PublicationStoreErrorKind::MissingPublication
    );
}
#[test]
fn abandonment_preserves_independent_namespace_vectors_and_all_evidence() {
    #[expect(clippy::disallowed_methods, reason = "read committed test vectors")]
    let manifest = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/publication-archives/namespace.tsv"),
    )
    .unwrap();
    let mut names = BTreeSet::new();
    for row in manifest.lines().filter(|l| !l.starts_with('#')) {
        let columns: Vec<_> = row.split('\t').collect();
        let name = columns[0];
        names.insert(name.to_owned());
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.0).unwrap();
        let mut p = store.publications(scratch.uid()).unwrap();
        #[expect(clippy::disallowed_methods, reason = "read committed test vectors")]
        let bytes = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("tests/vectors/publication-archives/{name}.bin")),
        )
        .unwrap();
        let expected = codec::decode(&bytes).unwrap();
        assert_eq!(GrainId::of(&bytes).to_string(), columns[1]);
        assert_eq!(expected.scope.digest().unwrap(), columns[2]);
        assert_eq!(expected.volume.as_str(), columns[3]);
        assert_eq!(
            ArchiveName {
                settled: false,
                volume: expected.volume.clone(),
                publication_id: expected.publication_id
            }
            .file_name(),
            columns[4]
        );
        let archive = archive_path(&p, &expected);
        if bytes.get(8..10) == Some(&[0, 1]) {
            let mut initial = expected.clone();
            initial.generation = 1;
            seeded_archive(&mut p, &initial);
            put(&archive, &bytes);
        } else {
            let mut initial = expected.clone();
            initial.generation = 1;
            p.begin(&initial).unwrap();
        }
        assert_namespace_abandonment(&mut p, &expected, &bytes, &archive);
    }
    assert_eq!(
        names,
        [
            "catalogue",
            "capacity",
            "awaiting",
            "response-answer",
            "max-generation",
            "v2-catalogue",
            "v2-capacity",
            "v2-awaiting",
            "v2-response-answer",
        ]
        .map(str::to_owned)
        .into_iter()
        .collect()
    );
}
fn assert_namespace_abandonment(
    p: &mut PublicationStore<'_>,
    expected: &Submission,
    bytes: &[u8],
    archive: &Path,
) {
    let result = p
        .abandon(
            &expected.scope,
            &expected.volume,
            expected.publication_id,
            ACK,
        )
        .unwrap();
    assert_eq!(result.archive.path, archive);
    assert_eq!(result.archive.submission, *expected);
    assert_eq!(
        result.archive.uncertain,
        expected
            .candidates
            .iter()
            .any(|c| !c.evidence.never_decided())
    );
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(archive).unwrap();
    assert_eq!(observed, bytes);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = !p.path(&expected.scope, &expected.volume).unwrap().exists();
    assert!(observed);
    assert_eq!(
        p.abandon(
            &expected.scope,
            &expected.volume,
            expected.publication_id,
            ACK
        )
        .unwrap(),
        result
    );
    assert_eq!(
        p.inspect_archive(
            &expected.scope.digest().unwrap(),
            &expected.volume,
            expected.publication_id
        )
        .unwrap(),
        result.archive
    );
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(archive).unwrap();
    assert_eq!(observed, bytes);
    assert_eq!(
        p.load(&expected.scope, &expected.volume).unwrap_err().kind,
        PublicationStoreErrorKind::Abandoned
    );
}
#[test]
fn changed_pins_allow_only_acknowledged_abandonment_and_report_both_sets() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    let mut configured = s.scope.clone();
    configured.pins = vec![[0x77; 32]];
    assert_eq!(configured.digest().unwrap(), s.scope.digest().unwrap());
    assert!(
        p.load(&configured, &s.volume)
            .unwrap_err()
            .reason
            .contains("scope mismatch")
    );
    let result = p
        .abandon(&configured, &s.volume, s.publication_id, ACK)
        .unwrap();
    assert_eq!(
        result.pin_difference,
        Some(PinDifference {
            retained: s.scope.pins.clone(),
            configured: configured.pins.clone()
        })
    );
    assert_eq!(result.archive.submission.scope, s.scope);
    assert_eq!(
        p.abandon(&configured, &s.volume, s.publication_id, ACK)
            .unwrap(),
        result
    );
}
#[test]
fn same_id_equal_duplicates_block_selection_then_retry_unlinks_only_live() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("catalogue");
    let archive = seeded_archive(&mut p, &s);
    let live = p.path(&s.scope, &s.volume).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let bytes = fs::read(&archive).unwrap();
    put(&live, &bytes);
    assert!(p.load(&s.scope, &s.volume).is_err());
    assert!(p.load_for_new(&s.scope, &s.volume, ACK).is_err());
    let mut next = s.clone();
    next.generation = 2;
    assert!(p.replace(1, &next).is_err());
    assert!(p.begin(&s).is_err());
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(&live).unwrap();
    assert_eq!(observed, bytes);
    let result = p
        .abandon(&s.scope, &s.volume, s.publication_id, ACK)
        .unwrap();
    assert_eq!(result.archive.submission, s);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = !live.exists();
    assert!(observed);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(archive).unwrap();
    assert_eq!(observed, bytes);
}
#[test]
fn differing_duplicate_bytes_refuse_without_advancing_or_deleting() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("catalogue");
    let archive = seeded_archive(&mut p, &s);
    let live = p.path(&s.scope, &s.volume).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let before = fs::read(&archive).unwrap();
    let mut changed = s.clone();
    changed.candidates[0].evidence.started += 1;
    let differing = codec::encode(&changed).unwrap();
    put(&live, &differing);
    assert!(
        p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
            .unwrap_err()
            .reason
            .contains("conflicting")
    );
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(&live).unwrap();
    assert_eq!(observed, differing);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(&archive).unwrap();
    assert_eq!(observed, before);
    assert!(!p.poisoned);
    complete(&mut changed);
    put(&live, &codec::encode(&changed).unwrap());
    assert!(
        p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
            .is_err()
    );
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = live.exists();
    assert!(observed);
}
#[test]
fn same_inode_complete_retry_preserves_both_names() {
    assert_same_inode_refusal_preserves_names(true);
}
#[test]
fn same_inode_different_id_retry_preserves_both_names() {
    assert_same_inode_refusal_preserves_names(false);
}
fn assert_same_inode_refusal_preserves_names(terminal: bool) {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    let live = p.path(&s.scope, &s.volume).unwrap();
    let archive = archive_path(&p, &s);
    let mut rejected = s.clone();
    if terminal {
        complete(&mut rejected);
    } else {
        rejected.publication_id = [0xff; 16];
    }
    let bytes = codec::encode(&rejected).unwrap();
    put(&live, &bytes);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory: plant the two-link canonical pair"
    )]
    fs::hard_link(&live, &archive).unwrap();
    let refusal = p
        .abandon(&s.scope, &s.volume, s.publication_id, ACK)
        .unwrap_err();
    for path in [&live, &archive] {
        #[expect(
            clippy::disallowed_methods,
            reason = "test-owned private scratch directory: prove refused retry preserved each name and its bytes"
        )]
        let observed = fs::read(path).unwrap();
        assert_eq!(observed, bytes);
        let meta = fs::symlink_metadata(path).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.nlink(), 2);
    }
    assert!(
        refusal
            .reason
            .contains(if terminal { "complete" } else { "mismatch" })
    );
    assert!(!p.poisoned);
}

#[test]
fn same_inode_pair_retry_repairs_only_exact_two_link_crash_state() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("catalogue");
    let archive = seeded_archive(&mut p, &s);
    assert_eq!(p.list_archives(&s.volume).unwrap().len(), 1);
    let live = p.path(&s.scope, &s.volume).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    fs::hard_link(&archive, &live).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let before = fs::read(&archive).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let inode = fs::metadata(&archive).unwrap().ino();
    assert!(p.load(&s.scope, &s.volume).is_err());
    assert_eq!(
        p.list_archives(&s.volume)
            .map(|a| a.len())
            .map_err(|e| (e.kind, e.reason)),
        Err((
            PublicationStoreErrorKind::Refused,
            format!(
                "{} has 2 links; a retained submission must have exactly one",
                archive.display()
            ),
        ))
    );
    let third = archive.with_extension("third");
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    fs::hard_link(&archive, &third).unwrap();
    assert!(
        p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
            .is_err()
    );
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = live.exists();
    assert!(observed);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    fs::remove_file(third).unwrap();
    let result = p
        .abandon(&s.scope, &s.volume, s.publication_id, ACK)
        .unwrap();
    assert_eq!(result.archive.submission, s);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = !live.exists();
    assert!(observed);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::metadata(&archive).unwrap().nlink();
    assert_eq!(observed, 1);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::metadata(&archive).unwrap().ino();
    assert_eq!(observed, inode);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(archive).unwrap();
    assert_eq!(observed, before);
}
#[test]
fn archive_retry_keeps_a_different_live_id_and_explicit_new_guards() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    let archive = seeded_archive(&mut p, &s);
    assert_eq!(
        p.load(&s.scope, &s.volume).unwrap_err().kind,
        PublicationStoreErrorKind::Abandoned
    );
    assert!(
        p.load_for_new(&s.scope, &s.volume, MayLandAcknowledgement::Unacknowledged)
            .is_err()
    );
    assert_eq!(p.load_for_new(&s.scope, &s.volume, ACK).unwrap(), None);
    assert!(
        p.begin(&s)
            .unwrap_err()
            .reason
            .contains("archived publication identity")
    );
    let mut new = s.clone();
    new.publication_id = [0xff; 16];
    p.begin(&new).unwrap();
    let live = p.path(&s.scope, &s.volume).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let before = fs::read(&live).unwrap();
    p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
        .unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(&live).unwrap();
    assert_eq!(observed, before);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = archive.exists();
    assert!(observed);
    new.generation = 2;
    assert_eq!(p.load(&new.scope, &new.volume).unwrap(), Some(new));
}
#[test]
fn archive_scan_parses_whole_directory_and_begin_checks_other_volume_ids() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    let archive = seeded_archive(&mut p, &s);
    let malformed = archive
        .parent()
        .unwrap()
        .join("bad.name.abandoned-000102030405060708090a0b0c0d0e0f.sub");
    put(&malformed, b"unrelated bytes");
    let mut new = s.clone();
    new.publication_id = [0xff; 16];
    assert_eq!(p.list_archives(&s.volume).unwrap_err().path, malformed);
    assert_eq!(p.load(&s.scope, &s.volume).unwrap_err().path, malformed);
    assert_eq!(p.begin(&new).unwrap_err().path, malformed);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    fs::remove_file(malformed).unwrap();
    let mut other = s.clone();
    change_volume(&mut other, "other");
    assert!(
        p.begin(&other)
            .unwrap_err()
            .reason
            .contains("archived publication identity")
    );
    other.publication_id = [0xfe; 16];
    p.begin(&other).unwrap();
    assert_eq!(p.list_archives(&s.volume).unwrap().len(), 1);
}
fn change_volume(s: &mut Submission, volume: &str) {
    s.volume = VolumeName::from_bytes(volume.as_bytes()).unwrap();
    let change = |bytes: &[u8]| {
        let mut root = granary_core::root::decode_root(bytes).unwrap();
        root.volume = s.volume.clone();
        granary_core::root::encode_root(&root).unwrap()
    };
    s.frozen.initial_root = change(&s.frozen.initial_root);
    for c in &mut s.candidates {
        c.root = change(&c.root);
        c.id = GrainId::of(&c.root);
    }
}
#[test]
fn targeted_abandonment_does_not_release_another_incomplete_scope() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    let mut other = s.clone();
    other.scope.credential_context.push(b'x');
    other.publication_id = [0xff; 16];
    let path = p.path(&other.scope, &other.volume).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let mut directory = fs::DirBuilder::new();
    directory.mode(0o700);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    directory.create(path.parent().unwrap()).unwrap();
    put(&path, &codec::encode(&other).unwrap());
    assert!(p.load(&s.scope, &s.volume).is_err());
    p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
        .unwrap();
    assert_eq!(
        p.load_for_new(&s.scope, &s.volume, ACK).unwrap_err().path,
        path
    );
    assert!(p.begin(&s).is_err());
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = path.exists();
    assert!(observed);
    assert_eq!(p.list_archives(&s.volume).unwrap().len(), 1);
}
#[test]
fn native_no_replace_resolves_leaves_in_validated_directory() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    let live = p.path(&s.scope, &s.volume).unwrap();
    let archive = archive_path(&p, &s);
    let scope = live.parent().unwrap();
    let directory = p.disk.directory(scope, true).unwrap();
    let relocated = scope.with_extension("relocated");
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory: move the scope after its descriptor was validated"
    )]
    fs::rename(scope, &relocated).unwrap();
    p.disk.ensure_directory(scope).unwrap();
    put(&live, b"decoy");
    let from = std::ffi::CString::new(live.file_name().unwrap().as_bytes()).unwrap();
    let to = std::ffi::CString::new(archive.file_name().unwrap().as_bytes()).unwrap();
    native_no_replace(&directory, &from, &to).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory: prove the original path's decoy was not moved"
    )]
    let observed = fs::read(&live).unwrap();
    assert_eq!(observed, b"decoy");
    assert!(fs::symlink_metadata(&archive).is_err());
    assert!(fs::symlink_metadata(relocated.join(live.file_name().unwrap())).is_err());
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory: prove the opened directory's retained record was moved"
    )]
    let observed = fs::read(relocated.join(archive.file_name().unwrap())).unwrap();
    assert_eq!(codec::decode(&observed).unwrap(), s);
}

#[test]
fn native_no_replace_preserves_collisions_including_dangling_symlink() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    let live = p.path(&s.scope, &s.volume).unwrap();
    let archive = archive_path(&p, &s);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let before = fs::read(&live).unwrap();
    put(&archive, &before);
    assert_eq!(
        p.disk
            .rename_no_replace(&live, &archive)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(&live).unwrap();
    assert_eq!(observed, before);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(&archive).unwrap();
    assert_eq!(observed, before);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    fs::remove_file(&archive).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    symlink("absent", &archive).unwrap();
    assert!(p.disk.rename_no_replace(&live, &archive).is_err());
    assert!(
        fs::symlink_metadata(&archive)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(&live).unwrap();
    assert_eq!(observed, before);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    fs::remove_file(&archive).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let inode = fs::metadata(&live).unwrap().ino();
    p.disk.rename_no_replace(&live, &archive).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = !live.exists();
    assert!(observed);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::metadata(archive).unwrap().ino();
    assert_eq!(observed, inode);
}
#[test]
fn unsupported_or_uncertain_move_fails_closed_and_poisons() {
    for (errno, after) in [
        (libc::EINVAL, false),
        (libc::ENOSYS, false),
        (libc::EOPNOTSUPP, false),
        (libc::EIO, true),
    ] {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.0).unwrap();
        let s = fixture("ready");
        {
            let mut p = store.publications(scratch.uid()).unwrap();
            p.begin(&s).unwrap();
            p.disk.fail_move = Some((errno, after));
            let live = p.path(&s.scope, &s.volume).unwrap();
            let archive = archive_path(&p, &s);
            assert!(
                p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
                    .is_err()
            );
            assert!(p.poisoned);
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            let observed = live.exists();
            assert_eq!(observed, !after);
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            let observed = archive.exists();
            assert_eq!(observed, after);
            p.disk.fail_move = None;
            assert!(
                p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
                    .unwrap_err()
                    .reason
                    .contains("reload")
            );
            assert!(p.list_archives(&s.volume).is_err());
            assert!(p.load_for_new(&s.scope, &s.volume, ACK).is_err());
        }
        drop(store);
        let mut store = Store::open(&scratch.0).unwrap();
        let mut p = store.publications(scratch.uid()).unwrap();
        p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
            .unwrap();
    }
}

#[test]
fn archive_custody_payload_and_path_rejections_never_become_absence() {
    for kind in [
        "corrupt",
        "oversized",
        "noncanonical",
        "wrong-scope",
        "wrong-id",
        "wrong-volume",
        "complete",
        "symlink",
        "hardlink",
        "nonregular",
        "fifo",
        "mode",
        "owner",
    ] {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.0).unwrap();
        let mut p = store.publications(scratch.uid()).unwrap();
        let s = fixture("ready");
        let archive = seeded_archive(&mut p, &s);
        #[expect(
            clippy::disallowed_methods,
            reason = "test-owned private scratch directory"
        )]
        let bytes = fs::read(&archive).unwrap();
        if kind == "owner" {
            p.disk.euid = scratch.uid() + 1;
            assert!(
                p.disk
                    .open_checked_record(&archive)
                    .unwrap_err()
                    .to_string()
                    .contains("owner")
            );
            p.disk.euid = scratch.uid();
            continue;
        }
        plant_rejected_archive(kind, &s, &archive);
        assert!(
            p.disk.open_checked_record(&archive).is_err()
                || [
                    "corrupt",
                    "oversized",
                    "noncanonical",
                    "wrong-scope",
                    "wrong-id",
                    "wrong-volume",
                    "complete"
                ]
                .contains(&kind)
        );
        // A hard link puts the same refused inode under two names; directory
        // order decides which one the walk meets first, so either is the refusal.
        let refused = if kind == "hardlink" {
            vec![archive.clone(), archive.with_extension("extra")]
        } else {
            vec![archive.clone()]
        };
        let listed = p.list_archives(&s.volume).unwrap_err().path;
        assert!(refused.contains(&listed), "{kind}: {listed:?}");
        let loaded = p.load(&s.scope, &s.volume).unwrap_err().path;
        assert!(refused.contains(&loaded), "{kind}: {loaded:?}");
        let mut new = s.clone();
        new.publication_id = [0xff; 16];
        let begun = p.begin(&new).unwrap_err().path;
        assert!(refused.contains(&begun), "{kind}: {begun:?}");
        assert!(
            p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
                .is_err(),
            "{kind}"
        );
        assert!(fs::symlink_metadata(&archive).is_ok());
        if kind == "hardlink" {
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            let observed = fs::read(&archive).unwrap();
            assert_eq!(observed, bytes);
        }
    }
}

fn plant_rejected_archive(kind: &str, s: &Submission, archive: &Path) {
    match kind {
        "corrupt" => put(archive, b"broken"),
        "oversized" => {
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            let mut options = File::options();
            options.write(true);
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            let file = options.open(archive).unwrap();
            file.set_len(codec::MAX_BYTES as u64 + 1).unwrap();
        }
        "noncanonical" => {
            let reject = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../granary-core/tests/vectors/retained-submission/reject-pins-order");
            #[expect(clippy::disallowed_methods, reason = "read committed test vectors")]
            put(archive, &fs::read(reject).unwrap());
        }
        "wrong-scope" => {
            let mut changed = s.clone();
            changed.scope.credential_context.push(b'x');
            put(archive, &codec::encode(&changed).unwrap());
        }
        "wrong-id" => {
            let mut changed = s.clone();
            changed.publication_id = [99; 16];
            put(archive, &codec::encode(&changed).unwrap());
        }
        "wrong-volume" => {
            let mut changed = s.clone();
            change_volume(&mut changed, "other");
            put(archive, &codec::encode(&changed).unwrap());
        }
        "complete" => {
            let mut changed = s.clone();
            complete(&mut changed);
            put(archive, &codec::encode(&changed).unwrap());
        }
        "symlink" => {
            // Keep the displaced archive outside every archive filename grammar.
            // A malformed archive-shaped backup could win the directory walk on
            // filesystems whose iteration order differs from APFS.
            let saved = archive.parent().unwrap().join("parked-original");
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            fs::rename(archive, &saved).unwrap();
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            symlink(&saved, archive).unwrap();
        }
        "hardlink" => {
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            fs::hard_link(archive, archive.with_extension("extra")).unwrap();
        }
        "nonregular" => {
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            fs::remove_file(archive).unwrap();
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            fs::create_dir(archive).unwrap();
        }
        "fifo" => {
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            fs::remove_file(archive).unwrap();
            crate::fsguard::testutil::mkfifo(archive);
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            fs::set_permissions(archive, fs::Permissions::from_mode(0o600)).unwrap();
        }
        "mode" => {
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            fs::set_permissions(archive, fs::Permissions::from_mode(0o640)).unwrap();
        }
        _ => unreachable!(),
    }
}
#[cfg(target_vendor = "apple")]
#[test]
fn archive_granting_acl_refuses_every_touch() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    let archive = seeded_archive(&mut p, &s);
    assert!(
        std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&archive)
            .status()
            .unwrap()
            .success()
    );
    assert!(p.disk.open_checked_record(&archive).is_err());
    assert!(p.list_archives(&s.volume).is_err());
    assert!(p.load(&s.scope, &s.volume).is_err());
    assert!(
        p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
            .is_err()
    );
    assert!(
        std::process::Command::new("chmod")
            .arg("-N")
            .arg(&archive)
            .status()
            .unwrap()
            .success()
    );
    assert!(p.list_archives(&s.volume).is_ok());
}
#[test]
fn archive_directory_barrier_failure_never_yields_selection_and_poison_sticks() {
    for level in ["root", "parent", "publications", "scope"] {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.0).unwrap();
        let s = fixture("ready");
        {
            let mut p = store.publications(scratch.uid()).unwrap();
            let archive = seeded_archive(&mut p, &s);
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            let bytes = fs::read(&archive).unwrap();
            let failure = match level {
                "root" => scratch.0.clone(),
                "parent" => scratch.0.parent().unwrap().to_owned(),
                "publications" => scratch.0.join("publications"),
                _ => archive.parent().unwrap().to_owned(),
            };
            p.disk.fail_directory_sync = Some(failure);
            assert!(p.load_for_new(&s.scope, &s.volume, ACK).is_err(), "{level}");
            assert!(p.poisoned);
            p.disk.fail_directory_sync = None;
            assert!(p.list_archives(&s.volume).is_err());
            assert!(
                p.inspect_archive(&s.scope.digest().unwrap(), &s.volume, s.publication_id)
                    .is_err()
            );
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            let observed = fs::read(&archive).unwrap();
            assert_eq!(observed, bytes);
        }
        drop(store);
        let mut store = Store::open(&scratch.0).unwrap();
        let mut p = store.publications(scratch.uid()).unwrap();
        assert_eq!(p.list_archives(&s.volume).unwrap().len(), 1);
    }
}
#[test]
fn cleanup_preserves_archives_and_unrelated_entries() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let s = fixture("ready");
    let archive;
    {
        let mut p = store.publications(scratch.uid()).unwrap();
        archive = seeded_archive(&mut p, &s);
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let bytes = fs::read(&archive).unwrap();
    let scope = archive.parent().unwrap();
    let scratch_name = scope.join("vol.sub.tmp-1");
    put(&scratch_name, b"scratch");
    let unrelated = scope.join("vol.sub.tmp-01");
    put(&unrelated, b"unrelated");
    let mut p = store.publications(scratch.uid()).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = !scratch_name.exists();
    assert!(observed);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = unrelated.exists();
    assert!(observed);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(&archive).unwrap();
    assert_eq!(observed, bytes);
    assert_eq!(p.list_archives(&s.volume).unwrap().len(), 1);
}

fn model_with_live(bytes: &[u8]) -> Model {
    let root = Path::new("/store");
    let live = Path::new("/store/publications/scope/vol.sub");
    let mut model = Model::default();
    for dir in [
        root,
        Path::new("/store/publications"),
        live.parent().unwrap(),
    ] {
        model.dirs.insert(dir.to_owned());
        model.durable_dirs.insert(dir.to_owned());
    }
    model.names.insert(live.to_owned(), 1);
    model.durable_names = model.names.clone();
    model.data.insert(1, bytes.to_vec());
    model.synced = model.data.clone();
    model
}
#[test]
fn archive_collision_during_move_preserves_both_complete_payloads() {
    let live = Path::new("/store/publications/scope/vol.sub");
    let archive =
        Path::new("/store/publications/scope/vol.abandoned-000102030405060708090a0b0c0d0e0f.sub");
    let old = codec::encode(&fixture("catalogue")).unwrap();
    let mut collision = fixture("catalogue");
    collision.generation += 1;
    let collision = codec::encode(&collision).unwrap();
    assert_ne!(collision, old);
    let mut model = model_with_live(&old);
    // The destination appears after catalogue preflight, at the rename itself.
    model.names.insert(archive.to_owned(), 2);
    model.durable_names.insert(archive.to_owned(), 2);
    model.data.insert(2, collision.clone());
    model.synced.insert(2, collision.clone());
    assert_eq!(
        move_archive(&mut model, live, archive, None, None)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(model.recovered(live), Some(old));
    assert_eq!(model.recovered(archive), Some(collision));
    assert_eq!(model.names, model.durable_names);
}

#[test]
fn archive_barriers_pin_bytes_ancestry_and_every_required_sync() {
    let root = Path::new("/store");
    let live = Path::new("/store/publications/scope/vol.sub");
    let archive =
        Path::new("/store/publications/scope/vol.abandoned-000102030405060708090a0b0c0d0e0f.sub");
    let old = codec::encode(&fixture("catalogue")).unwrap();
    let mut s = fixture("catalogue");
    s.generation = 2;
    let bytes = codec::encode(&s).unwrap();
    let mut model = model_with_live(&old);
    model.durable_dirs.clear();
    durable_replace(&mut model, root, live, &bytes).unwrap();
    move_archive(&mut model, live, archive, None, None).unwrap();
    assert_eq!(model.recovered(archive), Some(bytes.clone()));
    assert_eq!(model.recovered(live), None);
    assert_eq!(
        model.events,
        [
            "marker",
            "dirsync /store",
            "dirsync /",
            "mkdir /store/publications",
            "dirsync /store",
            "mkdir /store/publications/scope",
            "dirsync /store/publications",
            "create",
            "write",
            "filesync",
            "rename",
            "dirsync /store/publications/scope",
            "rename-no-replace",
            "dirsync /store/publications/scope"
        ]
    );
    model.events.clear();
    model.durable_dirs.clear();
    model.synced.clear();
    durable_archive(&mut model, root, archive, None).unwrap();
    assert_eq!(model.recovered(archive), Some(bytes));
    assert_eq!(model.recovered(live), None);
    assert_eq!(
        model.events,
        [
            "marker",
            "dirsync /store",
            "dirsync /",
            "dirsync /store/publications",
            "dirsync /store/publications/scope",
            "open-record",
            "filesync",
            "dirsync /store/publications/scope"
        ]
    );
    model.names.insert(live.to_owned(), model.names[archive]);
    model.events.clear();
    remove_duplicate(&mut model, live).unwrap();
    assert_eq!(model.recovered(live), None);
    assert!(model.recovered(archive).is_some());
    assert_eq!(
        model.events,
        ["unlink", "dirsync /store/publications/scope"]
    );
}
#[test]
fn archive_crash_cuts_recover_only_whole_generations_and_retry_without_rewrite() {
    // Model assumptions: a file sync persists its entire contents; a directory
    // sync commits that parent's entries atomically. Unsynced rename outcomes
    // include old L, new A and both names on the source inode, never torn bytes.
    let root = Path::new("/store");
    let live = Path::new("/store/publications/scope/vol.sub");
    let archive =
        Path::new("/store/publications/scope/vol.abandoned-000102030405060708090a0b0c0d0e0f.sub");
    let old = codec::encode(&fixture("catalogue")).unwrap();
    let mut s = fixture("catalogue");
    s.generation = 2;
    let bytes = codec::encode(&s).unwrap();
    for after in [false, true] {
        for cut in 0..=14 {
            let mut model = model_with_live(&old);
            model.cut = cut;
            model.after = after;
            let result = durable_replace(&mut model, root, live, &bytes)
                .and_then(|()| move_archive(&mut model, live, archive, None, None));
            let recovered_live = model.recovered(live);
            let recovered_archive = model.recovered(archive);
            for value in [&recovered_live, &recovered_archive].into_iter().flatten() {
                assert!(value == &old || value == &bytes);
                codec::decode(value).unwrap();
            }
            if cut == 0 {
                result.unwrap();
                assert_eq!(recovered_archive, Some(bytes.clone()));
                assert_eq!(recovered_live, None);
            } else {
                assert!(result.is_err());
                assert!(recovered_live.is_some() || recovered_archive.is_some());
            }
            // Explore independent spontaneous persistence of unsynced names, including
            // the two-link state, then establish A and remove only matching L.
            if let Some(inode) = model.names.get(archive).copied() {
                for keep_live in [false, true] {
                    let mut retry = model_with_live(&bytes);
                    retry.names.insert(archive.to_owned(), inode);
                    retry.data = model.data.clone();
                    retry.synced = model.synced.clone();
                    if keep_live {
                        retry.names.insert(live.to_owned(), inode);
                    } else {
                        retry.names.remove(live);
                    }
                    retry.durable_names = retry.names.clone();
                    durable_archive(&mut retry, root, archive, None).unwrap();
                    if keep_live {
                        remove_duplicate(&mut retry, live).unwrap();
                    }
                    assert_eq!(retry.recovered(archive), Some(bytes.clone()));
                    assert_eq!(retry.recovered(live), None);
                }
            }
        }
    }
    for after in [false, true] {
        for cut in 1..=10 {
            let mut retry = model_with_live(&bytes);
            retry.names.insert(archive.to_owned(), 1);
            retry.cut = cut;
            retry.after = after;
            let result = durable_archive(&mut retry, root, archive, None)
                .and_then(|()| remove_duplicate(&mut retry, live));
            assert!(result.is_err());
            // Before archive's first scope sync, L remains established. Unlink occurs
            // only after durable A exists. An uncertain unlink cannot lose A.
            assert!(retry.recovered(live).is_some() || retry.recovered(archive).is_some());
            if cut >= 9 {
                assert_eq!(retry.recovered(archive), Some(bytes.clone()));
            }
        }
    }
}
#[test]
fn independent_parents_explain_destination_before_source_order() {
    let bytes = codec::encode(&fixture("ready")).unwrap();
    let live = Path::new("/store/publications/scope/vol.sub");
    let nested = Path::new("/store/publications/scope/abandoned/vol/id.sub");
    let mut wrong = model_with_live(&bytes);
    let mut right = model_with_live(&bytes);
    for model in [&mut wrong, &mut right] {
        for dir in [
            Path::new("/store/publications/scope/abandoned"),
            nested.parent().unwrap(),
        ] {
            model.dirs.insert(dir.to_owned());
            model.durable_dirs.insert(dir.to_owned());
        }
        model.rename_no_replace(live, nested).unwrap();
    }
    wrong.sync_directory(live.parent().unwrap()).unwrap();
    assert_eq!(wrong.recovered(live), None);
    assert_eq!(wrong.recovered(nested), None);
    right.sync_directory(nested.parent().unwrap()).unwrap();
    assert_eq!(right.recovered(live), Some(bytes.clone()));
    assert_eq!(right.recovered(nested), Some(bytes));
}

#[test]
fn committed_selection_state_vectors_are_exact() {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/publication-archives");
    #[expect(clippy::disallowed_methods, reason = "read committed test vectors")]
    let manifest = fs::read_to_string(directory.join("states.tsv")).unwrap();
    let mut seen = BTreeSet::new();
    for row in manifest.lines().filter(|l| !l.starts_with('#')) {
        let c: Vec<_> = row.split('\t').collect();
        seen.insert(c[3]);
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.0).unwrap();
        let mut p = store.publications(scratch.uid()).unwrap();
        #[expect(clippy::disallowed_methods, reason = "read committed test vectors")]
        let bytes = fs::read(directory.join(format!("{}.bin", c[0]))).unwrap();
        let s = codec::decode(&bytes).unwrap();
        let mut initial = s.clone();
        initial.generation = 1;
        let archive = seeded_archive(&mut p, &initial);
        put(&archive, &bytes);
        let live = p.path(&s.scope, &s.volume).unwrap();
        let live_bytes = (c[1] != "-").then(|| {
            #[expect(clippy::disallowed_methods, reason = "read committed test vectors")]
            let bytes = fs::read(directory.join(format!("{}.bin", c[1]))).unwrap();
            bytes
        });
        if let Some(bytes) = &live_bytes {
            put(&live, bytes);
        }
        match c[2] {
            "Abandoned" => assert_eq!(
                p.load(&s.scope, &s.volume).unwrap_err().kind,
                PublicationStoreErrorKind::Abandoned
            ),
            "Conflict" => assert!(p.load(&s.scope, &s.volume).is_err()),
            "Live" => {
                let mut expected = codec::decode(live_bytes.as_ref().unwrap()).unwrap();
                expected.generation += 1;
                assert_eq!(p.load(&s.scope, &s.volume).unwrap(), Some(expected));
                put(&live, live_bytes.as_ref().unwrap());
            }
            _ => unreachable!(),
        }
        if c[3] == "refuse" {
            assert!(
                p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
                    .is_err()
            );
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            let observed = fs::read(&live).unwrap();
            assert_eq!(observed, live_bytes.unwrap());
        } else {
            p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
                .unwrap();
            if c[3] == "keep-live" {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "test-owned private scratch directory"
                )]
                let observed = fs::read(&live).unwrap();
                assert_eq!(observed, live_bytes.unwrap());
            } else {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "test-owned private scratch directory"
                )]
                let observed = !live.exists();
                assert!(observed);
            }
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "test-owned private scratch directory"
        )]
        let observed = fs::read(archive).unwrap();
        assert_eq!(observed, bytes);
    }
    assert_eq!(
        seen,
        ["idempotent", "keep-live", "unlink-live", "refuse"]
            .into_iter()
            .collect()
    );
}
#[test]
fn zero_identity_is_valid_but_live_generation_exhaustion_refuses() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let mut s = fixture("ready");
    s.publication_id = [0; 16];
    p.begin(&s).unwrap();
    let live = p.path(&s.scope, &s.volume).unwrap();
    s.generation = u64::MAX;
    let bytes = codec::encode(&s).unwrap();
    put(&live, &bytes);
    assert!(
        p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
            .unwrap_err()
            .reason
            .contains("exhausted")
    );
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(&live).unwrap();
    assert_eq!(observed, bytes);
    assert!(!p.poisoned);
    s.generation = 1;
    put(&live, &codec::encode(&s).unwrap());
    assert_eq!(
        p.abandon(&s.scope, &s.volume, s.publication_id, ACK)
            .unwrap()
            .archive
            .submission
            .publication_id,
        [0; 16]
    );
}

#[test]
fn archive_marker_and_file_sync_failures_poison_without_selection() {
    for marker in [false, true] {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.0).unwrap();
        let s = fixture("ready");
        {
            let mut p = store.publications(scratch.uid()).unwrap();
            let archive = seeded_archive(&mut p, &s);
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            let bytes = fs::read(&archive).unwrap();
            p.disk.fail_file_sync = !marker;
            p.disk.fail_marker_sync = marker;
            assert!(p.load_for_new(&s.scope, &s.volume, ACK).is_err());
            assert!(p.poisoned);
            p.disk.fail_file_sync = false;
            p.disk.fail_marker_sync = false;
            assert!(p.list_archives(&s.volume).is_err());
            #[expect(
                clippy::disallowed_methods,
                reason = "test-owned private scratch directory"
            )]
            let observed = fs::read(archive).unwrap();
            assert_eq!(observed, bytes);
        }
        drop(store);
        let mut store = Store::open(&scratch.0).unwrap();
        assert_eq!(
            store
                .publications(scratch.uid())
                .unwrap()
                .list_archives(&s.volume)
                .unwrap()
                .len(),
            1
        );
    }
}

#[test]
fn archive_uncertainty_includes_retired_candidates_with_no_current_uncertainty() {
    for retired_may_land in [true, false] {
        let scratch = Scratch::new();
        let mut store = Store::open(&scratch.0).unwrap();
        let mut p = store.publications(scratch.uid()).unwrap();
        let mut s = fixture("catalogue");
        for candidate in &mut s.candidates {
            if candidate.role != granary_core::retained_submission::Role::Retired
                || !retired_may_land
            {
                candidate.evidence.proved_no_write = candidate.evidence.started;
                candidate.evidence.last_answered_attempt = candidate.evidence.started;
            }
        }
        p.begin(&s).unwrap();
        let result = p
            .abandon(&s.scope, &s.volume, s.publication_id, ACK)
            .unwrap();
        assert_eq!(result.archive.uncertain, retired_may_land);
    }
}
#[test]
fn live_preflight_refusals_precede_archive_durability_operations() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    let archive = seeded_archive(&mut p, &s);
    let mut new = s.clone();
    new.publication_id = [0xff; 16];
    p.begin(&new).unwrap();
    let live = p.path(&new.scope, &new.volume).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let live_bytes = fs::read(&live).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let archive_bytes = fs::read(&archive).unwrap();
    p.disk.fail_marker_sync = true;
    let mut configured = new.scope.clone();
    configured.pins = vec![[0x77; 32]];
    assert!(
        p.load(&configured, &new.volume)
            .unwrap_err()
            .reason
            .contains("scope mismatch")
    );
    assert!(!p.poisoned);
    let mut successor = new.clone();
    successor.generation = 2;
    assert!(
        p.replace(2, &successor)
            .unwrap_err()
            .reason
            .contains("stale")
    );
    assert!(!p.poisoned);
    successor.generation = 1;
    successor.publication_id = [0xfe; 16];
    assert!(
        p.begin(&successor)
            .unwrap_err()
            .reason
            .contains("not complete")
    );
    assert!(!p.poisoned);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(&live).unwrap();
    assert_eq!(observed, live_bytes);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let observed = fs::read(&archive).unwrap();
    assert_eq!(observed, archive_bytes);
    p.disk.fail_marker_sync = false;
}

#[test]
fn read_inspection_resyncs_archives_and_a_failed_sync_is_io() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let s = fixture("ready");
    {
        let mut p = store.publications(scratch.uid()).unwrap();
        seeded_archive(&mut p, &s);
    }
    let mut p = store.publications_read_only(scratch.uid()).unwrap();
    let scope = archive_path(&p, &s).parent().unwrap().to_owned();
    let mut outcomes = Vec::new();
    for step in ["file", "scope", "none"] {
        match step {
            "file" => p.disk.fail_file_sync = true,
            "scope" => p.disk.fail_directory_sync = Some(scope.clone()),
            _ => {}
        }
        let refusal = p.inspect_selected(&s.scope, &s.volume).unwrap_err();
        outcomes.push((step, refusal.kind));
        p.disk.fail_file_sync = false;
        p.disk.fail_directory_sync = None;
    }
    assert_eq!(
        (outcomes, 3),
        (
            vec![
                ("file", PublicationStoreErrorKind::Io),
                ("scope", PublicationStoreErrorKind::Io),
                ("none", PublicationStoreErrorKind::Abandoned),
            ],
            3
        ),
        "an archive must be re-synced before it is reported, and a failed sync is I/O, not abandonment"
    );
}

#[test]
fn a_custody_failure_inside_the_barrier_is_refused_not_retried_as_io() {
    fn set_mode(path: &Path, mode: u32) {
        #[expect(
            clippy::disallowed_methods,
            reason = "test-owned private scratch directory"
        )]
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    let live = p.path(&s.scope, &s.volume).unwrap();
    let root = p.root().to_owned();
    let mut outcomes = Vec::new();
    // The record and the root each pass the enumeration that precedes the
    // barrier, then lose their custody before the barrier re-checks them.
    for (name, target, original, loosened) in [
        ("intact", &live, 0o600, 0o600),
        ("record mode", &live, 0o600, 0o644),
        ("root mode", &root, 0o700, 0o770),
    ] {
        set_mode(target, loosened);
        let result = p.resync_records(&[&live]);
        set_mode(target, original);
        outcomes.push((name, result.map_err(|e| e.kind)));
    }
    assert_eq!(
        (outcomes, 3),
        (
            vec![
                ("intact", Ok(())),
                ("record mode", Err(PublicationStoreErrorKind::Refused)),
                ("root mode", Err(PublicationStoreErrorKind::Refused)),
            ],
            3
        ),
        "a custody failure inside the barrier fails closed; it is not a retryable I/O failure"
    );
}

#[test]
fn only_device_filesystem_and_resource_failures_read_an_archive_as_io() {
    let path = Path::new("archive.sub");
    let kinds: Vec<_> = [
        ("EIO", io::Error::from_raw_os_error(libc::EIO)),
        ("ESTALE", io::Error::from_raw_os_error(libc::ESTALE)),
        ("ENOSPC", io::Error::from_raw_os_error(libc::ENOSPC)),
        ("EDQUOT", io::Error::from_raw_os_error(libc::EDQUOT)),
        ("EINTR", io::Error::from_raw_os_error(libc::EINTR)),
        ("EAGAIN", io::Error::from_raw_os_error(libc::EAGAIN)),
        ("EACCES", io::Error::from_raw_os_error(libc::EACCES)),
        ("EPERM", io::Error::from_raw_os_error(libc::EPERM)),
        ("ENOTDIR", io::Error::from_raw_os_error(libc::ENOTDIR)),
        (
            "invalid",
            io::Error::new(io::ErrorKind::InvalidData, "custody"),
        ),
        ("other", io::Error::other("wrong owner")),
    ]
    .into_iter()
    .map(|(name, cause)| (name, archive_read_error(path, &cause).kind))
    .collect();
    assert_eq!(
        (kinds, 11),
        (
            vec![
                ("EIO", PublicationStoreErrorKind::Io),
                ("ESTALE", PublicationStoreErrorKind::Io),
                ("ENOSPC", PublicationStoreErrorKind::Io),
                ("EDQUOT", PublicationStoreErrorKind::Io),
                ("EINTR", PublicationStoreErrorKind::Io),
                ("EAGAIN", PublicationStoreErrorKind::Io),
                ("EACCES", PublicationStoreErrorKind::Refused),
                ("EPERM", PublicationStoreErrorKind::Refused),
                ("ENOTDIR", PublicationStoreErrorKind::Refused),
                ("invalid", PublicationStoreErrorKind::Refused),
                ("other", PublicationStoreErrorKind::Refused),
            ],
            11
        ),
        "an archive read fails closed unless the device, the filesystem or a kernel resource failed"
    );
}

#[test]
fn an_unreadable_archive_is_refused_not_retried_as_io() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    let archive = seeded_archive(&mut p, &s);
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    fs::set_permissions(&archive, fs::Permissions::from_mode(0o000)).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let denied = fs::File::open(&archive).is_err();
    if !denied {
        // A privileged runner ignores mode bits; the errno table row covers it.
        return;
    }
    let refusal = p.list_archives(&s.volume).unwrap_err();
    assert_eq!(
        (refusal.kind, refusal.path),
        (PublicationStoreErrorKind::Refused, archive),
        "a permission failure on an archive must fail closed"
    );
}

#[test]
fn an_unreadable_live_record_is_refused_by_inspection_and_retried_by_load() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    let live = p.path(&s.scope, &s.volume).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    fs::set_permissions(&live, fs::Permissions::from_mode(0o000)).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    let denied = fs::File::open(&live).is_err();
    if !denied {
        // A privileged runner ignores mode bits; the errno table row covers it.
        return;
    }
    let inspected = p.inspect_selected(&s.scope, &s.volume).unwrap_err();
    let loaded = p.load(&s.scope, &s.volume).unwrap_err();
    assert_eq!(
        (
            (inspected.kind, inspected.path),
            (loaded.kind, loaded.path),
            2
        ),
        (
            (PublicationStoreErrorKind::Refused, live.clone()),
            (PublicationStoreErrorKind::Io, live),
            2
        ),
        "an inspection fails closed on a record its owner cannot read; load keeps retrying it"
    );
}

#[test]
fn a_scope_component_that_is_a_file_is_refused_by_inspection() {
    let scratch = Scratch::new();
    let mut store = Store::open(&scratch.0).unwrap();
    let mut p = store.publications(scratch.uid()).unwrap();
    let s = fixture("ready");
    p.begin(&s).unwrap();
    let live = p.path(&s.scope, &s.volume).unwrap();
    let scope = live.parent().unwrap().to_owned();
    #[expect(
        clippy::disallowed_methods,
        reason = "test-owned private scratch directory"
    )]
    fs::remove_dir_all(&scope).unwrap();
    put(&scope, b"not a directory");
    // The enumeration refuses the file before it reads the record; reading
    // the record directly meets ENOTDIR, which only the inspection refuses.
    let inspected = p.inspect_selected(&s.scope, &s.volume).unwrap_err();
    let retried = p.read(&live, &s.volume, retained_read_error).unwrap_err();
    let refused = p.read(&live, &s.volume, archive_read_error).unwrap_err();
    assert_eq!(
        (
            (inspected.kind, inspected.path),
            retried.kind,
            (refused.kind, refused.path),
            3
        ),
        (
            (PublicationStoreErrorKind::Refused, scope),
            PublicationStoreErrorKind::Io,
            (PublicationStoreErrorKind::Refused, live),
            3
        ),
        "a scope component replaced by a file fails closed under inspection"
    );
}
