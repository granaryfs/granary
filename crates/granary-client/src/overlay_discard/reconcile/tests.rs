// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use super::super::{
    CHANGED, MISSING, NOT_ELIGIBLE, discard_overlay, run,
    tests::{fixture, put, snapshot},
};
use super::*;
use crate::{
    OverlayDisk, OverlayIo as _, Store,
    overlay_test_support::ScratchDir,
    recovery::tests::{record, sign_doc, support::Transport},
};
use granary_core::{
    authority_answer::{self, Head, PublishAnswer},
    hash::HashAlgorithm,
    overlay_discard::parse_hex,
    overlay_journal::{IntentCause, JournalHeader},
    root::{self, RootSig},
    rootstore::RootStoreError,
};
use granary_store::crypto::SigningKey;
use std::path::PathBuf;

mod archive_rows;
pub(crate) use archive_rows::{archive_publication_bindings, probe_archive_rows};

struct Case {
    _scratch: ScratchDir,
    root: PathBuf,
    area: PathBuf,
    key: SigningKey,
    remote: Transport,
    record: Submission,
    journal: Vec<Record>,
    header: JournalHeader,
}

impl Case {
    fn new() -> Self {
        let (scratch, path, _, _, _) = fixture();
        let key = SigningKey::from_seed(&[9; 32]).unwrap();
        let mut record = record();
        record.scope.pins = vec![[11; 32]];
        let base = GrainId::of(&record.frozen.initial_root);
        let mut doc = root::decode_root(&record.frozen.initial_root).unwrap();
        doc.seq = 2;
        doc.parent = Some(base);
        let bytes = sign_doc(doc, &key);
        let candidate = &mut record.candidates[0];
        candidate.id = GrainId::of(&bytes);
        candidate.seq = 2;
        candidate.root = bytes.clone();
        record.frozen.initial_root = bytes;
        record.phase = p::Phase::AwaitingAnswer {
            candidate: 1,
            attempt: 1,
        };

        let area = path
            .join("overlay")
            .join(record.scope.digest().unwrap())
            .join(record.volume.as_str());
        let header = JournalHeader {
            writer: record.frozen.writer_identity,
            base_root: base,
            base_seq: 1,
            next_stage_id: 1,
            receipt_generation: 0,
        };
        let journal = vec![
            Record::CommitBoundary {
                candidate: candidate.id,
                through_seq: 0,
                publication_id: record.publication_id,
            },
            Record::CommitAttempt {
                boundary_seq: 1,
                publication_id: record.publication_id,
                attempt: 1,
            },
        ];
        Self {
            _scratch: scratch,
            root: path,
            area,
            key,
            remote: Transport::default(),
            record,
            journal,
            header,
        }
    }

    fn materialize(&self, archive: Option<bool>) {
        let uid = nix::unistd::geteuid().as_raw();
        let mut io = OverlayDisk::new(&self.root, uid);
        for dir in [self.area.parent().unwrap(), &self.area] {
            io.create_directory(dir).unwrap();
        }
        put(
            &self.area.join("writer"),
            &WriterRecord {
                writer: self.header.writer,
                volume: self.record.volume.clone(),
                ceiling: 1,
            }
            .encode()
            .unwrap(),
        );
        put(
            &self.area.join("journal"),
            &j::encode_journal(&self.header, &self.journal).unwrap(),
        );
        let (mut store, _) = Store::open_existing(&self.root).unwrap();
        store
            .publications(uid)
            .unwrap()
            .begin(&self.record)
            .unwrap();
        if let Some(settled) = archive {
            let live = self
                .root
                .join("publications")
                .join(hex(&self.scope()))
                .join(format!("{}.sub", self.record.volume.as_str()));
            let leaf = ArchiveName {
                volume: self.record.volume.clone(),
                publication_id: self.record.publication_id,
                settled,
            }
            .file_name();
            let dir = crate::fsguard::open_directory(live.parent().unwrap()).unwrap();
            nix::fcntl::renameat(&dir, live.file_name().unwrap(), &dir, leaf.as_str()).unwrap();
        }
    }

    fn scope(&self) -> [u8; 32] {
        parse_hex(&self.record.scope.digest().unwrap()).unwrap()
    }

    fn tuple(&self, move_archive: bool) -> Tuple {
        let plan = discard_overlay(&self.root, self.scope(), &self.record.volume, None).unwrap();
        let tuple = (plan.name.writer, plan.name.incarnation);
        if move_archive {
            discard_overlay(&self.root, self.scope(), &self.record.volume, Some(tuple)).unwrap();
        }
        tuple
    }

    async fn reconcile(&self, tuple: Tuple, route: Option<&Scope>) -> ReconcileRow {
        let before = snapshot(&self.root);
        let record = &self.record;
        let evidence =
            ArchiveReconciliation::open(&self.root, self.scope(), &record.volume, tuple).unwrap();
        let keys = TrustedKeys::new([*self.key.public_key()]).unwrap();
        let rows = evidence
            .probe(&self.remote, Some(route.unwrap_or(&record.scope)), &keys)
            .await;
        assert_eq!(
            snapshot(&self.root),
            before,
            "reconcile changed the frozen store"
        );
        {
            let authority = self.remote.remote.lock().unwrap();
            assert_eq!(
                (
                    authority.sends.len(),
                    authority.meta_uploads,
                    authority.bin_uploads
                ),
                (0, 0, 0)
            );
        }
        let (mut store, _) = Store::open_existing(&self.root).unwrap();
        let mut records = store.publications(nix::unistd::geteuid().as_raw()).unwrap();
        let refusal = records
            .load(&record.scope, &record.volume)
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("OverlayArchived"));
        assert_eq!(snapshot(&self.root), before);
        let [row]: [ReconcileRow; 1] = rows.try_into().unwrap();
        row
    }

    fn put_root(&self, bytes: Vec<u8>) {
        let doc = root::decode_root(&bytes).unwrap();
        assert!(
            self.remote
                .remote
                .lock()
                .unwrap()
                .roots
                .insert(doc.seq, bytes)
                .is_none()
        );
    }
}

#[tokio::test]
async fn reconcile_awaiting_answer_lands_at_head_then_below_head_with_stored_id() {
    let case = Case::new();
    case.materialize(None);
    let tuple = case.tuple(true);
    let row = case.reconcile(tuple, None).await;
    assert_eq!((row.status, row.landing), (Status::Unresolved, None));
    assert_eq!(row.refusal_reason(), Some(Refusal::Unresolved));
    for error in [
        RootStoreError::Elapsed {
            operation: "list roots",
            after: std::time::Duration::from_secs(1),
        },
        RootStoreError::Backend("unavailable authority".into()),
    ] {
        case.remote.remote.lock().unwrap().head_error = Some(error);
        let row = case.reconcile(tuple, None).await;
        assert_eq!((row.status, row.landing), (Status::Unresolved, None));
    }
    case.remote.remote.lock().unwrap().head_error = None;
    let candidate = &case.record.candidates[0];
    let mut doc = root::decode_root(&candidate.root).unwrap();
    doc.sigs.push(RootSig {
        key_id: [98; 32],
        sig: [0; 64],
    });
    let stored = root::encode_root(&doc).unwrap();
    let stored_id = GrainId::of(&stored);
    assert_ne!(stored_id, candidate.id);
    case.put_root(stored);
    for index in 0..2 {
        let row = case.reconcile(tuple, None).await;
        assert_eq!(
            (row.status, row.landing),
            (
                Status::Landed,
                Some(Landing {
                    candidate: candidate.id,
                    seq: candidate.seq,
                    stored: stored_id
                })
            )
        );
        if index == 0 {
            doc.seq += 1;
            doc.parent = Some(stored_id);
            case.put_root(sign_doc(doc.clone(), &case.key));
        }
    }
}

#[tokio::test]
async fn reconcile_distinguishes_foreign_occupancy_from_broken_ancestry() {
    for broken in [false, true] {
        let case = Case::new();
        case.materialize(None);
        let tuple = case.tuple(true);
        let candidate = &case.record.candidates[0];
        let mut doc = root::decode_root(&candidate.root).unwrap();
        doc.writer_uuid = [19; 16];
        let foreign = sign_doc(doc.clone(), &case.key);
        let parent = if broken {
            candidate.id
        } else {
            GrainId::of(&foreign)
        };
        case.put_root(foreign);
        doc.seq += 1;
        doc.parent = Some(parent);
        case.put_root(sign_doc(doc, &case.key));
        let row = case.reconcile(tuple, None).await;
        let (status, refusal) = if broken {
            (Status::Integrity, Some(Refusal::RemoteIntegrity))
        } else {
            (Status::NotLanded, None)
        };
        assert_eq!(
            (row.status, row.landing, row.refusal_reason()),
            (status, None, refusal)
        );
    }
}

#[tokio::test]
async fn reconcile_checks_witnesses_and_keeps_deferred_answers_unresolved() {
    for (mode, expected) in [
        ("B5", Status::Landed),
        ("settled", Status::Integrity),
        ("witness-mismatch", Status::Integrity),
        ("deferred", Status::Unresolved),
        ("no-send", Status::NotLanded),
        ("unbound", Status::Unresolved),
    ] {
        let mut case = Case::new();
        let candidate = case.record.candidates[0].clone();
        match mode {
            "B5" | "witness-mismatch" => {
                let witness = if mode == "B5" {
                    candidate.id
                } else {
                    GrainId::of(b"other witness")
                };
                case.journal.extend([
                    Record::LandedCommit {
                        boundary_seq: 1,
                        landed_seq: candidate.seq,
                        landed_root: witness,
                    },
                    Record::IntentRegistered {
                        generation: 1,
                        prepared_root: witness,
                        cause: IntentCause::LandedRefresh,
                    },
                ]);
                case.record.phase = p::Phase::Complete(p::Completion {
                    seq: candidate.seq,
                    id: candidate.id,
                    root: candidate.root.clone(),
                    receipt: None,
                });
                case.record.current = None;
            }
            "deferred" => {
                case.record.candidates[0].evidence.last_answered_attempt = 1;
                case.record.phase = p::Phase::Unresolved(p::Probe {
                    cycle: 1,
                    seq: candidate.seq,
                    reason: p::ProbeReason::ContentUnavailable,
                });
                case.record.last_response = Some(p::LastResponse {
                    candidate: 1,
                    attempt: 1,
                    status: 409,
                    token: b"stale-base".to_vec(),
                    answer: authority_answer::encode(PublishAnswer::StaleBase(Head::new(Some((
                        candidate.seq,
                        candidate.id,
                    )))))
                    .unwrap(),
                });
            }
            "no-send" => {
                case.record.phase = p::Phase::Ready;
                case.record.candidates[0].evidence = p::Evidence::default();
                case.journal.pop();
            }
            "unbound" => {
                if let Some(Record::CommitBoundary { candidate, .. }) = case.journal.first_mut() {
                    *candidate = GrainId::of(b"wrong frozen candidate");
                }
            }
            _ => {}
        }
        case.materialize((mode == "settled").then_some(true));
        let tuple = case.tuple(true);
        if mode != "no-send" {
            case.put_root(candidate.root.clone());
        }
        let row = case.reconcile(tuple, None).await;
        assert_eq!(row.status, expected, "{mode}");
        assert_eq!(
            row.landing.map(|landing| landing.stored),
            (!matches!(mode, "no-send" | "unbound")).then_some(candidate.id),
            "{mode}"
        );
    }
}

#[tokio::test]
async fn reconcile_refuses_wrong_selection_and_route() {
    let case = Case::new();
    case.materialize(None);
    let tuple = case.tuple(false);
    let refused = |scope, volume: &VolumeName, tuple, reason: Refusal| {
        let before = snapshot(&case.root);
        assert_eq!(
            ArchiveReconciliation::open(&case.root, scope, volume, tuple)
                .unwrap_err()
                .to_string(),
            reason.as_str()
        );
        assert_eq!(snapshot(&case.root), before);
    };
    refused(case.scope(), &case.record.volume, tuple, NOT_ELIGIBLE);
    assert_eq!(
        run(
            &case.root,
            case.scope(),
            &case.record.volume,
            Some(tuple),
            &mut |step, after| {
                if step == "intent scope" && after {
                    Err(super::super::DURABILITY)
                } else {
                    Ok(())
                }
            }
        ),
        Err(super::super::DURABILITY)
    );
    refused(case.scope(), &case.record.volume, tuple, Refusal::Pending);
    case.tuple(true);
    refused([4; 32], &case.record.volume, tuple, CHANGED);
    refused(
        case.scope(),
        &VolumeName::new("other".into()).unwrap(),
        tuple,
        MISSING,
    );
    refused(
        case.scope(),
        &case.record.volume,
        ([4; 16], tuple.1),
        CHANGED,
    );
    refused(
        case.scope(),
        &case.record.volume,
        (tuple.0, [4; 32]),
        CHANGED,
    );

    for mismatched in [
        Scope {
            pins: vec![[21; 32]],
            ..case.record.scope.clone()
        },
        Scope {
            authority_base: b"https://other.invalid".to_vec(),
            ..case.record.scope.clone()
        },
        Scope {
            credential_context: b"other".to_vec(),
            ..case.record.scope.clone()
        },
    ] {
        let row = case.reconcile(tuple, Some(&mismatched)).await;
        assert_eq!(row.status, Status::Unresolved);
        assert_eq!(case.remote.remote.lock().unwrap().max_seq_calls, 0);
    }
}

#[test]
fn reconcile_tsv_v1_vectors() {
    let head = concat!(
        "overlay-reconcile-v1\t",
        "1111111111111111111111111111111111111111111111111111111111111111\tvol\t",
        "22222222222222222222222222222222\t",
        "3333333333333333333333333333333333333333333333333333333333333333\t",
        "44444444444444444444444444444444\t"
    );
    let landing = Landing {
        candidate: GrainId::from_parts(HashAlgorithm::Blake3, [0x55; 32]),
        seq: 17,
        stored: GrainId::from_parts(HashAlgorithm::Blake3, [0x66; 32]),
    };
    let suffix = concat!(
        "\tblake3:5555555555555555555555555555555555555555555555555555555555555555\t17\t",
        "blake3:6666666666666666666666666666666666666666666666666666666666666666\n"
    );
    let vectors = [
        (Status::Landed, Some(landing), format!("landed{suffix}")),
        (Status::NotLanded, None, "not-landed\t-\t-\t-\n".into()),
        (Status::Unresolved, None, "unresolved\t-\t-\t-\n".into()),
        (
            Status::Unresolved,
            Some(landing),
            format!("unresolved{suffix}"),
        ),
        (Status::Integrity, None, "integrity\t-\t-\t-\n".into()),
        (
            Status::Integrity,
            Some(landing),
            format!("integrity{suffix}"),
        ),
    ];
    let digests = [
        "8678c0b64aef44e28ca56fb17cd2ef0bfeae6e7d4ff585b2f01c95c3054ac8b7",
        "798fb0427cb8f589de1d10f30048950479b6855f523a09b945d429adabed8a87",
        "9b30c8aa756b12a565d096d3722186d597031797762541bd22d284e83ecf9a2e",
        "089693bf50f1367b50a67a61f4cd31c11e339a2bf5468e9ecf1117213ae9be7b",
        "727852b1dcfb812a80b9fe0589ae4cd980a9297f352bbf274f886c71240450b8",
        "5677ff419fc13851ed9e844d54b58d9055f0530ba6c47bd6e45fbe0f83d0fa51",
    ];
    for ((status, observation, ending), digest) in vectors.into_iter().zip(digests) {
        let row = ReconcileRow {
            scope: [0x11; 32],
            name: DiscardName {
                volume: VolumeName::new("vol".into()).unwrap(),
                writer: [0x22; 16],
                incarnation: [0x33; 32],
            },
            publication: [0x44; 16],
            status,
            landing: observation,
        };
        let bytes = row.to_string();
        assert_eq!(bytes, format!("{head}{ending}"));
        assert_eq!(hex(GrainId::of(bytes.as_bytes()).digest()), digest);
    }
}
