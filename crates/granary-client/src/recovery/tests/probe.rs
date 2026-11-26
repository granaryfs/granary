// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one table binds exact preference and prefix ambiguity at head and ancestor variants"
)]
async fn a_signature_slot_cannot_turn_the_landed_candidate_into_foreign_occupancy() {
    let mut actual = Vec::new();
    for (name, below, foreign, aliases, exact) in [
        ("head", false, false, false, false),
        ("ancestor", true, false, false, false),
        ("foreign", true, true, false, false),
        ("ambiguous-head", false, false, true, false),
        ("ambiguous-ancestor", true, false, true, false),
        ("exact-alias", false, false, true, true),
        ("unsent-alias", false, false, true, false),
    ] {
        let (transport, _, key, keys, _, _) = setup();
        let mut record = record();
        let mut doc = root::decode_root(&record.candidates[0].root).unwrap();
        if aliases {
            doc.sigs.push(RootSig {
                key_id: [99; 32],
                sig: [0; 64],
            });
            let mut alias = candidate(2, 1, root::encode_root(&doc).unwrap());
            alias.role = Role::History;
            doc.sigs.pop();
            if name == "unsent-alias" {
                alias.root = record.candidates[0].root.clone();
                alias.id = record.candidates[0].id;
                alias.evidence = Evidence::default();
            }
            record.candidates.push(alias);
        }
        let bytes = if foreign {
            doc.writer_uuid = [99; 16];
            sign_doc(doc, &key)
        } else {
            doc.sigs.push(RootSig {
                key_id: [if exact { 99 } else { 98 }; 32],
                sig: [0; 64],
            });
            root::encode_root(&doc).unwrap()
        };
        granary_store::crypto::check_head(&bytes, record.volume.as_str(), 1, &keys).unwrap();
        {
            let mut roots = transport.remote.lock().unwrap();
            if below {
                let mut successor = root::decode_root(&bytes).unwrap();
                successor.seq = 2;
                successor.parent = Some(GrainId::of(&bytes));
                successor.writer_uuid = [77; 16];
                roots.roots.insert(2, sign_doc(successor, &key));
            }
            roots.roots.insert(1, bytes.clone());
        }
        let expected_id = GrainId::of(&bytes);
        let result = probe_submission(&transport, &record, 8, &keys).await;
        if let Ok(ProbeOutcome::Landed {
            candidate,
            stored_root,
            stored_id,
        }) = &result
        {
            assert_eq!(
                (candidate.id, GrainId::of(stored_root), *stored_id),
                (
                    if exact {
                        expected_id
                    } else {
                        record.candidates[0].id
                    },
                    expected_id,
                    expected_id
                ),
                "{name}: exact catalogue identity must win before prefix aliases"
            );
        }
        let ending = match &result {
            Ok(ProbeOutcome::Landed { .. }) => "landed".to_owned(),
            Ok(ProbeOutcome::NeverLanded(_)) => "never-landed".to_owned(),
            other => format!("{other:?}"),
        };
        let remote = transport.remote.lock().unwrap();
        actual.push((
            name,
            ending,
            remote.sends.len(),
            remote.meta_uploads,
            remote.bin_uploads,
        ));
    }
    assert_eq!(actual.len(), 7);
    assert_eq!(
        actual,
        [
            ("head", "landed"),
            ("ancestor", "landed"),
            ("foreign", "never-landed"),
            (
                "ambiguous-head",
                "Err(RemoteIntegrity(\"ambiguous probe candidate\"))"
            ),
            (
                "ambiguous-ancestor",
                "Err(RemoteIntegrity(\"ambiguous probe candidate\"))"
            ),
            ("exact-alias", "landed"),
            ("unsent-alias", "landed"),
        ]
        .map(|(name, ending)| (name, ending.to_owned(), 0, 0, 0))
    );
}

#[tokio::test]
async fn read_only_probe_distinguishes_landed_foreign_and_empty_without_writes() {
    let mut cases = 0;
    for ending in ["landed", "foreign", "empty"] {
        let (transport, _, key, keys, _, _) = setup();
        let record = record();
        let original = record.clone();
        if ending != "empty" {
            let bytes = if ending == "landed" {
                record.candidates[0].root.clone()
            } else {
                let mut doc = root::decode_root(&record.candidates[0].root).unwrap();
                doc.writer_uuid = [99; 16];
                sign_doc(doc, &key)
            };
            transport.remote.lock().unwrap().roots.insert(1, bytes);
        }
        let result = probe_submission(&transport, &record, 8, &keys)
            .await
            .unwrap();
        let observed = match result {
            ProbeOutcome::Landed { .. } => "landed",
            ProbeOutcome::NeverLanded(_) => "foreign",
            ProbeOutcome::Unresolved { seq } => {
                assert_eq!(seq, 1);
                "empty"
            }
        };
        let remote = transport.remote.lock().unwrap();
        assert_eq!(
            (
                observed,
                record == original,
                remote.sends.len(),
                remote.bin_uploads,
                remote.meta_uploads
            ),
            (ending, true, 0, 0, 0),
            "{ending}: the probe must classify without changing any evidence"
        );
        assert!(transport.durable.lock().unwrap().is_none());
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[tokio::test]
async fn read_only_probe_walks_hash_links_and_refuses_missing_or_untrusted_evidence() {
    let mut cases = 0;
    for fault in ["none", "link", "missing", "signature", "read"] {
        let (transport, _, key, keys, _, _) = setup();
        let record = record();
        let first = root_bytes(2);
        let mut head = root::decode_root(&first).unwrap();
        head.seq = 2;
        head.parent = Some(GrainId::of(&first));
        let head = sign_doc(head, &key);
        {
            let mut remote = transport.remote.lock().unwrap();
            remote.roots.insert(1, first);
            remote.roots.insert(2, head);
            match fault {
                "link" => {
                    remote.roots.insert(1, root_bytes(3));
                }
                "missing" => {
                    remote.roots.remove(&1);
                }
                "signature" => {
                    *remote.roots.get_mut(&2).unwrap().last_mut().unwrap() ^= 1;
                }
                "read" => remote.fail_probe = true,
                _ => (),
            }
        }
        let result = probe_submission(&transport, &record, 8, &keys).await;
        let observed = match result {
            Ok(ProbeOutcome::NeverLanded(proof)) => {
                assert!(proof.matches_submission(&record));
                assert!(proof.matches(
                    record.publication_id,
                    GrainId::of(&record.frozen.initial_root),
                    8
                ));
                assert!(!proof.matches(
                    record.publication_id,
                    GrainId::of(&record.frozen.initial_root),
                    7
                ));
                let mut changed = record.clone();
                changed.scope.credential_context.push(1);
                assert!(!proof.matches_submission(&changed));
                changed = record.clone();
                changed.candidates[0].evidence = Evidence::default();
                assert!(!proof.matches_submission(&changed));
                "none".to_owned()
            }
            Err(error) => error.to_string(),
            other => panic!("{fault}: unexpected probe: {other:?}"),
        };
        let remote = transport.remote.lock().unwrap();
        let expected = match fault {
            "link" => ("probe ancestry mismatch", 2),
            "missing" => ("probe chain root missing", 2),
            "signature" => ("untrusted probe head", 1),
            "read" => ("remote: store: injected probe failure", 1),
            _ => ("none", 2),
        };
        assert_eq!(
            (observed.as_str(), remote.probes),
            expected,
            "fault={fault}"
        );
        assert_eq!(
            (remote.sends.len(), remote.meta_uploads, remote.bin_uploads),
            (0, 0, 0)
        );
        cases += 1;
    }
    assert_eq!(cases, 5);
}

#[tokio::test]
async fn read_only_probe_excludes_never_sent_candidates_and_refuses_an_empty_domain() {
    let (transport, _, _, keys, _, _) = setup();
    let mut record = record();
    record.candidates[0].evidence = Evidence::default();
    let error = probe_submission(&transport, &record, 8, &keys)
        .await
        .unwrap_err();
    assert_eq!(
        (error.to_string(), transport.remote.lock().unwrap().probes),
        ("probe has no possibly-written candidates".to_owned(), 0)
    );
}

#[tokio::test]
async fn read_only_probe_ignores_never_sent_future_slots_and_binds_every_possible_candidate() {
    let (transport, _, key, keys, _, _) = setup();
    let mut record = record();
    let foreign = root_bytes(2);
    transport
        .remote
        .lock()
        .unwrap()
        .roots
        .insert(1, foreign.clone());
    let mut doc = root::decode_root(&record.frozen.initial_root).unwrap();
    doc.seq = 2;
    doc.parent = Some(GrainId::of(&foreign));
    let mut future = candidate(2, 1, sign_doc(doc, &key));
    future.seq = 2;
    future.role = Role::History;
    future.evidence = Evidence::default();
    record.candidates.push(future);
    granary_core::retained_submission::validate(&record).unwrap();
    let result = probe_submission(&transport, &record, 8, &keys)
        .await
        .unwrap();
    let ProbeOutcome::NeverLanded(proof) = result else {
        panic!("never-sent future slot must not make the probe unresolved: {result:?}")
    };
    assert_eq!(
        (
            proof.matches_submission(&record),
            transport.remote.lock().unwrap().probes
        ),
        (true, 1)
    );
    record.candidates[1].evidence.start().unwrap();
    assert!(
        !proof.matches_submission(&record),
        "a newly possibly-written candidate must invalidate the exact probed set"
    );
}

#[tokio::test]
async fn probe_returns_the_highest_candidate_and_its_stored_envelope_after_the_whole_walk() {
    let mut cases = 0;
    for (later, broken) in [(true, true), (false, false), (true, false)] {
        let (transport, _, key, keys, _, _) = setup();
        let mut record = record();
        let earlier = record.candidates[0].clone();
        let mut variant = root::decode_root(&earlier.root).unwrap();
        variant.sigs.push(RootSig {
            key_id: [98; 32],
            sig: [0; 64],
        });
        let variant = root::encode_root(&variant).unwrap();
        let mut next = root::decode_root(&variant).unwrap();
        next.seq = 2;
        next.parent = Some(GrainId::of(&variant));
        if !later {
            next.writer_uuid = [77; 16];
        }
        let next = sign_doc(next, &key);
        if later {
            record.candidates[0].role = Role::History;
            let mut candidate = candidate(2, 1, next.clone());
            candidate.seq = 2;
            record.current = Some(candidate.request);
            record.candidates.push(candidate);
        }
        let expected = record.candidates.last().unwrap().clone();
        let expected_stored = if later { next.clone() } else { variant.clone() };
        {
            let mut remote = transport.remote.lock().unwrap();
            remote
                .roots
                .insert(1, if broken { root_bytes(3) } else { variant });
            remote.roots.insert(2, next);
        }
        let result = probe_submission(&transport, &record, 8, &keys).await;
        if broken {
            assert_eq!(result.unwrap_err().to_string(), "probe ancestry mismatch");
        } else {
            let outcome = result.unwrap();
            let ProbeOutcome::Landed {
                candidate,
                stored_root,
                stored_id,
            } = outcome
            else {
                panic!("expected a verified landing, got {outcome:?}");
            };
            assert_eq!(
                (candidate, stored_root, stored_id),
                (
                    expected,
                    expected_stored.clone(),
                    GrainId::of(&expected_stored)
                ),
                "later={later}: the highest candidate and its actual stored bytes must travel together"
            );
        }
        let remote = transport.remote.lock().unwrap();
        assert_eq!(
            (
                remote.probes,
                remote.sends.len(),
                remote.meta_uploads,
                remote.bin_uploads
            ),
            (2, 0, 0, 0)
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[tokio::test]
async fn completed_landing_refetch_preserves_candidate_identity_and_pins_the_journal_id() {
    let mut cases = 0;
    for journalled in [false, true] {
        for fault in ["none", "missing", "read", "foreign", "journal-id"] {
            let (transport, _, key, keys, _, _) = setup();
            let mut record = record();
            let candidate = record.candidates[0].clone();
            record.phase = Phase::Complete(Completion {
                seq: candidate.seq,
                id: candidate.id,
                root: candidate.root.clone(),
                receipt: None,
            });
            record.current = None;
            let original = record.clone();
            let mut stored = root::decode_root(&candidate.root).unwrap();
            stored.sigs.push(RootSig {
                key_id: [98; 32],
                sig: [0; 64],
            });
            let stored = root::encode_root(&stored).unwrap();
            let id = GrainId::of(&stored);
            {
                let mut remote = transport.remote.lock().unwrap();
                if fault == "foreign" {
                    let mut foreign = root::decode_root(&stored).unwrap();
                    foreign.timestamp.secs += 1;
                    remote.roots.insert(1, sign_doc(foreign, &key));
                } else if fault != "missing" {
                    remote.roots.insert(1, stored.clone());
                }
                // RootStore reads use the same injected backend failure as probes.
                remote.fail_probe = fault == "read";
            }
            let expected = journalled.then_some((
                1,
                if fault == "journal-id" {
                    candidate.id
                } else {
                    id
                },
            ));
            let result =
                refetch_landing(&LandingReader(&transport), &record, expected, &keys).await;
            let observed = result
                .map(|landing| landing.map(|(bytes, id)| (bytes == stored, id)))
                .map_err(|e| e.to_string());
            let expected = if fault == "none" || (fault == "journal-id" && !journalled) {
                Ok(Some((true, id)))
            } else if fault == "missing" {
                Ok(None)
            } else {
                Err(if fault == "read" {
                    "remote: store: injected probe failure"
                } else {
                    "stored landing mismatch"
                }
                .to_owned())
            };
            let remote = transport.remote.lock().unwrap();
            assert_eq!(
                (
                    observed,
                    record == original,
                    remote.sends.len(),
                    remote.meta_uploads,
                    remote.bin_uploads
                ),
                (expected, true, 0, 0, 0),
                "journalled={journalled}, fault={fault}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 10);
}

struct LandingReader<'a>(&'a Transport);
impl granary_core::rootstore::RootStore for LandingReader<'_> {
    async fn put_root(
        &self,
        _: &str,
        _: u64,
        _: Vec<u8>,
    ) -> Result<(), granary_core::rootstore::RootStoreError> {
        panic!("landing re-fetch must never write");
    }
    async fn get_root(
        &self,
        volume: &str,
        seq: u64,
    ) -> Result<Option<Vec<u8>>, granary_core::rootstore::RootStoreError> {
        self.0.probe_root_once(volume, seq).await
    }
    async fn max_seq(
        &self,
        volume: &str,
    ) -> Result<Option<u64>, granary_core::rootstore::RootStoreError> {
        granary_core::rootstore::RootStore::max_seq(self.0, volume).await
    }
    async fn max_seq_above(
        &self,
        volume: &str,
        floor: u64,
    ) -> Result<Option<u64>, granary_core::rootstore::RootStoreError> {
        granary_core::rootstore::RootStore::max_seq_above(self.0, volume, floor).await
    }
    async fn read_hint(
        &self,
        _: &str,
        _: Option<&granary_core::rootstore::HintToken>,
    ) -> Result<granary_core::rootstore::HintRead, granary_core::rootstore::RootStoreError> {
        panic!("landing re-fetch must verify the numbered chain");
    }
    async fn write_hint(
        &self,
        _: &str,
        _: u64,
    ) -> Result<(), granary_core::rootstore::RootStoreError> {
        panic!("landing re-fetch must never write");
    }
}

#[tokio::test]
async fn completed_landing_refetch_does_not_reselect_a_higher_candidate() {
    let (transport, _, key, keys, _, _) = setup();
    let mut record = record();
    let earlier = record.candidates[0].clone();
    let mut variant = root::decode_root(&earlier.root).unwrap();
    variant.sigs.push(RootSig {
        key_id: [98; 32],
        sig: [0; 64],
    });
    let variant = root::encode_root(&variant).unwrap();
    let mut later = root::decode_root(&variant).unwrap();
    later.seq = 2;
    later.parent = Some(GrainId::of(&variant));
    let later = sign_doc(later, &key);
    record.candidates[0].role = Role::History;
    let mut candidate = candidate(2, 1, later.clone());
    candidate.seq = 2;
    record.candidates.push(candidate);
    record.phase = Phase::Complete(Completion {
        seq: 1,
        id: earlier.id,
        root: earlier.root,
        receipt: None,
    });
    record.current = None;
    transport
        .remote
        .lock()
        .unwrap()
        .roots
        .extend([(1, variant.clone()), (2, later)]);
    let original = record.clone();
    let mut cases = 0;
    for journal in [None, Some((1, GrainId::of(&variant)))] {
        let result = refetch_landing(&LandingReader(&transport), &record, journal, &keys).await;
        assert_eq!(
            (result.unwrap(), record == original),
            (Some((variant.clone(), GrainId::of(&variant))), true),
            "terminal completion cannot be replaced by a higher matching candidate"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}
