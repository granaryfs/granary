// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Archive evidence from writable mount fixtures.

use super::*;
use crate::overlay_discard::tests::claim_healthy_store;
use granary_core::overlay_discard::Outcome;

/// Every reported row's text, probed through any transport.
pub(crate) async fn probe_archive_rows(
    evidence: &ArchiveReconciliation,
    remote: &impl AuthorityTransport,
    route: Option<&Scope>,
    keys: &TrustedKeys,
) -> Vec<String> {
    evidence
        .probe(remote, route, keys)
        .await
        .iter()
        .map(|row| row.to_string().trim_end().to_owned())
        .collect()
}

/// Each journal-bound publication and whether a retained record was bound to it.
pub(crate) fn archive_publication_bindings(
    evidence: &ArchiveReconciliation,
) -> Vec<(String, bool, bool)> {
    evidence
        .publications
        .iter()
        .map(|(id, publication)| {
            (
                hex(id),
                publication.is_some(),
                publication.as_ref().is_some_and(|p| p.witness.is_some()),
            )
        })
        .collect()
}

fn clean_case(archive: Option<bool>) -> Case {
    let mut case = Case::new();
    case.journal.clear();
    case.materialize(archive);
    case
}

#[test]
fn discard_plan_refuses_a_settled_publication_archive() {
    let case = clean_case(Some(true));
    let plan = discard_overlay(&case.root, case.scope(), &case.record.volume, None);
    assert_eq!(plan.map_err(DiscardError::reason), Err(NOT_ELIGIBLE));
}

#[test]
fn discard_plan_admits_abandoned_and_incomplete_live_publications() {
    for (archive, label) in [(Some(false), "abandoned"), (None, "incomplete live")] {
        let case = clean_case(archive);
        let plan = discard_overlay(&case.root, case.scope(), &case.record.volume, None);
        assert!(
            matches!(&plan, Ok(row) if matches!(row.outcome, Outcome::Live(_))),
            "{label} publication must admit a live discard plan, got {plan:?}",
        );
    }
}

#[tokio::test]
async fn discard_retries_and_reconciles_a_claimed_healthy_store() {
    let case = clean_case(Some(true));
    let tuple = claim_healthy_store(&case.root, &case.area, case.scope(), &case.record.volume);
    assert_eq!(
        boundaryless_rows(&case, tuple).await,
        Ok(Vec::new()),
        "a settled archive alone has no publication that can still land",
    );
}

async fn boundaryless_rows(case: &Case, tuple: Tuple) -> Result<Vec<String>, Refusal> {
    let before = snapshot(&case.root);
    let opened = ArchiveReconciliation::open(&case.root, case.scope(), &case.record.volume, tuple);
    let result = match opened {
        Ok(evidence) => {
            let keys = TrustedKeys::new([*case.key.public_key()]).unwrap();
            Ok(probe_archive_rows(&evidence, &case.remote, Some(&case.record.scope), &keys).await)
        }
        Err(error) => Err(error.reason()),
    };
    let authority = case.remote.remote.lock().unwrap();
    assert_eq!(
        (
            snapshot(&case.root) == before,
            [
                authority.sends.len(),
                authority.meta_uploads,
                authority.bin_uploads,
                authority.max_seq_calls,
                authority.probes,
                authority.status_calls,
            ],
        ),
        (true, [0; 6]),
        "reconcile must preserve the store and make no authority request",
    );
    result
}

#[tokio::test]
async fn boundaryless_archive_refuses_an_incomplete_live_record() {
    let case = clean_case(None);
    let tuple = case.tuple(true);
    assert_eq!(
        boundaryless_rows(&case, tuple).await,
        Err(UNRESOLVED),
        "the incomplete live record can still land",
    );
}

#[tokio::test]
async fn boundaryless_archive_refuses_an_abandoned_record() {
    let case = clean_case(Some(false));
    let tuple = case.tuple(true);
    assert_eq!(
        boundaryless_rows(&case, tuple).await,
        Err(UNRESOLVED),
        "the abandoned record can still land",
    );
}

fn complete(record: &mut Submission) {
    let winner = record.candidates.first().unwrap();
    record.current = None;
    record.phase = p::Phase::Complete(p::Completion {
        seq: winner.seq,
        id: winner.id,
        root: winner.root.clone(),
        receipt: None,
    });
}

#[tokio::test]
async fn boundaryless_archive_refuses_a_possible_write_above_completion() {
    for possibly_written in [true, false] {
        let mut case = Case::new();
        case.journal.clear();
        let winner = case.record.candidates.first().unwrap();
        let mut later = winner.clone();
        later.number += 1;
        later.seq += 1;
        later.role = p::Role::History;
        let mut doc = root::decode_root(&winner.root).unwrap();
        doc.seq = later.seq;
        doc.parent = Some(winner.id);
        later.root = sign_doc(doc, &case.key);
        later.id = GrainId::of(&later.root);
        later.evidence = p::Evidence {
            started: 1,
            proved_no_write: u64::from(!possibly_written),
            last_answered_attempt: u64::from(!possibly_written),
            ..p::Evidence::default()
        };
        complete(&mut case.record);
        case.record.candidates.push(later);
        case.materialize(None);
        let tuple = claim_healthy_store(&case.root, &case.area, case.scope(), &case.record.volume);
        let expected = if possibly_written {
            Err(UNRESOLVED)
        } else {
            Ok(Vec::new())
        };
        assert_eq!(
            boundaryless_rows(&case, tuple).await,
            expected,
            "the candidate above the winner was possibly written: {possibly_written}",
        );
    }
}

#[tokio::test]
async fn boundaryless_archive_refuses_a_record_in_another_scope() {
    let case = clean_case(Some(true));
    let mut foreign = case.record.clone();
    foreign.scope.credential_context = b"other-writer".to_vec();
    foreign.publication_id = [23; 16];
    complete(&mut foreign);
    let foreign_digest = foreign.scope.digest().unwrap();
    assert_ne!(
        foreign_digest,
        hex(&case.scope()),
        "a distinct scope is required"
    );
    let (mut store, _) = Store::open_existing(&case.root).unwrap();
    store
        .publications(nix::unistd::geteuid().as_raw())
        .unwrap()
        .begin(&foreign)
        .unwrap();
    drop(store);
    let tuple = claim_healthy_store(&case.root, &case.area, case.scope(), &case.record.volume);
    assert_eq!(
        boundaryless_rows(&case, tuple).await,
        Err(UNRESOLVED),
        "even a complete live record in another scope prevents settlement",
    );
}

#[tokio::test]
async fn boundaryless_archive_refuses_contradictory_settled_records() {
    let mut case = Case::new();
    case.journal.clear();
    complete(&mut case.record);
    case.materialize(Some(true));
    let tuple = claim_healthy_store(&case.root, &case.area, case.scope(), &case.record.volume);
    assert_eq!(
        boundaryless_rows(&case, tuple).await,
        Err(UNRESOLVED),
        "a settled archive cannot contain a completed landing",
    );

    let case = clean_case(Some(true));
    let mut live = case.record.clone();
    complete(&mut live);
    let path = case
        .root
        .join("publications")
        .join(hex(&case.scope()))
        .join(format!("{}.sub", case.record.volume.as_str()));
    put(&path, &p::encode(&live).unwrap());
    let tuple = claim_healthy_store(&case.root, &case.area, case.scope(), &case.record.volume);
    assert_eq!(
        boundaryless_rows(&case, tuple).await,
        Err(UNRESOLVED),
        "one publication cannot be both settled and complete",
    );
}

#[tokio::test]
async fn boundaryless_archive_refuses_a_torn_journal() {
    let case = clean_case(Some(true));
    let length = j::encode_journal(&case.header, &case.journal)
        .unwrap()
        .len();
    let mut io = OverlayDisk::new(&case.root, nix::unistd::geteuid().as_raw());
    io.write_at(&case.area.join("journal"), length as u64, &[1])
        .unwrap();
    let tuple = case.tuple(true);
    assert_eq!(
        boundaryless_rows(&case, tuple).await,
        Err(UNRESOLVED),
        "a torn record can hide a publication boundary",
    );
}
