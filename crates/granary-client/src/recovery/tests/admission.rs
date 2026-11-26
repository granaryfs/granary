// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the refusal and intent table checks the saved first answer and the second drive together"
)]
async fn saved_admission_refusal_stops_automatic_resend_for_either_intent() {
    let mut second_drives = Vec::new();
    let mut expected = Vec::new();
    for (refusal, status, token) in [
        (
            crate::PublishRefusal::MissingReference,
            400,
            "missing-reference",
        ),
        (
            crate::PublishRefusal::InvalidReference,
            400,
            "invalid-reference",
        ),
        (
            crate::PublishRefusal::PublishWorkLimit,
            413,
            "publish-work-limit",
        ),
    ] {
        for intent in [RecoveryIntent::Continue, RecoveryIntent::ExplicitRecovery] {
            let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
            let mut r = record();
            r.candidates[0].evidence = Evidence::default();
            let handle = handle(&r);
            *transport.durable.lock().unwrap() = Some(r);
            let response = PublishResponse::Refused(refusal);
            transport
                .remote
                .lock()
                .unwrap()
                .plans
                .extend([Plan::Reply(response), Plan::Land]);

            let first = resume_publication(
                parts(
                    &transport,
                    &mut journal,
                    &key,
                    &keys,
                    &mut entropy,
                    &FixedClock(2),
                    &mut delay,
                ),
                &handle,
                intent,
            )
            .await
            .unwrap();
            let durable = transport.durable.lock().unwrap().clone().unwrap();
            assert_eq!(
                (
                    first.outcome,
                    first.response,
                    first.uncertain,
                    transport.remote.lock().unwrap().sends.len(),
                    &durable.phase,
                    durable.candidates.len(),
                    durable
                        .candidates
                        .iter()
                        .all(|c| c.evidence.never_decided()),
                    durable
                        .last_response
                        .as_ref()
                        .map(|a| (a.status, a.token.as_slice())),
                    delay.waits.len(),
                ),
                (
                    PublicationOutcome::Refused,
                    Some(response),
                    false,
                    1,
                    &Phase::Ready,
                    1,
                    true,
                    Some((status, token.as_bytes())),
                    0,
                ),
                "{refusal:?} {intent:?}: first drive"
            );
            let bytes = granary_core::retained_submission::encode(&durable).unwrap();
            assert_eq!(
                granary_core::retained_submission::decode(&bytes).unwrap(),
                durable
            );

            let second = resume_publication(
                parts(
                    &transport,
                    &mut journal,
                    &key,
                    &keys,
                    &mut entropy,
                    &FixedClock(2),
                    &mut delay,
                ),
                &handle,
                intent,
            )
            .await
            .unwrap();
            second_drives.push((
                refusal,
                intent,
                second.outcome == PublicationOutcome::Refused,
                second
                    .response
                    .as_ref()
                    .map(PublishResponse::identification),
                transport.remote.lock().unwrap().sends.len(),
            ));
            expected.push((refusal, intent, true, Some((status, Some(token))), 1));
        }
    }
    assert_eq!(second_drives.len(), 6);
    assert_eq!(
        second_drives, expected,
        "(refusal, intent, refused again, response, total sends)"
    );
}

#[tokio::test]
async fn probe_landing_from_an_earlier_send_wins_over_saved_refusal() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let record = record();
    let handle = handle(&record);
    let candidate = record.candidates[0].clone();
    *transport.durable.lock().unwrap() = Some(record);
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .push_back(Plan::Reply(PublishResponse::Refused(
            crate::PublishRefusal::MissingReference,
        )));
    let first = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    assert_eq!(
        (first.outcome, first.uncertain),
        (PublicationOutcome::Refused, true)
    );
    let probes = {
        let mut remote = transport.remote.lock().unwrap();
        remote.roots.insert(candidate.seq, candidate.root.clone());
        remote.probes
    };
    let second = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &handle,
        RecoveryIntent::Continue,
    )
    .await
    .unwrap();
    let remote = transport.remote.lock().unwrap();
    assert_eq!(
        (
            matches!(&second.outcome, PublicationOutcome::Landed(done) if done.root == candidate.root),
            second.uncertain,
            remote.sends.len(),
            remote.probes > probes
        ),
        (true, false, 1, true),
        "verified landing must precede the refusal gate: {second:?}"
    );
}

#[tokio::test]
async fn explicit_publication_recovery_charges_checked_unavailable() {
    let (transport, mut journal, key, keys, mut entropy, mut delay) = setup();
    let record = record();
    let handle = handle(&record);
    *transport.durable.lock().unwrap() = Some(record);
    let unavailable = PublishResponse::ServiceUnavailable(crate::ServiceReason::Unavailable);
    transport
        .remote
        .lock()
        .unwrap()
        .plans
        .extend((0..8).map(|_| Plan::Reply(unavailable)));
    let result = resume_publication(
        parts(
            &transport,
            &mut journal,
            &key,
            &keys,
            &mut entropy,
            &FixedClock(2),
            &mut delay,
        ),
        &handle,
        RecoveryIntent::ExplicitRecovery,
    )
    .await
    .unwrap();
    let durable = transport.durable.lock().unwrap().clone().unwrap();
    assert_eq!(
        (
            result.outcome,
            result.response,
            result.uncertain,
            transport.remote.lock().unwrap().sends.len(),
            delay.waits.len(),
            durable.unavailable_exemptions
        ),
        (
            PublicationOutcome::Pending,
            Some(unavailable),
            true,
            8,
            7,
            0
        ),
        "ordinary explicit recovery must charge all eight answers"
    );
}
