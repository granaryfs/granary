// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]
use super::*;

#[test]
fn every_outcome_has_verb_local_exit_code_and_one_json_object() {
    for (outcome, code) in [
        (Outcome::Landed, 0),
        (Outcome::Abandoned, 0),
        (Outcome::LocalError, 1),
        (Outcome::UsageError, 2),
        (Outcome::Pending, 3),
        (Outcome::Refused, 4),
        (Outcome::Unresolved, 5),
        (Outcome::BackendError, 6),
    ] {
        for route in [
            None,
            Some(Route::Authority),
            Some(Route::ServerSeam),
            Some(Route::DirectS3),
            Some(Route::Local),
        ] {
            let mut report = InvocationReport::new(None);
            report.outcome = outcome;
            report.route = route;
            report.diagnostic = Some("sanitized\nquoted \"diagnostic\"".into());
            let mut out = Vec::new();
            let mut err = Vec::new();
            assert_eq!(
                report.render(true, &mut out, &mut err),
                ExitCode::from(code)
            );
            let text = String::from_utf8(out).unwrap();
            assert!(text.starts_with('{'));
            assert!(text.ends_with("}\n"));
            assert_eq!(text.lines().count(), 1);
            assert!(text.contains(&format!("\"exit_code\":{code}")));
            assert!(text.contains("\"schema_version\":1"));
            assert!(text.contains("\"completion\":null"));
            assert!(text.contains("\"publication\":null"));
            assert!(err.is_empty());
        }
    }
}
struct Closed;
impl Write for Closed {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("closed"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn output_failure_exits_one_and_reports_known_landing_or_archival_on_stderr() {
    for outcome in [Outcome::Landed, Outcome::Abandoned] {
        let mut report = InvocationReport::new(None);
        report.outcome = outcome;
        report.publication_id = Some([7; 16]);
        let mut err = Vec::new();
        assert_eq!(
            report.render(true, &mut Closed, &mut err),
            ExitCode::from(1)
        );
        let text = String::from_utf8(err).unwrap();
        assert!(text.contains(outcome.name()));
        assert!(text.contains(&hex(&[7; 16])));
        assert!(!text.starts_with('{'));
    }
}
#[test]
fn submission_retained_requires_live_record_evidence() {
    for retention in [
        Retention::None,
        Retention::Live,
        Retention::Archive,
        Retention::Unknown,
    ] {
        for id in [None, Some([7; 16])] {
            let mut report = InvocationReport::new(None);
            report.outcome = Outcome::Pending;
            report.retention = retention;
            report.publication_id = id;
            let mut err = Vec::new();
            assert_eq!(
                report.render(false, &mut Vec::new(), &mut err),
                ExitCode::from(report.outcome.code())
            );
            assert_eq!(
                String::from_utf8(err)
                    .unwrap()
                    .contains("submission retained"),
                retention == Retention::Live && id.is_some()
            );
        }
    }
}
#[test]
fn completion_decode_failure_keeps_manifest_and_root_epoch_unavailable() {
    let root = b"invalid root".to_vec();
    let done = Completion {
        seq: 9,
        id: GrainId::of(&root),
        root,
        receipt: None,
    };
    let winner = Winner::authority(&done);
    assert_eq!(winner.seq, 9);
    assert!(winner.manifest_root.is_none());
    assert!(winner.root_epoch.is_none());
    assert!(winner.json().contains("\"manifest_root\":null"));
    assert!(winner.json().contains("\"root_epoch\":null"));
    assert!(winner.receipt.is_none());
}
#[test]
fn checked_answer_identification_keeps_service_reasons_and_uncertainty() {
    use granary_client::{PublishResponse, ServiceReason};
    for response in [
        PublishResponse::RateLimited,
        PublishResponse::ServiceUnavailable(ServiceReason::Unavailable),
        PublishResponse::ServiceUnavailable(ServiceReason::EnrollmentUnavailable),
        PublishResponse::ServiceUnavailable(ServiceReason::Fenced),
        PublishResponse::ServiceUnavailable(ServiceReason::Stopped),
    ] {
        let mut report = InvocationReport::new(None);
        report.response = Some(Identification::response(&response));
        report.uncertain = true;
        let (_, token) = response.identification();
        let json = report.json();
        assert!(json.contains(&format!("\"token\":{}", quote(token.unwrap()))));
        assert!(json.contains("\"uncertain\":true"));
    }
}
