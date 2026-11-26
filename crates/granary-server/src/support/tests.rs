// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

mod grant_reasons;

use super::*;
use crate::config::authority::AuthorityProfile;
use crate::{
    authority::{HeadRef, Observation, OpenPosition, TerminalState, VerifiedHead, VolumeView},
    debug_grant::{DebugGrantSnapshot, reader::ReaderCounters},
    diagnostics::{
        CaptureCounters, CaptureEntry, CaptureKind, CaptureRevision, CaptureSelector, CaptureSlot,
    },
    enrollment::{EnrollmentSnapshot, SnapshotCounters, SnapshotState},
    refusals::RefusalSnapshot,
    wire::ErrorToken,
};
use granary_core::root::VolumeName;
use granary_core::{
    debug_grant::{DebugGrant, GrantAction, GrantFields, GrantScope, Owner, Reason},
    enrollment::PrincipalId,
    hash::GrainId,
};

fn configuration_inputs() -> AuthorityConfig {
    AuthorityConfig {
        authority_profile: AuthorityProfile::SingleProcess,
        state_dir: "/SECRET-STATE".into(),
        enrollment_dir: "/SECRET-ENROLLMENT".into(),
        client_ca: "/SECRET-CA".into(),
        volumes: [
            (
                VolumeName::new("alpha".into()).unwrap(),
                (0..3).map(|i| [0x6b + i; 32]).collect(),
            ),
            (
                VolumeName::new("omega".into()).unwrap(),
                (0..8).map(|i| [0x7c + i; 32]).collect(),
            ),
        ]
        .into(),
        accept_unsupported_filesystem: true,
        controls: ControlsConfig::parse("7,9,33554432,268435456,3").unwrap(),
    }
}
pub(super) fn configuration() -> SupportConfiguration {
    bound_configuration(
        retain_configuration(
            &configuration_inputs(),
            Incarnation::from_bytes([0x41; 16]),
            11,
            Duration::from_millis(9876),
            Some(Duration::from_millis(5432)),
        )
        .unwrap(),
        "127.0.0.1:43210".parse().unwrap(),
    )
}
#[expect(
    clippy::too_many_lines,
    reason = "one fixture spells every cached field so omissions stay visible"
)]
pub(super) fn source() -> Observation {
    let incarnation = Incarnation::from_bytes([0x41; 16]);
    let principal = PrincipalId::from_bytes([0x42; 16]);
    let volume = VolumeName::new("alpha".into()).unwrap();
    let record = DebugGrant::new(GrantFields {
        incarnation,
        file_revision: 19,
        grant_generation: 17,
        action: GrantAction::Narrow,
        issuer_uid: 123,
        owner: Owner::from_bytes(b"SECRET-OWNER-SENTINEL").unwrap(),
        reason: Reason::from_bytes(b"SECRET-REASON-SENTINEL").unwrap(),
        issued_at: Timestamp { secs: -7, nanos: 9 },
        expires_at: Timestamp {
            secs: 32,
            nanos: 15,
        },
        scope: GrantScope::Conjunction {
            principal,
            volume: volume.clone(),
        },
        line_ceiling: 31,
        byte_ceiling: 12345,
    })
    .unwrap();
    let id = GrainId::of(b"support-root");
    Observation {
        volumes: [
            (
                volume.clone(),
                VolumeView::Log {
                    epoch: granary_core::authlog::Epoch::from_bytes([0x45; 16]),
                    head: Some(VerifiedHead::new(Some(HeadRef {
                        head_seq: 7,
                        head_id: id,
                    }))),
                    open: Some(OpenPosition {
                        entry_seq: 9,
                        candidate_id: id,
                    }),
                },
            ),
            (
                VolumeName::new("empty".into()).unwrap(),
                VolumeView::Log {
                    epoch: granary_core::authlog::Epoch::from_bytes([0x46; 16]),
                    head: Some(VerifiedHead::new(None)),
                    open: None,
                },
            ),
            (
                VolumeName::new("unknown".into()).unwrap(),
                VolumeView::Log {
                    epoch: granary_core::authlog::Epoch::from_bytes([0x47; 16]),
                    head: None,
                    open: None,
                },
            ),
            (VolumeName::new("omega".into()).unwrap(), VolumeView::NoLog),
        ]
        .into(),
        terminal: Some(TerminalState::Fenced),
        enrollment: EnrollmentSnapshot {
            state: SnapshotState::Ok {
                principals: 31,
                credentials: 57,
            },
            sequence: 99,
            counters: SnapshotCounters {
                missing: 1,
                unreadable: 2,
                unprotected: 3,
                oversize: 4,
                corrupt: 5,
                directory: 6,
                stalled: 7,
                reloads: 8,
                reload_failures: u64::MAX,
            },
        },
        refusals: RefusalSnapshot {
            totals: [
                ErrorToken::NotFound,
                ErrorToken::UnknownTarget,
                ErrorToken::AlreadyExists,
                ErrorToken::AddressMismatch,
                ErrorToken::VerifyFailed,
                ErrorToken::LayoutInvalid,
                ErrorToken::BadRange,
                ErrorToken::ExtentTooWide,
                ErrorToken::BadRequest,
                ErrorToken::MethodNotAllowed,
                ErrorToken::TooLarge,
                ErrorToken::Internal,
                ErrorToken::Unavailable,
                ErrorToken::NoPrincipal,
                ErrorToken::NotEnrolled,
                ErrorToken::RateLimited,
                ErrorToken::AuthorityManaged,
                ErrorToken::InvalidCandidate,
                ErrorToken::NoLog,
                ErrorToken::UnknownVolume,
                ErrorToken::StaleBase,
                ErrorToken::OperationBound,
                ErrorToken::NotDecided,
                ErrorToken::EpochMismatch,
                ErrorToken::VolumeDamaged,
                ErrorToken::Fenced,
                ErrorToken::Stopped,
                ErrorToken::EnrollmentUnavailable,
            ]
            .iter()
            .enumerate()
            .map(|(i, &r)| (r, i as u64 + 1))
            .collect(),
            principals: [
                (
                    principal,
                    [
                        (ErrorToken::RateLimited, 123),
                        (ErrorToken::Fenced, u64::MAX),
                    ]
                    .into(),
                ),
                (
                    PrincipalId::from_bytes([0x43; 16]),
                    [(ErrorToken::NoLog, 777)].into(),
                ),
            ]
            .into(),
        },
        debug_grant: Some(DebugGrantSnapshot {
            incarnation,
            state: "disabled",
            reason: Some("future-issued"),
            future_issued_lead_secs: Some(u64::MAX),
            observed: Some(record.clone()),
            accepted: Some(record),
            effective: Some(CaptureEntry {
                slot: CaptureSlot(11),
                selector: CaptureSelector::PrincipalAndVolume(principal, volume),
                kind: CaptureKind::AuthenticatedRequest,
                level: tracing::Level::DEBUG,
                remaining_lines: 13,
                remaining_bytes: 16384,
                deadline: Some(Timestamp {
                    secs: 32,
                    nanos: 15,
                }),
                lease: Some(17),
            }),
            slot: Some(CaptureSlot(11)),
            capture_revision: CaptureRevision(29),
            high_revision: 19,
            high_generation: 17,
            retired_generation: 16,
            reader_counters: ReaderCounters {
                refreshes: 101,
                reloads: 102,
                refusals: 103,
                unreadable: 104,
                stalled: 105,
                applications: 106,
                retirements: 107,
            },
            capture_counters: CaptureCounters {
                admitted: 201,
                budget_suppressed: 202,
                suppressed: 203,
                expiry_suppressed: 204,
                expired: 205,
                contention: 206,
                malformed: 207,
                oversize: 208,
                queued: 209,
                sink_drops: 210,
            },
        }),
    }
}
fn snapshot() -> SupportSnapshot {
    snapshot_from_observation(
        Incarnation::from_bytes([0x41; 16]),
        Timestamp {
            secs: 123_456_789,
            nanos: 987_654_321,
        },
        &source(),
    )
    .unwrap()
}

#[test]
fn support_snapshot_expired_grant_round_trips() {
    let mut observation = source();
    let grant = observation.debug_grant.as_mut().unwrap();
    grant.state = "disabled";
    grant.reason = Some("expired");
    grant.effective = None;
    let projected = snapshot_from_observation(
        grant.incarnation,
        Timestamp { secs: 60, nanos: 0 },
        &observation,
    )
    .unwrap();
    let encoded = projected.encode();
    assert!(
        encoded.is_ok(),
        "expired cached grant must encode without a demand refresh: {encoded:?}"
    );
    assert_eq!(SupportSnapshot::decode(&encoded.unwrap()), Ok(projected));
}

#[test]
fn support_export_configuration_provenance() {
    assert_eq!(
        millis(Duration::from_nanos(1)),
        Err(SupportError("duration precision"))
    );
    assert_eq!(
        millis(Duration::from_secs(u64::MAX)),
        Err(SupportError("duration overflow"))
    );
    let retain = |c: &AuthorityConfig| {
        retain_configuration(
            c,
            Incarnation::from_bytes([0; 16]),
            1,
            Duration::from_millis(1),
            None,
        )
    };
    let mut c = configuration_inputs();
    c.volumes.clear();
    assert_eq!(retain(&c), Err(SupportError("volume count")));
    let mut c = configuration_inputs();
    c.volumes.values_mut().next().unwrap().clear();
    assert_eq!(retain(&c), Err(SupportError("publisher key count")));
    let dto = configuration();
    assert_eq!(
        (
            dto.authority_profile,
            dto.volumes.values().copied().collect::<Vec<_>>(),
            dto.controls.tuple()
        ),
        (
            AuthorityProfile::SingleProcess,
            vec![3, 8],
            (7, 9, 33_554_432, 268_435_456, 3)
        )
    );
    assert_eq!(
        (
            dto.listen_port,
            dto.tls_enabled,
            dto.client_auth_required,
            dto.worker_threads,
            dto.shutdown_budget_ms,
            dto.dispatch_deadline_ms,
            dto.network_dispatch_limit_ms,
            dto.network_client_timeout_ms
        ),
        (43210, true, true, 11, 9876, Some(5432), 30000, 60000)
    );
    let result = dto.encode();
    assert!(
        result.is_ok(),
        "configuration must publish allowlisted bytes: {result:?}"
    );
    let bytes = result.unwrap();
    assert_eq!(SupportConfiguration::decode(&bytes), Ok(dto));
    assert_eq!(bytes, golden("configuration"));
    for secret in [b"SECRET".as_slice(), &[0x6b; 32], &[0x7c; 32]] {
        assert!(!bytes.windows(secret.len()).any(|s| s == secret));
    }
}
#[test]
fn support_export_snapshot_fidelity_and_labels() {
    let mut invalid = snapshot();
    invalid.enrollment.state = data::SnapshotState::Ok {
        principals: 0,
        credentials: 1,
    };
    assert_eq!(invalid.encode(), Err(SupportError("enrollment inventory")));
    let original = source();
    let dto = snapshot();
    let expected = granary_core::support::SupportSnapshot::decode(&golden("snapshot")).unwrap();
    assert_eq!(
        &dto, &expected,
        "every cached domain and counter must match the independent fixture"
    );
    let s = original.debug_grant.as_ref().unwrap();
    let g = dto.grant.as_ref().unwrap();
    let r = g.observed.as_ref().unwrap();
    let f = s.observed.as_ref().unwrap().fields();
    assert_eq!(
        (
            r.incarnation,
            r.file_revision,
            r.grant_generation,
            r.action,
            r.issuer_uid,
            r.issued_at,
            r.expires_at,
            &r.scope,
            r.line_ceiling,
            r.byte_ceiling
        ),
        (
            f.incarnation,
            f.file_revision,
            f.grant_generation,
            f.action,
            f.issuer_uid,
            f.issued_at,
            f.expires_at,
            &f.scope,
            f.line_ceiling,
            f.byte_ceiling
        )
    );
    assert_eq!(g.accepted, g.observed);
    let result = dto.encode();
    assert!(
        result.is_ok(),
        "snapshot must publish complete cached domains: {result:?}"
    );
    let bytes = result.unwrap();
    assert_eq!(SupportSnapshot::decode(&bytes), Ok(dto));
    assert_eq!(bytes, golden("snapshot"));
    for label in [
        b"SECRET-OWNER-SENTINEL".as_slice(),
        b"SECRET-REASON-SENTINEL",
    ] {
        assert!(!bytes.windows(label.len()).any(|s| s == label));
    }
}

fn golden(name: &str) -> Vec<u8> {
    let row = include_str!("../../../granary-core/tests/vectors/support_v1.tsv")
        .lines()
        .find(|l| l.split('\t').next() == Some(name))
        .unwrap();
    row.split('\t')
        .nth(1)
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn support_projection_capture_profile() {
    let sample = || {
        snapshot_from_observation(
            Incarnation::from_bytes([0x41; 16]),
            Timestamp { secs: 1, nanos: 0 },
            &source(),
        )
    };
    assert!(sample().is_ok(), "valid cached profile: {:?}", sample());
    let mut count = 0;
    for level in [tracing::Level::INFO, tracing::Level::TRACE] {
        let mut s = source();
        s.debug_grant
            .as_mut()
            .unwrap()
            .effective
            .as_mut()
            .unwrap()
            .level = level;
        assert_eq!(
            snapshot_from_observation(
                Incarnation::from_bytes([0x41; 16]),
                Timestamp { secs: 1, nanos: 0 },
                &s
            ),
            Err(SupportError("capture kind or level"))
        );
        count += 1;
    }
    assert_eq!(count, 2);
}
#[test]
fn support_configuration_controls_accept_set() {
    let mut count = 0;
    for cap in 0..=9_u64 {
        for rate in [0, 1, 4, u64::MAX] {
            for burst in [0, 1, 268_435_455, 268_435_456, u64::MAX] {
                let values = [rate, burst, rate, burst, cap];
                let parsed = ControlsConfig::parse(&values.map(|n| n.to_string()).join(","));
                let mut dto = configuration();
                dto.controls = data::SupportControls(values);
                let encoded = dto.encode();
                assert_eq!(
                    parsed.is_ok(),
                    encoded.is_ok(),
                    "controls {values:?}: parsed {parsed:?}, encoded {encoded:?}"
                );
                if parsed.is_err() {
                    assert_eq!(encoded, Err(SupportError("controls")));
                }
                count += 1;
            }
        }
    }
    assert_eq!(count, 200);
}

#[test]
fn round1_frozen_support_cannot_project_intent_reasons() {
    for token in [
        ErrorToken::IntentSuperseded,
        ErrorToken::IntentBound,
        ErrorToken::IntentChanged,
        ErrorToken::IntentAbsent,
        ErrorToken::IntentCursorChanged,
        ErrorToken::IntentEpochExhausted,
        ErrorToken::IntentQuota,
    ] {
        assert!(
            project_reason(token).is_none(),
            "frozen v1 must not alias intent reasons: {token:?}"
        );
    }
}
