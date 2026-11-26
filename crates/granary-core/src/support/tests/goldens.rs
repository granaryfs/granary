// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Semantic expectations transcribed independently of the codecs.
use super::*;
use crate::{
    authlog::Epoch,
    authority_answer::{Head, OpenPosition, VolumeStatus},
    hash::GrainId,
};

fn volume(name: &str) -> VolumeName {
    VolumeName::new(name.into()).unwrap()
}
fn principal(byte: u8) -> PrincipalId {
    PrincipalId::from_bytes([byte; 16])
}
fn scope() -> GrantScope {
    GrantScope::Conjunction {
        principal: principal(66),
        volume: volume("alpha"),
    }
}

pub(super) fn unavailable_snapshot(reason: UnavailableReason) -> SupportSnapshot {
    SupportSnapshot {
        incarnation: Incarnation::from_bytes([0x41; 16]),
        sampled_at: Timestamp {
            secs: 1234,
            nanos: 5678,
        },
        volumes: BTreeMap::from([(volume("alpha"), VolumeView::NoLog)]),
        terminal: None,
        enrollment: EnrollmentSnapshot {
            state: SnapshotState::Unavailable(reason),
            sequence: 2345,
            counters: SnapshotCounters {
                missing: 3451,
                unreadable: 3452,
                unprotected: 3453,
                oversize: 3454,
                corrupt: 3455,
                directory: 3456,
                stalled: 3457,
                reloads: 3458,
                reload_failures: 3459,
            },
        },
        refusals: RefusalSnapshot {
            totals: BTreeMap::new(),
            principals: BTreeMap::new(),
        },
        grant: None,
    }
}

pub(super) fn truncated_archive(support: bool) -> SupportArchive {
    let configuration =
        include_bytes!("../../../tests/vectors/support-configuration-sentinels.bin");
    let snapshot = include_bytes!("../../../tests/vectors/support-snapshot-sentinels.bin");
    let required = |kind, id: &[u8], member: &[u8], cap, bytes: &[u8]| ExportEntry {
        kind,
        id: id.to_vec(),
        projection_version: 1,
        cap,
        status: EntryStatus::Exported {
            member: member.to_vec(),
            length: u32::try_from(bytes.len()).unwrap(),
            digest: *GrainId::of(bytes).digest(),
        },
    };
    SupportArchive {
        manifest: SupportManifest {
            exported_at: Timestamp {
                secs: 1002,
                nanos: 1002,
            },
            incarnation: Incarnation::from_bytes([0x22; 16]),
            expected_incarnation: Some(Incarnation::from_bytes([0x22; 16])),
            sampled_at: Timestamp {
                secs: 1001,
                nanos: 1002,
            },
            age: SnapshotAge {
                status: AgeStatus::Fresh,
                seconds: 1,
                nanos: 0,
            },
            support_truncated: support,
            state_truncated: !support,
            entries: vec![
                required(
                    SourceKind::Snapshot,
                    b"SUPPORT-SNAPSHOT",
                    b"snapshot.bin",
                    8_388_608,
                    snapshot,
                ),
                required(
                    SourceKind::Configuration,
                    b"SUPPORT-CONFIGURATION",
                    b"configuration.bin",
                    32_768,
                    configuration,
                ),
                ExportEntry {
                    kind: if support {
                        SourceKind::SupportSummary
                    } else {
                        SourceKind::StateSummary
                    },
                    id: b"inventory".to_vec(),
                    projection_version: 1,
                    cap: 0,
                    status: EntryStatus::Refused(ExportRefusal::ScanLimit),
                },
            ],
        },
        members: BTreeMap::from([
            (b"configuration.bin".to_vec(), configuration.to_vec()),
            (b"snapshot.bin".to_vec(), snapshot.to_vec()),
        ]),
    }
}
pub(super) fn configuration() -> SupportConfiguration {
    SupportConfiguration {
        incarnation: Incarnation::from_bytes([65; 16]),
        authority_profile: AuthorityProfile::SingleProcess,
        volumes: BTreeMap::from([(volume("alpha"), 3), (volume("omega"), 8)]),
        accept_unsupported_filesystem: true,
        controls: SupportControls([7, 9, 33_554_432, 268_435_456, 3]),
        listen_port: 43_210,
        tls_enabled: true,
        client_auth_required: true,
        worker_threads: 11,
        shutdown_budget_ms: 9876,
        dispatch_deadline_ms: Some(5432),
        network_dispatch_limit_ms: 30_000,
        network_client_timeout_ms: 60_000,
    }
}
#[expect(
    clippy::too_many_lines,
    reason = "complete independent semantic expectation keeps the wire fields together"
)]
pub(super) fn snapshot() -> SupportSnapshot {
    use RefusalReason::*;
    let id = GrainId::from_bytes(&unhex(
        "01ad127b10e31cdea01030c196ee646e81afee51c23a2e256a45730b45ca0b6b2f",
    ))
    .unwrap();
    let record = SupportGrantRecord {
        incarnation: Incarnation::from_bytes([65; 16]),
        file_revision: 19,
        grant_generation: 17,
        action: GrantAction::Narrow,
        issuer_uid: 123,
        issued_at: Timestamp { secs: -7, nanos: 9 },
        expires_at: Timestamp {
            secs: 32,
            nanos: 15,
        },
        scope: scope(),
        line_ceiling: 31,
        byte_ceiling: 12_345,
    };
    // The enum list is the documented numeric registry, not the codec's table.
    let reasons = [
        NotFound,
        UnknownTarget,
        AlreadyExists,
        AddressMismatch,
        VerifyFailed,
        LayoutInvalid,
        BadRange,
        ExtentTooWide,
        BadRequest,
        MethodNotAllowed,
        TooLarge,
        Internal,
        Unavailable,
        NoPrincipal,
        NotEnrolled,
        RateLimited,
        AuthorityManaged,
        InvalidCandidate,
        NoLog,
        UnknownVolume,
        StaleBase,
        OperationBound,
        NotDecided,
        EpochMismatch,
        VolumeDamaged,
        Fenced,
        Stopped,
        EnrollmentUnavailable,
    ];
    SupportSnapshot {
        incarnation: Incarnation::from_bytes([65; 16]),
        sampled_at: Timestamp {
            secs: 123_456_789,
            nanos: 987_654_321,
        },
        volumes: BTreeMap::from([
            (
                volume("alpha"),
                VolumeView::Log(VolumeStatus {
                    epoch: Epoch::from_bytes([69; 16]),
                    head: Some(Head {
                        root: Some((7, id)),
                        next_seq: Some(8),
                    }),
                    open: Some(OpenPosition {
                        entry_seq: 9,
                        candidate_id: id,
                    }),
                }),
            ),
            (
                volume("empty"),
                VolumeView::Log(VolumeStatus {
                    epoch: Epoch::from_bytes([70; 16]),
                    head: Some(Head {
                        root: None,
                        next_seq: Some(1),
                    }),
                    open: None,
                }),
            ),
            (volume("omega"), VolumeView::NoLog),
            (
                volume("unknown"),
                VolumeView::Log(VolumeStatus {
                    epoch: Epoch::from_bytes([71; 16]),
                    head: None,
                    open: None,
                }),
            ),
        ]),
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
            totals: reasons
                .into_iter()
                .enumerate()
                .map(|(i, r)| (r, u64::try_from(i).unwrap() + 1))
                .collect(),
            principals: BTreeMap::from([
                (
                    principal(66),
                    BTreeMap::from([(RateLimited, 123), (Fenced, u64::MAX)]),
                ),
                (principal(67), BTreeMap::from([(NoLog, 777)])),
            ]),
        },
        grant: Some(SupportGrant {
            incarnation: Incarnation::from_bytes([65; 16]),
            state: "disabled",
            reason: Some("future-issued"),
            future_issued_lead_secs: Some(u64::MAX),
            observed: Some(record.clone()),
            accepted: Some(record),
            effective: Some(SupportCapture {
                slot: 11,
                scope: scope(),
                remaining_lines: 13,
                remaining_bytes: 16_384,
                deadline: Some(Timestamp {
                    secs: 32,
                    nanos: 15,
                }),
                lease: Some(17),
            }),
            slot: Some(11),
            capture_revision: 29,
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

// Fixed tags, booleans and values required equal by the format cannot have
// distinct sentinels. All independently variable numeric fields below do;
// nested records also differ so their order cannot silently swap.
pub(super) fn sentinel_configuration() -> SupportConfiguration {
    let mut c = configuration();
    c.incarnation = Incarnation::from_bytes([0x21; 16]);
    c.accept_unsupported_filesystem = false;
    c.controls = SupportControls([101, 102, 103, 268_435_457, 5]);
    c.worker_threads = 106;
    c.shutdown_budget_ms = 107;
    c.dispatch_deadline_ms = Some(108);
    c
}
#[expect(
    clippy::too_many_lines,
    reason = "distinct sentinels cover every independently variable snapshot field"
)]
pub(super) fn sentinel_snapshot() -> SupportSnapshot {
    let mut snapshot = snapshot();
    snapshot.incarnation = Incarnation::from_bytes([0x22; 16]);
    snapshot.sampled_at = Timestamp {
        secs: 1001,
        nanos: 1002,
    };
    let head_id = GrainId::from_bytes(&[&[1][..], &[0x29; 32][..]].concat()).unwrap();
    let open_id = GrainId::from_bytes(&[&[1][..], &[0x2a; 32][..]].concat()).unwrap();
    snapshot.volumes.insert(
        volume("alpha"),
        VolumeView::Log(VolumeStatus {
            epoch: Epoch::from_bytes([0x31; 16]),
            head: Some(Head {
                root: Some((1700, head_id)),
                next_seq: Some(1701),
            }),
            open: Some(OpenPosition {
                entry_seq: 1702,
                candidate_id: open_id,
            }),
        }),
    );
    snapshot.volumes.insert(
        volume("empty"),
        VolumeView::Log(VolumeStatus {
            epoch: Epoch::from_bytes([0x32; 16]),
            head: Some(Head {
                root: None,
                next_seq: Some(1),
            }),
            open: None,
        }),
    );
    snapshot.volumes.insert(
        volume("unknown"),
        VolumeView::Log(VolumeStatus {
            epoch: Epoch::from_bytes([0x33; 16]),
            head: None,
            open: None,
        }),
    );
    snapshot.enrollment.state = SnapshotState::Ok {
        principals: 1003,
        credentials: 1004,
    };
    snapshot.enrollment.sequence = 1005;
    snapshot.enrollment.counters = SnapshotCounters {
        missing: 1006,
        unreadable: 1007,
        unprotected: 1008,
        oversize: 1009,
        corrupt: 1010,
        directory: 1011,
        stalled: 1012,
        reloads: 1013,
        reload_failures: 1014,
    };
    for (i, count) in snapshot.refusals.totals.values_mut().enumerate() {
        *count = 1100 + u64::try_from(i).unwrap();
    }
    snapshot.refusals.principals = BTreeMap::from([
        (
            principal(0x2d),
            BTreeMap::from([(RefusalReason::RateLimited, 0), (RefusalReason::Fenced, 0)]),
        ),
        (principal(0x2e), BTreeMap::from([(RefusalReason::NoLog, 0)])),
    ]);
    let mut next = 1200;
    for reasons in snapshot.refusals.principals.values_mut() {
        for count in reasons.values_mut() {
            *count = next;
            next += 1;
        }
    }
    let grant = snapshot.grant.as_mut().unwrap();
    grant.incarnation = Incarnation::from_bytes([0x22; 16]);
    grant.future_issued_lead_secs = Some(1300);
    let observed = grant.observed.as_mut().unwrap();
    observed.incarnation = Incarnation::from_bytes([0x24; 16]);
    observed.file_revision = 1302;
    observed.grant_generation = 1301;
    observed.action = GrantAction::Issue;
    observed.issuer_uid = 1303;
    observed.issued_at = Timestamp {
        secs: 1304,
        nanos: 1305,
    };
    observed.expires_at = Timestamp {
        secs: 1306,
        nanos: 1307,
    };
    observed.line_ceiling = 131;
    observed.byte_ceiling = 1309;
    observed.scope = GrantScope::Conjunction {
        principal: principal(0x25),
        volume: volume("bravo"),
    };
    let accepted = grant.accepted.as_mut().unwrap();
    accepted.incarnation = Incarnation::from_bytes([0x26; 16]);
    accepted.file_revision = 1311;
    accepted.grant_generation = 1310;
    accepted.issuer_uid = 1312;
    accepted.issued_at = Timestamp {
        secs: 1313,
        nanos: 1314,
    };
    accepted.expires_at = Timestamp {
        secs: 1315,
        nanos: 1316,
    };
    accepted.line_ceiling = 132;
    accepted.byte_ceiling = 1318;
    accepted.scope = GrantScope::Conjunction {
        principal: principal(0x27),
        volume: volume("delta"),
    };
    let effective = grant.effective.as_mut().unwrap();
    effective.slot = 1400;
    effective.remaining_lines = 133;
    effective.remaining_bytes = 1402;
    effective.deadline = Some(Timestamp {
        secs: 1403,
        nanos: 1404,
    });
    effective.lease = Some(1405);
    effective.scope = GrantScope::Conjunction {
        principal: principal(0x28),
        volume: volume("gamma"),
    };
    grant.slot = Some(1406);
    grant.capture_revision = 1407;
    grant.high_revision = 1408;
    grant.high_generation = 1409;
    grant.retired_generation = 1410;
    grant.reader_counters = ReaderCounters {
        refreshes: 1500,
        reloads: 1501,
        refusals: 1502,
        unreadable: 1503,
        stalled: 1504,
        applications: 1505,
        retirements: 1506,
    };
    grant.capture_counters = CaptureCounters {
        admitted: 1600,
        budget_suppressed: 1601,
        suppressed: 1602,
        expiry_suppressed: 1603,
        expired: 1604,
        contention: 1605,
        malformed: 1606,
        oversize: 1607,
        queued: 1608,
        sink_drops: 1609,
    };
    snapshot
}
