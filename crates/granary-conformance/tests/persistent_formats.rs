// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Generated codec properties stay outside core's pure dependency closure.
#![expect(
    clippy::unwrap_used,
    reason = "generated test fixture invariants (standards rule 3)"
)]
use granary_core::{
    authlog::{
        self, Classified, Envelope, Epoch, Operation, Principal, Record, RecordBody, RootBytes,
        SubmissionIdentity, Tenant,
    },
    authority_answer::{Head, OpenPosition, VolumeStatus},
    debug_grant::{
        self, DebugGrant, GrantAction, GrantFields, GrantScope, Incarnation, Owner, Reason,
    },
    enrollment::{self, ClientSpkiDigest, EnrollmentSet, PrincipalId, TenantName},
    hash::GrainId,
    root::{self, RootDoc, RootSig, VolumeName},
    runmarker::{self, BootId, RunMarker},
    sheaf::Timestamp,
    support::*,
};
use proptest::prelude::*;
use std::collections::BTreeMap;

fn volume() -> VolumeName {
    VolumeName::new("alpha".into()).unwrap()
}
fn timestamp(secs: i64, nanos: u32) -> Timestamp {
    Timestamp { secs, nanos }
}
fn scope(which: u8, principal: PrincipalId) -> GrantScope {
    match which {
        0 => GrantScope::Principal(principal),
        1 => GrantScope::Volume(volume()),
        _ => GrantScope::Conjunction {
            principal,
            volume: volume(),
        },
    }
}
fn action(which: u8) -> GrantAction {
    match which {
        0 => GrantAction::Issue,
        1 => GrantAction::Narrow,
        _ => GrantAction::Revoke,
    }
}
fn configuration(
    inc: [u8; 16],
    values: [u64; 5],
    names: BTreeMap<String, u8>,
    optional: bool,
) -> SupportConfiguration {
    SupportConfiguration {
        incarnation: Incarnation::from_bytes(inc),
        authority_profile: AuthorityProfile::SingleProcess,
        volumes: names
            .into_iter()
            .map(|(name, keys)| (VolumeName::new(name).unwrap(), keys))
            .collect(),
        accept_unsupported_filesystem: optional,
        controls: SupportControls([
            values[0] % 1_000_000 + 1,
            values[1] % 1_000_000 + 1,
            values[2] % 1_000_000 + 1,
            268_435_456 + values[3] % 1_000_000,
            values[4] % 7 + 1,
        ]),
        listen_port: 43_210,
        tls_enabled: true,
        client_auth_required: true,
        worker_threads: values[0].max(1),
        shutdown_budget_ms: values[1].max(1),
        dispatch_deadline_ms: optional.then_some(values[2].max(1)),
        network_dispatch_limit_ms: 30_000,
        network_client_timeout_ms: 60_000,
    }
}
#[expect(
    clippy::too_many_lines,
    reason = "one generated value exercises every snapshot domain"
)]
fn snapshot(
    inc: [u8; 16],
    seed: [u8; 32],
    counts: [u64; 26],
    branch: u8,
    secs: i64,
    nanos: u32,
) -> SupportSnapshot {
    let principal = PrincipalId::from_bytes(inc);
    let issued = timestamp(secs, nanos);
    let expires = timestamp(secs + 1, nanos);
    let record = SupportGrantRecord {
        incarnation: Incarnation::from_bytes(inc),
        file_revision: counts[0].max(1),
        grant_generation: 1,
        action: action(branch % 3),
        issuer_uid: nanos,
        issued_at: issued,
        expires_at: expires,
        scope: scope(branch % 3, principal),
        line_ceiling: counts[1] % 1025,
        byte_ceiling: counts[2] % 1_048_577,
    };
    let reason = match branch % 4 {
        0 => RefusalReason::NotFound,
        1 => RefusalReason::RateLimited,
        2 => RefusalReason::Fenced,
        _ => RefusalReason::EnrollmentUnavailable,
    };
    let g = SupportGrant {
        incarnation: Incarnation::from_bytes(inc),
        state: match branch % 3 {
            0 => "unread",
            1 => "applied",
            _ => "disabled",
        },
        reason: (branch.is_multiple_of(2)).then_some("expired"),
        future_issued_lead_secs: (branch.is_multiple_of(2)).then_some(counts[3]),
        observed: Some(record.clone()),
        accepted: (branch.is_multiple_of(2)).then_some(record),
        effective: (branch.is_multiple_of(2)).then(|| SupportCapture {
            slot: counts[4],
            scope: scope(branch % 3, principal),
            remaining_lines: counts[5] % 1025,
            remaining_bytes: counts[6] % 1_048_577,
            deadline: Some(expires),
            lease: Some(counts[7]),
        }),
        slot: (branch.is_multiple_of(2)).then_some(counts[8]),
        capture_revision: counts[9],
        high_revision: counts[10],
        high_generation: counts[11],
        retired_generation: counts[12],
        reader_counters: ReaderCounters {
            refreshes: counts[0],
            reloads: counts[1],
            refusals: counts[2],
            unreadable: counts[3],
            stalled: counts[4],
            applications: counts[5],
            retirements: counts[6],
        },
        capture_counters: CaptureCounters {
            admitted: counts[7],
            budget_suppressed: counts[8],
            suppressed: counts[9],
            expiry_suppressed: counts[10],
            expired: counts[11],
            contention: counts[12],
            malformed: counts[13],
            oversize: counts[14],
            queued: counts[15],
            sink_drops: counts[16],
        },
    };
    SupportSnapshot {
        incarnation: Incarnation::from_bytes(inc),
        sampled_at: issued,
        volumes: BTreeMap::from([(
            volume(),
            if branch.is_multiple_of(2) {
                VolumeView::NoLog
            } else {
                VolumeView::Log(VolumeStatus {
                    epoch: Epoch::from_bytes(inc),
                    head: Some(Head::new(Some((
                        counts[17] % 18_446_744_073_709_551_614 + 1,
                        GrainId::of(&seed),
                    )))),
                    open: Some(OpenPosition {
                        entry_seq: counts[18].max(1),
                        candidate_id: GrainId::of(&seed),
                    }),
                })
            },
        )]),
        terminal: match branch % 3 {
            0 => None,
            1 => Some(TerminalState::Fenced),
            _ => Some(TerminalState::Stopped),
        },
        enrollment: EnrollmentSnapshot {
            state: if branch.is_multiple_of(2) {
                SnapshotState::Ok {
                    principals: 1,
                    credentials: usize::try_from(counts[19] % 16_385).unwrap(),
                }
            } else {
                SnapshotState::Unavailable(UnavailableReason::Stalled)
            },
            sequence: counts[20],
            counters: SnapshotCounters {
                missing: counts[0],
                unreadable: counts[1],
                unprotected: counts[2],
                oversize: counts[3],
                corrupt: counts[4],
                directory: counts[5],
                stalled: counts[6],
                reloads: counts[7],
                reload_failures: counts[8],
            },
        },
        refusals: RefusalSnapshot {
            totals: BTreeMap::from([(reason, counts[21])]),
            principals: BTreeMap::from([(principal, BTreeMap::from([(reason, counts[22])]))]),
        },
        grant: (!branch.is_multiple_of(4)).then_some(g),
    }
}
fn exported(kind: SourceKind, id: &[u8], name: &[u8], bytes: &[u8]) -> ExportEntry {
    ExportEntry {
        kind,
        id: id.to_vec(),
        projection_version: 1,
        cap: u32::try_from(kind.cap()).unwrap(),
        status: EntryStatus::Exported {
            member: name.to_vec(),
            length: u32::try_from(bytes.len()).unwrap(),
            digest: *GrainId::of(bytes).digest(),
        },
    }
}
fn bundle_exported(kind: BundleKind, bytes: &[u8]) -> BundleEntry {
    BundleEntry {
        kind,
        status: BundleEntryStatus::Exported {
            length: u32::try_from(bytes.len()).unwrap(),
            digest: *GrainId::of(bytes).digest(),
        },
    }
}
fn bundle_refused(kind: BundleKind, reason: BundleRefusal) -> BundleEntry {
    BundleEntry {
        kind,
        status: BundleEntryStatus::Refused(reason),
    }
}

fn bundle_configuration(
    flags: [bool; 17],
    pins: [u16; 2],
    threshold_bits: u64,
    tags: [u8; 5],
) -> BundleConfiguration {
    BundleConfiguration {
        mount_mode: tags[0],
        root_key_configured: flags[0],
        manifest_root_pinned: flags[1],
        trust_server: flags[2],
        tls_pin_count: pins[0],
        cache_configured: flags[3],
        seq_pinned: flags[4],
        uid_override: flags[5],
        gid_override: flags[6],
        allow_other: flags[7],
        foreground: flags[8],
        reset_floor: flags[9],
        force: flags[10],
        key_seed_configured: flags[11],
        store_dir_configured: flags[12],
        contention_threshold_bits: threshold_bits,
        certificate_configured: flags[13],
        key_configured: flags[14],
        credential_context_configured: flags[15],
        publisher_key_count: pins[1],
        wire_snapshot_configured: flags[16],
        log_format: tags[1],
        log_destination: tags[2],
        log_paths: tags[3],
        log_filter_source: tags[4],
    }
}
fn bundle_metrics(
    words: &[u64],
    incarnation: [u32; 4],
    available: [bool; 6],
    contention: u8,
) -> BundleMetrics {
    let mut next = words.iter().copied().cycle();
    let mut word = move || next.next().unwrap();
    let histograms = |w: &mut dyn FnMut() -> u64| BundleHistogram {
        buckets: std::array::from_fn(|_| w()),
        sum: w(),
    };
    BundleMetrics {
        incarnation,
        sequence: 1 + word() % (u64::MAX - 1),
        available,
        commits: std::array::from_fn(|_| word()),
        commit_duration: std::array::from_fn(|_| histograms(&mut word)),
        retries: std::array::from_fn(|_| word()),
        conflicts: word(),
        contention,
        syncs: std::array::from_fn(|_| word()),
        fuse: std::array::from_fn(|_| std::array::from_fn(|_| word())),
        registrations: std::array::from_fn(|_| word()),
        registration_duration: std::array::from_fn(|_| histograms(&mut word)),
        grains: word(),
        uploads: std::array::from_fn(|_| word()),
        rechunks: word(),
        cache: std::array::from_fn(|_| std::array::from_fn(|_| word())),
        transport: std::array::from_fn(|_| word()),
    }
}
/// One record carrying every key of `event`'s set, with the numeric-looking
/// payload in its first non-envelope key.
fn bundle_record(event: &str, payload: u64) -> String {
    let fields: Vec<String> = bundle_record_keys(event)
        .unwrap()
        .map(|key| match key {
            "event" => format!("\"event\":\"{event}\""),
            "spans" => {
                "\"spans\":[{\"name\":\"op\",\"op\":\"cor-0000000000000001\",\"kind\":\"commit\"}]"
                    .to_owned()
            }
            "level" | "target" => format!("\"{key}\":\"x\""),
            key => format!("\"{key}\":{payload}"),
        })
        .collect();
    format!("{{{}}}\n", fields.join(","))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]
    #[test]
    fn authority_log_records_round_trip(inc in any::<[u8;16]>(), seed in any::<[u8;32]>(),
        tenant in prop::collection::vec(any::<u8>(),1..=255), principal in prop::collection::vec(any::<u8>(),1..=1024),
        operation in prop::collection::vec(any::<u8>(),1..=255), seq in 1..=18_446_744_073_709_551_613_u64,
        secs in any::<i64>(), nanos in 0..1_000_000_000_u32, lost in any::<bool>()) {
        let envelope=Envelope::new(volume(),Epoch::from_bytes(inc));
        let id=GrainId::of(&seed);
        let base=(seq!=1).then_some(id);
        let candidate=root::encode_root(&RootDoc{
            volume:volume(),seq,parent:base,writer_uuid:inc,epoch:0,timestamp:timestamp(secs,nanos),
            chunker_spec:"generated".into(),manifest_root:id,binmap_index:id,sheaf_head:id,
            sigs:vec![RootSig{key_id:seed,sig:[0x55;64]}],
        }).unwrap();
        let candidate_id=GrainId::of(&candidate);
        let identity=SubmissionIdentity::new(Tenant::new(tenant).unwrap(),Principal::new(principal).unwrap(),Operation::new(operation).unwrap(),candidate_id);
        let outcome=if lost {RecordBody::Lost{identity:identity.clone(),occupant_id:GrainId::of(&[candidate.as_slice(),&[1]].concat())}} else {RecordBody::Landed{identity:identity.clone()}};
        let records=vec![
            Record::new(1,RecordBody::Decision{identity:identity.clone(),root_seq:seq,base,decided_at:timestamp(secs,nanos),candidate:RootBytes::new(candidate.clone()).unwrap()}).unwrap(),
            Record::new(1,RecordBody::Attestation{identity,stored_id:candidate_id,final_root:RootBytes::new(candidate).unwrap()}).unwrap(),
            Record::new(1,outcome).unwrap(),
        ];
        let mut bytes=authlog::encode_envelope(&envelope).as_bytes().to_vec();
        for r in &records {let append=authlog::encode_append(&envelope,r).unwrap();bytes.extend_from_slice(append.record());bytes.extend_from_slice(append.mark());}
        let Classified::Log{records:decoded,committed_len,tail_len,envelope:decoded_envelope}=authlog::classify(&bytes,&volume()).unwrap() else {prop_assert!(false,"log expected");return Ok(())};
        prop_assert_eq!((&decoded,committed_len,tail_len),(&records,bytes.len(),0));
        prop_assert_eq!(&decoded_envelope,&envelope);
        let mut canonical=authlog::encode_envelope(&decoded_envelope).as_bytes().to_vec();
        for r in &decoded {let append=authlog::encode_append(&decoded_envelope,r).unwrap();canonical.extend_from_slice(append.record());canonical.extend_from_slice(append.mark());}
        prop_assert_eq!(canonical,bytes);
    }
    #[test]
    fn run_marker_round_trip(boot in any::<[u8;16]>(),running in any::<bool>()) {
        let value=if running {RunMarker::Running(BootId::from_bytes(boot))} else {RunMarker::Clean};
        let bytes=runmarker::encode_marker(&value);
        prop_assert_eq!(runmarker::decode_marker(bytes.as_bytes()),Ok(value));
        prop_assert_eq!(runmarker::encode_marker(&runmarker::decode_marker(bytes.as_bytes()).unwrap()),bytes);
    }
    #[test]
    fn enrollment_set_round_trip(ids in prop::collection::btree_map(any::<[u8;16]>(),any::<bool>(),0..16),tenant in "[!-~]{1,255}",attach in any::<bool>()) {
        let mut value=EnrollmentSet::empty();
        let tenant=TenantName::parse(&tenant).unwrap();
        for (id,retired) in ids {
            let principal=PrincipalId::from_bytes(id);
            let digest=ClientSpkiDigest::from_bytes(*GrainId::of(&id).digest());
            value.mint(principal,tenant.clone(),digest).unwrap();
            if retired {value.revoke(&digest).unwrap();value.retire(&principal).unwrap();}
            else if attach {let digest=ClientSpkiDigest::from_bytes(*GrainId::of(&[id.as_slice(),&[1]].concat()).digest());value.attach(principal,digest).unwrap();}
        }
        let bytes=enrollment::encode_set(&value);
        prop_assert_eq!(enrollment::decode_set(bytes.as_bytes()),Ok(value));
        prop_assert_eq!(enrollment::encode_set(&enrollment::decode_set(bytes.as_bytes()).unwrap()),bytes);
    }
    #[test]
    fn debug_grant_round_trip(inc in any::<[u8;16]>(),seed in any::<[u8;16]>(),revision in 1..=u64::MAX,
        generation in any::<u64>(),branch in 0..3_u8,secs in -1_000_000_000_000_i64..1_000_000_000_000,
        nanos in 0..1_000_000_000_u32,duration in 1..=900_i64,uid in any::<u32>(),owner in "[!-~]{1,64}",reason in "[!-~]{1,64}",lines in 0..=1024_u64,bytecap in 0..=1_048_576_u64) {
        let value=DebugGrant::new(GrantFields{incarnation:Incarnation::from_bytes(inc),file_revision:revision,grant_generation:generation%revision+1,
            action:action(branch),issuer_uid:uid,owner:Owner::from_bytes(owner.as_bytes()).unwrap(),reason:Reason::from_bytes(reason.as_bytes()).unwrap(),
            issued_at:timestamp(secs,nanos),expires_at:timestamp(secs+duration,nanos),scope:scope(branch,PrincipalId::from_bytes(seed)),line_ceiling:lines,byte_ceiling:bytecap}).unwrap();
        let bytes=debug_grant::encode_grant(&value);
        prop_assert_eq!(debug_grant::decode_grant(bytes.as_bytes()),Ok(value));
        prop_assert_eq!(debug_grant::encode_grant(&debug_grant::decode_grant(bytes.as_bytes()).unwrap()),bytes);
    }
    #[test]
    fn support_configuration_round_trip(inc in any::<[u8;16]>(),values in any::<[u64;5]>(),names in prop::collection::btree_map("[a-z]{1,16}",1..=8_u8,1..5),optional in any::<bool>()) {
        let value=configuration(inc,values,names,optional);
        let bytes=value.encode().unwrap();
        prop_assert_eq!(SupportConfiguration::decode(&bytes),Ok(value));
        prop_assert_eq!(SupportConfiguration::decode(&bytes).unwrap().encode().unwrap(),bytes);
    }
    #[test]
    fn support_snapshot_round_trip(inc in any::<[u8;16]>(),seed in any::<[u8;32]>(),counts in any::<[u64;26]>(),branch in 0..12_u8,
        secs in -1_000_000_000_000_i64..1_000_000_000_000,nanos in 0..1_000_000_000_u32) {
        let value=snapshot(inc,seed,counts,branch,secs,nanos);
        let bytes=value.encode().unwrap();
        prop_assert_eq!(SupportSnapshot::decode(&bytes),Ok(value));
        prop_assert_eq!(SupportSnapshot::decode(&bytes).unwrap().encode().unwrap(),bytes);
    }
    #[test]
    fn support_manifest_and_archive_round_trip(inc in any::<[u8;16]>(),seed in any::<[u8;32]>(),counts in any::<[u64;26]>(),branch in 0..12_u8,
        secs in -1_000_000_000_000_i64..1_000_000_000_000,nanos in 0..1_000_000_000_u32,delta in -200..200_i64,expected in any::<bool>()) {
        let snapshot=snapshot(inc,seed,counts,branch,secs,nanos);
        let c=configuration(inc,[counts[0],counts[1],counts[2],counts[3],counts[4]],BTreeMap::from([("alpha".into(),1)]),expected);
        let members=BTreeMap::from([(b"snapshot.bin".to_vec(),snapshot.encode().unwrap()),(b"configuration.bin".to_vec(),c.encode().unwrap())]);
        let exported_at=timestamp(secs+delta,nanos);
        let sampled_at=timestamp(secs,nanos);
        let manifest=SupportManifest{exported_at,incarnation:Incarnation::from_bytes(inc),expected_incarnation:expected.then_some(Incarnation::from_bytes(inc)),sampled_at,
            age:SnapshotAge::between(exported_at,sampled_at).unwrap(),support_truncated:false,state_truncated:false,
            entries:vec![exported(SourceKind::Snapshot,b"SUPPORT-SNAPSHOT",b"snapshot.bin",&members[b"snapshot.bin".as_slice()]),exported(SourceKind::Configuration,b"SUPPORT-CONFIGURATION",b"configuration.bin",&members[b"configuration.bin".as_slice()]),ExportEntry{kind:SourceKind::Log,id:b"alpha".to_vec(),projection_version:1,cap:1024,status:EntryStatus::Refused(ExportRefusal::Missing)}]};
        let bytes=manifest.encode().unwrap();
        prop_assert_eq!(SupportManifest::decode(&bytes),Ok(manifest.clone()));
        prop_assert_eq!(SupportManifest::decode(&bytes).unwrap().encode().unwrap(),bytes);
        let archive=SupportArchive{manifest,members};
        let bytes=archive.encode().unwrap();
        prop_assert_eq!(SupportArchive::decode(&bytes),Ok(archive));
        prop_assert_eq!(SupportArchive::decode(&bytes).unwrap().encode().unwrap(),bytes);
    }
    #[test]
    fn support_bundle_version_and_configuration_round_trip(words in any::<[u32;4]>(),halves in any::<[u16;3]>(),os in 1..=3_u8,arch in 1..=3_u8,features in 0..8_u8,
        version_flags in any::<[bool;2]>(),flags in any::<[bool;17]>(),pins in any::<[u16;2]>(),threshold in 1..=0x3ff0_0000_0000_0000_u64,tags in (1..=2_u8,1..=2_u8,1..=2_u8,1..=2_u8,1..=5_u8)) {
        let version=BundleVersion{package_major:words[0],package_minor:words[1],package_patch:words[2],prerelease:version_flags[0],target_os:os,target_arch:arch,
            debug_assertions:version_flags[1],features,metrics_schema:halves[0].max(1),cache_marker_version:words[3].max(1),cache_index_version:halves[1].max(1),overlay_journal_version:halves[2].max(1)};
        let bytes=version.encode().unwrap();
        prop_assert_eq!(bytes.len(),27);
        prop_assert_eq!(BundleVersion::decode(&bytes),Ok(version));
        prop_assert_eq!(BundleVersion::decode(&bytes).unwrap().encode().unwrap(),bytes);
        let configuration=bundle_configuration(flags,pins,threshold,[tags.0,tags.1,tags.2,tags.3,tags.4]);
        let bytes=configuration.encode().unwrap();
        prop_assert_eq!(bytes.len(),34);
        prop_assert_eq!(BundleConfiguration::decode(&bytes),Ok(configuration));
        prop_assert_eq!(BundleConfiguration::decode(&bytes).unwrap().encode().unwrap(),bytes);
    }
    #[test]
    fn support_bundle_overlay_cache_and_failures_round_trip(counters in any::<[u64;12]>(),readiness in 1..=4_u8,commit_state in 0..=2_u8,requested in any::<bool>(),
        writer in any::<bool>(),failures in prop::collection::vec((1..=1000_u64,any::<bool>(),1..=BUNDLE_OPERATION_KINDS,1..=6_u8,prop::option::of(any::<[u8;8]>())),0..=64)) {
        let [namespace_entries,free_entries,cap,staged_files,journal_records,charged_bytes,reserved_bytes,orphan_bytes,captured_bytes,swept_files,swept_bytes,journal_bytes]=counters;
        let overlay=BundleOverlay{readiness,commit_state,namespace_entries,free_entries,cap,staged_files,journal_records,charged_bytes,reserved_bytes,orphan_bytes,captured_bytes,swept_files,swept_bytes,journal_bytes,commit_requested:requested};
        let bytes=overlay.encode().unwrap();
        prop_assert_eq!(bytes.len(),99);
        prop_assert_eq!(BundleOverlay::decode(&bytes),Ok(overlay));
        prop_assert_eq!(BundleOverlay::decode(&bytes).unwrap().encode().unwrap(),bytes);
        let cache=if writer {BundleCache::Writer{quota_bytes:counters[0],total_bytes:counters[1],live_objects:counters[2],journal_bytes:counters[3]}} else {BundleCache::ReadOnlyDegraded};
        let bytes=cache.encode().unwrap();
        prop_assert_eq!(bytes.len(),if writer {33} else {1});
        prop_assert_eq!(BundleCache::decode(&bytes),Ok(cache));
        prop_assert_eq!(BundleCache::decode(&bytes).unwrap().encode().unwrap(),bytes);
        let mut ordinal=0;
        let entries: Vec<BundleFailure>=failures.iter().map(|(step,first,kind,class,correlation)| {
            ordinal+=step;
            BundleFailure{ordinal,event:if *first {1} else {2},kind:if *first {*kind} else {0},class:*class,correlation:*correlation}
        }).collect();
        let failures=BundleFailures{entries};
        let bytes=failures.encode().unwrap();
        prop_assert_eq!(BundleFailures::decode(&bytes),Ok(failures));
        prop_assert_eq!(BundleFailures::decode(&bytes).unwrap().encode().unwrap(),bytes);
    }
    #[test]
    fn support_bundle_metrics_round_trip(words in prop::collection::vec(any::<u64>(),318),incarnation in any::<[u32;4]>(),available in any::<[bool;6]>(),contention in 0..=2_u8) {
        let metrics=bundle_metrics(&words,incarnation,available,contention);
        let bytes=metrics.encode().unwrap();
        prop_assert_eq!(bytes.len(),2577);
        prop_assert_eq!(BundleMetrics::decode(&bytes),Ok(metrics));
        prop_assert_eq!(BundleMetrics::decode(&bytes).unwrap().encode().unwrap(),bytes);
    }
    #[test]
    fn support_bundle_logs_round_trip(lost in any::<u64>(),picks in prop::collection::vec((0..148_usize,any::<u64>()),0..=24)) {
        let events: Vec<&str>=bundle_record_events().collect();
        prop_assert_eq!(events.len(),148);
        let records: Vec<String>=picks.iter().map(|(at,payload)| bundle_record(events[*at],*payload)).collect();
        let logs=BundleLogs{lost,records};
        let bytes=logs.encode().unwrap();
        prop_assert_eq!(BundleLogs::decode(&bytes),Ok(logs.clone()));
        prop_assert_eq!(logs.encode().unwrap(),bytes.clone());
        prop_assert_eq!(BundleLogs::decode(&bytes).unwrap().encode().unwrap(),bytes);
    }
    #[test]
    fn support_bundle_manifest_and_archive_round_trip(secs in any::<i64>(),nanos in 0..1_000_000_000_u32,include in any::<[bool;6]>(),
        cfg_unencodable in any::<bool>(),overlay_reason in 0..5_usize,cache_reason in 0..5_usize,writer in any::<bool>(),
        words in any::<[u64;16]>(),incarnation in any::<[u32;4]>(),available in any::<[bool;6]>(),contention in 0..=2_u8,
        flags in any::<[bool;17]>(),pins in any::<[u16;2]>()) {
        let five=[BundleRefusal::NotApplicable,BundleRefusal::Unavailable,BundleRefusal::Unreadable,BundleRefusal::Corrupt,BundleRefusal::TimedOut];
        let version=BundleVersion{package_major:1,package_minor:2,package_patch:3,prerelease:false,target_os:1,target_arch:2,debug_assertions:false,
            features:0,metrics_schema:if include[5] {BUNDLE_METRICS_SCHEMA} else {5},cache_marker_version:1,cache_index_version:1,overlay_journal_version:1}.encode().unwrap();
        let cfg=bundle_configuration(flags,pins,0.5_f64.to_bits(),[1,1,1,1,1]).encode().unwrap();
        let event=bundle_record_events().next().unwrap();
        let logs=BundleLogs{lost:words[0],records:vec![bundle_record(event,words[1])]}.encode().unwrap();
        let overlay=BundleOverlay{readiness:3,commit_state:0,namespace_entries:words[0],free_entries:words[1],cap:words[2],staged_files:words[3],
            journal_records:words[4],charged_bytes:words[5],reserved_bytes:words[6],orphan_bytes:words[7],captured_bytes:words[8],swept_files:words[9],
            swept_bytes:words[10],journal_bytes:words[11],commit_requested:false}.encode().unwrap();
        let cache=if writer {BundleCache::Writer{quota_bytes:words[0],total_bytes:words[1],live_objects:words[2],journal_bytes:words[3]}} else {BundleCache::ReadOnlyDegraded}.encode().unwrap();
        let failures=BundleFailures{entries:vec![]}.encode().unwrap();
        let metrics=bundle_metrics(&words,incarnation,available,contention).encode().unwrap();
        let mut entries=vec![bundle_exported(BundleKind::Version,&version)];
        let mut members=BTreeMap::from([(BundleKind::Version,version)]);
        for (idx,(kind,bytes)) in [(BundleKind::Configuration,cfg),(BundleKind::Logs,logs),(BundleKind::Overlay,overlay),(BundleKind::Cache,cache),(BundleKind::Failures,failures),(BundleKind::Metrics,metrics)].into_iter().enumerate() {
            if include[idx] {
                entries.push(bundle_exported(kind,&bytes));
                members.insert(kind,bytes);
            } else {
                let reason=match kind {
                    BundleKind::Configuration if cfg_unencodable => BundleRefusal::Unencodable,
                    BundleKind::Overlay => five[overlay_reason],
                    BundleKind::Cache => five[cache_reason],
                    _ => BundleRefusal::Unavailable,
                };
                entries.push(bundle_refused(kind,reason));
            }
        }
        let manifest=BundleManifest{bundled_at:timestamp(secs,nanos),entries};
        let bytes=manifest.encode().unwrap();
        prop_assert_eq!(BundleManifest::decode(&bytes),Ok(manifest.clone()));
        prop_assert_eq!(BundleManifest::decode(&bytes).unwrap().encode().unwrap(),bytes);
        let archive=BundleArchive{manifest,members};
        let bytes=archive.encode().unwrap();
        prop_assert_eq!(BundleArchive::decode(&bytes),Ok(archive));
        prop_assert_eq!(BundleArchive::decode(&bytes).unwrap().encode().unwrap(),bytes);
    }
    #[test]
    fn support_bundle_decoders_are_total_and_canonical(bytes in prop::collection::vec(any::<u8>(),0..300),flip in any::<prop::sample::Index>(),words in prop::collection::vec(any::<u64>(),318)) {
        granary_core::testkit::support_bundle_decode_probe(&bytes);
        let valid=bundle_metrics(&words,[1;4],[true;6],1).encode().unwrap();
        let mut flipped=valid.clone();
        let at=flip.index(flipped.len());
        flipped[at]^=0x55;
        granary_core::testkit::support_bundle_decode_probe(&flipped);
        granary_core::testkit::support_bundle_decode_probe(&valid[..at]);
    }
}
