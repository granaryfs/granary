// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
use super::{
    BUNDLE_ARCHIVE_DERIVED_MAX, BUNDLE_ARCHIVE_MAX, BUNDLE_MANIFEST_DERIVED_MAX,
    BUNDLE_MANIFEST_ENTRIES_MAX, BUNDLE_MANIFEST_MAX, BUNDLE_MEMBERS_MAX, BundleArchive,
    BundleEntry, BundleEntryStatus, BundleKind, BundleManifest, BundleRefusal,
    members::*,
    records::{self, bundle_record_events, bundle_record_keys},
};
use crate::{
    hash::GrainId,
    sheaf::Timestamp,
    support::{SupportArchive, SupportError, SupportManifest},
};
use std::collections::BTreeMap;

type Result<T> = std::result::Result<T, SupportError>;

/// An event's key set, collected for comparison.
fn keys_of(event: &str) -> Option<Vec<&'static str>> {
    bundle_record_keys(event).map(Iterator::collect)
}

#[test]
fn recovery_cli_and_event_contract_match_observed_completion() {
    let mut cases = 0;
    for (event, field, value) in [
        ("recover.journal_finished", "base_seq", "7"),
        ("recover.journal_blocked", "reason", "\"release\""),
    ] {
        let record = format!(
            "{{\"level\":\"INFO\",\"target\":\"granary_client::event\",\"event\":\"{event}\",\"{field}\":{value}}}\n"
        );
        let malformed = record.replace("}\n", ",\"unexpected\":true}\n");
        assert_eq!(
            (records::check(&record), records::check(&malformed)),
            (Ok(()), Err(SupportError("log record key"))),
            "cases={}, {record:?}",
            cases + 1
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn workspace_event_keys_are_closed() {
    let record = "{\"level\":\"WARN\",\"target\":\"granary_client::event\",\"event\":\"sync.workspace_exhausted\",\"reason\":\"SyncWorkspaceExhausted\",\"needed\":1073741825,\"limit\":1073741824}\n";
    let malformed = record.replace("}\n", ",\"path\":\"private\"}\n");
    assert_eq!(
        (
            records::check(record),
            records::check(&malformed),
            [record, &malformed].len()
        ),
        (Ok(()), Err(SupportError("log record key")), 2)
    );
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, b| {
        write!(&mut text, "{b:02x}").unwrap();
        text
    })
}
fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn rows(text: &'static str) -> impl Iterator<Item = Vec<&'static str>> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.split('\t').collect())
}

const KINDS: [&str; 9] = [
    "version",
    "configuration",
    "logs",
    "overlay",
    "cache",
    "failures",
    "metrics",
    "manifest",
    "archive",
];

/// Decode by object or member kind and re-encode: the codec's canonical round trip.
fn recode(kind: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    match kind {
        "version" => BundleVersion::decode(bytes)?.encode(),
        "configuration" => BundleConfiguration::decode(bytes)?.encode(),
        "logs" => BundleLogs::decode(bytes)?.encode(),
        "overlay" => BundleOverlay::decode(bytes)?.encode(),
        "cache" => BundleCache::decode(bytes)?.encode(),
        "failures" => BundleFailures::decode(bytes)?.encode(),
        "metrics" => BundleMetrics::decode(bytes)?.encode(),
        "manifest" => BundleManifest::decode(bytes)?.encode(),
        "archive" => BundleArchive::decode(bytes)?.encode(),
        other => panic!("no kind {other}"),
    }
}

const LOG_RECORDS: [&str; 6] = [
    "{\"level\":\"ERROR\",\"target\":\"granary_client::event\",\"event\":\"op.failed\",\"kind\":\"fsync\",\"class\":\"io\",\"spans\":[{\"name\":\"op\",\"op\":\"cor-2a2a2a2a2a2a2a2a\",\"kind\":\"commit\"}]}\n",
    "{\"level\":\"WARN\",\"event\":\"log.record_refused\",\"reason\":\"record_too_large\"}\n",
    "{\"event\":\"log.sink_loss\",\"telemetry_dropped\":0,\"protected_lost\":1,\"local_lost\":18446744073709551615}\n",
    "{\"event\":\"log.line\",\"message\":\"[gran log: cannot rotate the log file <log-file>; continuing in the current file]\",\"path\":\"<log-file>\",\"class\":\"io\"}\n",
    "{\"event\":\"log.line\",\"message\":\"say \\\"hi\\\" \\\\ \\u001b\",\"path\":\"<log-file>\",\"class\":\"io\"}\n",
    "{\"level\":\"WARN\",\"target\":\"granary_client::event\",\"event\":\"client.cache.insert.failed.to.write.the.object\",\"message\":\"cache insert failed to write the object\",\"id\":\"<id>\",\"error\":\"io\"}\n",
];

fn version() -> BundleVersion {
    BundleVersion {
        package_major: 1,
        package_minor: 2,
        package_patch: 3,
        prerelease: true,
        target_os: 2,
        target_arch: 1,
        debug_assertions: false,
        features: 5,
        metrics_schema: 0x0102,
        cache_marker_version: 0x0a0b_0c0d,
        cache_index_version: 0x0304,
        overlay_journal_version: 0x0506,
    }
}
fn configuration() -> BundleConfiguration {
    BundleConfiguration {
        mount_mode: 2,
        root_key_configured: true,
        manifest_root_pinned: false,
        trust_server: true,
        tls_pin_count: 3,
        cache_configured: true,
        seq_pinned: false,
        uid_override: true,
        gid_override: false,
        allow_other: true,
        foreground: false,
        reset_floor: true,
        force: false,
        key_seed_configured: true,
        store_dir_configured: false,
        contention_threshold_bits: 0.25_f64.to_bits(),
        certificate_configured: true,
        key_configured: false,
        credential_context_configured: true,
        publisher_key_count: 258,
        wire_snapshot_configured: true,
        log_format: 2,
        log_destination: 1,
        log_paths: 2,
        log_filter_source: 4,
    }
}
fn logs() -> BundleLogs {
    BundleLogs {
        lost: 0x0102_0304_0506_0708,
        records: LOG_RECORDS.map(str::to_owned).to_vec(),
    }
}
fn overlay() -> BundleOverlay {
    BundleOverlay {
        readiness: 3,
        commit_state: 2,
        namespace_entries: 11,
        free_entries: 12,
        cap: 13,
        staged_files: 14,
        journal_records: 15,
        charged_bytes: 16,
        reserved_bytes: 17,
        orphan_bytes: 18,
        captured_bytes: 19,
        swept_files: 20,
        swept_bytes: 21,
        journal_bytes: 22,
        commit_requested: true,
    }
}
fn writer() -> BundleCache {
    BundleCache::Writer {
        quota_bytes: 1000,
        total_bytes: 600,
        live_objects: 7,
        journal_bytes: 42,
    }
}
fn failures() -> BundleFailures {
    let entry = |ordinal, event, kind, class, correlation| BundleFailure {
        ordinal,
        event,
        kind,
        class,
        correlation,
    };
    BundleFailures {
        entries: vec![
            entry(1, 1, 9, 6, Some([1, 2, 3, 4, 5, 6, 7, 8])),
            entry(3, 1, 2, 1, None),
            entry(70_000, 2, 0, 3, Some([0xff; 8])),
        ],
    }
}
/// A running source of distinct values that also records the bytes each one
/// should occupy, in the order the document lists the fields.
struct Gen {
    next: u64,
    small: u32,
    bytes: Vec<u8>,
}
impl Gen {
    fn u64(&mut self) -> u64 {
        self.next += 0x0101;
        self.bytes.extend(self.next.to_be_bytes());
        self.next
    }
    fn u32(&mut self) -> u32 {
        self.small += 0x0102_0305;
        self.bytes.extend(self.small.to_be_bytes());
        self.small
    }
    fn words<const N: usize>(&mut self) -> [u64; N] {
        std::array::from_fn(|_| self.u64())
    }
    fn histograms<const N: usize>(&mut self) -> [BundleHistogram; N] {
        std::array::from_fn(|_| BundleHistogram {
            buckets: self.words::<12>(),
            sum: self.u64(),
        })
    }
}
/// A snapshot with a distinct value in every field, and its expected bytes.
fn metrics() -> (BundleMetrics, Vec<u8>) {
    let mut g = Gen {
        next: 0x0100_0000_0000_0000,
        small: 0,
        bytes: BUNDLE_METRICS_SCHEMA.to_be_bytes().to_vec(),
    };
    let incarnation = [g.u32(), g.u32(), g.u32(), g.u32()];
    let sequence = g.u64();
    let available = [true, false, true, true, false, true];
    g.bytes.extend(available.map(u8::from));
    let commits = g.words::<6>();
    let commit_duration = g.histograms::<6>();
    let retries = g.words::<3>();
    let conflicts = g.u64();
    g.bytes.push(1);
    let syncs = g.words::<4>();
    let fuse = std::array::from_fn(|_| g.words::<4>());
    let registrations = g.words::<4>();
    let registration_duration = g.histograms::<4>();
    let grains = g.u64();
    let uploads = g.words::<2>();
    let rechunks = g.u64();
    let cache = std::array::from_fn(|_| g.words::<2>());
    let transport = g.words::<2>();
    let value = BundleMetrics {
        incarnation,
        sequence,
        available,
        commits,
        commit_duration,
        retries,
        conflicts,
        contention: 1,
        syncs,
        fuse,
        registrations,
        registration_duration,
        grains,
        uploads,
        rechunks,
        cache,
        transport,
    };
    (value, g.bytes)
}
/// Every counter at the sentinel, the sequence at its last admitted value.
fn metrics_extremes() -> BundleMetrics {
    let full = BundleHistogram {
        buckets: [u64::MAX; 12],
        sum: u64::MAX,
    };
    BundleMetrics {
        incarnation: [u32::MAX; 4],
        sequence: u64::MAX - 1,
        available: [true; 6],
        commits: [u64::MAX; 6],
        commit_duration: [full; 6],
        retries: [u64::MAX; 3],
        conflicts: u64::MAX,
        contention: 2,
        syncs: [u64::MAX; 4],
        fuse: [[u64::MAX; 4]; 40],
        registrations: [u64::MAX; 4],
        registration_duration: [full; 4],
        grains: u64::MAX,
        uploads: [u64::MAX; 2],
        rechunks: u64::MAX,
        cache: [[u64::MAX; 2]; 2],
        transport: [u64::MAX; 2],
    }
}

fn exported(kind: BundleKind, bytes: &[u8]) -> BundleEntry {
    BundleEntry {
        kind,
        status: BundleEntryStatus::Exported {
            length: u32::try_from(bytes.len()).unwrap(),
            digest: *GrainId::of(bytes).digest(),
        },
    }
}
fn refused(kind: BundleKind, reason: BundleRefusal) -> BundleEntry {
    BundleEntry {
        kind,
        status: BundleEntryStatus::Refused(reason),
    }
}
fn archive_version() -> BundleVersion {
    BundleVersion {
        metrics_schema: BUNDLE_METRICS_SCHEMA,
        ..version()
    }
}
fn archive() -> BundleArchive {
    let items = [
        (BundleKind::Version, archive_version().encode().unwrap()),
        (BundleKind::Configuration, configuration().encode().unwrap()),
        (BundleKind::Logs, logs().encode().unwrap()),
        (BundleKind::Overlay, overlay().encode().unwrap()),
        (BundleKind::Cache, writer().encode().unwrap()),
        (BundleKind::Failures, failures().encode().unwrap()),
        (BundleKind::Metrics, metrics().0.encode().unwrap()),
    ];
    let entries = items
        .iter()
        .map(|(kind, bytes)| exported(*kind, bytes))
        .collect();
    let members = items.into_iter().collect();
    BundleArchive {
        manifest: BundleManifest {
            bundled_at: Timestamp {
                secs: 140,
                nanos: 3,
            },
            entries,
        },
        members,
    }
}
fn archive_refused() -> BundleArchive {
    let v = version().encode().unwrap();
    BundleArchive {
        manifest: BundleManifest {
            bundled_at: Timestamp {
                secs: 140,
                nanos: 3,
            },
            entries: vec![
                exported(BundleKind::Version, &v),
                refused(BundleKind::Configuration, BundleRefusal::Unencodable),
                refused(BundleKind::Logs, BundleRefusal::Unavailable),
                refused(BundleKind::Overlay, BundleRefusal::NotApplicable),
                refused(BundleKind::Cache, BundleRefusal::Unreadable),
                refused(BundleKind::Failures, BundleRefusal::Unavailable),
                refused(BundleKind::Metrics, BundleRefusal::Unavailable),
            ],
        },
        members: BTreeMap::from([(BundleKind::Version, v)]),
    }
}
fn independent_envelope(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = b"GRANARY\0".to_vec();
    bytes.extend(kind.to_be_bytes());
    bytes.extend(1_u16.to_be_bytes());
    bytes.extend(u32::try_from(body.len()).unwrap().to_be_bytes());
    bytes.extend(body);
    bytes.extend([1, 1]);
    let check = *GrainId::of(&bytes).digest();
    bytes.extend(check);
    bytes
}
fn independent_exported_entry(tag: u8, cap: u32, name: &[u8], member: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, 0, 1];
    out.extend(cap.to_be_bytes());
    out.push(1);
    out.push(u8::try_from(name.len()).unwrap());
    out.extend(name);
    out.extend(u32::try_from(member.len()).unwrap().to_be_bytes());
    out.extend([1, 1]);
    out.extend(GrainId::of(member).digest());
    out
}
fn independent_refused_entry(tag: u8, cap: u32, reason: u16) -> Vec<u8> {
    let mut out = vec![tag, 0, 1];
    out.extend(cap.to_be_bytes());
    out.push(2);
    out.extend(reason.to_be_bytes());
    out
}

/// The golden objects and members, by name, encoded from their values.
fn fixture(name: &str) -> Result<Vec<u8>> {
    match name {
        "version" => version().encode(),
        "configuration" => configuration().encode(),
        "logs" => logs().encode(),
        "logs-empty" => BundleLogs {
            lost: 0,
            records: Vec::new(),
        }
        .encode(),
        "overlay" => overlay().encode(),
        "cache-writer" => writer().encode(),
        "cache-degraded" => BundleCache::ReadOnlyDegraded.encode(),
        "failures" => failures().encode(),
        "failures-empty" => BundleFailures {
            entries: Vec::new(),
        }
        .encode(),
        "failures-kind-10" => BundleFailures {
            entries: vec![BundleFailure {
                ordinal: 1,
                event: 1,
                kind: 10,
                class: 1,
                correlation: None,
            }],
        }
        .encode(),
        "metrics" => metrics().0.encode(),
        "metrics-extremes" => metrics_extremes().encode(),
        "manifest" => archive().manifest.encode(),
        "archive" => archive().encode(),
        "archive-refused" => archive_refused().encode(),
        other => panic!("no fixture {other}"),
    }
}
fn independent_archive(manifest: &[u8], members: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let mut body = u32::try_from(manifest.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    body.extend(manifest);
    body.extend(u16::try_from(members.len()).unwrap().to_be_bytes());
    for (member_name, member_bytes) in members {
        body.push(u8::try_from(member_name.len()).unwrap());
        body.extend(*member_name);
        body.extend(u32::try_from(member_bytes.len()).unwrap().to_be_bytes());
        body.extend(member_bytes);
    }
    independent_envelope(0x0206, &body)
}
fn independent_manifest(entries: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut body = 140_i64.to_be_bytes().to_vec();
    body.extend(3_u32.to_be_bytes());
    body.extend(7_u16.to_be_bytes());
    for entry in entries {
        body.extend(entry);
    }
    independent_envelope(0x0205, &body)
}
/// The same bytes assembled from the document alone, never through the codec.
fn independent(name: &str) -> Vec<u8> {
    let words =
        |values: &[u64]| -> Vec<u8> { values.iter().flat_map(|v| v.to_be_bytes()).collect() };
    match name {
        "version" => vec![
            0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 1, 2, 1, 0, 5, 1, 2, 10, 11, 12, 13, 3, 4, 5, 6,
        ],
        "configuration" => [
            &[2, 1, 0, 1, 0, 3, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0][..],
            &[0x3f, 0xd0, 0, 0, 0, 0, 0, 0],
            &[1, 0, 1, 1, 2, 1, 2, 1, 2, 4],
        ]
        .concat(),
        "logs" => log_bytes(0x0102_0304_0506_0708, &LOG_RECORDS.map(str::as_bytes)),
        "logs-empty" => vec![0; 10],
        "overlay" => [&[3, 2][..], &words(&(11..=22).collect::<Vec<_>>()), &[1]].concat(),
        "cache-writer" => [&[1][..], &words(&[1000, 600, 7, 42])].concat(),
        "cache-degraded" => vec![2],
        "failures" => [
            &[0, 3][..],
            &words(&[1]),
            &[1, 9, 6, 1, 1, 2, 3, 4, 5, 6, 7, 8],
            &words(&[3]),
            &[1, 2, 1, 0],
            &words(&[70_000]),
            &[2, 0, 3, 1, 255, 255, 255, 255, 255, 255, 255, 255],
        ]
        .concat(),
        "failures-empty" => vec![0, 0],
        "failures-kind-10" => [&[0, 1][..], &words(&[1]), &[1, 10, 1, 0]].concat(),
        "metrics" => metrics().1,
        "metrics-extremes" => {
            let mut bytes = vec![0, 2];
            bytes.extend([0xff; 16]);
            bytes.extend((u64::MAX - 1).to_be_bytes());
            bytes.extend([1; 6]);
            bytes.extend([0xff; 8 * (6 + 6 * 13 + 3 + 1)]);
            bytes.push(2);
            bytes.extend([0xff; 8 * (4 + 160 + 4 + 4 * 13 + 1 + 2 + 1 + 4 + 2)]);
            bytes
        }
        "manifest" => {
            let mut v = independent("version");
            v[17] = 0;
            independent_manifest(
                [
                    (1, 64, b"version.bin".as_slice(), v),
                    (
                        2,
                        256,
                        b"configuration.bin".as_slice(),
                        independent("configuration"),
                    ),
                    (3, 1_114_112, b"logs.bin".as_slice(), independent("logs")),
                    (4, 256, b"overlay.bin".as_slice(), independent("overlay")),
                    (5, 64, b"cache.bin".as_slice(), independent("cache-writer")),
                    (6, 2048, b"failures.bin".as_slice(), independent("failures")),
                    (7, 4096, b"metrics.bin".as_slice(), independent("metrics")),
                ]
                .map(|(tag, cap, member, bytes)| {
                    independent_exported_entry(tag, cap, member, &bytes)
                }),
            )
        }
        "archive" => {
            let mut v = independent("version");
            v[17] = 0;
            independent_archive(
                &independent("manifest"),
                &[
                    (b"cache.bin", independent("cache-writer")),
                    (b"configuration.bin", independent("configuration")),
                    (b"failures.bin", independent("failures")),
                    (b"logs.bin", independent("logs")),
                    (b"metrics.bin", independent("metrics")),
                    (b"overlay.bin", independent("overlay")),
                    (b"version.bin", v),
                ],
            )
        }
        "archive-refused" => {
            let v = independent("version");
            let mut entries = vec![independent_exported_entry(1, 64, b"version.bin", &v)];
            entries.extend(
                [
                    (2, 256, 6),
                    (3, 1_114_112, 2),
                    (4, 256, 1),
                    (5, 64, 3),
                    (6, 2048, 2),
                    (7, 4096, 2),
                ]
                .map(|(tag, cap, reason)| independent_refused_entry(tag, cap, reason)),
            );
            independent_archive(&independent_manifest(entries), &[(b"version.bin", v)])
        }
        other => panic!("no independent bytes for {other}"),
    }
}
/// A logs member from its parts, written by hand.
fn log_bytes(lost: u64, records: &[&[u8]]) -> Vec<u8> {
    let mut bytes = lost.to_be_bytes().to_vec();
    bytes.extend(u16::try_from(records.len()).unwrap().to_be_bytes());
    for record in records {
        bytes.extend(u16::try_from(record.len()).unwrap().to_be_bytes());
        bytes.extend(*record);
    }
    bytes
}
/// A valid record of exactly `length` bytes (at least 34), newline included.
fn record_of(length: usize) -> String {
    let (head, tail) = ("{\"event\":\"log.line\",\"message\":\"", "\"}\n");
    format!(
        "{head}{}{tail}",
        "x".repeat(length - head.len() - tail.len())
    )
}
/// A record carrying every key of the event's set, and `extra` besides.
fn record_for(event: &str, extra: Option<&str>) -> String {
    let field = |key: &str| match key {
        "event" => format!("\"event\":\"{event}\""),
        "spans" => "\"spans\":[{\"name\":\"op\",\"op\":\"o\",\"kind\":\"k\"}]".to_owned(),
        key => format!("\"{key}\":\"v\""),
    };
    let mut fields: Vec<String> = keys_of(event).unwrap().into_iter().map(field).collect();
    fields.extend(extra.map(field));
    format!("{{{}}}\n", fields.join(","))
}

#[test]
fn bundle_member_goldens_are_canonical_and_pinned() {
    let mut seen = Vec::new();
    for row in rows(include_str!("../../../tests/vectors/support_bundle_v1.tsv")) {
        let (name, bytes) = (row[0], unhex(row[1]));
        let kind = name.split('-').next().unwrap();
        assert_eq!(
            fixture(name).as_deref(),
            Ok(bytes.as_slice()),
            "{name} golden"
        );
        assert_eq!(bytes, independent(name), "{name} independent bytes");
        assert_eq!(
            hex(GrainId::of(&bytes).digest()),
            row[2],
            "{name} member digest"
        );
        assert_eq!(recode(kind, &bytes), Ok(bytes.clone()), "{name} canonical");
        assert_eq!(fixture(name), fixture(name), "{name} deterministic");
        crate::testkit::support_bundle_decode_probe(&bytes);
        for i in 0..bytes.len() {
            assert!(recode(kind, &bytes[..i]).is_err(), "{name} truncation {i}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(recode(kind, &longer).is_err(), "{name} trailing byte");
        let mut refused = 0;
        for i in 0..bytes.len() {
            let mut flip = bytes.clone();
            flip[i] ^= 1;
            match recode(kind, &flip) {
                Ok(again) => assert!(again == flip, "{name} flip {i} not canonical"),
                Err(_) => refused += 1,
            }
        }
        assert!(refused > 0, "{name} refused no flip");
        if matches!(kind, "manifest" | "archive") {
            assert_eq!(refused, bytes.len(), "{name} raw flip is checksum refusal");
            let mut resigned_ok = 0;
            let mut resigned_reasons = std::collections::BTreeSet::new();
            for i in 0..bytes.len() - 32 {
                let mut flip = bytes.clone();
                flip[i] ^= 1;
                if kind == "archive" {
                    flip = crate::testkit::support_bundle_archive_recheck_input(&flip).unwrap();
                } else {
                    let tail = flip.len() - 32;
                    let sum = *GrainId::of(&flip[..tail]).digest();
                    flip[tail..].copy_from_slice(&sum);
                }
                match recode(kind, &flip) {
                    Ok(again) => {
                        assert_eq!(again, flip, "{name} resigned flip {i} not canonical");
                        resigned_ok += 1;
                    }
                    Err(SupportError(reason)) => {
                        resigned_reasons.insert(reason);
                    }
                }
            }
            if name == "archive" {
                assert!(
                    resigned_ok > 0,
                    "archive resigned flips reach valid member values; got resigned_ok={resigned_ok}, reasons={resigned_reasons:?}"
                );
                for expected in [
                    "projection version",
                    "build target arch",
                    "mount mode",
                    "log record syntax",
                    "overlay commit state",
                    "cache mode",
                    "failure order",
                    "metrics schema",
                    "archive metrics schema",
                ] {
                    assert!(
                        resigned_reasons.contains(expected),
                        "archive resigned flips missed {expected:?}; got {resigned_reasons:?}"
                    );
                }
            }
        }
        seen.push(name);
    }
    assert_eq!(seen.len(), 15, "every golden row ran: {seen:?}");
}

#[test]
fn bundle_member_rejects_carry_their_refusal_text() {
    let mut per_kind: BTreeMap<&str, usize> = BTreeMap::new();
    for row in rows(include_str!(
        "../../../tests/vectors/support_bundle_v1_rejects.tsv"
    )) {
        let (kind, name, text) = (row[0], row[1], row[3]);
        assert_eq!(
            recode(kind, &unhex(row[2])).map(|bytes| bytes.len()),
            Err(SupportError(text)),
            "reject {kind} {name}"
        );
        crate::testkit::support_bundle_decode_probe(&unhex(row[2]));
        *per_kind.entry(kind).or_default() += 1;
    }
    // The paired control: every kind has a valid golden and refusals of its own.
    for kind in KINDS {
        assert!(
            per_kind.get(kind).copied().unwrap_or(0) >= 4,
            "nonzero reject case count for {kind}: {per_kind:?}"
        );
        let golden = if kind == "cache" {
            "cache-writer"
        } else {
            kind
        };
        assert!(
            recode(kind, &fixture(golden).unwrap()).is_ok(),
            "{kind} valid"
        );
    }
    assert_eq!(
        per_kind.values().sum::<usize>(),
        include_str!("../../../tests/vectors/support_bundle_v1_rejects.tsv")
            .lines()
            .filter(|l| !l.starts_with('#'))
            .count()
    );
}

#[test]
fn bundle_configuration_threshold_admits_exactly_zero_exclusive_to_one() {
    let with = |bits: u64| BundleConfiguration {
        contention_threshold_bits: bits,
        ..configuration()
    };
    for bits in [
        1.0_f64.to_bits(),
        1,
        0.5_f64.to_bits(),
        f64::MIN_POSITIVE.to_bits(),
    ] {
        let bytes = with(bits).encode().unwrap();
        assert_eq!(
            BundleConfiguration::decode(&bytes),
            Ok(with(bits)),
            "{bits:#x}"
        );
    }
    for bits in [
        0,
        1.0_f64.to_bits() + 1,
        (-0.0_f64).to_bits(),
        f64::NAN.to_bits(),
        f64::INFINITY.to_bits(),
        (-0.5_f64).to_bits(),
    ] {
        assert_eq!(
            with(bits).encode(),
            Err(SupportError("contention threshold")),
            "{bits:#x}"
        );
    }
}

#[test]
fn bundle_member_caps_refuse_one_byte_past_their_bound() {
    let caps = [
        ("version", 64, "version"),
        ("configuration", 256, "configuration"),
        ("logs", 1_114_112, "logs"),
        ("overlay", 256, "overlay"),
        ("cache", 64, "cache-writer"),
        ("failures", 2048, "failures"),
        ("metrics", 4096, "metrics"),
    ];
    for (kind, cap, golden) in caps {
        let mut padded = fixture(golden).unwrap();
        padded.resize(cap, 0);
        assert_eq!(
            recode(kind, &padded),
            Err(SupportError("trailing support bytes")),
            "{kind} at its cap reaches the field walk"
        );
        padded.push(0);
        assert_eq!(
            recode(kind, &padded),
            Err(SupportError("support size bound")),
            "{kind} one byte past its cap"
        );
    }
    for (kind, cap, golden) in [
        ("manifest", 4096, "manifest"),
        ("archive", 2_097_152, "archive"),
    ] {
        let mut padded = fixture(golden).unwrap();
        padded.resize(cap, 0);
        assert_eq!(
            recode(kind, &padded),
            Err(SupportError("support checksum")),
            "{kind} at its cap reaches the envelope check"
        );
        padded.push(0);
        assert_eq!(
            recode(kind, &padded),
            Err(SupportError("support size bound")),
            "{kind} one byte past its cap"
        );
    }
    assert_eq!(
        [
            BUNDLE_VERSION_MAX,
            BUNDLE_CONFIGURATION_MAX,
            BUNDLE_OVERLAY_MAX,
            BUNDLE_CACHE_MAX,
            BUNDLE_LOGS_MAX,
            BUNDLE_FAILURES_MAX,
            BUNDLE_METRICS_MAX,
            BUNDLE_MANIFEST_MAX,
            BUNDLE_ARCHIVE_MAX,
            BUNDLE_MANIFEST_ENTRIES_MAX,
            BUNDLE_MEMBERS_MAX,
            BUNDLE_MANIFEST_DERIVED_MAX,
            BUNDLE_ARCHIVE_DERIVED_MAX,
        ],
        [
            64, 256, 256, 64, 1_114_112, 2048, 4096, 4096, 2_097_152, 7, 7, 512, 1_121_578
        ]
    );
}

#[test]
fn bundle_log_bounds_hold_on_both_sides() {
    let encode = |lost, records: Vec<String>| BundleLogs { lost, records }.encode();
    // The record-count bound: 1,024 records, which is also a total of exactly
    // 1,048,576 bytes.
    let full: Vec<String> = (0..1024).map(|_| record_of(1024)).collect();
    let bytes = encode(5, full.clone()).unwrap();
    assert_eq!(bytes.len(), 1_050_634);
    assert_eq!(
        bytes,
        log_bytes(5, &full.iter().map(String::as_bytes).collect::<Vec<_>>())
    );
    assert_eq!(
        BundleLogs::decode(&bytes),
        Ok(BundleLogs {
            lost: 5,
            records: full
        })
    );
    let over: Vec<String> = (0..1025).map(|_| record_of(64)).collect();
    assert_eq!(
        encode(0, over).map(|bytes| bytes.len()),
        Err(SupportError("support count bound"))
    );
    // The record-length bound: one record of exactly 32,768 bytes, and one of 32,769.
    let exact = record_of(32_768);
    let bytes = encode(0, vec![exact.clone()]).unwrap();
    assert_eq!(bytes.len(), 8 + 2 + 2 + 32_768);
    assert_eq!(BundleLogs::decode(&bytes).unwrap().records, [exact]);
    let large = record_of(32_769);
    assert_eq!(
        encode(0, vec![large.clone()]).map(|bytes| bytes.len()),
        Err(SupportError("support size bound"))
    );
    let mut wire = 0_u64.to_be_bytes().to_vec();
    wire.extend([0, 1, 0x80, 0x01]);
    wire.extend(large.as_bytes());
    assert_eq!(
        BundleLogs::decode(&wire).map(|logs| logs.records.len()),
        Err(SupportError("support size bound"))
    );
    // The total-bytes bound: 31 full records plus two more reach it, then pass it by one.
    let tail = |extra: usize| -> Vec<String> {
        let mut records: Vec<String> = (0..31).map(|_| record_of(32_768)).collect();
        records.extend([record_of(32_734 + extra), record_of(34)]);
        records
    };
    let at_bound = encode(0, tail(0)).unwrap();
    assert_eq!(at_bound.len(), 8 + 2 + 33 * 2 + 1_048_576);
    assert_eq!(BundleLogs::decode(&at_bound).unwrap().records.len(), 33);
    assert_eq!(
        encode(0, tail(1)).map(|bytes| bytes.len()),
        Err(SupportError("support size bound"))
    );
    let past = log_bytes(0, &tail(1).iter().map(String::as_bytes).collect::<Vec<_>>());
    assert_eq!(
        BundleLogs::decode(&past).map(|logs| logs.records.len()),
        Err(SupportError("support size bound"))
    );
}

#[test]
fn bundle_failure_count_bound_holds_on_both_sides() {
    let entry = |n: u64| BundleFailure {
        ordinal: n,
        event: 1,
        kind: 1,
        class: 1,
        correlation: None,
    };
    let at: Vec<_> = (1..=64).map(entry).collect();
    let bytes = BundleFailures {
        entries: at.clone(),
    }
    .encode()
    .unwrap();
    assert_eq!(bytes.len(), 2 + 64 * 12);
    assert_eq!(
        BundleFailures::decode(&bytes),
        Ok(BundleFailures { entries: at })
    );
    let over: Vec<_> = (1..=65).map(entry).collect();
    assert_eq!(
        BundleFailures { entries: over }.encode(),
        Err(SupportError("support count bound"))
    );
    assert_eq!(
        BundleFailures::decode(&[0, 65]),
        Err(SupportError("support count bound"))
    );
}

/// A declared count or length over its bound refuses with the bound's text,
/// not with the truncation a read-then-check order would report.
#[test]
fn bundle_declared_sizes_are_checked_before_any_read() {
    assert_eq!(
        BundleLogs::decode(&[0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]),
        Err(SupportError("support count bound"))
    );
    assert_eq!(
        BundleFailures::decode(&[0xff, 0xff]),
        Err(SupportError("support count bound"))
    );
    assert_eq!(
        BundleLogs::decode(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xff]),
        Err(SupportError("support size bound"))
    );
    assert_eq!(
        BundleLogs::decode(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x80, 0x01]),
        Err(SupportError("support size bound"))
    );
    assert_eq!(
        BundleLogs::decode(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00, 0x40]),
        Err(SupportError("truncated support field")),
        "an admitted length that the input cannot supply still reports the truncation"
    );
    assert_eq!(
        BundleManifest::decode(&independent_envelope(
            0x0205,
            &[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 8]
        )),
        Err(SupportError("support count bound"))
    );
    assert_eq!(
        BundleArchive::decode(&independent_envelope(0x0206, &[0, 0, 0x10, 0x01])),
        Err(SupportError("support size bound"))
    );
    let manifest_bytes = fixture("manifest").unwrap();
    let mut over_members = Vec::new();
    over_members.extend(u32::try_from(manifest_bytes.len()).unwrap().to_be_bytes());
    over_members.extend(&manifest_bytes);
    over_members.extend([0, 8]);
    assert_eq!(
        BundleArchive::decode(&independent_envelope(0x0206, &over_members)),
        Err(SupportError("support count bound"))
    );
    let mut over_member_len = Vec::new();
    over_member_len.extend(u32::try_from(manifest_bytes.len()).unwrap().to_be_bytes());
    over_member_len.extend(&manifest_bytes);
    over_member_len.extend([0, u8::try_from(BUNDLE_MEMBERS_MAX).unwrap(), 9]);
    over_member_len.extend(b"cache.bin");
    over_member_len.extend(65_u32.to_be_bytes());
    assert_eq!(
        BundleArchive::decode(&independent_envelope(0x0206, &over_member_len)),
        Err(SupportError("archive member length"))
    );
    let mut short_member = Vec::new();
    short_member.extend(u32::try_from(manifest_bytes.len()).unwrap().to_be_bytes());
    short_member.extend(&manifest_bytes);
    short_member.extend([0, u8::try_from(BUNDLE_MEMBERS_MAX).unwrap(), 9]);
    short_member.extend(b"cache.bin");
    short_member.extend(33_u32.to_be_bytes());
    assert_eq!(
        BundleArchive::decode(&independent_envelope(0x0206, &short_member)),
        Err(SupportError("truncated support field"))
    );
}

#[test]
fn bundle_manifest_and_archive_bounds_and_determinism() {
    let valid_manifest = archive().manifest;
    assert_eq!(valid_manifest.entries.len(), BUNDLE_MANIFEST_ENTRIES_MAX);
    assert!(valid_manifest.encode().unwrap().len() <= BUNDLE_MANIFEST_DERIVED_MAX);
    let mut eight_entries = valid_manifest.clone();
    eight_entries
        .entries
        .push(exported(BundleKind::Metrics, &fixture("metrics").unwrap()));
    assert_eq!(
        eight_entries.encode(),
        Err(SupportError("support count bound"))
    );
    let mut six_entries = valid_manifest.clone();
    six_entries.entries.pop();
    assert_eq!(
        six_entries.encode(),
        Err(SupportError("manifest entry count"))
    );
    let reasons = [
        (BundleRefusal::NotApplicable, "not-applicable"),
        (BundleRefusal::Unavailable, "unavailable"),
        (BundleRefusal::Unreadable, "unreadable"),
        (BundleRefusal::Corrupt, "corrupt"),
        (BundleRefusal::TimedOut, "timed-out"),
        (BundleRefusal::Unencodable, "unencodable"),
    ];
    for (reason, text) in reasons {
        assert_eq!(reason.to_string(), text);
    }
    let kinds = [
        BundleKind::Version,
        BundleKind::Configuration,
        BundleKind::Logs,
        BundleKind::Overlay,
        BundleKind::Cache,
        BundleKind::Failures,
        BundleKind::Metrics,
    ];
    let refusal_table = [
        [false, false, false, false, false, false],
        [false, true, false, false, false, true],
        [false, true, false, false, false, false],
        [true, true, true, true, true, false],
        [true, true, true, true, true, false],
        [false, true, false, false, false, false],
        [false, true, false, false, false, false],
    ];
    for (idx, (&kind, &row)) in kinds.iter().zip(&refusal_table).enumerate() {
        for (&(reason, _), allowed) in reasons.iter().zip(row) {
            let mut candidate = valid_manifest.clone();
            candidate.entries[idx] = refused(kind, reason);
            if allowed {
                let bytes = candidate.encode().unwrap();
                assert_eq!(BundleManifest::decode(&bytes), Ok(candidate));
            } else {
                assert_eq!(
                    candidate.encode(),
                    Err(SupportError("member refusal")),
                    "{kind:?} {reason:?}"
                );
            }
        }
    }
    let forward = archive();
    let forward_bytes = forward.encode().unwrap();
    assert!(forward_bytes.len() <= BUNDLE_ARCHIVE_DERIVED_MAX);
    assert_eq!(forward_bytes, forward.encode().unwrap());
    let mut extra_member = archive_refused();
    extra_member
        .members
        .insert(BundleKind::Cache, writer().encode().unwrap());
    assert_eq!(
        extra_member.encode(),
        Err(SupportError("archive member count"))
    );
    let mut oversize_member = archive_refused();
    oversize_member
        .members
        .insert(BundleKind::Version, vec![0; BUNDLE_ARCHIVE_MAX]);
    assert_eq!(
        oversize_member.encode(),
        Err(SupportError("archive member length"))
    );
    assert_eq!(
        crate::testkit::support_bundle_archive_recheck_input(&[0; 49]),
        None
    );
    assert_eq!(
        crate::testkit::support_bundle_archive_recheck_input(&vec![0; BUNDLE_ARCHIVE_MAX + 1]),
        None
    );
    assert_eq!(
        SupportManifest::decode(&fixture("manifest").unwrap()),
        Err(SupportError("support object kind"))
    );
    assert_eq!(
        SupportArchive::decode(&forward_bytes),
        Err(SupportError("support object kind"))
    );
}

#[test]
fn bundle_record_key_sets_are_closed_per_event() {
    assert_eq!(
        keys_of("op.failed"),
        Some(vec!["level", "target", "event", "spans", "kind", "class"])
    );
    assert_eq!(
        keys_of("log.record_refused"),
        Some(vec!["level", "event", "reason"])
    );
    assert_eq!(
        keys_of("commit.stopped"),
        Some(vec!["level", "target", "event", "spans", "cause"])
    );
    assert_eq!(keys_of("op.nope"), None);
    let events: Vec<&str> = bundle_record_events().collect();
    assert_eq!(events.len(), 148);
    let mut every_key: Vec<&str> = events.iter().flat_map(|e| keys_of(e).unwrap()).collect();
    every_key.sort_unstable();
    every_key.dedup();
    let (mut accepted, mut refused) = (0, 0);
    for event in &events {
        // The event's own set is admitted whole, in a record that is otherwise valid.
        assert_eq!(records::check(&record_for(event, None)), Ok(()), "{event}");
        accepted += 1;
        // Any key the table knows under another event is refused here: the
        // union of every set would admit it.
        for key in &every_key {
            if !keys_of(event).unwrap().contains(key) {
                assert_eq!(
                    records::check(&record_for(event, Some(key))),
                    Err(SupportError("log record key")),
                    "{key} under {event}"
                );
                refused += 1;
            }
        }
    }
    assert!(accepted == 148 && refused > 6000, "{accepted} {refused}");
}

/// The escapes admitted are exactly the ones the client's encoder writes: the
/// two quote escapes, and `\u` with four lowercase hex digits for a control
/// character. A scanner that took any four hex digits fails on the surrogates
/// and the printable characters; one that took uppercase fails on the letters.
#[test]
fn bundle_record_strings_admit_exactly_the_encoders_escapes() {
    let record = |escape: &str| format!("{{\"event\":\"log.line\",\"message\":\"{escape}\"}}\n");
    let syntax = Err(SupportError("log record syntax"));
    let (mut admitted, mut refused) = (0, 0);
    for code in 0..=0xffff_u32 {
        let encoded = char::from_u32(code).is_some_and(char::is_control);
        let result = records::check(&record(&format!("\\u{code:04x}")));
        assert_eq!(result.is_ok(), encoded, "\\u{code:04x}");
        if encoded {
            admitted += 1;
        } else {
            assert_eq!(result, syntax, "\\u{code:04x}");
            refused += 1;
        }
    }
    assert_eq!((admitted, refused), (65, 65_536 - 65));
    let upper = (0..=0xffff_u32)
        .filter(|code| char::from_u32(*code).is_some_and(char::is_control))
        .filter(|code| format!("{code:04x}") != format!("{code:04X}"))
        .inspect(|code| {
            assert_eq!(
                records::check(&record(&format!("\\u{code:04X}"))),
                syntax,
                "\\u{code:04X}"
            );
        })
        .count();
    assert!(upper > 0, "no control character spells a hex letter");
    let others = (0..128_u8).map(char::from);
    for ch in others.filter(|c| !c.is_control() && !"\"\\u".contains(*c)) {
        assert_eq!(
            records::check(&record(&format!("\\{ch}"))),
            syntax,
            "{ch:?}"
        );
    }
    assert_eq!(records::check(&record("a\\\"b\\\\c")), Ok(()));
}

/// An unsigned decimal is admitted only if it is canonical and fits a u64.
#[test]
fn bundle_record_decimals_are_canonical_u64() {
    let record = |n: &str| format!("{{\"event\":\"log.sink_loss\",\"local_lost\":{n}}}\n");
    for ok in ["0", "7", "10", "18446744073709551615"] {
        assert_eq!(records::check(&record(ok)), Ok(()), "{ok}");
    }
    for bad in [
        "18446744073709551616",
        "99999999999999999999",
        "100000000000000000000",
        "00",
        "01",
    ] {
        assert_eq!(
            records::check(&record(bad)),
            Err(SupportError("log record syntax")),
            "{bad}"
        );
    }
}

/// The first ordinal is any value from 1: a gap before it means eviction.
#[test]
fn bundle_failure_ordinals_start_anywhere_from_one() {
    let entry = |ordinal| BundleFailure {
        ordinal,
        event: 2,
        kind: 0,
        class: 1,
        correlation: None,
    };
    let from = BundleFailures {
        entries: vec![entry(7), entry(8)],
    };
    assert_eq!(BundleFailures::decode(&from.encode().unwrap()), Ok(from));
    let zero = BundleFailures {
        entries: vec![entry(0)],
    };
    assert_eq!(zero.encode(), Err(SupportError("failure order")));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one sweep builds every member kind from the same generator"
)]
fn bundle_member_round_trips_over_seeded_values() {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let events: Vec<&str> = bundle_record_events().collect();
    for round in 0..96_u64 {
        let tag = |n: u64, top: u64| u8::try_from(n % top).unwrap();
        let version = BundleVersion {
            package_major: u32::try_from(next() >> 32).unwrap(),
            package_minor: u32::try_from(next() >> 32).unwrap(),
            package_patch: u32::try_from(next() >> 32).unwrap(),
            prerelease: next() & 1 == 1,
            target_os: 1 + tag(next(), 3),
            target_arch: 1 + tag(next(), 3),
            debug_assertions: next() & 1 == 1,
            features: tag(next(), 8),
            metrics_schema: u16::try_from(1 + next() % 65_535).unwrap(),
            cache_marker_version: u32::try_from(1 + next() % 0xffff_ffff).unwrap(),
            cache_index_version: u16::try_from(1 + next() % 65_535).unwrap(),
            overlay_journal_version: u16::try_from(1 + next() % 65_535).unwrap(),
        };
        let configuration = BundleConfiguration {
            mount_mode: 1 + tag(next(), 2),
            tls_pin_count: u16::try_from(next() % 65_536).unwrap(),
            publisher_key_count: u16::try_from(next() % 65_536).unwrap(),
            contention_threshold_bits: f64::from(u16::try_from(1 + next() % 1000).unwrap())
                .recip()
                .to_bits(),
            log_format: 1 + tag(next(), 2),
            log_destination: 1 + tag(next(), 2),
            log_paths: 1 + tag(next(), 2),
            log_filter_source: 1 + tag(next(), 5),
            force: next() & 1 == 1,
            ..configuration()
        };
        let overlay = BundleOverlay {
            readiness: 1 + tag(next(), 4),
            commit_state: tag(next(), 3),
            namespace_entries: next(),
            journal_bytes: next(),
            commit_requested: next() & 1 == 1,
            ..overlay()
        };
        let cache = if next() & 1 == 1 {
            BundleCache::Writer {
                quota_bytes: next(),
                total_bytes: next(),
                live_objects: next(),
                journal_bytes: next(),
            }
        } else {
            BundleCache::ReadOnlyDegraded
        };
        let mut ordinal = 0;
        let entries = (0..next() % 65)
            .map(|_| {
                ordinal += 1 + next() % 1000;
                let first = next() & 1 == 1;
                BundleFailure {
                    ordinal,
                    event: if first { 1 } else { 2 },
                    kind: if first { 1 + tag(next(), 9) } else { 0 },
                    class: 1 + tag(next(), 6),
                    correlation: (next() & 1 == 1).then(|| next().to_be_bytes()),
                }
            })
            .collect();
        let failures = BundleFailures { entries };
        let records = (0..next() % 9)
            .map(|_| {
                let event = events[usize::try_from(next() % 120).unwrap()];
                record_for(event, None)
            })
            .collect();
        let logs = BundleLogs {
            lost: next(),
            records,
        };
        let mut metrics = metrics().0;
        metrics.sequence = 1 + next() % (u64::MAX - 1);
        metrics.commits = [next(); 6];
        metrics.fuse = [[next(); 4]; 40];
        metrics.contention = tag(next(), 3);
        for (kind, bytes) in [
            ("version", version.encode()),
            ("configuration", configuration.encode()),
            ("overlay", overlay.encode()),
            ("cache", cache.encode()),
            ("failures", failures.encode()),
            ("logs", logs.encode()),
            ("metrics", metrics.encode()),
        ] {
            let bytes = bytes.unwrap();
            assert_eq!(
                recode(kind, &bytes),
                Ok(bytes.clone()),
                "{kind} round {round}"
            );
            crate::testkit::support_bundle_decode_probe(&bytes);
            crate::testkit::support_bundle_decode_probe(&crate::testkit::fill(
                round,
                bytes.len() / 3,
            ));
        }
        assert_eq!(
            BundleVersion::decode(&version.encode().unwrap()),
            Ok(version)
        );
        assert_eq!(
            BundleLogs::decode(&logs.encode().unwrap()),
            Ok(logs.clone())
        );
        assert_eq!(logs.encode(), logs.encode(), "encoding is deterministic");
        let export_metrics = next() & 1 == 1;
        let archive_version = BundleVersion {
            metrics_schema: if export_metrics {
                BUNDLE_METRICS_SCHEMA
            } else {
                version.metrics_schema
            },
            ..version
        }
        .encode()
        .unwrap();
        let five_reasons = [
            BundleRefusal::NotApplicable,
            BundleRefusal::Unavailable,
            BundleRefusal::Unreadable,
            BundleRefusal::Corrupt,
            BundleRefusal::TimedOut,
        ];
        let mut manifest_entries = vec![exported(BundleKind::Version, &archive_version)];
        let mut archive_members = BTreeMap::from([(BundleKind::Version, archive_version)]);
        for (kind, include, member_bytes) in [
            (
                BundleKind::Configuration,
                next() & 1 == 1,
                configuration.encode().unwrap(),
            ),
            (BundleKind::Logs, next() & 1 == 1, logs.encode().unwrap()),
            (
                BundleKind::Overlay,
                next() & 1 == 1,
                overlay.encode().unwrap(),
            ),
            (BundleKind::Cache, next() & 1 == 1, cache.encode().unwrap()),
            (
                BundleKind::Failures,
                next() & 1 == 1,
                failures.encode().unwrap(),
            ),
            (
                BundleKind::Metrics,
                export_metrics,
                metrics.encode().unwrap(),
            ),
        ] {
            if include {
                manifest_entries.push(exported(kind, &member_bytes));
                archive_members.insert(kind, member_bytes);
            } else {
                let reason = match kind {
                    BundleKind::Configuration if next() & 1 == 1 => BundleRefusal::Unencodable,
                    BundleKind::Overlay | BundleKind::Cache => {
                        five_reasons[usize::try_from(next() % 5).unwrap()]
                    }
                    _ => BundleRefusal::Unavailable,
                };
                manifest_entries.push(refused(kind, reason));
            }
        }
        let manifest = BundleManifest {
            bundled_at: Timestamp {
                secs: i64::try_from(next() >> 1).unwrap(),
                nanos: u32::try_from(next() % 1_000_000_000).unwrap(),
            },
            entries: manifest_entries,
        };
        let manifest_bytes = manifest.encode().unwrap();
        assert_eq!(
            BundleManifest::decode(&manifest_bytes),
            Ok(manifest.clone())
        );
        assert_eq!(
            recode("manifest", &manifest_bytes),
            Ok(manifest_bytes.clone())
        );
        crate::testkit::support_bundle_decode_probe(&manifest_bytes);
        let bundle = BundleArchive {
            manifest,
            members: archive_members,
        };
        let bundle_bytes = bundle.encode().unwrap();
        assert_eq!(BundleArchive::decode(&bundle_bytes), Ok(bundle));
        assert_eq!(recode("archive", &bundle_bytes), Ok(bundle_bytes.clone()));
        crate::testkit::support_bundle_decode_probe(&bundle_bytes);
    }
}

#[test]
fn bundle_archive_recheck_repairs_flipped_golden_archive() {
    let valid_manifest = archive().manifest;
    for (idx, bad_len) in [
        (0, 26),
        (0, 28),
        (1, 33),
        (1, 35),
        (3, 98),
        (3, 100),
        (4, 2),
        (4, 32),
        (4, 34),
        (6, 2576),
        (6, 2578),
    ] {
        let mut bad_manifest = valid_manifest.clone();
        let BundleEntryStatus::Exported { digest, .. } = bad_manifest.entries[idx].status else {
            panic!("exported entry");
        };
        bad_manifest.entries[idx].status = BundleEntryStatus::Exported {
            length: bad_len,
            digest,
        };
        assert_eq!(
            bad_manifest.encode().map(|_| ()),
            Err(SupportError("member length")),
            "entry {idx} length {bad_len}"
        );
    }
    for name in ["archive", "archive-refused"] {
        let golden = fixture(name).unwrap();
        let original = BundleArchive::decode(&golden).unwrap();
        let flip_idx = golden.len() - crate::support::TRAILER_LEN - 1;
        let mut flipped = golden.clone();
        flipped[flip_idx] ^= 0x01;
        let repaired = crate::testkit::support_bundle_archive_recheck_input(&flipped).unwrap();
        let decoded = BundleArchive::decode(&repaired).unwrap();
        assert_eq!(
            (
                BundleArchive::decode(&flipped),
                decoded.members[&BundleKind::Version] != original.members[&BundleKind::Version],
                decoded.encode().as_ref()
            ),
            (Err(SupportError("support checksum")), true, Ok(&repaired)),
            "{name} flip repair"
        );
    }
}
