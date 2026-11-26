// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
use super::*;
fn required(kind: SourceKind, id: &[u8], name: &[u8], bytes: &[u8]) -> ExportEntry {
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
fn fixture() -> SupportArchive {
    let members = BTreeMap::from([
        (
            b"configuration.bin".to_vec(),
            b"configuration bytes".to_vec(),
        ),
        (b"snapshot.bin".to_vec(), b"snapshot bytes".to_vec()),
    ]);
    let exported_at = Timestamp {
        secs: 140,
        nanos: 3,
    };
    let sampled_at = Timestamp { secs: 20, nanos: 2 };
    SupportArchive {
        manifest: SupportManifest {
            exported_at,
            incarnation: Incarnation::from_bytes([65; 16]),
            expected_incarnation: Some(Incarnation::from_bytes([65; 16])),
            sampled_at,
            age: SnapshotAge::between(exported_at, sampled_at).unwrap(),
            support_truncated: false,
            state_truncated: false,
            entries: vec![
                required(
                    SourceKind::Snapshot,
                    b"SUPPORT-SNAPSHOT",
                    b"snapshot.bin",
                    &members[b"snapshot.bin".as_slice()],
                ),
                required(
                    SourceKind::Configuration,
                    b"SUPPORT-CONFIGURATION",
                    b"configuration.bin",
                    &members[b"configuration.bin".as_slice()],
                ),
                ExportEntry {
                    kind: SourceKind::Log,
                    id: b"alpha".to_vec(),
                    projection_version: 1,
                    cap: 1024,
                    status: EntryStatus::Refused(ExportRefusal::Missing),
                },
                ExportEntry {
                    kind: SourceKind::UnknownSupport,
                    id: b"unknown-0000".to_vec(),
                    projection_version: 1,
                    cap: 0,
                    status: EntryStatus::Refused(ExportRefusal::NotAllowlisted),
                },
            ],
        },
        members,
    }
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
fn decode(kind: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    if kind == "manifest" {
        SupportManifest::decode(bytes)?.encode()
    } else {
        SupportArchive::decode(bytes)?.encode()
    }
}
#[test]
fn support_formats_canonical_and_verified() {
    let a = fixture();
    for (kind, bytes) in [
        ("manifest", a.manifest.encode().unwrap()),
        ("archive", a.encode().unwrap()),
    ] {
        let row = include_str!("../../../tests/vectors/support_v1_export.tsv")
            .lines()
            .filter(|l| !l.starts_with('#'))
            .find(|l| l.split('\t').next() == Some(kind))
            .unwrap();
        let parts: Vec<_> = row.split('\t').collect();
        assert_eq!(
            (hex(&bytes), hex(&bytes[bytes.len() - 32..])),
            (parts[1].into(), parts[2].into()),
            "{kind} golden"
        );
        assert_eq!(decode(kind, &bytes), Ok(bytes.clone()));
        for i in 0..bytes.len() {
            assert!(decode(kind, &bytes[..i]).is_err(), "{kind} truncation {i}");
            let mut flip = bytes.clone();
            flip[i] ^= 1;
            assert!(decode(kind, &flip).is_err(), "{kind} exact byte flip {i}");
        }
    }
    let mut count = 0;
    for row in include_str!("../../../tests/vectors/support_v1_export_rejects.tsv")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let parts: Vec<_> = row.split('\t').collect();
        assert_eq!(
            decode(parts[0], &unhex(parts[2])).unwrap_err().to_string(),
            parts[3],
            "reject {}",
            parts[1]
        );
        count += 1;
    }
    assert!(count >= 24, "nonzero reject case count: {count}");
}
#[test]
fn support_export_entry_and_byte_caps() {
    assert_eq!(
        (MANIFEST_ENTRIES_MAX, MANIFEST_DERIVED_MAX),
        (2116, 541_952)
    );
    let mut a = fixture();
    a.manifest.entries.truncate(2);
    for n in 0..64 {
        a.manifest.entries.push(ExportEntry {
            kind: SourceKind::Log,
            id: format!("v{n:02}").into_bytes(),
            projection_version: 1,
            cap: 1024,
            status: EntryStatus::Refused(ExportRefusal::Missing),
        });
    }
    for kind in [SourceKind::UnknownSupport, SourceKind::UnknownState] {
        for n in 0..1024 {
            a.manifest.entries.push(ExportEntry {
                kind,
                id: format!("unknown-{n:04}").into_bytes(),
                projection_version: 1,
                cap: 0,
                status: EntryStatus::Refused(ExportRefusal::NotAllowlisted),
            });
        }
    }
    for kind in [SourceKind::SupportSummary, SourceKind::StateSummary] {
        a.manifest.entries.push(ExportEntry {
            kind,
            id: b"inventory".to_vec(),
            projection_version: 1,
            cap: 0,
            status: EntryStatus::Refused(ExportRefusal::ScanLimit),
        });
    }
    a.manifest.support_truncated = true;
    a.manifest.state_truncated = true;
    let bytes = a.manifest.encode().unwrap();
    assert_eq!(
        (a.manifest.entries.len(), bytes.len() <= 541_952),
        (2116, true)
    );
    assert_eq!(SupportManifest::decode(&bytes), Ok(a.manifest.clone()));
    a.manifest.entries.push(a.manifest.entries[0].clone());
    assert_eq!(
        a.manifest.encode(),
        Err(SupportError("support count bound"))
    );
    assert_eq!(
        SupportManifest::decode(&vec![0; 1_048_577]),
        Err(SupportError("support size bound"))
    );
    assert_eq!(
        SupportArchive::decode(&vec![0; 16_777_217]),
        Err(SupportError("support size bound"))
    );
}
#[test]
fn support_export_properties() {
    for seed in 0..128_u64 {
        let mut a = fixture();
        a.manifest.exported_at = Timestamp {
            secs: i64::try_from(seed).unwrap() - 32,
            nanos: u32::try_from(seed).unwrap(),
        };
        a.manifest.age =
            SnapshotAge::between(a.manifest.exported_at, a.manifest.sampled_at).unwrap();
        a.manifest.expected_incarnation = if seed.is_multiple_of(2) {
            None
        } else {
            Some(a.manifest.incarnation)
        };
        let bytes = crate::testkit::fill(seed, usize::try_from(seed).unwrap() + 1);
        a.members.insert(b"snapshot.bin".to_vec(), bytes.clone());
        a.manifest.entries[0] = required(
            SourceKind::Snapshot,
            b"SUPPORT-SNAPSHOT",
            b"snapshot.bin",
            &bytes,
        );
        let manifest = a.manifest.encode().unwrap();
        assert_eq!(SupportManifest::decode(&manifest), Ok(a.manifest.clone()));
        let archive = a.encode().unwrap();
        assert_eq!(SupportArchive::decode(&archive), Ok(a));
        crate::testkit::support_manifest_decode_probe(&manifest);
        crate::testkit::support_archive_decode_probe(&archive);
        let random = crate::testkit::fill(seed, usize::try_from(seed).unwrap() * 13);
        crate::testkit::support_manifest_decode_probe(&random);
        crate::testkit::support_archive_decode_probe(&random);
    }
}
#[test]
fn support_log_metadata_projection() {
    let m = SupportLogMetadata {
        volume: VolumeName::new("alpha".into()).unwrap(),
        envelope_version: 1,
        epoch: Epoch::from_bytes([7; 16]),
        size: u64::MAX,
        uid: 123,
        gid: 456,
        permissions: 0o640,
        mtime: Timestamp {
            secs: -1,
            nanos: 999_999_999,
        },
        ctime: Timestamp { secs: 1, nanos: 3 },
    };
    let bytes = m.encode().unwrap();
    assert_eq!(
        bytes,
        include_bytes!("../../../tests/vectors/support-log-metadata.bin")
    );
    assert_eq!(SupportLogMetadata::decode(&bytes), Ok(m.clone()));
    for i in 0..bytes.len() {
        assert!(SupportLogMetadata::decode(&bytes[..i]).is_err());
    }
    let mut bad = m.clone();
    bad.mtime.nanos = 1_000_000_000;
    assert_eq!(bad.encode(), Err(SupportError("timestamp nanoseconds")));
    bad = m.clone();
    bad.permissions = 4096;
    assert_eq!(bad.encode(), Err(SupportError("log permissions")));
    bad = m;
    bad.envelope_version = 2;
    assert_eq!(bad.encode(), Err(SupportError("log envelope version")));
}
