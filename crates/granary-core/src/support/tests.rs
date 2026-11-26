// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
mod goldens;
use super::snapshot::GRANT_REASONS;
use super::*;
use crate::{
    debug_grant::{GrantAction, GrantScope},
    enrollment::PrincipalId,
};
use goldens::{configuration, snapshot};
fn fixture(name: &str) -> Vec<u8> {
    let row = include_str!("../../tests/vectors/support_v1.tsv")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .find(|l| l.split('\t').next() == Some(name))
        .expect("named golden");
    unhex(row.split('\t').nth(1).expect("golden bytes"))
}
fn expired_snapshot() -> SupportSnapshot {
    let mut value = snapshot();
    value.grant.as_mut().unwrap().reason = Some("expired");
    value
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for b in bytes {
        write!(out, "{b:02x}").unwrap();
    }
    out
}
fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn support_formats_canonical_and_verified() {
    assert_eq!(
        SupportConfiguration::decode(&fixture("configuration")),
        Ok(configuration())
    );
    assert_eq!(
        SupportSnapshot::decode(&fixture("snapshot")),
        Ok(snapshot())
    );
    assert_eq!(
        SupportSnapshot::decode(&fixture("snapshot-expired")),
        Ok(expired_snapshot())
    );
    let cases = [
        ("configuration", configuration().encode()),
        ("snapshot", snapshot().encode()),
        ("snapshot-expired", expired_snapshot().encode()),
    ];
    for (name, result) in cases {
        assert!(
            result.is_ok(),
            "{name} must encode canonical bytes: {result:?}"
        );
        let bytes = result.unwrap();
        let vectors = include_str!("../../tests/vectors/support_v1.tsv");
        let vector = vectors
            .lines()
            .filter(|l| !l.starts_with('#'))
            .find_map(|l| {
                let mut f = l.split('\t');
                (f.next()? == name).then(|| (f.next().unwrap(), f.next().unwrap()))
            })
            .expect("nonempty golden vector");
        assert_eq!(
            (hex(&bytes), hex(&bytes[bytes.len() - 32..])),
            (vector.0.into(), vector.1.into()),
            "{name} golden"
        );
        let check = |input: &[u8]| -> Result<Vec<u8>> {
            if name == "configuration" {
                SupportConfiguration::decode(input)?.encode()
            } else {
                SupportSnapshot::decode(input)?.encode()
            }
        };
        assert_eq!(check(&bytes), Ok(bytes.clone()));
        for n in 0..bytes.len() {
            assert!(check(&bytes[..n]).is_err(), "{name} truncation {n}");
        }
        for n in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[n] ^= 1;
            assert!(check(&bad).is_err(), "{name} byte flip {n}");
        }
    }
    assert_eq!(
        SupportConfiguration::decode(&vec![0; CONFIGURATION_MAX + 1]),
        Err(SupportError("support size bound"))
    );
    assert_eq!(
        SupportSnapshot::decode(&vec![0; SNAPSHOT_MAX + 1]),
        Err(SupportError("support size bound"))
    );
    for count in [0, 1] {
        let mut value = snapshot();
        value.enrollment.state = SnapshotState::Ok {
            principals: count,
            credentials: count,
        };
        let encoded = value.encode();
        assert!(encoded.is_ok(), "valid inventory {count}: {encoded:?}");
        assert_eq!(SupportSnapshot::decode(&encoded.unwrap()), Ok(value));
    }
    let rejects = include_str!("../../tests/vectors/support_v1_rejects.tsv");
    let mut count = 0;
    for row in rejects.lines().filter(|l| !l.starts_with('#')) {
        let parts: Vec<_> = row.split('\t').collect();
        let bytes = unhex(parts[2]);
        let err = if parts[0] == "configuration" {
            SupportConfiguration::decode(&bytes)
                .err()
                .unwrap_or_else(|| panic!("reject {} unexpectedly accepted", parts[1]))
        } else {
            SupportSnapshot::decode(&bytes)
                .err()
                .unwrap_or_else(|| panic!("reject {} unexpectedly accepted", parts[1]))
        };
        assert_eq!(err.to_string(), parts[3], "reject {}", parts[1]);
        count += 1;
    }
    assert!(count >= 20, "reject case count {count}");
}
#[test]
fn support_formats_properties() {
    let mut cases = 0;
    for seed in 0..128_u64 {
        let mut c = configuration();
        c.incarnation = Incarnation::from_bytes(crate::testkit::fill(seed, 16).try_into().unwrap());
        c.dispatch_deadline_ms = if seed.is_multiple_of(2) {
            None
        } else {
            Some(seed)
        };
        let result = c.encode();
        assert!(
            result.is_ok(),
            "configuration property must encode: {result:?}"
        );
        let encoded = result.unwrap();
        assert_eq!(SupportConfiguration::decode(&encoded), Ok(c.clone()));
        assert_eq!(
            SupportConfiguration::decode(&encoded)
                .unwrap()
                .encode()
                .unwrap(),
            encoded
        );
        let mut s = snapshot();
        s.incarnation = c.incarnation;
        s.grant.as_mut().unwrap().incarnation = s.incarnation;
        s.sampled_at = Timestamp {
            secs: i64::try_from(seed).unwrap() - 64,
            nanos: u32::try_from(seed).unwrap(),
        };
        s.terminal = match seed % 3 {
            0 => None,
            1 => Some(TerminalState::Stopped),
            _ => Some(TerminalState::Fenced),
        };
        s.enrollment.state = if seed.is_multiple_of(2) {
            SnapshotState::Ok {
                principals: 16_384,
                credentials: 16_384,
            }
        } else {
            SnapshotState::Unavailable(
                super::snapshot::UNAVAILABLE[usize::try_from(seed % 7).unwrap()],
            )
        };
        let grant = s.grant.as_mut().unwrap();
        grant.state = super::snapshot::STATES[usize::try_from(seed % 3).unwrap()];
        grant.reason = Some(GRANT_REASONS[usize::try_from(seed).unwrap() % GRANT_REASONS.len()]);
        let record = grant.observed.as_mut().unwrap();
        record.action = match seed % 3 {
            0 => GrantAction::Issue,
            1 => GrantAction::Narrow,
            _ => GrantAction::Revoke,
        };
        record.scope = match seed % 3 {
            0 => GrantScope::Principal(PrincipalId::from_bytes([1; 16])),
            1 => GrantScope::Volume(VolumeName::new("z".into()).unwrap()),
            _ => record.scope.clone(),
        };
        if seed.is_multiple_of(5) {
            grant.effective = None;
            grant.accepted = None;
            grant.observed = None;
            grant.slot = None;
            grant.future_issued_lead_secs = None;
            grant.reason = None;
        }
        if seed.is_multiple_of(7) {
            s.grant = None;
        }
        let result = s.encode();
        assert!(result.is_ok(), "snapshot property must encode: {result:?}");
        let encoded = result.unwrap();
        assert_eq!(SupportSnapshot::decode(&encoded), Ok(s));
        assert_eq!(
            SupportSnapshot::decode(&encoded).unwrap().encode().unwrap(),
            encoded
        );
        let random = crate::testkit::fill(seed, usize::try_from(seed).unwrap() * 13);
        let _ = SupportSnapshot::decode(&random);
        let _ = SupportConfiguration::decode(&random);
        cases += 1;
    }
    assert_eq!(cases, 128);
}

#[test]
fn support_formats_fuzz_probe_replay() {
    use crate::testkit::{support_configuration_decode_probe, support_snapshot_decode_probe};
    let probe = |name: &str, bytes: &[u8]| {
        if name == "configuration" {
            support_configuration_decode_probe(bytes);
        } else {
            support_snapshot_decode_probe(bytes);
        }
    };
    let mut count = 0;
    for name in ["configuration", "snapshot", "snapshot-expired"] {
        let bytes = fixture(name);
        probe(name, &bytes);
        for index in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            probe(name, &changed);
            probe(name, &bytes[..index]);
            count += 2;
        }
    }
    for row in include_str!("../../tests/vectors/support_v1_rejects.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let mut parts = row.split('\t');
        let name = parts.next().unwrap();
        let _label = parts.next().unwrap();
        probe(name, &unhex(parts.next().unwrap()));
        count += 1;
    }
    for seed in 0..128 {
        let bytes = crate::testkit::fill(seed, usize::try_from(seed).unwrap() * 13);
        probe("configuration", &bytes);
        probe("snapshot", &bytes);
        count += 2;
    }
    assert_eq!(count, 5573, "nonempty paired probe replay");
}

#[test]
fn support_formats_controls_boundaries() {
    let cases = [
        ([1, 4_294_967_295, 33_554_432, 268_435_456, 7], true),
        ([1, 4_294_967_296, 33_554_432, 268_435_456, 7], false),
        ([1, 1, 1, 4_294_967_295, 7], true),
        ([1, 1, 1, 4_294_967_296, 7], false),
        ([1, 1, 33_554_432, 268_435_455, 7], false),
        ([1, 1, 33_554_432, 268_435_456, 8], false),
        ([1, 0, 33_554_432, 268_435_456, 7], false),
    ];
    let mut count = 0;
    for (values, valid) in cases {
        let mut value = configuration();
        value.controls = SupportControls(values);
        let encoded = value.encode();
        assert_eq!(encoded.is_ok(), valid, "controls {values:?}: {encoded:?}");
        if !valid {
            assert_eq!(encoded, Err(SupportError("controls")));
        }
        count += 1;
    }
    assert_eq!(count, 7);
}

#[test]
fn support_semantic_sentinels_and_embedded_status_bytes() {
    let configuration = goldens::sentinel_configuration();
    let snapshot = goldens::sentinel_snapshot();
    let c = include_bytes!("../../tests/vectors/support-configuration-sentinels.bin");
    let s = include_bytes!("../../tests/vectors/support-snapshot-sentinels.bin");
    assert_eq!(SupportConfiguration::decode(c), Ok(configuration.clone()));
    assert_eq!(configuration.encode().unwrap(), c);
    assert_eq!(SupportSnapshot::decode(s), Ok(snapshot.clone()));
    assert_eq!(snapshot.encode().unwrap(), s);
    for (name, bytes) in [
        (
            "alpha",
            include_bytes!("../../tests/vectors/support-embedded-alpha-status.bin").as_slice(),
        ),
        (
            "empty",
            include_bytes!("../../tests/vectors/support-embedded-empty-status.bin").as_slice(),
        ),
        (
            "unknown",
            include_bytes!("../../tests/vectors/support-embedded-unknown-status.bin").as_slice(),
        ),
    ] {
        let VolumeView::Log(status) = snapshot.volumes[&VolumeName::new(name.into()).unwrap()]
        else {
            panic!("embedded status")
        };
        assert_eq!(crate::authority_answer::decode_status(bytes), Ok(status));
        assert_eq!(
            crate::authority_answer::encode_status(status).unwrap(),
            bytes
        );
        assert_eq!(
            s.windows(bytes.len()).filter(|w| *w == bytes).count(),
            1,
            "one exact embedded status for {name}"
        );
    }
}

#[test]
fn support_archive_golden_contains_valid_projections() {
    let configuration = goldens::sentinel_configuration();
    let snapshot = goldens::sentinel_snapshot();
    let metadata = SupportLogMetadata {
        volume: VolumeName::new("alpha".into()).unwrap(),
        envelope_version: 1,
        epoch: crate::authlog::Epoch::from_bytes([7; 16]),
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
    let members = BTreeMap::from([
        (
            b"configuration.bin".to_vec(),
            include_bytes!("../../tests/vectors/support-configuration-sentinels.bin").to_vec(),
        ),
        (
            b"snapshot.bin".to_vec(),
            include_bytes!("../../tests/vectors/support-snapshot-sentinels.bin").to_vec(),
        ),
        (
            b"alpha.logmeta".to_vec(),
            include_bytes!("../../tests/vectors/support-log-metadata.bin").to_vec(),
        ),
    ]);
    let entry = |kind, id: &[u8], name: &[u8], cap| {
        let bytes = &members[name];
        ExportEntry {
            kind,
            id: id.to_vec(),
            projection_version: 1,
            cap,
            status: EntryStatus::Exported {
                member: name.to_vec(),
                length: u32::try_from(bytes.len()).unwrap(),
                digest: *GrainId::of(bytes).digest(),
            },
        }
    };
    let manifest = SupportManifest {
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
        support_truncated: false,
        state_truncated: false,
        entries: vec![
            entry(
                SourceKind::Snapshot,
                b"SUPPORT-SNAPSHOT",
                b"snapshot.bin",
                8_388_608,
            ),
            entry(
                SourceKind::Configuration,
                b"SUPPORT-CONFIGURATION",
                b"configuration.bin",
                32_768,
            ),
            entry(SourceKind::Log, b"alpha", b"alpha.logmeta", 1024),
        ],
    };
    let expected = SupportArchive { manifest, members };
    let bytes = include_bytes!("../../tests/vectors/support-valid-projections-archive.bin");
    assert_eq!(SupportArchive::decode(bytes), Ok(expected.clone()));
    assert_eq!(expected.encode().unwrap(), bytes);
    assert_eq!(expected.members.len(), 3);
    assert_eq!(
        SupportConfiguration::decode(&expected.members[b"configuration.bin".as_slice()]),
        Ok(configuration)
    );
    assert_eq!(
        SupportSnapshot::decode(&expected.members[b"snapshot.bin".as_slice()]),
        Ok(snapshot)
    );
    assert_eq!(
        SupportLogMetadata::decode(&expected.members[b"alpha.logmeta".as_slice()]),
        Ok(metadata)
    );
}

#[test]
fn support_inventory_flags_have_independent_goldens() {
    let cases = [
        (
            true,
            include_bytes!("../../tests/vectors/support-inventory-manifests/support.bin")
                .as_slice(),
            include_bytes!("../../tests/vectors/support-inventory-archives/support.bin").as_slice(),
        ),
        (
            false,
            include_bytes!("../../tests/vectors/support-inventory-manifests/state.bin").as_slice(),
            include_bytes!("../../tests/vectors/support-inventory-archives/state.bin").as_slice(),
        ),
    ];
    for (support, manifest_bytes, archive_bytes) in cases {
        let expected = goldens::truncated_archive(support);
        assert_eq!(
            SupportManifest::decode(manifest_bytes),
            Ok(expected.manifest.clone()),
            "independent inventory flags: support={support}"
        );
        assert_eq!(expected.manifest.encode().unwrap(), manifest_bytes);
        assert_eq!(SupportArchive::decode(archive_bytes), Ok(expected.clone()));
        assert_eq!(expected.encode().unwrap(), archive_bytes);
    }
    assert_eq!(cases.len(), 2, "both asymmetric inventories");
}

#[test]
fn support_enrollment_unavailable_tags_have_independent_goldens() {
    use UnavailableReason::{
        Corrupt, Directory, Missing, Oversize, Stalled, Unprotected, Unreadable,
    };
    // Literal tags and semantic variants follow the format's registry,
    // independently of the codec's encode/decode lookup table.
    let cases = [
        (
            1,
            Missing,
            include_bytes!("../../tests/vectors/support-enrollment-states/missing.bin").as_slice(),
        ),
        (
            2,
            Unreadable,
            include_bytes!("../../tests/vectors/support-enrollment-states/unreadable.bin")
                .as_slice(),
        ),
        (
            3,
            Unprotected,
            include_bytes!("../../tests/vectors/support-enrollment-states/unprotected.bin")
                .as_slice(),
        ),
        (
            4,
            Oversize,
            include_bytes!("../../tests/vectors/support-enrollment-states/oversize.bin").as_slice(),
        ),
        (
            5,
            Corrupt,
            include_bytes!("../../tests/vectors/support-enrollment-states/corrupt.bin").as_slice(),
        ),
        (
            6,
            Directory,
            include_bytes!("../../tests/vectors/support-enrollment-states/directory.bin")
                .as_slice(),
        ),
        (
            7,
            Stalled,
            include_bytes!("../../tests/vectors/support-enrollment-states/stalled.bin").as_slice(),
        ),
    ];
    for (tag, reason, bytes) in cases {
        let expected = goldens::unavailable_snapshot(reason);
        // Envelope, incarnation, time, sampling tag, count, alpha/NoLog,
        // and terminal occupy exactly 55 bytes before the enrollment tag.
        assert_eq!(
            bytes.get(55),
            Some(&tag),
            "literal state tag for {reason:?}"
        );
        assert_eq!(
            SupportSnapshot::decode(bytes),
            Ok(expected.clone()),
            "independent enrollment tag {tag}: {reason:?}"
        );
        assert_eq!(expected.encode().unwrap(), bytes);
    }
    assert_eq!(cases.len(), 7, "complete unavailable-state registry");
}
