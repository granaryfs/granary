// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

mod common;
use granary_core::{
    hash::GrainId,
    manifest::Name,
    overlay_journal::{
        Location, Parent, Record, RecordError, ResidualDisposition, ResidualFile, ResidualMode,
        ResidualPayloadHasher, UnmergedPath, UnmergedPathError, residual_inventory_check,
    },
};
use std::fmt::Write as _;

const LICENSE: &str = "# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>\n# SPDX-License-Identifier: Apache-2.0\n";

fn hex(bytes: &[u8]) -> String {
    let mut text = String::new();
    for byte in bytes {
        write!(text, "{byte:02x}")
            .unwrap_or_else(|error| panic!("fixture hex formatting: {error}"));
    }
    text
}

fn listing() -> UnmergedPath {
    let file = ResidualFile {
        stage_id: 1,
        at: Location {
            parent: Parent::root(),
            name: Name::new(b"f".to_vec()).unwrap_or_else(|error| panic!("fixture: {error}")),
        },
        exec: false,
        local_size: 0,
        payload_check: ResidualPayloadHasher::new(1, 0).finalize(),
    };
    UnmergedPath {
        writer: [17; 16],
        record: ResidualDisposition {
            boundary_seq: 3,
            publication_id: [7; 16],
            landed_root: GrainId::of(b"landed"),
            landed_seq: 2,
            source_end: 5,
            disposition: ResidualMode::KeepRemote,
            collision_count: 1,
            inventory_check: residual_inventory_check(std::slice::from_ref(&file))
                .unwrap_or_else(|error| panic!("fixture: {error}")),
        },
        file,
    }
}

fn maximum_listing() -> UnmergedPath {
    let mut maximum = listing();
    maximum.file.at.parent = Parent::new(
        (0..128)
            .map(|i| {
                Name::new(vec![
                    b'p';
                    match i {
                        0..15 => 255,
                        15 => 159,
                        _ => 1,
                    }
                ])
                .unwrap_or_else(|error| panic!("fixture: {error}"))
            })
            .collect(),
    )
    .unwrap_or_else(|error| panic!("fixture: {error}"));
    maximum.file.at.name =
        Name::new(vec![b'f'; 255]).unwrap_or_else(|error| panic!("fixture: {error}"));
    maximum.file.stage_id = 9_223_372_036_854_775_807;
    maximum.file.local_size = 9_223_372_036_854_775_807;
    maximum.file.exec = true;
    maximum.record.inventory_check = residual_inventory_check(std::slice::from_ref(&maximum.file))
        .unwrap_or_else(|error| panic!("fixture: {error}"));
    maximum
}

fn checked(mut bytes: Vec<u8>) -> Vec<u8> {
    let end = bytes.len() - 32;
    let check = blake3::derive_key(
        "granary unmerged path v1",
        bytes
            .get(..end)
            .unwrap_or_else(|| panic!("fixture covered bytes")),
    );
    bytes
        .get_mut(end..)
        .unwrap_or_else(|| panic!("fixture check bytes"))
        .copy_from_slice(&check);
    bytes
}

#[test]
fn unmerged_path_refuses_invalid_envelope() {
    let valid = listing();
    let bytes = valid.encode().unwrap();
    assert_eq!(UnmergedPath::decode(&bytes), Ok(valid));
    let mut results = Vec::new();
    for (label, offset, value, reason) in [
        ("magic", 0, 0, "unmerged path magic"),
        ("version", 9, 2, "unmerged path version"),
        ("flags", 11, 1, "unmerged path flags"),
        ("check", bytes.len() - 1, 1, "unmerged path check"),
    ] {
        let mut bad = bytes.clone();
        bad[offset] ^= value.max(1);
        if label != "check" {
            bad = checked(bad);
        }
        results.push((
            label,
            UnmergedPath::decode(&bad)
                .err()
                .map(|error| error.to_string()),
            Some(reason.to_owned()),
        ));
    }
    assert_eq!(results.len(), 4);
    assert_eq!(
        results
            .iter()
            .map(|(label, got, _)| (*label, got.clone()))
            .collect::<Vec<_>>(),
        results
            .iter()
            .map(|(label, _, want)| (*label, want.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn unmerged_path_refuses_source_substitution() {
    let source = listing();
    let filename = "0000000000000001.path";
    assert_eq!(
        source.check_binding(filename, &source.writer, &source.record, &source.file),
        Ok(())
    );
    let mut results = Vec::new();
    for label in [
        "descriptor",
        "filename",
        "writer",
        "record",
        "forged_self_consistent_listing",
    ] {
        let mut forged = source.clone();
        match label {
            "descriptor" => forged.file.exec = !forged.file.exec,
            "writer" => forged.writer[0] ^= 1,
            "record" => forged.record.source_end += 1,
            "forged_self_consistent_listing" => {
                forged.file.at.name = Name::new(b"forged".to_vec()).unwrap();
                forged.record.inventory_check =
                    residual_inventory_check(std::slice::from_ref(&forged.file)).unwrap();
            }
            _ => {}
        }
        let forged = UnmergedPath::decode(&forged.encode().unwrap()).unwrap();
        let filename = if label == "filename" {
            "0000000000000002.path"
        } else {
            filename
        };
        results.push((
            label,
            forged.check_binding(filename, &source.writer, &source.record, &source.file),
        ));
    }
    assert_eq!(results.len(), 5);
    assert_eq!(
        results,
        [
            "descriptor",
            "filename",
            "writer",
            "record",
            "forged_self_consistent_listing"
        ]
        .map(|label| (label, Err(UnmergedPathError::SourceMismatch)))
    );
}

#[test]
fn unmerged_path_binding_uses_canonical_hex_stage_names() {
    let mut source = listing();
    source.file.stage_id = 10;
    source.file.payload_check = ResidualPayloadHasher::new(10, 0).finalize();
    source.record.inventory_check =
        residual_inventory_check(std::slice::from_ref(&source.file)).unwrap();
    let listing = UnmergedPath::decode(&source.encode().unwrap()).unwrap();
    assert_eq!(
        listing.check_binding(
            "000000000000000a.path",
            &source.writer,
            &source.record,
            &source.file
        ),
        Ok(())
    );
    let mut count = 0;
    for filename in [
        "0000000000000010.path",
        "000000000000000A.path",
        "a.path",
        "000000000000000a.PATH",
    ] {
        assert_eq!(
            listing.check_binding(filename, &source.writer, &source.record, &source.file),
            Err(UnmergedPathError::SourceMismatch),
            "{filename}"
        );
        count += 1;
    }
    assert_eq!(count, 4);
}

#[test]
fn unmerged_path_goldens_and_bounds() {
    let maximum = maximum_listing();
    let mut vectors = LICENSE.to_owned();
    for (label, value, length) in [("minimum", listing(), 223), ("maximum", maximum, 4701)] {
        let bytes = value.encode().unwrap();
        assert_eq!(
            (bytes.len(), UnmergedPath::decode(&bytes)),
            (length, Ok(value))
        );
        writeln!(vectors, "{label}\t{}\t{}", hex(&bytes), GrainId::of(&bytes)).unwrap();
    }
    common::assert_golden(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors/overlay_journal_unmerged_v1.tsv"),
        &vectors,
    );
}

#[test]
fn unmerged_path_refuses_oversize_before_decode() {
    let mut oversized = maximum_listing().encode().unwrap();
    oversized.insert(oversized.len() - 32, 0);
    let oversized = checked(oversized);
    assert_eq!(
        (oversized.len(), UnmergedPath::decode(&oversized)),
        (4702, Err(UnmergedPathError::Length))
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table pins malformed bytes, independent binding context and matching fuzz seeds"
)]
fn unmerged_path_rejects_corpus_and_fuzz_seeds() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = listing();
    let valid = source.encode().unwrap();
    assert_eq!(UnmergedPath::decode(&valid), Ok(source.clone()));
    assert_eq!(
        source.check_binding(
            "0000000000000001.path",
            &source.writer,
            &source.record,
            &source.file
        ),
        Ok(())
    );
    let mut cases = vec![
        ("short", vec![], "unmerged path length", None),
        (
            "short_minimum",
            valid[..222].to_vec(),
            "unmerged path length",
            None,
        ),
        ("oversize", vec![0; 4702], "unmerged path length", None),
    ];
    for (label, offset, fields, reason) in [
        ("magic", 0, vec![0], "unmerged path magic"),
        ("version_zero", 8, vec![0, 0], "unmerged path version"),
        ("version_unknown", 8, vec![0, 2], "unmerged path version"),
        ("flags_low", 10, vec![0, 1], "unmerged path flags"),
        ("flags_high", 10, vec![128, 0], "unmerged path flags"),
        ("boundary_zero", 28, vec![0; 8], "unmerged path record"),
        ("root_algorithm", 52, vec![0], "unmerged path record"),
        ("landing_zero", 85, vec![0; 8], "unmerged path record"),
        ("landing_max", 85, vec![255; 8], "unmerged path record"),
        ("mode_zero", 101, vec![0], "unmerged path record"),
        ("mode_keep_local", 101, vec![1], "unmerged path disposition"),
        ("mode_unknown", 101, vec![3], "unmerged path record"),
        ("count_zero", 102, vec![0; 4], "unmerged path record"),
        ("stage_zero", 138, vec![0; 8], "unmerged path descriptor"),
        (
            "stage_above_max",
            138,
            9_223_372_036_854_775_808u64.to_be_bytes().to_vec(),
            "unmerged path descriptor",
        ),
        (
            "size_above_max",
            151,
            9_223_372_036_854_775_808u64.to_be_bytes().to_vec(),
            "unmerged path descriptor",
        ),
        (
            "depth_above_max",
            146,
            129u16.to_be_bytes().to_vec(),
            "unmerged path descriptor",
        ),
        (
            "name_length_overrun",
            148,
            vec![255],
            "unmerged path descriptor",
        ),
        ("exec_unknown", 150, vec![2], "unmerged path descriptor"),
    ] {
        let mut bad = valid.clone();
        bad[offset..offset + fields.len()].copy_from_slice(&fields);
        cases.push((label, checked(bad), reason, None));
    }
    for (label, name) in [
        ("name_empty", b"".as_slice()),
        ("name_slash", b"/"),
        ("name_nul", b"\0"),
        ("name_dot", b"."),
        ("name_dotdot", b".."),
        ("name_reserved", b".gran"),
    ] {
        let mut bad = valid.clone();
        bad.splice(
            148..150,
            std::iter::once(u8::try_from(name.len()).unwrap()).chain(name.iter().copied()),
        );
        if name.is_empty() {
            bad[146..148].copy_from_slice(&1u16.to_be_bytes());
            bad.splice(148..148, [1, b'a']);
        }
        cases.push((label, checked(bad), "unmerged path descriptor", None));
    }
    let mut bad_check = valid.clone();
    *bad_check.last_mut().unwrap() ^= 1;
    cases.push(("check", bad_check, "unmerged path check", None));
    let mut trailing = valid.clone();
    trailing.insert(valid.len() - 32, 0);
    cases.push((
        "trailing",
        checked(trailing),
        "unmerged path descriptor",
        None,
    ));
    let mut bad_parent = valid.clone();
    bad_parent[146..148].copy_from_slice(&1u16.to_be_bytes());
    bad_parent.splice(148..148, [1, b'/']);
    cases.push((
        "parent_name_slash",
        checked(bad_parent),
        "unmerged path descriptor",
        None,
    ));
    let mut overlong_parent = maximum_listing().encode().unwrap();
    // The sixteenth parent grows by one byte; shorten the leaf name to keep
    // the outer listing inside its bound and reach the aggregate path check.
    overlong_parent[3988] = 160;
    overlong_parent.insert(3989, b'p');
    overlong_parent[4373] = 254;
    overlong_parent.remove(4374);
    assert_eq!(
        (
            overlong_parent.len(),
            ResidualFile::decode(&overlong_parent[138..overlong_parent.len() - 32])
        ),
        (4701, Err(RecordError::PathTooLong { bytes: 4097 }))
    );
    cases.push((
        "parent_bytes_above_max",
        checked(overlong_parent),
        "unmerged path descriptor",
        None,
    ));
    for label in [
        "filename",
        "writer",
        "record",
        "descriptor",
        "forged_self_consistent_listing",
    ] {
        let mut forged = source.clone();
        match label {
            "writer" => forged.writer[0] ^= 1,
            "record" => forged.record.source_end += 1,
            "descriptor" => forged.file.exec = true,
            "forged_self_consistent_listing" => {
                forged.file.at.name = Name::new(b"forged".to_vec()).unwrap();
                forged.file.local_size = 6;
                let mut payload = ResidualPayloadHasher::new(1, 6);
                payload.update(b"forged");
                forged.file.payload_check = payload.finalize();
                forged.record.inventory_check =
                    residual_inventory_check(std::slice::from_ref(&forged.file)).unwrap();
                assert_ne!(forged.file, source.file);
                assert_eq!(
                    forged.record.inventory_check,
                    residual_inventory_check(std::slice::from_ref(&forged.file)).unwrap()
                );
            }
            _ => {}
        }
        let bytes = forged.encode().unwrap();
        assert_eq!(UnmergedPath::decode(&bytes), Ok(forged));
        let filename = if label == "filename" {
            "0000000000000002.path"
        } else {
            "0000000000000001.path"
        };
        cases.push((
            label,
            bytes,
            "unmerged path source mismatch",
            Some(filename),
        ));
    }
    let mut rejects = LICENSE.to_owned();
    let mut seeds = vec![
        ("minimum", valid),
        ("maximum", maximum_listing().encode().unwrap()),
    ];
    for (label, bytes, reason, filename) in &cases {
        let got = if let Some(filename) = filename {
            UnmergedPath::decode(bytes).unwrap().check_binding(
                filename,
                &source.writer,
                &source.record,
                &source.file,
            )
        } else {
            UnmergedPath::decode(bytes).map(|_| ())
        };
        assert_eq!(
            got.map_err(|error| error.to_string()),
            Err((*reason).to_owned()),
            "{label}"
        );
        let context = if let Some(filename) = filename {
            format!(
                "{filename}\t{}\t{}\t{}",
                hex(&source.writer),
                hex(&Record::ResidualDisposition(source.record)
                    .encode_payload()
                    .unwrap()),
                hex(&source.file.encode().unwrap())
            )
        } else {
            "-\t-\t-\t-".to_owned()
        };
        writeln!(rejects, "{label}\t{}\t{context}\t{reason}", hex(bytes)).unwrap();
        seeds.push((label, bytes.clone()));
    }
    assert_eq!(cases.len(), 37);
    common::assert_golden(
        &root.join("tests/vectors/overlay_journal_unmerged_v1_rejects.tsv"),
        &rejects,
    );
    for (label, bytes) in seeds {
        let path = root.join(format!(
            "fuzz/corpus/overlay_journal_decode/unmerged-{label}"
        ));
        if std::env::var_os("GRANARY_REGEN_VECTORS").is_some() {
            std::fs::write(&path, &bytes).unwrap();
            std::fs::write(path.with_extension("license"), LICENSE).unwrap();
        }
        assert_eq!(std::fs::read(path).unwrap(), bytes, "{label}");
    }
}

#[test]
fn empty_leaf_reject_reaches_descriptor() {
    let corpus =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/overlay_journal_decode");
    let valid = std::fs::read(corpus.join("unmerged-minimum")).unwrap();
    assert_eq!(UnmergedPath::decode(&valid), Ok(listing()));
    let bytes = std::fs::read(corpus.join("unmerged-name_empty")).unwrap();
    assert_eq!(
        (
            bytes.len(),
            UnmergedPath::decode(&bytes)
                .err()
                .map(|error| error.to_string())
        ),
        (224, Some("unmerged path descriptor".to_owned()))
    );
}

#[test]
fn unmerged_path_refuses_keep_local() {
    let remote = listing();
    let valid = remote.encode().unwrap();
    assert_eq!(UnmergedPath::decode(&valid), Ok(remote.clone()));
    let mut local = remote;
    local.record.disposition = ResidualMode::KeepLocal;
    let mut bytes = valid;
    bytes[101] = 1;
    let bytes = checked(bytes);
    assert_eq!(
        (
            UnmergedPath::decode(&bytes)
                .err()
                .map(|error| error.to_string()),
            local.encode().err().map(|error| error.to_string())
        ),
        (
            Some("unmerged path disposition".to_owned()),
            Some("unmerged path disposition".to_owned())
        )
    );
}

#[test]
fn shared_probe_replays_unmerged_seed() {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus/overlay_journal_decode/unmerged-minimum"),
    )
    .unwrap();
    assert_eq!(
        (bytes.len(), bytes.get(..8)),
        (223, Some(b"GRNOVUMP".as_slice()))
    );
    granary_core::testkit::overlay_journal_decode_probe(&bytes);
}

#[test]
fn unmerged_path_errors_retain_record_causes() {
    use std::error::Error as _;
    let source = listing();
    let mut record = source.clone();
    record.record.collision_count = 0;
    let record_error = record.encode().unwrap_err();
    assert_eq!(
        record_error,
        UnmergedPathError::Record(RecordError::EmptyInventory)
    );
    assert_eq!(
        record_error.source().map(ToString::to_string),
        Some("journal residual inventory is empty".to_owned())
    );
    let mut descriptor = source;
    descriptor.file.stage_id = 0;
    let descriptor_error = descriptor.encode().unwrap_err();
    assert_eq!(
        descriptor_error,
        UnmergedPathError::Descriptor(RecordError::StageIdOutOfRange { stage_id: 0 })
    );
    assert_eq!(
        descriptor_error.source().map(ToString::to_string),
        Some("journal stage id 0 is out of range".to_owned())
    );
    let mut bytes = listing().encode().unwrap();
    bytes[101] = 0;
    assert_eq!(
        UnmergedPath::decode(&checked(bytes)),
        Err(UnmergedPathError::Record(RecordError::BadDisposition {
            byte: 0
        }))
    );
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus/overlay_journal_decode/unmerged-name_empty"),
    )
    .unwrap();
    assert_eq!(
        UnmergedPath::decode(&bytes),
        Err(UnmergedPathError::Descriptor(RecordError::BadName(
            granary_core::manifest::NameError::Empty
        )))
    );
}
