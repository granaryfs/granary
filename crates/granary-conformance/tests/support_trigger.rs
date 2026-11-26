// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use granary_core::{hash::GrainId, mount_control::MountKey, support_trigger::*};
use proptest::prelude::*;
use std::collections::BTreeSet;

#[expect(
    clippy::unwrap_used,
    reason = "fixed hexadecimal fixture bytes (standards rule 3)"
)]
fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn mounted(roots: Vec<SourceRoot>) -> Header {
    Header::Layout(SourceLayout {
        mount: MountState::Mounted {
            mountpoint: (11, 12),
            key: MountKey {
                namespace_dev: 21,
                namespace_ino: 22,
                mount_id: 23,
                fuse_major: 24,
                fuse_minor: 25,
            },
        },
        roots,
    })
}

fn normalized_path() -> BoxedStrategy<Vec<u8>> {
    let byte = (0x20_u8..=u8::MAX)
        .prop_filter("path components contain neither slash nor DEL", |byte| {
            *byte != b'/' && *byte != 0x7f
        });
    prop::collection::vec(prop::collection::vec(byte, 1..=12), 1..=4)
        .prop_filter(
            "path components are neither dot nor dot-dot",
            |components| {
                components
                    .iter()
                    .all(|component| component != b"." && component != b"..")
            },
        )
        .prop_map(|components| {
            let mut path = Vec::new();
            for component in components {
                path.push(b'/');
                path.extend_from_slice(&component);
            }
            path
        })
        .boxed()
}

fn source_root(role: RootRole) -> BoxedStrategy<SourceRoot> {
    (normalized_path(), 1..=u64::MAX, 1..=u64::MAX)
        .prop_map(move |(path, dev, ino)| SourceRoot {
            role,
            path,
            dev,
            ino,
        })
        .boxed()
}

fn valid_header() -> BoxedStrategy<Header> {
    let mount = prop_oneof![
        Just(MountState::Absent),
        (
            1..=u64::MAX,
            1..=u64::MAX,
            1..=u64::MAX,
            1..=u64::MAX,
            1..=u32::MAX,
            any::<u32>(),
            any::<u32>(),
        )
            .prop_filter(
                "mountpoint and namespace differ and the FUSE device is nonzero",
                |(point_dev, point_ino, namespace_dev, namespace_ino, _, major, minor)| {
                    (*point_dev, *point_ino) != (*namespace_dev, *namespace_ino)
                        && (*major, *minor) != (0, 0)
                },
            )
            .prop_map(
                |(point_dev, point_ino, namespace_dev, namespace_ino, mount_id, major, minor)| {
                    MountState::Mounted {
                        mountpoint: (point_dev, point_ino),
                        key: MountKey {
                            namespace_dev,
                            namespace_ino,
                            mount_id,
                            fuse_major: major,
                            fuse_minor: minor,
                        },
                    }
                },
            ),
    ];
    let roots = (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        source_root(RootRole::Cache),
        source_root(RootRole::Overlay),
        source_root(RootRole::Store),
    )
        .prop_map(
            |(cache, overlay, store, cache_root, overlay_root, store_root)| {
                let mut roots = Vec::new();
                if cache {
                    roots.push(cache_root);
                }
                if overlay {
                    roots.push(overlay_root);
                }
                if store {
                    roots.push(store_root);
                }
                roots
            },
        )
        .prop_filter("root identities are unique", |roots| {
            roots.iter().enumerate().all(|(index, root)| {
                roots
                    .iter()
                    .take(index)
                    .all(|seen| (seen.dev, seen.ino) != (root.dev, root.ino))
            })
        });
    prop_oneof![
        Just(Header::Unavailable),
        (mount, roots).prop_map(|(mount, roots)| Header::Layout(SourceLayout { mount, roots })),
    ]
    .boxed()
}

#[test]
fn support_trigger_golden_vectors_are_canonical() {
    let expected = [
        ("request", request().to_vec()),
        ("unavailable", encode_header(&Header::Unavailable).unwrap()),
        (
            "absent",
            encode_header(&Header::Layout(SourceLayout {
                mount: MountState::Absent,
                roots: Vec::new(),
            }))
            .unwrap(),
        ),
        (
            "mounted",
            encode_header(&mounted(vec![
                SourceRoot {
                    role: RootRole::Cache,
                    path: b"/cache".to_vec(),
                    dev: 31,
                    ino: 32,
                },
                SourceRoot {
                    role: RootRole::Store,
                    path: vec![b'/', 0xff],
                    dev: 41,
                    ino: 42,
                },
            ]))
            .unwrap(),
        ),
        (
            "mounted-three",
            encode_header(&mounted(vec![
                SourceRoot {
                    role: RootRole::Cache,
                    path: b"/cache".to_vec(),
                    dev: 31,
                    ino: 32,
                },
                SourceRoot {
                    role: RootRole::Overlay,
                    path: b"/overlay".to_vec(),
                    dev: 41,
                    ino: 42,
                },
                SourceRoot {
                    role: RootRole::Store,
                    path: b"/store".to_vec(),
                    dev: 51,
                    ino: 52,
                },
            ]))
            .unwrap(),
        ),
    ];
    let rows: Vec<_> = include_str!("../vectors/support-trigger.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert_eq!(rows.len(), expected.len());
    let mut cases = 0;
    for (row, (name, bytes)) in rows.into_iter().zip(expected) {
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "row={row}");
        assert_eq!(fields[0], name);
        assert_eq!(unhex(fields[1]), bytes);
        assert_eq!(fields[2], GrainId::of(&bytes).digest_hex());
        if name == "request" {
            assert_eq!(decode_request(&bytes), Ok(()));
        } else {
            let value = decode_header(&bytes).unwrap();
            assert_eq!(encode_header(&value).unwrap(), bytes);
        }
        cases += 1;
    }
    assert_eq!(cases, 5);
}

#[test]
fn support_trigger_reject_vectors_have_paired_controls() {
    let mut cases = 0;
    for row in include_str!("../vectors/support-trigger-rejects.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let mut fields = row.splitn(4, ' ');
        let kind = fields.next().unwrap();
        let positive = unhex(fields.next().unwrap());
        let malformed = unhex(fields.next().unwrap());
        let reason = fields.next().unwrap();
        let actual = match kind {
            "request" => {
                assert_eq!(decode_request(&positive), Ok(()));
                decode_request(&malformed).unwrap_err()
            }
            "header" => {
                let value = decode_header(&positive).unwrap();
                assert_eq!(encode_header(&value).unwrap(), positive);
                decode_header(&malformed).unwrap_err()
            }
            "header-oversize" => {
                let value = decode_header(&positive).unwrap();
                assert_eq!(encode_header(&value).unwrap(), positive);
                let length =
                    usize::try_from(u32::from_be_bytes(malformed.try_into().unwrap())).unwrap();
                decode_header(&vec![0; length]).unwrap_err()
            }
            "header-path-overlong" => {
                let value = decode_header(&positive).unwrap();
                assert_eq!(encode_header(&value).unwrap(), positive);
                let length =
                    usize::try_from(u32::from_be_bytes(malformed.try_into().unwrap())).unwrap();
                let mut replacement = u16::try_from(length).unwrap().to_be_bytes().to_vec();
                replacement.push(b'/');
                replacement.resize(length + 2, b'x');
                let mut overlong = positive;
                overlong.splice(57..65, replacement);
                decode_header(&overlong).unwrap_err()
            }
            "header-prefix" => {
                assert_eq!(
                    header_frame_length(positive.try_into().unwrap()),
                    Ok(HEADER_MAX)
                );
                header_frame_length(malformed.try_into().unwrap()).unwrap_err()
            }
            "bundle-prefix" => {
                assert_eq!(
                    bundle_frame_length(positive.try_into().unwrap()),
                    Ok(BUNDLE_MAX)
                );
                bundle_frame_length(malformed.try_into().unwrap()).unwrap_err()
            }
            other => panic!("unknown reject-vector kind {other}"),
        };
        assert_eq!(actual.to_string(), reason);
        cases += 1;
    }
    let vector_reasons = include_str!("../vectors/support-trigger-rejects.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.splitn(4, ' ').nth(3).unwrap())
        .collect::<BTreeSet<_>>();
    let catalogue = Error::ALL
        .into_iter()
        .map(|error| error.to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        vector_reasons,
        catalogue.iter().map(String::as_str).collect(),
        "every closed refusal needs a malformed vector"
    );
    assert_eq!(cases, 47, "nonzero malformed support-trigger corpus");
}

#[test]
fn support_trigger_caps_and_layout_rules_refuse_at_the_boundary() {
    let mut legal_path = vec![b'x'; 4096];
    legal_path[0] = b'/';
    let root = |role, dev| SourceRoot {
        role,
        path: legal_path.clone(),
        dev,
        ino: 2,
    };
    let legal = mounted(vec![
        root(RootRole::Cache, 1),
        root(RootRole::Overlay, 2),
        root(RootRole::Store, 3),
    ]);
    let encoded = encode_header(&legal).unwrap();
    assert_eq!(
        (
            match &legal {
                Header::Layout(layout) => layout.roots.len(),
                Header::Unavailable => 0,
            },
            encoded.len(),
        ),
        (3, 12_401),
        "three maximum paths must produce the exact documented header maximum"
    );
    let mut over = legal.clone();
    let Header::Layout(layout) = &mut over else {
        unreachable!()
    };
    layout.roots.push(root(RootRole::Store, 4));
    assert_eq!(encode_header(&over), Err(Error::SourceCount));

    let mut over = mounted(vec![root(RootRole::Cache, 1)]);
    let Header::Layout(layout) = &mut over else {
        unreachable!()
    };
    layout.roots[0].path.push(b'x');
    assert_eq!(encode_header(&over), Err(Error::SourceIdentity));
    let mut malformed = encode_header(&mounted(vec![root(RootRole::Cache, 1)])).unwrap();
    malformed[57..59].copy_from_slice(&4097_u16.to_be_bytes());
    malformed.insert(59 + 4096, b'x');
    assert_eq!(decode_header(&malformed), Err(Error::SourceIdentity));
    assert_eq!(header_frame_length(10_u32.to_be_bytes()), Ok(10));
    assert_eq!(
        header_frame_length(9_u32.to_be_bytes()),
        Err(Error::HeaderSize)
    );
    assert_eq!(header_frame_length(12_401_u32.to_be_bytes()), Ok(12_401));
    assert_eq!(
        header_frame_length(12_402_u32.to_be_bytes()),
        Err(Error::HeaderSize)
    );
    assert_eq!(
        bundle_frame_length(2_097_152_u32.to_be_bytes()),
        Ok(2_097_152)
    );
    assert_eq!(
        bundle_frame_length(2_097_153_u32.to_be_bytes()),
        Err(Error::BundleSize)
    );
    assert_eq!(
        (HEADER_MAX, BUNDLE_MAX, REQUEST_LEN, VERSION),
        (12_401, 2_097_152, 10, 1)
    );
}

#[test]
fn support_trigger_error_catalogue_is_exhaustive_and_unique() {
    fn assert_exhaustive(error: Error) {
        match error {
            Error::RequestLength
            | Error::Magic
            | Error::Version
            | Error::RequestKind
            | Error::HeaderSize
            | Error::BundleSize
            | Error::SourceRole
            | Error::Trailing
            | Error::Truncated
            | Error::SourceCount
            | Error::MountIdentity
            | Error::SourceOrder
            | Error::SourceIdentity
            | Error::HeaderStatus => {}
        }
    }

    let variants = [
        Error::RequestLength,
        Error::Magic,
        Error::Version,
        Error::RequestKind,
        Error::HeaderSize,
        Error::BundleSize,
        Error::SourceRole,
        Error::Trailing,
        Error::Truncated,
        Error::SourceCount,
        Error::MountIdentity,
        Error::SourceOrder,
        Error::SourceIdentity,
        Error::HeaderStatus,
    ];
    for error in variants {
        assert_exhaustive(error);
        assert!(Error::ALL.contains(&error));
    }
    for (index, error) in Error::ALL.iter().enumerate() {
        assert!(
            !Error::ALL.iter().take(index).any(|seen| seen == error),
            "Error::ALL must contain each closed error exactly once"
        );
    }
}

proptest! {
    #[test]
    fn valid_support_trigger_headers_are_canonical(value in valid_header()) {
        let bytes = encode_header(&value).unwrap();
        let decoded = decode_header(&bytes).unwrap();
        prop_assert_eq!(&decoded, &value);
        prop_assert_eq!(encode_header(&decoded).unwrap(), bytes);
    }

    #[test]
    fn support_trigger_decoders_are_total(bytes in prop::collection::vec(any::<u8>(),0..12_500)) {
        if let Ok(value) = decode_header(&bytes) {
            let encoded = encode_header(&value).unwrap();
            prop_assert_eq!(encoded.as_slice(), bytes.as_slice());
        }
        if decode_request(&bytes).is_ok() {
            prop_assert_eq!(bytes, request());
        }
    }
}
