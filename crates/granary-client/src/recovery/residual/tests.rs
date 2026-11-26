// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::overlay_test_support::{Paths, PublishedTree};
use granary_core::rootstore::RootStore as _;

fn with_content(remaining: u64, check: impl FnOnce(&ReadOnlyContent<'_>, &crate::Store)) {
    let paths = Paths::new();
    let local = crate::Store::open(&paths.store).unwrap();
    let mut objects = preparation::VerifiedObjects::default();
    let node = granary_core::manifest::encode_dir_leaf(&[]).unwrap();
    objects.retained.insert(GrainId::of(&node), node);
    let budget = Budget::new(&(), remaining, None);
    let content = ReadOnlyContent {
        local: &local,
        objects: &objects,
        budget: &budget,
        payloads: Mutex::default(),
    };
    check(&content, &local);
}

#[test]
fn read_only_content_refuses_writes_and_unused_methods() {
    with_content(16_777_216, |content, local| {
        let bytes = b"never persist";
        let id = GrainId::of(bytes);
        assert_eq!(
            (
                content.put_object(id, bytes).err().map(|e| e.to_string()),
                content.payload(id).err().map(|e| e.to_string()),
                content.read_content(id, 0, 1).err().map(|e| e.to_string()),
                local.has(&id)
            ),
            (
                Some("intent refused: RecoveryResidualReadOnly".into()),
                Some("intent refused: RecoveryResidualReadOnly".into()),
                Some("overlay refused: residual preflight is read-only".into()),
                false
            )
        );
    });
}

#[test]
fn read_only_content_remembers_payload_only_in_memory() {
    with_content(1120, |content, local| {
        let grains = FileGrains::Inline(vec![]);
        let bytes = file_payload(0, &grains).unwrap();
        let id = GrainId::of(&bytes);
        content.remember_payload(id, 0, &grains).unwrap();
        content.remember_payload(id, 0, &grains).unwrap();
        let node = granary_core::manifest::encode_dir_leaf(&[]).unwrap();
        assert_eq!(content.get(&GrainId::of(&node)).unwrap(), node);
        assert_eq!(
            (
                content.payloads.lock().unwrap().get(&id).cloned(),
                local.has(&id)
            ),
            (Some(CapturedPayload { size: 0, grains }), false)
        );
    });
}

#[test]
fn read_only_content_workspace_refuses_before_payload_retention() {
    with_content(0, |content, local| {
        let grains = FileGrains::Inline(vec![]);
        let id = GrainId::of(&file_payload(0, &grains).unwrap());
        assert_eq!(
            (
                content
                    .remember_payload(id, 0, &grains)
                    .err()
                    .map(|e| e.to_string()),
                content.payloads.lock().unwrap().is_empty(),
                local.has(&id)
            ),
            (
                Some("intent refused: RecoveryResidualWorkspace".into()),
                true,
                false
            )
        );
        let node = granary_core::manifest::encode_dir_leaf(&[]).unwrap();
        assert_eq!(content.get(&GrainId::of(&node)).unwrap(), node);
    });
}

#[test]
fn read_closure_charges_objects_before_retaining_them() {
    let tree = PublishedTree::publish("v");
    let keys = TrustedKeys::new([*tree.key.public_key()]).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let paths = Paths::new();
    let local = crate::Store::open(&paths.store).unwrap();
    let bytes = granary_core::manifest::encode_dir_leaf(&[]).unwrap();
    let id = GrainId::of(&bytes);
    local.put(&id, &bytes).unwrap();
    let mut cases = 0;
    for remaining in [0, 16_777_216] {
        let budget = Budget::new(&(), remaining, None);
        let mut calls = 0;
        let result = runtime.block_on(preparation::read_closure_charged(
            &tree.remote,
            &local,
            &keys,
            &tree.volume,
            id,
            None,
            |n| {
                calls += 1;
                budget
                    .charge(n)
                    .map_err(|_| super::super::RecoveryError::Invalid("residual workspace"))
            },
        ));
        assert_eq!(
            (
                result
                    .as_ref()
                    .map(|objects| objects.retained.get(&id) == Some(&bytes))
                    .map_err(ToString::to_string),
                calls
            ),
            (
                if remaining == 0 {
                    Err("residual workspace".into())
                } else {
                    Ok(true)
                },
                1
            ),
            "{remaining}"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

fn local_namespace(
    tree: &PublishedTree,
    local: &crate::Store,
    bytes: &[u8],
    remaining: u64,
) -> Result<AuthenticatedNamespace, CoordinationError> {
    let manifest = GrainId::of(bytes);
    local.put(&manifest, bytes).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut doc = granary_core::root::decode_root(
        &rt.block_on(tree.remote.get_root("v", tree.seq))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    doc.manifest_root = manifest;
    doc.sigs.clear();
    doc.sigs.push(granary_core::root::RootSig {
        key_id: tree.key.key_id(),
        sig: tree
            .key
            .sign(&granary_core::root::signing_prefix_of(&doc).unwrap()),
    });
    let frozen = FrozenIntent {
        writer_identity: [1; 16],
        min_prefix_bits: 0,
        initial_root: granary_core::root::encode_root(&doc).unwrap(),
    };
    let keys = TrustedKeys::new([*tree.key.public_key()]).unwrap();
    let budget = Budget::new(&(), remaining, None);
    rt.block_on(namespace(
        &crate::overlay_test_support::Authority::new(
            tree,
            &std::sync::Arc::new(Mutex::new(
                crate::overlay_test_support::AuthorityState::default(),
            )),
        ),
        local,
        &keys,
        &tree.volume,
        &frozen,
        &[],
        &budget,
    ))
}

#[test]
fn residual_namespace_validates_a_24_mib_local_file() {
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let local = crate::Store::open(&paths.store).unwrap();
    let mut refs = Vec::new();
    for value in 0..3 {
        let bytes = vec![value; 8_388_608];
        let id = GrainId::of(&bytes);
        local.put(&id, &bytes).unwrap();
        refs.push(granary_core::manifest::GrainRef {
            id,
            unpacked_len: 8_388_608,
        });
    }
    let bytes = granary_core::manifest::encode_dir_leaf(&[granary_core::manifest::DirEntry {
        name: granary_core::manifest::Name::new(b"large".to_vec()).unwrap(),
        kind: granary_core::manifest::EntryKind::File {
            exec: false,
            size: 25_165_824,
            grains: FileGrains::Inline(refs),
        },
    }])
    .unwrap();
    let result = local_namespace(&tree, &local, &bytes, 16_777_216);
    assert_eq!(
        result
            .map(|namespace| {
                (
                    namespace.entries.len(),
                    namespace.entries.first().unwrap().size,
                )
            })
            .map_err(|e| e.to_string()),
        Ok((1, 25_165_824))
    );
}

#[test]
fn residual_namespace_over_budget_node_graph_has_its_own_refusal() {
    let tree = PublishedTree::publish("v");
    let paths = Paths::new();
    let local = crate::Store::open(&paths.store).unwrap();
    let bytes = granary_core::manifest::encode_dir_leaf(&[]).unwrap();
    let mut rows = Vec::new();
    for remaining in [0, 16_777_216] {
        rows.push((
            remaining,
            local_namespace(&tree, &local, &bytes, remaining)
                .map(|namespace| namespace.entries.len())
                .map_err(|e| e.to_string()),
        ));
    }
    assert_eq!(
        (&rows, rows.len()),
        (
            &vec![
                (0, Err("intent refused: RecoveryResidualWorkspace".into())),
                (16_777_216, Ok(0))
            ],
            2
        )
    );
}
