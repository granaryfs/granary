// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::{Arc, BTreeSet, CommitWalk, GrainId, follows, verify_commit_entries};
use crate::{OverlayEntry, OverlayKind, SyncRuntime as _};
use granary_core::grainsource::{GrainSource, GrainSourceError};
use granary_core::manifest::{self, DirEntry, EntryKind, FileGrains, GrainRef, Name};
use std::collections::BTreeMap;

#[test]
fn initial_candidate_landing_refuses_a_missing_lane_path() {
    let entry = |path: &str, inode| OverlayEntry {
        path: vec![Name::new(path.as_bytes().to_vec()).unwrap()],
        inode,
        kind: OverlayKind::Directory,
        stage_id: None,
        size: 0,
        exec: false,
    };
    let lane = super::RetainedCommit {
        serial: 1,
        instance: [0; 16],
        publication: [0; 16],
        boundary: 1,
        projected: false,
        entries: vec![entry("one", 1), entry("two", 2)],
        charge: 0,
        deadline: crate::TokioSyncRuntime.now(),
        mapped: None,
        observation: Arc::default(),
        operation_id: None,
        recovered: false,
    };
    let mut proof = crate::LandedProof {
        boundary_seq: 1,
        landed_root: GrainId::of(b"landed"),
        landed_seq: 2,
        captured_entries: lane.entries.clone(),
        entries: lane.entries.clone(),
    };
    lane.check_landed_namespace(&proof, false).unwrap();
    proof.entries.pop();
    assert_eq!(
        lane.check_landed_namespace(&proof, false)
            .unwrap_err()
            .to_string(),
        "intent refused: SyncCommitLandingIdentity"
    );
}

#[test]
fn landed_namespace_checks_shared_identities_and_unstaged_unique_paths() {
    use super::RetainedCommit;
    let entry = |name: &str, inode, kind| OverlayEntry {
        path: vec![Name::new(name.as_bytes().to_vec()).unwrap()],
        inode,
        kind,
        stage_id: None,
        size: 0,
        exec: false,
    };
    let file = OverlayKind::File {
        content: Some(GrainId::of(b"payload")),
    };
    let lane = RetainedCommit {
        serial: 1,
        instance: [0; 16],
        publication: [0; 16],
        boundary: 1,
        projected: false,
        entries: vec![
            entry("shared", 8, file.clone()),
            entry("changed", 9, OverlayKind::Directory),
            entry("deleted", 10, file.clone()),
        ],
        charge: 0,
        deadline: crate::TokioSyncRuntime.now(),
        mapped: None,
        observation: Arc::default(),
        operation_id: None,
        recovered: false,
    };
    let proof = crate::LandedProof {
        boundary_seq: 1,
        landed_root: GrainId::of(b"landed"),
        landed_seq: 3,
        captured_entries: lane.entries.clone(),
        entries: vec![
            entry("shared", 8, file.clone()),
            entry("changed", 0, file.clone()),
            entry("remote", 0, file),
        ],
    };
    lane.check_landed_namespace(&proof, true).unwrap();
    for case in [
        "changed shared inode",
        "staged",
        "unresolved file",
        "duplicate path",
    ] {
        let mut malformed = proof.clone();
        match case {
            "changed shared inode" => malformed.entries[0].inode = 80,
            "staged" => malformed.entries[0].stage_id = Some(1),
            "unresolved file" => malformed.entries[0].kind = OverlayKind::File { content: None },
            _ => malformed.entries.push(malformed.entries[0].clone()),
        }
        assert!(
            matches!(
                lane.check_landed_namespace(&malformed, true),
                Err(crate::CoordinationError::Refused(
                    "SyncCommitLandingIdentity"
                ))
            ),
            "{case}"
        );
    }
}

#[test]
fn a_parent_at_the_seq_ceiling_has_no_successor() {
    assert!(follows(4, 5));
    assert!(!follows(4, 6));
    assert!(!follows(u64::MAX, 0));
    assert!(!follows(u64::MAX, u64::MAX));
}

struct Nodes(BTreeMap<GrainId, Vec<u8>>);
impl GrainSource for Nodes {
    fn has(&self, id: &GrainId) -> bool {
        self.0.contains_key(id)
    }
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(GrainSourceError::Missing(*id))
    }
}
fn name(s: &str) -> Name {
    Name::new(s.as_bytes().to_vec()).unwrap()
}

/// `f` (one inline grain), and `d/s` (a spilled grain list of 130 grains).
fn landed() -> (GrainId, Nodes, Vec<OverlayEntry>) {
    let mut objects = BTreeMap::new();
    let mut grain = |bytes: Vec<u8>| {
        let id = GrainId::of(&bytes);
        objects.insert(id, bytes.clone());
        GrainRef {
            id,
            unpacked_len: u32::try_from(bytes.len()).unwrap(),
        }
    };
    let inline = FileGrains::Inline(vec![grain(b"inline".to_vec())]);
    let refs: Vec<GrainRef> = (0..130_u8).map(|i| grain(vec![i])).collect();
    let list = manifest::build_grain_list(&refs).unwrap();
    objects.extend(list.nodes);
    let spill = FileGrains::Spill {
        grain_count: 130,
        root: list.root,
    };
    let file = |name: Name, size: u64, grains: &FileGrains| DirEntry {
        name,
        kind: EntryKind::File {
            exec: false,
            size,
            grains: grains.clone(),
        },
    };
    let inner = manifest::build_dir(&[file(name("s"), 130, &spill)]).unwrap();
    objects.extend(inner.nodes);
    let top = manifest::build_dir(&[
        DirEntry {
            name: name("d"),
            kind: EntryKind::Dir { child: inner.root },
        },
        file(name("f"), 6, &inline),
    ])
    .unwrap();
    objects.extend(top.nodes);
    let entry = |path: Vec<Name>, kind: OverlayKind, size: u64| OverlayEntry {
        path,
        inode: 0,
        kind,
        stage_id: None,
        size,
        exec: false,
    };
    let content = |size: u64, grains: &FileGrains| OverlayKind::File {
        content: Some(GrainId::of(
            &manifest::node::file_payload(size, grains).unwrap(),
        )),
    };
    let expected = vec![
        entry(vec![name("d")], OverlayKind::Directory, 0),
        entry(vec![name("d"), name("s")], content(130, &spill), 130),
        entry(vec![name("f")], content(6, &inline), 6),
    ];
    (top.root, Nodes(objects), expected)
}

#[test]
fn a_landed_walk_refuses_any_object_its_binmap_does_not_resolve() {
    let (root, source, expected) = landed();
    let every: BTreeSet<GrainId> = source.0.keys().copied().collect();
    let walk = verify_commit_entries(root, &expected, &source, Some(&every))
        .unwrap_or_else(|e| panic!("a fully mapped closure was refused: {e}"));
    let _: CommitWalk = walk;
    assert!(verify_commit_entries(root, &expected, &source, None).is_ok());
    // Dropping any one object from the binmap must be caught: directory
    // nodes, the spill root and a grain-list node, and inline and listed grains.
    for gone in &every {
        let mut mapped = every.clone();
        mapped.remove(gone);
        let error = verify_commit_entries(root, &expected, &source, Some(&mapped))
            .err()
            .unwrap_or_else(|| panic!("an unmapped object {gone} was accepted"));
        assert!(
            matches!(
                error,
                super::CoordinationError::Refused("SyncCommitContainment")
            ),
            "wrong refusal for {gone}: {error}"
        );
    }
}
