// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{OverlayEntry, OverlayKind, SyncRuntime, TokioSyncRuntime};
use granary_core::manifest::{DirEntry, EntryKind, FileGrains, Name};
use std::collections::BTreeMap;

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

impl SyncContent for Nodes {
    fn payload(&self, _: GrainId) -> Result<FileGrains, CoordinationError> {
        Err(refused("SyncFixturePayload"))
    }
    fn read_content(&self, _: GrainId, _: u64, _: usize) -> Result<Vec<u8>, crate::OverlayError> {
        Err(crate::OverlayError::ContentUnavailable)
    }
    fn put_object(&self, _: GrainId, _: &[u8]) -> Result<(), CoordinationError> {
        Ok(())
    }
    fn remember_payload(
        &self,
        _: GrainId,
        _: u64,
        _: &FileGrains,
    ) -> Result<(), CoordinationError> {
        Ok(())
    }
}

#[test]
fn landed_entries_preserve_only_same_kind_inodes_and_follow_manifest_paths() {
    let name = |s: &str| Name::new(s.as_bytes().to_vec()).unwrap();
    let file = EntryKind::File {
        exec: true,
        size: 0,
        grains: FileGrains::Inline(vec![]),
    };
    let tree = granary_core::manifest::build_dir(&[
        DirEntry {
            name: name("added"),
            kind: file.clone(),
        },
        DirEntry {
            name: name("changed"),
            kind: file.clone(),
        },
        DirEntry {
            name: name("shared"),
            kind: file,
        },
    ])
    .unwrap();
    let entries = [
        OverlayEntry {
            path: vec![name("changed")],
            inode: 40,
            kind: OverlayKind::Directory,
            stage_id: None,
            size: 0,
            exec: false,
        },
        OverlayEntry {
            path: vec![name("removed")],
            inode: 41,
            kind: OverlayKind::Directory,
            stage_id: None,
            size: 0,
            exec: false,
        },
        OverlayEntry {
            path: vec![name("shared")],
            inode: 42,
            kind: OverlayKind::File { content: None },
            stage_id: Some(3),
            size: 99,
            exec: false,
        },
    ];
    let source = Nodes(tree.nodes.into_iter().collect());
    let landed = build_landed_entries(tree.root, &entries, &source).unwrap();
    assert_eq!(
        landed
            .iter()
            .map(|e| (e.path.clone(), e.inode, e.stage_id, e.size, e.exec))
            .collect::<Vec<_>>(),
        vec![
            (vec![name("added")], 0, None, 0, true),
            (vec![name("changed")], 0, None, 0, true),
            (vec![name("shared")], 42, None, 0, true)
        ]
    );
    assert!(
        landed
            .iter()
            .all(|e| matches!(e.kind, OverlayKind::File { content: Some(_) }))
    );
}

#[test]
fn landed_entry_build_is_not_quadratic_in_entries() {
    let names: Vec<Name> = (0..30_000_u32)
        .map(|i| Name::new(format!("f{i:06}").into_bytes()).unwrap())
        .collect();
    let dir: Vec<DirEntry> = names
        .iter()
        .map(|name| DirEntry {
            name: name.clone(),
            kind: EntryKind::File {
                exec: false,
                size: 0,
                grains: FileGrains::Inline(Vec::new()),
            },
        })
        .collect();
    let tree = granary_core::manifest::build_dir(&dir).unwrap();
    let source = Nodes(tree.nodes.into_iter().collect());
    let mut entries: Vec<OverlayEntry> = names
        .iter()
        .enumerate()
        .map(|(inode, name)| OverlayEntry {
            path: vec![name.clone()],
            inode: inode as u64 + 1,
            kind: OverlayKind::File { content: None },
            stage_id: Some(1),
            size: 0,
            exec: false,
        })
        .collect();
    entries.reverse();
    let started = TokioSyncRuntime.now();
    let entries = build_landed_entries(tree.root, &entries, &source).unwrap();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(3),
        "landed entry build scanned every entry per leaf"
    );
    assert!(entries.iter().all(|entry| {
        entry.stage_id.is_none() && matches!(entry.kind, OverlayKind::File { content: Some(_) })
    }));
}
