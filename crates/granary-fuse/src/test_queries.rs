// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Owned directory queries for mutable adapter and opcode fixtures.

use crate::{OverlayChildren, OverlayDirectory, OverlayMetadata, OverlayNode, WriteError};
use granary_core::manifest::Name;
use granary_vfs::NodeKind;
use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

pub(crate) type Cursor = (Vec<Name>, Option<Name>);

pub(crate) fn path(
    nodes: &BTreeMap<Vec<Name>, OverlayNode>,
    path: &[Name],
) -> Result<OverlayMetadata, WriteError> {
    let node = nodes.get(path).ok_or(WriteError::Missing)?;
    let nlink = if node.kind == NodeKind::Dir {
        let count = nodes
            .range((Excluded(path.to_vec()), Unbounded))
            .take_while(|(key, _)| key.starts_with(path))
            .filter(|(key, child)| key.len() == path.len() + 1 && child.kind == NodeKind::Dir)
            .count();
        2u32.checked_add(u32::try_from(count).map_err(|_| WriteError::Invalid)?)
            .ok_or(WriteError::Invalid)?
    } else {
        1
    };
    Ok(OverlayMetadata {
        inode: node.stage.unwrap_or(0),
        node: node.clone(),
        nlink,
    })
}

pub(crate) fn lookup(
    nodes: &BTreeMap<Vec<Name>, OverlayNode>,
    parent: &[Name],
    name: &Name,
) -> Result<OverlayMetadata, WriteError> {
    if nodes.get(parent).ok_or(WriteError::Missing)?.kind != NodeKind::Dir {
        return Err(WriteError::NotDirectory);
    }
    let mut child = parent.to_vec();
    child.push(name.clone());
    path(nodes, &child)
}

pub(crate) fn directory(
    nodes: &BTreeMap<Vec<Name>, OverlayNode>,
    directory_path: &[Name],
) -> Result<OverlayDirectory<Cursor>, WriteError> {
    let directory = path(nodes, directory_path)?;
    if directory.node.kind != NodeKind::Dir {
        return Err(WriteError::NotDirectory);
    }
    let mut parent = directory_path.to_vec();
    parent.pop();
    Ok(OverlayDirectory {
        directory,
        parent: path(nodes, &parent)?,
        cursor: (directory_path.to_vec(), None),
    })
}

pub(crate) fn children(
    nodes: &BTreeMap<Vec<Name>, OverlayNode>,
    cursor: &Cursor,
) -> Result<OverlayChildren<Cursor>, WriteError> {
    let (parent, after) = cursor;
    let mut start = parent.clone();
    if let Some(after) = after {
        start.push(after.clone());
    }
    let mut candidates = nodes
        .range((Excluded(start), Unbounded))
        .take_while(|(key, _)| key.starts_with(parent))
        .filter(|(key, _)| key.len() == parent.len() + 1);
    let mut entries = Vec::new();
    for (key, _) in candidates.by_ref().take(256) {
        entries.push(path(nodes, key)?);
    }
    let next = if candidates.next().is_some() {
        Some((
            parent.clone(),
            entries.last().and_then(|e| e.node.path.last()).cloned(),
        ))
    } else {
        None
    };
    Ok(OverlayChildren { entries, next })
}
