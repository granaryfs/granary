// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Authenticated ranges from the mediator-owned immutable object store.

use super::verified_range::VerifiedRangeCache;
use super::{ContentSource, OverlayError, OverlayIo, OverlayStore, OwnershipStatus, Store};
use crate::store::StoreError;
use granary_core::encoding::{Cursor, ObjectType, open_envelope};
use granary_core::hash::GrainId;
use granary_core::manifest::{self, EntryKind, FileGrains, GrainRef};
use std::sync::Arc;

pub(crate) struct LocalContent<'a> {
    store: &'a Store,
    payload: Option<(GrainId, u64, Arc<FileGrains>)>,
    memo: Option<&'a mut VerifiedRangeCache>,
    expected_size: Option<u64>,
    missing: Option<GrainId>,
}

impl<'a> LocalContent<'a> {
    pub(crate) fn new(store: &'a Store) -> Self {
        Self {
            store,
            payload: None,
            memo: None,
            expected_size: None,
            missing: None,
        }
    }

    pub(crate) fn with_cache(
        store: &'a Store,
        memo: &'a mut VerifiedRangeCache,
        expected_size: Option<u64>,
    ) -> Self {
        Self {
            store,
            payload: None,
            memo: Some(memo),
            expected_size,
            missing: None,
        }
    }

    pub(crate) const fn missing_id(&self) -> Option<GrainId> {
        self.missing
    }

    pub(crate) fn payload(
        &mut self,
        content: GrainId,
    ) -> Result<(u64, Arc<FileGrains>), OverlayError> {
        if let Some((id, size, grains)) = &self.payload
            && *id == content
        {
            return Ok((*size, grains.clone()));
        }
        if let Some((size, grains)) = self.memo.as_deref().and_then(|memo| memo.payload(content)) {
            if size > granary_core::overlay_journal::SIZE_MAX
                || self.expected_size.is_some_and(|expected| expected != size)
            {
                return Err(OverlayError::ContentCorrupt);
            }
            self.payload = Some((content, size, Arc::clone(&grains)));
            return Ok((size, grains));
        }
        let bytes = object(self.store, content, &mut self.missing)?;
        #[cfg(test)]
        METADATA_VISITS.with(|cell| {
            let (payloads, lists) = cell.get();
            cell.set((payloads + 1, lists));
        });
        // The stored content identity addresses the canonical file payload,
        // without a name or exec tag. Supply only that framing to the existing
        // strict leaf decoder; no separate payload accept predicate is needed.
        let mut body = 1u32.to_be_bytes().to_vec();
        body.extend_from_slice(&[1, b'f', manifest::node::ENTRY_TAG_FILE]);
        body.extend_from_slice(&bytes);
        let entries = manifest::decode_dir_leaf(Cursor::new(&body))
            .map_err(|_| OverlayError::ContentCorrupt)?;
        let EntryKind::File { size, grains, .. } =
            &entries.first().ok_or(OverlayError::ContentCorrupt)?.kind
        else {
            return Err(OverlayError::ContentCorrupt);
        };
        if *size > granary_core::overlay_journal::SIZE_MAX
            || self.expected_size.is_some_and(|expected| expected != *size)
        {
            return Err(OverlayError::ContentCorrupt);
        }
        let grains = Arc::new(grains.clone());
        self.payload = Some((content, *size, Arc::clone(&grains)));
        Ok((*size, grains))
    }
}

impl<P: OverlayIo> OverlayStore<P> {
    pub(crate) fn copy_up_local(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
        at: granary_core::overlay_journal::Location,
    ) -> Result<u64, OverlayError> {
        self.ready_to_serve(store, ownership)?;
        let size = self
            .namespace
            .entries
            .get(&super::state::path(&at))
            .ok_or_else(|| OverlayError::refused("copy-up missing"))?
            .size;
        let mut source = LocalContent::new(store);
        source.expected_size = Some(size);
        let content = self
            .namespace
            .entries
            .get(&super::state::path(&at))
            .and_then(|entry| match entry.kind {
                super::OverlayKind::File { content } => content,
                _ => None,
            })
            .ok_or_else(|| OverlayError::refused("copy-up content missing"))?;
        source.payload(content)?;
        self.ready(store, ownership)?;
        self.copy_up_ready(at, &mut source)
    }

    pub(crate) fn read_base_local(
        &mut self,
        store: &Store,
        ownership: &OwnershipStatus,
        path: &[manifest::Name],
        offset: u64,
        length: usize,
        memo: &mut VerifiedRangeCache,
    ) -> Result<Vec<u8>, OverlayError> {
        self.ready_to_serve(store, ownership)?;
        let size = self
            .namespace
            .entries
            .get(path)
            .ok_or_else(|| OverlayError::refused("base read missing"))?
            .size;
        let mut source = LocalContent::with_cache(store, memo, Some(size));
        self.ready(store, ownership)?;
        self.read_base_ready(path, offset, length, &mut source)
    }
}

impl ContentSource for LocalContent<'_> {
    fn read_verified(
        &mut self,
        content: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        if length > super::BUFFER {
            return Err(OverlayError::ContentCorrupt);
        }
        let (size, grains) = self.payload(content)?;
        if length == 0 {
            return Ok(Vec::new());
        }
        let end = offset
            .checked_add(length as u64)
            .ok_or(OverlayError::ContentCorrupt)?;
        if end > size {
            return Err(OverlayError::ContentCorrupt);
        }
        let mut output = Vec::with_capacity(length);
        match grains.as_ref() {
            FileGrains::Inline(refs) => {
                range_from_refs(
                    self.store,
                    &mut self.memo,
                    &mut self.missing,
                    refs,
                    size,
                    offset,
                    end,
                    &mut output,
                )?;
            }
            FileGrains::Spill { grain_count, root } => {
                range_from_list(
                    self.store,
                    &mut self.memo,
                    &mut self.missing,
                    *root,
                    u64::from(*grain_count),
                    size,
                    offset,
                    end,
                    1,
                    &mut output,
                )?;
            }
        }
        if output.len() != length {
            return Err(OverlayError::ContentCorrupt);
        }
        if let Some(memo) = self.memo.as_deref_mut() {
            memo.insert_payload(content, size, grains);
        }
        Ok(output)
    }
}

fn object(
    store: &Store,
    id: GrainId,
    missing: &mut Option<GrainId>,
) -> Result<Vec<u8>, OverlayError> {
    let result = store.get(&id).map_err(|error| match error {
        StoreError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
            *missing = Some(id);
            OverlayError::ContentUnavailable
        }
        StoreError::Io { source, .. } => OverlayError::Io(source),
        StoreError::Corrupt { .. } | StoreError::Incompatible { .. } | StoreError::Locked => {
            OverlayError::ContentCorrupt
        }
    });
    #[cfg(test)]
    LOCAL_READ_WORK.with(|cell| {
        let (reads, bytes) = cell.get();
        cell.set((reads + 1, bytes + result.as_ref().map_or(0, Vec::len)));
    });
    result
}

#[cfg(test)]
std::thread_local! {
    static LOCAL_READ_WORK: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
    static METADATA_VISITS: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

#[cfg(test)]
pub(crate) fn measure_metadata_visits<T>(action: impl FnOnce() -> T) -> (T, (usize, usize)) {
    let before = METADATA_VISITS.get();
    let answer = action();
    let after = METADATA_VISITS.get();
    (answer, (after.0 - before.0, after.1 - before.1))
}

#[cfg(test)]
pub(crate) fn measure_local_reads<T>(action: impl FnOnce() -> T) -> (T, (usize, usize)) {
    let before = LOCAL_READ_WORK.get();
    let answer = action();
    let after = LOCAL_READ_WORK.get();
    (answer, (after.0 - before.0, after.1 - before.1))
}

#[expect(
    clippy::too_many_arguments,
    reason = "one bounded inline range with memoized cache and missing-object tracking"
)]
fn range_from_refs(
    store: &Store,
    memo: &mut Option<&mut VerifiedRangeCache>,
    missing: &mut Option<GrainId>,
    refs: &[GrainRef],
    size: u64,
    offset: u64,
    end: u64,
    output: &mut Vec<u8>,
) -> Result<(), OverlayError> {
    let total = refs.iter().try_fold(0u64, |sum, r| {
        sum.checked_add(u64::from(r.unpacked_len))
            .ok_or(OverlayError::ContentCorrupt)
    })?;
    if total != size {
        return Err(OverlayError::ContentCorrupt);
    }
    let mut start = 0u64;
    for r in refs {
        let next = start
            .checked_add(u64::from(r.unpacked_len))
            .ok_or(OverlayError::ContentCorrupt)?;
        if start < end && next > offset {
            let bytes = if let Some(bytes) = memo
                .as_deref()
                .and_then(|memo| memo.grain(r.id, r.unpacked_len))
            {
                bytes
            } else {
                Arc::<[u8]>::from(object(store, r.id, missing)?)
            };
            if bytes.len() as u64 != u64::from(r.unpacked_len) {
                return Err(OverlayError::ContentCorrupt);
            }
            let from = usize::try_from(offset.saturating_sub(start))
                .map_err(|_| OverlayError::ContentCorrupt)?;
            let to =
                usize::try_from(end.min(next) - start).map_err(|_| OverlayError::ContentCorrupt)?;
            output.extend_from_slice(bytes.get(from..to).ok_or(OverlayError::ContentCorrupt)?);
            if let Some(memo) = memo.as_deref_mut() {
                memo.insert_grain(r.id, r.unpacked_len, bytes);
            }
        }
        start = next;
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "one bounded range with the pinned parent aggregates and tree depth"
)]
fn range_from_list(
    store: &Store,
    memo: &mut Option<&mut VerifiedRangeCache>,
    missing: &mut Option<GrainId>,
    id: GrainId,
    count: u64,
    size: u64,
    offset: u64,
    end: u64,
    depth: u32,
    output: &mut Vec<u8>,
) -> Result<(), OverlayError> {
    if depth > manifest::DEPTH_MAX {
        return Err(OverlayError::ContentCorrupt);
    }
    let bytes = if let Some(bytes) = memo.as_deref().and_then(|memo| memo.list(id)) {
        bytes
    } else {
        Arc::<[u8]>::from(object(store, id, missing)?)
    };
    let (kind, cursor) = open_envelope(&bytes).map_err(|_| OverlayError::ContentCorrupt)?;
    #[cfg(test)]
    METADATA_VISITS.with(|cell| {
        let (payloads, lists) = cell.get();
        cell.set((payloads, lists + 1));
    });
    let result = match kind {
        ObjectType::GrainListLeaf => {
            let refs = manifest::decode_grain_list_leaf(cursor)
                .map_err(|_| OverlayError::ContentCorrupt)?;
            if refs.len() as u64 != count {
                return Err(OverlayError::ContentCorrupt);
            }
            range_from_refs(store, memo, missing, &refs, size, offset, end, output)
        }
        ObjectType::GrainListIndex => {
            let children = manifest::decode_grain_list_index(cursor)
                .map_err(|_| OverlayError::ContentCorrupt)?;
            if children
                .first()
                .is_none_or(|c| c.cum_ref_count == 0 || c.cum_unpacked_len == 0)
            {
                return Err(OverlayError::ContentCorrupt);
            }
            if children
                .last()
                .map(|c| (c.cum_ref_count, c.cum_unpacked_len))
                != Some((count, size))
            {
                return Err(OverlayError::ContentCorrupt);
            }
            let (mut start, mut previous_count) = (0, 0);
            for child in children {
                if start < end && child.cum_unpacked_len > offset {
                    range_from_list(
                        store,
                        memo,
                        missing,
                        child.child,
                        child
                            .cum_ref_count
                            .checked_sub(previous_count)
                            .ok_or(OverlayError::ContentCorrupt)?,
                        child
                            .cum_unpacked_len
                            .checked_sub(start)
                            .ok_or(OverlayError::ContentCorrupt)?,
                        offset.saturating_sub(start),
                        end.min(child.cum_unpacked_len) - start,
                        depth + 1,
                        output,
                    )?;
                }
                start = child.cum_unpacked_len;
                previous_count = child.cum_ref_count;
            }
            Ok(())
        }
        _ => Err(OverlayError::ContentCorrupt),
    };
    if result.is_ok()
        && let Some(memo) = memo.as_deref_mut()
    {
        memo.insert_list(id, bytes);
    }
    result
}
