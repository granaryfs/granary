// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Byte-offset read planning over inline and spilled grain lists.

use alloc::vec;
use alloc::vec::Vec;
use granary_core::encoding::{self, ObjectType};
use granary_core::hash::GrainId;
use granary_core::manifest::{self, FileGrains, GrainListIndexChild, GrainRef};

use crate::{GrainFetch, ReaderError, Snapshot};

/// One grain's contribution to one `read`: fetch `id`, then copy
/// `[skip, skip + take)` of its decompressed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrainSlice {
    pub id: GrainId,
    /// What the manifest declares this grain's decompressed length to be.
    pub unpacked_len: u32,
    pub skip: u32,
    pub take: u32,
}

/// The most grains one `read` may touch. A caller's read cannot be
/// answered SHORT if its transport zero-fills an unanswered remainder
/// (FUSE does) — that would be silent corruption — so a request this
/// reader cannot serve completely must FAIL rather than return less.
/// That makes "how many grains can one read span" a resource question,
/// and this is the answer: a hostile manifest of one-byte grains would
/// otherwise turn a single 1 MiB read into a million fetches. No
/// manifest granary's own chunker produces comes near it.
pub const READ_MAX_GRAINS: usize = 4096;

/// The most bytes one `read` may be asked for.
///
/// `READ_MAX_GRAINS` bounds how many GRAINS a read may span; it does not
/// bound the byte length at all — 4096 grains of `GRAIN_UNPACKED_MAX`
/// (8 MiB) is 32 GiB, and `read_at` sizes its output buffer from `size`
/// BEFORE fetching anything, so a `size` of `u32::MAX` asks for a ~4 GiB
/// zeroed allocation up front. The house invariant is length-bounded
/// BEFORE allocation: never size a buffer from an attacker-controlled
/// field.
///
/// The kernel's own `max_read`/`max_pages` negotiation would normally bound this —
/// but it lives outside this crate, the adapter's `session_config`
/// (`granary-fuse`'s `options.rs`) does not set it, and a reader must
/// not depend on a limit its caller may never have configured.
/// So the reader carries its own, well above any read size a
/// well-behaved caller would ask for, and far below a figure that can
/// exhaust a mount.
///
/// Refusing rather than truncating is forced: a caller that cannot tell
/// a short read from a truncated file must never receive one (FUSE is
/// one such caller — the kernel zero-fills an unanswered remainder).
pub const READ_MAX_BYTES: u32 = 16 * 1024 * 1024;

fn checked_u32(value: u64) -> Result<u32, ReaderError> {
    u32::try_from(value).map_err(|_| ReaderError::Inconsistent)
}

fn append_refs(
    refs: &[GrainRef],
    offset: u64,
    mut remaining: u64,
    plan: &mut Vec<GrainSlice>,
) -> Result<u64, ReaderError> {
    let mut grain_start = 0_u64;
    let mut position = offset;
    for grain_ref in refs {
        if remaining == 0 {
            break;
        }
        let grain_len = u64::from(grain_ref.unpacked_len);
        let grain_end = grain_start
            .checked_add(grain_len)
            .ok_or(ReaderError::Inconsistent)?;
        if grain_end <= position {
            grain_start = grain_end;
            continue;
        }
        let skip = checked_u32(
            position
                .checked_sub(grain_start)
                .ok_or(ReaderError::Inconsistent)?,
        )?;
        let available = grain_ref
            .unpacked_len
            .checked_sub(skip)
            .ok_or(ReaderError::Inconsistent)?;
        let take = checked_u32(remaining.min(u64::from(available)))?;
        let next_len = plan
            .len()
            .checked_add(1)
            .ok_or(ReaderError::ReadTooFragmented)?;
        if next_len > READ_MAX_GRAINS {
            return Err(ReaderError::ReadTooFragmented);
        }
        plan.push(GrainSlice {
            id: grain_ref.id,
            unpacked_len: grain_ref.unpacked_len,
            skip,
            take,
        });
        remaining = remaining
            .checked_sub(u64::from(take))
            .ok_or(ReaderError::Inconsistent)?;
        position = position
            .checked_add(u64::from(take))
            .ok_or(ReaderError::Inconsistent)?;
        grain_start = grain_end;
    }
    Ok(remaining)
}

fn exact_inline_plan(
    refs: &[GrainRef],
    offset: u64,
    want: u64,
) -> Result<Vec<GrainSlice>, ReaderError> {
    let mut plan = Vec::new();
    let remaining = append_refs(refs, offset, want, &mut plan)?;
    if remaining == 0 {
        Ok(plan)
    } else {
        Err(ReaderError::Inconsistent)
    }
}

#[derive(Debug)]
struct GrainIndexFrame {
    children: Vec<GrainListIndexChild>,
    next_child: usize,
    base: u64,
}

struct GrainCursor<'a> {
    snapshot: &'a Snapshot,
    stack: Vec<GrainIndexFrame>,
    leaf: Vec<GrainRef>,
    leaf_base: u64,
}

/// An index node's own end, checked against what its PARENT declared for it.
///
/// **What this pair of checks cannot see.** They validate the nodes on the
/// path the offset actually takes. A node that lies about the SPLIT between
/// two of its children — leaving the total honest — puts the selected
/// subtree at a shifted base whose real extent then matches the equally
/// shifted declaration, and the read returns a byte from the wrong leaf. Real
/// lengths 10/20/10 with declared cumulatives 5/25/40 is the shape: a read at
/// offset 7 lands in the second leaf, whose real end of 25 equals its
/// declared end, and the lie lives in a sibling the seek never visits.
/// Detecting it needs every child's real extent, which for an index child
/// means walking its whole subtree — `O(fanout x depth)` decodes, which would
/// turn `spill_seek_decodes_depth_not_offset` red and give up the O(depth)
/// seek. The complete guard is `validate_dir_tree`'s `CumulativeMismatch` in
/// the caller's preamble, or an index-time walk of the grain-list trees that
/// `Snapshot::new` does not do. Register row.
///
/// The descent navigates by `cum_unpacked_len`, so a node that overstates a
/// child's extent routes a read into the next leaf and serves a byte that
/// belongs to a different offset — with no error, which is the failure that
/// arrives looking like success. `declared_end` is the extent the parent
/// promised for this subtree; for the spill ROOT there is no parent and so
/// nothing to compare against. Equality is the invariant, not an upper
/// bound: `cum_unpacked_len` is cumulative THROUGH a child, so child `k`'s
/// extent is exactly `cum[k] - cum[k-1]`.
fn check_index_end(
    children: &[GrainListIndexChild],
    base: u64,
    declared_end: Option<u64>,
) -> Result<(), ReaderError> {
    let total = children
        .last()
        .map(|child| child.cum_unpacked_len)
        .ok_or(ReaderError::Inconsistent)?;
    let end = base.checked_add(total).ok_or(ReaderError::Inconsistent)?;
    if declared_end.is_some_and(|promised| promised != end) {
        return Err(ReaderError::Inconsistent);
    }
    Ok(())
}

/// A grain-list LEAF's real extent, checked against what its parent declared.
/// Same contract as [`check_index_end`], one level down: this is the check
/// that catches a lie about a leaf, and the two are deliberately separate so
/// that neither can mask the other.
fn check_leaf_end(
    refs: &[GrainRef],
    base: u64,
    declared_end: Option<u64>,
) -> Result<(), ReaderError> {
    let end = checked_refs_end(refs, base)?;
    if declared_end.is_some_and(|promised| promised != end) {
        return Err(ReaderError::Inconsistent);
    }
    Ok(())
}

fn checked_refs_end(refs: &[GrainRef], base: u64) -> Result<u64, ReaderError> {
    refs.iter().try_fold(base, |end, grain_ref| {
        end.checked_add(u64::from(grain_ref.unpacked_len))
            .ok_or(ReaderError::Inconsistent)
    })
}

impl<'a> GrainCursor<'a> {
    fn seek(
        snapshot: &'a Snapshot,
        root: &GrainId,
        offset: u64,
        declared_size: u64,
    ) -> Result<Self, ReaderError> {
        let mut current = *root;
        let mut base = 0_u64;
        let mut depth = 1_u32;
        let mut stack = Vec::new();
        // The spill ROOT has no parent — but the entry that names it does
        // declare the file's size, and `validate_dir_tree` makes "tree total
        // equals declared size" an invariant, so the size is the root's
        // declaration. Without this the root is the one node in the whole
        // descent whose extent nothing compares.
        let mut declared_end: Option<u64> = Some(declared_size);
        loop {
            if depth > manifest::DEPTH_MAX {
                return Err(ReaderError::Inconsistent);
            }
            let bytes = snapshot.structure_node(&current)?;
            #[cfg(test)]
            crate::snapshot::bump_decode_for_read();
            let (object_type, cursor) =
                encoding::open_envelope(bytes).map_err(|_| ReaderError::Inconsistent)?;
            match object_type {
                ObjectType::GrainListLeaf => {
                    let leaf = manifest::decode_grain_list_leaf(cursor)
                        .map_err(|_| ReaderError::Inconsistent)?;
                    check_leaf_end(&leaf, base, declared_end)?;
                    return Ok(Self {
                        snapshot,
                        stack,
                        leaf,
                        leaf_base: base,
                    });
                }
                ObjectType::GrainListIndex => {
                    let children = manifest::decode_grain_list_index(cursor)
                        .map_err(|_| ReaderError::Inconsistent)?;
                    check_index_end(&children, base, declared_end)?;
                    let relative = offset.checked_sub(base).ok_or(ReaderError::Inconsistent)?;
                    let mut previous = 0_u64;
                    let mut selected = None;
                    for (position, child) in children.iter().enumerate() {
                        if child.cum_unpacked_len > relative {
                            let child_base = base
                                .checked_add(previous)
                                .ok_or(ReaderError::Inconsistent)?;
                            let next_child =
                                position.checked_add(1).ok_or(ReaderError::Inconsistent)?;
                            let child_end = base
                                .checked_add(child.cum_unpacked_len)
                                .ok_or(ReaderError::Inconsistent)?;
                            selected = Some((child.child, child_base, next_child, child_end));
                            break;
                        }
                        previous = child.cum_unpacked_len;
                    }
                    let (child, child_base, next_child, child_end) =
                        selected.ok_or(ReaderError::Inconsistent)?;
                    stack.push(GrainIndexFrame {
                        children,
                        next_child,
                        base,
                    });
                    current = child;
                    base = child_base;
                    declared_end = Some(child_end);
                    depth = depth.checked_add(1).ok_or(ReaderError::Inconsistent)?;
                }
                _ => return Err(ReaderError::Inconsistent),
            }
        }
    }

    fn advance_leaf(&mut self) -> Result<bool, ReaderError> {
        loop {
            let next = if let Some(frame) = self.stack.last_mut() {
                let position = frame.next_child;
                let child = frame.children.get(position).copied();
                if child.is_some() {
                    frame.next_child = frame
                        .next_child
                        .checked_add(1)
                        .ok_or(ReaderError::Inconsistent)?;
                }
                let previous = position
                    .checked_sub(1)
                    .and_then(|previous_position| frame.children.get(previous_position))
                    .map_or(0, |previous_child| previous_child.cum_unpacked_len);
                child.map(|child| (child.child, frame.base, previous, child.cum_unpacked_len))
            } else {
                return Ok(false);
            };
            if let Some((child, parent_base, previous, cumulative)) = next {
                let child_base = parent_base
                    .checked_add(previous)
                    .ok_or(ReaderError::Inconsistent)?;
                let child_end = parent_base
                    .checked_add(cumulative)
                    .ok_or(ReaderError::Inconsistent)?;
                let depth = u32::try_from(self.stack.len())
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or(ReaderError::Inconsistent)?;
                self.descend_first(child, child_base, depth, Some(child_end))?;
                return Ok(true);
            }
            let _finished = self.stack.pop();
        }
    }

    fn descend_first(
        &mut self,
        mut current: GrainId,
        base: u64,
        mut depth: u32,
        mut declared_end: Option<u64>,
    ) -> Result<(), ReaderError> {
        loop {
            if depth > manifest::DEPTH_MAX {
                return Err(ReaderError::Inconsistent);
            }
            let bytes = self.snapshot.structure_node(&current)?;
            #[cfg(test)]
            crate::snapshot::bump_decode_for_read();
            let (object_type, cursor) =
                encoding::open_envelope(bytes).map_err(|_| ReaderError::Inconsistent)?;
            match object_type {
                ObjectType::GrainListLeaf => {
                    let leaf = manifest::decode_grain_list_leaf(cursor)
                        .map_err(|_| ReaderError::Inconsistent)?;
                    check_leaf_end(&leaf, base, declared_end)?;
                    self.leaf = leaf;
                    self.leaf_base = base;
                    return Ok(());
                }
                ObjectType::GrainListIndex => {
                    let children = manifest::decode_grain_list_index(cursor)
                        .map_err(|_| ReaderError::Inconsistent)?;
                    check_index_end(&children, base, declared_end)?;
                    let child = children.first().copied().ok_or(ReaderError::Inconsistent)?;
                    self.stack.push(GrainIndexFrame {
                        children,
                        next_child: 1,
                        base,
                    });
                    // The first child starts at this node's own base, so
                    // its declared extent is its own cumulative length.
                    declared_end = Some(
                        base.checked_add(child.cum_unpacked_len)
                            .ok_or(ReaderError::Inconsistent)?,
                    );
                    current = child.child;
                    depth = depth.checked_add(1).ok_or(ReaderError::Inconsistent)?;
                }
                _ => return Err(ReaderError::Inconsistent),
            }
        }
    }
}

fn exact_spill_plan(
    snapshot: &Snapshot,
    root: &GrainId,
    offset: u64,
    want: u64,
    declared_size: u64,
) -> Result<Vec<GrainSlice>, ReaderError> {
    let mut plan = Vec::new();
    if want == 0 {
        return Ok(plan);
    }
    let mut cursor = GrainCursor::seek(snapshot, root, offset, declared_size)?;
    let selected_leaf_end = checked_refs_end(&cursor.leaf, cursor.leaf_base)?;
    if selected_leaf_end <= offset {
        return Err(ReaderError::Inconsistent);
    }
    let mut position = offset;
    let mut remaining = want;
    loop {
        let leaf_offset = position
            .checked_sub(cursor.leaf_base)
            .ok_or(ReaderError::Inconsistent)?;
        let before = remaining;
        remaining = append_refs(&cursor.leaf, leaf_offset, remaining, &mut plan)?;
        let consumed = before
            .checked_sub(remaining)
            .ok_or(ReaderError::Inconsistent)?;
        position = position
            .checked_add(consumed)
            .ok_or(ReaderError::Inconsistent)?;
        if remaining == 0 {
            return Ok(plan);
        }
        if !cursor.advance_leaf()? {
            return Err(ReaderError::Inconsistent);
        }
        if cursor.leaf_base != position {
            return Err(ReaderError::Inconsistent);
        }
    }
}

impl Snapshot {
    /// Plans which grain ranges contribute to a byte-offset read.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError`] when the grain list disagrees with the
    /// previously validated file declaration or exceeds a reader bound.
    pub fn read_plan(
        &self,
        grains: &FileGrains,
        declared_size: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<GrainSlice>, ReaderError> {
        if offset >= declared_size {
            return Ok(Vec::new());
        }
        let want = u64::from(size).min(
            declared_size
                .checked_sub(offset)
                .ok_or(ReaderError::Inconsistent)?,
        );
        match grains {
            FileGrains::Inline(refs) => exact_inline_plan(refs, offset, want),
            FileGrains::Spill { root, .. } => {
                exact_spill_plan(self, root, offset, want, declared_size)
            }
        }
    }

    /// Reads one complete byte range through a synchronous grain source.
    ///
    /// # Errors
    ///
    /// Returns [`ReaderError`] if planning fails, a grain is unavailable, or
    /// fetched bytes disagree with the manifest declaration.
    pub fn read_at(
        &self,
        fetch: &mut dyn GrainFetch,
        grains: &FileGrains,
        declared_size: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, ReaderError> {
        // BEFORE the allocation, and before `offset >= declared_size` can
        // make this look harmless: an oversized `size` is refused outright
        // rather than clamped, because clamping would answer a read SHORT
        // and the kernel zero-fills the remainder.
        if size > READ_MAX_BYTES {
            return Err(ReaderError::ReadTooLarge);
        }
        if offset >= declared_size {
            return Ok(Vec::new());
        }
        let want = u64::from(size).min(
            declared_size
                .checked_sub(offset)
                .ok_or(ReaderError::Inconsistent)?,
        );
        let plan = self.read_plan(grains, declared_size, offset, size)?;
        let capacity = usize::try_from(want).map_err(|_| ReaderError::Inconsistent)?;
        let mut output = vec![0_u8; capacity];
        let mut written = 0_usize;
        for slice in plan {
            let grain = fetch
                .grain(&slice.id, slice.unpacked_len)
                .map_err(|_| ReaderError::GrainUnavailable)?;
            let declared_len =
                usize::try_from(slice.unpacked_len).map_err(|_| ReaderError::Inconsistent)?;
            if grain.len() != declared_len {
                return Err(ReaderError::Inconsistent);
            }
            let start = usize::try_from(slice.skip).map_err(|_| ReaderError::Inconsistent)?;
            let end_u32 = slice
                .skip
                .checked_add(slice.take)
                .ok_or(ReaderError::Inconsistent)?;
            let end = usize::try_from(end_u32).map_err(|_| ReaderError::Inconsistent)?;
            let bytes = grain.get(start..end).ok_or(ReaderError::Inconsistent)?;
            let output_end = written
                .checked_add(bytes.len())
                .ok_or(ReaderError::Inconsistent)?;
            let target = output
                .get_mut(written..output_end)
                .ok_or(ReaderError::Inconsistent)?;
            target.copy_from_slice(bytes);
            written = output_end;
            drop(grain);
        }
        if written != capacity {
            return Err(ReaderError::Inconsistent);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests;
