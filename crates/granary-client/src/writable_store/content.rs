// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Clean-content generation, admitted base observation, and the mediated
//! [`ImmutableContent`] facade over the single [`Store`] and `VerifiedRangeCache`.

use super::{CoordinationError, OverlayError, OverlayIo, Store, WritableStore, refused};
use crate::overlay_store::{
    ContentSource as _, local_content::LocalContent, verified_range::VerifiedRangeCache,
};
use granary_core::{
    binmap::ShardEntry,
    grainsource::{GrainSource, GrainSourceError},
    hash::GrainId,
    intent,
    manifest::{self, FileGrains},
};
use std::{collections::BTreeMap, sync::Arc};

/// Admitted base pin and clean-content cache generation observed from the mediator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountViewContext {
    pub base_id: GrainId,
    pub base_seq: u64,
    pub generation: u64,
}

/// The view a writable mount serves: its pinned base and the material every
/// clean read resolves through. The mediator holds the only copy
/// ([`WritableStore::mount_pin`]), and every reader takes it inside the same
/// acquisition as the effect it guards, so no reader compares a view against
/// a base captured earlier. `base_id` is always `GrainId::of(&base_bytes)`:
/// both constructors derive the id from the bytes they hold.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ViewContext {
    pub(crate) base_id: GrainId,
    pub(crate) base_seq: u64,
    pub(crate) base_bytes: Vec<u8>,
    /// The bin table, positionally numbered; an `Arc` so clones of one
    /// context share it rather than copy it. A rebuild reads its own table
    /// from the new root's binmap and carries none over from the view it
    /// replaces.
    pub(crate) bins: Arc<[[u8; 32]]>,
    /// Every id the base's binmap resolves, with its extent.
    pub(crate) entries: BTreeMap<GrainId, ShardEntry>,
    /// Every clean file's `(size, grains)` under its payload id.
    pub(crate) pin_files: BTreeMap<GrainId, (u64, FileGrains)>,
    /// Every manifest structure node of the base, by id.
    pub(crate) pin_nodes: BTreeMap<GrainId, Vec<u8>>,
}

impl ViewContext {
    /// The material one file of this view needs to be read from it: its
    /// payload entry, the grain-list nodes under its spill root, and the
    /// extents of its grains, with this view's base fields and bin table.
    /// A node absent from this view or undecodable is left out, so the
    /// preparation that reads the material refuses at that node. Each node
    /// is expanded once however many lists name it, so the work is bounded
    /// by the file's distinct nodes, not by the references they repeat.
    pub(crate) fn file_material(&self, content: &GrainId) -> Self {
        use granary_core::encoding::{ObjectType, open_envelope};
        use granary_core::manifest::{decode_grain_list_index, decode_grain_list_leaf};
        let mut material = Self {
            base_id: self.base_id,
            base_seq: self.base_seq,
            base_bytes: self.base_bytes.clone(),
            bins: Arc::clone(&self.bins),
            entries: BTreeMap::new(),
            pin_files: BTreeMap::new(),
            pin_nodes: BTreeMap::new(),
        };
        let Some((size, grains)) = self.pin_files.get(content) else {
            return material;
        };
        let mut keep = |id: GrainId| {
            if let Some(entry) = self.entries.get(&id) {
                material.entries.insert(id, *entry);
            }
        };
        let mut lists = Vec::new();
        match grains {
            FileGrains::Inline(inline) => inline.iter().for_each(|grain| keep(grain.id)),
            FileGrains::Spill { root, .. } => lists.push((*root, 0u32)),
        }
        while let Some((id, depth)) = lists.pop() {
            if depth > manifest::DEPTH_MAX || material.pin_nodes.contains_key(&id) {
                continue;
            }
            let Some(bytes) = self.pin_nodes.get(&id) else {
                continue;
            };
            material.pin_nodes.insert(id, bytes.clone());
            #[cfg(test)]
            MATERIAL_EXPANSIONS.with(|count| count.set(count.get() + 1));
            match open_envelope(bytes) {
                Ok((ObjectType::GrainListLeaf, body)) => {
                    if let Ok(leaf) = decode_grain_list_leaf(body) {
                        for grain in leaf {
                            keep(grain.id);
                        }
                    }
                }
                Ok((ObjectType::GrainListIndex, body)) => {
                    if let Ok(index) = decode_grain_list_index(body) {
                        lists.extend(index.iter().map(|child| (child.child, depth + 1)));
                    }
                }
                _ => {}
            }
        }
        material.pin_files.insert(*content, (*size, grains.clone()));
        material
    }

    /// The base entries of the tree under `manifest_root`, read from this
    /// view's nodes alone and decoded as a landing's are, each with inode 0
    /// and sorted by path. Nothing is fetched: a rebuild records every node
    /// it validated, so a node absent here is a view not rebuilt from that
    /// root.
    ///
    /// # Errors
    /// `SyncBase` for a node this view does not hold or does not decode,
    /// or an entry of a kind an overlay cannot hold. After a successful
    /// rebuild of `manifest_root` that arm is an equivalent mutant, named
    /// rather than chased.
    pub(crate) fn overlay_entries(
        &self,
        manifest_root: GrainId,
    ) -> Result<Vec<crate::OverlayEntry>, CoordinationError> {
        super::capture::overlay_base_entries(
            &PinNodes(&self.pin_nodes),
            manifest_root,
            &|_, _| 0,
            &mut |_, _| Ok(()),
            &|| crate::sync::refused("SyncBase"),
        )
        .map_err(|_| crate::sync::refused("SyncBase"))
    }
}

/// A view's structure nodes as a source: an id it does not hold is missing.
struct PinNodes<'a>(&'a BTreeMap<GrainId, Vec<u8>>);
impl GrainSource for PinNodes<'_> {
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

#[cfg(test)]
std::thread_local! {
    static MATERIAL_EXPANSIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Short-lived authenticated content facade borrowing the single mediator
/// [`Store`] and `VerifiedRangeCache`.
pub struct ImmutableContent<'a> {
    store: &'a Store,
    range_cache: &'a mut VerifiedRangeCache,
    view: MountViewContext,
}

impl std::fmt::Debug for ImmutableContent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImmutableContent")
            .field("view", &self.view)
            .finish_non_exhaustive()
    }
}

impl ImmutableContent<'_> {
    /// Admitted `(base_id, base_seq)` and cache generation observed when this
    /// facade was acquired.
    #[must_use]
    pub const fn view(&self) -> MountViewContext {
        self.view
    }

    /// Check whether `id` is already present in the mediator's sole [`Store`].
    #[must_use]
    pub fn has(&self, id: &GrainId) -> bool {
        GrainSource::has(self.store, id)
    }

    /// Read and hash-authenticate `id` from the mediator's sole [`Store`].
    ///
    /// # Errors
    /// Missing object, hash mismatch, oversized object, or local I/O failure.
    pub fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        GrainSource::get(self.store, id)
    }

    /// Resolve and authenticate the canonical file payload for `content`.
    ///
    /// # Errors
    /// Missing or corrupt payload, or size exceeding the overlay limit.
    pub fn payload(&mut self, content: GrainId) -> Result<FileGrains, CoordinationError> {
        let mut source = LocalContent::with_cache(self.store, self.range_cache, None);
        let (size, grains) = source.payload(content)?;
        let result = (*grains).clone();
        self.range_cache.insert_payload(content, size, grains);
        Ok(result)
    }

    /// Read and authenticate `[offset, offset + length)` from `content`,
    /// verifying inline and spilled grain-list structures and range bounds.
    ///
    /// # Errors
    /// Out-of-bounds range, corrupt payload/spill/grain, or missing object.
    pub fn read_content(
        &mut self,
        content: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, OverlayError> {
        self.read_content_or_missing(content, offset, length)
            .map_err(|(error, _)| error)
    }

    pub(crate) fn read_content_or_missing(
        &mut self,
        content: GrainId,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, (OverlayError, Option<GrainId>)> {
        let mut source = LocalContent::with_cache(self.store, self.range_cache, None);
        source
            .read_verified(content, offset, length)
            .map_err(|error| (error, source.missing_id()))
    }

    /// Store one hash-verified immutable object in the mediator's sole [`Store`].
    ///
    /// # Errors
    /// Hash mismatch, object exceeding `META_MAX_BYTES`, or store I/O.
    pub fn put_object(&mut self, id: GrainId, bytes: &[u8]) -> Result<(), CoordinationError> {
        match super::overlay::put_verified(self.store, id, bytes) {
            Ok(_) => Ok(()),
            Err(OverlayError::Refused("immutable object size bound")) => {
                Err(OverlayError::ContentCorrupt.into())
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Authenticate and record a canonical `(size, grains)` file payload under
    /// `content` in both the mediator's [`Store`] and `VerifiedRangeCache`.
    ///
    /// # Errors
    /// Size overflow, non-canonical or mismatched payload digest, or store I/O.
    pub fn remember_payload(
        &mut self,
        content: GrainId,
        size: u64,
        grains: &FileGrains,
    ) -> Result<(), CoordinationError> {
        if size > granary_core::overlay_journal::SIZE_MAX {
            return Err(OverlayError::ContentCorrupt.into());
        }
        let bytes =
            manifest::node::file_payload(size, grains).map_err(|_| OverlayError::ContentCorrupt)?;
        if GrainId::of(&bytes) != content {
            return Err(OverlayError::ContentCorrupt.into());
        }
        self.put_object(content, &bytes)?;
        let mut source = LocalContent::with_cache(self.store, self.range_cache, Some(size));
        let (decoded_size, decoded_grains) = source.payload(content)?;
        self.range_cache
            .insert_payload(content, decoded_size, decoded_grains);
        Ok(())
    }
}

impl<P: OverlayIo> WritableStore<P> {
    pub(crate) fn mount_base(&self) -> Result<(GrainId, u64), CoordinationError> {
        self.check()?;
        Ok(self
            .overlay
            .as_ref()
            .ok_or_else(|| refused("IntentReplayPending"))?
            .sync_base()?)
    }

    /// The view the mount is pinned to, if one is bound. Readers take it
    /// inside the acquisition whose effect depends on it.
    pub(crate) fn mount_pin(&self) -> Option<Arc<ViewContext>> {
        self.mount_pin.clone()
    }

    /// Bind the mount's view. The start binds the view it opened before the
    /// mediator is shared; a landing's install rebinds it in the acquisition
    /// that switches the base, under engine admission.
    pub(crate) fn bind_mount(&mut self, context: Arc<ViewContext>) {
        self.mount_pin = Some(context);
    }

    /// Refuse a view-dependent effect once an attached engine has moved the
    /// admitted base away from the pinned one. Without a pin nothing is
    /// guarded, as a store no mount has bound serves no view.
    ///
    /// # Errors
    /// `ViewPending` when the admitted base differs from the pin's, or the
    /// base's own readiness refusal.
    pub(crate) fn guard_view(&self) -> Result<(), CoordinationError> {
        if let Some(pin) = self.mount_pin.as_ref().filter(|_| self.engine_attached)
            && self.mount_base()? != (pin.base_id, pin.base_seq)
        {
            // Keep crate::sync::refused; super::refused records an intent
            // coordination failure metric.
            return Err(crate::sync::refused("ViewPending"));
        }
        Ok(())
    }

    /// Seal the object a lease holds, under a lock the caller already holds;
    /// `None` when a landing replaced the object after the lease was taken.
    pub(crate) fn seal_lease(
        &mut self,
        inode: u64,
    ) -> Result<Option<crate::SyncBoundary>, CoordinationError> {
        self.guard_view()?;
        let (_, stage) = self
            .object_leases
            .get(&inode)
            .copied()
            .ok_or_else(|| crate::sync::refused("SyncLeaseMissing"))?;
        if self.replaced_leases.contains(&inode) {
            // It was clean when it was replaced, and has refused every write
            // since: nothing is owed.
            return Ok(None);
        }
        let target = stage.map_or(crate::SyncTarget::File(inode), crate::SyncTarget::Stage);
        self.overlay_transaction(|overlay| overlay.seal_sync(target))
            .map(Some)
    }

    /// Mark every clean leased object whose inode a landing `retired`, so
    /// its pending syncs seal nothing. A lease outlives the descriptors
    /// that took it, so the leases themselves are read, not the open
    /// objects.
    pub(crate) fn replace_leases(&mut self, retired: &BTreeMap<u64, crate::OverlayEntry>) {
        for (inode, (_, stage)) in &self.object_leases {
            if stage.is_none() && retired.contains_key(inode) {
                self.replaced_leases.insert(*inode);
            }
        }
    }

    /// Observe the admitted `(base_id, base_seq)` together with the current
    /// clean-content cache generation.
    ///
    /// # Errors
    /// Fencing, poison, or unready ownership/replay state.
    pub fn mount_view_context(&mut self) -> Result<MountViewContext, CoordinationError> {
        self.check_readiness()?;
        let (base_id, base_seq) = self.mount_base()?;
        Ok(MountViewContext {
            base_id,
            base_seq,
            generation: self.range_cache.generation(),
        })
    }

    /// Borrow the single mediator [`Store`] and `VerifiedRangeCache` for one
    /// authenticated content transaction under the engine's admission rules,
    /// the same readiness every admitted view operation checks. Observes the
    /// admitted `(base_id, base_seq)` and cache generation.
    ///
    /// # Errors
    /// Fencing, poison, or unready ownership/replay state.
    pub fn immutable_content(&mut self) -> Result<ImmutableContent<'_>, CoordinationError> {
        self.check_readiness()?;
        self.content_facade()
    }

    /// [`Self::immutable_content`] for a start finishing what the store
    /// holds before it serves: the store's own refusals and an open overlay
    /// stand in for readiness, so a store whose overlay is still recovering
    /// a commit lane can be read.
    ///
    /// # Errors
    /// Fencing, poison, or no overlay open.
    pub(crate) fn immutable_content_for_recovery(
        &mut self,
    ) -> Result<ImmutableContent<'_>, CoordinationError> {
        self.check()?;
        self.content_facade()
    }

    /// The content facade on the open overlay's base.
    fn content_facade(&mut self) -> Result<ImmutableContent<'_>, CoordinationError> {
        let (base_id, base_seq) = self
            .overlay
            .as_ref()
            .ok_or_else(|| refused("IntentReplayPending"))?
            .sync_base()?;
        let view = MountViewContext {
            base_id,
            base_seq,
            generation: self.range_cache.generation(),
        };
        Ok(ImmutableContent {
            store: &self.store,
            range_cache: &mut self.range_cache,
            view,
        })
    }

    /// Check that the admitted owner is `expected_owner` and the admitted base
    /// is the pinned one, reading the pin in this same acquisition.
    ///
    /// A store with no pin bound refuses `SyncBaseBinding` too. That arm is
    /// an equivalent mutant, named rather than chased: the start binds the
    /// pin before the mediator is shared, nothing unbinds it, and this
    /// method's callers run on a mount's mediator, so no caller reaches it
    /// without a pin.
    ///
    /// # Errors
    /// `SyncOwnerBinding`, `SyncBaseBinding`, or the view's readiness refusal.
    pub(crate) fn check_mount_binding(
        &mut self,
        expected_owner: ([u8; 16], u64, [u8; 16]),
    ) -> Result<MountViewContext, CoordinationError> {
        if self.admitted_owner()? != expected_owner {
            return Err(refused("SyncOwnerBinding"));
        }
        let view = self.mount_view_context()?;
        if self
            .mount_pin
            .as_ref()
            .is_none_or(|pin| (view.base_id, view.base_seq) != (pin.base_id, pin.base_seq))
        {
            return Err(refused("SyncBaseBinding"));
        }
        Ok(view)
    }

    pub(crate) fn admitted_owner(
        &mut self,
    ) -> Result<([u8; 16], u64, [u8; 16]), CoordinationError> {
        self.check_readiness()?;
        let receipt = intent::decode_receipt(&self.carrier.current)
            .map_err(|_| refused("IntentOwnershipPending"))?;
        if receipt.instance != self.config.instance {
            return Err(refused("IntentOwnershipPending"));
        }
        Ok((self.carrier.writer, receipt.epoch, receipt.instance))
    }

    pub(crate) fn engine_attached(&self) -> bool {
        self.engine_attached
    }

    /// The overlay's base, read past the poison and fence checks.
    #[cfg(test)]
    pub(crate) fn overlay_base_for_test(&self) -> Option<(GrainId, u64)> {
        self.overlay.as_ref()?.sync_base().ok()
    }

    /// The object `id` from the mediator's store, read past every
    /// readiness check.
    #[cfg(test)]
    pub(crate) fn stored_for_test(&self, id: &GrainId) -> Option<Vec<u8>> {
        GrainSource::get(&self.store, id).ok()
    }

    /// The overlay's engine graph charges, read past the poison and fence
    /// checks.
    #[cfg(test)]
    pub(crate) fn overlay_captured_for_test(&self) -> Option<u64> {
        Some(self.overlay.as_ref()?.summary().captured_bytes)
    }

    #[cfg(test)]
    pub(crate) fn content_admission_for_test(&self) -> (bool, usize) {
        (self.engine_attached, self.capture_queue.len())
    }

    /// The generations the capture queue and the failed-caller set track, and
    /// whether a commit lane is closed.
    #[cfg(test)]
    pub(crate) fn sync_provenance_for_test(
        &self,
    ) -> (
        std::collections::BTreeSet<u64>,
        std::collections::BTreeSet<u64>,
        bool,
    ) {
        (
            self.capture_queue.keys().copied().collect(),
            self.failed_sync_registrations.clone(),
            self.commit_lane.is_some(),
        )
    }

    #[cfg(test)]
    pub(crate) fn content_phase_for_test(&mut self, phase: granary_core::overlay_ownership::Phase) {
        self.carrier.phase = phase;
    }

    #[cfg(test)]
    pub(crate) fn range_cache_snapshot_for_test(&self) -> (u64, usize, usize, usize, usize) {
        self.range_cache.snapshot_for_test()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use granary_core::manifest::{
        DirEntry, EntryKind, GRAINLIST_LEAF_MAX_REFS, GrainListIndexChild, GrainRef, Name, node,
    };

    /// An index whose children all name one full leaf stands for many
    /// references through two nodes, and the tree validates. The material
    /// expands each node once and keeps one extent per distinct grain.
    #[test]
    fn file_material_expands_a_repeated_list_node_once() {
        const REFS: u64 = GRAINLIST_LEAF_MAX_REFS as u64;
        const CHILDREN: u64 = 3;
        let width = usize::try_from(REFS).unwrap();
        let grain = GrainId::of(b"repeated grain");
        let refs = vec![
            GrainRef {
                id: grain,
                unpacked_len: 1,
            };
            width
        ];
        let leaf = node::encode_grain_list_leaf(&refs).unwrap();
        let leaf_id = GrainId::of(&leaf);
        let children: Vec<_> = (1..=CHILDREN)
            .map(|child| GrainListIndexChild {
                child: leaf_id,
                cum_unpacked_len: child * REFS,
                cum_ref_count: child * REFS,
            })
            .collect();
        let index = node::encode_grain_list_index(&children).unwrap();
        let index_id = GrainId::of(&index);
        let total = CHILDREN * REFS;
        let grains = FileGrains::Spill {
            grain_count: u32::try_from(total).unwrap(),
            root: index_id,
        };
        let content = GrainId::of(&manifest::node::file_payload(total, &grains).unwrap());
        let dir = manifest::build_dir(&[DirEntry {
            name: Name::new(b"repeated".to_vec()).unwrap(),
            kind: EntryKind::File {
                exec: false,
                size: total,
                grains: grains.clone(),
            },
        }])
        .unwrap();
        let mut nodes: BTreeMap<GrainId, Vec<u8>> = dir.nodes.into_iter().collect();
        nodes.insert(leaf_id, leaf.clone());
        nodes.insert(index_id, index.clone());
        let validated = manifest::validate_dir_tree(&dir.root, &|id| nodes.get(id).cloned())
            .map(|stats| stats.grains);
        assert_eq!(validated, Ok(total), "premise: the repeated tree validates");
        let entry = ShardEntry {
            id: grain,
            bin_ordinal: 0,
            offset: 0,
            comp_len: 1,
        };
        let view = ViewContext {
            base_id: GrainId::of(b"base"),
            base_seq: 1,
            base_bytes: b"base".to_vec(),
            bins: Arc::from(vec![[0; 32]]),
            entries: BTreeMap::from([(grain, entry)]),
            pin_files: BTreeMap::from([(content, (total, grains))]),
            pin_nodes: BTreeMap::from([(leaf_id, leaf), (index_id, index)]),
        };
        let before = MATERIAL_EXPANSIONS.get();
        let material = view.file_material(&content);
        let expansions = MATERIAL_EXPANSIONS.get() - before;
        assert_eq!(
            (
                material.pin_files.len(),
                material.pin_nodes.len(),
                material.entries.len(),
                expansions,
            ),
            (1, 2, 1, 2)
        );
    }
}
