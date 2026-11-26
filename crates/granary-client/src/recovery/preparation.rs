// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::{
    AuthorityTransport, PublicationJournal, RecoveredObjects, RecoveryError, RecoveryParts,
};
use crate::{
    OwnedCandidate, Policy,
    publish::{self, RemoteState},
};
use granary_core::{
    encoding::{self, ObjectType},
    grainsource::{GrainSource, GrainSourceError},
    hash::GrainId,
    identity::WriterIdentity,
    manifest::{self, EntryKind, FileGrains},
    retained_submission::FrozenIntent,
    root::{self, VolumeName},
    sheaf,
};
use granary_store::{
    codec::GrainCodec,
    crypto::{self, TrustedKeys},
};
use std::collections::{BTreeMap, BTreeSet};

/// A head, ancestry, sheaf chain and binmap verified with publisher trust.
/// Private fields keep unverified diagnostics out of preparation.
#[derive(Debug)]
pub(super) struct VerifiedBase {
    volume: VolumeName,
    state: RemoteState,
}
impl VerifiedBase {
    pub(super) fn into_state(self) -> RemoteState {
        self.state
    }
    #[must_use]
    pub(super) fn target_seq(&self) -> u64 {
        self.state.seq
    }
}

pub(super) async fn verify_base<T: AuthorityTransport>(
    remote: &T,
    volume: &VolumeName,
    keys: &TrustedKeys,
) -> Result<VerifiedBase, RecoveryError> {
    let Some(seq) = remote.max_seq(volume.as_str()).await? else {
        if root::is_reserved_volume_name(volume) {
            return Err(RecoveryError::Invalid("reserved volume name"));
        }
        return Ok(VerifiedBase {
            volume: volume.clone(),
            state: RemoteState::empty(),
        });
    };
    let target = granary_core::authority_answer::next_seq(Some(seq)).ok_or(
        RecoveryError::RemoteIntegrity("candidate sequence exhausted"),
    )?;
    let head = remote
        .probe_root_once(volume.as_str(), seq)
        .await?
        .ok_or(RecoveryError::RemoteIntegrity("listed head missing"))?;
    let mut doc = crypto::check_head(&head, volume.as_str(), seq, keys)
        .map_err(|_| RecoveryError::RemoteIntegrity("untrusted head"))?;
    let mut commit = read_sheaf(remote, volume, doc.sheaf_head).await?;
    if commit.manifest_root != doc.manifest_root || commit.timestamp != doc.timestamp {
        return Err(RecoveryError::RemoteIntegrity("head sheaf mismatch"));
    }
    for parent_seq in (1..seq).rev() {
        let bytes = remote
            .probe_root_once(volume.as_str(), parent_seq)
            .await?
            .ok_or(RecoveryError::RemoteIntegrity("ancestor missing"))?;
        let parent = root::check_link(doc.parent, &bytes, volume.as_str(), parent_seq)
            .map_err(|_| RecoveryError::RemoteIntegrity("root ancestry mismatch"))?;
        if commit.parent != Some(parent.sheaf_head) {
            return Err(RecoveryError::RemoteIntegrity("sheaf ancestry mismatch"));
        }
        commit = read_sheaf(remote, volume, parent.sheaf_head).await?;
        if commit.manifest_root != parent.manifest_root || commit.timestamp != parent.timestamp {
            return Err(RecoveryError::RemoteIntegrity("ancestor sheaf mismatch"));
        }
        doc = parent;
    }
    if commit.parent.is_some() {
        return Err(RecoveryError::RemoteIntegrity("first sheaf has parent"));
    }
    let state = publish::state_from_head(remote, volume, seq, &head, keys).await?;
    if state.seq != target {
        return Err(RecoveryError::RemoteIntegrity(
            "candidate sequence mismatch",
        ));
    }
    Ok(VerifiedBase {
        volume: volume.clone(),
        state,
    })
}
async fn read_sheaf<T: AuthorityTransport>(
    remote: &T,
    volume: &VolumeName,
    id: GrainId,
) -> Result<sheaf::SheafDoc, RecoveryError> {
    let bytes = remote.get_meta(volume.as_str(), &id).await?;
    if GrainId::of(&bytes) != id {
        return Err(RecoveryError::RemoteIntegrity("sheaf hash mismatch"));
    }
    sheaf::decode_sheaf(&bytes).map_err(|_| RecoveryError::RemoteIntegrity("malformed sheaf"))
}

/// Verified overlay; corrupt local files are never overwritten.
#[derive(Debug, Default)]
pub(crate) struct VerifiedObjects {
    pub(crate) retained: BTreeMap<GrainId, Vec<u8>>,
    verified_lengths: BTreeMap<GrainId, usize>,
}
impl VerifiedObjects {
    pub(super) fn overlay<'a, G: GrainSource>(&'a self, local: &'a G) -> Overlay<'a, G> {
        Overlay {
            local,
            objects: self,
        }
    }
}
pub(super) struct Overlay<'a, G> {
    local: &'a G,
    objects: &'a VerifiedObjects,
}
impl<G: GrainSource> GrainSource for Overlay<'_, G> {
    fn get(&self, id: &GrainId) -> Result<Vec<u8>, GrainSourceError> {
        if let Some(bytes) = self.objects.retained.get(id) {
            return Ok(bytes.clone());
        }
        match self.local.get(id) {
            Ok(bytes)
                if self.objects.verified_lengths.get(id) == Some(&bytes.len())
                    && GrainId::of(&bytes) == *id =>
            {
                Ok(bytes)
            }
            Ok(_) => Err(GrainSourceError::Corrupt(*id)),
            Err(error) => Err(error),
        }
    }
    fn has(&self, id: &GrainId) -> bool {
        self.objects.retained.contains_key(id) || self.local.has(id)
    }
}
enum Item {
    Node(GrainId),
    Grain(GrainId, u32),
}

pub(super) async fn reconstruct<T: AuthorityTransport, J: PublicationJournal>(
    p: &mut RecoveryParts<'_, T, J>,
    volume: &VolumeName,
    frozen: &FrozenIntent,
) -> Result<VerifiedObjects, RecoveryError> {
    let doc = root::decode_root(&frozen.initial_root)
        .map_err(|_| RecoveryError::Invalid("malformed frozen root"))?;
    crypto::check_head(
        &frozen.initial_root,
        volume.as_str(),
        doc.seq,
        p.publisher_keys,
    )
    .map_err(|_| RecoveryError::Invalid("untrusted frozen root"))?;
    if p.journal.recovered().is_some() {
        let state = publish::state_from_head(
            p.transport,
            volume,
            doc.seq,
            &frozen.initial_root,
            p.publisher_keys,
        )
        .await?;
        load_structure(p.transport, &mut *p.journal, &state, doc.manifest_root).await?;
        return Ok(VerifiedObjects {
            retained: BTreeMap::new(),
            verified_lengths: recovered(&mut *p.journal)?.verified.clone(),
        });
    }
    closure(p, volume, doc.manifest_root, Some(frozen)).await
}

pub(super) async fn closure<T: AuthorityTransport, J: PublicationJournal>(
    p: &mut RecoveryParts<'_, T, J>,
    volume: &VolumeName,
    manifest: GrainId,
    frozen: Option<&FrozenIntent>,
) -> Result<VerifiedObjects, RecoveryError> {
    read_closure(
        p.transport,
        &*p.journal,
        p.publisher_keys,
        volume,
        manifest,
        frozen,
    )
    .await
}

pub(crate) async fn read_closure<T: granary_core::binstore::BinStore, L: GrainSource + ?Sized>(
    remote: &T,
    local: &L,
    keys: &TrustedKeys,
    volume: &VolumeName,
    manifest: GrainId,
    frozen: Option<&FrozenIntent>,
) -> Result<VerifiedObjects, RecoveryError> {
    read_closure_charged(remote, local, keys, volume, manifest, frozen, |_| Ok(())).await
}

pub(super) async fn read_closure_charged<
    T: granary_core::binstore::BinStore,
    L: GrainSource + ?Sized,
>(
    remote: &T,
    local: &L,
    keys: &TrustedKeys,
    volume: &VolumeName,
    manifest: GrainId,
    frozen: Option<&FrozenIntent>,
    mut charge: impl FnMut(usize) -> Result<(), RecoveryError>,
) -> Result<VerifiedObjects, RecoveryError> {
    let mut objects = VerifiedObjects::default();
    let mut expanded = BTreeSet::new();
    let mut work = vec![Item::Node(manifest)];
    let mut index = None;
    let mut codec = GrainCodec::new().map_err(|_| RecoveryError::Invalid("codec unavailable"))?;
    while let Some(item) = work.pop() {
        let (id, cap, length) = match item {
            Item::Node(id) => (id, manifest::MANIFEST_NODE_MAX_BYTES, None),
            Item::Grain(id, len) => (id, len, Some(len)),
        };
        if let (Some(length), Some(&verified_length)) = (length, objects.verified_lengths.get(&id))
        {
            if verified_length != length as usize {
                return Err(RecoveryError::Invalid("frozen grain length mismatch"));
            }
            continue;
        }
        let (bytes, recovered) = if let Some(bytes) = objects.retained.get(&id) {
            (bytes.clone(), false)
        } else {
            match local.get(&id) {
                Ok(bytes) if GrainId::of(&bytes) == id => (bytes, false),
                Ok(_) | Err(GrainSourceError::Missing(_) | GrainSourceError::Corrupt(_)) => {
                    let frozen =
                        frozen.ok_or(RecoveryError::Invalid("initial content unavailable"))?;
                    if index.is_none() {
                        let doc = root::decode_root(&frozen.initial_root)
                            .map_err(|_| RecoveryError::Invalid("frozen root"))?;
                        index = Some(
                            publish::state_from_head(
                                remote,
                                volume,
                                doc.seq,
                                &frozen.initial_root,
                                keys,
                            )
                            .await?,
                        );
                    }
                    let state = index
                        .as_ref()
                        .ok_or(RecoveryError::Invalid("missing frozen index"))?;
                    (
                        fetch_mapped(remote, state, &mut codec, &id, cap).await?,
                        true,
                    )
                }
                Err(_) => return Err(RecoveryError::Invalid("local content read failed")),
            }
        };
        if (length.is_none() || recovered) && !objects.retained.contains_key(&id) {
            charge(bytes.len())?;
        }
        if bytes.len() > cap as usize || (recovered && GrainId::of(&bytes) != id) {
            return Err(RecoveryError::Invalid("frozen object hash or cap mismatch"));
        }
        if let Some(length) = length {
            if bytes.len() != length as usize {
                return Err(RecoveryError::Invalid("frozen grain length mismatch"));
            }
        } else if expanded.insert(id) {
            work.extend(children(&bytes)?);
        }
        objects.verified_lengths.insert(id, bytes.len());
        // Local file grains remain on disk; only nodes and recovered objects
        // need retained bytes for manifest validation and the preparation overlay.
        if length.is_none() || recovered {
            objects.retained.insert(id, bytes);
        }
    }
    manifest::validate_dir_tree(&manifest, &|id| objects.retained.get(id).cloned())
        .map_err(|_| RecoveryError::Invalid("invalid frozen manifest structure"))?;
    Ok(objects)
}
/// One object's mapped extent from `state`'s signed binmap, its declared
/// expansion checked against `cap` before the codec allocates it.
async fn fetch_mapped<T: granary_core::binstore::BinStore>(
    remote: &T,
    state: &RemoteState,
    codec: &mut GrainCodec,
    id: &GrainId,
    cap: u32,
) -> Result<Vec<u8>, RecoveryError> {
    let entry = state
        .known
        .get(id)
        .ok_or(RecoveryError::Invalid("frozen object unmapped"))?;
    let digest = state
        .bins
        .get(entry.bin_ordinal as usize)
        .ok_or(RecoveryError::Invalid("frozen bin ordinal"))?;
    let frame = remote
        .get_bin_range(digest, entry.offset, entry.comp_len)
        .await?;
    if frame.len() != entry.comp_len as usize {
        return Err(RecoveryError::Invalid("short frozen extent"));
    }
    // Check the declared expansion before the codec allocates it.
    let declared = granary_core::binfmt::decode_frame_header(&frame)
        .map_err(|_| RecoveryError::Invalid("frozen frame header"))?;
    if declared.unpacked_len > cap {
        return Err(RecoveryError::Invalid("frozen object exceeds declaration"));
    }
    codec
        .decompress_frame(&frame)
        .map_err(|_| RecoveryError::Invalid("corrupt frozen frame"))
}

fn recovered<J: PublicationJournal>(
    journal: &mut J,
) -> Result<&mut RecoveredObjects, RecoveryError> {
    journal
        .recovered()
        .ok_or(RecoveryError::Invalid("journal holds no recovered set"))
}

/// Walk only `manifest`'s structure nodes through `state`, the signed binmap
/// of the root naming it. Each node must be mapped; it is read from the
/// journal's store or fetched, hash- and cap-checked, and every reference it
/// makes must be mapped. After the whole tree validates, each node is stored
/// and joins the verified set, and each file's payload is recorded. File
/// grains are never fetched: their references are returned with lengths.
pub(super) async fn load_structure<T: granary_core::binstore::BinStore, J: PublicationJournal>(
    remote: &T,
    journal: &mut J,
    state: &RemoteState,
    manifest: GrainId,
) -> Result<BTreeMap<GrainId, u32>, RecoveryError> {
    let mut codec = GrainCodec::new().map_err(|_| RecoveryError::Invalid("codec unavailable"))?;
    let mut nodes = BTreeMap::new();
    let mut grains = BTreeMap::new();
    let mut work = vec![manifest];
    while let Some(id) = work.pop() {
        if nodes.contains_key(&id) {
            continue;
        }
        if !state.known.contains_key(&id) {
            return Err(RecoveryError::Invalid("structure node unmapped"));
        }
        let bytes = match journal.get(&id) {
            Ok(bytes) if GrainId::of(&bytes) == id => bytes,
            Ok(_) | Err(GrainSourceError::Missing(_) | GrainSourceError::Corrupt(_)) => {
                fetch_mapped(
                    remote,
                    state,
                    &mut codec,
                    &id,
                    manifest::MANIFEST_NODE_MAX_BYTES,
                )
                .await?
            }
            Err(_) => return Err(RecoveryError::Invalid("local content read failed")),
        };
        if bytes.len() > manifest::MANIFEST_NODE_MAX_BYTES as usize || GrainId::of(&bytes) != id {
            return Err(RecoveryError::Invalid(
                "structure node hash or cap mismatch",
            ));
        }
        if !crate::sync::contained(&bytes, &state.known) {
            return Err(RecoveryError::Invalid("structure reference unmapped"));
        }
        for item in children(&bytes)? {
            match item {
                Item::Node(child) => work.push(child),
                Item::Grain(grain, length) => {
                    grains.insert(grain, length);
                }
            }
        }
        nodes.insert(id, bytes);
    }
    manifest::validate_dir_tree(&manifest, &|id| nodes.get(id).cloned())
        .map_err(|_| RecoveryError::Invalid("invalid structure manifest"))?;
    for (id, bytes) in nodes {
        for (size, file) in files(&bytes)? {
            let payload = manifest::node::file_payload(size, &file)
                .map_err(|_| RecoveryError::Invalid("malformed manifest node"))?;
            recovered(journal)?
                .payloads
                .insert(GrainId::of(&payload), file);
        }
        journal.put_recovered(&id, &bytes)?;
        recovered(journal)?.verified.insert(id, bytes.len());
    }
    Ok(grains)
}
fn files(bytes: &[u8]) -> Result<Vec<(u64, FileGrains)>, RecoveryError> {
    let invalid = |_| RecoveryError::Invalid("malformed manifest node");
    let (kind, cursor) = encoding::open_envelope(bytes).map_err(invalid)?;
    if kind != ObjectType::DirLeaf {
        return Ok(Vec::new());
    }
    Ok(manifest::decode_dir_leaf(cursor)
        .map_err(invalid)?
        .into_iter()
        .filter_map(|entry| match entry.kind {
            EntryKind::File { size, grains, .. } => Some((size, grains)),
            _ => None,
        })
        .collect())
}

/// Store the prepared root's file grains that its parent's binmap lacks,
/// each a member of the prepared root's own binmap, read from the journal's
/// store or fetched, and hash- and length-checked before it is stored.
/// Their total raw length uses the configured local workspace policy; this
/// counter does not reserve memory.
pub(super) async fn stage_novel<T: granary_core::binstore::BinStore, J: PublicationJournal>(
    remote: &T,
    journal: &mut J,
    prepared: &RemoteState,
    parent: &BTreeMap<GrainId, granary_core::binmap::ShardEntry>,
    grains: &BTreeMap<GrainId, u32>,
    bound: u64,
) -> Result<(), RecoveryError> {
    let mut codec = GrainCodec::new().map_err(|_| RecoveryError::Invalid("codec unavailable"))?;
    let mut total: u64 = 0;
    for (&id, &length) in grains {
        if parent.contains_key(&id) || recovered(journal)?.verified.contains_key(&id) {
            continue;
        }
        total = total.saturating_add(u64::from(length));
        if total > bound {
            return Err(RecoveryError::Refused("SyncWorkspaceExhausted"));
        }
        if !prepared.known.contains_key(&id) {
            return Err(RecoveryError::Invalid("novel grain unmapped"));
        }
        let bytes = match journal.get(&id) {
            Ok(bytes) if GrainId::of(&bytes) == id => bytes,
            Ok(_) | Err(GrainSourceError::Missing(_) | GrainSourceError::Corrupt(_)) => {
                fetch_mapped(remote, prepared, &mut codec, &id, length).await?
            }
            Err(_) => return Err(RecoveryError::Invalid("local content read failed")),
        };
        if bytes.len() != length as usize || GrainId::of(&bytes) != id {
            return Err(RecoveryError::Invalid(
                "novel grain hash or length mismatch",
            ));
        }
        journal.put_recovered(&id, &bytes)?;
        recovered(journal)?.verified.insert(id, bytes.len());
    }
    Ok(())
}

/// Admit a merged manifest only through `head`'s signed binmap or the
/// journal's verified set: every node is a member of one, hash-checked as
/// read from the journal's store, and every reference it makes is too.
pub(super) fn check_recovered<J: PublicationJournal>(
    journal: &mut J,
    head: &BTreeMap<GrainId, granary_core::binmap::ShardEntry>,
    manifest: GrainId,
) -> Result<VerifiedObjects, RecoveryError> {
    let verified = recovered(journal)?.verified.clone();
    let source: &J = journal;
    let admitted = |id: &GrainId| head.contains_key(id) || verified.contains_key(id);
    manifest::validate_dir_tree(&manifest, &|id| {
        if !admitted(id) {
            return None;
        }
        let bytes = source.get(id).ok()?;
        (GrainId::of(&bytes) == *id && crate::sync::contained_by(&bytes, &admitted))
            .then_some(bytes)
    })
    .map_err(|_| RecoveryError::Invalid("merged manifest outside the verified set"))?;
    Ok(VerifiedObjects {
        retained: BTreeMap::new(),
        verified_lengths: verified,
    })
}
fn children(bytes: &[u8]) -> Result<Vec<Item>, RecoveryError> {
    let invalid = |_| RecoveryError::Invalid("malformed manifest node");
    let (kind, cursor) = encoding::open_envelope(bytes).map_err(invalid)?;
    let mut out = Vec::new();
    match kind {
        ObjectType::DirLeaf => {
            for entry in manifest::decode_dir_leaf(cursor).map_err(invalid)? {
                match entry.kind {
                    EntryKind::Dir { child } => {
                        out.push(Item::Node(child));
                    }
                    EntryKind::File { grains, .. } => match grains {
                        FileGrains::Inline(refs) => {
                            out.extend(refs.into_iter().map(|r| Item::Grain(r.id, r.unpacked_len)));
                        }
                        FileGrains::Spill { root, .. } => out.push(Item::Node(root)),
                    },
                    EntryKind::Symlink { .. } | EntryKind::Fifo | EntryKind::Socket => {}
                }
            }
        }
        ObjectType::DirInterior => out.extend(
            manifest::decode_dir_interior(cursor)
                .map_err(invalid)?
                .into_iter()
                .map(|c| Item::Node(c.child)),
        ),
        ObjectType::GrainListLeaf => out.extend(
            manifest::decode_grain_list_leaf(cursor)
                .map_err(invalid)?
                .into_iter()
                .map(|r| Item::Grain(r.id, r.unpacked_len)),
        ),
        ObjectType::GrainListIndex => out.extend(
            manifest::decode_grain_list_index(cursor)
                .map_err(invalid)?
                .into_iter()
                .map(|c| Item::Node(c.child)),
        ),
        _ => return Err(RecoveryError::Invalid("object is not a manifest node")),
    }
    Ok(out)
}

pub(super) async fn prepare<T: AuthorityTransport, J: PublicationJournal>(
    p: &mut RecoveryParts<'_, T, J>,
    objects: &VerifiedObjects,
    base: VerifiedBase,
    frozen: &FrozenIntent,
    writer: Option<[u8; 16]>,
) -> Result<OwnedCandidate, RecoveryError> {
    let doc = root::decode_root(&frozen.initial_root)
        .map_err(|_| RecoveryError::Invalid("frozen root"))?;
    let policy = Policy {
        min_prefix_bits: frozen.min_prefix_bits,
    };
    let manifest = p
        .journal
        .rebase_manifest(frozen, base.state.parent, base.state.seq)
        .await?;
    let merged;
    // A recovered set grew during the rebase, even when the merge reproduced
    // the frozen manifest, so its check always reads the set as it is now.
    let objects = if p.journal.recovered().is_some() {
        merged = check_recovered(&mut *p.journal, &base.state.known, manifest)?;
        &merged
    } else if manifest == doc.manifest_root {
        objects
    } else {
        merged = closure(p, &base.volume, manifest, None).await?;
        &merged
    };
    let bytes = if let Some(writer) = writer {
        let accepted = publish::accept_from_state(
            p.transport,
            &objects.overlay(&*p.journal),
            manifest,
            crate::HarvestStats::default(),
            &base.volume,
            p.clock.now(),
            policy,
            base.state,
        )
        .await?;
        let mut doc = accepted.doc;
        doc.writer_uuid = writer;
        let prefix =
            root::signing_prefix_of(&doc).map_err(|_| RecoveryError::Invalid("prepared root"))?;
        doc.sigs.push(root::RootSig {
            key_id: p.signer.key_id(),
            sig: p.signer.sign(&prefix),
        });
        root::encode_root(&doc).map_err(|_| RecoveryError::Invalid("prepared root"))?
    } else {
        publish::prepare_from_state(
            p.transport,
            &objects.overlay(&*p.journal),
            manifest,
            crate::HarvestStats::default(),
            &base.volume,
            p.signer,
            &WriterIdentity::from_bytes(frozen.writer_identity),
            p.clock.now(),
            policy,
            base.state,
        )
        .await?
        .root_bytes
    };
    OwnedCandidate::new(base.volume.as_str(), bytes.into())
        .map_err(|_| RecoveryError::Invalid("prepared candidate"))
}
