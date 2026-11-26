// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Whole-bin and mapped-frame verification, retaining one bin at a time.

use std::collections::BTreeMap;

use granary_core::binfmt::{
    BinIndexEntry, MAX_GRAINS_PER_BIN, decode_bin, decode_frame_header, frame_bytes,
};
use granary_core::encoding::{ObjectType, open_envelope};
use granary_core::hash::{DIGEST_LEN, GrainId};
use granary_store::codec::{CodecError, GrainCodec};

use super::binmap::Additions;
use super::budget::Work;
use super::proofs::{Allocation, Lengths};
use super::{
    Result, ValidationAttempt, ValidationError, ValidationObject, ValidationRead, check_id, invalid,
};

/// Cache bytes only for structure objects, and lengths for file edges. Both
/// come from decoded, hash-verified frames. Only node bytes are disposable.
#[derive(Debug)]
pub(super) struct Facts {
    lengths: Lengths,
    allocation: Allocation,
    nodes: BTreeMap<GrainId, Vec<u8>>,
    node_bytes: usize,
}

impl Facts {
    pub(super) fn new(lengths: Lengths, allocation: Allocation) -> Self {
        Self {
            lengths,
            allocation,
            nodes: BTreeMap::new(),
            node_bytes: 0,
        }
    }

    pub(super) fn lengths(&self) -> &Lengths {
        &self.lengths
    }

    pub(super) fn into_lengths(self) -> Lengths {
        self.lengths
    }

    pub(super) fn node(&self, id: &GrainId) -> Option<Vec<u8>> {
        self.nodes.get(id).cloned()
    }

    pub(super) fn remember(&mut self, id: GrainId, bytes: &[u8], len: u32) -> Result<()> {
        self.lengths.insert(&self.allocation, id, len)?;
        self.remember_node(id, bytes);
        Ok(())
    }

    pub(super) fn remember_node(&mut self, id: GrainId, bytes: &[u8]) {
        const NODE_BYTES: usize = 1024 * 1024;
        if bytes.len() <= NODE_BYTES.saturating_sub(self.node_bytes)
            && matches!(
                open_envelope(bytes),
                Ok((
                    ObjectType::DirLeaf
                        | ObjectType::DirInterior
                        | ObjectType::GrainListLeaf
                        | ObjectType::GrainListIndex,
                    _
                ))
            )
            && !self.nodes.contains_key(&id)
        {
            self.node_bytes += bytes.len();
            self.nodes.insert(id, bytes.to_vec());
        }
    }
}

pub(super) async fn verify(
    work: &mut ValidationAttempt,
    source: &impl ValidationRead,
    table: &[[u8; DIGEST_LEN]],
    old_count: usize,
    mut additions: Additions,
    mut facts: Facts,
) -> Result<Facts> {
    while let Some((&ordinal, _)) = additions.by_bin.first_key_value()
        && ordinal < old_count
    {
        let (_, mappings) = additions
            .by_bin
            .pop_first()
            .ok_or(ValidationError::InvalidReference)?;
        let digest = table
            .get(ordinal)
            .ok_or(ValidationError::InvalidReference)?;
        facts = verify_bin(work, source, *digest, true, mappings, facts).await?;
    }
    for (ordinal, &digest) in table.iter().enumerate().skip(old_count) {
        let mappings = additions.by_bin.remove(&ordinal).unwrap_or_default();
        facts = verify_bin(work, source, digest, false, mappings, facts).await?;
    }
    Ok(facts)
}

async fn verify_bin(
    work: &mut ValidationAttempt,
    source: &impl ValidationRead,
    digest: [u8; DIGEST_LEN],
    verified: bool,
    mappings: Vec<BinIndexEntry>,
    mut facts: Facts,
) -> Result<Facts> {
    let (bin, entries) = read_bin(work, source, digest, verified).await?;
    if mappings.is_empty() {
        return Ok(facts);
    }
    work.blocking(move |work| {
        let mut codec = GrainCodec::new().map_err(|error| codec_error(&error))?;
        let mut scratch = Vec::new();
        for mapping in mappings {
            work.steps(1)?;
            check_mapping(&entries, &mapping)?;
            let frame = frame_bytes(&bin, &mapping).map_err(invalid)?;
            let (grain, len) = decode_frame(work, &mut codec, frame, mapping.id, &mut scratch)?;
            facts.remember(mapping.id, grain, len)?;
        }
        Ok(facts)
    })
    .await
}

pub(super) fn check_mapping(entries: &[BinIndexEntry], mapping: &BinIndexEntry) -> Result<()> {
    let position = entries
        .binary_search_by_key(&mapping.offset, |entry| entry.offset)
        .map_err(|_| ValidationError::InvalidReference)?;
    if entries.get(position) == Some(mapping) {
        Ok(())
    } else {
        Err(ValidationError::InvalidReference)
    }
}

pub(super) async fn read_bin(
    work: &mut ValidationAttempt,
    source: &impl ValidationRead,
    digest: [u8; DIGEST_LEN],
    verified: bool,
) -> Result<(Vec<u8>, Vec<BinIndexEntry>)> {
    let bin = work
        .read(source, ValidationObject::Bin(digest), verified)
        .await?;
    let count = open_envelope(&bin)
        .ok()
        .and_then(|(object, mut cursor)| {
            (object == ObjectType::Bin)
                .then(|| cursor.u32().ok())
                .flatten()
        })
        .filter(|&count| count <= MAX_GRAINS_PER_BIN)
        .unwrap_or(0);
    work.meter(u64::from(count)).await?;
    work.blocking(move |_| {
        if GrainId::of(&bin).digest() != &digest {
            return Err(if verified {
                ValidationError::Unavailable
            } else {
                ValidationError::InvalidReference
            });
        }
        let entries = decode_bin(&bin).map_err(invalid)?;
        Ok((bin, entries))
    })
    .await
}

fn codec_error(error: &CodecError) -> ValidationError {
    match error {
        CodecError::Zstd(_) => ValidationError::Unavailable,
        _ => ValidationError::InvalidReference,
    }
}

pub(super) async fn read_frame(
    work: &mut ValidationAttempt,
    source: &impl ValidationRead,
    digest: [u8; DIGEST_LEN],
    row: granary_core::binmap::ShardEntry,
    verified: bool,
) -> Result<(Vec<u8>, u32)> {
    let frame = work
        .read(
            source,
            ValidationObject::BinRange(digest, row.offset, row.comp_len),
            verified,
        )
        .await?;
    if let Ok(header) = decode_frame_header(&frame) {
        work.prepare_expansion(header.unpacked_len).await?;
    }
    work.blocking(move |work| {
        let mut codec = GrainCodec::new().map_err(|error| codec_error(&error))?;
        let mut scratch = Vec::new();
        let result = if frame.len() as u64 == u64::from(row.comp_len) {
            decode_frame(work, &mut codec, &frame, row.id, &mut scratch).map(|(_, len)| len)
        } else {
            Err(ValidationError::InvalidReference)
        };
        match result {
            Ok(len) => Ok((scratch, len)),
            Err(ValidationError::InvalidReference) if verified => Err(ValidationError::Unavailable),
            Err(error) => Err(error),
        }
    })
    .await
}

fn decode_frame<'a>(
    work: &mut Work,
    codec: &mut GrainCodec,
    frame: &[u8],
    id: GrainId,
    scratch: &'a mut Vec<u8>,
) -> Result<(&'a [u8], u32)> {
    let header = decode_frame_header(frame).map_err(invalid)?;
    work.expand(header.unpacked_len)?;
    let grain = codec
        .decompress_frame_into(frame, scratch)
        .map_err(|error| codec_error(&error))?;
    check_id(grain, id)?;
    Ok((grain, header.unpacked_len))
}
