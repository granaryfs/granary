// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Bounded immutable payload authentication and shared-boundary admission.

use super::capture::{QueuedCapture, QueuedFile, captured_refs, lost, object};
use super::{CoordinationError, PendingIntent, WritableStore, refused};
use crate::overlay_store::{CapturedPart, ContentSource, OverlayIo, SyncBoundary};
use granary_core::grainsource::GrainSource;
use granary_core::manifest::FileGrains;

/// Authenticated grain payload tied to one file of an exact live seal. The
/// private binding prevents substituting newer staging or caller-supplied refs.
#[derive(Debug)]
pub struct VerifiedSyncPayload {
    boundary: u64,
    index: usize,
    file: QueuedFile,
}

const WORKSPACE: u64 = 4_194_304 + 65_536;

/// Engine-owned incremental verifier. It holds no mediator guard; authentication
/// and provider callbacks run between independent local range transactions.
#[derive(Debug)]
pub struct SyncPayloadVerifier {
    boundary: u64,
    index: usize,
    file: QueuedFile,
    refs: Vec<granary_core::manifest::GrainRef>,
    next_ref: usize,
    grain: Vec<u8>,
    used: usize,
    processed: u64,
    initialized: bool,
    failed: bool,
    retained: u64,
}
impl SyncPayloadVerifier {
    /// Authenticate the declared grain list outside the mediator.
    /// # Errors
    /// Missing/malformed/hash-mismatched content or repeated initialization.
    pub fn authenticate(&mut self, source: &dyn GrainSource) -> Result<(), CoordinationError> {
        if self.initialized || self.failed {
            return Err(lost());
        }
        match captured_refs(source, self.file.size, &self.file.grains) {
            Ok(refs) => {
                self.refs = refs;
                self.initialized = true;
                Ok(())
            }
            Err(error) => {
                self.failed = true;
                Err(error)
            }
        }
    }

    /// Consume the next opaque snapshot range outside the mediator. Callers
    /// cannot fabricate bytes, reorder ranges or replace the captured version.
    /// # Errors
    /// Foreign/reordered range, unavailable content or unequal authenticated bytes.
    pub fn consume(
        &mut self,
        range: crate::CapturedRange,
        source: &dyn GrainSource,
        immutable: &mut impl ContentSource,
    ) -> Result<(), CoordinationError> {
        if !self.initialized
            || self.failed
            || range.boundary != self.boundary
            || range.index != self.index
            || range.offset != self.processed
        {
            self.failed = true;
            return Err(lost());
        }
        let result = self.consume_parts(range.parts, source, immutable);
        self.failed |= result.is_err();
        result
    }

    fn consume_parts(
        &mut self,
        parts: Vec<CapturedPart>,
        source: &dyn GrainSource,
        immutable: &mut impl ContentSource,
    ) -> Result<(), CoordinationError> {
        for part in parts {
            let bytes = match part {
                CapturedPart::Dirty {
                    bytes,
                    start,
                    length,
                } => bytes.get(start..start + length).ok_or_else(lost)?.to_vec(),
                CapturedPart::Zero(length) => vec![0; length],
                CapturedPart::Immutable {
                    content,
                    offset,
                    length,
                } => {
                    let bytes = immutable.read_verified(content, offset, length)?;
                    if bytes.len() != length {
                        return Err(lost());
                    }
                    bytes
                }
            };
            let mut remaining = bytes.as_slice();
            while !remaining.is_empty() {
                if self.used == self.grain.len() {
                    let next = self.refs.get(self.next_ref).ok_or_else(lost)?;
                    self.grain = object(source, next.id)?;
                    if self.grain.len() as u64 != u64::from(next.unpacked_len) {
                        return Err(lost());
                    }
                    self.next_ref += 1;
                    self.used = 0;
                }
                let n = remaining.len().min(self.grain.len() - self.used);
                if n == 0 || self.grain.get(self.used..self.used + n) != remaining.get(..n) {
                    return Err(lost());
                }
                self.used += n;
                remaining = remaining.get(n..).ok_or_else(lost)?;
            }
            self.processed = self
                .processed
                .checked_add(bytes.len() as u64)
                .ok_or_else(lost)?;
            if self.processed > self.file.size {
                return Err(lost());
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<VerifiedSyncPayload, CoordinationError> {
        if !self.initialized
            || self.failed
            || self.processed != self.file.size
            || self.next_ref != self.refs.len()
            || self.used != self.grain.len()
        {
            return Err(lost());
        }
        Ok(VerifiedSyncPayload {
            boundary: self.boundary,
            index: self.index,
            file: self.file,
        })
    }
}

impl<P: OverlayIo> WritableStore<P> {
    /// Reserve payload refs and bounded verification workspace before any source
    /// callback. Obtain ranges in separate short overlay transactions and pass
    /// them to the returned verifier outside all local guards.
    /// # Errors
    /// Invalid/stale context or non-poisoning declared-cap exhaustion.
    pub fn begin_sync_payload(
        &mut self,
        boundary: &SyncBoundary,
        index: usize,
        grains: FileGrains,
    ) -> Result<SyncPayloadVerifier, CoordinationError> {
        self.check()?;
        let file = boundary.files().get(index).ok_or_else(lost)?;
        let retained = u64::from(grains.grain_count())
            .checked_mul(128)
            .and_then(|n| n.checked_add(512))
            .ok_or_else(lost)?;
        let result = self
            .overlay
            .as_mut()
            .ok_or_else(lost)?
            .reserve_sync_graph(boundary, retained + WORKSPACE);
        self.retain_overlay_bundle(result.as_ref().err());
        result?;
        Ok(SyncPayloadVerifier {
            boundary: boundary.id(),
            index,
            file: QueuedFile {
                capture: file.capture_token().cloned(),
                entry: file.entry().cloned(),
                size: file.size(),
                through_seq: boundary.through_seq(),
                grains,
                verified: true,
                needs_mark: file.needs_mark(),
            },
            refs: Vec::new(),
            next_ref: 0,
            grain: Vec::new(),
            used: 0,
            processed: 0,
            initialized: false,
            failed: false,
            retained,
        })
    }

    /// Finish authentication and release temporary workspace. A failed verifier
    /// releases its graph charge without completing the seal or any file floor.
    /// # Errors
    /// Foreign/stale seal, failed/incomplete verifier or accounting mismatch.
    pub fn finish_sync_payload(
        &mut self,
        boundary: &SyncBoundary,
        verifier: SyncPayloadVerifier,
    ) -> Result<VerifiedSyncPayload, CoordinationError> {
        self.check()?;
        if verifier.boundary != boundary.id() {
            return Err(lost());
        }
        let retained = verifier.retained;
        let result = verifier.finish();
        let released = self.overlay.as_mut().ok_or_else(lost)?.release_sync_graph(
            boundary,
            WORKSPACE + if result.is_err() { retained } else { 0 },
        );
        self.retain_overlay_bundle(released.as_ref().err());
        released?;
        result
    }

    /// Explicit memory-only disposal of an abandoned verifier. Its seal and
    /// capture floors remain owned until boundary completion/disposal.
    /// # Errors
    /// Foreign/stale seal or accounting mismatch.
    pub fn abandon_sync_payload(
        &mut self,
        boundary: &SyncBoundary,
        verifier: SyncPayloadVerifier,
    ) -> Result<(), CoordinationError> {
        if verifier.boundary != boundary.id() {
            return Err(lost());
        }
        let retained = verifier.retained;
        drop(verifier);
        let result = self
            .overlay
            .as_mut()
            .ok_or_else(lost)?
            .release_sync_graph(boundary, WORKSPACE + retained);
        self.retain_overlay_bundle(result.as_ref().err());
        result?;
        Ok(())
    }

    /// Admit one registration for every selected file in a shared seal. The
    /// carrier retains bounded incarnation/cursor/root binding; owned payload
    /// graphs stay volatile and cap-accounted until explicit completion.
    /// # Errors
    /// Missing/foreign/duplicate payloads, stale seal, cap or persistence failure.
    pub fn prepare_sync_registration(
        &mut self,
        root: &[u8],
        boundary: SyncBoundary,
        payloads: Vec<VerifiedSyncPayload>,
        clock: &impl granary_core::clock::Clock,
        verify: impl FnMut(&granary_core::root::RootDoc, &[u8]) -> bool,
    ) -> Result<PendingIntent, CoordinationError> {
        self.check()?;
        self.overlay
            .as_ref()
            .ok_or_else(lost)?
            .validate_flushed_sync_boundary(&boundary)?;
        if payloads.len() != boundary.files().len()
            || self.capture_queue.values().any(|queued| {
                queued
                    .boundary
                    .as_ref()
                    .is_some_and(|b| b.id() == boundary.id())
            })
        {
            return Err(refused("IntentSyncPayloadBinding"));
        }
        let mut selected = std::collections::BTreeMap::new();
        for payload in payloads {
            if payload.boundary != boundary.id()
                || payload.index >= boundary.files().len()
                || selected.insert(payload.index, payload.file).is_some()
            {
                return Err(refused("IntentSyncPayloadBinding"));
            }
        }
        let charge = (root.len() as u64)
            .checked_mul(3)
            .and_then(|n| n.checked_add(4096))
            .ok_or_else(lost)?;
        let reserved = self
            .overlay
            .as_mut()
            .ok_or_else(lost)?
            .reserve_sync_graph(&boundary, charge);
        self.retain_overlay_bundle(reserved.as_ref().err());
        reserved?;
        let context = [
            boundary.id().to_be_bytes().as_slice(),
            boundary.incarnation().to_be_bytes().as_slice(),
            boundary.through_seq().to_be_bytes().as_slice(),
            granary_core::hash::GrainId::of(root).to_bytes().as_slice(),
        ]
        .concat();
        let request = match self.prepare_registration(root, context, clock, verify) {
            Ok(request) => request,
            Err(error) => {
                let released = self
                    .overlay
                    .as_mut()
                    .ok_or_else(lost)?
                    .release_sync_graph(&boundary, charge);
                self.retain_overlay_bundle(released.as_ref().err());
                released?;
                return Err(error);
            }
        };
        let generation =
            granary_core::intent::decode_register(request.bytes(), request.volume(), |_, _| true)
                .map_err(|_| lost())?
                .generation;
        self.capture_queue.insert(
            generation,
            QueuedCapture {
                request: request.clone(),
                files: selected.into_values().collect(),
                boundary: Some(boundary),
            },
        );
        Ok(request)
    }
}
