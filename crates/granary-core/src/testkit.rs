// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Test/fuzz instrumentation. `#[doc(hidden)]`, no stability promises,
//! never product logic. The probes deliberately panic on invariant
//! violations — they are the shared body of the fuzz targets
//! (`fuzz/fuzz_targets/`) and the stable corpus-replay tests
//! (`tests/fuzz_corpus_replay.rs`), per the nightly-free PR-CI
//! design.

use std::future::Future;

use crate::hash::GrainId;

/// Poll a future to completion without an executor. For a fake whose
/// futures are `ready`-shaped (no body ever truly awaits), one poll
/// always finishes them; a `Pending` here means the fake grew a real
/// await point, which is exactly what this asserts against. Shared by
/// `binstore/tests.rs`, `rootstore/tests.rs` and `decisionlog/tests.rs`
/// — the `BinStore`, `RootStore` and `DecisionLog` in-crate fakes all
/// qualify — so none of the three keeps its own copy.
///
/// # Panics
/// If `fut` is still `Pending` after one poll.
#[cfg(test)]
pub(crate) fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => v,
        std::task::Poll::Pending => panic!("block_on: the fake future never pends, but did"),
    }
}

/// Deterministic buffer fill (xorshift64) — the golden-vector and
/// property-test input generator. NOT a determinism-seam violation: no
/// ambient entropy, caller supplies the seed.
#[must_use]
pub fn fill(seed: u64, len: usize) -> Vec<u8> {
    // xorshift64 has a zero fixed point; remap 0 to a fixed odd constant
    // DISTINCT from any passthrough seed: seed.max(1) aliases
    // 0 to 1.
    let mut state = if seed == 0 {
        0x2545_f491_4f6c_dd1d
    } else {
        seed
    };
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Chunk `data` and assert every thresh invariant. Panics on violation.
pub fn chunk_probe(data: &[u8]) {
    let grains: Vec<crate::thresh::Grain> = crate::thresh::grains(data).collect();
    let mut pos = 0usize;
    for (i, g) in grains.iter().enumerate() {
        assert_eq!(g.offset, pos, "grains not contiguous");
        assert!(g.length > 0, "empty grain");
        assert!(
            g.length <= crate::thresh::MAX_GRAIN,
            "grain exceeds MAX_GRAIN"
        );
        if i + 1 < grains.len() {
            assert!(
                g.length >= crate::thresh::MIN_GRAIN,
                "non-final grain under MIN_GRAIN"
            );
        }
        pos += g.length;
    }
    assert_eq!(pos, data.len(), "grains do not cover input");
    if !data.is_empty() && data.len() < crate::thresh::MIN_GRAIN {
        assert_eq!(grains.len(), 1, "sub-minimum input was split");
    }
    // Hash cost bounded: only id small inputs (fuzz throughput).
    if data.len() <= 2 * 1024 * 1024 {
        for g in &grains {
            let slice = data.get(g.offset..g.offset + g.length);
            assert!(slice.is_some(), "grain range escapes buffer");
            if let Some(s) = slice {
                let _ = GrainId::of(s);
            }
        }
    }
}

/// Decode arbitrary bytes as a binary [`GrainId`]; on success, both
/// encodings must roundtrip canonically. Panics on violation.
pub fn grainid_decode_probe(data: &[u8]) {
    if let Ok(id) = GrainId::from_bytes(data) {
        assert_eq!(
            id.to_bytes().as_slice(),
            data,
            "binary roundtrip not canonical"
        );
        let text = id.to_string();
        assert!(
            text.parse::<GrainId>().is_ok_and(|back| back == id),
            "text roundtrip failed"
        );
    }
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = s.parse::<GrainId>(); // must never panic
    }
}

/// Fuzz probe: manifest object decode totality — decode any bytes as
/// an object (all four types dispatched via the envelope); when decode
/// succeeds, re-encode must reproduce the input byte-for-byte
/// (canonical-form property). The input is then reinterpreted as a
/// length-prefixed blob sequence (u16 BE length, blob)* and fed to the
/// TREE WALKER rooted at the first blob's id — walker totality (no
/// panic) is the property; Ok and Err are both fine.
pub fn manifest_decode_probe(data: &[u8]) {
    use crate::encoding::{self, ObjectType};
    use crate::manifest::{node, tree};
    if let Ok((ty, cursor)) = encoding::open_envelope(data) {
        match ty {
            ObjectType::DirLeaf => {
                if let Ok(entries) = node::decode_dir_leaf(cursor) {
                    let re = node::encode_dir_leaf(&entries)
                        .unwrap_or_else(|e| panic!("decoded implies encodable: {e}"));
                    assert_eq!(re, data, "canonical-form violation (dir leaf)");
                }
            }
            ObjectType::DirInterior => {
                if let Ok(children) = node::decode_dir_interior(cursor) {
                    let re = node::encode_dir_interior(&children)
                        .unwrap_or_else(|e| panic!("decoded implies encodable: {e}"));
                    assert_eq!(re, data, "canonical-form violation (interior)");
                }
            }
            ObjectType::GrainListLeaf => {
                if let Ok(refs) = node::decode_grain_list_leaf(cursor) {
                    let re = node::encode_grain_list_leaf(&refs)
                        .unwrap_or_else(|e| panic!("decoded implies encodable: {e}"));
                    assert_eq!(re, data, "canonical-form violation (grain-list leaf)");
                }
            }
            ObjectType::GrainListIndex => {
                if let Ok(ch) = node::decode_grain_list_index(cursor) {
                    let re = node::encode_grain_list_index(&ch)
                        .unwrap_or_else(|e| panic!("decoded implies encodable: {e}"));
                    assert_eq!(re, data, "canonical-form violation (grain-list index)");
                }
            }
            // Part II object types have their OWN probes below — this
            // probe exercises manifest decoding only (explicit arm, not
            // a wildcard: the registry-closure discipline).
            ObjectType::Bin
            | ObjectType::BinmapIndex
            | ObjectType::BinTable
            | ObjectType::BinmapShard
            | ObjectType::Root
            | ObjectType::Sheaf => {}
        }
    }
    // Walker totality over arbitrary object soups: frame the input,
    // key each blob by its real id, walk from the first blob.
    let mut c = encoding::Cursor::new(data);
    let mut map = std::collections::BTreeMap::new();
    let mut root = None;
    while let Ok(len) = c.u16() {
        let Ok(blob) = c.take(usize::from(len)) else {
            break;
        };
        let id = GrainId::of(blob);
        if root.is_none() {
            root = Some(id);
        }
        map.insert(id, blob.to_vec());
    }
    if let Some(root) = root {
        let _ = tree::validate_dir_tree(&root, &|id| map.get(id).cloned());
    }
}

/// `manifest_walk`: the cursor against the one-shot over a fuzzer-shaped
/// object map. Input: `n` (one byte, capped at 32), then `n` blobs each
/// prefixed by a little-endian `u16` length (capped at 4096), then a
/// `u32` residency mask. A frame that runs off the end is CLAMPED to the
/// bytes that remain rather than discarding the execution (see the loop).
/// Ids are computed by hashing, so a blob's
/// reference to a fabricated child is simply missing. The one-shot over
/// the whole map, the cursor fetching needs from the map, and the cursor
/// fetching hints too must agree exactly — `Ok(stats)` equal or the same
/// first error — for every input.
pub fn manifest_walk_probe(data: &[u8]) {
    use crate::manifest::{PREFETCH_HINT_MAX, Step, TreeCursor, ValidateError, validate_dir_tree};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    let mut at = 0usize;
    let Some(&n) = data.first() else { return };
    at += 1;
    let n = usize::from(n).min(32);
    let mut store: BTreeMap<GrainId, Vec<u8>> = BTreeMap::new();
    let mut order: Vec<GrainId> = Vec::new();
    for _ in 0..n {
        // A missing length prefix ends the frame; a body that runs off
        // the end is CLAMPED to what remains. Returning here instead threw
        // the WHOLE execution away, and a size-changing mutation of any
        // blob desynchronises every later length prefix, so nearly every
        // insert/erase was discarded unasserted; the sibling
        // `manifest_decode_probe` already breaks rather than returns.
        // Clamping rather than a bare `break` leaves `at` at the true end
        // of the input ON THIS PATH, so a truncated frame does not make the
        // mask below be read out of a blob's own bytes. It is not a
        // guarantee in general: a declared length ABOVE the 4,096 cap is
        // capped, `truncated` stays false, and the body's tail is parsed as
        // the next length prefix — pre-existing, unchanged here, and
        // harmless because every framing yields a self-consistent store.
        let Some(len_bytes) = data.get(at..at + 2) else {
            break;
        };
        let Ok(len_arr) = <[u8; 2]>::try_from(len_bytes) else {
            break;
        };
        let len = usize::from(u16::from_le_bytes(len_arr)).min(4096);
        at += 2;
        let blob = data
            .get(at..at + len)
            .or_else(|| data.get(at..))
            .unwrap_or_default();
        let truncated = blob.len() != len;
        at += blob.len();
        let id = GrainId::of(blob);
        order.push(id);
        store.insert(id, blob.to_vec());
        if truncated {
            break;
        }
    }
    let Some(root) = order.first().copied() else {
        return;
    };
    let mask = data
        .get(at..at + 4)
        .and_then(|m| <[u8; 4]>::try_from(m).ok())
        .map_or(0, u32::from_le_bytes);
    let initial: BTreeMap<GrainId, Vec<u8>> = order
        .iter()
        .enumerate()
        .filter(|(i, _)| i < &32 && mask & (1 << i) != 0)
        .filter_map(|(_, id)| store.get(id).map(|b| (*id, b.clone())))
        .collect();
    let reference = validate_dir_tree(&root, &|id| store.get(id).cloned());
    for hints in [false, true] {
        let resident = RefCell::new(initial.clone());
        let mut cursor = TreeCursor::new(root);
        let got = loop {
            match cursor.resume(&|id| resident.borrow().get(id).cloned()) {
                Err(e) => break Err(e),
                Ok(Step::Done(stats)) => break Ok(stats),
                Ok(Step::Need(id)) => match store.get(&id) {
                    Some(bytes) => {
                        // The in-tree `Drive::Cursor` harness asserts this and
                        // the probe did not. Without it a walker that asks for
                        // an id it already holds spins here forever: libFuzzer
                        // reports a bare timeout artefact, and
                        // `replay_committed_corpus` is killed at nextest's
                        // 120 s `terminate-after` (`.config/nextest.toml`
                        // scopes it to `package(granary-core)`) as a TIMEOUT
                        // with no diagnosis. The assert names the id instead.
                        // Asserting on a WALKER bug is this probe's whole job
                        // — `assert_eq!` below does the same; "never panic"
                        // binds malformed INPUT, not a detector firing on a
                        // real defect.
                        assert!(
                            !resident.borrow().contains_key(&id),
                            "a Need for a resident id is an unstable fetch"
                        );
                        resident.borrow_mut().insert(id, bytes.clone());
                        if hints {
                            let wanted = cursor.prefetch_hints(
                                &|id| resident.borrow().get(id).cloned(),
                                PREFETCH_HINT_MAX,
                            );
                            let mut r = resident.borrow_mut();
                            for h in wanted.entering.into_iter().chain(wanted.queued_roots) {
                                if let Some(b) = store.get(&h) {
                                    r.entry(h).or_insert_with(|| b.clone());
                                }
                            }
                        }
                    }
                    None => break Err(ValidateError::MissingObject { id }),
                },
            }
        };
        assert_eq!(got, reference, "hints={hints}");
    }
}

/// Fuzz probe: bin decode totality + canonical form — when decode
/// succeeds, slicing every extent back out and re-encoding must
/// reproduce the input byte-for-byte.
pub fn bin_decode_probe(data: &[u8]) {
    use crate::binfmt::{self, PackedFrame};
    if let Ok(entries) = binfmt::decode_bin(data) {
        let frames: Vec<PackedFrame> = entries
            .iter()
            .map(|e| PackedFrame {
                id: e.id,
                frame: binfmt::frame_bytes(data, e)
                    .unwrap_or_else(|err| panic!("decoded entry must slice: {err}"))
                    .to_vec(),
            })
            .collect();
        let re = binfmt::encode_bin(&frames)
            .unwrap_or_else(|err| panic!("decoded implies encodable: {err}"));
        assert_eq!(re, data, "canonical-form violation (bin)");
    }
}

/// Fuzz probe: binmap object decode totality + canonical form for all
/// three binmap types, dispatched via the envelope like a reader would.
pub fn binmap_decode_probe(data: &[u8]) {
    use crate::binmap;
    use crate::encoding::{self, ObjectType};
    let Ok((ty, _)) = encoding::open_envelope(data) else {
        return;
    };
    match ty {
        ObjectType::BinTable => {
            if let Ok(bins) = binmap::decode_bin_table(data) {
                let re = binmap::encode_bin_table(&bins)
                    .unwrap_or_else(|err| panic!("decoded implies encodable: {err}"));
                assert_eq!(re, data, "canonical-form violation (bin table)");
            }
        }
        ObjectType::BinmapShard => {
            if let Ok(entries) = binmap::decode_shard(data) {
                let re = binmap::encode_shard(&entries)
                    .unwrap_or_else(|err| panic!("decoded implies encodable: {err}"));
                assert_eq!(re, data, "canonical-form violation (shard)");
            }
        }
        ObjectType::BinmapIndex => {
            if let Ok(doc) = binmap::decode_binmap_index(data) {
                let re = binmap::encode_binmap_index(doc.prefix_bits, doc.bin_table, &doc.shards)
                    .unwrap_or_else(|err| panic!("decoded implies encodable: {err}"));
                assert_eq!(re, data, "canonical-form violation (binmap index)");
            }
        }
        _ => {}
    }
}

/// Fuzz probe: root decode totality + canonical form + the
/// signature-domain identity (writer-side prefix == received-bytes
/// prefix), plus hint-body parse totality over the same input
/// reinterpreted as text (the CURRENT body is untrusted input).
pub fn root_decode_probe(data: &[u8]) {
    use crate::{root, rootstore};
    if let Ok(doc) = root::decode_root(data) {
        let re = root::encode_root(&doc)
            .unwrap_or_else(|err| panic!("decoded implies encodable: {err}"));
        assert_eq!(re, data, "canonical-form violation (root)");
        let received = root::signed_prefix(data)
            .unwrap_or_else(|err| panic!("decoded implies prefix-splittable: {err}"));
        let writer = root::signing_prefix_of(&doc)
            .unwrap_or_else(|err| panic!("decoded implies prefixable: {err}"));
        assert_eq!(received, writer, "signature-domain divergence");
    }
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = rootstore::parse_hint_body(s); // must never panic
    }
}

/// Fuzz probe: sheaf decode totality + canonical form.
pub fn sheaf_decode_probe(data: &[u8]) {
    use crate::sheaf;
    if let Ok(doc) = sheaf::decode_sheaf(data) {
        let re = sheaf::encode_sheaf(&doc)
            .unwrap_or_else(|err| panic!("decoded implies encodable: {err}"));
        assert_eq!(re, data, "canonical-form violation (sheaf)");
    }
}

/// Fuzz probe: cache-index decode totality + canonical form, for BOTH
/// object kinds the shared `GRNI` envelope names.
///
/// Snapshot half: a successful `decode_snapshot` must re-encode to the
/// identical bytes (canonical form), same shape as every other decoder
/// probe in this module.
///
/// Journal half: `open_index_envelope` + `replay_journal` never panics
/// or errors by construction (the torn-tail rule), so the property this
/// half proves is different — re-encoding every RECOVERED record must
/// reproduce exactly the trusted prefix of the body: the whole body on
/// `CleanEof`, or exactly the bytes up to `TruncatedAt`'s offset and no
/// further.
pub fn cacheindex_decode_probe(data: &[u8]) {
    use crate::cacheindex::{self, JournalTail};
    if let Ok(entries) = cacheindex::decode_snapshot(data) {
        let re = cacheindex::encode_snapshot(&entries)
            .unwrap_or_else(|err| panic!("decoded implies encodable: {err}"));
        assert_eq!(re, data, "canonical-form violation (cache-index snapshot)");
    }
    if let Ok((cacheindex::FileKind::Journal, body)) = cacheindex::open_index_envelope(data) {
        let (records, tail) = cacheindex::replay_journal(body);
        let mut re = Vec::new();
        for r in &records {
            cacheindex::encode_record_into(&mut re, r);
        }
        match tail {
            JournalTail::CleanEof => {
                assert_eq!(re, body, "clean-eof replay must reproduce the whole body");
            }
            JournalTail::TruncatedAt(offset) => {
                assert_eq!(
                    re.len(),
                    offset,
                    "recovered records must span exactly the prefix before the tear"
                );
                assert_eq!(
                    re,
                    body.get(..offset).unwrap_or_default(),
                    "re-encoded prefix must match the original bytes exactly"
                );
            }
        }
    }
}

/// Fuzz probe: authority-log classification totality + canonical form.
///
/// Runs [`crate::authlog::classify`] against a FIXED volume name, and
/// again against the volume the input's own envelope names when it has
/// a valid one and it DIFFERS from the fixed volume
/// (`authlog::envelope_volume`) — a mutation that only changes
/// the envelope's volume field would otherwise never reach the
/// pairs/grammar logic under the fixed-volume run alone, since it would
/// refuse at the `WrongVolume` check every time. Skipping the second run
/// when the two volumes already agree avoids paying for the same
/// classification twice on every corpus seed (they are all built for the
/// fixed volume).
///
/// For every [`crate::authlog::Classified::Log`] verdict, re-encoding
/// the envelope and every record+mark must reproduce EXACTLY
/// `data[..committed_len]` (the canonical-form property every decoder
/// probe in this module shares), and `committed_len + tail_len` must
/// equal `data.len()`. Never panics otherwise: `NoEnvelope` and every
/// `Err` are both fine.
pub fn authlog_classify_probe(data: &[u8]) {
    use crate::authlog;
    use crate::root::VolumeName;

    // The corpus seeds are built for this volume, so a decision seed's
    // candidate root names it and reaches the body decoder's cross-field
    // checks rather than failing its volume check.
    let fixed = VolumeName::new("vol-a".to_owned()).unwrap_or_else(|e| panic!("{e}"));
    check_authlog_classify(data, &fixed);

    if let Some(named) = authlog::envelope_volume(data)
        && named != fixed
    {
        check_authlog_classify(data, &named);
    }

    // The record-body decoder, driven directly: the first byte is the
    // tag, the rest is the body. A body it accepts must re-encode to the
    // same bytes (canonical form), whatever the checks around it would
    // have said.
    if let Some((&tag, body)) = data.split_first()
        && let Ok(decoded) = authlog::decode_record_body(tag, body, &fixed)
    {
        let mut re = Vec::new();
        authlog::encode_record_body(&mut re, &decoded, &fixed)
            .unwrap_or_else(|e| panic!("a decoded body must re-encode: {e}"));
        assert_eq!(
            re, body,
            "canonical-form violation (authority log record body)"
        );
    }
}

fn check_authlog_classify(data: &[u8], volume: &crate::root::VolumeName) {
    use crate::authlog::{self, Classified};

    let Ok(verdict) = authlog::classify(data, volume) else {
        return;
    };
    let Classified::Log {
        envelope,
        records,
        committed_len,
        tail_len,
    } = verdict
    else {
        return;
    };
    assert_eq!(
        committed_len.checked_add(tail_len),
        Some(data.len()),
        "committed_len + tail_len must equal the input length"
    );
    let mut re = authlog::encode_envelope(&envelope).as_bytes().to_vec();
    for record in &records {
        let append = authlog::encode_append(&envelope, record)
            .unwrap_or_else(|e| panic!("a classified record must re-encode: {e}"));
        re.extend_from_slice(append.record());
        re.extend_from_slice(append.mark());
    }
    assert_eq!(
        re,
        data.get(..committed_len).unwrap_or_default(),
        "canonical-form violation (authority log)"
    );
}

/// The input [`runmarker_decode_probe`] decodes a second time: `data` of a
/// marker's length with its check recomputed over everything before it, or
/// `None` for any other length.
pub(crate) fn runmarker_recheck_input(data: &[u8]) -> Option<Vec<u8>> {
    use crate::runmarker::{CHECK_CONTEXT, CHECK_LEN, CLEAN_LEN, RUNNING_LEN};

    if !matches!(data.len(), CLEAN_LEN | RUNNING_LEN) {
        return None;
    }
    let mut rebuilt = data.to_vec();
    rebuilt.truncate(data.len().saturating_sub(CHECK_LEN));
    let check = blake3::derive_key(CHECK_CONTEXT, &rebuilt);
    rebuilt.extend_from_slice(&check);
    Some(rebuilt)
}

/// Fuzz body for the run marker's decoder: never panics, and a byte string
/// it accepts must be exactly what the encoder writes for the value
/// (canonical form). Random bytes almost never carry a valid check, so an
/// input of a marker's length is also decoded with its check recomputed over
/// its first `len - 32` bytes; that is what reaches the version, state and
/// length rules and the canonical-form assertion.
pub fn runmarker_decode_probe(data: &[u8]) {
    use crate::runmarker::{decode_marker, encode_marker};

    fn assert_canonical(input: &[u8]) {
        if let Ok(marker) = decode_marker(input) {
            assert_eq!(
                encode_marker(&marker).as_bytes(),
                input,
                "canonical-form violation (run marker)"
            );
        }
    }

    assert_canonical(data);
    if let Some(rebuilt) = runmarker_recheck_input(data) {
        assert_canonical(&rebuilt);
    }
}

/// The input [`enrollment_decode_probe`] decodes a second time: `data` long
/// enough to carry the header and a check, with its check recomputed over
/// everything before it, or `None` for a shorter input.
pub(crate) fn enrollment_recheck_input(data: &[u8]) -> Option<Vec<u8>> {
    use crate::enrollment::{CHECK_CONTEXT, CHECK_LEN, MIN_LEN};

    if data.len() < MIN_LEN {
        return None;
    }
    let mut rebuilt = data.to_vec();
    rebuilt.truncate(data.len().saturating_sub(CHECK_LEN));
    let check = blake3::derive_key(CHECK_CONTEXT, &rebuilt);
    rebuilt.extend_from_slice(&check);
    Some(rebuilt)
}

/// Fuzz body for the enrollment set's decoder: never panics, and a byte
/// string it accepts must be exactly what the encoder writes for the value
/// (canonical form). Random bytes almost never carry a valid check, so an
/// input long enough to carry one is also decoded with its check recomputed
/// over its first `len - 32` bytes; that is what reaches the version, count
/// and record rules and the canonical-form assertion.
pub fn enrollment_decode_probe(data: &[u8]) {
    use crate::enrollment::{decode_set, encode_set};

    fn assert_canonical(input: &[u8]) {
        if let Ok(set) = decode_set(input) {
            assert_eq!(
                encode_set(&set).as_bytes(),
                input,
                "canonical-form violation (enrollment set)"
            );
        }
    }

    assert_canonical(data);
    if let Some(rebuilt) = enrollment_recheck_input(data) {
        assert_canonical(&rebuilt);
    }
}

/// Recompute a debug grant's check only within the codec's input bounds.
pub(crate) fn debug_grant_recheck_input(data: &[u8]) -> Option<Vec<u8>> {
    use crate::debug_grant::{CHECK_CONTEXT, CHECK_LEN, ENCODED_MAX, MIN_LEN};

    if !(MIN_LEN..=ENCODED_MAX).contains(&data.len()) {
        return None;
    }
    let (covered, _) = data.split_last_chunk::<CHECK_LEN>()?;
    let mut rebuilt = covered.to_vec();
    rebuilt.extend_from_slice(&blake3::derive_key(CHECK_CONTEXT, covered));
    Some(rebuilt)
}

/// Decoder fuzz body shared with stable replay. Tries received bytes and
/// a bounded copy with a repaired check to reach field validation.
///
/// # Panics
/// If a decoded value fails construction or its input is not canonical.
pub fn debug_grant_decode_probe(data: &[u8]) {
    use crate::debug_grant::{DebugGrant, decode_grant, encode_grant};

    fn assert_canonical(bytes: &[u8]) {
        if let Ok(grant) = decode_grant(bytes) {
            assert_eq!(
                DebugGrant::new(grant.fields().clone()),
                Ok(grant.clone()),
                "decoded debug grant violates construction bounds"
            );
            assert_eq!(
                encode_grant(&grant).as_bytes(),
                bytes,
                "canonical-form violation (debug grant)"
            );
        }
    }
    assert_canonical(data);
    if let Some(repaired) = debug_grant_recheck_input(data) {
        assert_canonical(&repaired);
    }
}

/// Conformance suite for [`crate::binstore::BinStore`]: every semantic
/// the trait's docs PIN, asserted through the bound.
///
/// Generic on purpose, and shared on purpose. The trait is the surface a
/// simulator's fake and the production adapter must BOTH satisfy, and a
/// divergence between them is invisible to tests that each side writes
/// for itself — the fake stays self-consistent, production stays
/// self-consistent, and the two disagree only where an adversarial input
/// lands. Running one body against both is the only structural closure:
/// a rule that holds in one implementation and not the other cannot pass
/// here.
///
/// Panics with a message naming the violated rule. Callers supply an
/// EMPTY store — the suite writes its own objects.
///
/// # Panics
/// On any deviation from the pinned semantics.
pub async fn binstore_conformance<B: crate::binstore::BinStore>(store: &B) {
    use crate::hash::GrainId;
    use crate::rootstore::RootStoreError;

    // --- put_bin: content-addressed, so a second write is SUCCESS ----
    let body: Vec<u8> = (0..100u8).collect();
    let digest = *GrainId::of(&body).digest();
    assert_eq!(
        store.put_bin(&digest, body.clone()).await,
        Ok(true),
        "a first put_bin must report the bin NOVEL"
    );
    assert_eq!(
        store.put_bin(&digest, body.clone()).await,
        Ok(false),
        "a second put_bin must be SUCCESS reporting not-novel, never AlreadyExists"
    );

    // --- get_bin_range: the pinned range semantic, both halves -------
    assert_eq!(
        store.get_bin_range(&digest, 0, 100).await,
        Ok(body.clone()),
        "a whole-object range must return the whole object"
    );
    assert_eq!(
        store.get_bin_range(&digest, 10, 5).await,
        Ok(body.get(10..15).unwrap_or_default().to_vec()),
        "an interior range must return exactly that slice"
    );
    // Starts INSIDE, overhangs the end: short-read, never an error.
    assert_eq!(
        store.get_bin_range(&digest, 90, 50).await,
        Ok(body.get(90..100).unwrap_or_default().to_vec()),
        "an overhanging range whose start is in bounds must SHORT-READ"
    );
    // Starts AT or PAST the end, or spans nothing: a range error, never
    // an empty success. This is the half a clamp-everywhere fake gets
    // wrong while agreeing with the adapter on everything above.
    for (offset, len, why) in [
        (100u64, 8u32, "starting exactly AT the end"),
        (200, 8, "starting past the end"),
        (10, 0, "zero-length range"),
    ] {
        let got = store.get_bin_range(&digest, offset, len).await;
        assert!(
            // An implementation that reaches its store over HTTP reports the
            // server's refusal as its status, which is the same backend
            // failure typed.
            matches!(
                got,
                Err(RootStoreError::Backend(_) | RootStoreError::UnexpectedStatus { .. })
            ),
            "({offset}, {len}) — {why} — must be a range error, got {got:?}"
        );
    }
    assert_eq!(
        store.get_bin_range(&digest, u64::MAX, 1).await,
        Err(RootStoreError::RangeOverflow),
        "offset + len overflowing u64 must be refused by checked arithmetic"
    );
    let absent = *GrainId::of(b"a bin that was never put").digest();
    assert_eq!(
        store.get_bin_range(&absent, 0, 8).await,
        Err(RootStoreError::NotFound),
        "a range read of an absent bin must be NotFound, never an empty read"
    );

    // --- put_meta / get_meta ----------------------------------------
    let meta = b"a meta object".to_vec();
    let id = GrainId::of(&meta);
    assert_eq!(
        store.put_meta("vol-conf", &id, meta.clone()).await,
        Ok(true),
        "a first put_meta must report the object NOVEL"
    );
    assert_eq!(
        store.put_meta("vol-conf", &id, meta.clone()).await,
        Ok(false),
        "a second put_meta must be SUCCESS reporting not-novel"
    );
    assert_eq!(
        store.get_meta("vol-conf", &id).await,
        Ok(meta.clone()),
        "get_meta must return the bytes put_meta stored"
    );
    let absent_id = GrainId::of(b"a meta object that was never put");
    assert_eq!(
        store.get_meta("vol-conf", &absent_id).await,
        Err(RootStoreError::NotFound),
        "get_meta on an absent id must be NotFound"
    );
    // A volume is a namespace: the same id in another volume is absent.
    assert_eq!(
        store.get_meta("vol-other", &id).await,
        Err(RootStoreError::NotFound),
        "meta objects are per-volume; the same id must not leak across volumes"
    );

    // --- checked_volume, on BOTH volume-taking methods ---------------
    // A name that is not DNS-1123 must never become a key: `Path::from`
    // normalises `a/b`, `a//b` and `a/b/` into one keyspace.
    for bad in ["a/b", "a//b", "a/b/", "", "-a", "Vol"] {
        let put = store.put_meta(bad, &id, meta.clone()).await;
        assert!(
            matches!(put, Err(RootStoreError::InvalidVolume { .. })),
            "put_meta accepted the invalid volume {bad:?}: {put:?}"
        );
        let get = store.get_meta(bad, &id).await;
        assert!(
            matches!(get, Err(RootStoreError::InvalidVolume { .. })),
            "get_meta accepted the invalid volume {bad:?}: {get:?}"
        );
    }
}

/// Conformance suite for [`crate::rootstore::RootStore`]: every semantic
/// the trait's docs PIN, asserted through the bound.
///
/// Generic and shared for the same reason
/// [`binstore_conformance`] is — the trait is the surface a simulator's
/// fake and the production adapter must BOTH satisfy, and a divergence
/// between them is invisible to tests each side writes for itself. It
/// matters more here than there: the CAS scenarios (crash sweep, re-run
/// convergence, concurrent publishers, the ambiguous PUT whose probe
/// fails) are `put_root`/`get_root`/`max_seq` properties end to end, so a
/// fake that diverges makes them prove something about the fake.
///
/// The divergence is not hypothetical: the rule that `max_seq` excludes
/// seq 0 and `read_hint` treats a seq-0 hint as missing lived only in the
/// production adapter while the in-core fake implemented neither half,
/// and every test on both sides stayed green.
///
/// Panics with a message naming the violated rule. Callers supply an
/// EMPTY store — the suite writes its own roots and hints, under volume
/// names of its own so it never collides with [`binstore_conformance`].
///
/// # Panics
/// On any deviation from the pinned semantics.
pub async fn rootstore_conformance<R: crate::rootstore::RootStore>(store: &R) {
    put_root_is_create_if_absent(store).await;
    max_seq_is_the_numeric_maximum(store).await;
    seq_zero_is_never_a_head(store).await;
    seq_max_is_never_a_head(store).await;
    the_hint_is_advisory_and_revalidatable(store).await;
    a_volume_is_a_namespace(store).await;
    every_volume_taking_method_checks_the_name(store).await;
}

/// `put_root` creates IF ABSENT — and the property is not the error, it
/// is that the loser's bytes never reach the object. A last-writer-wins
/// store returns the same `AlreadyExists` and breaks the append-only
/// chain anyway.
async fn put_root_is_create_if_absent<R: crate::rootstore::RootStore>(store: &R) {
    use crate::rootstore::RootStoreError;
    let vol = "root-conf-cas";
    let winner = b"the root the first writer created".to_vec();
    let loser = b"the root a second writer must never land".to_vec();
    assert_eq!(
        store.put_root(vol, 1, winner.clone()).await,
        Ok(()),
        "a first put_root at a free seq must succeed"
    );
    assert_eq!(
        store.put_root(vol, 1, loser).await,
        Err(RootStoreError::AlreadyExists),
        "a second put_root at an occupied seq must be AlreadyExists"
    );
    assert_eq!(
        store.get_root(vol, 1).await,
        Ok(Some(winner)),
        "put-if-absent must not OVERWRITE: the loser's bytes must not be there"
    );
    assert_eq!(
        store.get_root(vol, 2).await,
        Ok(None),
        "an absent seq must be Ok(None) — the cheap 404 a forward probe expects, never an error"
    );
    assert_eq!(
        store.get_root(vol, u64::MAX).await,
        Ok(None),
        "the highest seq the key format can name is absent like any other, never an error"
    );
}

/// `max_seq` takes the NUMERIC maximum, CLIENT-side.
///
/// The seqs go in out of order and across the decimal-vs-lexicographic
/// boundary: "10" sorts below "9" as text, so an implementation that
/// trusted a sorted listing (list order is NOT a contract) answers 9.
/// What this canNOT reach through the trait is independence from listing
/// ORDER — that needs a store returning a genuinely shuffled listing,
/// which no seam method exposes.
async fn max_seq_is_the_numeric_maximum<R: crate::rootstore::RootStore>(store: &R) {
    use crate::rootstore::filter_above;

    let vol = "root-conf-max";
    for seq in [2u64, 10, 9] {
        assert_eq!(
            store.put_root(vol, seq, vec![0xD0]).await,
            Ok(()),
            "seq {seq} is free and must store"
        );
    }
    assert_eq!(
        store.max_seq(vol).await,
        Ok(Some(10)),
        "max_seq must take the NUMERIC maximum — \"10\" sorts below \"9\" lexicographically"
    );
    assert_eq!(
        store.max_seq("root-conf-empty").await,
        Ok(None),
        "a volume with no roots has no head"
    );
    // The hint lives under the same volume and is NOT a numbered root.
    assert_eq!(store.write_hint(vol, 99).await, Ok(()));
    let max = store.max_seq(vol).await;
    assert_eq!(
        max,
        Ok(Some(10)),
        "the advisory hint is not a root: writing one must not move max_seq"
    );
    for floor in [0, 2, 8, 9, 10, 11, u64::MAX] {
        assert_eq!(
            store.max_seq_above(vol, floor).await,
            max.clone().map(|seq| filter_above(seq, floor)),
            "max_seq_above must agree with max_seq strictly above floor {floor}"
        );
    }
    assert_eq!(
        store.max_seq_above("root-conf-empty", 0).await,
        Ok(None),
        "a volume with no roots has no head above the floor"
    );
}

/// SEQ 0 IS NEVER A HEAD, on either read path.
async fn seq_zero_is_never_a_head<R: crate::rootstore::RootStore>(store: &R) {
    use crate::rootstore::HintRead;
    let vol = "root-conf-zero";
    assert_eq!(
        store.put_root(vol, 0, vec![0xA0]).await,
        Ok(()),
        "the seq-0 rule is placed on the READ paths, so the write path is where the plant comes \
         from — put_root's documented failures are AlreadyExists and Backend, and neither is \
         `this seq is 0`"
    );
    assert_eq!(
        store.get_root(vol, 0).await,
        Ok(Some(vec![0xA0])),
        "the plant must really be at seq 0 — otherwise the max_seq assertion below proves nothing"
    );
    assert_eq!(
        store.max_seq(vol).await,
        Ok(None),
        "a planted seq-0 root must not become the head: it would block the first publish to a \
         fresh volume"
    );
    assert_eq!(
        store.max_seq_above(vol, 0).await,
        Ok(None),
        "a planted seq-0 root must not become the head of a bounded listing"
    );
    assert_eq!(store.put_root(vol, 1, vec![0xA1]).await, Ok(()));
    assert_eq!(
        store.max_seq(vol).await,
        Ok(Some(1)),
        "a real root still resolves alongside a planted seq 0"
    );
    assert_eq!(store.write_hint(vol, 0).await, Ok(()));
    assert_eq!(
        store.read_hint(vol, None).await,
        Ok(HintRead::Missing),
        "a hint body of 0 must degrade to Missing — Current {{ seq: 0 }} sends every reader \
         through a doomed get_root(0) first"
    );
    assert_eq!(store.write_hint(vol, 1).await, Ok(()));
    assert!(
        matches!(
            store.read_hint(vol, None).await,
            Ok(HintRead::Current { seq: 1, .. })
        ),
        "a real hint still reads back — the seq-0 degrade must not wedge the hint path"
    );
}

/// SEQ `u64::MAX` IS NEVER A HEAD — the mirror of
/// [`seq_zero_is_never_a_head`] at the other end of the range.
///
/// Seq 0 blocks the FIRST publish forever; seq `u64::MAX` blocks EVERY
/// publish forever. One create-only PUT at the top of the range leaves no
/// higher seq to advance to and no way to reclaim the one taken, so a
/// `max_seq` that answered it would terminate the volume's sequence
/// permanently. The exclusion lives on the path that SELECTS a head and
/// never at the key: the key still admits the value, `get_root` still
/// returns what was planted, and the maximum falls back to the next real
/// seq.
async fn seq_max_is_never_a_head<R: crate::rootstore::RootStore>(store: &R) {
    let vol = "root-conf-top";
    assert_eq!(
        store.put_root(vol, u64::MAX, vec![0xF0]).await,
        Ok(()),
        "the rule is placed on the READ path, so the write path is where the plant comes from \
         — `put_root` is create-if-absent and nothing else, at the top of the range exactly as \
         at seq 0: the store may create either key even though neither may be selected as head"
    );
    assert_eq!(
        store.get_root(vol, u64::MAX).await,
        Ok(Some(vec![0xF0])),
        "the exclusion is at the HEAD, not at the key: a planted root must stay readable by \
         explicit get_root, which is the only recovery path an operator has for it"
    );
    assert_eq!(
        store.max_seq(vol).await,
        Ok(None),
        "a volume whose ONLY key is u64::MAX has no head — today that volume is permanently \
         unusable, and the fallback is what makes its first publish possible"
    );
    assert_eq!(
        store.max_seq_above(vol, u64::MAX - 1).await,
        Ok(None),
        "a bounded listing must also skip a planted u64::MAX above its floor"
    );
    assert_eq!(store.put_root(vol, 5, vec![0xF5]).await, Ok(()));
    assert_eq!(
        store.max_seq(vol).await,
        Ok(Some(5)),
        "an ordinary root alongside a planted u64::MAX is the head: the maximum falls back to \
         the next real seq rather than to nothing"
    );
    // POSITIVE CONTROL. Exactly ONE value is reserved, not a band and not
    // "anything high" — an implementation that answered `None` whenever a
    // u64::MAX key existed, or that refused the top of the range wholesale,
    // passes every row above and fails here.
    assert_eq!(store.put_root(vol, u64::MAX - 1, vec![0xF1]).await, Ok(()));
    assert_eq!(
        store.max_seq(vol).await,
        Ok(Some(u64::MAX - 1)),
        "u64::MAX - 1 is the top of the USABLE range (`1 ..= u64::MAX - 1`) and an ordinary \
         head — the reserved value is one value wide"
    );
}

/// The hint is ADVISORY and REVALIDATABLE: `Missing` when there is none,
/// `Current` with a token to cache, `NotModified` for that token, and a
/// NEW token once the hint moves.
async fn the_hint_is_advisory_and_revalidatable<R: crate::rootstore::RootStore>(store: &R) {
    use crate::rootstore::HintRead;
    let vol = "root-conf-hint";
    assert_eq!(
        store.read_hint(vol, None).await,
        Ok(HintRead::Missing),
        "a volume with no hint reads Missing, never an error"
    );
    assert_eq!(store.write_hint(vol, 1).await, Ok(()));
    let first = match store.read_hint(vol, None).await {
        Ok(HintRead::Current { seq, token }) => {
            assert_eq!(seq, 1, "read_hint must answer the seq write_hint wrote");
            token
        }
        other => panic!("want Current {{ seq: 1, .. }} after write_hint(1), got {other:?}"),
    };
    assert_eq!(
        store.read_hint(vol, Some(&first)).await,
        Ok(HintRead::NotModified),
        "the token the store handed back must revalidate — the conditional hint poll's 304"
    );
    // A fresh hint INVALIDATES the cached token. A stale token that still
    // revalidated would pin a reader to a dead seq forever.
    assert_eq!(store.write_hint(vol, 2).await, Ok(()));
    match store.read_hint(vol, Some(&first)).await {
        Ok(HintRead::Current { seq, token }) => {
            assert_eq!(seq, 2, "the new hint's seq must be the one just written");
            assert_ne!(
                token, first,
                "a moved hint must mint a NEW token, or the cached one never goes stale"
            );
        }
        other => panic!("want Current {{ seq: 2, .. }} with a new token, got {other:?}"),
    }
    // A cached token against a volume that has no hint at all is the
    // LOST-HINT case the `Missing` variant names: still not an error.
    assert_eq!(
        store.read_hint("root-conf-empty", Some(&first)).await,
        Ok(HintRead::Missing),
        "a cached token must not turn an absent hint into an error"
    );
}

/// A volume is a NAMESPACE, for roots and for hints alike.
async fn a_volume_is_a_namespace<R: crate::rootstore::RootStore>(store: &R) {
    use crate::rootstore::HintRead;
    let (a, b) = ("root-conf-ns-a", "root-conf-ns-b");
    assert_eq!(store.put_root(a, 1, vec![0xBB]).await, Ok(()));
    assert_eq!(store.write_hint(a, 1).await, Ok(()));
    assert_eq!(
        store.get_root(b, 1).await,
        Ok(None),
        "seq 1 in one volume must not be visible from another"
    );
    assert_eq!(store.max_seq(b).await, Ok(None), "and neither is its head");
    assert_eq!(
        store.read_hint(b, None).await,
        Ok(HintRead::Missing),
        "hints are per-volume too"
    );
    // The same seq in another volume is a different key, so it is FREE —
    // an implementation that dropped the volume from the key would see
    // this as an occupied seq instead.
    assert_eq!(
        store.put_root(b, 1, vec![0xCC]).await,
        Ok(()),
        "the same seq in another volume must not collide"
    );
    assert_eq!(store.get_root(b, 1).await, Ok(Some(vec![0xCC])));
    assert_eq!(
        store.get_root(a, 1).await,
        Ok(Some(vec![0xBB])),
        "and the first volume's root is untouched by it"
    );
}

/// `checked_volume` on EVERY volume-taking method.
///
/// A name that is not DNS-1123 must never become a key: `Path::from`
/// normalises `a/b`, `a//b` and `a/b/` into one keyspace. Asserted per
/// METHOD — each builds its own key, so a guard on `put_root` alone
/// leaves the read and hint paths open.
async fn every_volume_taking_method_checks_the_name<R: crate::rootstore::RootStore>(store: &R) {
    use crate::rootstore::RootStoreError;
    for bad in ["a/b", "a//b", "a/b/", "", "-a", "Vol"] {
        let put = store.put_root(bad, 1, vec![0xEE]).await;
        assert!(
            matches!(put, Err(RootStoreError::InvalidVolume { .. })),
            "put_root accepted the invalid volume {bad:?}: {put:?}"
        );
        let get = store.get_root(bad, 1).await;
        assert!(
            matches!(get, Err(RootStoreError::InvalidVolume { .. })),
            "get_root accepted the invalid volume {bad:?}: {get:?}"
        );
        let read = store.read_hint(bad, None).await;
        assert!(
            matches!(read, Err(RootStoreError::InvalidVolume { .. })),
            "read_hint accepted the invalid volume {bad:?}: {read:?}"
        );
        let write = store.write_hint(bad, 1).await;
        assert!(
            matches!(write, Err(RootStoreError::InvalidVolume { .. })),
            "write_hint accepted the invalid volume {bad:?}: {write:?}"
        );
        let max = store.max_seq(bad).await;
        assert!(
            matches!(max, Err(RootStoreError::InvalidVolume { .. })),
            "max_seq accepted the invalid volume {bad:?}: {max:?}"
        );
        let above = store.max_seq_above(bad, 0).await;
        assert!(
            matches!(above, Err(RootStoreError::InvalidVolume { .. })),
            "max_seq_above accepted the invalid volume {bad:?}: {above:?}"
        );
    }
    // The guard REFUSES, it does not block: a blanket refuser would
    // satisfy every assertion in the loop above.
    let good = "root-conf-guard";
    assert_eq!(store.put_root(good, 1, vec![0xFF]).await, Ok(()));
    assert_eq!(
        store.max_seq(good).await,
        Ok(Some(1)),
        "a DNS-1123 name still resolves after the refusals"
    );
}

// ======================================================== DecisionLog

/// Fixture-seeding hook for [`decisionlog_conformance`]'s recovery-
/// verdict and startup-state cases: on-disk states no valid sequence of
/// [`crate::decisionlog::DecisionLog`] calls can produce, which each
/// implementation's own test harness must still be able to plant
/// directly. `#[doc(hidden)]` like the rest of this module — no
/// stability promise.
///
/// Not fallible: seeding a fixture is a test-harness operation, not a
/// call under test, so an implementation that cannot honour one panics
/// rather than threading a `Result` the suite would only unwrap.
pub trait DecisionLogFixture {
    /// Plant `bytes` as `volume`'s log content exactly, bypassing every
    /// `DecisionLog` call (`initialise`, `append`, `truncate`, ...).
    /// Used to seed a torn tail, or an otherwise-invalid file, that only
    /// [`crate::authlog::classify`] — never `DecisionLog::read` itself,
    /// which never classifies — reacts to.
    fn seed_bytes(
        &self,
        volume: &crate::root::VolumeName,
        bytes: Vec<u8>,
    ) -> impl Future<Output = ()> + Send;

    /// Plant `bytes` as the marker's content exactly, bypassing
    /// [`crate::decisionlog::DecisionLog::write_marker`] and its codec:
    /// bytes no encoder produced (a torn or damaged marker, or a
    /// zero-length file). Test-only; the seam must hand them back
    /// uninterpreted.
    fn seed_marker_bytes(&self, bytes: &[u8]) -> impl Future<Output = ()> + Send;

    /// Make the state directory exist and hold nothing: no marker, no
    /// volume's log, no temporary. No sequence of successful
    /// `DecisionLog` calls reaches this state — `write_marker` and
    /// `initialise` are the only calls that create the directory, and
    /// both leave something in it when they succeed (one failing after
    /// its directory creation can leave it empty, which this suite, with
    /// no fault model, cannot produce) — so `read_marker`'s
    /// `Missing { state_dir: Empty }` row needs this hook seeded directly.
    fn seed_empty_state_dir(&self) -> impl Future<Output = ()> + Send;

    /// Plant `volume`'s exact-named leftover temporary, bypassing every
    /// `DecisionLog` call. The only real way one is ever created is an
    /// `initialise` interrupted between its link and its unlink — a
    /// crash this suite (with no crash model) cannot produce on its
    /// own — so [`crate::decisionlog::DecisionLog::remove_temporary`]'s conformance case
    /// needs this hook.
    fn seed_temporary(&self, volume: &crate::root::VolumeName) -> impl Future<Output = ()> + Send;

    /// Whether the store's state directory is provisioned: it exists
    /// before the store is built, and a store refuses to be built without
    /// it, so `Absent` is never observed. Such a store starts, and
    /// [`reset`](Self::reset) returns it, with the directory existing and
    /// empty, and the suite expects `Empty` wherever it would otherwise
    /// expect `Absent`. The default is `false`: the store creates the
    /// directory in its first write.
    fn state_dir_provisioned(&self) -> bool {
        false
    }

    /// Return the store to its just-constructed state: no marker, no
    /// volumes, no temporaries, the state directory absent (existing and
    /// empty, for a [provisioned](Self::state_dir_provisioned) one). The suite
    /// otherwise shares one store throughout a single
    /// [`decisionlog_conformance`] run, and nothing in `DecisionLog`
    /// itself ever un-writes the marker or un-creates the directory —
    /// this is the only way to observe `Missing { state_dir: Absent }`
    /// more than once in one run.
    fn reset(&self) -> impl Future<Output = ()> + Send;
}

/// A validated volume name for one of this suite's fixed fixture names.
fn decisionlog_conf_volume(name: &str) -> crate::root::VolumeName {
    crate::root::VolumeName::new(name.to_owned()).unwrap_or_else(|e| panic!("{e}"))
}

/// A minimal, valid envelope naming `volume` — any fixed epoch, since
/// these checks never touch recovery's epoch-matching rule.
fn decisionlog_conf_envelope(volume: &crate::root::VolumeName) -> crate::authlog::Envelope {
    crate::authlog::Envelope::new(
        volume.clone(),
        crate::authlog::Epoch::from_bytes([0x42; crate::authlog::EPOCH_LEN]),
    )
}

/// A minimal, valid record at `seq`: a decision of a seq-1 root of
/// `volume`, the one record kind that opens an entry on its own, so a
/// log holding it alone at seq 1 classifies as a log with an open
/// entry. `seed` makes the identity and the candidate distinct. The
/// suite never classifies a log holding one at another seq —
/// `DecisionLog` moves bytes, it does not interpret them.
fn decisionlog_conf_record(
    volume: &crate::root::VolumeName,
    seq: u64,
    seed: u8,
) -> crate::authlog::Record {
    let doc = crate::root::RootDoc {
        volume: volume.clone(),
        seq: 1,
        parent: None,
        writer_uuid: [seed; crate::root::WRITER_UUID_LEN],
        epoch: 1,
        timestamp: crate::sheaf::Timestamp {
            secs: 1_760_000_000,
            nanos: 0,
        },
        chunker_spec: "dlog-conf".to_owned(),
        manifest_root: GrainId::of(&[seed]),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![crate::root::RootSig {
            key_id: [0x01; crate::root::KEY_ID_LEN],
            sig: [0x02; crate::root::ED25519_SIG_LEN],
        }],
    };
    let candidate = crate::root::encode_root(&doc).unwrap_or_else(|e| panic!("{e}"));
    let identity = crate::authlog::SubmissionIdentity::new(
        crate::authlog::Tenant::new(vec![seed]).unwrap_or_else(|e| panic!("{e}")),
        crate::authlog::Principal::new(vec![seed]).unwrap_or_else(|e| panic!("{e}")),
        crate::authlog::Operation::new(vec![seed]).unwrap_or_else(|e| panic!("{e}")),
        GrainId::of(&candidate),
    );
    crate::authlog::Record::new(
        seq,
        crate::authlog::RecordBody::Decision {
            identity,
            root_seq: 1,
            base: None,
            decided_at: crate::sheaf::Timestamp {
                secs: 1_760_000_001,
                nanos: 0,
            },
            candidate: crate::authlog::RootBytes::new(candidate).unwrap_or_else(|e| panic!("{e}")),
        },
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

/// A committed record and mark at `seq` of `envelope`'s log under the
/// tag the authority-log registry reserves (`0x05`), each with a check
/// that holds, and a body laid out as a stale-base refusal: the
/// submission identity (tenant `11`, principal `2222`, operation `33`,
/// `candidate_id`), a reason byte `0x01`, and a present head (seq 5, the
/// id of `b"head"`). v1 never writes this tag, so a log holding the pair
/// is committed history no correct writer produces, and it must refuse.
///
///
/// # Panics
/// Never for the fixed fields it encodes.
#[must_use]
pub fn authlog_reserved_tag_pair(
    envelope: &crate::authlog::Envelope,
    seq: u64,
    candidate_id: GrainId,
) -> Vec<u8> {
    use crate::authlog;

    let mut body = Vec::new();
    authlog::encode_hex16(&mut body, &[0x11]);
    authlog::encode_hex16(&mut body, &[0x22, 0x22]);
    authlog::encode_hex16(&mut body, &[0x33]);
    body.extend_from_slice(&candidate_id.to_bytes());
    body.push(0x01);
    body.push(0x01);
    body.extend_from_slice(&5u64.to_be_bytes());
    body.extend_from_slice(&GrainId::of(b"head").to_bytes());

    let tag = 0x05;
    let mut out = vec![tag];
    out.extend_from_slice(&envelope.version().to_be_bytes());
    out.extend_from_slice(&envelope.epoch().to_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    let body_len = u32::try_from(body.len()).unwrap_or_else(|e| panic!("{e}"));
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(&body);
    let check = blake3::derive_key(authlog::RECORD_CONTEXT, &out);
    out.extend_from_slice(&check);
    out.extend_from_slice(&authlog::build_mark(envelope.epoch(), seq, tag, check));
    out
}

/// Conformance suite for [`crate::decisionlog::DecisionLog`]: every
/// semantic the trait's docs and spec §8's contract card pin, asserted
/// through the bound — one body per seam trait, run at every
/// implementation site, the same shape as [`binstore_conformance`] and
/// [`rootstore_conformance`]. Generic and shared for the same reason
/// those are — a fake that stays self-consistent and a production
/// adapter that stays self-consistent can still disagree on the
/// semantic, and this is the only body that runs against both.
///
/// Asserts EXACT bytes and records, never mere re-encoding: every
/// round-trip below compares the log's bytes byte for byte, and the
/// recovery-verdict cases run [`crate::authlog::classify`] on
/// [`crate::decisionlog::DecisionLog::read`]'s own result rather than on
/// bytes the suite built by hand.
///
/// Callers supply an EMPTY store, under volume names of its own
/// (`dlog-conf-*`) so it never collides with another suite sharing the
/// same store. The `read_marker` check runs FIRST and must: every other
/// check below calls `initialise`, which creates a volume's log in the
/// one shared state directory and makes it `Occupied` for the rest of
/// the run.
///
/// Fault-injection behaviour (a fake's crash-consistency model) is
/// explicitly out of reach here, by construction, the same as it is for
/// [`binstore_conformance`]/[`rootstore_conformance`]'s fault
/// schedules — it is tested separately, on the fake alone.
///
/// Panics with a message naming the violated rule.
///
/// # Panics
/// On any deviation from the pinned semantics.
pub async fn decisionlog_conformance<L>(log: &L)
where
    L: crate::decisionlog::DecisionLog + DecisionLogFixture,
{
    decisionlog_marker_states_and_round_trip(log).await;
    decisionlog_append_then_read(log).await;
    decisionlog_initialise_twice_is_already_exists_and_unchanged(log).await;
    decisionlog_complete_namespace_is_idempotent(log).await;
    decisionlog_truncate_then_read(log).await;
    decisionlog_truncate_refuses_out_of_range(log).await;
    decisionlog_resync_changes_nothing(log).await;
    decisionlog_missing_log_versus_present_invalid(log).await;
    decisionlog_volume_is_a_namespace(log).await;
    decisionlog_mutating_calls_on_a_never_initialised_volume_are_not_found(log).await;
    decisionlog_remove_temporary_removes_only_the_temporary(log).await;
    decisionlog_torn_tail_discarded_after_truncate(log).await;
}

/// `read_marker`'s three `Missing` states, a `write_marker` that
/// succeeds straight from `Absent`, and a `write_marker`/`read_marker`
/// round-trip from an occupied directory. MUST run before any other
/// check in this suite: `Absent` is true only of a wholly untouched
/// store, and every other check below calls `initialise`. Uses
/// [`DecisionLogFixture::reset`] to observe `Absent` a second time,
/// since nothing in `DecisionLog` itself ever un-writes a marker. A store
/// whose state directory is
/// [provisioned](DecisionLogFixture::state_dir_provisioned) never reads
/// `Absent`: it starts `Empty`, and its first `write_marker` is from
/// `Empty`.
async fn decisionlog_marker_states_and_round_trip<L>(log: &L)
where
    L: crate::decisionlog::DecisionLog + DecisionLogFixture,
{
    use crate::decisionlog::{MarkerRead, StateDirectory};
    use crate::runmarker::{BootId, RunMarker, encode_marker};

    let untouched = if log.state_dir_provisioned() {
        StateDirectory::Empty
    } else {
        StateDirectory::Absent
    };
    assert_eq!(
        log.read_marker().await,
        Ok(MarkerRead::Missing {
            state_dir: untouched
        }),
        "an untouched store's state directory must read Absent (Empty when provisioned)"
    );
    // write_marker must succeed straight from Absent: it is the call
    // that CREATES the state directory, not one that presupposes it
    // (unless the directory is provisioned, when this is from Empty).
    let from_absent = encode_marker(&RunMarker::Running(BootId::from_bytes([0x11; 16])));
    log.write_marker(&from_absent).await.unwrap_or_else(|e| {
        panic!("write_marker must succeed from an untouched state directory: {e}")
    });
    assert_eq!(
        log.read_marker().await,
        Ok(MarkerRead::Present(from_absent.as_bytes().to_vec())),
        "read_marker must answer exactly the bytes write_marker wrote, even from Absent"
    );

    log.reset().await;
    assert_eq!(
        log.read_marker().await,
        Ok(MarkerRead::Missing {
            state_dir: untouched
        }),
        "reset must return the store to its just-constructed state"
    );
    log.seed_empty_state_dir().await;
    assert_eq!(
        log.read_marker().await,
        Ok(MarkerRead::Missing {
            state_dir: StateDirectory::Empty
        }),
        "a state directory holding nothing must read Empty, not Absent"
    );
    log.seed_bytes(
        &decisionlog_conf_volume("dlog-conf-marker-occupant"),
        b"anything at all".to_vec(),
    )
    .await;
    assert_eq!(
        log.read_marker().await,
        Ok(MarkerRead::Missing {
            state_dir: StateDirectory::Occupied
        }),
        "a state directory holding an occupant with no marker must read Occupied"
    );
    let marker = encode_marker(&RunMarker::Clean);
    log.write_marker(&marker).await.unwrap_or_else(|e| {
        panic!("write_marker must succeed on an occupied state directory: {e}")
    });
    assert_eq!(
        log.read_marker().await,
        Ok(MarkerRead::Present(marker.as_bytes().to_vec())),
        "read_marker must answer exactly the bytes write_marker wrote"
    );

    // The seam moves bytes and never decodes them: whatever the medium
    // holds at the marker's name comes back as Present, damaged, empty or
    // not a marker at all. Refusing them is the engine's startup table's job.
    let mut flipped = marker.as_bytes().to_vec();
    if let Some(byte) = flipped.last_mut() {
        *byte ^= 0x01;
    }
    let planted: [(&[u8], &str); 3] = [
        (
            b"opaque marker bytes, uninterpreted by this seam",
            "non-marker bytes",
        ),
        (b"", "a zero-length marker file"),
        (&flipped, "a valid marker with one byte flipped"),
    ];
    for (bytes, what) in planted {
        log.seed_marker_bytes(bytes).await;
        assert_eq!(
            log.read_marker().await,
            Ok(MarkerRead::Present(bytes.to_vec())),
            "read_marker must answer {what} verbatim as Present, not interpret it"
        );
    }
}

/// `append` then `read`: the log holds exactly the envelope plus every
/// appended record and its mark, byte for byte.
async fn decisionlog_append_then_read<L>(log: &L)
where
    L: crate::decisionlog::DecisionLog + DecisionLogFixture,
{
    let vol = decisionlog_conf_volume("dlog-conf-append");
    let envelope = decisionlog_conf_envelope(&vol);
    let encoded_envelope = crate::authlog::encode_envelope(&envelope);
    log.initialise(&encoded_envelope)
        .await
        .unwrap_or_else(|e| panic!("initialise on a free name must succeed: {e}"));
    let record = decisionlog_conf_record(&vol, 1, 0xA0);
    let append =
        crate::authlog::encode_append(&envelope, &record).unwrap_or_else(|e| panic!("{e}"));
    log.append(&append)
        .await
        .unwrap_or_else(|e| panic!("append after initialise must succeed: {e}"));

    let mut expected = encoded_envelope.as_bytes().to_vec();
    expected.extend_from_slice(append.record());
    expected.extend_from_slice(append.mark());
    assert_eq!(
        log.read(&vol).await,
        Ok(Some(expected)),
        "append then read must return exactly the envelope plus the appended record and mark"
    );
}

/// `initialise` on an existing name must be `AlreadyExists`, and must
/// leave the existing bytes exactly as they were — never overwritten
/// with the new envelope it was refused.
async fn decisionlog_initialise_twice_is_already_exists_and_unchanged<L>(log: &L)
where
    L: crate::decisionlog::DecisionLog + DecisionLogFixture,
{
    let vol = decisionlog_conf_volume("dlog-conf-init-twice");
    let envelope = decisionlog_conf_envelope(&vol);
    log.initialise(&crate::authlog::encode_envelope(&envelope))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let before = log.read(&vol).await;

    // A DIFFERENT envelope (a distinct epoch) naming the SAME volume: if
    // the second initialise silently overwrote, `before` and the
    // post-call read would diverge.
    let other_envelope = crate::authlog::Envelope::new(
        vol.clone(),
        crate::authlog::Epoch::from_bytes([0x99; crate::authlog::EPOCH_LEN]),
    );
    assert_eq!(
        log.initialise(&crate::authlog::encode_envelope(&other_envelope))
            .await,
        Err(crate::decisionlog::LogIoError::AlreadyExists),
        "initialise on an occupied name must be AlreadyExists"
    );
    assert_eq!(
        log.read(&vol).await,
        before,
        "a refused initialise must leave the existing bytes exactly unchanged"
    );
}

/// `complete_namespace` is idempotent: calling it again once it has
/// returned changes nothing.
async fn decisionlog_complete_namespace_is_idempotent<L>(log: &L)
where
    L: crate::decisionlog::DecisionLog + DecisionLogFixture,
{
    let vol = decisionlog_conf_volume("dlog-conf-complete-ns");
    let envelope = decisionlog_conf_envelope(&vol);
    log.initialise(&crate::authlog::encode_envelope(&envelope))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    log.complete_namespace(&vol)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let after_first = log.read(&vol).await;
    log.complete_namespace(&vol)
        .await
        .unwrap_or_else(|e| panic!("complete_namespace must be idempotent: {e}"));
    assert_eq!(
        log.read(&vol).await,
        after_first,
        "a second complete_namespace must change nothing"
    );
}

/// `truncate` then `read`, on a wholly ordinary (untorn) log: truncating
/// away a later, fully-valid record leaves exactly the earlier prefix.
async fn decisionlog_truncate_then_read<L>(log: &L)
where
    L: crate::decisionlog::DecisionLog + DecisionLogFixture,
{
    let vol = decisionlog_conf_volume("dlog-conf-truncate");
    let envelope = decisionlog_conf_envelope(&vol);
    log.initialise(&crate::authlog::encode_envelope(&envelope))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let first = crate::authlog::encode_append(&envelope, &decisionlog_conf_record(&vol, 1, 0xB0))
        .unwrap_or_else(|e| panic!("{e}"));
    log.append(&first).await.unwrap_or_else(|e| panic!("{e}"));
    let prefix = log
        .read(&vol)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("just-initialised volume must read Some"));
    let second = crate::authlog::encode_append(&envelope, &decisionlog_conf_record(&vol, 2, 0xB1))
        .unwrap_or_else(|e| panic!("{e}"));
    log.append(&second).await.unwrap_or_else(|e| panic!("{e}"));

    let cut = u64::try_from(prefix.len()).unwrap_or_else(|e| panic!("{e}"));
    log.truncate(&vol, cut)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        log.read(&vol).await,
        Ok(Some(prefix)),
        "truncate must leave exactly the untouched prefix"
    );
}

/// `truncate` to a length longer than the file refuses with
/// `OutOfRange`, and leaves the bytes exactly unchanged. A fake that
/// silently no-ops on a too-long `len` (plain `Vec::truncate`'s own
/// behaviour, unless guarded) passes every other truncate case above and
/// fails only here.
async fn decisionlog_truncate_refuses_out_of_range<L>(log: &L)
where
    L: crate::decisionlog::DecisionLog + DecisionLogFixture,
{
    let vol = decisionlog_conf_volume("dlog-conf-truncate-range");
    let envelope = decisionlog_conf_envelope(&vol);
    log.initialise(&crate::authlog::encode_envelope(&envelope))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let append = crate::authlog::encode_append(&envelope, &decisionlog_conf_record(&vol, 1, 0xB2))
        .unwrap_or_else(|e| panic!("{e}"));
    log.append(&append).await.unwrap_or_else(|e| panic!("{e}"));
    let before = log
        .read(&vol)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("just-appended volume must read Some"));
    let too_far = u64::try_from(before.len()).unwrap_or_else(|e| panic!("{e}")) + 1;
    assert_eq!(
        log.truncate(&vol, too_far).await,
        Err(crate::decisionlog::LogIoError::OutOfRange),
        "truncate past the file's end must refuse, never silently no-op"
    );
    assert_eq!(
        log.read(&vol).await,
        Ok(Some(before)),
        "a refused truncate must leave the bytes exactly unchanged"
    );
}

/// `resync` changes no byte.
async fn decisionlog_resync_changes_nothing<L>(log: &L)
where
    L: crate::decisionlog::DecisionLog + DecisionLogFixture,
{
    let vol = decisionlog_conf_volume("dlog-conf-resync");
    let envelope = decisionlog_conf_envelope(&vol);
    log.initialise(&crate::authlog::encode_envelope(&envelope))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let append = crate::authlog::encode_append(&envelope, &decisionlog_conf_record(&vol, 1, 0xC0))
        .unwrap_or_else(|e| panic!("{e}"));
    log.append(&append).await.unwrap_or_else(|e| panic!("{e}"));
    let before = log.read(&vol).await;
    log.resync(&vol).await.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(log.read(&vol).await, before, "resync must change no byte");
}

/// A missing log (`Ok(None)`) versus a present but invalid one
/// (`Ok(Some(_))`, which `read` never classifies — that is
/// [`crate::authlog::classify`]'s job on the bytes it returns).
async fn decisionlog_missing_log_versus_present_invalid<L>(log: &L)
where
    L: crate::decisionlog::DecisionLog + DecisionLogFixture,
{
    assert_eq!(
        log.read(&decisionlog_conf_volume("dlog-conf-missing"))
            .await,
        Ok(None),
        "a volume with no log must read None"
    );

    let vol = decisionlog_conf_volume("dlog-conf-invalid");
    // Longer than any v1 envelope can ever be, and not a whole envelope,
    // so `classify` must refuse it rather than call it an empty log —
    // yet `read` must return it exactly, whole and uninterpreted.
    let garbage = vec![0xAAu8; 200];
    log.seed_bytes(&vol, garbage.clone()).await;
    assert_eq!(
        log.read(&vol).await,
        Ok(Some(garbage.clone())),
        "a present, invalid file must read Some(_) with its exact bytes, never None"
    );
    assert!(
        crate::authlog::classify(&garbage, &vol).is_err(),
        "the invalid bytes read must themselves refuse to classify"
    );
}

/// A volume is a NAMESPACE: one volume's log is invisible from another,
/// and two volumes' distinct envelopes never collide.
async fn decisionlog_volume_is_a_namespace<L>(log: &L)
where
    L: crate::decisionlog::DecisionLog + DecisionLogFixture,
{
    let a = decisionlog_conf_volume("dlog-conf-ns-a");
    let b = decisionlog_conf_volume("dlog-conf-ns-b");
    let envelope_a = decisionlog_conf_envelope(&a);
    log.initialise(&crate::authlog::encode_envelope(&envelope_a))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        log.read(&b).await,
        Ok(None),
        "a log created for one volume must not be visible from another"
    );
    let envelope_b = decisionlog_conf_envelope(&b);
    log.initialise(&crate::authlog::encode_envelope(&envelope_b))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(
        log.read(&a).await,
        log.read(&b).await,
        "two volumes' distinct envelopes must not collide"
    );
}

/// `append`, `truncate`, `resync` and `complete_namespace` on a volume
/// that was never `initialise`d all answer `NotFound`, and create
/// nothing: `read` still answers `None` afterward.
async fn decisionlog_mutating_calls_on_a_never_initialised_volume_are_not_found<L>(log: &L)
where
    L: crate::decisionlog::DecisionLog + DecisionLogFixture,
{
    let vol = decisionlog_conf_volume("dlog-conf-never-init");
    let envelope = decisionlog_conf_envelope(&vol);
    let append = crate::authlog::encode_append(&envelope, &decisionlog_conf_record(&vol, 1, 0xE0))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        log.append(&append).await,
        Err(crate::decisionlog::LogIoError::NotFound),
        "append on a never-initialised volume must be NotFound"
    );
    assert_eq!(
        log.truncate(&vol, 0).await,
        Err(crate::decisionlog::LogIoError::NotFound),
        "truncate on a never-initialised volume must be NotFound"
    );
    assert_eq!(
        log.resync(&vol).await,
        Err(crate::decisionlog::LogIoError::NotFound),
        "resync on a never-initialised volume must be NotFound"
    );
    assert_eq!(
        log.complete_namespace(&vol).await,
        Err(crate::decisionlog::LogIoError::NotFound),
        "complete_namespace on a never-initialised volume must be NotFound"
    );
    assert_eq!(
        log.read(&vol).await,
        Ok(None),
        "none of the refused calls above may have created a log"
    );
}

/// `remove_temporary`: `Ok(false)` when there is none; `Ok(true)`, then
/// gone, when one was seeded — and it never touches the log's own name:
/// seeding both a log and a temporary for the same volume and removing
/// the temporary must leave the log's bytes exactly as they were.
async fn decisionlog_remove_temporary_removes_only_the_temporary<L>(log: &L)
where
    L: crate::decisionlog::DecisionLog + DecisionLogFixture,
{
    let vol = decisionlog_conf_volume("dlog-conf-remove-temp");
    assert_eq!(
        log.remove_temporary(&vol).await,
        Ok(false),
        "removing an absent temporary must be Ok(false), never an error"
    );

    let envelope = decisionlog_conf_envelope(&vol);
    log.initialise(&crate::authlog::encode_envelope(&envelope))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let log_bytes = log.read(&vol).await;
    log.seed_temporary(&vol).await;
    assert_eq!(
        log.remove_temporary(&vol).await,
        Ok(true),
        "removing a seeded temporary must be Ok(true)"
    );
    assert_eq!(
        log.read(&vol).await,
        log_bytes,
        "removing the temporary must never touch the log's own bytes"
    );
    assert_eq!(
        log.remove_temporary(&vol).await,
        Ok(false),
        "the temporary is gone: a second removal must be Ok(false)"
    );

    // `complete_namespace` removes a leftover temporary beside an existing
    // log, and leaves the log's bytes alone.
    log.seed_temporary(&vol).await;
    log.complete_namespace(&vol)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        log.remove_temporary(&vol).await,
        Ok(false),
        "complete_namespace must remove the leftover temporary"
    );
    assert_eq!(log.read(&vol).await, log_bytes, "and never touch the log");

    // `initialise` removes a leftover temporary before it publishes, so a
    // stale temporary cannot block a first initialise.
    let fresh = decisionlog_conf_volume("dlog-conf-init-over-temp");
    log.seed_temporary(&fresh).await;
    log.initialise(&crate::authlog::encode_envelope(
        &decisionlog_conf_envelope(&fresh),
    ))
    .await
    .unwrap_or_else(|e| panic!("initialise over a leftover temporary: {e}"));
    assert_eq!(
        log.remove_temporary(&fresh).await,
        Ok(false),
        "initialise must remove the leftover temporary"
    );
}

/// The recovery-verdict case `truncate` exists for: a torn tail —
/// bytes no valid `append` could leave, seeded through the fixture
/// hook — is discarded by `truncate`, leaving the committed prefix
/// exactly, which then classifies clean.
async fn decisionlog_torn_tail_discarded_after_truncate<L>(log: &L)
where
    L: crate::decisionlog::DecisionLog + DecisionLogFixture,
{
    let vol = decisionlog_conf_volume("dlog-conf-recovery-torn");
    let envelope = decisionlog_conf_envelope(&vol);
    let append = crate::authlog::encode_append(&envelope, &decisionlog_conf_record(&vol, 1, 0xD0))
        .unwrap_or_else(|e| panic!("{e}"));
    let mut committed = crate::authlog::encode_envelope(&envelope)
        .as_bytes()
        .to_vec();
    committed.extend_from_slice(append.record());
    committed.extend_from_slice(append.mark());

    // A tail no valid `append` can leave: garbage with no mark inside
    // it — the interrupted-append shape recovery's `truncate` exists to
    // discard (spec §6.4).
    let mut torn = committed.clone();
    torn.extend_from_slice(&[0xEFu8; 30]);
    log.seed_bytes(&vol, torn).await;

    let seeded = log
        .read(&vol)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("seeded bytes must read back"));
    let committed_len = match crate::authlog::classify(&seeded, &vol) {
        Ok(crate::authlog::Classified::Log {
            committed_len,
            tail_len,
            ..
        }) => {
            assert!(
                tail_len > 0,
                "the fixture's tail must actually need discarding"
            );
            committed_len
        }
        other => panic!("a torn tail must classify as Log with a tail: {other:?}"),
    };

    let cut = u64::try_from(committed_len).unwrap_or_else(|e| panic!("{e}"));
    log.truncate(&vol, cut)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        log.read(&vol).await,
        Ok(Some(committed)),
        "truncate must discard exactly the torn tail, byte for byte"
    );
    let after = log
        .read(&vol)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("truncated volume must still read Some"));
    match crate::authlog::classify(&after, &vol) {
        Ok(crate::authlog::Classified::Log { tail_len: 0, .. }) => {}
        other => panic!("the truncated log must classify clean, with no tail left: {other:?}"),
    }
}

/// Strict mount-control totality, frame-bound and canonical re-encoding probe.
pub fn mount_control_decode_probe(bytes: &[u8]) {
    if let Ok(prefix) = bytes.get(..4).unwrap_or_default().try_into() {
        let _ = crate::mount_control::frame_length(prefix);
    }
    if let Ok(value) = crate::mount_control::decode(bytes) {
        assert_eq!(crate::mount_control::encode(&value).as_deref(), Ok(bytes));
    }
}

/// Strict support-trigger totality, frame-bound and canonical re-encoding probe.
pub fn support_trigger_decode_probe(bytes: &[u8]) {
    if let Ok(prefix) = bytes.get(..4).unwrap_or_default().try_into() {
        let _ = crate::support_trigger::header_frame_length(prefix);
        let _ = crate::support_trigger::bundle_frame_length(prefix);
    }
    if crate::support_trigger::decode_request(bytes).is_ok() {
        assert_eq!(bytes, crate::support_trigger::request());
    }
    if let Ok(value) = crate::support_trigger::decode_header(bytes) {
        assert_eq!(
            crate::support_trigger::encode_header(&value).as_deref(),
            Ok(bytes)
        );
    }
    support_bundle_decode_probe(bytes);
}

/// Strict publish-answer and volume-status totality and canonical re-encoding probe.
pub fn authority_answer_decode_probe(data: &[u8]) {
    if let Ok(status) = crate::authority_answer::decode_status(data) {
        assert_eq!(
            crate::authority_answer::encode_status(status).as_deref(),
            Ok(data)
        );
    }
    if let Ok(answer) = crate::authority_answer::decode(data) {
        assert_eq!(crate::authority_answer::encode(answer).as_deref(), Ok(data));
    }
}

/// Strict intent-body totality and canonical re-encoding probe: every input
/// either refuses or decodes to a value that re-encodes to the same bytes, for
/// each of the four bodies. The signature step accepts, so the structural
/// rules are what the input exercises.
pub fn intent_decode_probe(data: &[u8]) {
    use crate::intent as i;
    let Ok(volume) = crate::root::VolumeName::new("granary-test".to_owned()) else {
        return;
    };
    let accept = |_: &crate::root::RootDoc, _: &[u8]| true;
    if let Ok(r) = i::decode_register(data, &volume, accept) {
        assert_eq!(
            i::encode_register(&r.writer, r.epoch, &r.instance, r.generation, r.root).as_deref(),
            Ok(data)
        );
    }
    if let Ok(r) = i::decode_ownership(data) {
        assert_eq!(i::encode_ownership(r).as_deref(), Ok(data));
    }
    if let Ok(r) = i::decode_grant(data) {
        assert_eq!(i::encode_grant(r).as_deref(), Ok(data));
    }
    if let Ok(r) = i::decode_release(data) {
        assert_eq!(i::encode_release(r).as_deref(), Ok(data));
    }
    if let Ok(r) = i::decode_receipt(data) {
        assert_eq!(i::encode_receipt(r).as_deref(), Ok(data));
    }
    if let Ok(r) = i::decode_readback(data, &volume, accept) {
        assert_eq!(i::encode_readback(r.cursor, &r.rows).as_deref(), Ok(data));
    }
}

/// Accepted archive names must round-trip to the exact canonical input bytes.
pub fn archive_name_probe(data: &[u8]) {
    if let Ok(Some(name)) = crate::retained_archive::ArchiveName::parse(data) {
        assert_eq!(name.file_name().as_bytes(), data);
    }
}

/// Exercise the complete retained decoder and, with repaired envelope checks,
/// its structural rules. V2 must encode identically, and v1 upgrades to v2
/// without changing the decoded submission.
/// # Panics
/// If a decoded submission fails its version's canonical encoding rules.
pub fn retained_submission_decode_probe(data: &[u8]) {
    use crate::retained_submission::{self as r, MAX_BYTES};
    let check_canonical = |bytes: &[u8]| {
        if let Ok(value) = r::decode(bytes) {
            let canonical =
                r::encode(&value).unwrap_or_else(|err| panic!("decoded implies encodable: {err}"));
            if bytes.get(8..10) == Some(&[0, 1]) {
                assert_eq!(value.unavailable_exemptions, 0);
                assert_eq!(r::decode(&canonical), Ok(value));
            } else {
                assert_eq!(canonical, bytes);
            }
        }
    };
    check_canonical(data);
    if !(46..=MAX_BYTES).contains(&data.len()) {
        return;
    }
    let mut bytes = data.to_vec();
    repair_retained_submission_check(&mut bytes);
    check_canonical(&bytes);
}

/// Construct older-format bytes for a store fixture with a known v1 value.
/// # Panics
/// If the value is invalid or contains exemptions that v1 cannot represent.
#[must_use]
pub fn retained_submission_v1_fixture(value: &crate::retained_submission::Submission) -> Vec<u8> {
    assert_eq!(value.unavailable_exemptions, 0);
    let mut bytes = crate::retained_submission::encode(value)
        .unwrap_or_else(|err| panic!("fixture must be encodable: {err}"));
    // The old payload omits the final two-byte field before the check.
    bytes.truncate(bytes.len() - 2);
    if let Some(version) = bytes.get_mut(8..10) {
        version.copy_from_slice(&1_u16.to_be_bytes());
    }
    repair_retained_submission_check(&mut bytes);
    bytes
}

fn repair_retained_submission_check(bytes: &mut [u8]) {
    use crate::retained_submission::CHECK_CONTEXT;
    let Ok(len) = u32::try_from(bytes.len()) else {
        return;
    };
    if let Some(field) = bytes.get_mut(10..14) {
        field.copy_from_slice(&len.to_be_bytes());
    }
    let end = bytes.len() - 32;
    if let Some((body, check)) = bytes.split_at_mut_checked(end) {
        check.copy_from_slice(&blake3::derive_key(CHECK_CONTEXT, body));
    }
}

/// Support decoder fuzz body: bounded inputs and checksum-repaired counterparts.
/// # Panics
/// If decoding accepts bytes that cannot be canonically re-encoded.
pub fn support_snapshot_decode_probe(data: &[u8]) {
    support_decode_probe(data, crate::support::SNAPSHOT_MAX, |bytes| {
        crate::support::SupportSnapshot::decode(bytes).map(|value| value.encode())
    });
}
/// Configuration decoder fuzz body: bounded inputs and repaired checksums.
/// # Panics
/// If decoding accepts bytes that cannot be canonically re-encoded.
pub fn support_configuration_decode_probe(data: &[u8]) {
    support_decode_probe(data, crate::support::CONFIGURATION_MAX, |bytes| {
        crate::support::SupportConfiguration::decode(bytes).map(|value| value.encode())
    });
}
fn support_decode_probe(
    data: &[u8],
    cap: usize,
    check: impl Fn(
        &[u8],
    ) -> Result<
        Result<Vec<u8>, crate::support::SupportError>,
        crate::support::SupportError,
    >,
) {
    let canonical = |bytes: &[u8]| {
        if let Ok(encoded) = check(bytes) {
            assert_eq!(encoded.as_deref(), Ok(bytes), "noncanonical support input");
        }
    };
    canonical(data);
    if (50..=cap).contains(&data.len())
        && let Some((prefix, _)) = data.split_last_chunk::<32>()
    {
        let mut repaired = prefix.to_vec();
        repaired.extend_from_slice(crate::hash::GrainId::of(prefix).digest());
        canonical(&repaired);
    }
}

/// Manifest decoder probe, including repaired exact-byte checksums.
/// # Panics
/// If accepted bytes cannot be canonically re-encoded.
pub fn support_manifest_decode_probe(data: &[u8]) {
    support_decode_probe(data, crate::support::MANIFEST_MAX, |bytes| {
        crate::support::SupportManifest::decode(bytes).map(|value| value.encode())
    });
}
/// Archive decoder probe, including repaired exact-byte checksums.
/// # Panics
/// If accepted bytes cannot be canonically re-encoded.
pub fn support_archive_decode_probe(data: &[u8]) {
    if let Ok(value) = crate::support::SupportLogMetadata::decode(data) {
        assert_eq!(
            value.encode().as_deref(),
            Ok(data),
            "noncanonical log metadata input"
        );
    }
    support_decode_probe(data, crate::support::ARCHIVE_MAX, |bytes| {
        crate::support::SupportArchive::decode(bytes).map(|value| value.encode())
    });
}

/// Bundle decoder probe: the manifest, archive (including repaired member
/// digests, inner manifest checksum and outer checksum) and every member
/// decoder run on the input, and an accepted input must re-encode to itself.
/// The input also runs as one log record, so the record scanner sees text that
/// no framing reaches.
/// # Panics
/// If an accepted input cannot be canonically re-encoded.
pub fn support_bundle_decode_probe(data: &[u8]) {
    use crate::support::{
        BUNDLE_MANIFEST_MAX, BundleArchive, BundleCache, BundleConfiguration, BundleFailures,
        BundleLogs, BundleManifest, BundleMetrics, BundleOverlay, BundleVersion, SupportError,
    };
    fn canonical<T>(
        data: &[u8],
        decoded: Result<T, SupportError>,
        encode: impl FnOnce(&T) -> Result<Vec<u8>, SupportError>,
    ) {
        if let Ok(value) = decoded {
            assert_eq!(
                encode(&value).as_deref(),
                Ok(data),
                "noncanonical bundle member input"
            );
        }
    }
    canonical(data, BundleVersion::decode(data), BundleVersion::encode);
    canonical(
        data,
        BundleConfiguration::decode(data),
        BundleConfiguration::encode,
    );
    canonical(data, BundleLogs::decode(data), BundleLogs::encode);
    canonical(data, BundleOverlay::decode(data), BundleOverlay::encode);
    canonical(data, BundleCache::decode(data), BundleCache::encode);
    canonical(data, BundleFailures::decode(data), BundleFailures::encode);
    canonical(data, BundleMetrics::decode(data), BundleMetrics::encode);
    if let Ok(record) = std::str::from_utf8(data) {
        let logs = BundleLogs {
            lost: 0,
            records: vec![record.to_owned()],
        };
        if let Ok(bytes) = logs.encode() {
            assert_eq!(BundleLogs::decode(&bytes), Ok(logs), "record round trip");
        }
    }
    support_decode_probe(data, BUNDLE_MANIFEST_MAX, |bytes| {
        BundleManifest::decode(bytes).map(|value| value.encode())
    });
    canonical(data, BundleArchive::decode(data), BundleArchive::encode);
    if let Some(repaired) = support_bundle_archive_recheck_input(data) {
        canonical(
            &repaired,
            BundleArchive::decode(&repaired),
            BundleArchive::encode,
        );
    }
}

/// The input [`support_bundle_decode_probe`] and the archive golden flip test
/// scan after mutating: each framed member's digest is recomputed into its
/// manifest entry, the inner manifest's trailing checksum is recomputed, and
/// the outer archive's trailing checksum is recomputed, so mutated bytes reach
/// the strict member decoders and the version/metrics schema check.
pub(crate) fn support_bundle_archive_recheck_input(data: &[u8]) -> Option<Vec<u8>> {
    use crate::{
        hash::GrainId,
        support::{
            BUNDLE_ARCHIVE_MAX, BUNDLE_MANIFEST_MAX, CHECK_LEN, HEADER_LEN, OVERHEAD, TRAILER_LEN,
            bundle::{
                ARCHIVE_MANIFEST_LEN_WIDTH, ARCHIVE_MANIFEST_OFFSET, ARCHIVE_MEMBER_COUNT_WIDTH,
                ENTRY_EXPORTED_TAIL_LEN, ENTRY_HEAD_LEN, ENTRY_REFUSED_TAIL_LEN,
                MANIFEST_ENTRIES_OFFSET, MEMBER_LEN_WIDTH, STATUS_EXPORTED, STATUS_REFUSED,
            },
        },
    };
    if !(OVERHEAD..=BUNDLE_ARCHIVE_MAX).contains(&data.len()) {
        return None;
    }
    let mut fixed = data.to_vec();
    let body_end = fixed.len() - TRAILER_LEN;
    if let Some(len_bytes) = fixed
        .get(HEADER_LEN..ARCHIVE_MANIFEST_OFFSET)
        .and_then(|s| <[u8; ARCHIVE_MANIFEST_LEN_WIDTH]>::try_from(s).ok())
        && let Ok(manifest_len) = usize::try_from(u32::from_be_bytes(len_bytes))
        && manifest_len <= BUNDLE_MANIFEST_MAX
        && let Some(manifest_end) = ARCHIVE_MANIFEST_OFFSET.checked_add(manifest_len)
        && manifest_end <= body_end
    {
        let mut digests = std::collections::BTreeMap::new();
        if let Some(mut rest) =
            fixed.get(manifest_end.saturating_add(ARCHIVE_MEMBER_COUNT_WIDTH)..body_end)
        {
            while let Some((&name_len, after_name_len)) = rest.split_first()
                && let Some((name, after_name)) =
                    after_name_len.split_at_checked(usize::from(name_len))
                && let Some((len_bytes, after_len)) =
                    after_name.split_first_chunk::<MEMBER_LEN_WIDTH>()
                && let Ok(member_len) = usize::try_from(u32::from_be_bytes(*len_bytes))
                && let Some((member_bytes, tail)) = after_len.split_at_checked(member_len)
            {
                digests.insert(name.to_vec(), *GrainId::of(member_bytes).digest());
                rest = tail;
            }
        }
        if manifest_len >= OVERHEAD {
            if let Some(mut entries) = fixed.get_mut(
                ARCHIVE_MANIFEST_OFFSET + MANIFEST_ENTRIES_OFFSET..manifest_end - TRAILER_LEN,
            ) {
                while let Some((head, after_head)) =
                    entries.split_first_chunk_mut::<ENTRY_HEAD_LEN>()
                {
                    let [.., status] = *head;
                    match status {
                        STATUS_EXPORTED => {
                            let Some((&mut name_len, after_name_len)) =
                                after_head.split_first_mut()
                            else {
                                break;
                            };
                            let Some((name, after_name)) =
                                after_name_len.split_at_mut_checked(usize::from(name_len))
                            else {
                                break;
                            };
                            let Some((entry_tail, rest)) =
                                after_name.split_first_chunk_mut::<ENTRY_EXPORTED_TAIL_LEN>()
                            else {
                                break;
                            };
                            if let (Some(digest), Some((_, dest))) = (
                                digests.get(name as &[u8]),
                                entry_tail.split_last_chunk_mut::<CHECK_LEN>(),
                            ) {
                                dest.copy_from_slice(digest);
                            }
                            entries = rest;
                        }
                        STATUS_REFUSED => {
                            let Some((_, rest)) =
                                after_head.split_first_chunk_mut::<ENTRY_REFUSED_TAIL_LEN>()
                            else {
                                break;
                            };
                            entries = rest;
                        }
                        _ => break,
                    }
                }
            }
            if let Some(manifest) = fixed.get_mut(ARCHIVE_MANIFEST_OFFSET..manifest_end)
                && let Some((prefix, sum)) = manifest.split_last_chunk_mut::<CHECK_LEN>()
            {
                sum.copy_from_slice(GrainId::of(prefix).digest());
            }
        }
    }
    let (prefix, sum) = fixed.split_last_chunk_mut::<CHECK_LEN>()?;
    sum.copy_from_slice(GrainId::of(prefix).digest());
    Some(fixed)
}

/// The input [`overlay_journal_decode_probe`] scans a second time: `data`
/// with the header check recomputed, and every frame that carries a bounded
/// `len` with its check recomputed in turn, so mutated bytes reach the
/// payload decoder and the value rules instead of stopping at a check.
/// `None` when `data` is shorter than a header.
pub(crate) fn overlay_journal_recheck_input(data: &[u8]) -> Option<Vec<u8>> {
    use crate::overlay_journal::{CHECK_LEN, HEADER_CONTEXT, JOURNAL_HEADER_LEN};

    let mut fixed = data.to_vec();
    let header_check = {
        let covered = fixed.get(..JOURNAL_HEADER_LEN - CHECK_LEN)?;
        blake3::derive_key(HEADER_CONTEXT, covered)
    };
    fixed
        .get_mut(JOURNAL_HEADER_LEN - CHECK_LEN..JOURNAL_HEADER_LEN)?
        .copy_from_slice(&header_check);
    let mut offset = JOURNAL_HEADER_LEN;
    while let Some(total) = fixed
        .get_mut(offset..)
        .and_then(|rest| crate::overlay_journal::refresh_frame_check(&header_check, rest))
    {
        offset = offset.saturating_add(total);
    }
    Some(fixed)
}

/// `data` with the writer record's trailing check recomputed, or `None` for
/// an input too short to carry one.
pub(crate) fn overlay_writer_recheck_input(data: &[u8]) -> Option<Vec<u8>> {
    use crate::overlay_journal::{CHECK_LEN, WRITER_CONTEXT};

    let mut fixed = data.to_vec();
    let body_len = fixed.len().checked_sub(CHECK_LEN)?;
    let check = blake3::derive_key(WRITER_CONTEXT, fixed.get(..body_len)?);
    fixed.get_mut(body_len..)?.copy_from_slice(&check);
    Some(fixed)
}

/// `data` with the staging header's identity check and mark check
/// recomputed, or `None` for an input of the wrong length.
pub(crate) fn overlay_staging_recheck_input(data: &[u8]) -> Option<Vec<u8>> {
    use crate::overlay_journal::{
        CHECK_LEN, MARK_CONTEXT, MARK_OFFSET, STAGING_CONTEXT, STAGING_HEADER_LEN,
        STAGING_IDENTITY_LEN, STAGING_MARK_LEN,
    };

    if data.len() != STAGING_HEADER_LEN {
        return None;
    }
    let mut fixed = data.to_vec();
    let identity_check = blake3::derive_key(STAGING_CONTEXT, fixed.get(..STAGING_IDENTITY_LEN)?);
    fixed
        .get_mut(STAGING_IDENTITY_LEN..MARK_OFFSET)?
        .copy_from_slice(&identity_check);
    let fields_end = MARK_OFFSET + STAGING_MARK_LEN - CHECK_LEN;
    let mut hasher = blake3::Hasher::new_derive_key(MARK_CONTEXT);
    hasher.update(&identity_check);
    hasher.update(fixed.get(MARK_OFFSET..fields_end)?);
    fixed
        .get_mut(fields_end..fields_end + CHECK_LEN)?
        .copy_from_slice(hasher.finalize().as_bytes());
    Some(fixed)
}

/// Fuzz body for the overlay area's four codecs: never panics; a journal the
/// scan accepts re-encodes to exactly its valid prefix (canonical form) and
/// that prefix is no longer than the input; a writer record or a staging
/// header or unmerged listing that decodes re-encodes to the same bytes.
/// Random bytes almost never carry a valid check, so journal, writer and
/// staging inputs are also decoded with their checks recomputed; that is what
/// reaches their field and value rules.
///
/// # Panics
/// If an accepted input does not re-encode canonically.
pub fn overlay_journal_decode_probe(data: &[u8]) {
    use crate::overlay_journal::{
        JOURNAL_HEADER_LEN, JournalEnd, JournalHeader, MarkState, StagingHeader, UnmergedPath,
        WriterRecord, encode_record_checked, scan_journal_with,
    };

    fn journal(input: &[u8]) {
        let Ok(header) = JournalHeader::decode(input.get(..JOURNAL_HEADER_LEN).unwrap_or(input))
        else {
            return;
        };
        let header_check = header.check();
        let mut offset = JOURNAL_HEADER_LEN;
        let Ok(scan) = scan_journal_with(input, |seq, record| {
            let frame = encode_record_checked(&header_check, seq, record);
            let bytes = frame.as_deref().ok();
            let end = offset.saturating_add(bytes.map_or(0, <[u8]>::len));
            assert_eq!(
                bytes,
                input.get(offset..end),
                "canonical-form violation (overlay journal)"
            );
            offset = end;
        }) else {
            return;
        };
        assert_eq!(offset, scan.valid_len, "valid prefix and visitor disagree");
        assert!(
            scan.valid_len <= input.len(),
            "valid prefix longer than input"
        );
        assert_eq!(
            matches!(scan.end, JournalEnd::Clean),
            scan.valid_len == input.len()
        );
    }
    fn writer(input: &[u8]) {
        if let Ok(record) = WriterRecord::decode(input) {
            assert_eq!(
                record.encode().as_deref(),
                Ok(input),
                "canonical-form violation (overlay writer)"
            );
        }
    }
    fn staging(input: &[u8]) {
        if let Ok(header) = StagingHeader::decode(input)
            && header.mark != MarkState::Damaged
        {
            assert_eq!(
                header.encode().as_deref(),
                Ok(input),
                "canonical-form violation (staging header)"
            );
        }
    }

    journal(data);
    writer(data);
    staging(data);
    if let Some(fixed) = overlay_journal_recheck_input(data) {
        journal(&fixed);
    }
    if let Some(fixed) = overlay_writer_recheck_input(data) {
        writer(&fixed);
    }
    if let Some(fixed) = overlay_staging_recheck_input(data) {
        staging(&fixed);
    }
    if let Ok(listing) = UnmergedPath::decode(data) {
        assert_eq!(
            listing.encode().as_deref(),
            Ok(data),
            "canonical-form violation (unmerged path)"
        );
    }
}

/// Minimal valid ownership snapshot for corpus and property fixtures.
#[must_use]
pub fn ownership_fixture() -> crate::overlay_ownership::Carrier {
    use crate::overlay_ownership::{Carrier, Phase};
    Carrier {
        scope: crate::retained_submission::Scope {
            authority_base: b"https://authority.invalid".to_vec(),
            pins: vec![],
            credential_context: b"fixture".to_vec(),
        },
        volume: crate::root::VolumeName::from_bytes(b"v")
            .unwrap_or_else(|e| panic!("constant fixture volume: {e}")),
        writer: [1; 16],
        instance: [2; 16],
        revision: 0,
        phase: Phase::Unowned,
        cursor: 0,
        allocated: 0,
        sent: 0,
        handshake: vec![],
        grant: vec![],
        current: vec![],
        root: vec![],
        selected: vec![],
        selected_root: vec![],
        selected_cursor: 0,
        consent: vec![],
        fence: 0,
        fence_evidence: vec![],
        pending: vec![],
    }
}

/// Check canonical discard parsing and encoding against the raw input.
pub fn overlay_discard_decode_probe(bytes: &[u8]) {
    use crate::overlay_discard::{DiscardName, Row};
    if let Ok(Some((name, intent))) = DiscardName::parse(bytes) {
        assert_eq!(name.leaf(intent).as_bytes(), bytes);
    }
    if let Ok(row) = Row::parse(bytes) {
        assert_eq!(row.to_string().as_bytes(), bytes);
    }
}

/// Decode totality and canonical re-encode, shared with corpus replay.
pub fn overlay_ownership_decode_probe(bytes: &[u8]) {
    if let Ok(c) = crate::overlay_ownership::decode(bytes) {
        assert!(
            crate::overlay_ownership::encode(&c).is_ok_and(|encoded| encoded == bytes),
            "canonical ownership roundtrip"
        );
    }
}
