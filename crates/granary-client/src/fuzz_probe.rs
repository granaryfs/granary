// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Fuzz/replay instrumentation for cache parsing and authority validation.
//! Each libFuzzer target and stable corpus replay calls the same probe body.
//! No stability promise or product policy attaches to these entry points.
//! Cache round-trip properties live with the parser's private grammar constants.

use crate::cache::{HeadAnchor, parse_anchor_bytes, render_anchor_bytes};

/// The anchor reader's cap: a longer file is refused before the parser sees
/// it, so the fuzz lane's `-max_len` for this target is exactly this value,
/// and a test holds the two equal.
pub const ANCHOR_FILE_MAX_BYTES: u64 = crate::cache::ANCHOR_FILE_MAX_BYTES;

/// Fuzz probe: `anchors/<volume>` decode totality + canonical form. A
/// reachable panic on arbitrary bytes is the bug this exists to catch —
/// `parse_anchor_bytes` is a byte-level parser of attacker-writable disk
/// content and must degrade untrusted input to `None`, never panic.
///
/// Canonical form: every `HeadAnchor` this parser successfully decodes
/// re-renders to the EXACT input bytes. This holds by construction —
/// `parse_anchor_hint_line`'s own field parsers (`parse_anchor_seq`,
/// `parse_anchor_token` = `valid_anchor_token`, `parse_anchor_stamp`)
/// already enforce every bound `persistable_anchor_hint` (the renderer's
/// own gate) checks, so a successfully-decoded hint can never fail that
/// gate — but the property is ASSERTED here, not merely reasoned about,
/// the same discipline `granary_core::testkit`'s decoder probes use.
///
/// # Panics
/// If the canonical-form property is violated — the intended failure
/// mode for both the fuzz target and the corpus-replay test that call
/// this.
pub fn anchor_decode_probe(data: &[u8]) {
    if let Some(HeadAnchor { seq, hint }) = parse_anchor_bytes(data) {
        let re = render_anchor_bytes(seq, hint.as_ref());
        assert_eq!(re, data, "canonical-form violation (anchor)");
    }
}

/// Maximum packed validator input: status, header selector, and bounded answer.
pub const AUTHORITY_VALIDATE_MAX_BYTES: usize = 3 + granary_core::authority_answer::MAX_BYTES + 1;

/// Exercise candidate construction and request-relative wire validation on
/// arbitrary bytes. The fixed request gives the validator a nonempty domain
/// independently of whether the fuzz input contains a valid root.
pub fn authority_validate_probe(data: &[u8]) {
    use crate::authority_transport::{OwnedCandidate, PublishRequest};
    use granary_core::authlog::Epoch;
    use granary_core::hash::GrainId;
    use granary_core::root::{self, RootDoc, RootSig, Timestamp, VolumeName};
    use std::sync::Arc;
    metrics_labels_probe(data);
    if let Ok(value) = std::str::from_utf8(data) {
        let _ = crate::publication_config::PublisherTrust::default().push(value);
        let _ = crate::publication_config::CredentialContext::new(value);
        if let Ok(context) = crate::publication_config::CredentialContext::new("fuzz") {
            let _ = crate::publication_config::publication_scope(value, &[[1; 32]], &context);
        }
    }
    let _ = OwnedCandidate::new("vol", Arc::from(data));
    let Ok(volume) = VolumeName::new("vol".to_owned()) else {
        return;
    };
    let doc = RootDoc {
        volume,
        seq: 5,
        parent: Some(GrainId::of(b"parent")),
        writer_uuid: [1; 16],
        epoch: 1,
        timestamp: Timestamp { secs: 1, nanos: 0 },
        chunker_spec: "opaque spec".to_owned(),
        manifest_root: GrainId::of(b"manifest"),
        binmap_index: GrainId::of(b"binmap"),
        sheaf_head: GrainId::of(b"sheaf"),
        sigs: vec![RootSig {
            key_id: [1; 32],
            sig: [2; 64],
        }],
    };
    let Ok(bytes) = root::encode_root(&doc) else {
        return;
    };
    let Ok(candidate) = OwnedCandidate::new("vol", bytes.into()) else {
        return;
    };
    let Ok(request) = PublishRequest::new(
        "vol",
        Epoch::from_bytes([1; 16]),
        b"operation",
        candidate.clone(),
        vec![candidate],
    ) else {
        return;
    };
    crate::authority_transport::fuzz_validate(&request, data);
}

/// Exercise every closed metrics label parser with the bytes supplied by the
/// authority/configuration fuzz target. Non-UTF-8 is refused before parsing.
pub fn metrics_labels_probe(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = crate::CommitResult::parse(text);
    let _ = crate::RegistrationResult::parse(text);
    let _ = crate::MetricsGroup::parse(text);
    let _ = crate::CachePhase::parse(text);
    let _ = crate::CacheResult::parse(text);
    let _ = crate::UploadObject::parse(text);
    let _ = crate::ByteDirection::parse(text);
    let _ = granary_fuse::Callback::parse(text);
    let _ = crate::observe::Outcome::parse(text);
}
