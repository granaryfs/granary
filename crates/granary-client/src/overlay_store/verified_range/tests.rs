// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn verified_grain_budget_includes_keys_and_shared_allocations() {
    let mut memo = VerifiedRangeCache::default();
    for number in 0u8..40 {
        let bytes = vec![number; 262_144];
        let id = GrainId::of(&bytes);
        memo.insert_grain(id, 262_144, Arc::from(bytes));
        let charge: usize = memo.grains.values().map(|bytes| bytes.len() + 2048).sum();
        assert_eq!(
            (memo.grain_bytes, memo.grain_bytes <= 8_388_608),
            (charge, true),
            "grain budget accounting: iteration={number}, charge={charge}, rows={}",
            memo.grains.len()
        );
    }
    let oversized = vec![b'x'; 8_388_608];
    let id = GrainId::of(&oversized);
    let before = memo.grain_bytes;
    memo.insert_grain(id, 8_388_608, Arc::from(oversized));
    assert_eq!(
        (memo.grain_bytes, memo.grain(id, 8_388_608).is_none()),
        (before, true),
        "oversized object stays outside the cache including container overhead"
    );
    assert!(
        !memo.grains.is_empty(),
        "nonempty budget controls: {}",
        memo.grains.len()
    );
}

#[test]
fn verified_metadata_budget_evicts_owned_nodes_and_refuses_oversized_values() {
    let mut memo = VerifiedRangeCache::default();
    for number in 0u16..500 {
        let refs = vec![
            granary_core::manifest::GrainRef {
                id: GrainId::of(&number.to_be_bytes()),
                unpacked_len: 1,
            };
            1024
        ];
        let bytes = granary_core::manifest::encode_grain_list_leaf(&refs).unwrap();
        let id = GrainId::of(&bytes);
        memo.insert_list(id, Arc::from(bytes));
        let charge: usize = memo.metadata.values().map(|(_, bytes)| *bytes).sum();
        assert_eq!(
            (memo.metadata_bytes, memo.metadata_bytes <= 16_777_216),
            (charge, true),
            "metadata budget accounting: iteration={number}, rows={}",
            memo.metadata.len()
        );
    }
    let bytes = vec![b'x'; 16_777_216];
    let id = GrainId::of(&bytes);
    let before = memo.metadata_bytes;
    memo.insert_list(id, Arc::from(bytes));
    assert_eq!(
        (memo.metadata_bytes, memo.list(id).is_none()),
        (before, true),
        "oversized metadata must use checked fallback"
    );
    assert!(
        !memo.metadata.is_empty(),
        "nonempty metadata controls: {}",
        memo.metadata.len()
    );
}

#[test]
fn verified_range_generation_exhaustion_refuses_without_reusing_a_generation() {
    let mut memo = VerifiedRangeCache::default();
    let data = b"verified bytes";
    let id = GrainId::of(data);
    memo.insert_grain(id, 14, Arc::from(data.as_slice()));
    memo.invalidate().unwrap();
    assert_eq!(
        (memo.generation(), memo.grains.len()),
        (1, 0),
        "nonempty valid invalidation"
    );
    memo.generation = u64::MAX;
    assert!(
        matches!(memo.invalidate(), Err(OverlayError::Poisoned)),
        "generation overflow must refuse, actual={memo:?}"
    );
    assert_eq!(memo.generation(), 18_446_744_073_709_551_615);
}

#[test]
fn completion_token_capacity_evicts_without_carrying_old_incarnations() {
    let mut tokens = crate::writable_start::CompletionTokens::default();
    tokens.admit_generation(1);
    for number in 0u32..1025 {
        tokens.completed(GrainId::of(&number.to_be_bytes()));
    }
    let (retained, first) = tokens.retained_for_test();
    assert_eq!(retained, 1024, "literal token ceiling: actual={retained}");
    let id = first.unwrap();
    assert!(tokens.contains(id), "nonempty resident token control");
    tokens.admit_generation(2);
    assert_eq!(
        (tokens.retained_for_test().0, tokens.contains(id)),
        (0, false),
        "new incarnation cannot consume old completions"
    );
    tokens.completed(id);
    tokens.remove(id);
    assert_eq!(
        (tokens.retained_for_test().0, tokens.contains(id)),
        (0, false),
        "observed damage removes only completed evidence"
    );
}

fn cache_scale(insertions: u32) {
    let mut cache = VerifiedRangeCache::default();
    let mut tokens = crate::writable_start::CompletionTokens::default();
    tokens.admit_generation(1);
    let mut peaks = (0, 0, 0);
    for number in 0..insertions {
        let data = number.to_be_bytes();
        let grain_id = GrainId::of(&data);
        let grains = FileGrains::Inline(vec![granary_core::manifest::GrainRef {
            id: grain_id,
            unpacked_len: 4,
        }]);
        let encoded = granary_core::manifest::node::file_payload(4, &grains).unwrap();
        let content = GrainId::of(&encoded);
        cache.insert_payload(content, 4, Arc::new(grains));
        cache.insert_grain(grain_id, 4, Arc::from(data.as_slice()));
        tokens.completed(content);
        peaks.0 = peaks.0.max(cache.metadata_bytes);
        peaks.1 = peaks.1.max(cache.grain_bytes);
        peaks.2 = peaks.2.max(tokens.retained_for_test().0);
    }
    assert_eq!(
        (std::mem::size_of::<FileGrains>() + std::mem::size_of::<granary_core::manifest::GrainRef>(), cache.metadata.values().all(|(value, _)| matches!(value, Metadata::Payload(4, refs) if matches!(refs.as_ref(), FileGrains::Inline(refs) if refs.len() == 1 && refs.capacity() == 1)))),
        (80, true),
        "actual payload layout and nonempty one-reference measurement premise"
    );
    let metadata_sum = cache.metadata.len() * 2128;
    let grain_sum: usize = cache.grains.values().map(|bytes| bytes.len() + 2048).sum();
    assert_eq!(
        (
            cache.metadata_bytes,
            cache.grain_bytes,
            peaks.0 <= 16_777_216,
            peaks.1 <= 8_388_608,
            peaks.2,
            !cache.metadata.is_empty(),
            !cache.grains.is_empty()
        ),
        (metadata_sum, grain_sum, true, true, 1024, true, true),
        "cache scale must charge retained values and evict under literal ceilings: insertions={insertions}, peaks={peaks:?}"
    );
    eprintln!(
        "cache measurement: insertions={insertions}, metadata_rows={}, metadata_charge={}, grain_rows={}, grain_charge={}, completion_rows={}, peak_charges={peaks:?}; charged occupancy excludes allocator/transient peaks",
        cache.metadata.len(),
        metadata_sum,
        cache.grains.len(),
        grain_sum,
        tokens.retained_for_test().0
    );
    cache.invalidate().unwrap();
    tokens.admit_generation(2);
    assert_eq!(
        (
            cache.metadata_bytes,
            cache.grain_bytes,
            cache.metadata.len(),
            cache.grains.len(),
            tokens.retained_for_test().0
        ),
        (0, 0, 0, 0, 0)
    );
}

#[test]
fn verified_range_scale_10000_measures_charged_cache_ceilings() {
    cache_scale(10_000);
}

#[test]
fn verified_range_scale_100000_measures_charged_cache_ceilings() {
    cache_scale(100_000);
}
