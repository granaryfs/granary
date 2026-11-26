// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn bytes(n: usize) -> Vec<u8> {
    let mut state = 0x517c_c1b7_2722_0a95u64;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

fn reference(data: &[u8]) -> Vec<GrainRef> {
    thresh::grains(data)
        .map(|grain| GrainRef {
            id: GrainId::of(&data[grain.offset..grain.offset + grain.length]),
            unpacked_len: u32::try_from(grain.length).unwrap(),
        })
        .collect()
}

fn run(old: &[u8], new: &[u8], dirty: Vec<(u64, u64)>) -> (Vec<GrainRef>, RechunkStats) {
    let old_refs = reference(old);
    let mut offsets = vec![0];
    for grain in &old_refs {
        offsets.push(offsets.last().unwrap() + u64::from(grain.unpacked_len));
    }
    let mut cutter = Cutter {
        old: old_refs,
        offsets,
        dirty,
        size: new.len() as u64,
        buffer: Vec::new(),
        buffer_start: 0,
        stats: RechunkStats::default(),
    };
    let result = cutter
        .run(
            &mut |offset, n| {
                assert!(n <= 65_536, "immutable read exceeded range bound");
                let offset = usize::try_from(offset).unwrap();
                Ok(new[offset..offset + n].to_vec())
            },
            &mut |id, data| {
                assert_eq!(GrainId::of(data), id);
                Ok(())
            },
        )
        .unwrap();
    (result, cutter.stats)
}

#[test]
fn one_byte_rechunks_to_first_resync() {
    let original = bytes(67_108_864);
    let edit = 33_554_432usize;
    let mut newer = original.clone();
    newer[edit] ^= 1;
    let old_refs = reference(&original);
    let expected = reference(&newer);
    let (actual, stats) = run(&original, &newer, vec![(edit as u64, edit as u64 + 1)]);
    assert_eq!(
        actual, expected,
        "incremental cuts changed file bytes or canonical boundaries"
    );
    // Establish a shared boundary independently of the incremental algorithm.
    let boundaries = |refs: &[GrainRef]| {
        let mut offset = 0;
        refs.iter()
            .map(|grain| {
                offset += u64::from(grain.unpacked_len);
                offset
            })
            .collect::<Vec<_>>()
    };
    let old_boundaries = boundaries(&old_refs);
    let shared = boundaries(&expected)
        .into_iter()
        .find(|at| *at > edit as u64 && old_boundaries.contains(at))
        .unwrap();
    let start = old_boundaries
        .iter()
        .copied()
        .take_while(|at| *at < edit as u64)
        .last()
        .unwrap();
    assert!(
        shared - start <= 8_388_608,
        "fixture has no nearby shared boundary"
    );
    let old_ids: std::collections::BTreeSet<_> = old_refs.iter().map(|grain| grain.id).collect();
    let novel: std::collections::BTreeSet<_> = actual
        .iter()
        .map(|grain| grain.id)
        .filter(|id| !old_ids.contains(id))
        .collect();
    assert!(
        novel.len() <= 65,
        "ordinary edit uploaded too many novel grains"
    );
    eprintln!("{stats:?}; novel_grains={}", novel.len());
    assert_eq!(
        stats.cutter_bytes,
        shared - start,
        "did not stop at first proved resynchronisation"
    );
    assert!(
        stats.read_bytes <= 8_388_608 && stats.max_buffer <= thresh::MAX_GRAIN,
        "lookahead exceeded its bound"
    );
    assert!(stats.cut_grains <= 65 && stats.reused_grains > 128);
    assert!(
        !stats.fallback,
        "ordinary edit counted as full-span fallback"
    );
}

#[test]
fn rechunk_no_resync_to_eof() {
    let original = bytes(9_437_199);
    let replacement = vec![0; original.len()];
    let (actual, stats) = run(&original, &replacement, vec![(0, original.len() as u64)]);
    assert_eq!(actual, reference(&replacement));
    assert_eq!(
        (stats.cutter_bytes, stats.reused_grains, stats.fallback),
        (original.len() as u64, 0, true)
    );
    let (initial, stats) = run(&[], &replacement, vec![(0, replacement.len() as u64)]);
    assert_eq!(initial, actual);
    assert!(!stats.fallback, "initial chunking counted as fallback");
}

#[test]
fn overlapping_expansions_extension_truncation_and_boundary_edit_match_full_cuts() {
    let original = bytes(9_437_201);
    let boundary = u64::from(reference(&original)[0].unpacked_len);
    for (at, second, length) in [
        (boundary, boundary + 2, original.len()),
        (9_437_201, 9_437_202, 9_437_211),
        (boundary, boundary + 1, usize::try_from(boundary).unwrap()),
    ] {
        let mut newer = original.clone();
        newer.resize(length, 0);
        let mut dirty = Vec::new();
        if length < original.len() {
            dirty.push((length as u64, original.len() as u64));
        } else {
            newer[usize::try_from(at).unwrap()] ^= 7;
            newer[usize::try_from(second).unwrap()] ^= 9;
            dirty.push((at, at + 1));
            dirty.push((second, newer.len() as u64));
        }
        let (actual, stats) = run(&original, &newer, dirty);
        assert_eq!(actual, reference(&newer));
        assert!(
            stats.cutter_bytes <= newer.len() as u64,
            "overlapping expansion scanned twice"
        );
    }
    let (actual, stats) = run(&original, &[], vec![(0, original.len() as u64)]);
    assert!(actual.is_empty() && stats.cutter_bytes == 0 && !stats.fallback);
}

#[test]
fn rechunk_does_not_reuse_a_suffix_with_later_changes_in_same_interval() {
    let original = bytes(9_437_199);
    let mut newer = original.clone();
    *newer.last_mut().unwrap() ^= 1;
    let (actual, stats) = run(&original, &newer, vec![(0, newer.len() as u64)]);
    assert_eq!(
        actual,
        reference(&newer),
        "changed suffix reused before dirty interval ended"
    );
    assert_eq!(stats.cutter_bytes, newer.len() as u64);
    assert!(stats.fallback);
}

#[test]
fn rechunk_reuses_only_equal_logical_offsets() {
    let original = bytes(9_437_199);
    let old = reference(&original);
    let mut at = 0;
    let old_boundaries: Vec<_> = old
        .iter()
        .map(|grain| {
            at += u64::from(grain.unpacked_len);
            at
        })
        .collect();
    let fixture = (131_072..2_097_152).step_by(65_536).find_map(|length| {
        let mut newer = original.clone();
        newer[..length].fill(0);
        let first = granary_core::thresh::grains(&newer).next().unwrap().length;
        (first > length && old_boundaries.binary_search(&(first as u64)).is_err())
            .then_some((newer, length))
    });
    assert!(fixture.is_some(), "fixture failed to displace first cut");
    let (newer, changed) = fixture.unwrap();
    let expected = reference(&newer);
    let (actual, stats) = run(&original, &newer, vec![(0, changed as u64)]);
    assert_eq!(
        actual, expected,
        "unequal logical offsets reused old suffix"
    );
    assert!(stats.cutter_bytes < newer.len() as u64 && !stats.fallback);
}

/// The landing's readback classes a transient store failure as unavailable,
/// beside the deadline; a permanent store answer, an absent or a substituted
/// root is a refusal, and a signature failure stays corrupt.
#[test]
fn a_view_root_readback_transport_failure_is_classed_unavailable() {
    use crate::observe::FailureClass;
    assert_eq!(
        [
            "SyncDeadline",
            "ViewRootUnavailable",
            "SyncCommitReadback",
            "ViewRootUnpublished",
            "ViewRootMismatch",
            "SyncCommitSignature",
        ]
        .map(|reason| failure_class(&refused(reason))),
        [
            FailureClass::Unavailable,
            FailureClass::Unavailable,
            FailureClass::Refused,
            FailureClass::Refused,
            FailureClass::Refused,
            FailureClass::Corrupt,
        ]
    );
}
