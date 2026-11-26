// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use granary_core::manifest::{
    DirEntry, EntryKind, FileGrains, GrainRef, Name, build_dir, build_grain_list,
};

struct Head {
    candidate: ValidationCandidate,
    digests: Vec<Digest>,
    rows: Vec<ShardEntry>,
    width: u8,
}

fn file(name: &str, bytes: &[u8]) -> (DirEntry, PackedFrame) {
    let packed = frame(bytes);
    (
        DirEntry {
            name: Name::new(name.as_bytes().to_vec()).unwrap(),
            kind: EntryKind::File {
                exec: false,
                size: bytes.len() as u64,
                grains: FileGrains::Inline(vec![GrainRef {
                    id: packed.id,
                    unpacked_len: u32::try_from(bytes.len()).unwrap(),
                }]),
            },
        },
        packed,
    )
}

fn publish(
    store: &mut Objects,
    prior: Option<&Head>,
    entries: &[DirEntry],
    payloads: Vec<PackedFrame>,
) -> Head {
    publish_at_width(
        store,
        prior,
        entries,
        payloads,
        prior.map_or(0, |head| head.width),
    )
}

fn publish_at_width(
    store: &mut Objects,
    prior: Option<&Head>,
    entries: &[DirEntry],
    payloads: Vec<PackedFrame>,
    width: u8,
) -> Head {
    let tree = build_dir(entries).unwrap();
    let mut frames = payloads;
    frames.extend(tree.nodes.iter().map(|(_, bytes)| frame(bytes)));
    let mut rows = prior.map_or_else(Vec::new, |head| head.rows.clone());
    let mut digests = prior.map_or_else(Vec::new, |head| head.digests.clone());
    let mut seen: std::collections::BTreeSet<GrainId> = rows.iter().map(|r| r.id).collect();
    frames.retain(|f| seen.insert(f.id));
    for batch in frames.chunks(granary_core::binfmt::MAX_GRAINS_PER_BIN as usize) {
        let (digest, added) = store.bin(batch, u32::try_from(digests.len()).unwrap());
        digests.push(digest);
        rows.extend(added);
    }
    let table = store.meta(encode_bin_table(&digests).unwrap());
    let (index, _) = make_map(store, table, &rows, width);
    let candidate = candidate(store, prior.map(|head| &head.candidate), tree.root, index);
    Head {
        candidate,
        digests,
        rows,
        width,
    }
}

fn volume(n: usize) -> (Objects, Head, Vec<DirEntry>) {
    volume_at_width(n, 0)
}

fn volume_at_width(n: usize, width: u8) -> (Objects, Head, Vec<DirEntry>) {
    let mut store = Objects::default();
    let (entries, payloads): (Vec<_>, Vec<_>) = (0..n)
        .map(|i| {
            file(
                &format!("f{i:06}"),
                format!("payload of file {i}").as_bytes(),
            )
        })
        .unzip();
    let head = publish_at_width(&mut store, None, &entries, payloads, width);
    (store, head, entries)
}

async fn successor_calls(n: usize) -> (usize, usize) {
    let (mut store, head, mut entries) = volume(n);
    let proof = validate(&store, &head.candidate, None, ValidationLimits::default())
        .await
        .expect("genesis");
    store.take_calls();
    let (entry, payload) = file("zz-added", b"one new small file");
    entries.push(entry);
    let next = publish(&mut store, Some(&head), &entries, vec![payload]);
    validate(
        &store,
        &next.candidate,
        Some(&proof),
        ValidationLimits::default(),
    )
    .await
    .expect("valid additive successor");
    let calls = store.take_calls();
    let ranges = calls
        .iter()
        .filter(|(key, _)| matches!(key, Key::Range(..)))
        .count();
    (calls.len(), ranges)
}

#[tokio::test]
async fn one_added_file_takes_few_reads_on_both_volume_sizes() {
    let small = successor_calls(50).await;
    let large = successor_calls(400).await;
    assert!(
        large.0 < small.0 + 50,
        "one added file cost {} reads at 50 files and {} at 400 (range reads {} -> {})",
        small.0,
        large.0,
        small.1,
        large.1
    );
}

#[tokio::test]
async fn default_limits_admit_one_added_file_on_an_8300_file_volume() {
    let (mut store, head, mut entries) = volume(8_300);
    let proof = validate(&store, &head.candidate, None, ValidationLimits::default())
        .await
        .expect("genesis of 8300 files");
    let genesis_calls = store.take_calls().len();
    let (entry, payload) = file("zz-added", b"one new small file");
    entries.push(entry);
    let next = publish(&mut store, Some(&head), &entries, vec![payload]);
    let result = validate(
        &store,
        &next.candidate,
        Some(&proof),
        ValidationLimits::default(),
    )
    .await
    .map(|_| ());
    let calls = store.take_calls().len();
    assert_eq!(
        result,
        Ok(()),
        "genesis dispatched {genesis_calls} reads and successor dispatched {calls} reads"
    );
}

#[tokio::test]
async fn small_edit_does_not_recharge_expansion_of_unchanged_grains() {
    let mut store = Objects::default();
    let big: Vec<Vec<u8>> = (0u8..3)
        .map(|i| {
            let mut bytes = vec![i; 4 * 1024 * 1024];
            bytes[0] = 0xA0 + i;
            bytes
        })
        .collect();
    let (mut entries, payloads): (Vec<_>, Vec<_>) = big
        .iter()
        .enumerate()
        .map(|(i, bytes)| file(&format!("big{i}"), bytes))
        .unzip();
    let head = publish(&mut store, None, &entries, payloads);
    let proof = validate(&store, &head.candidate, None, ValidationLimits::default())
        .await
        .expect("genesis");
    let (entry, payload) = file("tiny", b"tiny");
    entries.push(entry);
    let next = publish(&mut store, Some(&head), &entries, vec![payload]);
    validate(
        &store,
        &next.candidate,
        Some(&proof),
        ValidationLimits::default(),
    )
    .await
    .expect("control: default limits");
    let limits = ValidationLimits {
        expansion: 1024 * 1024,
        ..ValidationLimits::default()
    };
    let result = validate(&store, &next.candidate, Some(&proof), limits)
        .await
        .map(|_| ());
    assert_eq!(
        result,
        Ok(()),
        "1 MiB of expansion allowance for a 4-byte edit over 12 MiB of unchanged grains"
    );
}

#[tokio::test]
async fn shared_spill_root_under_two_files_checks_each_declared_size() {
    let data = b"content carried across publishes";
    let len = u32::try_from(data.len()).unwrap();
    let refs = vec![
        GrainRef {
            id: GrainId::of(data),
            unpacked_len: len,
        };
        300
    ];
    let spill = build_grain_list(&refs).unwrap();
    let entry = |name: &[u8], size: u64| DirEntry {
        name: Name::new(name.to_vec()).unwrap(),
        kind: EntryKind::File {
            exec: false,
            size,
            grains: FileGrains::Spill {
                root: spill.root,
                grain_count: 300,
            },
        },
    };
    let total = u64::from(len) * 300;
    for (second, valid) in [(total, true), (total + 1, false), (total - 1, false)] {
        let mut store = Objects::default();
        let mut payloads = vec![frame(data)];
        payloads.extend(spill.nodes.iter().map(|(_, bytes)| frame(bytes)));
        let head = publish(
            &mut store,
            None,
            &[entry(b"a", total), entry(b"b", second)],
            payloads,
        );
        let result = validate(&store, &head.candidate, None, ValidationLimits::default())
            .await
            .map(|_| ());
        assert_eq!(
            result,
            if valid { Ok(()) } else { Err(InvalidReference) },
            "second size {second}"
        );
    }
}

async fn min_steps(store: &Objects, candidate: &ValidationCandidate) -> u64 {
    let (mut low, mut high) = (0u64, 1_000_000u64);
    while low < high {
        let mid = low + (high - low) / 2;
        let limits = ValidationLimits {
            steps: mid,
            ..ValidationLimits::default()
        };
        match validate(store, candidate, None, limits).await {
            Ok(_) => high = mid,
            Err(WorkLimit) => low = mid + 1,
            Err(other) => panic!("unexpected {other:?} at {mid} steps"),
        }
    }
    low
}

#[tokio::test]
async fn repeated_file_edges_to_one_grain_are_each_charged() {
    let data = b"content carried across publishes";
    let len = u32::try_from(data.len()).unwrap();
    let mut needed = Vec::new();
    for count in [200u64, 1_200] {
        let refs = vec![
            GrainRef {
                id: GrainId::of(data),
                unpacked_len: len,
            };
            usize::try_from(count).unwrap()
        ];
        let spill = build_grain_list(&refs).unwrap();
        let mut store = Objects::default();
        let mut payloads = vec![frame(data)];
        payloads.extend(spill.nodes.iter().map(|(_, bytes)| frame(bytes)));
        let head = publish(
            &mut store,
            None,
            &[DirEntry {
                name: Name::new(b"f".to_vec()).unwrap(),
                kind: EntryKind::File {
                    exec: false,
                    size: u64::from(len) * count,
                    grains: FileGrains::Spill {
                        root: spill.root,
                        grain_count: u32::try_from(count).unwrap(),
                    },
                },
            }],
            payloads,
        );
        let exact = min_steps(&store, &head.candidate).await;
        let at = ValidationLimits {
            steps: exact,
            ..ValidationLimits::default()
        };
        validate(&store, &head.candidate, None, at)
            .await
            .expect("exact");
        let under = ValidationLimits {
            steps: exact - 1,
            ..ValidationLimits::default()
        };
        assert_eq!(
            validate(&store, &head.candidate, None, under)
                .await
                .map(|_| ()),
            Err(WorkLimit)
        );
        needed.push(exact);
    }
    assert!(needed[1] >= needed[0] + 1_000, "{needed:?}");
}

#[tokio::test]
async fn default_limits_admit_a_25000_file_genesis() {
    let (store, head, _) = volume(25_000);
    let result = validate(&store, &head.candidate, None, ValidationLimits::default())
        .await
        .map(|_| ());
    let calls = store.take_calls().len();
    assert_eq!(result, Ok(()), "genesis dispatched {calls} reads");
}

#[tokio::test]
async fn small_edit_does_not_recharge_bytes_of_unchanged_grains() {
    let mut store = Objects::default();
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let big: Vec<Vec<u8>> = (0..3)
        .map(|_| {
            (0..1024 * 1024)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state.to_le_bytes()[0]
                })
                .collect()
        })
        .collect();
    let (mut entries, payloads): (Vec<_>, Vec<_>) = big
        .iter()
        .enumerate()
        .map(|(i, bytes)| file(&format!("big{i}"), bytes))
        .unzip();
    let head = publish(&mut store, None, &entries, payloads);
    let proof = validate(&store, &head.candidate, None, ValidationLimits::default())
        .await
        .expect("genesis");
    let (entry, payload) = file("tiny", b"tiny");
    entries.push(entry);
    let next = publish(&mut store, Some(&head), &entries, vec![payload]);
    store.take_calls();
    let limits = ValidationLimits {
        bytes: 2 * 1024 * 1024,
        ..ValidationLimits::default()
    };
    let result = validate(&store, &next.candidate, Some(&proof), limits)
        .await
        .map(|_| ());
    let fetched: usize = store
        .take_calls()
        .iter()
        .filter_map(|(key, _)| match key {
            Key::Range(_, _, len) => Some(*len as usize),
            _ => None,
        })
        .sum();
    assert_eq!(
        result,
        Ok(()),
        "2 MiB byte allowance for a 4-byte edit; {fetched} bytes of old frames requested"
    );
}

#[tokio::test]
async fn default_limits_admit_one_added_file_on_large_sharded_volumes() {
    for n in [45_000, 90_000] {
        let limits = ValidationLimits::default();
        let (mut store, head, mut entries) = volume_at_width(n, 2);
        // Give the fixture's genesis extra steps so this checks the successor
        // independently of the default-limit genesis test.
        let proof = validate(
            &store,
            &head.candidate,
            None,
            ValidationLimits {
                steps: 32 * limits.steps,
                ..limits
            },
        )
        .await
        .expect("genesis with extra steps");
        let (entry, payload) = file("zz-added", b"one new small file");
        entries.push(entry);
        let next = publish(&mut store, Some(&head), &entries, vec![payload]);
        let result = validate(&store, &next.candidate, Some(&proof), limits).await;
        assert!(result.is_ok(), "{n} files: {:?}", result.err());
    }
}

#[tokio::test]
async fn default_limits_admit_large_genesis_at_multiple_binmap_widths() {
    for n in [45_000, 90_000] {
        let (mut store, head, _) = volume(n);
        let table = store.meta(encode_bin_table(&head.digests).unwrap());
        for width in [0, 1, 2, 3] {
            let (index, shards) = make_map(&mut store, table, &head.rows, width);
            let genesis = candidate(&mut store, None, head.candidate.manifest, index);
            store.take_calls();
            let result = validate(&store, &genesis, None, ValidationLimits::default()).await;
            assert!(
                result.is_ok(),
                "{n} files, width {width}: {:?}",
                result.err()
            );
            let calls = store.take_calls();
            for shard in shards {
                assert_eq!(
                    calls
                        .iter()
                        .filter(|(key, _)| *key == Key::Meta(shard))
                        .count(),
                    1
                );
            }
        }
    }
}

fn shared(limit: usize) -> PublicationValidator {
    let mut validator = PublicationValidator::new(ValidationLimits::default(), 2);
    validator.limit_proofs(limit);
    validator
}

async fn validate_in(
    validator: &PublicationValidator,
    store: &Objects,
    candidate: &ValidationCandidate,
    parent: Option<&VerifiedContent>,
) -> Result<VerifiedContent> {
    validator
        .begin(std::sync::Arc::new(TestClock::default()))
        .await
        .expect("slot")
        .validate(store, candidate.clone(), parent)
        .await
}

async fn intake_proof(
    validator: &PublicationValidator,
    store: &Objects,
    candidate: &ValidationCandidate,
) -> Result<VerifiedContent> {
    let mut work = validator
        .begin_intake(std::sync::Arc::new(TestClock::default()))
        .await
        .expect("intake slot");
    let (cache, lengths) =
        crate::authority::content::intake::verify_content(store, &mut work, candidate).await?;
    Ok(VerifiedContent {
        root: candidate.clone(),
        cache,
        lengths,
    })
}

fn named(mut head: Head, volume: &str) -> Head {
    head.candidate.volume = VolumeName::new(volume.to_owned()).unwrap();
    head
}

fn cost(head: &Head) -> usize {
    let buckets: std::collections::BTreeSet<u8> =
        head.rows.iter().map(|row| row.id.digest()[0]).collect();
    buckets.len() * 512 + head.rows.len() * 96
}

#[tokio::test]
async fn length_learned_by_a_sibling_candidate_is_not_carried() {
    let (mut store, head, mut entries) = volume(3);
    let validator = shared(1 << 30);
    let proof = validate_in(&validator, &store, &head.candidate, None)
        .await
        .expect("genesis");
    // Sibling 1 maps and verifies X; it is refused later / lost.
    let (entry, payload) = file("x", b"content only the losing sibling mapped");
    entries.push(entry);
    let loser = publish(&mut store, Some(&head), &entries, vec![payload]);
    let loser_proof = validate_in(&validator, &store, &loser.candidate, Some(&proof))
        .await
        .expect("sibling one is valid");
    // Sibling 2 over the same parent names X in its tree but never maps it.
    let unmapped = publish(&mut store, Some(&head), &entries, vec![]);
    assert_eq!(
        validate_in(&validator, &store, &unmapped.candidate, Some(&proof))
            .await
            .map(|_| ()),
        Err(MissingReference),
        "X is unmapped on this chain"
    );
    // The loser's proof is no baseline for a child of the parent.
    assert_eq!(
        validate_in(&validator, &store, &unmapped.candidate, Some(&loser_proof))
            .await
            .map(|_| ()),
        Err(Unavailable)
    );
    // A wrong declared length for an inherited grain is still refused.
    let mut lying = entries.clone();
    lying.pop();
    let (mut entry, _) = file("f000001-copy", b"payload of file 1");
    if let EntryKind::File { size, grains, .. } = &mut entry.kind {
        *size += 1;
        if let FileGrains::Inline(refs) = grains {
            refs[0].unpacked_len += 1;
        }
    }
    lying.push(entry);
    lying.sort_by(|l, r| l.name.as_bytes().cmp(r.name.as_bytes()));
    let lying = publish(&mut store, Some(&head), &lying, vec![]);
    assert_eq!(
        validate_in(&validator, &store, &lying.candidate, Some(&proof))
            .await
            .map(|_| ()),
        Err(InvalidReference)
    );
}

#[tokio::test]
async fn pool_accounting_returns_to_zero_across_cycles() {
    let (mut store, head, mut entries) = volume(400);
    let (entry, payload) = file("zz-added", b"one new small file");
    entries.push(entry);
    let next = publish(&mut store, Some(&head), &entries, vec![payload]);
    let validator = shared(cost(&head));
    let proofs = validator.proofs();
    for round in 0..200 {
        let proof = validate_in(&validator, &store, &head.candidate, None)
            .await
            .unwrap_or_else(|error| panic!("round {round} genesis: {error:?}"));
        assert_eq!(proofs.live_bytes(), cost(&head));
        let child = validate_in(&validator, &store, &next.candidate, Some(&proof))
            .await
            .unwrap_or_else(|error| panic!("round {round} child: {error:?}"));
        assert!(proofs.live_bytes() > cost(&next));
        assert!(proofs.live_bytes() < cost(&next) + cost(&head));
        if round % 2 == 0 {
            drop(proof);
            drop(child);
        } else {
            drop(child);
            drop(proof);
        }
        assert_eq!(proofs.live_bytes(), 0);
        // A refused attempt also returns what it staged.
        let mut bad = next.candidate.clone();
        bad.manifest = GrainId::of(b"payload of file 1");
        let proof = validate_in(&validator, &store, &head.candidate, None)
            .await
            .unwrap_or_else(|error| panic!("round {round} second genesis: {error:?}"));
        assert!(
            validate_in(&validator, &store, &bad, Some(&proof))
                .await
                .is_err()
        );
        assert_eq!(proofs.live_bytes(), cost(&head));
        drop(proof);
        assert_eq!(proofs.live_bytes(), 0);
    }
}

#[tokio::test]
async fn lru_eviction_across_volumes_keeps_recent_and_in_flight_proofs() {
    let (mut store_a, head_a, mut entries_a) = volume(400);
    let head_a = named(head_a, "vol-a");
    let (store_b, head_b, _) = volume(400);
    let head_b = named(head_b, "vol-b");
    let (store_c, head_c, _) = volume(400);
    let head_c = named(head_c, "vol-c");
    let each = cost(&head_a);
    let validator = shared(2 * each + each / 2);
    let proofs = validator.proofs().clone();
    let (va, vb, vc) = (
        head_a.candidate.volume.clone(),
        head_b.candidate.volume.clone(),
        head_c.candidate.volume.clone(),
    );
    proofs.install(
        validate_in(&validator, &store_a, &head_a.candidate, None)
            .await
            .expect("a"),
    );
    proofs.install(
        validate_in(&validator, &store_b, &head_b.candidate, None)
            .await
            .expect("b"),
    );
    // Touch A: B is now least recently used.
    let retained_a = proofs
        .get(&va, head_a.candidate.root_id)
        .expect("a present");
    let c = intake_proof(&validator, &store_c, &head_c.candidate)
        .await
        .expect("reserve intake with a full LRU");
    assert!(proofs.has_landed(&vb));
    assert_eq!(proofs.resident_bytes(), 2 * each);
    assert_eq!(proofs.live_bytes(), 3 * each);
    proofs.install(c);
    assert!(!proofs.has_landed(&vb), "b evicted at promotion");
    assert!(proofs.has_landed(&va));
    assert_eq!(proofs.resident_bytes(), 2 * each);
    assert_eq!(proofs.live_bytes(), 2 * each);

    // A wrong root ID for C removes its own stale proof.
    assert!(proofs.get(&vc, GrainId::of(b"another root")).is_none());
    assert!(!proofs.has_landed(&vc));
    proofs.install(
        validate_in(&validator, &store_b, &head_b.candidate, None)
            .await
            .expect("b again"),
    );
    let c = intake_proof(&validator, &store_c, &head_c.candidate)
        .await
        .expect("intake can run while a reader holds a");
    proofs.install(c);
    assert!(!proofs.has_landed(&va));
    assert!(
        proofs.has_landed(&vb),
        "the reader must not cost b its place"
    );
    assert_eq!(proofs.resident_bytes(), 2 * each);
    assert_eq!(proofs.live_bytes(), 3 * each);

    let (entry, payload) = file("zz-added", b"one new small file");
    entries_a.push(entry);
    let mut next_a = publish(&mut store_a, Some(&head_a), &entries_a, vec![payload]);
    next_a.candidate.volume = va;
    validate_in(&validator, &store_a, &next_a.candidate, Some(&retained_a))
        .await
        .expect("the evicted proof is readable");
    assert_eq!(proofs.live_bytes(), 3 * each);
    drop(retained_a);
    assert_eq!(proofs.live_bytes(), 2 * each);
    proofs.discard(&vb);
    proofs.discard(&vc);
    assert_eq!(proofs.resident_bytes(), 0);
    assert_eq!(proofs.live_bytes(), 0);
}

#[tokio::test]
async fn staged_allocation_preserves_another_volumes_landed_proof() {
    let (store_a, head_a, _) = volume(400);
    let head_a = named(head_a, "vol-a");
    let each = cost(&head_a);
    let validator = shared(each + each / 2);
    let proofs = validator.proofs().clone();
    proofs.install(
        validate_in(&validator, &store_a, &head_a.candidate, None)
            .await
            .expect("a"),
    );
    // B's staged proof crosses the LRU budget before finding a false length.
    let mut store_b = Objects::default();
    let (mut entries, payloads): (Vec<_>, Vec<_>) = (0..400)
        .map(|i| file(&format!("g{i:06}"), format!("other payload {i}").as_bytes()))
        .unzip();
    if let EntryKind::File { size, grains, .. } = &mut entries[399].kind {
        *size += 1;
        if let FileGrains::Inline(refs) = grains {
            refs[0].unpacked_len += 1;
        }
    }
    let head_b = named(publish(&mut store_b, None, &entries, payloads), "vol-b");
    assert_eq!(
        validate_in(&validator, &store_b, &head_b.candidate, None)
            .await
            .map(|_| ()),
        Err(InvalidReference)
    );
    assert_eq!(proofs.live_bytes(), each);
    assert_eq!(proofs.resident_bytes(), each);
    assert!(
        proofs
            .get(&head_a.candidate.volume, head_a.candidate.root_id)
            .is_some(),
        "a refused candidate on vol-b evicted vol-a's landed proof"
    );
}

#[tokio::test]
async fn volume_growing_past_the_length_cap_is_a_definitive_refusal() {
    const CAP: usize = 1 << 20;
    let limits = ValidationLimits {
        steps: 32_000_000,
        wall_time: Duration::from_mins(2),
        ..ValidationLimits::default()
    };
    let validator = PublicationValidator::new(limits, 2);
    let mut store = Objects::default();
    let mut codec = GrainCodec::new().unwrap();
    let payloads = (1..CAP)
        .map(|i| {
            let bytes = i.to_le_bytes();
            PackedFrame {
                id: GrainId::of(&bytes),
                frame: codec.compress_grain(&bytes).unwrap(),
            }
        })
        .collect();
    // The empty tree contributes one more mapped grain. The cap applies to
    // all mappings, including payloads outside the manifest.
    let head = publish_at_width(&mut store, None, &[], payloads, 4);
    assert_eq!(head.rows.len(), CAP);
    let proof = validate_in(&validator, &store, &head.candidate, None)
        .await
        .expect("genesis at the cap");
    let extra = frame(b"one grain past the length cap");
    let next = publish(&mut store, Some(&head), &[], vec![extra]);
    assert_eq!(next.rows.len(), CAP + 1);
    let error = validate_in(&validator, &store, &next.candidate, Some(&proof))
        .await
        .map(|_| ())
        .expect_err("cap plus one is refused");
    assert_eq!(error, ValidationError::LengthLimit);
    let response = crate::adapter::publish::outcome(&crate::authority::Answer::Validation(error));
    assert_eq!(response.status(), crate::wire::Status::ContentTooLarge);
    assert_eq!(
        response.error(),
        Some(crate::wire::ErrorToken::PublishWorkLimit)
    );
    // Intake identifies the definitive limit before trying to read a bin.
    store.stored.remove(&Key::Bin(next.digests[0]));
    store.take_calls();
    let error = intake_proof(&validator, &store, &next.candidate)
        .await
        .map(|_| ())
        .expect_err("cap plus one is refused even when a bin is missing");
    assert_eq!(error, ValidationError::LengthLimit);
    let response = crate::adapter::publish::outcome(&crate::authority::Answer::Validation(error));
    assert_eq!(response.status(), crate::wire::Status::ContentTooLarge);
    assert_eq!(
        response.error(),
        Some(crate::wire::ErrorToken::PublishWorkLimit)
    );
    assert!(
        store
            .take_calls()
            .iter()
            .all(|(key, _)| matches!(key, Key::Meta(_))),
        "cold intake can identify the over-limit map before reading bins"
    );
}

#[tokio::test]
async fn pool_full_of_landed_proofs_does_not_starve_staged_attempts() {
    let (mut store_a, head_a, mut entries_a) = volume(400);
    let (store_b, head_b, _) = volume(400);
    let head_b = named(head_b, "vol-b");
    let validator = shared(cost(&head_a) + cost(&head_b));
    let proofs = validator.proofs();
    for (store, head) in [(&store_a, &head_a), (&store_b, &head_b)] {
        proofs.install(
            intake_proof(&validator, store, &head.candidate)
                .await
                .unwrap(),
        );
    }

    let (entry, payload) = file("zz-added", b"one new small file");
    entries_a.push(entry);
    let next_a = publish(&mut store_a, Some(&head_a), &entries_a, vec![payload]);
    let parent = proofs
        .get(&head_a.candidate.volume, head_a.candidate.root_id)
        .expect("warm parent");
    let edit = validate_in(&validator, &store_a, &next_a.candidate, Some(&parent))
        .await
        .expect("warm edit validates with a full landed pool");
    assert!(proofs.has_landed(&head_b.candidate.volume));
    assert_eq!(proofs.resident_bytes(), cost(&head_a) + cost(&head_b));
    proofs.install(edit);
    assert!(!proofs.has_landed(&head_b.candidate.volume));
    assert_eq!(proofs.resident_bytes(), cost(&next_a));
    assert!(
        proofs
            .get(&next_a.candidate.volume, next_a.candidate.root_id)
            .is_some()
    );
}

#[tokio::test]
async fn two_staged_attempts_and_one_landed_proof_under_pressure() {
    use crate::authority::join::{Raced, race};

    let (store_a, head_a, _) = volume(400);
    let (store_b, head_b, _) = volume(400);
    let head_b = named(head_b, "vol-b");
    let (store_c, head_c, _) = volume(400);
    let head_c = named(head_c, "vol-c");
    let validator = shared(cost(&head_b) + cost(&head_c));
    let proofs = validator.proofs();
    proofs.install(
        intake_proof(&validator, &store_a, &head_a.candidate)
            .await
            .unwrap(),
    );
    let clock = std::sync::Arc::new(TestClock::default());
    let mut work_b = validator.begin(clock.clone()).await.unwrap();
    let mut work_c = validator.begin(clock).await.unwrap();
    let mut b = std::pin::pin!(work_b.validate(&store_b, head_b.candidate.clone(), None));
    let mut c = std::pin::pin!(work_c.validate(&store_c, head_c.candidate.clone(), None));
    let (b, c) = match race(b.as_mut(), c.as_mut()).await {
        Raced::First(b) => (b, c.await),
        Raced::Second(c) => (b.await, c),
    };
    assert!(proofs.has_landed(&head_a.candidate.volume));
    assert!(
        b.is_ok() && c.is_ok(),
        "both candidates must validate: {:?}, {:?}",
        b.as_ref().err(),
        c.as_ref().err()
    );
    proofs.install(b.unwrap());
    proofs.install(c.unwrap());
    assert!(!proofs.has_landed(&head_a.candidate.volume));
    assert!(proofs.has_landed(&head_b.candidate.volume));
    assert!(proofs.has_landed(&head_c.candidate.volume));
    assert_eq!(proofs.resident_bytes(), cost(&head_b) + cost(&head_c));
    assert_eq!(proofs.live_bytes(), proofs.resident_bytes());
}

#[tokio::test]
async fn rotating_an_intake_slice_keeps_partially_verified_lengths_and_the_ticket() {
    let limits = ValidationLimits {
        reads: 1,
        ..ValidationLimits::default()
    };
    let validator = PublicationValidator::new(limits, 2);
    let clock = std::sync::Arc::new(TestClock::default());
    let mut intake = validator.begin_intake(clock.clone()).await.unwrap();
    let allocation = intake.length_allocation().unwrap();
    let mut partial = proofs::Lengths::default();
    let id = GrainId::of(b"first verified length");
    partial.insert(&allocation, id, 13).unwrap();
    assert_eq!(validator.proofs().live_bytes(), 608);
    intake.prepare_page(1).await.unwrap();
    intake.list_page().unwrap();

    let mut waiting = std::pin::pin!(validator.begin_intake(clock));
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    // Another read forces a new slice with evidence still live.
    intake.prepare_page(1).await.unwrap();
    intake.list_page().unwrap();
    assert_eq!(partial.get(&id), Some(13));
    assert_eq!(validator.proofs().live_bytes(), 608);
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;

    drop(partial);
    drop(intake);
    assert_eq!(validator.proofs().live_bytes(), 0);
    waiting.await.unwrap();
}

#[tokio::test]
async fn cancelled_validation_holds_its_slot_until_detached_lengths_are_dropped() {
    use crate::authority::join::{Raced, race};
    use tokio::sync::oneshot;

    struct DiscardedProof {
        allocation: proofs::Allocation,
        observed: Option<oneshot::Sender<Result<()>>>,
    }

    impl Drop for DiscardedProof {
        fn drop(&mut self) {
            let result = proofs::Lengths::default().insert(
                &self.allocation,
                GrainId::of(b"length in detached work"),
                1,
            );
            if let Some(observed) = self.observed.take() {
                let _ = observed.send(result);
            }
        }
    }

    let validator = PublicationValidator::default();
    let mut attempt = validator
        .begin(std::sync::Arc::new(TestClock::default()))
        .await
        .unwrap();
    let (entered, running) = oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let (observed, dropped) = oneshot::channel();
    let allocation = attempt.length_allocation().unwrap();
    {
        let work = std::pin::pin!(attempt.blocking(move |_| {
            entered.send(()).unwrap();
            wait.recv().unwrap();
            Ok(DiscardedProof {
                allocation,
                observed: Some(observed),
            })
        }));
        match race(work, std::pin::pin!(running)).await {
            Raced::First(_) => panic!("blocking work completed before release"),
            Raced::Second(result) => result.unwrap(),
        }
        // Drop the waiter while the blocking work still holds the slot.
    }
    drop(attempt);
    release.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), dropped)
            .await
            .unwrap()
            .unwrap(),
        Ok(())
    );
}
