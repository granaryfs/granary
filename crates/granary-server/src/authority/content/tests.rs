// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

mod file_lengths;

use std::collections::BTreeMap;
use std::future::{pending, ready};
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use granary_core::binfmt::{PackedFrame, decode_bin, encode_bin};
use granary_core::binmap::{
    ShardEntry, encode_bin_table, encode_binmap_index, encode_shard, shard_for,
};
use granary_core::clock::Clock;
use granary_core::manifest::encode_dir_leaf;
use granary_core::sheaf::{SheafDoc, SheafOp, Timestamp, encode_sheaf};
use granary_store::codec::GrainCodec;

use super::*;
use ValidationError::{InvalidReference, MissingReference, Unavailable, WorkLimit};

type Digest = [u8; DIGEST_LEN];

#[derive(Default)]
struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            secs: self.0.load(Ordering::Relaxed),
            nanos: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Meta(GrainId),
    Bin(Digest),
    Range(Digest, u64, u32),
}

#[derive(Default)]
struct Objects {
    stored: BTreeMap<Key, Vec<u8>>,
    calls: Mutex<Vec<(Key, u64)>>,
}

impl Objects {
    fn meta(&mut self, bytes: Vec<u8>) -> GrainId {
        let id = GrainId::of(&bytes);
        self.stored.insert(Key::Meta(id), bytes);
        id
    }

    fn bin(&mut self, frames: &[PackedFrame], ordinal: u32) -> (Digest, Vec<ShardEntry>) {
        let bytes = encode_bin(frames).expect("bin");
        let digest = *GrainId::of(&bytes).digest();
        let rows = decode_bin(&bytes)
            .expect("index")
            .into_iter()
            .map(|entry| ShardEntry {
                id: entry.id,
                bin_ordinal: ordinal,
                offset: entry.offset,
                comp_len: entry.comp_len,
            })
            .collect();
        self.stored.insert(Key::Bin(digest), bytes);
        (digest, rows)
    }

    fn take_calls(&self) -> Vec<(Key, u64)> {
        std::mem::take(&mut *self.calls.lock().expect("calls"))
    }
}

impl ValidationRead for Objects {
    fn read(
        &self,
        object: ValidationObject<'_>,
        cap: u64,
    ) -> impl Future<Output = std::result::Result<Vec<u8>, ValidationReadError>> + Send {
        let key = match object {
            ValidationObject::Meta(_, id) => Key::Meta(id),
            ValidationObject::Bin(digest) => Key::Bin(digest),
            ValidationObject::BinRange(digest, offset, len) => Key::Range(digest, offset, len),
            ValidationObject::Root(..) => return ready(Err(ValidationReadError::Unavailable)),
        };
        let bytes = match key {
            Key::Range(digest, offset, len) => self.stored.get(&Key::Bin(digest)).and_then(|bin| {
                let start = usize::try_from(offset).ok()?;
                bin.get(start..start.checked_add(len as usize)?)
            }),
            _ => self.stored.get(&key).map(Vec::as_slice),
        };
        self.calls.lock().expect("calls").push((key, cap));
        ready(match bytes {
            Some(bytes) if bytes.len() as u64 > cap => Err(ValidationReadError::OverCap),
            Some(bytes) => Ok(bytes.to_vec()),
            None => Err(ValidationReadError::Missing),
        })
    }
}

struct Fixture {
    store: Objects,
    candidate: ValidationCandidate,
    digest: Digest,
    rows: Vec<ShardEntry>,
    table: GrainId,
    shards: Vec<GrainId>,
    reserve: ShardEntry,
}

impl Fixture {
    fn at_width(width: u8) -> Self {
        let mut store = Objects::default();
        let dir = frame(&encode_dir_leaf(&[]).expect("empty dir"));
        let manifest = dir.id;
        let content = frame(b"content carried across publishes");
        let spare = frame(b"initially unmapped content");
        let (digest, mut rows) = store.bin(&[dir, content, spare], 0);
        let reserve = rows.pop().expect("unmapped row");
        let table = store.meta(encode_bin_table(&[digest]).expect("table"));
        let (index, shards) = make_map(&mut store, table, &rows, width);
        let candidate = candidate(&mut store, None, manifest, index);
        Self {
            store,
            candidate,
            digest,
            rows,
            table,
            shards,
            reserve,
        }
    }

    async fn baseline(&self) -> VerifiedContent {
        let proof = validate(
            &self.store,
            &self.candidate,
            None,
            ValidationLimits::default(),
        )
        .await
        .expect("verified genesis");
        self.store.take_calls();
        proof
    }

    fn successor(&mut self, table: GrainId, rows: &[ShardEntry], width: u8) -> ValidationCandidate {
        let (binmap, _) = make_map(&mut self.store, table, rows, width);
        candidate(
            &mut self.store,
            Some(&self.candidate),
            self.candidate.manifest,
            binmap,
        )
    }
}

fn frame(bytes: &[u8]) -> PackedFrame {
    PackedFrame {
        id: GrainId::of(bytes),
        frame: GrainCodec::new()
            .expect("codec")
            .compress_grain(bytes)
            .expect("frame"),
    }
}

fn make_map(
    store: &mut Objects,
    table: GrainId,
    rows: &[ShardEntry],
    width: u8,
) -> (GrainId, Vec<GrainId>) {
    let mut slots = vec![Vec::new(); 1usize << width];
    for row in rows {
        slots
            .get_mut(shard_for(&row.id, width))
            .expect("slot")
            .push(*row);
    }
    let shards: Vec<_> = slots
        .into_iter()
        .map(|mut rows| {
            rows.sort_by_key(|row| row.id);
            store.meta(encode_shard(&rows).expect("shard"))
        })
        .collect();
    let index = put_index(store, table, &shards, width);
    (index, shards)
}

fn put_index(store: &mut Objects, table: GrainId, shards: &[GrainId], width: u8) -> GrainId {
    store.meta(encode_binmap_index(width, table, shards).expect("index"))
}

fn sheaf(store: &mut Objects, parent: Option<GrainId>, manifest: GrainId) -> GrainId {
    store.meta(
        encode_sheaf(&SheafDoc {
            parent,
            manifest_root: manifest,
            timestamp: Timestamp { secs: 0, nanos: 0 },
            ops: vec![SheafOp::PublishTree],
        })
        .expect("sheaf"),
    )
}

fn candidate(
    store: &mut Objects,
    parent: Option<&ValidationCandidate>,
    manifest: GrainId,
    binmap: GrainId,
) -> ValidationCandidate {
    let sheaf = sheaf(store, parent.map(|p| p.sheaf), manifest);
    ValidationCandidate {
        volume: VolumeName::new("test".to_owned()).expect("volume"),
        root_id: GrainId::of(&sheaf.to_bytes()),
        parent: parent.map(|p| p.root_id),
        manifest,
        binmap,
        sheaf,
    }
}

async fn validate(
    store: &Objects,
    candidate: &ValidationCandidate,
    parent: Option<&VerifiedContent>,
    limits: ValidationLimits,
) -> Result<VerifiedContent> {
    PublicationValidator::new(limits, 1)
        .begin(std::sync::Arc::new(TestClock::default()))
        .await
        .expect("validation slot")
        .validate(store, candidate.clone(), parent)
        .await
}

#[tokio::test]
async fn missing_each_reference_can_be_retried_with_the_exact_candidate() {
    let mut fixture = Fixture::at_width(0);
    let keys = [
        Key::Meta(fixture.candidate.sheaf),
        Key::Meta(fixture.candidate.binmap),
        Key::Meta(fixture.table),
        Key::Meta(*fixture.shards.first().expect("shard")),
        Key::Bin(fixture.digest),
    ];
    for key in keys {
        let original = fixture.store.stored.remove(&key).expect("uploaded object");
        assert_eq!(
            validate(
                &fixture.store,
                &fixture.candidate,
                None,
                ValidationLimits::default()
            )
            .await
            .expect_err("missing upload"),
            MissingReference,
            "{key:?}"
        );
        fixture.store.stored.insert(key, original);
        let proof = fixture.baseline().await;
        assert!(proof.matches(&fixture.candidate.volume, fixture.candidate.root_id));
    }
}

#[tokio::test]
async fn bytes_under_each_content_address_are_hashed() {
    let mut fixture = Fixture::at_width(0);
    let keys = [
        Key::Meta(fixture.candidate.sheaf),
        Key::Meta(fixture.candidate.binmap),
        Key::Meta(fixture.table),
        Key::Meta(*fixture.shards.first().expect("shard")),
        Key::Bin(fixture.digest),
    ];
    for key in keys {
        let bytes = fixture.store.stored.get_mut(&key).expect("uploaded object");
        let last = bytes.last_mut().expect("nonempty");
        *last ^= 1;
        assert_eq!(
            validate(
                &fixture.store,
                &fixture.candidate,
                None,
                ValidationLimits::default()
            )
            .await
            .expect_err("wrong object hash"),
            InvalidReference,
            "{key:?}"
        );
        *fixture
            .store
            .stored
            .get_mut(&key)
            .expect("object")
            .last_mut()
            .expect("byte") ^= 1;
    }
    fixture.baseline().await;
}

#[tokio::test]
async fn strictly_decodes_hash_correct_metadata_and_checks_sheaf_links() {
    let mut fixture = Fixture::at_width(0);
    let parent = fixture.baseline().await;
    let mut child = candidate(
        &mut fixture.store,
        Some(&fixture.candidate),
        fixture.candidate.manifest,
        fixture.candidate.binmap,
    );

    for (parent_id, manifest) in [
        (None, child.manifest),
        (Some(GrainId::of(b"wrong parent")), child.manifest),
        (
            Some(fixture.candidate.sheaf),
            GrainId::of(b"wrong manifest"),
        ),
    ] {
        child.sheaf = sheaf(&mut fixture.store, parent_id, manifest);
        assert_eq!(
            validate(
                &fixture.store,
                &child,
                Some(&parent),
                ValidationLimits::default()
            )
            .await
            .expect_err("wrong sheaf link"),
            InvalidReference
        );
    }

    let original = fixture.candidate.clone();
    let malformed = fixture.store.meta(b"not an encoded object".to_vec());
    let malformed_table = put_index(&mut fixture.store, malformed, &fixture.shards, 0);
    let malformed_shard = put_index(&mut fixture.store, fixture.table, &[malformed], 0);
    for candidate in [
        ValidationCandidate {
            sheaf: malformed,
            ..original.clone()
        },
        ValidationCandidate {
            binmap: malformed,
            ..original.clone()
        },
        ValidationCandidate {
            binmap: malformed_table,
            ..original.clone()
        },
        ValidationCandidate {
            binmap: malformed_shard,
            ..original
        },
    ] {
        assert_eq!(
            validate(
                &fixture.store,
                &candidate,
                None,
                ValidationLimits::default()
            )
            .await
            .expect_err("malformed metadata"),
            InvalidReference
        );
    }
}

#[tokio::test]
async fn refuses_missing_or_confused_non_genesis_baselines_before_reads() {
    let mut fixture = Fixture::at_width(0);
    let proof = fixture.baseline().await;
    let template = candidate(
        &mut fixture.store,
        Some(&fixture.candidate),
        fixture.candidate.manifest,
        fixture.candidate.binmap,
    );
    let wrong_volume = ValidationCandidate {
        volume: VolumeName::new("other".to_owned()).expect("volume"),
        ..template.clone()
    };
    let wrong_head = ValidationCandidate {
        parent: Some(GrainId::of(b"another root")),
        ..template.clone()
    };
    for (root, baseline) in [
        (&template, None),
        (&wrong_volume, Some(&proof)),
        (&wrong_head, Some(&proof)),
    ] {
        assert_eq!(
            validate(&fixture.store, root, baseline, ValidationLimits::default())
                .await
                .expect_err("no matching baseline"),
            Unavailable
        );
        assert!(fixture.store.take_calls().is_empty());
    }
    validate(
        &fixture.store,
        &template,
        Some(&proof),
        ValidationLimits::default(),
    )
    .await
    .expect("unchanged content");
    assert_eq!(
        fixture
            .store
            .take_calls()
            .into_iter()
            .map(|(key, _)| key)
            .collect::<Vec<_>>(),
        [Key::Meta(template.sheaf)]
    );
}

#[tokio::test]
async fn refuses_missing_manifest_mapping_and_wrong_root_node_type() {
    let mut fixture = Fixture::at_width(0);
    let index = fixture.candidate.binmap;
    for (id, want) in [
        (GrainId::of(b"not mapped"), MissingReference),
        (
            GrainId::of(b"content carried across publishes"),
            InvalidReference,
        ),
    ] {
        let root = candidate(&mut fixture.store, None, id, index);
        assert_eq!(
            validate(&fixture.store, &root, None, ValidationLimits::default())
                .await
                .expect_err("manifest root"),
            want
        );
    }
}

#[tokio::test]
async fn rejects_table_prefix_changes_removals_and_remaps_at_both_widths() {
    for width in [0, 2] {
        let mut fixture = Fixture::at_width(0);
        let proof = fixture.baseline().await;
        let (digest, remapped) = fixture
            .store
            .bin(&[frame(b"content carried across publishes")], 1);
        let table = fixture
            .store
            .meta(encode_bin_table(&[fixture.digest, digest]).expect("table"));
        let reversed = fixture
            .store
            .meta(encode_bin_table(&[digest, fixture.digest]).expect("table"));
        let old_root = *fixture.rows.first().expect("root mapping");
        let remapped = *remapped.first().expect("remapped row");
        let original = fixture.rows.clone();
        for (index_table, rows) in [
            (table, vec![old_root]),
            (table, vec![old_root, remapped]),
            (reversed, original.clone()),
        ] {
            let child = fixture.successor(index_table, &rows, width);
            assert_eq!(
                validate(
                    &fixture.store,
                    &child,
                    Some(&proof),
                    ValidationLimits::default()
                )
                .await
                .expect_err("invalid map preservation"),
                InvalidReference
            );
        }
        let child = fixture.successor(table, &original, width);
        validate(
            &fixture.store,
            &child,
            Some(&proof),
            ValidationLimits::default(),
        )
        .await
        .expect("retained map and valid spare bin");
    }
}

#[tokio::test]
async fn checks_routing_real_ordinals_and_exact_index_extents() {
    let mut fixture = Fixture::at_width(0);
    let rows = fixture.rows.clone();
    let original = *rows.first().expect("root mapping");
    let content = *rows.last().expect("content mapping");
    let mut malformed = rows.clone();
    malformed.sort_by_key(|row| row.id);
    let taken = fixture.store.meta(encode_shard(&malformed).expect("shard"));
    let empty = fixture.store.meta(encode_shard(&[]).expect("empty"));
    let swapped = if shard_for(&original.id, 1) == 0 {
        vec![empty, taken]
    } else {
        vec![taken, empty]
    };
    let misrouted = put_index(&mut fixture.store, fixture.table, &swapped, 1);
    for binmap in [
        misrouted,
        make_map(
            &mut fixture.store,
            fixture.table,
            &[
                original,
                ShardEntry {
                    bin_ordinal: 1,
                    ..content
                },
            ],
            0,
        )
        .0,
        make_map(
            &mut fixture.store,
            fixture.table,
            &[
                original,
                ShardEntry {
                    offset: content.offset + 1,
                    ..content
                },
            ],
            0,
        )
        .0,
        make_map(
            &mut fixture.store,
            fixture.table,
            &[
                original,
                ShardEntry {
                    comp_len: content.comp_len + 1,
                    ..content
                },
            ],
            0,
        )
        .0,
    ] {
        let root = candidate(&mut fixture.store, None, fixture.candidate.manifest, binmap);
        assert_eq!(
            validate(&fixture.store, &root, None, ValidationLimits::default())
                .await
                .expect_err("malformed shard mapping"),
            InvalidReference
        );
    }
}

#[tokio::test]
async fn verifies_unreachable_additions_and_unmapped_new_bin_structure() {
    let mut fixture = Fixture::at_width(0);
    let parent = fixture.baseline().await;
    let good = frame(b"additional grain outside the manifest");
    let mut wrong_hash = good.clone();
    wrong_hash.id = GrainId::of(b"forged grain name");
    let mut wrong_length = good.clone();
    *wrong_length.frame.get_mut(8).expect("length byte") += 1;
    let mut bad_payload = good.clone();
    *bad_payload.frame.get_mut(9).expect("zstd payload") ^= 1;

    for (packed, valid) in [
        (good, true),
        (wrong_hash, false),
        (wrong_length, false),
        (bad_payload, false),
    ] {
        let (digest, rows) = fixture.store.bin(&[packed], 1);
        let table = fixture
            .store
            .meta(encode_bin_table(&[fixture.digest, digest]).expect("table"));
        let mut mappings = fixture.rows.clone();
        mappings.extend(rows);
        let child = fixture.successor(table, &mappings, 0);

        let all = validate(
            &fixture.store,
            &child,
            Some(&parent),
            ValidationLimits::default(),
        )
        .await;
        if valid {
            all.expect("valid unreachable addition");
            let keys = fixture.store.take_calls();
            assert_eq!(
                keys.iter()
                    .filter(|(key, _)| *key == Key::Bin(digest))
                    .count(),
                1
            );
        } else {
            assert_eq!(all.expect_err("malformed frame"), InvalidReference);
            let limit = ValidationLimits {
                expansion: 0,
                ..ValidationLimits::default()
            };
            assert_eq!(
                validate(&fixture.store, &child, Some(&parent), limit)
                    .await
                    .expect_err("charge before decompression"),
                WorkLimit
            );
        }
    }
    let malformed_bin = b"invalid bin framing".to_vec();
    let digest = *GrainId::of(&malformed_bin).digest();
    fixture.store.stored.insert(Key::Bin(digest), malformed_bin);
    let table = fixture
        .store
        .meta(encode_bin_table(&[fixture.digest, digest]).expect("table"));
    let old_rows = fixture.rows.clone();
    let child = fixture.successor(table, &old_rows, 0);
    assert_eq!(
        validate(
            &fixture.store,
            &child,
            Some(&parent),
            ValidationLimits::default()
        )
        .await
        .expect_err("strict bin framing even without mappings"),
        InvalidReference
    );
}

#[tokio::test]
async fn cold_parent_shard_is_charged_and_missing_old_objects_are_unavailable() {
    let mut fixture = Fixture::at_width(0);
    let mut parent = fixture.baseline().await;
    let mut rows = fixture.rows.clone();
    rows.push(fixture.reserve);
    let child = fixture.successor(fixture.table, &rows, 0);
    let cold = Key::Meta(*fixture.shards.first().expect("old shard"));

    // The unchanged table and index stay resident. Evict only the old
    // shard to exercise the incremental read.
    let limits = ValidationLimits {
        reads: 4,
        ..ValidationLimits::default()
    };
    validate(&fixture.store, &child, Some(&parent), limits)
        .await
        .expect("four warm reads");
    let warm_calls = fixture.store.take_calls();
    assert_eq!(warm_calls.len(), 4);
    assert!(warm_calls.iter().all(|(key, _)| *key != cold));

    parent.cache.evict_shard();
    assert_eq!(
        validate(&fixture.store, &child, Some(&parent), limits)
            .await
            .expect_err("extra cold read"),
        WorkLimit
    );
    assert_eq!(fixture.store.take_calls().len(), 4);
    let limits = ValidationLimits { reads: 5, ..limits };
    validate(&fixture.store, &child, Some(&parent), limits)
        .await
        .expect("exact cold budget");
    let cold_calls = fixture.store.take_calls();
    assert_eq!(cold_calls.len(), 5);
    assert!(cold_calls.iter().any(|(key, _)| *key == cold));

    parent.evict_cached_objects();
    for key in [
        Key::Meta(fixture.candidate.binmap),
        Key::Meta(fixture.table),
        cold,
        Key::Bin(fixture.digest),
    ] {
        let bytes = fixture.store.stored.remove(&key).expect("old object");
        assert_eq!(
            validate(
                &fixture.store,
                &child,
                Some(&parent),
                ValidationLimits::default()
            )
            .await
            .expect_err("missing old object"),
            Unavailable,
            "{key:?}"
        );
        fixture
            .store
            .stored
            .insert(key.clone(), b"wrong bytes at a verified key".to_vec());
        assert_eq!(
            validate(
                &fixture.store,
                &child,
                Some(&parent),
                ValidationLimits::default()
            )
            .await
            .expect_err("changed verified object"),
            Unavailable,
            "{key:?}"
        );
        fixture.store.stored.insert(key, bytes);
    }
}

#[tokio::test]
async fn width_cannot_decrease_even_when_every_mapping_remains_in_slot_zero() {
    use granary_core::manifest::{DirEntry, EntryKind, Name};

    let mut store = Objects::default();
    let bytes = (1u8..=u8::MAX)
        .filter_map(|name| Name::new(vec![name]).ok())
        .map(|name| {
            encode_dir_leaf(&[DirEntry {
                name,
                kind: EntryKind::Fifo,
            }])
            .expect("dir")
        })
        .find(|bytes| shard_for(&GrainId::of(bytes), 1) == 0)
        .expect("dir in slot zero");
    let manifest = GrainId::of(&bytes);
    let (digest, rows) = store.bin(&[frame(&bytes)], 0);
    let table = store.meta(encode_bin_table(&[digest]).expect("table"));
    let (wide, _) = make_map(&mut store, table, &rows, 1);
    let (narrow, _) = make_map(&mut store, table, &rows, 0);
    let root = candidate(&mut store, None, manifest, wide);
    let proof = validate(&store, &root, None, ValidationLimits::default())
        .await
        .expect("genesis");
    let child = candidate(&mut store, Some(&root), manifest, narrow);
    assert_eq!(
        validate(&store, &child, Some(&proof), ValidationLimits::default())
            .await
            .expect_err("width decrease"),
        InvalidReference
    );
}

#[tokio::test]
async fn max_width_sweep_counts_repeated_shards() {
    let mut fixture = Fixture::at_width(11);
    let proof = fixture.baseline().await;
    let rows = fixture.rows.clone();
    let increase = fixture.successor(fixture.table, &rows, 12);
    let limits = ValidationLimits {
        reads: 4_096,
        ..ValidationLimits::default()
    };
    assert_eq!(
        validate(&fixture.store, &increase, Some(&proof), limits)
            .await
            .expect_err("repeated shard reads exhaust budget"),
        WorkLimit
    );
    assert_eq!(fixture.store.take_calls().len(), 4_096);
    validate(
        &fixture.store,
        &increase,
        Some(&proof),
        ValidationLimits::default(),
    )
    .await
    .expect("valid width-12 transition fits the default");
    assert_eq!(fixture.store.take_calls().len(), 2 + 2_048 - 1 + 4_096);
}

#[tokio::test(start_paused = true)]
async fn clocks_and_concurrency_gate_store_calls() {
    use std::sync::Arc;
    let clock = Arc::new(TestClock::default());
    let validator = PublicationValidator::new(ValidationLimits::default(), 1);
    let mut attempt = validator.begin(clock.clone()).await.expect("slot");
    let mut queued = std::pin::pin!(validator.begin(clock.clone()));
    std::future::poll_fn(|cx| {
        assert!(queued.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    clock.0.store(30, Ordering::Relaxed);
    let fixture = Fixture::at_width(0);
    assert_eq!(
        attempt
            .validate(&fixture.store, fixture.candidate, None)
            .await
            .expect_err("expired slot"),
        Unavailable
    );
    assert!(fixture.store.take_calls().is_empty());
    drop(attempt);
    let mut granted = queued.await.expect("released slot");
    let fixture = Fixture::at_width(0);
    granted
        .validate(&fixture.store, fixture.candidate, None)
        .await
        .expect("deadline starts on grant");
    assert_eq!(
        validator.begin(clock).await.expect_err("queue deadline"),
        Unavailable
    );
}

#[tokio::test(start_paused = true)]
async fn deadline_cancels_stalled_read_even_with_fixed_clock() {
    struct Stalled;
    impl ValidationRead for Stalled {
        fn read(
            &self,
            _: ValidationObject<'_>,
            _: u64,
        ) -> impl Future<Output = std::result::Result<Vec<u8>, ValidationReadError>> + Send
        {
            pending()
        }
    }

    let limits = ValidationLimits {
        wall_time: Duration::from_secs(1),
        ..ValidationLimits::default()
    };
    let mut attempt = PublicationValidator::new(limits, 1)
        .begin(std::sync::Arc::new(TestClock::default()))
        .await
        .expect("slot");
    let volume = VolumeName::new("test".to_owned()).expect("volume");
    assert_eq!(
        attempt
            .read(&Stalled, ValidationObject::Root(&volume, 1), false)
            .await
            .expect_err("runtime deadline"),
        Unavailable
    );
}

#[tokio::test]
async fn exact_admission_limits_and_one_past_each() {
    let fixture = Fixture::at_width(0);
    let bytes = fixture
        .store
        .stored
        .values()
        .map(|bytes| bytes.len() as u64)
        .sum();
    let expansion = (encode_dir_leaf(&[]).expect("dir").len()
        + b"content carried across publishes".len()) as u64;
    let limits = ValidationLimits {
        reads: 5,
        bytes,
        expansion,
        steps: 24,
        ..ValidationLimits::default()
    };
    validate(&fixture.store, &fixture.candidate, None, limits)
        .await
        .expect("all limits exact");
    assert_eq!(fixture.store.take_calls().len(), 5);

    for (limits, dispatched) in [
        (ValidationLimits { reads: 4, ..limits }, 4),
        (
            ValidationLimits {
                bytes: bytes - 1,
                ..limits
            },
            5,
        ),
        (
            ValidationLimits {
                expansion: expansion - 1,
                ..limits
            },
            5,
        ),
        (
            ValidationLimits {
                steps: 23,
                ..limits
            },
            5,
        ),
        (ValidationLimits { steps: 0, ..limits }, 0),
    ] {
        assert_eq!(
            validate(&fixture.store, &fixture.candidate, None, limits)
                .await
                .expect_err("one over the allowance"),
            WorkLimit
        );
        let calls = fixture.store.take_calls();
        assert_eq!(calls.len(), dispatched);
        if limits.bytes < bytes {
            let bin_bytes = fixture
                .store
                .stored
                .get(&Key::Bin(fixture.digest))
                .expect("bin")
                .len() as u64;
            assert_eq!(
                calls.last(),
                Some(&(Key::Bin(fixture.digest), bin_bytes - 1))
            );
        }
    }
}

#[tokio::test]
async fn changed_root_can_resolve_through_an_inherited_shard() {
    use granary_core::manifest::{DirEntry, EntryKind, Name};

    let mut fixture = Fixture::at_width(0);
    let old_manifest = frame(&encode_dir_leaf(&[]).expect("dir"));
    let new_manifest = frame(
        &encode_dir_leaf(&[DirEntry {
            name: Name::new(b"directory".to_vec()).expect("name"),
            kind: EntryKind::Dir {
                child: old_manifest.id,
            },
        }])
        .expect("dir"),
    );
    let (digest, rows) = fixture.store.bin(&[old_manifest, new_manifest.clone()], 0);
    let table = fixture
        .store
        .meta(encode_bin_table(&[digest]).expect("table"));
    let (binmap, _) = make_map(&mut fixture.store, table, &rows, 0);
    fixture.candidate = candidate(&mut fixture.store, None, fixture.candidate.manifest, binmap);
    let proof = fixture.baseline().await;
    let child = candidate(
        &mut fixture.store,
        Some(&fixture.candidate),
        new_manifest.id,
        binmap,
    );
    validate(
        &fixture.store,
        &child,
        Some(&proof),
        ValidationLimits::default(),
    )
    .await
    .expect("new manifest root in old bin");
    assert_eq!(
        fixture
            .store
            .take_calls()
            .into_iter()
            .map(|(key, _)| key)
            .collect::<Vec<_>>(),
        [
            Key::Meta(child.sheaf),
            Key::Range(digest, rows[1].offset, rows[1].comp_len),
            Key::Range(digest, rows[0].offset, rows[0].comp_len),
        ]
    );
}

#[tokio::test]
async fn manifest_walk_checks_nested_shape_and_old_file_edges() {
    use granary_core::manifest::{
        DirEntry, EntryKind, FileGrains, GrainRef, InteriorChild, Name, encode_dir_interior,
        encode_grain_list_leaf,
    };
    let name = |bytes: &[u8]| Name::new(bytes.to_vec()).unwrap();
    let mut fx = Fixture::at_width(0);
    let proof = fx.baseline().await;
    let data = GrainId::of(b"content carried across publishes");
    let actual = u32::try_from(b"content carried across publishes".len()).unwrap();
    let (left, right) = (b"a".as_slice(), b"b".as_slice());
    let leaf = |n| {
        frame(
            &encode_dir_leaf(&[DirEntry {
                name: name(n),
                kind: EntryKind::Fifo,
            }])
            .unwrap(),
        )
    };
    let (a, b) = (leaf(left), leaf(right));
    let interior = frame(
        &encode_dir_interior(&[
            InteriorChild {
                first_key: name(left),
                child: a.id,
                subtree_entry_count: 1,
            },
            InteriorChild {
                first_key: name(right),
                child: b.id,
                subtree_entry_count: 1,
            },
        ])
        .unwrap(),
    );
    let nest = |child| {
        frame(
            &encode_dir_leaf(&[DirEntry {
                name: name(b"nested"),
                kind: EntryKind::Dir { child },
            }])
            .unwrap(),
        )
    };
    let noncanonical = nest(interior.id);
    let make_spill = |len, size_adjustment| {
        let refs = vec![
            GrainRef {
                id: data,
                unpacked_len: len
            };
            129
        ];
        let spill = frame(&encode_grain_list_leaf(&refs).unwrap());
        let dir = frame(
            &encode_dir_leaf(&[DirEntry {
                name: name(b"file"),
                kind: EntryKind::File {
                    exec: false,
                    size: u64::from(len) * 129 + size_adjustment,
                    grains: FileGrains::Spill {
                        root: spill.id,
                        grain_count: 129,
                    },
                },
            }])
            .unwrap(),
        );
        (dir, spill)
    };
    let (wrong_edge, bad_spill) = make_spill(actual + 1, 0);
    let (wrong_total, good_spill) = make_spill(actual, 1);
    let (canonical, canonical_spill) = make_spill(actual, 0);

    for (nodes, valid) in [
        (vec![noncanonical, interior, a, b], false),
        (vec![wrong_edge, bad_spill], false),
        (vec![wrong_total, good_spill], false),
        (vec![canonical, canonical_spill], true),
    ] {
        let tree = nodes[0].id;
        let (digest, added) = fx.store.bin(&nodes, 1);
        let table = fx
            .store
            .meta(encode_bin_table(&[fx.digest, digest]).unwrap());
        let rows = [fx.rows.clone(), added].concat();
        let (map, _) = make_map(&mut fx.store, table, &rows, 0);
        let candidate = candidate(&mut fx.store, Some(&fx.candidate), tree, map);
        let result = validate(
            &fx.store,
            &candidate,
            Some(&proof),
            ValidationLimits::default(),
        )
        .await;
        if valid {
            result.unwrap();
        } else {
            assert_eq!(result.unwrap_err(), InvalidReference);
        }
    }
}

#[tokio::test]
async fn unchanged_manifest_skips_only_after_map_preservation() {
    let mut fx = Fixture::at_width(0);
    let proof = fx.baseline().await;
    let same = fx.successor(fx.table, &fx.rows.clone(), 0);
    validate(
        &fx.store,
        &same,
        Some(&proof),
        ValidationLimits {
            reads: 1,
            ..ValidationLimits::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(fx.store.take_calls().len(), 1);

    let changed = fx.successor(fx.table, &[fx.rows[0]], 0);
    assert_eq!(changed.manifest, same.manifest);
    assert_eq!(
        validate(
            &fx.store,
            &changed,
            Some(&proof),
            ValidationLimits::default()
        )
        .await
        .unwrap_err(),
        InvalidReference
    );
}

#[tokio::test]
async fn elapsed_intake_slice_restores_the_allowance_before_the_next_action() {
    use std::sync::Arc;
    let limits = ValidationLimits {
        reads: 3,
        ..ValidationLimits::default()
    };
    let clock = Arc::new(TestClock::default());
    let mut attempt = PublicationValidator::new(limits, 2)
        .begin_intake(clock.clone())
        .await
        .unwrap();
    attempt.list_page().unwrap();
    clock.0.store(30, Ordering::Relaxed);
    // One charged read leaves enough for this action even without rotation.
    attempt.prepare_page(0).await.unwrap();
    for _ in 0..3 {
        attempt.list_page().unwrap();
    }
}
