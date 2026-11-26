// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A head another writer published, adopted as the mount's view: the
//! production hook's checks before the private floor moves, its refusals
//! and closes, the install itself, and a restart after a cut at each step.

use super::*;
use crate::sync::Adopted;
use crate::writable_store::sync_engine::AdoptionHold;

/// A file the remote head adds three directories deep.
const REMOTE_DEEP: &[u8] = b"a file the remote head adds three directories deep\n";

/// What an adoption ended with, as text.
fn outcome(result: &Result<Adopted, crate::CoordinationError>) -> String {
    format!("{result:?}")
}

/// What a refused or deferred adoption must leave as it found it: the pin,
/// the mediator's base, the journal's bytes, the private floor and the
/// cached root at the head's seq.
type Untouched = (
    Option<Base>,
    Option<Base>,
    Vec<u8>,
    Option<u64>,
    Option<Vec<u8>>,
);

impl BoundMount {
    fn adopt(&self, seq: u64) -> Result<Adopted, crate::CoordinationError> {
        self.runtime.block_on(self.engine.adopt_head(seq))
    }
    pub(super) fn mediator(&self) -> crate::SharedWritableStore<OverlayDisk> {
        self.with_mount(|mount| mount.shared_mediator().clone())
            .expect("the adapter state is present")
    }
    fn pin(&self) -> Option<Base> {
        self.with_mount(|mount| mount.pinned_base_for_test())
    }
    fn base(&self) -> Option<Base> {
        self.mediator().with(|local| local.mount_base()).ok()
    }
    fn journal(&self) -> Vec<u8> {
        std::fs::read(overlay_area(&self.paths, &input(&self.tree, &self.paths)).join("journal"))
            .unwrap()
    }
    fn floor(&self) -> Option<u64> {
        let anchor = self
            .paths
            .cache
            .join("anchors")
            .join(format!("{}.mount", self.tree.volume.as_str()));
        let text = std::fs::read_to_string(anchor).ok()?;
        text.strip_prefix("seq ")?.trim_end().parse().ok()
    }
    fn cached_root(&self, seq: u64) -> Option<Vec<u8>> {
        std::fs::read(
            self.paths
                .cache
                .join("roots")
                .join(self.tree.volume.as_str())
                .join(format!("{seq:020}")),
        )
        .ok()
    }
    fn untouched(&self, seq: u64) -> Untouched {
        (
            self.pin(),
            self.base(),
            self.journal(),
            self.floor(),
            self.cached_root(seq),
        )
    }
    /// Open `path`, write `bytes` at its start, and close it unless `keep`;
    /// the object, when kept.
    pub(super) fn write_path(&self, path: &[u8], bytes: &'static [u8], keep: bool) -> Option<u64> {
        use granary_fuse::{MountBackend as _, OverlayMutation as M};
        self.with_mount(|mount| {
            let object = mount.overlay_open(&path_names(path)).unwrap().unwrap();
            mount.prepare_object(object).unwrap();
            mount
                .overlay_mutate(M::BoundWrite {
                    object,
                    offset: 0,
                    bytes,
                    append: false,
                })
                .unwrap();
            if keep {
                return Some(object);
            }
            mount.overlay_close(object).unwrap();
            None
        })
        .flatten()
    }
    fn release(&self, object: u64) {
        use granary_fuse::MountBackend as _;
        self.with_mount(|mount| mount.overlay_close(object).unwrap());
    }
    fn read(&self, path: &[u8]) -> Option<Result<Vec<u8>, granary_fuse::WriteError>> {
        use granary_fuse::MountBackend as _;
        self.with_mount(|mount| {
            let object = mount
                .overlay_open(&path_names(path))?
                .ok_or(granary_fuse::WriteError::Missing)?;
            let read = mount
                .prepare_object(object)
                .and_then(|()| mount.read_object(object, 0, 65_536));
            mount.overlay_close(object)?;
            read
        })
    }
    pub(super) fn sends(&self) -> Vec<bool> {
        self.gate.sends.lock().unwrap().clone()
    }
}

/// Each precondition alone, with the others met, against a head H that
/// adds one file: a closed view closes, a write-capable descriptor and each
/// piece of local or in-flight work defers, a head not above the pin, below
/// the shared floor or past what a journal header can carry is refused, and
/// with nothing held the head installs. Every case but the control leaves
/// the pin, the mediator's base, the journal, the private floor and the
/// cached root at the head's seq as they were: each check precedes the
/// session's first write. Case count 15.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table of the fifteen preconditions over the same fixture"
)]
fn adoption_checks_every_precondition_before_the_floor_moves() {
    let installed = outcome(&Ok(Adopted::Installed));
    let deferred = outcome(&Ok(Adopted::Deferred));
    let refused = outcome(&Ok(Adopted::Refused {
        cause: crate::sync::refused("ViewHeadRefused"),
    }));
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for case in [
        "closed view",
        "write-capable descriptor",
        "no write-capable descriptor (control)",
        "dirty overlay",
        "commit construction",
        "projected sync",
        "retained sync",
        "mediator commit lane",
        "capture owing completion",
        "object lease",
        "stage handle",
        "retained registration",
        "head not above the pin",
        "head below the shared floor",
        "head at the counter maximum",
    ] {
        let fixture = BoundMount::new();
        disjoint_head(&fixture.tree, &fixture.runtime);
        let head = fixture.tree.seq + 1;
        let mut target = head;
        let mut kept = None;
        match case {
            "closed view" => {
                fixture.with_mount(Mount::close_view_for_test);
            }
            "write-capable descriptor" => *fixture.gate.writers.lock().unwrap() = Some(true),
            "dirty overlay" => {
                fixture.write_path(b"f.txt", b"local", false);
            }
            "commit construction" => fixture
                .engine
                .hold_adoption_for_test(crate::sync::EngineHold::Construction),
            "projected sync" => fixture
                .engine
                .hold_adoption_for_test(crate::sync::EngineHold::ProjectedSync),
            "retained sync" => fixture
                .engine
                .hold_adoption_for_test(crate::sync::EngineHold::RetainedSync),
            "mediator commit lane" | "capture owing completion" | "retained registration" => {
                let hold = match case {
                    "mediator commit lane" => AdoptionHold::CommitLane,
                    "capture owing completion" => AdoptionHold::CaptureQueue,
                    _ => AdoptionHold::Registration,
                };
                fixture
                    .mediator()
                    .with(|store| {
                        store.hold_adoption_for_test(hold);
                        Ok(())
                    })
                    .unwrap();
            }
            "object lease" => fixture
                .mediator()
                .with(|store| {
                    store.object_leases.insert(u64::MAX, (1, None));
                    Ok(())
                })
                .unwrap(),
            "stage handle" => kept = fixture.write_path(b"f.txt", b"local", true),
            "head not above the pin" => target = fixture.tree.seq,
            "head below the shared floor" => {
                let anchor = fixture
                    .paths
                    .cache
                    .join("anchors")
                    .join(fixture.tree.volume.as_str());
                std::fs::write(anchor, format!("seq {:020}\n", head + 1)).unwrap();
            }
            "head at the counter maximum" => {
                let (base_id, mut doc) =
                    root_doc(&fixture.tree, &fixture.runtime, fixture.tree.seq);
                doc.seq = u64::MAX - 1;
                doc.parent = Some(base_id);
                target = sign_and_put(&fixture.tree, &fixture.runtime, doc);
            }
            _ => {}
        }
        let before = fixture.untouched(target);
        let result = fixture.adopt(target);
        let after = fixture.untouched(target);
        let control = case.ends_with("(control)");
        let want = match case {
            "closed view" => outcome(&Ok(Adopted::Closed)),
            _ if control => installed.clone(),
            "head not above the pin"
            | "head below the shared floor"
            | "head at the counter maximum" => refused.clone(),
            _ => deferred.clone(),
        };
        observed.push((case, outcome(&result), control || after == before));
        expected.push((case, want, true));
        if control {
            assert_eq!(
                (fixture.pin().map(|pin| pin.1), fixture.floor()),
                (Some(head), Some(head)),
                "control: the pin and the private floor move to the head"
            );
        }
        if let Some(object) = kept {
            fixture.release(object);
        }
    }
    assert_eq!(observed, expected, "(case, outcome, nothing moved)");
    assert_eq!(observed.len(), 15);
}

/// A head whose time the kernel cannot hold is refused, and the view stays
/// open on its pin: the pin is still verified and served, so nothing closes
/// and nothing is revoked.
#[test]
fn adoption_refuses_a_root_whose_time_the_kernel_cannot_hold() {
    let fixture = BoundMount::bound(multi_thread(), |_| None);
    disjoint_head(&fixture.tree, &fixture.runtime);
    let (pin, floor) = (fixture.pin(), fixture.floor());
    let result = fixture.adopt(fixture.tree.seq + 1);
    // A revocation is sent on its own task once admission is released, which
    // is before the adoption returns: give a sent one time to land.
    std::thread::sleep(std::time::Duration::from_millis(100));
    let sent = !fixture.sends().is_empty();
    assert_eq!(
        (
            outcome(&result),
            fixture.view_pending(),
            fixture.pin() == pin,
            fixture.floor() == floor,
            sent,
        ),
        (
            outcome(&Ok(Adopted::Refused {
                cause: crate::sync::refused("ViewTimeUnrepresentable")
            })),
            Some(false),
            true,
            true,
            false,
        ),
        "(outcome, view pending, pin unchanged, floor unchanged, revoked)"
    );
}

/// A node read that fails at the transport, or that the store answers with
/// a refused range, is "no answer yet": nothing changed, no gate was
/// entered, and the same head installs when tried again. A head whose new
/// node's frame does not verify is refused before the gate. Case count 3.
#[test]
fn adoption_answers_err_for_a_failed_node_read_and_refused_for_a_bad_one() {
    let mut cases = 0;
    for case in ["transport", "refused range", "frame"] {
        let fixture = BoundMount::new();
        disjoint_head(&fixture.tree, &fixture.runtime);
        let head = fixture.tree.seq + 1;
        let before = fixture.untouched(head);
        {
            let mut state = fixture.state.lock().unwrap();
            match case {
                "transport" => state.next_range_fault = Some(RangeFault::Unavailable),
                "refused range" => state.next_range_fault = Some(RangeFault::Refused),
                _ => state.next_range_fault = Some(RangeFault::Corrupt),
            }
        }
        let result = fixture.adopt(head);
        let first = (
            outcome(&result),
            fixture.untouched(head) == before,
            fixture.gate.attempts.load(Ordering::SeqCst),
        );
        if case == "frame" {
            assert_eq!(
                first,
                (
                    outcome(&Ok(Adopted::Refused {
                        cause: crate::sync::refused("SyncBase")
                    })),
                    true,
                    0
                ),
                "{case}: (outcome, nothing changed, gate attempts)"
            );
        } else {
            let kept = if case == "transport" {
                crate::OverlayError::ContentUnavailable.into()
            } else {
                crate::sync::binmap_error(crate::PublishError::Remote(
                    RootStoreError::RefusedResponse {
                        reason: "a range answer of another extent".to_owned(),
                        kind: granary_core::rootstore::RefusalKind::Extent,
                    },
                ))
            };
            assert_eq!(
                first,
                (outcome(&Err(kept)), true, 0),
                "{case}: (outcome, nothing changed, gate attempts)"
            );
            let again = fixture.adopt(head);
            assert_eq!(
                (outcome(&again), fixture.pin().map(|pin| pin.1)),
                (outcome(&Ok(Adopted::Installed)), Some(head)),
                "{case}: the same head installs when tried again"
            );
        }
        cases += 1;
    }
    assert_eq!(cases, 3);
}

/// A store that refuses the check under the gate serves nothing more, so
/// the adoption closes the view and revokes it, once admission is released.
/// The private floor never moved.
#[test]
fn adoption_closes_on_a_store_that_refuses_its_check() {
    let fixture = BoundMount::new();
    disjoint_head(&fixture.tree, &fixture.runtime);
    fixture.write_path(b"f.txt", b"local", false);
    let mediator = fixture.mediator();
    let crate::overlay_store::OverlayQuery::Found(found) = mediator
        .overlay_transaction(|overlay| overlay.query_path(&handler_path(b"f.txt")))
        .unwrap()
    else {
        panic!("premise: f.txt is in the view")
    };
    let stage = found.entry.and_then(|entry| entry.stage_id).unwrap();
    let floor = fixture.floor();
    let faults = fixture.faults.clone();
    *fixture.gate.before_attempt.lock().unwrap() = Some(Box::new(move || {
        faults.arm(
            "overlay.stage.truncate",
            "before",
            1,
            crate::FaultAction::Fail,
        );
        let shrink = mediator.overlay_transaction(|overlay| overlay.truncate(stage, 2));
        assert!(shrink.is_err(), "premise: the shrink poisons the store");
    }));
    let result = fixture.adopt(fixture.tree.seq + 1);
    let sent = eventually(|| fixture.sends().len() == 1);
    assert_eq!(
        (
            outcome(&result),
            fixture.view_pending(),
            sent,
            fixture.sends(),
            fixture.floor() == floor,
        ),
        (
            outcome(&Ok(Adopted::Closed)),
            Some(true),
            true,
            vec![true],
            true
        ),
        "(outcome, view pending, revoked, admission free at each send, floor unchanged)"
    );
}

/// A head the mount cannot verify or serve is refused, and the mount keeps
/// serving its pin: the corrupt head omits a node from its binmap, the
/// unservable ones hold a symlink target the mount cannot return, landed by
/// a second writer, or a FIFO. None closes the view. Case count 3.
#[test]
fn adoption_refuses_a_head_it_cannot_verify_or_serve_and_keeps_serving() {
    let mut observed = Vec::new();
    for case in ["corrupt", "unservable", "fifo"] {
        let fixture = BoundMount::new();
        let head = match case {
            "corrupt" => {
                let (_, doc) = root_doc(&fixture.tree, &fixture.runtime, fixture.tree.seq);
                publish_without(
                    &fixture.tree,
                    &fixture.runtime,
                    fixture.tree.seq,
                    doc.manifest_root,
                )
            }
            "unservable" => land_long_link(&fixture.tree),
            _ => publish_with_fifo(&fixture.tree, &fixture.runtime, fixture.tree.seq),
        };
        let (pin, floor) = (fixture.pin(), fixture.floor());
        let result = fixture.adopt(head);
        observed.push((
            case,
            outcome(&result),
            fixture.view_pending(),
            fixture.pin() == pin && fixture.floor() == floor,
            fixture.read(b"sub/g.txt"),
        ));
    }
    let reason = |reason| {
        outcome(&Ok(Adopted::Refused {
            cause: crate::sync::refused(reason),
        }))
    };
    assert_eq!(
        observed,
        vec![
            (
                "corrupt",
                reason("SyncBase"),
                Some(false),
                true,
                Some(Ok(FILE_CONTENT.to_vec()))
            ),
            (
                "unservable",
                reason("ViewUnservable"),
                Some(false),
                true,
                Some(Ok(FILE_CONTENT.to_vec()))
            ),
            (
                "fifo",
                reason("ViewUnservable"),
                Some(false),
                true,
                Some(Ok(FILE_CONTENT.to_vec()))
            ),
        ],
        "(case, outcome, view pending, pin and floor unchanged, a clean read served)"
    );
}

/// Publish, at the seq after `seq`, the root at `seq` with a FIFO added to
/// its root directory: a leaf new to every view, framed in a bin of its own
/// that the head's binmap maps. Its seq.
fn publish_with_fifo(tree: &PublishedTree, runtime: &tokio::runtime::Runtime, seq: u64) -> u64 {
    use granary_core::{binfmt, binmap, encoding};
    let remote = remote_handle(&tree.mem);
    let volume = tree.volume.as_str();
    let (parent, mut doc) = root_doc(tree, runtime, seq);
    let nodes = structure_nodes(tree, runtime, seq);
    let (kind, cursor) = encoding::open_envelope(&nodes[&doc.manifest_root]).unwrap();
    assert_eq!(
        kind,
        encoding::ObjectType::DirLeaf,
        "premise: the root is one leaf"
    );
    let mut entries = manifest::decode_dir_leaf(cursor).unwrap();
    entries.push(DirEntry {
        name: granary_core::manifest::Name::new(b"fifo".to_vec()).unwrap(),
        kind: EntryKind::Fifo,
    });
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let leaf = manifest::encode_dir_leaf(&entries).unwrap();
    let id = GrainId::of(&leaf);
    let frame = granary_store::codec::GrainCodec::new()
        .unwrap()
        .compress_grain(&leaf)
        .unwrap();
    let bin = binfmt::encode_bin(&[binfmt::PackedFrame { id, frame }]).unwrap();
    let located = binfmt::decode_bin(&bin).unwrap()[0];
    let digest = *GrainId::of(&bin).digest();
    runtime.block_on(async {
        remote.put_bin(&digest, bin).await.unwrap();
        let index =
            binmap::decode_binmap_index(&remote.get_meta(volume, &doc.binmap_index).await.unwrap())
                .unwrap();
        let mut bins =
            binmap::decode_bin_table(&remote.get_meta(volume, &index.bin_table).await.unwrap())
                .unwrap();
        let ordinal = u32::try_from(bins.len()).unwrap();
        bins.push(digest);
        let table = binmap::encode_bin_table(&bins).unwrap();
        let table_id = GrainId::of(&table);
        remote.put_meta(volume, &table_id, table).await.unwrap();
        let mut shards = index.shards.clone();
        let at = binmap::shard_for(&id, index.prefix_bits);
        let mut shard =
            binmap::decode_shard(&remote.get_meta(volume, &shards[at]).await.unwrap()).unwrap();
        shard.push(binmap::ShardEntry {
            id,
            bin_ordinal: ordinal,
            offset: located.offset,
            comp_len: located.comp_len,
        });
        shard.sort_by_key(|entry| entry.id);
        let bytes = binmap::encode_shard(&shard).unwrap();
        shards[at] = GrainId::of(&bytes);
        remote.put_meta(volume, &shards[at], bytes).await.unwrap();
        let index_bytes =
            binmap::encode_binmap_index(index.prefix_bits, table_id, &shards).unwrap();
        doc.binmap_index = GrainId::of(&index_bytes);
        remote
            .put_meta(volume, &doc.binmap_index, index_bytes)
            .await
            .unwrap();
    });
    doc.manifest_root = id;
    doc.parent = Some(parent);
    doc.seq = seq + 1;
    sign_and_put(tree, runtime, doc)
}

/// The published tree, as a second writer reaches it: the same store,
/// volume and key.
fn second_writer(tree: &PublishedTree) -> PublishedTree {
    PublishedTree {
        seq: tree.seq,
        seed: tree.seed,
        remote: remote_handle(&tree.mem),
        mem: Arc::clone(&tree.mem),
        key: SigningKey::from_seed(&tree.seed).unwrap(),
        volume: tree.volume.clone(),
        file_id: tree.file_id,
        manifest_root: tree.manifest_root,
        binmap_index: tree.binmap_index,
        sheaf_head: tree.sheaf_head,
    }
}

/// Land, from a second writer's mount, a head holding a symlink whose
/// 4096-byte target no mount can return; its seq.
fn land_long_link(tree: &PublishedTree) -> u64 {
    use granary_core::overlay_journal::{CreateKind, Location, Parent, Record};
    let mut writer = EngineMount::with_tree(Paths::new(), second_writer(tree));
    writer
        .ready
        .backend_for_test()
        .shared_mediator()
        .overlay_transaction(|overlay| {
            overlay.namespace_record(Record::Create {
                at: Location {
                    name: granary_core::manifest::Name::new(b"long-link".to_vec()).unwrap(),
                    parent: Parent::new(vec![]).unwrap(),
                },
                kind: CreateKind::Symlink {
                    target: granary_core::manifest::SymlinkTarget::new(vec![b't'; 4096]).unwrap(),
                },
            })
        })
        .unwrap();
    let lane = writer.construct(90).unwrap();
    let result = writer.drive(&lane, 91);
    assert!(landed(&result), "premise: the second writer's head lands");
    remote_seq(&writer.tree, &writer.runtime)
}

/// An equivocating cached root at the head's seq closes the view, and the
/// revocation is sent once admission is released.
#[test]
fn adoption_closes_and_revokes_on_equivocation() {
    let fixture = BoundMount::new();
    disjoint_head(&fixture.tree, &fixture.runtime);
    let head = fixture.tree.seq + 1;
    fixture.plant_equivocation(head);
    let result = fixture.adopt(head);
    let sent = eventually(|| fixture.sends().len() == 1);
    assert_eq!(
        (
            outcome(&result),
            fixture.view_pending(),
            sent,
            fixture.sends()
        ),
        (outcome(&Ok(Adopted::Closed)), Some(true), true, vec![true]),
        "(outcome, view pending, revoked, admission free at each send)"
    );
}

/// The landed bytes of `f.txt`, a head over them that rewrites `sub/g.txt`
/// at the same size, adds a file three directories deep and removes
/// `original-link`, published by another writer; its seq.
fn remote_head(fixture: &HookedMount, landed_file: &[u8]) -> u64 {
    publish_source(&fixture.tree, &fixture.runtime, |source| {
        write_operation_source(source, landed_file);
        std::fs::write(source.join("sub/g.txt"), rewritten()).unwrap();
        std::fs::create_dir_all(source.join("a/b/c")).unwrap();
        std::fs::write(source.join("a/b/c/deep.txt"), REMOTE_DEEP).unwrap();
        std::fs::remove_file(source.join("original-link")).unwrap();
    })
}

/// The journal's header and scanned state.
fn journal_scan(fixture: &HookedMount) -> granary_core::overlay_journal::JournalScan {
    let bytes = std::fs::read(
        overlay_area(&fixture.paths, &input(&fixture.tree, &fixture.paths)).join("journal"),
    )
    .unwrap();
    granary_core::overlay_journal::scan_journal(&bytes).unwrap()
}

/// A clean mount adopts the head another writer published over its own
/// landing: the pin, the mediator's base, the engine's base and the private
/// floor move to the head, the journal is the head's header with no record
/// and the old counters, the view change names the head's paths, and the
/// view serves. A local write's fsync then registers a prepared root whose
/// parent is the head.
#[test]
fn adoption_installs_a_clean_mount_on_the_remote_head() {
    let fixture = HookedMount::new();
    let object = fixture.dirty();
    fixture.close(object);
    let lane = fixture.construct(70).unwrap();
    assert!(
        landed(&fixture.drive(&lane, 80)),
        "premise: the mount's own commit lands"
    );
    let before = journal_scan(&fixture);
    let records = captured_records(&fixture.paths, &input(&fixture.tree, &fixture.paths)).1;
    assert!(
        before.state.next_stage_id() > 1
            && before.state.highest_generation() > 0
            && records.len() == 1,
        "premise: the landing left counters past their start and one record: {records:?}"
    );
    let landed_file = fixture.read_path(b"f.txt").unwrap();
    let head = remote_head(&fixture, &landed_file);
    let head_bytes = fixture.store_root(head);
    let head_id = GrainId::of(&head_bytes);
    let result = fixture.runtime.block_on(fixture.engine.adopt_head(head));
    let after = journal_scan(&fixture);
    let records = captured_records(&fixture.paths, &input(&fixture.tree, &fixture.paths)).1;
    let paths: Vec<_> = fixture
        .changes()
        .last()
        .map(|change| {
            change
                .paths
                .iter()
                .map(|path| (names(&path.path), path.old.is_some(), path.new.is_some()))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        (
            outcome(&result),
            fixture.pin(),
            fixture.pin_bytes() == head_bytes,
            fixture.base().ok(),
            fixture.floor(),
            (after.header.base_root, after.header.base_seq),
            records.len(),
            (
                after.state.next_stage_id(),
                after.state.highest_generation()
            ) == (
                before.state.next_stage_id(),
                before.state.highest_generation()
            ),
            paths,
            fixture.mount().observe_engine_view().is_ok(),
        ),
        (
            outcome(&Ok(Adopted::Installed)),
            (head_id, head),
            true,
            Some((head_id, head)),
            Some(head),
            (head_id, head),
            0,
            true,
            vec![
                ("a".to_owned(), false, true),
                ("a/b".to_owned(), false, true),
                ("a/b/c".to_owned(), false, true),
                ("a/b/c/deep.txt".to_owned(), false, true),
                ("original-link".to_owned(), true, false),
                ("sub/g.txt".to_owned(), true, true),
            ],
            true,
        ),
        "(outcome, pin, pin bytes, mediator base, floor, journal base, records, \
         counters kept, view change, view served)"
    );
    let object = fixture.dirty();
    fixture.close(object);
    let synced = sync_tree(&fixture.engine, &fixture.runtime).map_err(|error| error.to_string());
    let registered = fixture.state.lock().unwrap().root.clone();
    let parent = root::decode_root(&registered)
        .ok()
        .and_then(|doc| doc.parent);
    assert_eq!(
        (synced, parent, fixture.read_path(b"a/b/c/deep.txt")),
        (Ok(()), Some(head_id), Ok(REMOTE_DEEP.to_vec())),
        "(the fsync, the registered root's parent: the engine's base, the head's file read)"
    );
}

/// What a restart after a cut found, as the start reports it.
fn started(
    result: &Result<crate::WritableReadiness<Authority, OverlayDisk>, WritableStartError>,
) -> &'static str {
    result
        .as_ref()
        .map_or_else(WritableStartError::name, |_| "Ok")
}

/// A restart after an adoption cut at each of its steps starts on the head
/// it discovers, H or a later H2: a refusal before the floor moved, a cut
/// after the floor moved and before the switch, a replacement cut at its
/// build, and one cut after its rename. Each starts with the journal, the
/// mediator's base, the pin and the private floor on that head, its journal
/// rewritten. A journal on H that later took a record of the mount's own
/// work is finished on H, its commit landing above the head discovered, H
/// or H2, which the start then serves with the journal, the mediator's
/// base, the pin and the floor on it. Every
/// cut is made on the store, in the order an adoption makes them: the
/// floor, then the journal. Case count 10.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table of the five cuts, each restarted on two heads"
)]
fn adoption_crash_points_restart_on_the_discovered_head() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    for cut in ["refused", "floor", "build", "rename", "own work"] {
        for later in [false, true] {
            let tree = mounted_operation_tree();
            let paths = Paths::new();
            let input = input(&tree, &paths);
            let (ready, state, _) = attempt(&input, &tree, "valid", &Events::default());
            let mut ready = ready.unwrap();
            disjoint_head(&tree, &runtime);
            let head = tree.seq + 1;
            let (head_id, _) = root_doc(&tree, &runtime, head);
            if cut != "refused" {
                let anchor = paths
                    .cache
                    .join("anchors")
                    .join(format!("{}.mount", tree.volume.as_str()));
                std::fs::write(anchor, format!("seq {head:020}\n")).unwrap();
            }
            if matches!(cut, "build" | "rename" | "own work") {
                let deadline =
                    crate::SyncRuntime::now(&FastWaitRuntime) + std::time::Duration::from_mins(1);
                let content = ready
                    .backend_for_test()
                    .sync_content(Arc::new(Authority::new(&tree, &state)))
                    .unwrap()
                    .with_deadline(Arc::new(FastWaitRuntime), deadline);
                let mediator = ready.backend_for_test().shared_mediator().clone();
                let published = runtime
                    .block_on(crate::sync::PublishedRoot::read(
                        &tree.remote,
                        &tree.volume,
                        head,
                        None,
                        &trusted(&tree),
                    ))
                    .unwrap();
                let (_, _, entries, _) = runtime
                    .block_on(crate::writable_start::adoption_verdict(
                        &published, &content,
                    ))
                    .unwrap()
                    .unwrap();
                let faults = mediator.with(|store| Ok(store.fault_control())).unwrap();
                match cut {
                    "build" => {
                        faults.arm(
                            "overlay.replace.build",
                            "partial",
                            1,
                            crate::FaultAction::Fail,
                        );
                    }
                    "rename" => {
                        faults.arm(
                            "overlay.replace.rename",
                            "after",
                            1,
                            crate::FaultAction::Fail,
                        );
                    }
                    _ => {}
                }
                let replaced = mediator.with(|store| store.replace_adopted(head_id, head, entries));
                assert_eq!(
                    replaced.is_ok(),
                    cut == "own work",
                    "{cut}: premise, the replacement is cut where armed: {replaced:?}"
                );
                if cut == "own work" {
                    use granary_core::overlay_journal::{Location, Parent, Record};
                    let at = |name: &[u8]| Location {
                        parent: Parent::root(),
                        name: granary_core::manifest::Name::new(name.to_vec()).unwrap(),
                    };
                    mediator
                        .overlay_transaction(|overlay| {
                            overlay.namespace_record(Record::Move {
                                from: at(b"f.txt"),
                                to: at(b"moved.txt"),
                            })
                        })
                        .unwrap();
                }
            }
            let floor_before = std::fs::read_to_string(
                paths
                    .cache
                    .join("anchors")
                    .join(format!("{}.mount", tree.volume.as_str())),
            )
            .ok()
            .and_then(|text| text.strip_prefix("seq ")?.trim_end().parse::<u64>().ok());
            assert_eq!(
                floor_before,
                Some(if cut == "refused" { tree.seq } else { head }),
                "{cut}: premise, the private floor the cut left"
            );
            drop(ready);
            let discovered = if later {
                publish_source(&tree, &runtime, |source| {
                    write_operation_source(source, FILE_CONTENT);
                    std::fs::write(source.join("later.txt"), b"a later head\n").unwrap();
                })
            } else {
                head
            };
            let (discovered_id, _) = root_doc(&tree, &runtime, discovered);
            let journal = overlay_area(&paths, &input).join("journal");
            let before = std::fs::read(&journal).unwrap();
            // A journal holding the mount's own work is finished first,
            // through an authority that takes its commit.
            let mut result = if cut == "own work" {
                restart_publishing(&input, &tree, &state)
            } else {
                restart(&input, &tree, &state)
            };
            let after = std::fs::read(&journal).unwrap();
            let header = granary_core::overlay_journal::scan_journal(&after)
                .unwrap()
                .header;
            let floor = std::fs::read_to_string(
                paths
                    .cache
                    .join("anchors")
                    .join(format!("{}.mount", tree.volume.as_str())),
            )
            .ok()
            .and_then(|text| text.strip_prefix("seq ")?.trim_end().parse::<u64>().ok());
            let bases = result.as_mut().ok().map(|ready| {
                let base = ready.mediator_for_test().mount_base().ok();
                (base, ready.verified_base().1)
            });
            observed.push((
                cut,
                later,
                started(&result),
                (header.base_root, header.base_seq),
                bases,
                floor,
                after == before,
            ));
            let on = (discovered_id, discovered);
            expected.push(match cut {
                // Finished on H: its commit lands above the head it
                // discovers, which the start then serves.
                "own work" => {
                    let landed = remote_seq(&tree, &runtime);
                    let landed = (root_doc(&tree, &runtime, landed).0, landed);
                    (
                        cut,
                        later,
                        "Ok",
                        landed,
                        Some((Some(landed), landed.1)),
                        Some(landed.1),
                        false,
                    )
                }
                _ => (
                    cut,
                    later,
                    "Ok",
                    on,
                    Some((Some(on), discovered)),
                    Some(discovered),
                    false,
                ),
            });
        }
    }
    assert_eq!(
        observed, expected,
        "(cut, a later head, start, journal base, (mediator base, pin seq), private floor, \
         journal bytes kept)"
    );
    assert_eq!(observed.len(), 10);
}

/// A head the pin has already passed is refused before its root is read or
/// its tree walked: a second head is adopted, then the first, whose new
/// node no view holds, is refused with no node read and no gate entered.
#[test]
fn a_stale_head_refuses_before_its_tree_is_walked() {
    let fixture = BoundMount::new();
    disjoint_head(&fixture.tree, &fixture.runtime);
    let first = fixture.tree.seq + 1;
    let second = publish_source(&fixture.tree, &fixture.runtime, |source| {
        write_operation_source(source, FILE_CONTENT);
        std::fs::write(source.join("later.txt"), b"a later head\n").unwrap();
    });
    assert_eq!(
        outcome(&fixture.adopt(second)),
        outcome(&Ok(Adopted::Installed)),
        "premise: the later head installs"
    );
    let reads = || {
        (
            fixture.state.lock().unwrap().ranges.len(),
            fixture.gate.attempts.load(Ordering::SeqCst),
        )
    };
    let before = reads();
    let result = fixture.adopt(first);
    let after = reads();
    assert_eq!(
        (
            outcome(&result),
            after.0 - before.0,
            after.1 - before.1,
            fixture.pin().map(|pin| pin.1)
        ),
        (
            outcome(&Ok(Adopted::Refused {
                cause: crate::sync::refused("ViewHeadRefused")
            })),
            0,
            0,
            Some(second)
        ),
        "(outcome, node reads, gate attempts, pin seq)"
    );
}
