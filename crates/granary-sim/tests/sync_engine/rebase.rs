// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_client::{OverlayEntry, OverlayKind, PublicationOutcome, RecoveryIntent};
use granary_core::{
    grainsource::GrainSource,
    manifest::{self, EntryKind, FileGrains},
};
use granary_sim::secure_random::SeededSecureRandom;
use support::{Delay, PublishPlan, at, foreign_head};

#[test]
#[expect(
    clippy::redundant_closure_for_method_calls,
    reason = "the transaction facade requires a higher-ranked lifetime; a method pointer does not compile"
)]
fn stage_appended_before_and_after_rebased_replace_landed_replays_against_landed_base() {
    for seed in [1, 42, 43] {
        let fixture = Fixture::new();
        let stage = fixture.create("local", b"sealed");
        let (done, _) = fixture.runtime.run(seed, 100_000, async {
            let lane = fixture.engine.construct_commit(SyncOptions::default(),
                &mut SeededSecureRandom::for_incarnation(44, 0)).await.unwrap();
            foreign_head(&fixture).await;
            fixture.remote.publication_plan.lock().unwrap().extend([PublishPlan::StaleCurrent, PublishPlan::Land]);
            fixture.store.lock().unwrap().overlay_transaction(|t| t.write(stage, 0, b"suffix").map(|_| ())).unwrap();
            // A suffix creation occupies the next local inode before the remote
            // entry is installed, so allocating that entry early would collide.
            let suffix = fixture.create("suffix", b"carried");
            let before = fixture.store.lock().unwrap().overlay_transaction(|t| t.entries()).unwrap();
            let result = fixture.engine.drive_commit(&lane,
                &mut SeededSecureRandom::for_incarnation(45, 0), &mut Delay,
                RecoveryIntent::Continue, SyncOptions::default()).await.unwrap();
            let PublicationOutcome::Landed(done) = result.outcome else { panic!("clean disjoint rebase did not land: {result:?}"); };
            let installed = fixture.store.lock().unwrap().overlay_transaction(|t| t.entries()).unwrap();
            assert_eq!(installed.iter().map(|entry| entry.path.last().unwrap().as_bytes().to_vec()).collect::<Vec<_>>(),
                vec![b"local".to_vec(), b"remote".to_vec(), b"suffix".to_vec()],
                "seed {seed}: merged landing must retain the remote contribution and local suffix");
            let old = |name: &[u8]| before.iter().find(|e| e.path.last().unwrap().as_bytes() == name).unwrap().inode;
            let inode = |name: &[u8]| installed.iter().find(|e| e.path.last().unwrap().as_bytes() == name).unwrap().inode;
            assert_eq!((inode(b"local"), inode(b"suffix"), inode(b"remote") != inode(b"suffix")),
                (old(b"local"), old(b"suffix"), true), "seed {seed}: install identities");
            let doc = granary_core::root::decode_root(&done.root).unwrap();
            let bytes = fixture.content.get(&doc.manifest_root).unwrap();
            let (_, cursor) = granary_core::encoding::open_envelope(&bytes).unwrap();
            let base: Vec<_> = manifest::decode_dir_leaf(cursor).unwrap().into_iter().map(|entry| {
                let EntryKind::File { size, exec, grains } = entry.kind else { panic!("expected file"); };
                let content = GrainId::of(&manifest::node::file_payload(size, &grains).unwrap());
                OverlayEntry { path: vec![entry.name], inode: 0, kind: OverlayKind::File { content: Some(content) },
                    stage_id: None, size, exec }
            }).collect();
            // Append a copy-up after replacement, anchored to the new remote file.
            fixture.store.lock().unwrap().immutable_content().unwrap()
                .remember_payload(GrainId::of(&manifest::node::file_payload(0, &FileGrains::Inline(vec![])).unwrap()),
                    0, &FileGrains::Inline(vec![])).unwrap();
            let after = fixture.store.lock().unwrap().overlay_transaction(|t| {
                let id = t.copy_up(at("remote"))?;
                t.write(id, 0, b"after")?;
                let boundary = t.seal_sync(SyncTarget::Tree)?;
                t.flush_sync_boundary(&boundary)?;
                t.release_sync_boundary(&boundary)?;
                Ok(id)
            }).unwrap();
            fixture.replay_landed(&done.root, base);
            let replayed = fixture.store.lock().unwrap().overlay_transaction(|t| {
                Ok((t.read_stage(stage, 0, 6)?, t.read_stage(suffix, 0, 7)?, t.read_stage(after, 0, 5)?))
            }).unwrap();
            assert_eq!(replayed, (b"suffix".to_vec(), b"carried".to_vec(), b"after".to_vec()), "seed {seed}");
            done
        }).unwrap();
        assert_eq!(done.seq, 3, "seed {seed}: one clean rebase");
    }
}

#[test]
fn two_writers_disjoint_paths_rebase_and_land_across_seeds() {
    for seed in [1, 42, 43] {
        let fixture = Fixture::new();
        fixture.create("local", b"sealed");
        let (done, _) = fixture
            .runtime
            .run(seed, 100_000, async {
                let lane = fixture
                    .engine
                    .construct_commit(
                        SyncOptions::default(),
                        &mut SeededSecureRandom::for_incarnation(44, 0),
                    )
                    .await
                    .unwrap();
                foreign_head(&fixture).await;
                fixture
                    .remote
                    .publication_plan
                    .lock()
                    .unwrap()
                    .extend([PublishPlan::StaleCurrent, PublishPlan::Land]);
                let result = fixture
                    .engine
                    .drive_commit(
                        &lane,
                        &mut SeededSecureRandom::for_incarnation(45, 0),
                        &mut Delay,
                        RecoveryIntent::Continue,
                        SyncOptions::default(),
                    )
                    .await
                    .unwrap();
                let PublicationOutcome::Landed(done) = result.outcome else {
                    panic!("seed {seed}: disjoint rebase did not land: {result:?}");
                };
                done
            })
            .unwrap();
        let doc = granary_core::root::decode_root(&done.root).unwrap();
        let bytes = fixture.content.get(&doc.manifest_root).unwrap();
        let (_, cursor) = granary_core::encoding::open_envelope(&bytes).unwrap();
        let landed: Vec<_> = manifest::decode_dir_leaf(cursor)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name.as_bytes().to_vec())
            .collect();
        let retries = fixture
            .metrics()
            .lines()
            .find_map(|line| {
                line.strip_prefix("granary_client_commit_retries_total{reason=\"conflict\"} ")
            })
            .map(str::to_owned);
        assert_eq!(
            (landed, done.seq, retries.as_deref()),
            (vec![b"local".to_vec(), b"remote".to_vec()], 3, Some("1")),
            "seed {seed}: both writers' paths in one landing after exactly one conflict retry"
        );
        fixture.assert_file(&done.root, "local", b"sealed");
    }
}
