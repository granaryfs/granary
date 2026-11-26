// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The mount's sync profile, chosen at startup, selects what each sync job
//! the adapter starts waits for: its registration, or its own publication.

use super::*;
use granary_fuse::{MountBackend as _, MountSyncError, MountSyncRequest, OverlayMutation as M};

/// What a sync left behind: publications sent, the authority's head seq,
/// registrations sent and fsyncs recorded.
type Counts = (usize, u64, usize, u64);

impl BoundMount {
    fn counts(&self) -> Counts {
        let (ok, failed) = self.sync_outcomes();
        let state = self.state.lock().unwrap();
        (
            state.publications.len(),
            remote_seq(&self.tree, &self.runtime),
            state.sends.len(),
            ok + failed,
        )
    }
    fn sync_outcomes(&self) -> (u64, u64) {
        let rendered = self
            .metrics
            .snapshot()
            .unwrap()
            .render_prometheus()
            .unwrap();
        super::super::super::super::observed::sync_metric_counts(&rendered)
    }
    /// Start the job the adapter would for `request`, outside its gate, and
    /// wait for its one completion.
    fn sync(&self, request: MountSyncRequest) -> Option<Result<(), MountSyncError>> {
        let job = match self.with_mount(|mount| mount.prepare_sync(request))? {
            Ok(job) => job,
            Err(error) => return Some(Err(error)),
        };
        let (sent, completed) = std::sync::mpsc::channel();
        job.start(Box::new(move |result| {
            let _ = sent.send(result);
        }));
        completed.recv_timeout(BOUND).ok()
    }
    /// Open `path` as the adapter does and keep it open.
    fn open(&self, path: &[u8]) -> u64 {
        self.with_mount(|mount| {
            let object = mount.overlay_open(&path_names(path)).unwrap().unwrap();
            mount.prepare_object(object).unwrap();
            object
        })
        .unwrap()
    }
    fn write(&self, object: u64, bytes: &[u8]) {
        self.with_mount(|mount| {
            mount
                .overlay_mutate(M::BoundWrite {
                    object,
                    offset: 0,
                    bytes,
                    append: false,
                })
                .unwrap();
        })
        .unwrap();
    }
    pub(super) fn close(&self, object: u64) {
        self.with_mount(|mount| mount.overlay_close(object).unwrap())
            .unwrap();
    }
    /// The counts once the fsyncs recorded reach `fsyncs`: the reply is
    /// delivered before the engine records it.
    fn counts_at(&self, fsyncs: u64) -> Counts {
        let _ = eventually(|| self.counts().3 >= fsyncs);
        self.counts()
    }
}

fn delta(before: Counts, after: Counts) -> (usize, u64, u64) {
    (after.0 - before.0, after.1 - before.1, after.3 - before.3)
}

/// With no option a mount sync answers once registered and publishes
/// nothing; the published profile answers each file sync, data sync and
/// directory sync only on its own publication, one per call, a clean call
/// too. Either way every call records exactly one fsync, and closing the
/// file records none and publishes nothing.
#[test]
fn projected_profile_and_sync_flags() {
    let mut cases = 0;
    for (profile, published) in [
        (crate::SyncProfile::default(), (0, 0)),
        (crate::SyncProfile::Published, (1, 1)),
    ] {
        let fixture = BoundMount::with_profile(profile);
        let object = fixture.open(b"f.txt");
        fixture.write(object, b"profile-one");
        let requests = [
            (
                "fsync dirty",
                MountSyncRequest::File {
                    object,
                    datasync: false,
                },
            ),
            (
                "fdatasync clean",
                MountSyncRequest::File {
                    object,
                    datasync: true,
                },
            ),
            (
                "fsyncdir root",
                MountSyncRequest::Directory {
                    path: vec![],
                    datasync: false,
                },
            ),
            (
                "fdatasync dir",
                MountSyncRequest::Directory {
                    path: path_names(b"sub"),
                    datasync: true,
                },
            ),
        ];
        for (name, request) in requests {
            let before = fixture.counts();
            let result = fixture.sync(request);
            let after = fixture.counts_at(before.3 + 1);
            assert_eq!(
                (result, delta(before, after)),
                (Some(Ok(())), (published.0, published.1, 1)),
                "{profile:?} {name}: (reply, (publications, head seqs, fsyncs recorded))"
            );
            cases += 1;
        }
        let before = fixture.counts();
        fixture.close(object);
        assert_eq!(fixture.counts_at(before.3), before, "{profile:?}: close");
        cases += 1;
    }
    assert_eq!(cases, 10);
}

/// On the published profile a descriptor whose clean object a landing
/// replaced syncs at once: its version is already published and it takes
/// no write, so the call registers nothing, publishes nothing and records
/// no fsync, though other work is waiting to be published. That work's own
/// sync then publishes it.
#[test]
fn projected_replaced_descriptor_sync_makes_no_engine_call() {
    let fixture = BoundMount::with_profile(crate::SyncProfile::Published);
    let held = fixture.open(b"sub/g.txt");
    let lane = fixture.construct(70);
    publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
        std::fs::write(source.join("sub/g.txt"), rewritten()).unwrap();
    });
    let landing = fixture.drive(&lane, 80);
    let replaced = fixture
        .with_mount(|mount| mount.replaced_for_test(held).is_some())
        .unwrap();
    assert!(
        landed(&landing) && replaced,
        "premise: a landing replaced the held object; got {} (replaced={replaced})",
        refusal(&landing)
    );
    let other = fixture.open(b"f.txt");
    fixture.write(other, b"eligible-work");
    let request = |object| MountSyncRequest::File {
        object,
        datasync: false,
    };
    let before = fixture.counts();
    let exception = fixture.sync(request(held));
    let after = fixture.counts();
    // An engine call publishes before it replies, and records its fsync
    // just after: by the time the other file's sync has published and
    // replied, both would be counted.
    let control = fixture.sync(request(other));
    let published = fixture.counts_at(before.3 + 1);
    assert_eq!(
        (
            exception,
            (after.0 - before.0, after.1 - before.1, after.2 - before.2),
            control,
            delta(before, published),
        ),
        (Some(Ok(())), (0, 0, 0), Some(Ok(())), (1, 1, 1)),
        "(replaced descriptor's reply, its (publications, head seqs, registrations), the other \
         file's reply, both calls' (publications, head seqs, fsyncs))"
    );
    fixture.close(other);
    fixture.close(held);
}
