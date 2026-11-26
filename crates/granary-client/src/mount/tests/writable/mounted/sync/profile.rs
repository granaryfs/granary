// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The sync profile through a real mount: every syscall that syncs reaches
//! one job, which answers as the profile the mount started with says.

use super::super::super::commit_lane::publish_head;
use super::*;
use std::os::unix::fs::OpenOptionsExt as _;

/// Publications sent, the authority's head seq, registrations sent, fsyncs
/// recorded, and every sync request the adapter made, as (directory,
/// datasync).
type Counts = (usize, u64, usize, u64, Vec<(bool, bool)>);

impl SyncMount {
    fn counts(&self) -> Counts {
        let (ok, failed) = self.sync_outcomes();
        let mut requests = self.observer.sync_requests();
        requests.extend(self.observer.write_sync_requests());
        (
            self.publications(),
            self.remote_seq(),
            self.registrations(),
            ok + failed,
            requests,
        )
    }
    /// The counts once the fsyncs recorded reach `fsyncs`: the reply is
    /// delivered before the engine records it.
    /// The counts once at least one fsync past `before` is recorded and
    /// every sync request made since has recorded its own: the reply is
    /// delivered before the engine records it. Polled from this thread,
    /// since `counts` blocks on the fixture runtime itself.
    fn counts_after(&self, before: &Counts) -> Counts {
        let settled = |now: &Counts| {
            let fsyncs = now.3 - before.3;
            fsyncs > 0 && usize::try_from(fsyncs).ok() == Some(now.4.len() - before.4.len())
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let now = self.counts();
            if settled(&now) || std::time::Instant::now() >= deadline {
                return now;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    fn open_with(&self, name: &str, flags: i32) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(flags)
            .open(self.paths.mountpoint.join(name))
            .unwrap()
    }
}

/// (publications, head seqs, fsyncs recorded, new requests) between two counts.
fn delta(before: &Counts, after: &Counts) -> (usize, u64, u64, Vec<(bool, bool)>) {
    (
        after.0 - before.0,
        after.1 - before.1,
        after.3 - before.3,
        after.4[before.4.len()..].to_vec(),
    )
}

/// One syscall that syncs, and the request the adapter should make for it.
type Call<'a> = (
    &'a str,
    (bool, bool),
    Box<dyn Fn() -> std::io::Result<()> + 'a>,
);

/// fsync, fdatasync, fsyncdir and an `O_SYNC` and `O_DSYNC` write each make
/// one sync request and record one fsync; with no option none publishes,
/// and the published profile publishes once per call. Closing the files
/// (flush and release) makes no request and publishes nothing.
#[test]
fn writable_linux_projected_profile_and_sync_flags() {
    if !venue("writable_linux_projected_profile_and_sync_flags") {
        return;
    }
    let mut cases = 0;
    for (profile, published) in [
        (crate::SyncProfile::default(), (0, 0)),
        (crate::SyncProfile::Published, (1, 1)),
    ] {
        let fixture = SyncMount::with_profile(sync_deadline(), Hook::Bound, profile);
        let file = fixture.file();
        let full_sync = fixture.open_with("f.txt", 0x0010_1000);
        let data_only = fixture.open_with("f.txt", 0x0000_1000);
        let calls: [Call<'_>; 5] = [
            (
                "fsync",
                (false, false),
                Box::new(|| {
                    file.write_at(b"profile-one", 0)?;
                    file.sync_all()
                }),
            ),
            ("fdatasync", (false, true), Box::new(|| file.sync_data())),
            (
                "fsyncdir",
                (true, false),
                Box::new(|| std::fs::File::open(fixture.paths.mountpoint.as_path())?.sync_all()),
            ),
            (
                "O_SYNC write",
                (false, false),
                Box::new(|| full_sync.write_at(b"profile-two", 0).map(drop)),
            ),
            (
                "O_DSYNC write",
                (false, true),
                Box::new(|| data_only.write_at(b"profile-six", 0).map(drop)),
            ),
        ];
        for (name, request, call) in calls {
            let before = fixture.counts();
            let result = call().map_err(|error| error.raw_os_error());
            let after = fixture.counts_after(&before);
            // A synchronous write may also draw the kernel's own fsync after
            // it, which can arrive as a full fsync: the call's own mode must
            // be among the requests, all on the same kind of object, and each
            // request is one engine call with its own fsync and, on the
            // published profile, its own publication.
            let (publications, seqs, fsyncs, requests) = delta(&before, &after);
            let calls = u64::try_from(requests.len()).unwrap();
            assert_eq!(
                (
                    result,
                    requests.contains(&request) && requests.iter().all(|seen| seen.0 == request.0),
                    (publications, seqs, fsyncs),
                ),
                (
                    Ok(()),
                    true,
                    (published.0 * requests.len(), published.1 * calls, calls),
                ),
                "{profile:?} {name}: (result, {request:?} among same-kind requests, (publications, head seqs, fsyncs)); requests {requests:?}"
            );
            cases += 1;
        }
        let before = fixture.counts();
        drop((file, full_sync, data_only));
        assert_eq!(fixture.counts(), before, "{profile:?}: close");
        fixture.finish();
        cases += 1;
    }
    assert_eq!(cases, 12);
}

/// On the published profile an fsync on a descriptor whose clean file a
/// landing replaced answers at once: the adapter asks, but nothing is
/// registered, published or recorded as an fsync, though another file
/// waits to be published. That file's own fsync then publishes it.
#[test]
fn writable_linux_projected_replaced_descriptor_sync_makes_no_engine_call() {
    if !venue("writable_linux_projected_replaced_descriptor_sync_makes_no_engine_call") {
        return;
    }
    let fixture =
        SyncMount::with_profile(sync_deadline(), Hook::Bound, crate::SyncProfile::Published);
    let held = std::fs::File::open(fixture.paths.mountpoint.join("sub/g.txt")).unwrap();
    let lane = fixture.construct_commit(70).unwrap();
    let mut rewritten = FILE_CONTENT.to_vec();
    rewritten[..4].copy_from_slice(b"head");
    publish_head(&fixture.tree, &fixture.runtime, FILE_CONTENT, |source| {
        std::fs::write(source.join("sub/g.txt"), &rewritten).unwrap();
    });
    let landing = fixture.drive_commit(&lane, 80);
    assert!(
        landed(&landing),
        "premise: the landing installed; got {landing:?}"
    );
    let other = fixture.file();
    other.write_at(b"eligible-work", 0).unwrap();
    let before = fixture.counts();
    let exception = held.sync_all().map_err(|error| error.raw_os_error());
    let after = fixture.counts();
    // An engine call publishes before it replies and records its fsync just
    // after: once the other file's fsync has published, both are counted.
    let control = other.sync_all().map_err(|error| error.raw_os_error());
    let published = fixture.counts_after(&after);
    assert_eq!(
        (
            exception,
            (after.0 - before.0, after.1 - before.1, after.2 - before.2),
            after.4[before.4.len()..].to_vec(),
            control,
            delta(&before, &published),
        ),
        (
            Ok(()),
            (0, 0, 0),
            vec![(false, false)],
            Ok(()),
            (1, 1, 1, vec![(false, false), (false, false)]),
        ),
        "(replaced descriptor's fsync, its (publications, head seqs, registrations), its \
         requests, the other file's fsync, both calls' (publications, head seqs, fsyncs, \
         requests))"
    );
    drop((held, other));
    fixture.finish();
}
