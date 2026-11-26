// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

//! Unit tests for `crate::filesystem` — the
//! `fuser::Filesystem` adapter's private,
//! `Request`/`Reply`-free helper methods, which carry the
//! real logic behind each callback's one terminal `match`.
//!
//! Out-of-line: `granary-fuse`'s non-test artifact
//! has a workspace consumer (`granary-client`), so
//! the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use super::{
    GranaryFs, MountInner, access_check, kernel_time, node_kind_of, outcome_from_full,
    statfs_reply, to_file_attr, to_file_type,
};
#[cfg(feature = "conformance-breakage")]
use crate::DirPlusSink;
use crate::{FUSE_SERVE_LIMITS, MountBackend, MountRefused, SinkOutcome};
use fuser::{AccessFlags, Filesystem, INodeNo, OpenAccMode};
use granary_core::hash::GrainId;
use granary_core::manifest::{
    DirEntry, EntryKind, FileGrains, GrainRef, Name, SymlinkTarget, TreeStats, build_dir,
};
use granary_core::sheaf::Timestamp;
use granary_vfs::{
    Attr, AttrPolicy, GrainFetch, GrainUnavailable, HandleKind, InodeTable, NodeKind, ServeLimits,
    Snapshot,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

mod sync;
mod terminal;
mod view;

#[derive(Debug, Clone, Default)]
struct TestBackend {
    grains: BTreeMap<GrainId, Vec<u8>>,
    shutdown_calls: Arc<AtomicUsize>,
    readiness_calls: Arc<AtomicUsize>,
    /// How many times this backend's own
    /// `Drop` performed a "clean close" — the counter the poisoned-
    /// destroy test reads to prove the crash signal was NOT undone.
    drop_closes: Arc<AtomicUsize>,
    /// Models `MountSession`'s own `cache: Option<Cache>`: present
    /// until `shutdown` or `abandon` takes it, at which point `Drop`
    /// finds nothing to close. There is no real resource to take
    /// here, so this is a plain bool doing the same job.
    disarmed: bool,
}

impl GrainFetch for TestBackend {
    fn grain(&mut self, id: &GrainId, _unpacked_len: u32) -> Result<Vec<u8>, GrainUnavailable> {
        self.grains
            .get(id)
            .cloned()
            .ok_or_else(|| GrainUnavailable::new(format!("missing test grain {id}")))
    }
}

impl MountBackend for TestBackend {
    type DirectoryCursor = ();
    fn overlay_path(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<crate::OverlayMetadata, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_lookup(
        &mut self,
        _parent: &[granary_core::manifest::Name],
        _name: &granary_core::manifest::Name,
    ) -> Result<crate::OverlayMetadata, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_directory(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<crate::OverlayDirectory<()>, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_children(
        &mut self,
        _cursor: &(),
    ) -> Result<crate::OverlayChildren<()>, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }

    fn overlay_nodes(&mut self) -> Result<Vec<crate::OverlayNode>, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_capacity(&mut self) -> Result<crate::OverlayCapacity, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_readlink(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<Vec<u8>, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn prepare_shrink_retry(
        &mut self,
        _request: crate::MountShrinkRequest,
    ) -> Result<Box<dyn crate::MountSyncJob>, crate::MountSyncError> {
        Err(crate::MountSyncError::InvalidRequest)
    }

    fn prepare_sync(
        &mut self,
        _request: crate::MountSyncRequest,
    ) -> Result<Box<dyn crate::MountSyncJob>, crate::MountSyncError> {
        Err(crate::MountSyncError::InvalidRequest)
    }

    fn overlay_open(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<Option<u64>, crate::WriteError> {
        Ok(None)
    }
    fn overlay_object(&mut self, _object: u64) -> Result<crate::OverlayNode, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_close(&mut self, _object: u64) -> Result<(), crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn prepare_object(&mut self, _object: u64) -> Result<(), crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn prepare_detach(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<(), crate::WriteError> {
        Ok(())
    }
    fn read_object(
        &mut self,
        _object: u64,
        _offset: u64,
        _length: usize,
    ) -> Result<Vec<u8>, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn prepare_overlay(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<(), crate::WriteError> {
        Ok(())
    }
    fn overlay_setattr(
        &mut self,
        _path: &[granary_core::manifest::Name],
        _size: Option<u64>,
        _exec: Option<bool>,
    ) -> Result<crate::OverlayMetadata, crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn overlay_mutate(
        &mut self,
        _operation: crate::OverlayMutation<'_>,
    ) -> Result<(), crate::WriteError> {
        Err(crate::WriteError::Unimplemented)
    }
    fn snapshot_fixture(&self) -> bool {
        true
    }

    fn mutation_readiness(&mut self) -> Result<(), crate::MountError> {
        self.readiness_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn shutdown(&mut self) -> Result<(), String> {
        self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
        self.disarmed = true;
        Ok(())
    }

    fn abandon(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for TestBackend {
    // Models `MountSession`'s own `Drop`: a real backend closes its
    // cache on drop unless `abandon` took it first. Without this, a
    // test backend is STICKIER than the real thing and the whole
    // class this test exists for is invisible.
    fn drop(&mut self) {
        if !self.disarmed {
            self.drop_closes.fetch_add(1, Ordering::SeqCst);
        }
    }
}

// ---- the Filesystem implementation witness --------------------------------------
//
// This compile-time witness requires `GranaryFs<TestBackend>` to satisfy
// `Filesystem`. There is no branch to exercise: its only failure mode is
// the type not satisfying the bound, which is exactly what it proves.
#[test]
fn the_adapter_satisfies_fusers_bounds() {
    const fn assert_fs<T: Filesystem>() {}
    assert_fs::<GranaryFs<TestBackend>>();
}

// ---- pure helpers ----------------------------------------------------

#[test]
fn outcome_from_full_maps_true_to_full_and_false_to_added() {
    assert_eq!(outcome_from_full(true), SinkOutcome::Full);
    assert_eq!(outcome_from_full(false), SinkOutcome::Added);
}

#[test]
fn access_check_refuses_write_and_refuses_execute_without_an_exec_bit() {
    // 0o555 is what `Snapshot::attr_for` gives a directory or an exec:true file;
    // 0o444 is every other regular file. The mode is what makes X_OK
    // discriminating, so both arms are exercised for every mask.
    const EXECUTABLE: u16 = 0o555;
    const NOT_EXECUTABLE: u16 = 0o444;
    for perm in [EXECUTABLE, NOT_EXECUTABLE] {
        assert_eq!(access_check(AccessFlags::empty(), perm), Ok(()));
        assert_eq!(access_check(AccessFlags::R_OK, perm), Ok(()));
        assert_eq!(
            access_check(AccessFlags::W_OK, perm),
            Err(fuser::Errno::EACCES),
            "a read-only mount refuses W_OK whatever the mode says"
        );
        assert_eq!(
            access_check(AccessFlags::R_OK | AccessFlags::W_OK, perm),
            Err(fuser::Errno::EACCES)
        );
    }
    // Execute permission depends on the entry mode.
    assert_eq!(access_check(AccessFlags::X_OK, EXECUTABLE), Ok(()));
    assert_eq!(
        access_check(AccessFlags::X_OK, NOT_EXECUTABLE),
        Err(fuser::Errno::EACCES),
        "X_OK on a 0444 file must be refused, not approved: a mount \
         without default_permissions would otherwise be silently permissive"
    );
    assert_eq!(
        access_check(AccessFlags::R_OK | AccessFlags::X_OK, NOT_EXECUTABLE),
        Err(fuser::Errno::EACCES)
    );
}

#[test]
fn statfs_reply_derives_blocks_and_files_from_tree_stats_and_zeros_free_space() {
    let stats = TreeStats {
        dirs: 2,
        files: 3,
        symlinks: 1,
        entries: 6,
        grains: 4,
        bytes: 9000,
    };
    let (blocks, bfree, bavail, files, ffree, bsize, namelen, frsize) = statfs_reply(stats);
    assert_eq!(bsize, 4096);
    assert_eq!(frsize, 4096);
    assert_eq!(
        namelen,
        u32::try_from(granary_core::manifest::name::NAME_MAX).expect("NAME_MAX fits in u32"),
        "namelen must track NAME_MAX, the same cap check_name_length enforces, so a move \
         of that constant cannot leave statfs silently lying with both gates green"
    );
    assert_eq!(
        blocks,
        9000_u64.div_ceil(4096),
        "blocks must come from stats.bytes"
    );
    assert_eq!(
        files, 7,
        "files must be stats.entries + 1 for the mount root"
    );
    assert_eq!(
        bfree, 0,
        "read-only and immutable: no free blocks to report"
    );
    assert_eq!(bavail, 0);
    assert_eq!(
        ffree, 0,
        "read-only and immutable: no free inodes to report"
    );
}

#[test]
fn statfs_reply_on_default_stats_is_zeros_plus_the_root() {
    // The standing note this function's own doc names: every
    // fixture passes `TreeStats::default()`. Pinning the behaviour
    // on exactly that input is what makes a future real-stats
    // wiring change this test rather than silently drift past it.
    let (blocks, _, _, files, _, _, _, _) = statfs_reply(TreeStats::default());
    assert_eq!(blocks, 0);
    assert_eq!(files, 1, "the root alone, even with zeroed stats");
}

#[test]
fn to_file_attr_maps_ino_kind_and_copies_the_passed_instant_into_all_four_fields() {
    let attr = Attr {
        ino: 7,
        generation: 3,
        kind: NodeKind::Symlink,
        perm: 0o777,
        nlink: 1,
        uid: 9,
        gid: 10,
        size: 5,
        blocks: 1,
        blksize: 4096,
        // Deliberately NOT `mount_time` below: proves the four
        // `FileAttr` timestamps come from the instant the `Bent` carries,
        // never from `attr.time` — which stays the format's own
        // `Timestamp` all the way through this adapter.
        time: Timestamp { secs: -1, nanos: 1 },
    };
    let mount_time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(42);
    // `Bent`'s tuple field is private to the `bent` submodule, so
    // use the real (unarmed) constructor, `GranaryFs::bend`.
    let (fs, _) = fixture_fs();
    let file_attr = to_file_attr(&fs.bend(attr, mount_time));
    assert_eq!(
        file_attr.ino,
        INodeNo(7),
        "trap T1: this is the value ReplyDirectoryPlus::add reads"
    );
    assert_eq!(file_attr.kind, to_file_type(NodeKind::Symlink));
    assert_eq!(file_attr.perm, 0o777);
    assert_eq!(file_attr.nlink, 1);
    assert_eq!(file_attr.uid, 9);
    assert_eq!(file_attr.gid, 10);
    assert_eq!(file_attr.size, 5);
    assert_eq!(file_attr.blocks, 1);
    assert_eq!(file_attr.blksize, 4096);
    assert_eq!(
        file_attr.atime, mount_time,
        "all four timestamps are the ONE converted value, taken as a \
         parameter — not `attr.time`, which this adapter never converts"
    );
    assert_eq!(file_attr.mtime, mount_time);
    assert_eq!(file_attr.ctime, mount_time);
    assert_eq!(file_attr.crtime, mount_time);
}

/// `kernel_time`: the adapter's mount-time timestamp conversion, and the
/// measurement that shows its REFUSAL guards an empty set on this
/// platform.
///
/// `secs = i64::MIN` was proposed as the live hostile case, on the
/// grounds that `Timestamp::is_valid` checks only `nanos`. Measured:
/// `i64::MIN` seconds IS a representable `SystemTime` here — a unix
/// `timespec` carries an `i64` `tv_sec`, so the conversion produces
/// `tv_sec: i64::MIN` and succeeds. And `take_timestamp` enforces
/// `is_valid()` on DECODE, so no root can carry `nanos >= 1e9` either.
/// Between them, every `Timestamp` a decoded root can hold converts —
/// which is exactly why the `MountRefused::UnrepresentableTimestamp`
/// arm has no test of its own; this suite, on `kernel_time` directly,
/// is its positive control.
///
/// The refusal is kept anyway, because the conversion target is fixed by
/// `fuser` and `fuser`'s own `time_from_system_time` SATURATES rather
/// than refusing — to `(i64::MAX, 999_999_999)` and `(i64::MIN, 0)` —
/// which is the behaviour the mount's own rule forbids. The two branches
/// are NOT alike, and saying "both unreachable" would be false: the
/// positive one is genuinely unreachable, while the `(i64::MIN, 0)`
/// branch IS TAKEN by `kernel_time(i64::MIN, 0)` and is harmless only
/// because `-2^63` saturates to itself, so the clamp happens to be the
/// identity. A guard whose failure is unreachable still needs its
/// negative demonstrated, so step 1 below pins `kernel_time`'s contract
/// DIRECTLY, with an input the decoder cannot produce.
#[test]
fn kernel_time_converts_every_d11_valid_timestamp_and_refuses_a_genuine_overflow() {
    // 1. The guard's NEGATIVE, reached DIRECTLY on the helper rather
    //    than through `Snapshot::new`. `nanos = u32::MAX` is itself
    //    INVALID (`Timestamp::is_valid` requires `nanos <
    //    NANOS_PER_SEC`), so `take_timestamp` refuses it at parse and
    //    `Snapshot::new`'s own `InvalidTimestamp` guard refuses it again
    //    directly — this exact value can never reach `kernel_time` in
    //    production. `kernel_time` checks representability, so the
    //    `None` below is an arithmetic overflow, not a validity
    //    short-circuit: 4.29 s of nanos carries into the
    //    seconds field, and `i64::MAX` seconds has no headroom left to
    //    carry into. A VALID `nanos` (< 1e9) can never do this — see
    //    step 2's loop, which converts `i64::MAX` seconds successfully
    //    the moment `nanos` is under one second, because such an addend
    //    never carries into a whole-seconds base.
    assert_eq!(
        kernel_time(Timestamp {
            secs: i64::MAX,
            nanos: u32::MAX,
        }),
        None,
        "the conversion refuses rather than saturating, even reached directly with an \
         input the engine's own validity gate would never let through"
    );

    // 2. Every extreme a DECODED root can actually carry converts.
    for timestamp in [
        Timestamp { secs: 0, nanos: 0 },
        Timestamp {
            secs: i64::MIN,
            nanos: 0,
        },
        Timestamp {
            secs: i64::MIN,
            nanos: 999_999_999,
        },
        Timestamp {
            secs: i64::MAX,
            nanos: 999_999_999,
        },
    ] {
        assert!(
            timestamp.is_valid(),
            "the fixture must be decodable: {timestamp:?}"
        );
        let converted = kernel_time(timestamp);
        println!("kernel_time {timestamp:?} -> {converted:?}");
        assert!(
            converted.is_some(),
            "a decodable timestamp must convert: {timestamp:?}"
        );
    }

    // 3. And `secs = i64::MIN` still MOUNTS end to end —
    //    through `GranaryFs::new`, not merely `Snapshot::new`, which is
    //    the positive control `MountRefused::UnrepresentableTimestamp`
    //    needs.
    let entries = [file(b"only")];
    let built = build_dir(&entries).expect("fixture builds");
    let root = built.root;
    let hostile = Timestamp {
        secs: i64::MIN,
        nanos: 0,
    };
    let snapshot = Snapshot::new(
        built.nodes.into_iter().collect(),
        root,
        hostile,
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("i64::MIN seconds is a valid Timestamp and representable on a 64-bit unix");
    let mount = GranaryFs::new(
        snapshot,
        TestBackend::default(),
        1,
        crate::MountWritability::ReadOnly,
    )
    .expect("the adapter must admit a snapshot carrying this platform's hostile root timestamp");
    // The mount must report the ROOT's own timestamp — not merely admit
    // the snapshot. `is_ok()` alone asserts nothing about the VALUE
    // `GranaryFs::new` stored; a build that converted a constant instead
    // of `snapshot.timestamp()` would pass that check on every mount.
    assert_eq!(
        mount.mount_time,
        kernel_time(hostile).expect("step 2 above already converts this exact value"),
        "the mount must report the root's own converted timestamp, not some other instant"
    );
}

/// The sign-convention pin for `kernel_time`.
/// The format makes `nanos` a non-negative offset
/// FORWARD from `secs`, so `{ secs: -123, nanos: 456_789 }` is
/// 122.999543211 s before the epoch, not 123.000456789 s before it —
/// the naive reading a `secs`-then-`nanos` truncation bug would produce.
/// `kernel_time_converts_every_d11_valid_timestamp_and_refuses_a_genuine_overflow`
/// above only asserts `is_some()`/`is_none()`: it pins that the
/// conversion SUCCEEDS or FAILS, never what value a success carries, so
/// a mutation that truncates `nanos` to whole microseconds
/// (`nanos / 1_000 * 1_000`) passes it. This test pins the VALUE.
#[test]
fn kernel_time_preserves_the_sign_convention_of_a_pre_epoch_timestamp() {
    let timestamp = Timestamp {
        secs: -123,
        nanos: 456_789,
    };
    assert!(timestamp.is_valid(), "fixture must be decodable");
    let converted = kernel_time(timestamp).expect("a valid pre-epoch timestamp converts");
    let before_epoch = std::time::SystemTime::UNIX_EPOCH
        .duration_since(converted)
        .expect("a pre-epoch publish timestamp is before the epoch");
    assert_eq!(
        before_epoch,
        std::time::Duration::new(122, 999_543_211),
        "the instant is 122.999543211 s before the epoch, not 123.000456789"
    );
}

#[test]
fn to_file_type_covers_every_node_kind() {
    assert_eq!(to_file_type(NodeKind::Dir), fuser::FileType::Directory);
    assert_eq!(to_file_type(NodeKind::File), fuser::FileType::RegularFile);
    assert_eq!(to_file_type(NodeKind::Symlink), fuser::FileType::Symlink);
}

// ---- fixtures ----------------------------------------------------------

fn file(name: &[u8]) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::File {
            exec: false,
            size: 0,
            grains: FileGrains::Inline(Vec::new()),
        },
    }
}

fn dir(name: &[u8], child: GrainId) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::Dir { child },
    }
}

fn symlink(name: &[u8], target: &[u8]) -> DirEntry {
    DirEntry {
        name: Name::new(name.to_vec()).expect("fixture name is valid"),
        kind: EntryKind::Symlink {
            target: SymlinkTarget::new(target.to_vec()).expect("fixture target is valid"),
        },
    }
}

/// root -> {"child" (dir, empty), "leaf" (file), "link" (symlink ->
/// "leaf")}. One fixture wide enough to exercise every `NodeKind` the
/// inode table can allocate.
fn snapshot_fixture() -> (Snapshot, GrainId) {
    let child = build_dir(&[]).expect("child dir builds");
    // `build_dir` requires strict memcmp order.
    let entries = [
        dir(b"child", child.root),
        file(b"leaf"),
        symlink(b"link", b"leaf"),
    ];
    let built = build_dir(&entries).expect("fixture directory builds");
    let mut nodes = child.nodes.into_iter().collect::<BTreeMap<_, _>>();
    nodes.extend(built.nodes);
    let snapshot = Snapshot::new(
        nodes,
        built.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("fixture snapshot indexes");
    (snapshot, built.root)
}

fn fixture_fs() -> (GranaryFs<TestBackend>, Arc<AtomicUsize>) {
    let (snapshot, _root) = snapshot_fixture();
    let shutdown_calls = Arc::new(AtomicUsize::new(0));
    let backend = TestBackend {
        grains: BTreeMap::new(),
        shutdown_calls: shutdown_calls.clone(),
        readiness_calls: Arc::default(),
        drop_closes: Arc::new(AtomicUsize::new(0)),
        disarmed: false,
    };
    (
        GranaryFs::new(snapshot, backend, 1, crate::MountWritability::ReadOnly)
            .expect("fixture snapshot admits the adapter's limits"),
        shutdown_calls,
    )
}

// ---- GranaryFs::new: the mount-time readlink-bound refusal --------------

/// A snapshot admitted under a LOOSER readlink bound than this adapter's
/// own `readlink` reply can carry must be refused at mount time, naming
/// both bounds, rather than admitted and left to surface later as an
/// opaque per-call `EIO`.
#[test]
fn new_refuses_a_snapshot_whose_readlink_bound_exceeds_the_adapters_own() {
    let built = build_dir(&[]).expect("empty fixture directory builds");
    let looser_bound = FUSE_SERVE_LIMITS.readlink_target_max_bytes + 1;
    let snapshot = Snapshot::new(
        built.nodes.into_iter().collect(),
        built.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        ServeLimits {
            readlink_target_max_bytes: looser_bound,
        },
    )
    .expect("fixture snapshot indexes");

    let result = GranaryFs::new(
        snapshot,
        TestBackend::default(),
        1,
        crate::MountWritability::ReadOnly,
    );

    let refusal = result.expect_err(
        "a snapshot admitting a looser readlink bound than this adapter can serve must be \
         refused",
    );
    assert_eq!(
        refusal,
        MountRefused::ReadlinkBoundExceeded {
            snapshot_bound: looser_bound,
            adapter_bound: FUSE_SERVE_LIMITS.readlink_target_max_bytes,
        },
        "the refusal must name both the snapshot's bound and the adapter's own"
    );
}

/// The POSITIVE CONTROL for the refusal above. Without it, a mutation
/// that refused every mount would pass the negative test just as well as
/// the real, bound-gated check.
///
/// It builds the SAME empty fixture as the refusal test and varies ONLY
/// the bound. Holding the tree shape constant ensures the pair identifies
/// the bound, rather than the fixture shape, as the deciding input.
#[test]
fn new_admits_a_snapshot_whose_readlink_bound_is_no_looser_than_the_adapters_own() {
    let built = build_dir(&[]).expect("empty fixture directory builds");
    let snapshot = Snapshot::new(
        built.nodes.into_iter().collect(),
        built.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("fixture snapshot indexes");

    assert!(
        GranaryFs::new(
            snapshot,
            TestBackend::default(),
            1,
            crate::MountWritability::ReadOnly
        )
        .is_ok(),
        "a snapshot built under this adapter's own bound must be admitted"
    );
}

// ---- lookup_entry ------------------------------------------------------

#[test]
fn lookup_entry_returns_the_child_and_credits_it_once() {
    let (fs, _) = fixture_fs();
    let attr = fs
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .expect("leaf resolves");
    assert_eq!(attr.kind, NodeKind::File);
    assert_eq!(attr.generation, 1);
    let again = fs
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .expect("second lookup resolves");
    assert_eq!(again.ino, attr.ino, "the same path must reuse the same ino");
}

#[test]
fn lookup_entry_refuses_an_overlong_name_without_allocating_anything() {
    let (fs, _) = fixture_fs();
    let over_long = vec![b'a'; granary_core::manifest::name::NAME_MAX + 1];
    let result = fs
        .lookup_entry(INodeNo::ROOT, &over_long)
        .map_err(super::ReplyError::errno);
    assert_eq!(result, Err(fuser::Errno::ENAMETOOLONG));
    // No credit and no row: check via a second call that root's
    // table state is untouched by re-deriving resident_count is not
    // exposed publicly here, so assert indirectly: a lookup of a
    // DIFFERENT, valid name still gets the very next ino (2), proving
    // nothing was allocated for the refused name.
    let leaf = fs
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .expect("leaf resolves");
    assert_eq!(
        leaf.ino, 2,
        "the refused overlong name must not have consumed an inode number"
    );
}

#[test]
fn lookup_entry_reports_enoent_for_a_missing_name() {
    let (fs, _) = fixture_fs();
    assert_eq!(
        fs.lookup_entry(INodeNo::ROOT, b"nope")
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOENT)
    );
}

// ---- getattr_attr / resolve_own_entry -----------------------------------

#[test]
fn getattr_attr_reports_the_roots_own_directory_attributes() {
    let (fs, _) = fixture_fs();
    let attr = fs
        .getattr_attr(INodeNo::ROOT)
        .map_err(super::ReplyError::errno)
        .expect("root resolves");
    assert_eq!(attr.kind, NodeKind::Dir);
    assert_eq!(attr.ino, 1);
}

#[test]
fn getattr_attr_reports_a_childs_own_kind_not_the_parents() {
    let (fs, _) = fixture_fs();
    let leaf = fs
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .expect("leaf resolves");
    let attr = fs
        .getattr_attr(INodeNo(leaf.ino))
        .map_err(super::ReplyError::errno)
        .expect("getattr on the child resolves");
    assert_eq!(
        attr.kind,
        NodeKind::File,
        "must report the CHILD's kind, not root's Dir"
    );
    assert_eq!(attr.ino, leaf.ino);
}

// ---- readlink_bytes ------------------------------------------------------

#[test]
fn readlink_bytes_returns_the_raw_target() {
    let (fs, _) = fixture_fs();
    let link = fs
        .lookup_entry(INodeNo::ROOT, b"link")
        .map_err(super::ReplyError::errno)
        .expect("link resolves");
    let target = fs
        .readlink_bytes(INodeNo(link.ino))
        .map_err(super::ReplyError::errno)
        .expect("readlink succeeds");
    assert_eq!(target, b"leaf");
}

#[test]
fn readlink_bytes_refuses_a_non_symlink() {
    let (fs, _) = fixture_fs();
    let leaf = fs
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .expect("leaf resolves");
    assert_eq!(
        fs.readlink_bytes(INodeNo(leaf.ino))
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EIO)
    );
}

// ---- Breakage routes through every Attr/content site -------------------
//
// These pin the SITING claim itself at the GranaryFs
// level, not just the pure/wrapper level breakage.rs's own tests
// cover: that `lookup_entry`, `getattr_attr`, `read_bytes` and
// `readlink_bytes` actually call the routing methods, not merely that
// the routing methods are individually correct.

#[cfg(feature = "conformance-breakage")]
#[test]
fn lookup_entry_bends_exec_everywhere_when_breakage_is_armed() {
    let (mut fs, _) = fixture_fs();
    fs.set_breakage(crate::Breakage::ExecEverywhere);
    let leaf = fs
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .expect("leaf resolves");
    assert_eq!(
        leaf.perm, 0o555,
        "an unarmed leaf is 0o444 (non-exec); armed it must be 0o555"
    );
}

#[cfg(feature = "conformance-breakage")]
#[test]
fn getattr_attr_bends_misreport_size_when_breakage_is_armed() {
    let (mut fs, _) = fixture_fs();
    fs.set_breakage(crate::Breakage::MisreportSize);
    let leaf = fs
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .expect("leaf resolves (and is ALSO bent, since lookup_entry routes too)");
    assert_eq!(
        leaf.size, 1,
        "leaf's honest size is 0; lookup_entry must report 1 when armed"
    );
    let again = fs
        .getattr_attr(INodeNo(leaf.ino))
        .map_err(super::ReplyError::errno)
        .expect("getattr on the same ino resolves");
    assert_eq!(
        again.size, 1,
        "getattr_attr must ALSO bend — if it forgot to call self.bend, this would read 0"
    );
}

#[cfg(feature = "conformance-breakage")]
#[test]
fn lookup_entry_and_getattr_attr_follow_a_sibling_symlink_when_breakage_is_armed() {
    let (mut fs, _) = fixture_fs();
    fs.set_breakage(crate::Breakage::FollowSymlink);
    let link = fs
        .lookup_entry(INodeNo::ROOT, b"link")
        .map_err(super::ReplyError::errno)
        .expect("link resolves");
    assert_eq!(
        link.kind,
        NodeKind::File,
        "lookup_entry must report the referent's File kind, not Symlink"
    );
    let again = fs
        .getattr_attr(INodeNo(link.ino))
        .map_err(super::ReplyError::errno)
        .expect("getattr on the followed ino resolves");
    assert_eq!(
        again.kind,
        NodeKind::File,
        "resolve_own_entry (getattr's path) must ALSO follow — this is a SEPARATE call site"
    );
}

#[cfg(feature = "conformance-breakage")]
#[test]
fn readlink_bytes_refuses_a_followed_symlink_ino_under_breakage_since_the_walker_never_calls_it() {
    // Documents the accepted consequence of symlink substitution: once
    // FollowSymlink is armed, readdirplus/getattr report this ino as
    // a File, so the oracle's own walker never calls readlink on it
    // at all. A DIRECT readlink still goes through the same
    // resolve_own_entry substitution and so still refuses (EIO) —
    // this is not a regression to "fix", it is the documented shape.
    let (mut fs, _) = fixture_fs();
    fs.set_breakage(crate::Breakage::FollowSymlink);
    let link = fs
        .lookup_entry(INodeNo::ROOT, b"link")
        .map_err(super::ReplyError::errno)
        .expect("link resolves");
    assert_eq!(
        fs.readlink_bytes(INodeNo(link.ino))
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EIO)
    );
}

#[cfg(feature = "conformance-breakage")]
#[test]
fn readlink_bytes_appends_one_byte_when_breakage_mangle_symlink_target_is_armed() {
    let (mut fs, _) = fixture_fs();
    let link = fs
        .lookup_entry(INodeNo::ROOT, b"link")
        .map_err(super::ReplyError::errno)
        .expect("link resolves");
    fs.set_breakage(crate::Breakage::MangleSymlinkTarget);
    let target = fs
        .readlink_bytes(INodeNo(link.ino))
        .map_err(super::ReplyError::errno)
        .expect("readlink succeeds");
    assert_eq!(
        target.len(),
        5,
        "the honest target \"leaf\" is 4 bytes; armed it must be 5"
    );
    assert_eq!(
        &target[..4],
        b"leaf",
        "the honest bytes must still be a PREFIX"
    );
}

#[cfg(feature = "conformance-breakage")]
#[test]
fn breakage_mangle_symlink_target_if_armed_never_pushes_a_target_at_the_cap() {
    // The bound is CHECKED, not assumed from gendir's own fixture
    // choices — a manifest symlink target may legally be exactly
    // SYMLINK_TARGET_MAX (4096) bytes (`SymlinkTarget::new` permits it),
    // and this must leave such a target honest rather than push it past
    // the kernel's servable ceiling. Note the two constants are one byte
    // apart and both halves below are deliberately expressed in the one
    // that governs them: this half pins a target ABOVE the ceiling, the
    // half after it pins the last target BELOW it.
    let (mut fs, _) = fixture_fs();
    fs.set_breakage(crate::Breakage::MangleSymlinkTarget);
    let at_cap = vec![b'x'; granary_core::manifest::name::SYMLINK_TARGET_MAX];
    let result = fs.mangle_symlink_target_if_armed(at_cap.clone());
    assert_eq!(
        result, at_cap,
        "a target already at SYMLINK_TARGET_MAX must not be pushed past it"
    );

    // Below the SERVABLE CEILING the mangle still fires — this is the
    // OTHER half of the same guard, and pins that the bound above does
    // not turn the whole transform into a no-op. "Below the cap" is not
    // the condition: at 4095 the target is below `SYMLINK_TARGET_MAX` and
    // the mangle does NOT fire, because the bound is the servable
    // ceiling. The value is
    // `FUSE_READLINK_TARGET_MAX_4K_PAGE - 1` (4094) and must stay adjacent
    // to the ceiling — a target "well below" it would not detect a bound
    // that drifted by one.
    let under_cap = vec![b'x'; crate::FUSE_READLINK_TARGET_MAX_4K_PAGE - 1];
    let mangled = fs.mangle_symlink_target_if_armed(under_cap.clone());
    assert_eq!(mangled.len(), under_cap.len() + 1);
}

#[cfg(feature = "conformance-breakage")]
#[test]
fn breakage_mangle_never_produces_a_reply_the_kernel_would_refuse() {
    let (mut fs, _) = fixture_fs();
    fs.set_breakage(crate::Breakage::MangleSymlinkTarget);
    let at_servable_ceiling = vec![b'x'; crate::FUSE_READLINK_TARGET_MAX_4K_PAGE];
    let result = fs.mangle_symlink_target_if_armed(at_servable_ceiling.clone());
    assert_eq!(
        result, at_servable_ceiling,
        "a target at the kernel's servable ceiling must not be pushed past it"
    );
}

// -------- the readdirplus dispatch, testable --

/// A `DirPlusSink` fake with NO `fuser::ReplyDirectoryPlus`
/// anywhere near it — same shape as `breakage.rs`'s own
/// `RecordingSink`, reused here because THIS module cannot see
/// that one (it is private to `breakage`'s own test module).
#[cfg(feature = "conformance-breakage")]
#[derive(Default)]
struct FakePlusSink {
    offered: Vec<(Attr, Vec<u8>)>,
}

#[cfg(feature = "conformance-breakage")]
impl DirPlusSink for FakePlusSink {
    fn offer(&mut self, attr: Attr, name: &[u8], _next: u64) -> SinkOutcome {
        self.offered.push((attr, name.to_vec()));
        SinkOutcome::Added
    }
}

/// MUTATION-PROVED: deleting `list_dir_plus_dispatch`'s ENTIRE
/// `#[cfg] if let Some(breakage)` arm left the suite 173/173 green
/// before this test existed, because `readdirplus` itself is
/// unreachable from an in-process test. This drives the
/// EXTRACTED dispatch directly, on a real `GranaryFs`, against a
/// fake sink — `OmitEntry` is a WRAPPER-level effect (unaffected by
/// applying ExecEverywhere/MisreportSize in `RealDirPlusSink::offer`), so it
/// is visible through a fake sink and proves the armed branch of
/// the dispatch itself actually ran.
#[cfg(feature = "conformance-breakage")]
#[test]
fn list_dir_plus_dispatch_routes_through_the_breakage_wrapper_when_armed() {
    let (mut fs, _) = fixture_fs();
    fs.set_breakage(crate::Breakage::OmitEntry);
    let mut sink = FakePlusSink::default();
    let result = fs.with_inner(|inner| {
        fs.list_dir_plus_dispatch(inner, u64::from(INodeNo::ROOT), 0, &mut sink)
    });
    assert!(result.is_ok(), "listing must still succeed: {result:?}");
    let names: Vec<Vec<u8>> = sink.offered.iter().map(|(_, n)| n.clone()).collect();
    assert_eq!(
        names,
        vec![
            b".".to_vec(),
            b"..".to_vec(),
            b"leaf".to_vec(),
            b"link".to_vec()
        ],
        "\"child\" (the alphabetically-first non-dot entry) must be withheld — this only \
         happens if the dispatch actually routed through list_dir_plus_with_breakage; if \
         the armed arm were deleted, every entry (including \"child\") would be present"
    );
}

/// MUTATION-PROVED: replacing `self.bend(attr)` with a bare
/// `Bent(attr)` inside what is now `bent_reply_parts` ALSO left the
/// suite green — nothing reached the readdirplus path's OWN bend call (`ExecEverywhere`/
/// `MisreportSize` are now applied by `RealDirPlusSink::offer`,
/// so the dispatch test above cannot see them). This drives
/// `bent_reply_parts` directly.
#[cfg(feature = "conformance-breakage")]
#[test]
fn bent_reply_parts_applies_the_armed_attr_level_transform() {
    let (mut fs, _) = fixture_fs();
    fs.set_breakage(crate::Breakage::MisreportSize);
    let attr = Attr {
        ino: 7,
        generation: 1,
        kind: NodeKind::File,
        perm: 0o444,
        nlink: 1,
        uid: 0,
        gid: 0,
        size: 10,
        blocks: 1,
        blksize: 4096,
        time: Timestamp { secs: 0, nanos: 0 },
    };
    let (_, file_attr, _) = fs.bent_reply_parts(attr, fs.mount_time);
    assert_eq!(
        file_attr.size, 11,
        "bent_reply_parts must apply the armed transform (via GranaryFs::bend), not just \
         wrap the raw Attr unchanged"
    );
}

// ---- open_handle: trap T10's access-mode refusal ------------------------

#[test]
fn open_handle_refuses_every_mode_but_read_only() {
    let (fs, _) = fixture_fs();
    let leaf = fs
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .expect("leaf resolves");
    assert!(
        fs.open_handle(INodeNo(leaf.ino), OpenAccMode::O_RDONLY)
            .map_err(super::ReplyError::errno)
            .is_ok()
    );
    assert_eq!(
        fs.open_handle(INodeNo(leaf.ino), OpenAccMode::O_WRONLY)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EACCES)
    );
    assert_eq!(
        fs.open_handle(INodeNo(leaf.ino), OpenAccMode::O_RDWR)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EACCES)
    );
}

// The inode-table open-count bump this test's PREVIOUS name claimed to
// check is constrained by `release_handle_reclaims_only_when_the_last_handle_of_the_right_kind_releases`
// and `release_handle_of_the_wrong_kind_is_a_no_op` below (both drive
// residency at `nlookup == 0` off it), not by this test — this one
// checks only that two opens of the same inode never collide on the
// same handle number.
#[test]
fn open_handle_returns_a_distinct_handle_for_each_open() {
    let (fs, _) = fixture_fs();
    let leaf = fs
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .expect("leaf resolves");
    let fh1 = fs
        .open_handle(INodeNo(leaf.ino), OpenAccMode::O_RDONLY)
        .map_err(super::ReplyError::errno)
        .expect("first open succeeds");
    let fh2 = fs
        .open_handle(INodeNo(leaf.ino), OpenAccMode::O_RDONLY)
        .map_err(super::ReplyError::errno)
        .expect("second open succeeds");
    assert_ne!(fh1, fh2, "two opens of the same inode get distinct handles");
}

// ---- release_handle: obligations 2 and 4 --------------------------------

#[test]
fn release_handle_reclaims_only_when_the_last_handle_of_the_right_kind_releases() {
    let (fs, _) = fixture_fs();
    // "link" is looked up FIRST so it gets ino 2; "leaf" second gets
    // ino 3. `link_fh` (opened first) therefore gets handle number 1,
    // and `leaf_fh1` (opened second) gets handle number 2 — the SAME
    // raw number as `link`'s ino. This is deliberate: a
    // `release_handle` that mistakenly falls back to treating a
    // handle's own bare number as an ino (instead of acting only on
    // `HandleTable::release`'s `Some`) would, on leaf_fh1's DUPLICATE
    // release below, reclaim `link` — a different, independently
    // observable inode — rather than merely failing to disturb
    // `leaf`'s own count. A same-inode-only fixture cannot distinguish
    // the fallback from correct behaviour because its bogus ino lands
    // on the never-reclaimed root.
    let link = fs
        .lookup_entry(INodeNo::ROOT, b"link")
        .map_err(super::ReplyError::errno)
        .expect("link resolves");
    let leaf = fs
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .expect("leaf resolves");
    let link_fh = fs
        .open_handle(INodeNo(link.ino), OpenAccMode::O_RDONLY)
        .map_err(super::ReplyError::errno)
        .expect("link opens");
    let leaf_fh1 = fs
        .open_handle(INodeNo(leaf.ino), OpenAccMode::O_RDONLY)
        .map_err(super::ReplyError::errno)
        .expect("leaf's first open succeeds");
    let leaf_fh2 = fs
        .open_handle(INodeNo(leaf.ino), OpenAccMode::O_RDONLY)
        .map_err(super::ReplyError::errno)
        .expect("leaf's second open succeeds");
    assert_eq!(
        u64::from(leaf_fh1),
        link.ino,
        "fixture precondition: leaf_fh1's raw number must coincide with link's ino"
    );
    // Drop both lookup credits so residency below reflects ONLY each
    // inode's own handle count.
    let _ = fs.with_inner(|inner| {
        inner.inodes.forget(link.ino, 1);
        inner.inodes.forget(leaf.ino, 1);
        Ok(())
    });
    let resolves = |ino: u64| {
        fs.with_inner(|inner| inner.inodes.resolve(ino).map(|_| ()))
            .is_ok()
    };
    assert!(
        resolves(link.ino),
        "link's own handle must keep it resident at nlookup == 0"
    );
    assert!(
        resolves(leaf.ino),
        "leaf's two live handles must keep it resident at nlookup == 0"
    );

    fs.release_handle(leaf_fh1, HandleKind::File)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert!(
        resolves(leaf.ino),
        "one of leaf's two handles released — the second must still keep it resident"
    );

    // A duplicate release of leaf_fh1 must be a strict no-op: it
    // must not touch leaf's remaining handle (leaf_fh2) NOR, the
    // property this fixture exists to isolate, `link` — which a
    // bug reusing leaf_fh1's bare number as an ino would reclaim.
    fs.release_handle(leaf_fh1, HandleKind::File)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert!(
        resolves(leaf.ino),
        "a duplicate release must not reclaim an inode the second handle still uses"
    );
    assert!(
        resolves(link.ino),
        "a duplicate release of a DIFFERENT handle must not disturb an unrelated inode \
         merely because that handle's raw number equals this inode's ino"
    );

    fs.release_handle(leaf_fh2, HandleKind::File)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert!(
        !resolves(leaf.ino),
        "the last handle releasing must reclaim the inode"
    );

    fs.release_handle(link_fh, HandleKind::File)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert!(
        !resolves(link.ino),
        "link's own last handle releasing must reclaim it too"
    );
}

#[test]
fn release_handle_of_the_wrong_kind_is_a_no_op() {
    let (fs, _) = fixture_fs();
    // Same coincidence as the test above, applied to the WRONG-KIND
    // case: `link` is looked up first (ino 2), `leaf` second (ino
    // 3); `link_fh` gets handle number 1 and `leaf_fh` gets handle
    // number 2 — the same raw number as `link`'s ino. Releasing
    // `leaf_fh` as the WRONG kind must not disturb `link`, which a
    // fallback that reused `leaf_fh`'s bare number as an ino would.
    let link = fs
        .lookup_entry(INodeNo::ROOT, b"link")
        .map_err(super::ReplyError::errno)
        .expect("link resolves");
    let leaf = fs
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .expect("leaf resolves");
    let link_fh = fs
        .open_handle(INodeNo(link.ino), OpenAccMode::O_RDONLY)
        .map_err(super::ReplyError::errno)
        .expect("link opens");
    let leaf_fh = fs
        .open_handle(INodeNo(leaf.ino), OpenAccMode::O_RDONLY)
        .map_err(super::ReplyError::errno)
        .expect("leaf opens");
    assert_eq!(
        u64::from(leaf_fh),
        link.ino,
        "fixture precondition: leaf_fh's raw number must coincide with link's ino"
    );
    let _ = fs.with_inner(|inner| {
        inner.inodes.forget(link.ino, 1);
        inner.inodes.forget(leaf.ino, 1);
        Ok(())
    });
    let resolves = |ino: u64| {
        fs.with_inner(|inner| inner.inodes.resolve(ino).map(|_| ()))
            .is_ok()
    };
    assert!(resolves(link.ino));
    assert!(resolves(leaf.ino));

    // Releasing a FILE handle as though it were a DIRECTORY handle
    // must not release it, and must not touch `link` either.
    fs.release_handle(leaf_fh, HandleKind::Directory)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert!(
        resolves(leaf.ino),
        "a release naming the wrong handle kind must not touch the real handle"
    );
    assert!(
        resolves(link.ino),
        "a wrong-kind release must not disturb an unrelated inode merely because \
         the handle's raw number equals that inode's ino"
    );

    // The real handle still releases correctly under the right kind.
    fs.release_handle(leaf_fh, HandleKind::File)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert!(!resolves(leaf.ino));
    fs.release_handle(link_fh, HandleKind::File)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert!(!resolves(link.ino));
}

// ---- destroy: obligation 1 ----------------------------------------------

#[test]
fn destroy_shuts_down_and_takes_the_backend_when_the_lock_is_clean() {
    let (mut fs, shutdown_calls) = fixture_fs();
    fs.destroy();
    assert_eq!(shutdown_calls.load(Ordering::SeqCst), 1);
    assert!(
        fs.inner.lock().expect("lock is not poisoned").is_none(),
        "destroy must take ownership of MountInner on a clean shutdown"
    );
}

#[test]
fn destroy_declines_shutdown_on_a_poisoned_lock() {
    let (mut fs, shutdown_calls) = fixture_fs();
    let inner: &Mutex<Option<MountInner<TestBackend>>> = &fs.inner;
    let joined = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let _guard = inner.lock().expect("lock acquires before the panic");
                panic!("deliberate poison for this test");
            })
            .join()
    });
    assert!(joined.is_err(), "the spawned thread must have panicked");
    assert!(
        fs.inner.is_poisoned(),
        "the panic must have poisoned the lock"
    );

    fs.destroy();

    assert_eq!(
        shutdown_calls.load(Ordering::SeqCst),
        0,
        "obligation 1: destroy must NOT call shutdown on a poisoned lock"
    );
}

// ---- destroy + Drop: the crash signal the crash path deletes -------------
//
// `destroy_declines_shutdown_on_a_poisoned_lock` above cannot see this
// defect: its `TestBackend` had no `Drop`, so nothing in it performs
// the "clean close" that `MountSession`'s real `Drop` performs once
// `GranaryFs` (and so `MountInner`, and so the backend) is actually
// dropped. `TestBackend`'s own `Drop`, added above, models that.
//
// First failure, quoted verbatim, run with `TestBackend::drop` and
// its `disarmed`/`drop_closes` fields already in place but with
// `GranaryFs::destroy` still its OLD self (the poison arm returns
// immediately, without taking `inner` or calling anything on the
// backend):
//
//   thread 'filesystem::tests::a_poisoned_destroy_is_not_undone_by_the_backends_own_drop' \
//   panicked at crates/granary-fuse/src/filesystem.rs:1479:9:   <- as recorded
//   THEN; that assertion is in this file now, and filesystem.rs is 1,356 lines
//   assertion `left == right` failed: obligation 1's whole point: a poisoned destroy \
//   must not be undone by the backend's own Drop
//     left: 1
//    right: 0
//
// The poisoned-destroy test requires zero clean closes: dropping `fs`
// after a poisoned destroy must not run a guard-removing clean close.

fn destroy_fixture() -> (GranaryFs<TestBackend>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let (snapshot, _root) = snapshot_fixture();
    let shutdown_calls = Arc::new(AtomicUsize::new(0));
    let drop_closes = Arc::new(AtomicUsize::new(0));
    let backend = TestBackend {
        grains: BTreeMap::new(),
        shutdown_calls: shutdown_calls.clone(),
        readiness_calls: Arc::default(),
        drop_closes: drop_closes.clone(),
        disarmed: false,
    };
    (
        GranaryFs::new(snapshot, backend, 1, crate::MountWritability::ReadOnly)
            .expect("fixture snapshot admits the adapter's limits"),
        shutdown_calls,
        drop_closes,
    )
}

#[test]
fn a_poisoned_destroy_is_not_undone_by_the_backends_own_drop() {
    let (mut fs, shutdown_calls, drop_closes) = destroy_fixture();
    let inner: &Mutex<Option<MountInner<TestBackend>>> = &fs.inner;
    let joined = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let _guard = inner.lock().expect("lock acquires before the panic");
                panic!("deliberate poison for this test");
            })
            .join()
    });
    assert!(joined.is_err(), "the spawned thread must have panicked");
    assert!(
        fs.inner.is_poisoned(),
        "the panic must have poisoned the lock"
    );

    fs.destroy();
    drop(fs);

    assert_eq!(
        drop_closes.load(Ordering::SeqCst),
        0,
        "obligation 1's whole point: a poisoned destroy must not be undone by the \
         backend's own Drop"
    );
    assert_eq!(
        shutdown_calls.load(Ordering::SeqCst),
        0,
        "a poisoned destroy must never call shutdown"
    );
}

// The control this counter needs to be trusted at all: a NON-poisoned
// destroy must record exactly one shutdown and ZERO drop-closes,
// because `destroy` took the inner and `shutdown` disarmed it before
// the backend was ever dropped — so `a_poisoned_destroy_is_not_undone_
// by_the_backends_own_drop`'s `0` above is a real assertion, not a
// counter that can only ever read zero.
#[test]
fn a_clean_destroy_calls_shutdown_once_and_never_drop_closes() {
    let (mut fs, shutdown_calls, drop_closes) = destroy_fixture();
    fs.destroy();
    drop(fs);
    assert_eq!(shutdown_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        drop_closes.load(Ordering::SeqCst),
        0,
        "destroy took the inner and shutdown disarmed it; the drop that follows must \
         find nothing to close"
    );
}

// ---- resolve_own_entry / node_kind_of, directly ---------------------------

#[test]
fn resolve_own_entry_synthesises_a_dir_entry_for_the_root() {
    let (fs, _) = fixture_fs();
    // A SEPARATE, freshly-built `InodeTable` over the same
    // deterministic fixture — `resolve_own_entry` takes `inodes` as
    // an explicit parameter and does not read `fs`'s own internal
    // table, so this stays decoupled from `fs`'s bookkeeping while
    // still matching its `snapshot` (`snapshot_fixture` is a pure
    // builder: byte-identical output on every call).
    let (_, root) = snapshot_fixture();
    let inodes = InodeTable::new(root, 1, 1);
    let entry = fs.resolve_own_entry(&inodes, 1).expect("root resolves");
    assert_eq!(entry.kind, EntryKind::Dir { child: root });
}

#[test]
fn node_kind_of_maps_every_representable_entry_kind() {
    let (snapshot, root) = snapshot_fixture();
    let dir_entry = snapshot.lookup(&root, b"child").expect("child looked up");
    let file_entry = snapshot.lookup(&root, b"leaf").expect("leaf looked up");
    let link_entry = snapshot.lookup(&root, b"link").expect("link looked up");
    assert_eq!(node_kind_of(&snapshot, &dir_entry), Ok(NodeKind::Dir));
    assert_eq!(node_kind_of(&snapshot, &file_entry), Ok(NodeKind::File));
    assert_eq!(node_kind_of(&snapshot, &link_entry), Ok(NodeKind::Symlink));
}

// ---- read_bytes: real-content read coverage ---------------------------------------
//
// `read_bytes` had zero tests anywhere in the repo before this fixture.
// A real single-grain inline file, built the same way `granary-vfs`'s
// `read.rs`'s own `inline_fixture` does, so the fetched bytes are genuine content (not
// zeros) and a truncation or an offset slip is observable against
// actual source bytes rather than coincidentally-equal padding.

fn read_fixture() -> (GranaryFs<TestBackend>, INodeNo, Vec<u8>) {
    let content: Vec<u8> = (0_u8..40).collect();
    let grain_id = GrainId::of(&content);
    let grain_ref = GrainRef {
        id: grain_id,
        unpacked_len: u32::try_from(content.len()).expect("fixture length fits"),
    };
    let entries = [DirEntry {
        name: Name::new(b"leaf".to_vec()).expect("fixture name is valid"),
        kind: EntryKind::File {
            exec: false,
            size: u64::try_from(content.len()).expect("fixture length fits"),
            grains: FileGrains::Inline(vec![grain_ref]),
        },
    }];
    let built = build_dir(&entries).expect("fixture directory builds");
    let snapshot = Snapshot::new(
        built.nodes.into_iter().collect(),
        built.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("fixture snapshot indexes");
    let mut grains = BTreeMap::new();
    grains.insert(grain_id, content.clone());
    let backend = TestBackend {
        grains,
        shutdown_calls: Arc::new(AtomicUsize::new(0)),
        readiness_calls: Arc::default(),
        drop_closes: Arc::new(AtomicUsize::new(0)),
        disarmed: false,
    };
    let fs = GranaryFs::new(snapshot, backend, 1, crate::MountWritability::ReadOnly)
        .expect("fixture snapshot admits the adapter's limits");
    let leaf = fs
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .expect("leaf resolves");
    (fs, INodeNo(leaf.ino), content)
}

#[test]
fn read_bytes_matches_source_for_whole_file_and_offset_and_refuses_a_non_file_ino() {
    let (fs, leaf_ino, content) = read_fixture();

    let whole = fs
        .read_bytes(leaf_ino, 0, u32::try_from(content.len()).expect("fits"))
        .map_err(super::ReplyError::errno)
        .expect("a whole-file read succeeds");
    assert_eq!(
        whole, content,
        "a whole-file read must return exactly the source bytes (trap T7: never reply short)"
    );

    // A genuine sub-range, distinct from the whole-file case above and
    // large enough (7 of 40 bytes, starting past the front) that a
    // mutation only affecting the OFFSET path cannot hide behind
    // coincidental agreement with offset 0.
    let offset = 10_u64;
    let want = 7_u32;
    let start = usize::try_from(offset).expect("fits");
    let end = start + usize::try_from(want).expect("fits");
    let partial = fs
        .read_bytes(leaf_ino, offset, want)
        .map_err(super::ReplyError::errno)
        .expect("an offset read succeeds");
    assert_eq!(
        partial,
        content[start..end],
        "an offset read must return exactly the requested slice of the source, \
         not the whole file and not some other slice"
    );

    assert_eq!(
        fs.read_bytes(INodeNo::ROOT, 0, 10)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EIO),
        "a non-file ino must answer EIO (ReaderError::Inconsistent), not an empty Ok"
    );
}

#[cfg(feature = "conformance-breakage")]
#[test]
fn read_bytes_truncates_a_read_that_covers_the_final_byte_when_breakage_is_armed() {
    let (mut fs, leaf_ino, content) = read_fixture();
    fs.set_breakage(crate::Breakage::TruncateRead);

    let whole = fs
        .read_bytes(leaf_ino, 0, u32::try_from(content.len()).expect("fits"))
        .map_err(super::ReplyError::errno)
        .expect("a whole-file read still succeeds");
    assert_eq!(
        whole,
        content[..content.len() - 1],
        "a read whose range covers the final byte must come back one byte short"
    );

    // A read that does NOT reach the final byte must stay honest —
    // this is what keeps TruncateRead classified as `content` rather
    // than something that also disturbs unrelated reads.
    let front = fs
        .read_bytes(leaf_ino, 0, 5)
        .map_err(super::ReplyError::errno)
        .expect("a front-only read succeeds");
    assert_eq!(
        front,
        content[..5],
        "a read that does not cover the final byte must not be touched"
    );
}

// ---- opendir_handle: directory-handle kind ------------------------------------
//
// `opendir_handle` had zero tests anywhere in the repo before this one.
// The property that matters is the one `releasedir` depends on:
// `HandleTable::release`'s documented no-op on a kind mismatch means a
// one-word `HandleKind::Directory` -> `HandleKind::File` slip here is a
// PERMANENT inode-row leak on every directory open, because
// `releasedir` always releases with `HandleKind::Directory` and would
// then never find a match.

#[test]
fn opendir_handle_registers_a_directory_handle_that_releasedir_reclaims() {
    let (fs, _) = fixture_fs();
    let child = fs
        .lookup_entry(INodeNo::ROOT, b"child")
        .map_err(super::ReplyError::errno)
        .expect("child resolves");
    let fh = fs
        .opendir_handle(INodeNo(child.ino))
        .map_err(super::ReplyError::errno)
        .expect("opendir succeeds");
    // Drop the lookup credit so residency below reflects ONLY the
    // handle opendir_handle just registered.
    let _ = fs.with_inner(|inner| {
        inner.inodes.forget(child.ino, 1);
        Ok(())
    });
    let resolves = || {
        fs.with_inner(|inner| inner.inodes.resolve(child.ino).map(|_| ()))
            .is_ok()
    };
    assert!(
        resolves(),
        "a live directory handle must keep the inode resident at nlookup == 0"
    );

    // `releasedir`'s own call shape (filesystem.rs's `Filesystem::releasedir`):
    // always `HandleKind::Directory`, never the raw ino.
    fs.release_handle(fh, HandleKind::Directory)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert!(
        !resolves(),
        "releasedir must release the handle opendir registered; a kind mismatch leaks \
         the inode row permanently"
    );
}

// ---- lookup_entry on a wide directory: parent root versus entry leaf ------------------
//
// Every OTHER fixture in this module is a single-leaf directory, where
// `Snapshot::lookup`'s returned `Entry.leaf` (the B-tree LEAF an entry
// was found in) coincides with the directory's own ROOT node, so a
// `dir`/`entry.leaf` mix-up in `lookup_entry` is invisible. A directory
// wide enough to span more than one B-tree leaf (`DIR_LEAF_MAX_ENTRIES`
// is 256) is what makes the two diverge.

fn wide_dir_fixture() -> (GranaryFs<TestBackend>, GrainId, Vec<u8>) {
    let names: Vec<Vec<u8>> = (0_u32..600)
        .map(|i| format!("f{i:04}").into_bytes())
        .collect();
    let entries: Vec<DirEntry> = names.iter().map(|name| file(name)).collect();
    let built = build_dir(&entries).expect("wide fixture directory builds");
    let snapshot = Snapshot::new(
        built.nodes.into_iter().collect(),
        built.root,
        Timestamp { secs: 1, nanos: 2 },
        TreeStats::default(),
        AttrPolicy { uid: 3, gid: 4 },
        FUSE_SERVE_LIMITS,
    )
    .expect("wide fixture snapshot indexes");
    let fs = GranaryFs::new(
        snapshot,
        TestBackend::default(),
        1,
        crate::MountWritability::ReadOnly,
    )
    .expect("wide fixture snapshot admits the adapter's limits");
    (fs, built.root, names[0].clone())
}

#[test]
fn lookup_entry_records_the_wide_directorys_root_not_the_btree_leaf_it_found_the_child_in() {
    let (fs, root, name) = wide_dir_fixture();

    // Executed proof, not merely reasoned: on THIS fixture the leaf a
    // name is found in really does differ from the directory's own
    // root.
    let direct = fs
        .snapshot
        .lookup(&root, &name)
        .expect("direct lookup of the wide-dir child succeeds");
    assert_ne!(
        direct.leaf, root,
        "fixture precondition: a 600-entry directory must span more than one B-tree \
         leaf, or entry.leaf coincides with the root and this test cannot distinguish \
         the bug from correct code"
    );

    // The lookup_entry -> getattr_attr round trip: both must agree on
    // the same child, same as every other lookup_entry test in this
    // module already checks. This assertion passes REGARDLESS of the
    // dir/entry.leaf mix-up: resolve_own_entry always re-looks-up the
    // SAME name in whichever node the row records (leaf or root), and
    // that node contains the same manifest entry either way, so
    // getattr_attr cannot observe the corruption. It is included for
    // parity with the rest of this module, not as the kill.
    let attr = fs
        .lookup_entry(INodeNo::ROOT, &name)
        .map_err(super::ReplyError::errno)
        .expect("wide-dir child resolves");
    let via_getattr = fs
        .getattr_attr(INodeNo(attr.ino))
        .map_err(super::ReplyError::errno)
        .expect("getattr on the freshly looked-up child resolves");
    assert_eq!(
        via_getattr, attr,
        "lookup_entry and getattr_attr must report identical attributes for the same child"
    );

    // The actual kill: the child's inode-table row must record the
    // DIRECTORY ROOT it lives in — what `dir_and_parent` hands back as
    // the node this child's OWN children's ".." is synthesised from —
    // not the B-tree leaf `Snapshot::lookup` happened to descend to.
    let recorded_dir = fs
        .with_inner(|inner| inner.inodes.resolve(attr.ino).map(|(_, dir, _)| dir))
        .expect("child row exists");
    assert_eq!(
        recorded_dir, root,
        "the child's recorded `dir` field must be the wide directory's own root, not \
         the B-tree leaf its entry happened to be found in"
    );
}

#[test]
fn writable_init_wire_reply_never_enables_offered_writeback() {
    use fuser::{InitFlags, Session, SessionACL};
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;
    let mut cases = 0;
    for offered in [
        InitFlags::FUSE_DO_READDIRPLUS,
        InitFlags::FUSE_DO_READDIRPLUS | InitFlags::FUSE_WRITEBACK_CACHE,
    ] {
        let (daemon, mut kernel) = UnixStream::pair().unwrap();
        kernel
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&56u32.to_ne_bytes());
        frame.extend_from_slice(&26u32.to_ne_bytes()); // FUSE_INIT
        frame.extend_from_slice(&1u64.to_ne_bytes());
        frame.extend_from_slice(&0u64.to_ne_bytes());
        for _ in 0..4 {
            frame.extend_from_slice(&0u32.to_ne_bytes());
        }
        for value in [7u32, 31, 4096, u32::try_from(offered.bits()).unwrap()] {
            frame.extend_from_slice(&value.to_ne_bytes());
        }
        kernel.write_all(&frame).unwrap();
        let (filesystem, _) = fixture_fs();
        let session = Session::from_fd(
            filesystem,
            daemon.into(),
            SessionACL::Owner,
            crate::writable_session_config(),
        )
        .unwrap();
        let mut header = [0u8; 16];
        kernel.read_exact(&mut header).unwrap();
        let length = u32::from_ne_bytes(header[0..4].try_into().unwrap()) as usize;
        assert_eq!(i32::from_ne_bytes(header[4..8].try_into().unwrap()), 0);
        let mut reply = vec![0; length - 16];
        kernel.read_exact(&mut reply).unwrap();
        let flags = u32::from_ne_bytes(reply[12..16].try_into().unwrap());
        assert_ne!(
            flags & u32::try_from(InitFlags::FUSE_DO_READDIRPLUS.bits()).unwrap(),
            0
        );
        assert_eq!(
            flags & u32::try_from(InitFlags::FUSE_WRITEBACK_CACHE.bits()).unwrap(),
            0,
            "negotiated INIT reply must exclude writeback even when offered"
        );
        drop(session);
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// A dirty-only mode function and an option-derived policy both fail this row.
#[test]
fn writable_modes_cover_lookup_getattr_and_directory_plus_reply_sites() {
    for (writability, directory, file_mode) in [
        (crate::MountWritability::ReadOnly, 0o555, 0o444),
        (crate::MountWritability::Writable, 0o755, 0o644),
    ] {
        let (snapshot, _) = snapshot_fixture();
        let fs = GranaryFs::new(snapshot, TestBackend::default(), 17, writability).unwrap();
        assert_eq!(
            fs.getattr_attr(INodeNo::ROOT)
                .map_err(super::ReplyError::errno)
                .unwrap()
                .perm,
            directory,
            "root mode"
        );
        for (name, expected) in [
            (b"child".as_slice(), directory),
            (b"leaf", file_mode),
            (b"link", 0o777),
        ] {
            let lookup = fs
                .lookup_entry(INodeNo::ROOT, name)
                .map_err(super::ReplyError::errno)
                .unwrap();
            let getattr = fs
                .getattr_attr(INodeNo(lookup.ino))
                .map_err(super::ReplyError::errno)
                .unwrap();
            let entry = fs
                .snapshot
                .lookup(&fs.snapshot.manifest_root(), name)
                .unwrap();
            let raw = fs.snapshot.attr_for(&entry, lookup.ino, 17).unwrap();
            let (_, plus, _) = fs.bent_reply_parts(raw, fs.mount_time);
            assert_eq!(
                (lookup.perm, getattr.perm, plus.perm),
                (expected, expected, expected),
                "all attribute reply sites"
            );
            assert_eq!(
                (lookup.uid, lookup.gid, lookup.time),
                (3, 4, Timestamp { secs: 1, nanos: 2 })
            );
        }
        let writable = writability == crate::MountWritability::Writable;
        assert_eq!(fs.ttl().is_zero(), writable);
        assert_eq!(fs.open_reply_flags(false).is_empty(), writable);
        assert_eq!(fs.open_reply_flags(true).is_empty(), writable);
        let attr = fs
            .lookup_entry(INodeNo::ROOT, b"leaf")
            .map_err(super::ReplyError::errno)
            .unwrap();
        assert_eq!(access_check(AccessFlags::W_OK, attr.perm).is_ok(), writable);
    }
}

/// Deleting the daemon RO gate must be visible without the kernel RO option.
#[test]
fn writable_refusals_precede_backend_dispatch_on_read_only_adapters() {
    for writability in [
        crate::MountWritability::ReadOnly,
        crate::MountWritability::Writable,
    ] {
        let (snapshot, _) = snapshot_fixture();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut backend = TestBackend::default();
        backend.readiness_calls = calls.clone();
        let fs = GranaryFs::new(snapshot, backend, 17, writability).unwrap();
        let ro = writability == crate::MountWritability::ReadOnly;
        let expected = if ro {
            fuser::Errno::EROFS
        } else {
            fuser::Errno::ENOTSUP
        };
        let mut cases = 0;
        for callback in [
            crate::Callback::Link,
            crate::Callback::Setxattr,
            crate::Callback::Removexattr,
        ] {
            assert_eq!(
                fs.completed(callback, fs.refused_mutation()),
                Err(expected),
                "{callback:?}"
            );
            cases += 1;
        }
        for mode in [0o010_000, 0o020_000, 0o060_000, 0o140_000] {
            assert_eq!(
                fs.node_refusal(mode).map_err(super::ReplyError::errno),
                Err(expected),
                "special node {mode:o}"
            );
            cases += 1;
        }
        for flags in [2, 4] {
            assert_eq!(
                fs.rename_refusal(flags).map_err(super::ReplyError::errno),
                Err(expected),
                "rename flags {flags}"
            );
            cases += 1;
        }
        for flags in [3, 5, 6, 7, 8, u32::MAX] {
            assert_eq!(
                fs.rename_refusal(flags).map_err(super::ReplyError::errno),
                Err(if ro { expected } else { fuser::Errno::EINVAL })
            );
            cases += 1;
        }
        assert_eq!(
            (cases, calls.load(Ordering::SeqCst)),
            (15, if ro { 0 } else { 15 })
        );
        let leaf = fs
            .lookup_entry(INodeNo::ROOT, b"leaf")
            .map_err(super::ReplyError::errno)
            .unwrap();
        assert_eq!(
            fs.setattr_result(INodeNo(leaf.ino), None, Some(7), true, None)
                .map_err(super::ReplyError::errno)
                .map(|a| a.size),
            Err(expected),
            "mixed setattr must refuse before size"
        );
        assert_eq!(
            fs.getattr_attr(INodeNo(leaf.ino))
                .map_err(super::ReplyError::errno)
                .unwrap()
                .size,
            0
        );
        assert_eq!(
            fs.xattr_query(INodeNo(leaf.ino), Some(std::ffi::OsStr::new("user.x")), 0)
                .map_err(super::ReplyError::errno),
            Err(if ro {
                fuser::Errno::NO_XATTR
            } else {
                fuser::Errno::ENOTSUP
            })
        );
        assert_eq!(
            fs.xattr_query(INodeNo(leaf.ino), None, 0)
                .map_err(super::ReplyError::errno),
            if ro {
                Ok(super::XattrReply::Size(0))
            } else {
                Err(fuser::Errno::ENOTSUP)
            }
        );
    }
}

/// Pure synchronous reads stay no-effect; write-intent opens and creates admit
/// and retain synchronous flags on writable mounts while RO stays refused.
#[test]
fn writable_synchronous_flags_are_scoped_to_write_intent_and_create() {
    #[cfg(target_os = "linux")]
    let (file_sync, data_sync) = (0x0010_1000, 0x1000);
    #[cfg(target_os = "macos")]
    let (file_sync, data_sync) = (0x80, 0x0040_0000);
    assert_eq!(
        (
            super::synchronous_datasync(fuser::OpenFlags(0)),
            super::synchronous_datasync(fuser::OpenFlags(file_sync)),
            super::synchronous_datasync(fuser::OpenFlags(data_sync)),
            super::synchronous_datasync(fuser::OpenFlags(file_sync | data_sync)),
        ),
        (None, Some(false), Some(true), Some(false)),
        "O_SYNC must classify as file sync before O_DSYNC data sync"
    );
    for writability in [
        crate::MountWritability::ReadOnly,
        crate::MountWritability::Writable,
    ] {
        let (snapshot, _) = snapshot_fixture();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut backend = TestBackend::default();
        backend.readiness_calls = calls.clone();
        let fs = GranaryFs::new(snapshot, backend, 17, writability).unwrap();
        let ino = INodeNo(
            fs.lookup_entry(INodeNo::ROOT, b"leaf")
                .map_err(super::ReplyError::errno)
                .unwrap()
                .ino,
        );
        for sync in [file_sync, data_sync] {
            let fh = fs
                .open_flags_handle(ino, fuser::OpenFlags(sync))
                .map_err(super::ReplyError::errno)
                .expect("pure synchronous read ignores the flag");
            fs.release_handle(fh, HandleKind::File)
                .map_err(super::ReplyError::errno)
                .unwrap();
            for mode in [1, 2] {
                let opened = fs
                    .open_flags_handle(ino, fuser::OpenFlags(sync | mode))
                    .map_err(super::ReplyError::errno);
                if writability == crate::MountWritability::ReadOnly {
                    assert_eq!(opened, Err(fuser::Errno::EACCES));
                } else {
                    let fh = opened.expect("writable mount admits synchronous write open");
                    let retained = fs
                        .write_inner(|inner| Ok(inner.write_handles.get(&u64::from(fh)).copied()))
                        .unwrap();
                    assert_eq!(retained, Some(fuser::OpenFlags(sync | mode)));
                    fs.release_handle(fh, HandleKind::File)
                        .map_err(super::ReplyError::errno)
                        .unwrap();
                }
            }
            // Create mutates even when its requested access mode is read-only.
            assert_eq!(
                fs.create_overlay(
                    INodeNo::ROOT,
                    b"new",
                    NodeKind::File,
                    0o644,
                    Some(fuser::OpenFlags(sync))
                )
                .map_err(super::ReplyError::errno)
                .map(|_| ()),
                Err(if writability == crate::MountWritability::ReadOnly {
                    fuser::Errno::EROFS
                } else {
                    fuser::Errno::ENOSYS
                })
            );
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            if writability == crate::MountWritability::ReadOnly {
                0
            } else {
                6
            }
        );
    }
}

#[derive(Debug, Default)]
struct Replies(
    Mutex<Vec<(crate::Callback, crate::CallbackOutcome)>>,
    Mutex<Vec<(i32, i32)>>,
);
impl crate::CallbackObserver for Replies {
    fn begin(&self, _callback: crate::Callback) -> Option<Box<dyn crate::CallbackScope>> {
        None
    }
    fn completed(&self, callback: crate::Callback, result: crate::CallbackOutcome) {
        self.0.lock().unwrap().push((callback, result));
    }
    fn write_flags_for_test(&self, request_flags: i32, retained_flags: i32) {
        self.1.lock().unwrap().push((request_flags, retained_flags));
    }
}

/// Counting at an offer, frame or syscall instead of the terminal reply fails this row.
#[test]
fn writable_terminal_completions_count_once_and_preserve_release_failures() {
    let (mut fs, _) = fixture_fs();
    let observer = Arc::new(Replies::default());
    fs.observer = Some(observer.clone());
    for callback in crate::Callback::ALL {
        assert_eq!(fs.unimplemented(*callback), Err(fuser::Errno::ENOSYS));
    }
    assert_eq!(observer.0.lock().unwrap().len(), 40);
    assert!(
        observer
            .0
            .lock()
            .unwrap()
            .iter()
            .all(|(_, result)| *result == crate::CallbackOutcome::Refused)
    );
    let fh = fs
        .open_handle(INodeNo::ROOT, OpenAccMode::O_RDONLY)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        fs.completed(
            crate::Callback::Release,
            fs.release_handle(fh, HandleKind::File)
        ),
        Ok(())
    );
    let mut inner = fs.inner.lock().unwrap();
    *inner = None;
    drop(inner);
    assert_eq!(
        fs.completed(
            crate::Callback::Release,
            fs.release_handle(fh, HandleKind::File)
        ),
        Err(fuser::Errno::EIO)
    );
    assert_eq!(
        observer.0.lock().unwrap().last(),
        Some(&(
            crate::Callback::Release,
            crate::CallbackOutcome::Failed(crate::MountError::Io)
        ))
    );
}

#[test]
fn writable_metadata_refusals_preserve_content_and_canonical_noops() {
    let (snapshot, _) = snapshot_fixture();
    let fs = GranaryFs::new(
        snapshot,
        TestBackend::default(),
        17,
        crate::MountWritability::Writable,
    )
    .unwrap();
    let ino = INodeNo(
        fs.lookup_entry(INodeNo::ROOT, b"leaf")
            .map_err(super::ReplyError::errno)
            .unwrap()
            .ino,
    );
    for mode in [0o600, 0o444, 0o655, 0o4644, 0o1644, u32::MAX] {
        assert_eq!(
            fs.setattr_result(ino, Some(mode), Some(9), false, None)
                .map_err(super::ReplyError::errno)
                .map(|a| a.size),
            Err(fuser::Errno::ENOTSUP)
        );
    }
    assert_eq!(
        fs.setattr_result(ino, Some(0o644), None, false, None)
            .map_err(super::ReplyError::errno)
            .map(|a| (a.perm, a.size)),
        Ok((0o644, 0))
    );
    assert_eq!(
        fs.setattr_result(ino, None, None, false, None)
            .map_err(super::ReplyError::errno)
            .map(|a| a.size),
        Ok(0)
    );
    assert_eq!(
        fs.node_refusal(0).map_err(super::ReplyError::errno),
        Err(fuser::Errno::EINVAL)
    );
    assert_eq!(
        fs.node_refusal(0o040_000).map_err(super::ReplyError::errno),
        Err(fuser::Errno::EINVAL)
    );
}

#[derive(Debug, Default, Clone, Copy)]
enum ChildReply {
    #[default]
    Valid,
    MissingName,
    WrongParent,
    Nested,
    Repeated,
    Descending,
    EmptyContinuation,
    WrongLookup,
    ExtraDirectoryCopy,
}

#[derive(Debug, Default)]
struct MutableBackend {
    nodes: BTreeMap<Vec<Name>, crate::OverlayNode>,
    bind_objects: bool,
    objects: BTreeMap<u64, (crate::OverlayNode, u64)>,
    next_object: u64,
    closes: Vec<u64>,
    close_failure: bool,
    detach_error: Option<crate::MountError>,
    detach_preparations: usize,
    targets: BTreeMap<Vec<Name>, Vec<u8>>,
    calls: Vec<&'static str>,
    sync_objects: Vec<u64>,
    sync_error: Option<crate::MountSyncError>,
    pending_syncs: Option<sync::PendingSyncs>,
    shrink_requests: Vec<crate::MountShrinkRequest>,
    prepare_probe: Option<std::sync::Weak<GranaryFs<Self>>>,
    prepare_count: usize,
    probe_count: usize,
    prepare_panic: bool,
    prepare_hook: Option<view::PrepareHook>,
    capacity: crate::OverlayCapacity,
    capacity_calls: usize,
    view_calls: usize,
    path_queries: usize,
    open_queries: usize,
    bound_setattrs: usize,
    path_setattrs: usize,
    shrink_floor: u64,
    page_calls: usize,
    copied_child_rows: usize,
    attempt_child_rows: Vec<usize>,
    attempt_copy_starts: Vec<usize>,
    page_changes: usize,
    child_reply: ChildReply,
    view_error: Option<crate::WriteError>,
    failure: Option<(&'static str, crate::MountError)>,
    failures_seen: usize,
    abandoned: Arc<AtomicUsize>,
    lookup_queries: usize,
    view_boundary: Option<Arc<dyn crate::ViewBoundary>>,
}
impl GrainFetch for MutableBackend {
    fn grain(&mut self, _: &GrainId, _: u32) -> Result<Vec<u8>, GrainUnavailable> {
        Err(GrainUnavailable::new("unused mutable fixture"))
    }
}
impl MutableBackend {
    fn inject(&mut self, site: &'static str) -> Result<(), crate::MountError> {
        if let Some((at, cause)) = self.failure
            && at == site
        {
            self.failures_seen += 1;
            return Err(cause);
        }
        Ok(())
    }
}
impl MountBackend for MutableBackend {
    type DirectoryCursor = crate::test_queries::Cursor;
    fn overlay_path(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<crate::OverlayMetadata, crate::WriteError> {
        self.path_queries += 1;
        self.inject("overlay_path")
            .map_err(crate::WriteError::Backend)?;
        if let Some(error) = self.view_error {
            return Err(error);
        }
        crate::test_queries::path(&self.nodes, path)
    }
    fn overlay_lookup(
        &mut self,
        parent: &[granary_core::manifest::Name],
        name: &granary_core::manifest::Name,
    ) -> Result<crate::OverlayMetadata, crate::WriteError> {
        self.lookup_queries += 1;
        self.inject("overlay_lookup")
            .map_err(crate::WriteError::Backend)?;
        if let Some(error) = self.view_error {
            return Err(error);
        }
        let mut row = crate::test_queries::lookup(&self.nodes, parent, name)?;
        if matches!(self.child_reply, ChildReply::WrongLookup) {
            row.node.path = vec![Name::new(b"other".to_vec()).unwrap()];
        }
        Ok(row)
    }
    fn overlay_directory(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<crate::OverlayDirectory<Self::DirectoryCursor>, crate::WriteError> {
        self.inject("overlay_directory")
            .map_err(crate::WriteError::Backend)?;
        if let Some(error) = self.view_error {
            return Err(error);
        }
        self.attempt_copy_starts.push(crate::source::entry_copies());
        let directory = crate::test_queries::directory(&self.nodes, path)?;
        if matches!(self.child_reply, ChildReply::ExtraDirectoryCopy) {
            let _extra = directory.directory.node.clone();
        }
        self.attempt_child_rows.push(0);
        Ok(directory)
    }
    fn overlay_children(
        &mut self,
        cursor: &Self::DirectoryCursor,
    ) -> Result<crate::OverlayChildren<Self::DirectoryCursor>, crate::WriteError> {
        self.inject("overlay_children")
            .map_err(crate::WriteError::Backend)?;
        if let Some(error) = self.view_error {
            return Err(error);
        }
        self.page_calls += 1;
        if cursor.1.is_some() && self.page_changes > 0 {
            self.page_changes -= 1;
            return Err(crate::WriteError::Backend(
                crate::MountError::PlanningExhausted,
            ));
        }
        let mut page = crate::test_queries::children(&self.nodes, cursor)?;
        self.copied_child_rows += page.entries.len();
        if let Some(rows) = self.attempt_child_rows.last_mut() {
            *rows += page.entries.len();
        }
        if matches!(self.child_reply, ChildReply::MissingName)
            && let Some(child) = page.entries.first_mut()
        {
            child.node.path.clear();
        }
        match self.child_reply {
            ChildReply::WrongParent => {
                if let Some(child) = page.entries.first_mut() {
                    child
                        .node
                        .path
                        .insert(0, Name::new(b"other".to_vec()).unwrap());
                }
            }
            ChildReply::Nested => {
                if let Some(child) = page.entries.first_mut() {
                    child.node.path.push(Name::new(b"nested".to_vec()).unwrap());
                }
            }
            ChildReply::Repeated if cursor.1.is_some() => {
                if let Some(child) = page.entries.first_mut() {
                    child.node.path = vec![Name::new(b"child-0000".to_vec()).unwrap()];
                }
            }
            ChildReply::Descending if page.entries.len() >= 2 => {
                page.entries.swap(0, 1);
            }
            ChildReply::EmptyContinuation if self.page_calls == 1 => {
                page.entries.clear();
                page.next = Some(cursor.clone());
            }
            _ => (),
        }
        Ok(page)
    }

    fn mutation_readiness(&mut self) -> Result<(), crate::MountError> {
        self.inject("mutation_readiness")?;
        Ok(())
    }
    fn overlay_nodes(&mut self) -> Result<Vec<crate::OverlayNode>, crate::WriteError> {
        self.inject("overlay_nodes")
            .map_err(crate::WriteError::Backend)?;
        self.view_calls += 1;
        if let Some(error) = self.view_error {
            return Err(error);
        }
        Ok(self.nodes.values().cloned().collect())
    }
    fn overlay_capacity(&mut self) -> Result<crate::OverlayCapacity, crate::WriteError> {
        self.inject("overlay_capacity")
            .map_err(crate::WriteError::Backend)?;
        self.capacity_calls += 1;
        if let Some(error) = self.view_error {
            return Err(error);
        }
        Ok(self.capacity)
    }
    fn overlay_readlink(&mut self, path: &[Name]) -> Result<Vec<u8>, crate::WriteError> {
        self.inject("overlay_readlink")
            .map_err(crate::WriteError::Backend)?;
        if let Some(error) = self.view_error {
            return Err(error);
        }
        self.targets
            .get(path)
            .cloned()
            .ok_or(crate::WriteError::Missing)
    }
    fn prepare_shrink_retry(
        &mut self,
        request: crate::MountShrinkRequest,
    ) -> Result<Box<dyn crate::MountSyncJob>, crate::MountSyncError> {
        self.shrink_requests.push(request);
        Ok(Box::new(sync::Job))
    }

    fn prepare_sync(
        &mut self,
        request: crate::MountSyncRequest,
    ) -> Result<Box<dyn crate::MountSyncJob>, crate::MountSyncError> {
        if let crate::MountSyncRequest::File { object, .. } = &request {
            self.sync_objects.push(*object);
        }
        self.calls.push(match request {
            crate::MountSyncRequest::File {
                datasync: false, ..
            } => "fsync",
            crate::MountSyncRequest::File { datasync: true, .. } => "fdatasync",
            crate::MountSyncRequest::Directory { .. } => "fsyncdir",
        });
        if let Some(pending) = &self.pending_syncs {
            return Ok(Box::new(sync::DeferredJob(pending.clone())));
        }
        if let Some(error) = self.sync_error {
            return Ok(Box::new(sync::FailingJob(error)));
        }
        Ok(Box::new(sync::Job))
    }

    fn overlay_open(&mut self, path: &[Name]) -> Result<Option<u64>, crate::WriteError> {
        self.open_queries += 1;
        self.inject("overlay_open")
            .map_err(crate::WriteError::Backend)?;
        if !self.bind_objects {
            return Ok(None);
        }
        let node = self.nodes.get_mut(path).ok_or(crate::WriteError::Missing)?;
        let id = if let Some(id) = node.stage {
            id
        } else {
            self.next_object += 1;
            node.stage = Some(self.next_object);
            self.next_object
        };
        let object = self.objects.entry(id).or_insert((node.clone(), 0));
        object.1 += 1;
        Ok(Some(id))
    }
    fn overlay_object(&mut self, id: u64) -> Result<crate::OverlayNode, crate::WriteError> {
        self.inject("overlay_object")
            .map_err(crate::WriteError::Backend)?;
        let object = self
            .objects
            .get_mut(&id)
            .ok_or(crate::WriteError::Missing)?;
        if let Some(node) = self.nodes.values().find(|n| n.stage == Some(id)) {
            object.0 = node.clone();
        }
        Ok(object.0.clone())
    }
    fn prepare_object(&mut self, id: u64) -> Result<(), crate::WriteError> {
        self.inject("prepare_object")
            .map_err(crate::WriteError::Backend)?;
        let node = self.overlay_object(id)?;
        self.prepare_overlay(&node.path)
    }
    fn read_object(
        &mut self,
        id: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, crate::WriteError> {
        self.inject("read_object")
            .map_err(crate::WriteError::Backend)?;
        let node = self.overlay_object(id)?;
        Ok(vec![
            b'Z';
            usize::try_from(
                node.size.saturating_sub(offset).min(length as u64)
            )
            .unwrap()
        ])
    }
    fn overlay_close(&mut self, id: u64) -> Result<(), crate::WriteError> {
        self.inject("overlay_close")
            .map_err(crate::WriteError::Backend)?;
        let object = self
            .objects
            .get_mut(&id)
            .ok_or(crate::WriteError::Missing)?;
        object.1 -= 1;
        if object.1 == 0 {
            self.objects.remove(&id);
        }
        self.closes.push(id);
        if self.close_failure {
            Err(crate::WriteError::Backend(crate::MountError::Io))
        } else {
            Ok(())
        }
    }
    fn prepare_detach(&mut self, _path: &[Name]) -> Result<(), crate::WriteError> {
        self.inject("prepare_detach")
            .map_err(crate::WriteError::Backend)?;
        self.detach_preparations += 1;
        if let Some(error) = self.detach_error {
            Err(crate::WriteError::Backend(error))
        } else {
            Ok(())
        }
    }
    fn prepare_overlay(&mut self, _path: &[Name]) -> Result<(), crate::WriteError> {
        self.inject("prepare_overlay")
            .map_err(crate::WriteError::Backend)?;
        self.prepare_count += 1;
        if let Some(fs) = self
            .prepare_probe
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            self.probe_count += 1;
            let state = fs
                .inner
                .try_lock()
                .expect("network preparation retained adapter gate");
            assert!(
                state.is_none(),
                "planning must own the unavailable state exclusively"
            );
        }
        if let Some(hook) = &self.prepare_hook {
            (hook.0)();
        }
        assert!(!self.prepare_panic, "fixture preparation panic");
        Ok(())
    }
    fn overlay_setattr(
        &mut self,
        path: &[granary_core::manifest::Name],
        size: Option<u64>,
        exec: Option<bool>,
    ) -> Result<crate::OverlayMetadata, crate::WriteError> {
        self.path_setattrs += 1;
        if size.is_some_and(|size| size < self.shrink_floor) {
            return Err(crate::WriteError::PendingShrink);
        }
        if size.is_some() {
            self.prepare_overlay(path)?;
        }
        self.overlay_mutate(crate::OverlayMutation::Setattr { path, size, exec })?;
        self.overlay_path(path)
    }
    fn overlay_mutate(
        &mut self,
        operation: crate::OverlayMutation<'_>,
    ) -> Result<(), crate::WriteError> {
        use crate::OverlayMutation as M;
        self.inject("overlay_mutate")
            .map_err(crate::WriteError::Backend)?;
        match operation {
            M::BoundWrite {
                object,
                offset,
                bytes,
                append,
            } => {
                let mut node = self.overlay_object(object)?;
                node.size = node
                    .size
                    .max(if append { node.size } else { offset } + bytes.len() as u64);
                if let Some(live) = self.nodes.values_mut().find(|n| n.stage == Some(object)) {
                    live.size = node.size;
                }
                self.objects.get_mut(&object).unwrap().0 = node;
                self.calls.push("write");
            }
            M::BoundSetattr { object, size, exec } => {
                self.bound_setattrs += 1;
                if size.is_some_and(|size| size < self.shrink_floor) {
                    return Err(crate::WriteError::PendingShrink);
                }
                let mut node = self.overlay_object(object)?;
                if let Some(size) = size {
                    node.size = size;
                }
                if let Some(exec) = exec {
                    node.exec = exec;
                }
                if let Some(live) = self.nodes.values_mut().find(|n| n.stage == Some(object)) {
                    *live = node.clone();
                }
                self.objects.get_mut(&object).unwrap().0 = node;
                self.calls.push("setattr");
            }
            M::Symlink { path, target } => {
                self.calls.push("symlink");
                self.targets
                    .insert(path.to_vec(), target.as_bytes().to_vec());
                self.nodes.insert(
                    path.to_vec(),
                    crate::OverlayNode {
                        path: path.to_vec(),
                        kind: NodeKind::Symlink,
                        size: u64::from(target.wire_len()),
                        exec: false,
                        stage: None,
                    },
                );
            }
            M::Create { path, kind, exec } => {
                self.calls.push("create");
                self.nodes.insert(
                    path.to_vec(),
                    crate::OverlayNode {
                        path: path.to_vec(),
                        kind,
                        size: if kind == NodeKind::Dir { 4096 } else { 0 },
                        exec,
                        stage: None,
                    },
                );
            }
            M::Write {
                path,
                offset,
                bytes,
                append,
            } => {
                self.calls.push("write");
                let node = self.nodes.get_mut(path).ok_or(crate::WriteError::Missing)?;
                node.size = node
                    .size
                    .max(if append { node.size } else { offset } + bytes.len() as u64);
            }
            M::Setattr { path, size, exec } => {
                self.calls.push("setattr");
                let node = self.nodes.get_mut(path).ok_or(crate::WriteError::Missing)?;
                if let Some(size) = size {
                    node.size = size;
                }
                if let Some(exec) = exec {
                    node.exec = exec;
                }
            }
            M::Remove { path, .. } => {
                self.calls.push("remove");
                self.nodes.remove(path).ok_or(crate::WriteError::Missing)?;
            }
            M::Rename { from, to, .. } => {
                self.calls.push("rename");
                let mut node = self.nodes.remove(from).ok_or(crate::WriteError::Missing)?;
                node.path = to.to_vec();
                self.nodes.insert(to.to_vec(), node);
            }
        }
        Ok(())
    }
    fn view_boundary(&self) -> Option<Arc<dyn crate::ViewBoundary>> {
        self.view_boundary.clone()
    }
    fn shutdown(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn abandon(&mut self) {
        self.abandoned.fetch_add(1, Ordering::SeqCst);
    }
}
fn mutable_adapter(writable: bool) -> GranaryFs<MutableBackend> {
    mutable_adapter_over(MutableBackend::default(), writable)
}
/// The adapter over `backend`, its overlay holding only the root.
fn mutable_adapter_over(backend: MutableBackend, writable: bool) -> GranaryFs<MutableBackend> {
    let (snapshot, _) = snapshot_fixture();
    let root = crate::OverlayNode {
        path: Vec::new(),
        kind: NodeKind::Dir,
        size: 4096,
        exec: false,
        stage: None,
    };
    let backend = MutableBackend {
        nodes: [(Vec::new(), root)].into_iter().collect(),
        ..backend
    };
    GranaryFs::new(
        snapshot,
        backend,
        17,
        if writable {
            crate::MountWritability::Writable
        } else {
            crate::MountWritability::ReadOnly
        },
    )
    .unwrap()
}
#[expect(
    clippy::too_many_lines,
    reason = "each callback shares the same mediated dispatch witness and RO control"
)]
fn callback_control(operation: &str) {
    for writable in [true, false] {
        let fs = mutable_adapter(writable);
        let (ino, fh) = if matches!(
            operation,
            "write" | "truncate" | "chmod" | "unlink" | "rename" | "rmdir"
        ) {
            // Fixture setup is identical; only the subsequent adapter policy differs.
            let (attr, fh) = if writable {
                fs.create_overlay(
                    INodeNo::ROOT,
                    b"new",
                    if operation == "rmdir" {
                        NodeKind::Dir
                    } else {
                        NodeKind::File
                    },
                    0o644,
                    if operation == "rmdir" {
                        None
                    } else {
                        Some(fuser::OpenFlags(2))
                    },
                )
                .map_err(super::ReplyError::errno)
                .unwrap()
            } else {
                let mut guard = fs.inner.lock().unwrap();
                let inner = guard.as_mut().unwrap();
                let path = vec![Name::new(b"new".to_vec()).unwrap()];
                let kind = if operation == "rmdir" {
                    NodeKind::Dir
                } else {
                    NodeKind::File
                };
                inner.backend.nodes.insert(
                    path.clone(),
                    crate::OverlayNode {
                        path,
                        kind,
                        size: if kind == NodeKind::Dir { 4096 } else { 0 },
                        exec: false,
                        stage: None,
                    },
                );
                let (ino, _) = inner
                    .inodes
                    .lookup(vec![b"new".to_vec()], fs.snapshot.manifest_root(), kind)
                    .unwrap();
                let fh = inner.handles.open(ino, HandleKind::File).unwrap();
                inner.inodes.open(ino).unwrap();
                inner.write_handles.insert(fh, fuser::OpenFlags(2));
                (fs.node_attr_for_test(ino), Some(fuser::FileHandle(fh)))
            };
            (INodeNo(attr.ino), fh)
        } else {
            (INodeNo::ROOT, None)
        };
        let (before, count) = {
            let guard = fs.inner.lock().unwrap();
            let inner = guard.as_ref().unwrap();
            (inner.backend.nodes.clone(), inner.backend.calls.len())
        };
        let result = match operation {
            "create" | "mknod" => fs
                .create_overlay(
                    INodeNo::ROOT,
                    b"new",
                    NodeKind::File,
                    0o755,
                    (operation == "create").then_some(fuser::OpenFlags(2)),
                )
                .map_err(super::ReplyError::errno)
                .map(|(attr, fh)| {
                    assert_eq!(
                        (attr.perm, attr.kind, fh.is_some()),
                        (0o755, NodeKind::File, operation == "create")
                    );
                }),
            "mkdir" => fs
                .create_overlay(INodeNo::ROOT, b"new", NodeKind::Dir, 0o700, None)
                .map_err(super::ReplyError::errno)
                .map(|(attr, _)| {
                    assert_eq!((attr.perm, attr.kind), (0o755, NodeKind::Dir));
                }),
            "write" => fs
                .write_overlay(ino, fh.unwrap(), 3, b"Z")
                .map_err(super::ReplyError::errno)
                .map(|count| assert_eq!(count, 1)),
            "truncate" => fs
                .setattr_result(ino, None, Some(8), false, fh)
                .map_err(super::ReplyError::errno)
                .map(|attr| assert_eq!(attr.size, 8)),
            "chmod" => fs
                .setattr_result(ino, Some(0o755), None, false, None)
                .map_err(super::ReplyError::errno)
                .map(|attr| assert_eq!(attr.perm, 0o755)),
            "unlink" => fs
                .remove_overlay(INodeNo::ROOT, b"new", false)
                .map_err(super::ReplyError::errno),
            "rmdir" => fs
                .remove_overlay(INodeNo::ROOT, b"new", true)
                .map_err(super::ReplyError::errno),
            "rename" => fs
                .rename_overlay(INodeNo::ROOT, b"new", INodeNo::ROOT, b"moved", 0)
                .map_err(super::ReplyError::errno),
            _ => panic!("unknown callback fixture"),
        };
        let guard = fs.inner.lock().unwrap();
        let inner = guard.as_ref().unwrap();
        if writable {
            assert_eq!(
                (result, inner.backend.calls.len() - count),
                (Ok(()), 1),
                "{operation}: missing or misrouted mediated dispatch"
            );
            if operation == "rename" {
                assert_eq!(
                    (
                        inner.inodes.peek(&vec![b"new".to_vec()]),
                        inner.inodes.peek(&vec![b"moved".to_vec()])
                    ),
                    (None, Some(u64::from(ino)))
                );
            }
            if matches!(operation, "unlink" | "rmdir") {
                assert_eq!(inner.inodes.peek(&vec![b"new".to_vec()]), None);
            }
        } else {
            assert_eq!(
                (
                    result,
                    inner.backend.calls.len() - count,
                    inner.backend.nodes.clone()
                ),
                (Err(fuser::Errno::EROFS), 0, before),
                "{operation}: RO bypass reached the backend"
            );
        }
    }
}
impl<B: MountBackend> GranaryFs<B> {
    fn node_attr_for_test(&self, ino: u64) -> super::Bent {
        self.bend(
            Attr {
                ino,
                generation: 17,
                kind: NodeKind::File,
                perm: 0o444,
                nlink: 1,
                uid: 0,
                gid: 0,
                size: 0,
                blocks: 0,
                blksize: 4096,
                time: self.snapshot.timestamp(),
            },
            self.mount_time,
        )
    }
}
#[test]
fn writable_callbacks_create_and_ro_pair() {
    callback_control("create");
}
#[test]
fn writable_callbacks_regular_mknod_and_ro_pair() {
    callback_control("mknod");
}
#[test]
fn writable_callbacks_write_and_ro_pair() {
    callback_control("write");
}
#[test]
fn writable_callbacks_truncate_and_ro_pair() {
    callback_control("truncate");
}
#[test]
fn writable_callbacks_mkdir_and_ro_pair() {
    callback_control("mkdir");
}
#[test]
fn writable_callbacks_unlink_and_ro_pair() {
    callback_control("unlink");
}
#[test]
fn writable_callbacks_rmdir_and_ro_pair() {
    callback_control("rmdir");
}
#[test]
fn writable_callbacks_rename_and_ro_pair() {
    callback_control("rename");
}
#[test]
fn writable_callbacks_exec_chmod_and_ro_pair() {
    callback_control("chmod");
}

#[test]
fn writable_callbacks_handle_name_and_mixed_field_guards_precede_capture() {
    let fs = mutable_adapter(true);
    let (attr, fh) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"new",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .map_err(super::ReplyError::errno)
        .unwrap();
    let ino = INodeNo(attr.ino);
    let fh = fh.unwrap();
    let readonly = fs
        .open_flags_handle(ino, fuser::OpenFlags(0))
        .map_err(super::ReplyError::errno)
        .unwrap();
    let initial = {
        let guard = fs.inner.lock().unwrap();
        let inner = guard.as_ref().unwrap();
        (inner.backend.calls.len(), inner.backend.nodes.clone())
    };
    let mut cases = 0;
    for (bound_ino, handle) in [
        (INodeNo::ROOT, fh),
        (ino, fuser::FileHandle(u64::MAX)),
        (ino, readonly),
    ] {
        assert_eq!(
            fs.write_overlay(bound_ino, handle, 0, b"")
                .map_err(super::ReplyError::errno),
            Err(fuser::Errno::EBADF),
            "empty input must still validate exact handle/mode"
        );
        cases += 1;
    }
    for (mode, unsupported) in [(Some(0o600), false), (Some(0o755), true)] {
        assert_eq!(
            fs.setattr_result(ino, mode, Some(99), unsupported, Some(fh))
                .map_err(super::ReplyError::errno)
                .map(|a| a.size),
            Err(fuser::Errno::ENOTSUP),
            "all fields must validate before size capture"
        );
        cases += 1;
    }
    for name in [b"".as_slice(), b".", b"..", b"a/b", b"nul\0"] {
        assert_eq!(
            fs.create_overlay(INodeNo::ROOT, name, NodeKind::File, 0o644, None)
                .map_err(super::ReplyError::errno)
                .map(|_| ()),
            Err(fuser::Errno::EINVAL)
        );
        cases += 1;
    }
    assert_eq!(
        fs.create_overlay(INodeNo::ROOT, &[b'x'; 256], NodeKind::File, 0o644, None)
            .map_err(super::ReplyError::errno)
            .map(|_| ()),
        Err(fuser::Errno::ENAMETOOLONG)
    );
    cases += 1;
    for flags in [2, 4, 8, 3] {
        assert_eq!(
            fs.rename_overlay(INodeNo::ROOT, b"new", INodeNo::ROOT, b"moved", flags)
                .map_err(super::ReplyError::errno),
            Err(if matches!(flags, 2 | 4) {
                fuser::Errno::ENOTSUP
            } else {
                fuser::Errno::EINVAL
            })
        );
        cases += 1;
    }
    assert_eq!(cases, 15);
    let guard = fs.inner.lock().unwrap();
    let inner = guard.as_ref().unwrap();
    assert_eq!(
        (inner.backend.calls.len(), inner.backend.nodes.clone()),
        initial,
        "refused callback leaked a mediated effect"
    );
}

#[test]
fn writable_callbacks_synchronous_create_gate_has_no_capture() {
    #[cfg(target_os = "linux")]
    const SYNC: [(i32, &[u8]); 2] = [(0x0010_1000, b"sync"), (0x1000, b"dsync")];
    #[cfg(target_os = "macos")]
    const SYNC: [(i32, &[u8]); 2] = [(0x80, b"sync"), (0x0040_0000, b"dsync")];
    let mut cases = 0;
    for writable in [true, false] {
        let fs = mutable_adapter(writable);
        for (sync, name) in SYNC {
            let created = fs
                .create_overlay(
                    INodeNo::ROOT,
                    name,
                    NodeKind::File,
                    0o644,
                    Some(fuser::OpenFlags(2 | sync)),
                )
                .map_err(super::ReplyError::errno);
            if writable {
                let (_, fh) = created.expect("writable mount admits synchronous create");
                let fh = fh.expect("create opens handle");
                let retained = fs
                    .write_inner(|inner| Ok(inner.write_handles.get(&u64::from(fh)).copied()))
                    .unwrap();
                assert_eq!(retained, Some(fuser::OpenFlags(2 | sync)));
            } else {
                assert_eq!(created.map(|_| ()), Err(fuser::Errno::EROFS));
            }
            cases += 1;
        }
        {
            let guard = fs.inner.lock().unwrap();
            let inner = guard.as_ref().unwrap();
            assert_eq!(
                (inner.backend.calls.len(), inner.backend.nodes.len()),
                if writable { (2, 3) } else { (0, 1) }
            );
        }
    }
    assert_eq!(cases, 4);
}

#[test]
fn writable_callbacks_append_retains_the_native_open_flag() {
    #[cfg(target_os = "linux")]
    const APPEND: i32 = 1024;
    #[cfg(target_os = "macos")]
    const APPEND: i32 = 8;
    let fs = mutable_adapter(true);
    let (attr, fh) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"new",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2 | APPEND)),
        )
        .map_err(super::ReplyError::errno)
        .unwrap();
    let ino = INodeNo(attr.ino);
    let fh = fh.unwrap();
    fs.write_overlay(ino, fh, 0, b"abc")
        .map_err(super::ReplyError::errno)
        .unwrap();
    fs.write_overlay(ino, fh, 1, b"Z")
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        fs.setattr_result(ino, None, None, false, Some(fh))
            .map_err(super::ReplyError::errno)
            .unwrap()
            .size,
        4,
        "ignored append flag overwrote an existing byte instead of extending EOF"
    );
}

#[test]
fn writable_callbacks_preparation_releases_the_adapter_gate() {
    let fs = Arc::new(mutable_adapter(true));
    let (attr, fh) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"new",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .map_err(super::ReplyError::errno)
        .unwrap();
    {
        let mut guard = fs.inner.lock().unwrap();
        guard.as_mut().unwrap().backend.prepare_probe = Some(Arc::downgrade(&fs));
    }
    fs.write_overlay(INodeNo(attr.ino), fh.unwrap(), 0, b"x")
        .map_err(super::ReplyError::errno)
        .unwrap();
    let guard = fs.inner.lock().unwrap();
    let inner = guard.as_ref().unwrap();
    assert_eq!(
        (
            inner.backend.prepare_count,
            inner.backend.probe_count,
            inner.backend.calls.as_slice()
        ),
        (1, 1, &["create", "write"][..]),
        "missing preparation cannot authorize local capture"
    );
}

#[test]
fn writable_callbacks_preparation_panic_abandons_without_clean_close() {
    let fs = mutable_adapter(true);
    let (attr, fh) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"new",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .map_err(super::ReplyError::errno)
        .unwrap();
    let abandoned = {
        let mut guard = fs.inner.lock().unwrap();
        let backend = &mut guard.as_mut().unwrap().backend;
        backend.prepare_panic = true;
        backend.abandoned.clone()
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fs.write_overlay(INodeNo(attr.ino), fh.unwrap(), 0, b"x")
            .map_err(super::ReplyError::errno)
    }));
    assert_eq!(
        (
            result.is_err(),
            abandoned.load(Ordering::SeqCst),
            fs.inner.lock().unwrap().is_none()
        ),
        (true, 1, true),
        "panic must abandon the owned backend, leaving no serving state"
    );
}

fn bound_adapter() -> GranaryFs<MutableBackend> {
    let fs = mutable_adapter(true);
    fs.inner
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .backend
        .bind_objects = true;
    fs
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one sequence connects unlink/recreation, detached metadata and exact final release"
)]
fn writable_objects_adapter_unlink_recreate_and_detached_metadata_keep_identity() {
    let fs = bound_adapter();
    let (attr, first) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"old",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .map_err(super::ReplyError::errno)
        .unwrap();
    let ino = INodeNo(attr.ino);
    let first = first.unwrap();
    let second = fs
        .open_flags_handle(ino, fuser::OpenFlags(0))
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        fs.read_handle_bytes(ino, second, 0, 16_777_217)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EINVAL)
    );
    assert_eq!(
        fs.inner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .backend
            .prepare_count,
        0,
        "oversized reads refuse before immutable preparation"
    );
    fs.write_overlay(ino, first, 0, b"abc")
        .map_err(super::ReplyError::errno)
        .unwrap();
    fs.remove_overlay(INodeNo::ROOT, b"old", false)
        .map_err(super::ReplyError::errno)
        .unwrap();
    let (new, replacement) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"old",
            NodeKind::File,
            0o755,
            Some(fuser::OpenFlags(2)),
        )
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_ne!(new.ino, attr.ino);
    assert_eq!(
        (
            fs.getattr_attr(ino)
                .map_err(super::ReplyError::errno)
                .unwrap()
                .size,
            fs.getattr_attr(ino)
                .map_err(super::ReplyError::errno)
                .unwrap()
                .nlink,
            fs.read_handle_bytes(ino, second, 0, 9)
                .map_err(super::ReplyError::errno)
                .unwrap()
        ),
        (3, 0, b"ZZZ".to_vec()),
        "detached inode/handle must not resolve the replacement path"
    );
    let before = fs
        .inner
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .backend
        .calls
        .len();
    assert_eq!(
        fs.setattr_result(ino, Some(0o755), Some(1), false, Some(first))
            .map_err(super::ReplyError::errno)
            .map(|a| a.size),
        Err(fuser::Errno::ENOTSUP)
    );
    assert_eq!(
        fs.setattr_result(ino, Some(0o644), None, false, Some(first))
            .map_err(super::ReplyError::errno)
            .unwrap()
            .perm,
        0o644
    );
    assert_eq!(
        fs.inner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .backend
            .calls
            .len(),
        before,
        "refused mixed detached metadata and canonical no-op append nothing"
    );
    assert_eq!(
        fs.setattr_result(ino, None, Some(5), false, Some(first))
            .map_err(super::ReplyError::errno)
            .unwrap()
            .size,
        5
    );
    fs.write_overlay(ino, first, 1, b"Q")
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        fs.read_handle_bytes(ino, second, 0, 9)
            .map_err(super::ReplyError::errno)
            .unwrap()
            .len(),
        5
    );
    assert_eq!(
        fs.setattr_result(INodeNo(new.ino), None, None, false, replacement)
            .map_err(super::ReplyError::errno)
            .unwrap()
            .size,
        0
    );
    assert_eq!(
        fs.release_handle(first, HandleKind::Directory)
            .map_err(super::ReplyError::errno),
        Ok(())
    );
    assert_eq!(
        fs.release_handle(first, HandleKind::File)
            .map_err(super::ReplyError::errno),
        Ok(())
    );
    assert_eq!(
        fs.release_handle(first, HandleKind::File)
            .map_err(super::ReplyError::errno),
        Ok(())
    );
    assert_eq!(
        fs.read_handle_bytes(ino, second, 0, 9)
            .map_err(super::ReplyError::errno)
            .unwrap()
            .len(),
        5,
        "duplicate/wrong-kind release must not close the second handle"
    );
    assert_eq!(
        fs.release_handle(second, HandleKind::File)
            .map_err(super::ReplyError::errno),
        Ok(())
    );
    assert_eq!(
        (
            fs.getattr_attr(ino)
                .map_err(super::ReplyError::errno)
                .unwrap()
                .size,
            fs.getattr_attr(ino)
                .map_err(super::ReplyError::errno)
                .unwrap()
                .perm
        ),
        (5, 0o644),
        "lookup credits keep detached metadata after last close"
    );
    assert_eq!(
        fs.read_handle_bytes(ino, second, 0, 1)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EBADF)
    );
    let mut guard = fs.inner.lock().unwrap();
    let inner = guard.as_mut().unwrap();
    assert_eq!(inner.backend.closes.len(), 2);
    inner.inodes.forget(attr.ino, 1);
    assert_eq!(inner.inodes.peek(&vec![b"old".to_vec()]), Some(new.ino));
    drop(guard);
    fs.release_handle(replacement.unwrap(), HandleKind::File)
        .map_err(super::ReplyError::errno)
        .unwrap();
}

#[test]
fn writable_objects_adapter_replacement_and_rename_bind_the_displaced_object() {
    let fs = bound_adapter();
    let (source, source_fh) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"source",
            NodeKind::File,
            0o755,
            Some(fuser::OpenFlags(2)),
        )
        .map_err(super::ReplyError::errno)
        .unwrap();
    let (target, target_fh) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"target",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .map_err(super::ReplyError::errno)
        .unwrap();
    let source_fh = source_fh.unwrap();
    let target_fh = target_fh.unwrap();
    fs.write_overlay(INodeNo(target.ino), target_fh, 0, b"old")
        .map_err(super::ReplyError::errno)
        .unwrap();
    fs.rename_overlay(INodeNo::ROOT, b"source", INodeNo::ROOT, b"target", 0)
        .map_err(super::ReplyError::errno)
        .unwrap();
    fs.write_overlay(INodeNo(target.ino), target_fh, 3, b"x")
        .map_err(super::ReplyError::errno)
        .unwrap();
    fs.write_overlay(INodeNo(source.ino), source_fh, 0, b"n")
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        (
            fs.setattr_result(INodeNo(source.ino), None, None, false, Some(source_fh))
                .map_err(super::ReplyError::errno)
                .unwrap()
                .size,
            fs.getattr_attr(INodeNo(target.ino))
                .map_err(super::ReplyError::errno)
                .unwrap()
                .size
        ),
        (1, 4),
        "displaced fd and moved source must never share backing"
    );
    assert_eq!(
        fs.write_overlay(INodeNo(source.ino), target_fh, 0, b"")
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EBADF)
    );
    fs.release_handle(target_fh, HandleKind::File)
        .map_err(super::ReplyError::errno)
        .unwrap();
    fs.release_handle(source_fh, HandleKind::File)
        .map_err(super::ReplyError::errno)
        .unwrap();
}

#[test]
fn writable_objects_adapter_release_failure_is_terminal_and_not_repeated() {
    let mut fs = bound_adapter();
    let observer = Arc::new(Replies::default());
    fs.observer = Some(observer.clone());
    let (_, fh) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"file",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .map_err(super::ReplyError::errno)
        .unwrap();
    let fh = fh.unwrap();
    fs.inner
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .backend
        .close_failure = true;
    assert_eq!(
        fs.completed(
            crate::Callback::Release,
            fs.release_handle(fh, HandleKind::File)
        ),
        Err(fuser::Errno::EIO)
    );
    assert_eq!(
        fs.release_handle(fh, HandleKind::File)
            .map_err(super::ReplyError::errno),
        Ok(())
    );
    assert_eq!(
        (
            fs.inner
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .backend
                .closes
                .len(),
            observer.0.lock().unwrap().clone()
        ),
        (
            1,
            vec![(
                crate::Callback::Release,
                crate::CallbackOutcome::Failed(crate::MountError::Io)
            )]
        )
    );
}

#[test]
fn writable_objects_symlink_adapter_target_boundaries_and_ro_pair() {
    let mut cases = 0;
    for writable in [true, false] {
        let fs = mutable_adapter(writable);
        for (name, target, expected) in [
            (b"opaque".as_slice(), b"../\xff".as_slice(), Ok(())),
            (b"empty", b"", Err(fuser::Errno::EINVAL)),
            (b"nul", b"x\0", Err(fuser::Errno::EINVAL)),
            (b"long", &[b'x'; 4096], Err(fuser::Errno::ENAMETOOLONG)),
        ] {
            let answer = fs
                .symlink_overlay(INodeNo::ROOT, name, target)
                .map_err(super::ReplyError::errno);
            if writable && expected.is_ok() {
                assert_eq!(
                    answer.as_ref().map(|a| (a.kind, a.perm, a.size)),
                    Ok((NodeKind::Symlink, 0o777, 4)),
                    "symlink callback must return the captured entry"
                );
                let attr = answer.unwrap();
                assert_eq!(
                    (
                        attr.kind,
                        attr.perm,
                        attr.size,
                        fs.readlink_bytes(INodeNo(attr.ino))
                            .map_err(super::ReplyError::errno)
                            .unwrap()
                    ),
                    (NodeKind::Symlink, 0o777, 4, target.to_vec())
                );
            } else {
                assert_eq!(
                    answer.map(|_| ()),
                    if writable {
                        expected
                    } else {
                        Err(fuser::Errno::EROFS)
                    }
                );
            }
            cases += 1;
        }
        if writable {
            let attr = fs
                .symlink_overlay(INodeNo::ROOT, b"limit", &[b'x'; 4095])
                .map_err(super::ReplyError::errno)
                .unwrap();
            assert_eq!(
                fs.readlink_bytes(INodeNo(attr.ino))
                    .map_err(super::ReplyError::errno)
                    .unwrap(),
                vec![b'x'; 4095]
            );
        }
        assert_eq!(
            fs.inner
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .backend
                .calls
                .len(),
            if writable { 2 } else { 0 }
        );
    }
    assert_eq!(cases, 8);
}

#[test]
fn writable_objects_lookup_only_detachment_keeps_metadata_without_retargeting() {
    let fs = mutable_adapter(true);
    let (old, _) = fs
        .create_overlay(INodeNo::ROOT, b"name", NodeKind::File, 0o644, None)
        .map_err(super::ReplyError::errno)
        .unwrap();
    fs.remove_overlay(INodeNo::ROOT, b"name", false)
        .map_err(super::ReplyError::errno)
        .unwrap();
    let (new, _) = fs
        .create_overlay(INodeNo::ROOT, b"name", NodeKind::File, 0o755, None)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_ne!(old.ino, new.ino);
    assert_eq!(
        (
            fs.getattr_attr(INodeNo(old.ino))
                .map_err(super::ReplyError::errno)
                .unwrap()
                .perm,
            fs.getattr_attr(INodeNo(old.ino))
                .map_err(super::ReplyError::errno)
                .unwrap()
                .nlink
        ),
        (0o644, 0)
    );
    assert_eq!(
        fs.setattr_result(INodeNo(old.ino), None, None, false, None)
            .map_err(super::ReplyError::errno)
            .unwrap()
            .perm,
        0o644
    );
}

#[test]
fn writable_objects_detached_parent_cannot_retarget_a_recreated_directory() {
    let fs = mutable_adapter(true);
    let (old, _) = fs
        .create_overlay(INodeNo::ROOT, b"dir", NodeKind::Dir, 0o755, None)
        .map_err(super::ReplyError::errno)
        .unwrap();
    fs.remove_overlay(INodeNo::ROOT, b"dir", true)
        .map_err(super::ReplyError::errno)
        .unwrap();
    let (new, _) = fs
        .create_overlay(INodeNo::ROOT, b"dir", NodeKind::Dir, 0o755, None)
        .map_err(super::ReplyError::errno)
        .unwrap();
    let before = fs
        .inner
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .backend
        .calls
        .len();
    assert_eq!(
        fs.create_overlay(INodeNo(old.ino), b"file", NodeKind::File, 0o644, None)
            .map_err(super::ReplyError::errno)
            .map(|_| ()),
        Err(fuser::Errno::ENOENT)
    );
    assert_eq!(
        fs.inner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .backend
            .calls
            .len(),
        before
    );
    assert!(
        fs.create_overlay(INodeNo(new.ino), b"file", NodeKind::File, 0o644, None)
            .map_err(super::ReplyError::errno)
            .is_ok()
    );
}

#[test]
fn writable_objects_same_path_rename_never_prepares_a_held_target() {
    let fs = bound_adapter();
    let (_, fh) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"file",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .map_err(super::ReplyError::errno)
        .unwrap();
    fs.inner
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .backend
        .detach_error = Some(crate::MountError::Unavailable);
    assert_eq!(
        fs.rename_overlay(INodeNo::ROOT, b"file", INodeNo::ROOT, b"file", 0)
            .map_err(super::ReplyError::errno),
        Ok(()),
        "same-path rename must not fetch a target that will not detach"
    );
    assert_eq!(
        fs.inner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .backend
            .detach_preparations,
        0
    );
    assert_eq!(
        fs.rename_overlay(INodeNo::ROOT, b"missing", INodeNo::ROOT, b"missing", 0)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOENT),
        "same-path exemption cannot fabricate existence"
    );
    let (_, target_fh) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"target",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        fs.rename_overlay(INodeNo::ROOT, b"file", INodeNo::ROOT, b"target", 0)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EIO),
        "a real replacement plan still uses preparation"
    );
    assert_eq!(
        fs.inner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .backend
            .detach_preparations,
        1
    );
    fs.release_handle(fh.unwrap(), HandleKind::File)
        .map_err(super::ReplyError::errno)
        .unwrap();
    fs.release_handle(target_fh.unwrap(), HandleKind::File)
        .map_err(super::ReplyError::errno)
        .unwrap();
}

#[derive(Default)]
struct LiveSink {
    plain: Vec<(u64, fuser::FileType, Vec<u8>, u64)>,
    plus: Vec<(Attr, Vec<u8>, u64)>,
    capacity: Option<usize>,
}
impl crate::DirSink for LiveSink {
    fn offer(&mut self, ino: u64, kind: fuser::FileType, name: &[u8], next: u64) -> SinkOutcome {
        if self.capacity.is_some_and(|limit| self.plain.len() >= limit) {
            return SinkOutcome::Full;
        }
        self.plain.push((ino, kind, name.to_vec(), next));
        SinkOutcome::Added
    }
}
impl crate::DirPlusSink for LiveSink {
    fn offer(&mut self, attr: Attr, name: &[u8], next: u64) -> SinkOutcome {
        if self.capacity.is_some_and(|limit| self.plus.len() >= limit) {
            return SinkOutcome::Full;
        }
        self.plus.push((attr, name.to_vec(), next));
        SinkOutcome::Added
    }
}

fn live_fixture() -> (GranaryFs<MutableBackend>, u64, u64, u64) {
    let fs = mutable_adapter(true);
    let (dir, _) = fs
        .create_overlay(INodeNo::ROOT, b"live-dir", NodeKind::Dir, 0o755, None)
        .map_err(super::ReplyError::errno)
        .unwrap();
    let (file, _) = fs
        .create_overlay(INodeNo::ROOT, b"live-file", NodeKind::File, 0o644, None)
        .map_err(super::ReplyError::errno)
        .unwrap();
    fs.setattr_overlay(INodeNo(file.ino), Some(0o755), Some(513), false, None)
        .map_err(super::ReplyError::errno)
        .unwrap();
    let link = fs
        .symlink_overlay(INodeNo::ROOT, b"live-link", b"live-file")
        .map_err(super::ReplyError::errno)
        .unwrap();
    (fs, dir.ino, file.ino, link.ino)
}

// Correct answers through a whole-tree fallback still violate live query bounds.
#[test]
fn writable_callbacks_do_not_request_whole_namespace_views() {
    let (fs, _, file, _) = live_fixture();
    let cardinality = fs.write_inner(|i| Ok(i.backend.nodes.len())).unwrap();
    assert_eq!(cardinality, 4, "fixture cardinality: {cardinality}");
    let mut observations = Vec::new();
    for site in [
        "lookup",
        "getattr",
        "open",
        "setattr",
        "readdir",
        "readdirplus",
        "create",
        "symlink",
        "unlink",
    ] {
        let before = fs.write_inner(|i| Ok(i.backend.view_calls)).unwrap();
        let answer = match site {
            "lookup" => fs
                .lookup_entry(INodeNo::ROOT, b"live-file")
                .map(|a| a.size == 513),
            "getattr" => fs.getattr_attr(INodeNo(file)).map(|a| a.size == 513),
            "open" => fs
                .open_flags_handle(INodeNo(file), fuser::OpenFlags(0))
                .and_then(|fh| fs.release_handle(fh, HandleKind::File))
                .map(|()| true),
            "setattr" => fs
                .setattr_result(INodeNo(file), None, None, false, None)
                .map(|a| a.size == 513),
            "readdir" => {
                let mut sink = LiveSink::default();
                fs.directory_entries(1, 0, &mut sink)
                    .map(|()| sink.plain.len() == 5)
            }
            "readdirplus" => {
                let mut sink = LiveSink::default();
                fs.directory_entries_plus(1, 0, &mut sink)
                    .map(|()| sink.plus.len() == 5)
            }
            "create" => fs
                .create_overlay(INodeNo::ROOT, b"new", NodeKind::Dir, 0o755, None)
                .map(|(a, _)| a.nlink == 2),
            "symlink" => fs
                .symlink_overlay(INodeNo::ROOT, b"new-link", b"new")
                .map(|a| a.size == 3),
            "unlink" => fs
                .remove_overlay(INodeNo::ROOT, b"live-file", false)
                .map(|()| true),
            _ => unreachable!(),
        }
        .map_err(super::ReplyError::errno);
        let copies = fs
            .write_inner(|i| Ok(i.backend.view_calls - before))
            .unwrap();
        observations.push((site, answer, copies));
    }
    assert_eq!(
        observations,
        [
            "lookup",
            "getattr",
            "open",
            "setattr",
            "readdir",
            "readdirplus",
            "create",
            "symlink",
            "unlink"
        ]
        .map(|site| (site, Ok(true), 0)),
        "callback answers and whole-namespace requests"
    );
}

#[test]
fn writable_bound_setter_queries_current_and_final_attributes_only() {
    let fs = mutable_adapter(true);
    fs.write_inner(|inner| {
        inner.backend.bind_objects = true;
        Ok(())
    })
    .unwrap();
    let (attr, fh) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"file",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .unwrap();
    let ino = INodeNo(attr.ino);
    let fh = fh.unwrap();
    let cardinality = fs
        .write_inner(|i| Ok((i.backend.nodes.len(), i.backend.objects.len())))
        .unwrap();
    assert_eq!(
        cardinality,
        (2, 1),
        "actual namespace/held identities: {cardinality:?}"
    );
    let mut cases = 0;
    for (mode, size, wanted, queries, prepares, dispatches) in [
        (None, Some(8), (8, 0o644), 2, 1, 1),
        (Some(0o755), None, (8, 0o755), 2, 0, 1),
        (Some(0o644), Some(7), (7, 0o644), 2, 1, 1),
        (Some(0o644), None, (7, 0o644), 1, 0, 0),
    ] {
        let before = fs
            .write_inner(|i| {
                Ok((
                    i.backend.path_queries,
                    i.backend.prepare_count,
                    i.backend.bound_setattrs,
                    i.backend.view_calls,
                ))
            })
            .unwrap();
        let answer = fs
            .setattr_result(ino, mode, size, false, Some(fh))
            .map(|a| (a.size, a.perm))
            .map_err(super::ReplyError::errno);
        let work = fs
            .write_inner(|i| {
                Ok((
                    i.backend.path_queries - before.0,
                    i.backend.prepare_count - before.1,
                    i.backend.bound_setattrs - before.2,
                    i.backend.view_calls - before.3,
                ))
            })
            .unwrap();
        assert_eq!(
            (answer, work),
            (Ok(wanted), (queries, prepares, dispatches, 0)),
            "complete adapter setter answer/sequence, mode={mode:?}, size={size:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 4, "nonempty adapter setter cases: {cases}");
    fs.release_handle(fh, HandleKind::File).unwrap();
}

#[test]
fn writable_unbound_setter_owns_preparation_and_final_attributes() {
    let fs = Arc::new(mutable_adapter(true));
    fs.write_inner(|inner| {
        inner.backend.prepare_probe = Some(Arc::downgrade(&fs));
        Ok(())
    })
    .unwrap();
    let (attr, fh) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"file",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .unwrap();
    let ino = INodeNo(attr.ino);
    let fh = fh.unwrap();
    let cardinality = fs
        .write_inner(|i| Ok((i.backend.nodes.len(), i.backend.objects.len())))
        .unwrap();
    assert_eq!(
        cardinality,
        (2, 0),
        "actual namespace/held identities: {cardinality:?}"
    );
    let mut cases = 0;
    for (mode, size, wanted, queries, prepares, dispatches) in [
        (None, Some(8), (8, 0o644), 2, 1, 1),
        (Some(0o755), None, (8, 0o755), 2, 0, 1),
        (Some(0o644), Some(7), (7, 0o644), 2, 1, 1),
        (Some(0o644), None, (7, 0o644), 1, 0, 0),
    ] {
        let before = fs
            .write_inner(|i| {
                Ok((
                    i.backend.path_queries,
                    i.backend.prepare_count,
                    i.backend.path_setattrs,
                    i.backend.view_calls,
                ))
            })
            .unwrap();
        let answer = fs
            .setattr_result(ino, mode, size, false, None)
            .map(|a| (a.size, a.perm))
            .map_err(super::ReplyError::errno);
        let work = fs
            .write_inner(|i| {
                Ok((
                    i.backend.path_queries - before.0,
                    i.backend.prepare_count - before.1,
                    i.backend.path_setattrs - before.2,
                    i.backend.view_calls - before.3,
                ))
            })
            .unwrap();
        assert_eq!(
            (answer, work),
            (Ok(wanted), (queries, prepares, dispatches, 0)),
            "complete adapter setter answer/sequence, mode={mode:?}, size={size:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 4, "nonempty adapter setter cases: {cases}");
    fs.release_handle(fh, HandleKind::File).unwrap();
}

// Partial observations must not reach a sink or acquire PLUS credits.
#[test]
fn writable_listing_restarts_partial_pages_and_exhausts_three_attempts() {
    let mut cases = 0;
    for plus in [false, true] {
        for changes in [0, 2, 3] {
            let fs = mutable_adapter(true);
            fs.write_inner(|inner| {
                for index in 0..513 {
                    let path = vec![Name::new(format!("child-{index:04}").into_bytes()).unwrap()];
                    inner.backend.nodes.insert(
                        path.clone(),
                        crate::OverlayNode {
                            path,
                            kind: NodeKind::File,
                            size: 7,
                            exec: false,
                            stage: None,
                        },
                    );
                }
                let cardinality = inner.backend.nodes.len();
                assert_eq!(cardinality, 514, "fixture cardinality: {cardinality}");
                Ok(())
            })
            .unwrap();
            let fh = fs.opendir_handle(INodeNo::ROOT).unwrap();
            fs.write_inner(|i| {
                i.backend.page_changes = changes;
                Ok(())
            })
            .unwrap();
            let mut sink = LiveSink::default();
            let result = if plus {
                fs.directory_entries_plus_handle(1, fh, 0, &mut sink)
            } else {
                fs.directory_entries_handle(1, fh, 0, &mut sink)
            }
            .map_err(super::ReplyError::errno);
            let actual = fs
                .write_inner(|i| {
                    Ok((
                        i.backend.page_calls,
                        i.inodes.resident_count(),
                        i.directory_cursors.get(&u64::from(fh)).unwrap().len(),
                    ))
                })
                .unwrap();
            let offered = if plus {
                sink.plus.len()
            } else {
                sink.plain.len()
            };
            let expected = if changes == 3 {
                (Err(fuser::Errno::EAGAIN), 0, (6, 1, 0))
            } else {
                (
                    Ok(()),
                    515,
                    (changes * 2 + 3, if plus { 514 } else { 1 }, 515),
                )
            };
            assert_eq!(
                (result, offered, actual),
                expected,
                "listing plus={plus}, context changes={changes}"
            );
            if changes < 3 {
                let names: Vec<_> = if plus {
                    sink.plus.iter().map(|r| r.1.clone()).collect()
                } else {
                    sink.plain.iter().map(|r| r.2.clone()).collect()
                };
                assert_eq!(
                    (
                        names.first().unwrap().as_slice(),
                        names.last().unwrap().as_slice()
                    ),
                    (b".".as_slice(), b"child-0512".as_slice())
                );
            }
            fs.release_handle(fh, HandleKind::Directory).unwrap();
            cases += 1;
        }
    }
    assert_eq!(cases, 6, "nonempty listing cases: {cases}");
}

#[test]
fn writable_listing_io_fault_never_retries_or_offers_rows() {
    let mut cases = 0;
    for plus in [false, true] {
        for fault in [false, true] {
            let fs = mutable_adapter(true);
            let fh = fs.opendir_handle(INodeNo::ROOT).unwrap();
            fs.write_inner(|inner| {
                let path = vec![Name::new(b"child".to_vec()).unwrap()];
                inner.backend.nodes.insert(
                    path.clone(),
                    crate::OverlayNode {
                        path,
                        kind: NodeKind::File,
                        size: 9,
                        exec: false,
                        stage: None,
                    },
                );
                let cardinality = inner.backend.nodes.len();
                assert_eq!(cardinality, 2, "nonempty fault fixture: {cardinality}");
                if fault {
                    inner.backend.failure = Some(("overlay_children", crate::MountError::Io));
                }
                Ok(())
            })
            .unwrap();
            let mut sink = LiveSink::default();
            let result = if plus {
                fs.directory_entries_plus_handle(1, fh, 0, &mut sink)
            } else {
                fs.directory_entries_handle(1, fh, 0, &mut sink)
            }
            .map_err(super::ReplyError::errno);
            let actual = fs
                .write_inner(|i| {
                    Ok((
                        i.backend.failures_seen,
                        i.inodes.resident_count(),
                        i.directory_cursors.get(&u64::from(fh)).unwrap().len(),
                    ))
                })
                .unwrap();
            let expected = if fault {
                (Err(fuser::Errno::EIO), 0, (1, 1, 0))
            } else {
                (Ok(()), 3, (0, if plus { 2 } else { 1 }, 3))
            };
            assert_eq!(
                (result, sink.plain.len() + sink.plus.len(), actual),
                expected,
                "listing plus={plus}, fault={fault}"
            );
            fs.release_handle(fh, HandleKind::Directory).unwrap();
            cases += 1;
        }
    }
    assert_eq!(cases, 4, "fault and control route counts: {cases}");
}

#[test]
fn writable_listing_malformed_child_refuses_before_cookie_publication() {
    let mut cases = 0;
    for plus in [false, true] {
        for malformed in [false, true] {
            let fs = mutable_adapter(true);
            let fh = fs.opendir_handle(INodeNo::ROOT).unwrap();
            fs.write_inner(|inner| {
                let path = vec![Name::new(b"child".to_vec()).unwrap()];
                inner.backend.nodes.insert(
                    path.clone(),
                    crate::OverlayNode {
                        path,
                        kind: NodeKind::File,
                        size: 9,
                        exec: false,
                        stage: None,
                    },
                );
                let cardinality = inner.backend.nodes.len();
                assert_eq!(cardinality, 2, "nonempty child fixture: {cardinality}");
                inner.backend.child_reply = if malformed {
                    ChildReply::MissingName
                } else {
                    ChildReply::Valid
                };
                Ok(())
            })
            .unwrap();
            let mut sink = LiveSink::default();
            let result = if plus {
                fs.directory_entries_plus_handle(1, fh, 0, &mut sink)
            } else {
                fs.directory_entries_handle(1, fh, 0, &mut sink)
            }
            .map_err(super::ReplyError::errno);
            let actual = fs
                .write_inner(|i| {
                    Ok((
                        i.backend.page_calls,
                        i.inodes.resident_count(),
                        i.directory_cursors.get(&u64::from(fh)).unwrap().len(),
                    ))
                })
                .unwrap();
            let expected = if malformed {
                (Err(fuser::Errno::EIO), 0, (1, 1, 0))
            } else {
                (Ok(()), 3, (1, if plus { 2 } else { 1 }, 3))
            };
            assert_eq!(
                (result, sink.plain.len() + sink.plus.len(), actual),
                expected,
                "listing plus={plus}, malformed={malformed}"
            );
            fs.release_handle(fh, HandleKind::Directory).unwrap();
            cases += 1;
        }
    }
    assert_eq!(cases, 4, "malformed and valid child route counts: {cases}");
}

// A snapshot-only reader loses created names and reports stale size/exec/nlink.
#[test]
fn writable_live_lookup_observes_namespace_and_identity() {
    let (fs, dir, file, link) = live_fixture();
    let mut cases = 0;
    for (name, ino, mode, size) in [
        (b"live-dir".as_slice(), dir, 0o755, 4096),
        (b"live-file", file, 0o755, 513),
        (b"live-link", link, 0o777, 9),
    ] {
        assert_eq!(
            fs.lookup_entry(INodeNo::ROOT, name)
                .map_err(super::ReplyError::errno)
                .map(|a| (a.ino, a.perm, a.size)),
            Ok((ino, mode, size)),
            "live lookup {name:?}"
        );
        cases += 1;
    }
    assert_eq!(
        fs.lookup_entry(INodeNo::ROOT, b"leaf")
            .map_err(super::ReplyError::errno)
            .map(|a| a.ino),
        Err(fuser::Errno::ENOENT),
        "absent in live namespace despite immutable pin"
    );
    assert_eq!(cases, 3);
}

#[test]
fn writable_live_getattr_reports_current_size_exec_and_directory_links() {
    let (fs, dir, file, link) = live_fixture();
    let mut cases = 0;
    for (ino, mode, size, nlink) in [
        (1, 0o755, 4096, 3),
        (dir, 0o755, 4096, 2),
        (file, 0o755, 513, 1),
        (link, 0o777, 9, 1),
    ] {
        assert_eq!(
            fs.getattr_attr(INodeNo(ino))
                .map_err(super::ReplyError::errno)
                .map(|a| (a.perm, a.size, a.nlink, a.uid, a.gid, a.time)),
            Ok((mode, size, nlink, 3, 4, Timestamp { secs: 1, nanos: 2 })),
            "live getattr {ino}"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn writable_live_access_follows_exec_changes() {
    let (fs, _, file, _) = live_fixture();
    assert_eq!(
        fs.access_attr(
            INodeNo(file),
            AccessFlags::R_OK | AccessFlags::W_OK | AccessFlags::X_OK
        )
        .map_err(super::ReplyError::errno),
        Ok(())
    );
    fs.setattr_overlay(INodeNo(file), Some(0o644), None, false, None)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        (
            fs.access_attr(INodeNo(file), AccessFlags::X_OK)
                .map_err(super::ReplyError::errno),
            fs.access_attr(INodeNo(file), AccessFlags::W_OK)
                .map_err(super::ReplyError::errno)
        ),
        (Err(fuser::Errno::EACCES), Ok(()))
    );
}

#[test]
fn writable_live_plain_listing_uses_current_namespace_without_credits() {
    let (fs, dir, file, link) = live_fixture();
    let before = fs.write_inner(|i| Ok(i.inodes.resident_count())).unwrap();
    let mut sink = LiveSink::default();
    fs.directory_entries(1, 0, &mut sink)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        sink.plain
            .iter()
            .map(|(ino, _, name, next)| (*ino, name.as_slice(), *next))
            .collect::<Vec<_>>(),
        [
            (1, b".".as_slice(), 1),
            (1, b"..", 2),
            (dir, b"live-dir", 3),
            (file, b"live-file", 4),
            (link, b"live-link", 5)
        ]
    );
    assert_eq!(
        fs.write_inner(|i| Ok(i.inodes.resident_count())).unwrap(),
        before
    );
    let mut resumed = LiveSink::default();
    fs.directory_entries(1, 3, &mut resumed)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(resumed.plain.len(), 2);
    assert_eq!(resumed.plain.first().unwrap().2, b"live-file");
}

#[test]
fn writable_live_plus_listing_uses_current_attributes_and_credits() {
    let (fs, dir, file, link) = live_fixture();
    let mut sink = LiveSink::default();
    fs.directory_entries_plus(1, 0, &mut sink)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        sink.plus
            .iter()
            .map(|(a, name, next)| (a.ino, name.as_slice(), a.perm, a.size, a.nlink, *next))
            .collect::<Vec<_>>(),
        [
            (1, b".".as_slice(), 0o755, 4096, 3, 1),
            (1, b"..", 0o755, 4096, 3, 2),
            (dir, b"live-dir", 0o755, 4096, 2, 3),
            (file, b"live-file", 0o755, 513, 1, 4),
            (link, b"live-link", 0o777, 9, 1, 5)
        ]
    );
    fs.write_inner(|i| {
        for ino in [dir, file, link] {
            i.inodes.forget(ino, 1);
            assert!(i.inodes.resolve(ino).is_ok());
            i.inodes.forget(ino, 1);
            assert!(i.inodes.resolve(ino).is_err());
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn writable_live_opendir_refuses_a_regular_file_without_a_handle_hold() {
    let (fs, _, file, _) = live_fixture();
    assert_eq!(
        fs.opendir_handle(INodeNo(file))
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOTDIR)
    );
    fs.write_inner(|i| {
        i.inodes.forget(file, 1);
        assert!(
            i.inodes.resolve(file).is_err(),
            "refused opendir must acquire no inode hold"
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn writable_live_plus_full_rolls_back_only_the_unoffered_credit() {
    let (fs, dir, file, link) = live_fixture();
    // Remove all creation credits; the namespace still contains these objects.
    fs.write_inner(|inner| {
        for ino in [dir, file, link] {
            inner.inodes.forget(ino, 1);
        }
        Ok(())
    })
    .unwrap();
    let mut sink = LiveSink {
        capacity: Some(3),
        ..LiveSink::default()
    };
    fs.directory_entries_plus(1, 0, &mut sink)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        sink.plus
            .iter()
            .map(|(_, name, _)| name.as_slice())
            .collect::<Vec<_>>(),
        [b".".as_slice(), b"..", b"live-dir"]
    );
    fs.write_inner(|inner| {
        assert_eq!(inner.inodes.resident_count(), 2);
        assert_eq!(
            inner.inodes.peek(&vec![b"live-file".to_vec()]),
            None,
            "FULL entry's credit must be repaid"
        );
        let credited = inner.inodes.peek(&vec![b"live-dir".to_vec()]).unwrap();
        inner.inodes.forget(credited, 1);
        assert_eq!(
            inner.inodes.resident_count(),
            1,
            "dots do not take lookup credits"
        );
        Ok(())
    })
    .unwrap();
    let mut plain = LiveSink::default();
    fs.directory_entries(1, 2, &mut plain)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        plain
            .plain
            .iter()
            .map(|(ino, _, _, _)| *ino)
            .collect::<Vec<_>>(),
        [0, 0, 0],
        "plain listing cannot allocate unreferenced rows"
    );
    assert_eq!(
        fs.write_inner(|inner| Ok(inner.inodes.resident_count()))
            .unwrap(),
        1
    );
    let mut resumed = LiveSink::default();
    fs.directory_entries_plus(1, 3, &mut resumed)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        resumed
            .plus
            .iter()
            .map(|(_, name, next)| (name.as_slice(), *next))
            .collect::<Vec<_>>(),
        [(b"live-file".as_slice(), 4), (b"live-link", 5)]
    );
}

#[test]
fn writable_live_nested_rename_remove_and_parent_links_stay_current() {
    let (fs, dir, file, _) = live_fixture();
    fs.rename_overlay(INodeNo::ROOT, b"live-file", INodeNo(dir), b"moved", 0)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        fs.lookup_entry(INodeNo::ROOT, b"live-file")
            .map_err(super::ReplyError::errno)
            .map(|a| a.ino),
        Err(fuser::Errno::ENOENT)
    );
    assert_eq!(
        fs.lookup_entry(INodeNo(dir), b"moved")
            .map_err(super::ReplyError::errno)
            .map(|a| (a.ino, a.size, a.perm)),
        Ok((file, 513, 0o755))
    );
    assert_eq!(
        fs.getattr_attr(INodeNo(file))
            .map_err(super::ReplyError::errno)
            .map(|a| a.size),
        Ok(513)
    );
    let mut sink = LiveSink::default();
    fs.directory_entries_plus(dir, 0, &mut sink)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        sink.plus
            .iter()
            .map(|(a, name, _)| (a.ino, name.as_slice(), a.nlink))
            .collect::<Vec<_>>(),
        [
            (dir, b".".as_slice(), 2),
            (1, b"..", 3),
            (file, b"moved", 1)
        ]
    );
    fs.remove_overlay(INodeNo(dir), b"moved", false)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        fs.lookup_entry(INodeNo(dir), b"moved")
            .map_err(super::ReplyError::errno)
            .map(|a| a.ino),
        Err(fuser::Errno::ENOENT)
    );
    assert_eq!(
        fs.getattr_attr(INodeNo(file))
            .map_err(super::ReplyError::errno)
            .map(|a| (a.ino, a.size, a.nlink)),
        Ok((file, 513, 0))
    );
    let mut empty = LiveSink::default();
    fs.directory_entries(dir, 0, &mut empty)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        empty
            .plain
            .iter()
            .map(|(_, _, name, _)| name.as_slice())
            .collect::<Vec<_>>(),
        [b".".as_slice(), b".."]
    );
    let fh = fs
        .opendir_handle(INodeNo(dir))
        .map_err(super::ReplyError::errno)
        .unwrap();
    fs.release_handle(fh, HandleKind::Directory)
        .map_err(super::ReplyError::errno)
        .unwrap();
}

#[test]
fn writable_live_queries_keep_read_only_pin_and_modes_without_overlay_calls() {
    let fs = mutable_adapter(false);
    let file = fs
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        (
            file.perm,
            fs.getattr_attr(INodeNo(file.ino))
                .map_err(super::ReplyError::errno)
                .unwrap()
                .perm
        ),
        (0o444, 0o444)
    );
    assert_eq!(
        fs.access_attr(INodeNo(file.ino), AccessFlags::W_OK)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EACCES)
    );
    assert_eq!(
        fs.access_attr(INodeNo(file.ino), AccessFlags::R_OK)
            .map_err(super::ReplyError::errno),
        Ok(())
    );
    let mut plain = LiveSink::default();
    let mut plus = LiveSink::default();
    fs.directory_entries(1, 0, &mut plain)
        .map_err(super::ReplyError::errno)
        .unwrap();
    fs.directory_entries_plus(1, 0, &mut plus)
        .map_err(super::ReplyError::errno)
        .unwrap();
    let expected = [b".".as_slice(), b"..", b"child", b"leaf", b"link"];
    assert_eq!(
        plain
            .plain
            .iter()
            .map(|(_, _, n, _)| n.as_slice())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        plus.plus
            .iter()
            .map(|(_, n, _)| n.as_slice())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        plus.plus.iter().map(|(a, _, _)| a.perm).collect::<Vec<_>>(),
        [0o555, 0o555, 0o555, 0o444, 0o777]
    );
    fs.write_inner(|inner| {
        assert_eq!(
            (inner.backend.view_calls, inner.backend.calls.len()),
            (0, 0)
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn writable_live_query_failure_never_substitutes_the_pin() {
    let (fs, _, file, _) = live_fixture();
    fs.write_inner(|inner| {
        inner.backend.view_error = Some(crate::WriteError::Backend(crate::MountError::Stale));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        fs.lookup_entry(INodeNo::ROOT, b"leaf")
            .map_err(super::ReplyError::errno)
            .map(|a| a.ino),
        Err(fuser::Errno::ESTALE)
    );
    assert_eq!(
        fs.getattr_attr(INodeNo(file))
            .map_err(super::ReplyError::errno)
            .map(|a| a.ino),
        Err(fuser::Errno::ESTALE)
    );
    assert_eq!(
        fs.access_attr(INodeNo(file), AccessFlags::W_OK)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ESTALE)
    );
    assert_eq!(
        fs.directory_entries(1, 0, &mut LiveSink::default())
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ESTALE)
    );
    assert_eq!(
        fs.directory_entries_plus(1, 0, &mut LiveSink::default())
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ESTALE)
    );
    assert_eq!(
        fs.opendir_handle(INodeNo::ROOT)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ESTALE)
    );
}

#[cfg(feature = "conformance-breakage")]
#[test]
fn writable_live_plus_bends_attributes_once_at_terminal_conversion() {
    let (mut fs, _, file, _) = live_fixture();
    fs.set_breakage(crate::Breakage::MisreportSize);
    let mut sink = LiveSink::default();
    fs.directory_entries_plus(1, 0, &mut sink)
        .map_err(super::ReplyError::errno)
        .unwrap();
    let attr = sink.plus.iter().find(|(a, _, _)| a.ino == file).unwrap().0;
    assert_eq!(
        (attr.size, fs.bent_reply_parts(attr, fs.mount_time).1.size),
        (513, 514)
    );
}

/// Snapshot accounting, full enumeration and double-counted orphan bytes fail here.
#[test]
fn writable_statfs_uses_one_cheap_fresh_capacity_read_and_preserves_ro() {
    for writable in [true, false] {
        let fs = mutable_adapter(writable);
        let values = [
            crate::OverlayCapacity {
                cap: 65536,
                files: 1,
                free_entries: 7,
                ..Default::default()
            },
            crate::OverlayCapacity {
                cap: 65536,
                charged: 8192,
                reserved: 4096,
                captured: 4096,
                files: 3,
                free_entries: 4,
            },
            crate::OverlayCapacity {
                cap: 65536,
                charged: 16384,
                reserved: 4096,
                captured: 4096,
                files: 2,
                free_entries: 3,
            },
            crate::OverlayCapacity {
                cap: 65536,
                charged: u64::MAX,
                reserved: 4096,
                captured: 4096,
                files: 2,
                free_entries: 0,
            },
        ];
        for value in values {
            fs.write_inner(|inner| {
                inner.backend.capacity = value;
                Ok(())
            })
            .unwrap();
            let free = value
                .cap
                .saturating_sub(value.charged)
                .saturating_sub(value.reserved)
                .saturating_sub(value.captured)
                / 4096;
            let wanted = if writable {
                (
                    16,
                    free,
                    free,
                    value.files,
                    value.free_entries,
                    4096,
                    255,
                    4096,
                )
            } else {
                statfs_reply(fs.snapshot.stats())
            };
            assert_eq!(
                fs.statfs_dispatch().map_err(super::ReplyError::errno),
                Ok(wanted),
                "fresh mediated capacity: {value:?}"
            );
        }
        let counts = fs
            .write_inner(|inner| Ok((inner.backend.capacity_calls, inner.backend.view_calls)))
            .unwrap();
        assert_eq!(
            counts,
            (if writable { 4 } else { 0 }, 0),
            "statfs must never enumerate entries"
        );
    }
}

#[test]
fn writable_statfs_propagates_owner_failure_without_snapshot_fallback() {
    let fs = mutable_adapter(true);
    fs.write_inner(|inner| {
        inner.backend.view_error = Some(crate::WriteError::Backend(crate::MountError::Stale));
        Ok(())
    })
    .unwrap();
    assert_eq!(
        fs.statfs_dispatch().map_err(super::ReplyError::errno),
        Err(fuser::Errno::ESTALE)
    );
}

#[test]
fn writable_owner_policy_is_preserved_at_live_and_immutable_reply_sites() {
    let (live, _, file, _) = live_fixture();
    let (ro, _) = fixture_fs();
    let ro_file = ro
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .unwrap();
    let mut sink = LiveSink::default();
    live.directory_entries_plus(1, 0, &mut sink)
        .map_err(super::ReplyError::errno)
        .unwrap();
    let mut cases = 0;
    for (fs, ino, mode) in [(&live, file, 0o755), (&live, 1, 0o755)] {
        let attr = fs
            .getattr_attr(INodeNo(ino))
            .map_err(super::ReplyError::errno)
            .unwrap();
        let kernel = to_file_attr(&attr);
        assert_eq!((kernel.uid, kernel.gid, kernel.perm), (3, 4, mode));
        cases += 1;
    }
    for attr in [
        ro_file,
        ro.getattr_attr(INodeNo::ROOT)
            .map_err(super::ReplyError::errno)
            .unwrap(),
    ] {
        let kernel = to_file_attr(&attr);
        assert_eq!((kernel.uid, kernel.gid), (3, 4));
        cases += 1;
    }
    assert!(sink.plus.iter().all(|(a, _, _)| (a.uid, a.gid) == (3, 4)));
    assert_eq!(cases, 4);
}

#[test]
fn writable_detached_inode_only_chmod_preserves_checked_object_and_refuses_exec_change() {
    let fs = bound_adapter();
    let (attr, held) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"old",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .map_err(super::ReplyError::errno)
        .unwrap();
    let ino = INodeNo(attr.ino);
    fs.remove_overlay(INodeNo::ROOT, b"old", false)
        .map_err(super::ReplyError::errno)
        .unwrap();
    let (replacement, _) = fs
        .create_overlay(INodeNo::ROOT, b"old", NodeKind::File, 0o755, None)
        .map_err(super::ReplyError::errno)
        .unwrap();
    let before = fs
        .inner
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .backend
        .calls
        .clone();
    assert_eq!(
        (
            fs.setattr_result(ino, Some(0o755), None, false, None)
                .map_err(super::ReplyError::errno)
                .map(|a| a.perm),
            fs.setattr_result(ino, Some(0o644), None, false, None)
                .map_err(super::ReplyError::errno)
                .map(|a| a.perm)
        ),
        (Err(fuser::Errno::ENOTSUP), Ok(0o644)),
        "inode-only fchmod must select the held object before detached metadata policy"
    );
    assert_eq!(
        fs.setattr_result(ino, Some(0o644), Some(1), false, None)
            .map_err(super::ReplyError::errno)
            .map(|a| a.size),
        Err(fuser::Errno::ENOENT)
    );
    assert_eq!(
        fs.setattr_result(ino, Some(0o644), None, true, None)
            .map_err(super::ReplyError::errno)
            .map(|a| a.perm),
        Err(fuser::Errno::ENOTSUP)
    );
    assert_eq!(
        fs.getattr_attr(INodeNo(replacement.ino))
            .map_err(super::ReplyError::errno)
            .unwrap()
            .perm,
        0o755
    );
    assert_eq!(
        fs.inner.lock().unwrap().as_ref().unwrap().backend.calls,
        before
    );
    fs.release_handle(held.unwrap(), HandleKind::File)
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        fs.setattr_result(ino, Some(0o644), None, false, None)
            .map_err(super::ReplyError::errno)
            .map(|a| a.perm),
        Err(fuser::Errno::ENOENT),
        "lookup credits alone cannot authorize orphan metadata"
    );
    let (ro, _) = fixture_fs();
    let leaf = ro
        .lookup_entry(INodeNo::ROOT, b"leaf")
        .map_err(super::ReplyError::errno)
        .unwrap();
    assert_eq!(
        ro.setattr_result(INodeNo(leaf.ino), Some(0o444), None, false, None)
            .map_err(super::ReplyError::errno)
            .map(|a| a.perm),
        Err(fuser::Errno::EROFS)
    );
}

/// An errno-only terminal loses the content failure class while keeping EIO.
#[test]
fn writable_terminal_preserves_content_failure_classes() {
    let mut cases = 0;
    for cause in [
        crate::MountError::Corrupt,
        crate::MountError::Unavailable,
        crate::MountError::Io,
    ] {
        let mut fs = mutable_adapter(true);
        let observer = Arc::new(Replies::default());
        fs.observer = Some(observer.clone());
        fs.inner
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .backend
            .view_error = Some(crate::WriteError::Backend(cause));
        let result = fs.statfs_dispatch();
        assert_eq!(
            fs.completed(crate::Callback::Statfs, result),
            Err(fuser::Errno::EIO)
        );
        assert_eq!(
            observer.0.lock().unwrap().as_slice(),
            &[(
                crate::Callback::Statfs,
                crate::CallbackOutcome::Failed(cause)
            )],
            "terminal must retain the typed content class"
        );
        assert_eq!(
            fs.inner
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .backend
                .capacity_calls,
            1
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

fn terminal_site_action(
    fs: &GranaryFs<MutableBackend>,
    site: &str,
    ino: INodeNo,
    handle: fuser::FileHandle,
    plain_ino: u64,
    link_ino: u64,
) -> (crate::Callback, Result<(), super::ReplyError>) {
    match site {
        "mutation_readiness" => (crate::Callback::Link, fs.refused_mutation()),
        "overlay_lookup" => (
            crate::Callback::Lookup,
            fs.lookup_entry(INodeNo::ROOT, b"file").map(|_| ()),
        ),
        "overlay_capacity" => (crate::Callback::Statfs, fs.statfs_dispatch().map(|_| ())),
        "overlay_readlink" => (
            crate::Callback::Readlink,
            fs.readlink_bytes(INodeNo(link_ino)).map(|_| ()),
        ),
        "overlay_open" => (
            crate::Callback::Open,
            fs.open_flags_handle(ino, fuser::OpenFlags(0)).map(|_| ()),
        ),
        "overlay_object" => {
            fs.remove_overlay(INodeNo::ROOT, b"file", false).unwrap();
            (crate::Callback::Getattr, fs.getattr_attr(ino).map(|_| ()))
        }
        "prepare_object" => (
            crate::Callback::Write,
            fs.write_overlay(ino, handle, 0, b"x").map(|_| ()),
        ),
        "read_object" => (
            crate::Callback::Read,
            fs.read_handle_bytes(ino, handle, 0, 1).map(|_| ()),
        ),
        "overlay_close" => (
            crate::Callback::Release,
            fs.release_handle(handle, HandleKind::File),
        ),
        "prepare_detach" => (
            crate::Callback::Unlink,
            fs.remove_overlay(INodeNo::ROOT, b"file", false),
        ),
        "prepare_overlay" => (
            crate::Callback::Setattr,
            fs.setattr_result(INodeNo(plain_ino), None, Some(1), false, None)
                .map(|_| ()),
        ),
        "overlay_mutate" => (
            crate::Callback::Mkdir,
            fs.create_overlay(INodeNo::ROOT, b"dir", NodeKind::Dir, 0o755, None)
                .map(|_| ()),
        ),
        _ => unreachable!(),
    }
}

/// Each backend map must carry a typed cause, including preparation outside gates.
#[test]
fn writable_terminal_backend_sites_keep_typed_failures_and_errno() {
    let mut cases = 0;
    for cause in [
        crate::MountError::Corrupt,
        crate::MountError::Unavailable,
        crate::MountError::Io,
    ] {
        for site in [
            "mutation_readiness",
            "overlay_lookup",
            "overlay_capacity",
            "overlay_readlink",
            "overlay_open",
            "overlay_object",
            "prepare_object",
            "read_object",
            "overlay_close",
            "prepare_detach",
            "prepare_overlay",
            "overlay_mutate",
        ] {
            let mut fs = bound_adapter();
            let observer = Arc::new(Replies::default());
            fs.observer = Some(observer.clone());
            let (attr, handle) = fs
                .create_overlay(
                    INodeNo::ROOT,
                    b"file",
                    NodeKind::File,
                    0o644,
                    Some(fuser::OpenFlags(2)),
                )
                .unwrap();
            let handle = handle.unwrap();
            let ino = INodeNo(attr.ino);
            let plain_ino = fs
                .create_overlay(INodeNo::ROOT, b"plain", NodeKind::File, 0o644, None)
                .unwrap()
                .0
                .ino;
            let link_ino = fs
                .symlink_overlay(INodeNo::ROOT, b"link", b"target")
                .unwrap()
                .ino;
            fs.inner.lock().unwrap().as_mut().unwrap().backend.failure = Some((site, cause));
            let (callback, result) =
                terminal_site_action(&fs, site, ino, handle, plain_ino, link_ino);
            assert_eq!(fs.completed(callback, result), Err(fuser::Errno::EIO));
            assert_eq!(
                observer.0.lock().unwrap().as_slice(),
                &[(callback, crate::CallbackOutcome::Failed(cause))],
                "typed terminal cause at {site}"
            );
            assert_eq!(
                fs.inner
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .backend
                    .failures_seen,
                1,
                "nonzero exact injected seam {site}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 36);
}

/// Refused bounds must not reach copy-up, even when the backend would accept them.
#[test]
fn writable_guard_bounds_and_parent_type_precede_preparation() {
    let fs = bound_adapter();
    let (attr, fh) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"file",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .unwrap();
    let ino = INodeNo(attr.ino);
    let fh = fh.unwrap();
    let wr = fs.open_flags_handle(ino, fuser::OpenFlags(1)).unwrap();
    let initial = {
        let slot = fs.inner.lock().unwrap();
        let b = &slot.as_ref().unwrap().backend;
        (b.calls.len(), b.prepare_count)
    };
    let too_long =
        vec![0; usize::try_from(granary_core::overlay_journal::EXTENT_LEN_MAX).unwrap() + 1];
    let mut cases = 0;
    for (offset, bytes, error) in [
        (0, too_long.as_slice(), fuser::Errno::EINVAL),
        (u64::MAX, b"x".as_slice(), fuser::Errno::EINVAL),
        (u64::MAX, b"".as_slice(), fuser::Errno::EFBIG),
        (
            granary_core::overlay_journal::SIZE_MAX,
            b"x".as_slice(),
            fuser::Errno::EFBIG,
        ),
    ] {
        assert_eq!(
            fs.write_overlay(ino, fh, offset, bytes)
                .map_err(super::ReplyError::errno),
            Err(error),
            "write bounds before capture"
        );
        cases += 1;
    }
    assert_eq!(
        fs.read_handle_bytes(ino, wr, 0, 0)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EBADF),
        "empty read validates write-only mode"
    );
    assert_eq!(
        fs.read_handle_bytes(ino, fh, 0, granary_vfs::READ_MAX_BYTES + 1)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EINVAL),
        "read size is bounded before preparation"
    );
    assert_eq!(
        fs.create_overlay(ino, b"child", NodeKind::File, 0o644, None)
            .map(|_| ())
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOTDIR),
        "parent type before capture"
    );
    assert_eq!(
        fs.setattr_result(ino, None, Some(u64::MAX), false, Some(fh))
            .map(|_| ())
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EFBIG),
        "resize bound before preparation"
    );
    let slot = fs.inner.lock().unwrap();
    let b = &slot.as_ref().unwrap().backend;
    assert_eq!(
        (b.calls.len(), b.prepare_count),
        initial,
        "guard refusals have no captured or prepared prefix"
    );
    assert_eq!(cases + 4, 8);
}

/// Root-only and fresh-name fixtures cannot discriminate these live-view guards.
#[test]
fn writable_guard_live_parents_detachment_dots_and_resume() {
    let (fs, dir, file, _) = live_fixture();
    assert_eq!(
        fs.lookup_entry(INodeNo(file), b"child")
            .map(|_| ())
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOTDIR),
        "lookup validates a regular parent"
    );
    assert_eq!(
        (
            fs.lookup_entry(INodeNo(file), b"invalid/name")
                .map(|_| ())
                .map_err(super::ReplyError::errno),
            fs.lookup_entry(INodeNo::ROOT, b"invalid/name")
                .map(|_| ())
                .map_err(super::ReplyError::errno)
        ),
        (Err(fuser::Errno::ENOTDIR), Err(fuser::Errno::EINVAL)),
        "live parent type refusal precedes malformed child name"
    );
    assert_eq!(
        fs.directory_entries(file, 0, &mut LiveSink::default())
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOTDIR),
        "listing validates directory kind"
    );
    assert_eq!(
        fs.directory_entries_plus(file, 0, &mut LiveSink::default())
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOTDIR)
    );
    assert_eq!(
        fs.setattr_result(INodeNo(dir), None, Some(1), false, None)
            .map(|_| ())
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EISDIR),
        "directory resize refuses before preparation"
    );
    let mut resumed = LiveSink::default();
    fs.directory_entries_plus(1, 3, &mut resumed).unwrap();
    assert_eq!(
        (
            resumed.plus.len(),
            resumed.plus.first().unwrap().1.as_slice()
        ),
        (2, b"live-file".as_slice()),
        "PLUS cookie resumes after admitted entries"
    );
    let mut dots = LiveSink::default();
    fs.directory_entries_plus(dir, 0, &mut dots).unwrap();
    assert_eq!(dots.plus.len(), 2);
    fs.write_inner(|inner| {
        inner.inodes.forget(dir, 1); // The creation credit; resume skipped this entry.
        assert!(
            inner.inodes.resolve(dir).is_err(),
            "nested dots must not acquire lookup credits"
        );
        Ok(())
    })
    .unwrap();
    let old = fs.lookup_entry(INodeNo::ROOT, b"live-dir").unwrap().ino;
    fs.remove_overlay(INodeNo::ROOT, b"live-dir", true).unwrap();
    let new = fs
        .create_overlay(INodeNo::ROOT, b"live-dir", NodeKind::Dir, 0o755, None)
        .unwrap()
        .0
        .ino;
    fs.create_overlay(INodeNo(new), b"child", NodeKind::File, 0o644, None)
        .unwrap();
    assert_eq!(
        fs.lookup_entry(INodeNo(old), b"child")
            .map(|_| ())
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOENT),
        "detached directory cannot query replacement children"
    );
    assert!(fs.lookup_entry(INodeNo(new), b"child").is_ok());
}

/// Exact release must retire the adapter resource maps as well as the backend hold.
#[test]
fn writable_guard_release_retires_exact_resource_maps() {
    let fs = bound_adapter();
    let (attr, first) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"file",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(2)),
        )
        .unwrap();
    let first = first.unwrap();
    let second = fs
        .open_flags_handle(INodeNo(attr.ino), fuser::OpenFlags(2))
        .unwrap();
    for (fh, remaining) in [(first, 1), (second, 0)] {
        fs.release_handle(fh, HandleKind::File).unwrap();
        fs.release_handle(fh, HandleKind::File).unwrap();
        fs.write_inner(|inner| {
            assert_eq!(
                (
                    inner.object_handles.len(),
                    inner.write_handles.len(),
                    inner.backend.closes.len()
                ),
                (remaining, remaining, 2 - remaining),
                "exact release retires resource maps once"
            );
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn writable_guard_statfs_clamps_backend_entry_count_to_adapter_identity_space() {
    let fs = mutable_adapter(true);
    fs.write_inner(|inner| {
        inner.backend.capacity.free_entries = u64::MAX;
        Ok(())
    })
    .unwrap();
    assert_eq!(
        fs.statfs_dispatch().unwrap().4,
        u64::MAX - 2,
        "entry estimate cannot exceed remaining session identities"
    );
}

#[test]
fn writable_directory_pages_survive_unlink_and_create() {
    for plus in [false, true] {
        let (fs, dir, _, _) = live_fixture();
        let fh = fs.opendir_handle(INodeNo::ROOT).unwrap();
        assert_eq!(
            fs.directory_entries_handle(dir, fh, 0, &mut LiveSink::default())
                .map_err(super::ReplyError::errno),
            Err(fuser::Errno::EBADF)
        );
        assert_eq!(
            fs.directory_entries_plus_handle(dir, fh, 0, &mut LiveSink::default())
                .map_err(super::ReplyError::errno),
            Err(fuser::Errno::EBADF)
        );
        let mut first = LiveSink {
            capacity: Some(3),
            ..LiveSink::default()
        };
        let offset = if plus {
            fs.directory_entries_plus_handle(1, fh, 0, &mut first)
                .unwrap();
            first.plus.last().unwrap().2
        } else {
            fs.directory_entries_handle(1, fh, 0, &mut first).unwrap();
            first.plain.last().unwrap().3
        };
        fs.remove_overlay(INodeNo::ROOT, b"live-dir", true).unwrap();
        fs.create_overlay(INodeNo::ROOT, b"zz-added", NodeKind::File, 0o644, None)
            .unwrap();
        let mut second = LiveSink::default();
        let names = if plus {
            fs.directory_entries_plus_handle(1, fh, offset, &mut second)
                .unwrap();
            second
                .plus
                .iter()
                .map(|r| r.1.as_slice())
                .collect::<Vec<_>>()
        } else {
            fs.directory_entries_handle(1, fh, offset, &mut second)
                .unwrap();
            second
                .plain
                .iter()
                .map(|r| r.2.as_slice())
                .collect::<Vec<_>>()
        };
        assert!(
            names.contains(&b"live-file".as_slice()) && names.contains(&b"live-link".as_slice())
        );
        assert_eq!(
            names,
            [b"live-file".as_slice(), b"live-link", b"zz-added"],
            "entry skipped or duplicated"
        );
        fs.release_handle(fh, HandleKind::Directory).unwrap();
        fs.write_inner(|inner| {
            assert!(inner.directory_cursors.is_empty());
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn writable_entry_attribute_failure_leaves_no_unpublished_holds() {
    for operation in ["create", "mkdir", "mknod", "symlink"] {
        let fs = mutable_adapter(true);
        fs.write_inner(|inner| {
            inner.backend.bind_objects = true;
            inner.backend.failure = Some(("overlay_path", crate::MountError::Io));
            Ok(())
        })
        .unwrap();
        let result = if operation == "symlink" {
            fs.symlink_overlay(INodeNo::ROOT, b"new", b"target")
                .map(|_| ())
        } else {
            fs.create_overlay(
                INodeNo::ROOT,
                b"new",
                if operation == "mkdir" {
                    NodeKind::Dir
                } else {
                    NodeKind::File
                },
                0o644,
                (operation == "create").then_some(fuser::OpenFlags(2)),
            )
            .map(|_| ())
        };
        assert_eq!(
            result.map_err(super::ReplyError::errno),
            Err(fuser::Errno::EIO)
        );
        fs.write_inner(|inner| {
            assert!(
                inner.backend.objects.is_empty(),
                "unpublished backend hold: {operation}"
            );
            assert_eq!(
                inner.inodes.resident_count(),
                1,
                "unpublished lookup credit: {operation}"
            );
            assert!(inner.write_handles.is_empty() && inner.object_handles.is_empty());
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn writable_unimplemented_live_view_never_serves_snapshot_entries() {
    let (fs, _, _, link) = live_fixture();
    let fh = fs.opendir_handle(INodeNo::ROOT).unwrap();
    let (leaf, handle) = fs
        .create_overlay(
            INodeNo::ROOT,
            b"leaf",
            NodeKind::File,
            0o644,
            Some(fuser::OpenFlags(0)),
        )
        .unwrap();
    fs.write_inner(|inner| {
        inner.backend.view_error = Some(crate::WriteError::Unimplemented);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        fs.lookup_entry(INodeNo::ROOT, b"leaf")
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOSYS)
    );
    assert_eq!(
        fs.getattr_attr(INodeNo::ROOT)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOSYS)
    );
    assert_eq!(
        fs.directory_entries_handle(1, fh, 0, &mut LiveSink::default())
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOSYS)
    );
    assert_eq!(
        fs.directory_entries_plus_handle(1, fh, 0, &mut LiveSink::default())
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOSYS)
    );
    assert_eq!(
        fs.readlink_bytes(INodeNo(link))
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOSYS)
    );
    assert_eq!(
        fs.open_flags_handle(INodeNo::ROOT, fuser::OpenFlags(0))
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOSYS)
    );
    assert_eq!(
        fs.setattr_result(INodeNo::ROOT, None, None, false, None)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOSYS)
    );
    assert_eq!(
        fs.read_handle_bytes(INodeNo(leaf.ino), handle.unwrap(), 0, 1)
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::ENOSYS)
    );
}

#[test]
fn writable_fallocate_checks_mutation_and_handle_before_refusal() {
    for mode in [0, 1, 3, 8, 16, 32, 64, i32::MAX] {
        let fs = mutable_adapter(true);
        let (attr, fh) = fs
            .create_overlay(
                INodeNo::ROOT,
                b"file",
                NodeKind::File,
                0o644,
                Some(fuser::OpenFlags(2)),
            )
            .unwrap();
        let ino = INodeNo(attr.ino);
        let fh = fh.unwrap();
        assert_eq!(
            fs.fallocate_result(ino, fh, mode)
                .map_err(super::ReplyError::errno),
            Err(fuser::Errno::ENOTSUP)
        );
        assert_eq!(
            fs.fallocate_result(ino, fuser::FileHandle(u64::MAX), mode)
                .map_err(super::ReplyError::errno),
            Err(fuser::Errno::EBADF)
        );
        assert_eq!(
            fs.fallocate_result(INodeNo::ROOT, fh, mode)
                .map_err(super::ReplyError::errno),
            Err(fuser::Errno::EBADF)
        );
        let readonly = fs.open_flags_handle(ino, fuser::OpenFlags(0)).unwrap();
        assert_eq!(
            fs.fallocate_result(ino, readonly, mode)
                .map_err(super::ReplyError::errno),
            Err(fuser::Errno::EBADF)
        );
        let directory = fs.opendir_handle(INodeNo::ROOT).unwrap();
        assert_eq!(
            fs.fallocate_result(INodeNo::ROOT, directory, mode)
                .map_err(super::ReplyError::errno),
            Err(fuser::Errno::EBADF)
        );
        fs.write_inner(|i| {
            i.backend.failure = Some(("mutation_readiness", crate::MountError::Stale));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            fs.fallocate_result(ino, fuser::FileHandle(u64::MAX), mode)
                .map_err(super::ReplyError::errno),
            Err(fuser::Errno::ESTALE)
        );
        let ro = mutable_adapter(false);
        assert_eq!(
            ro.fallocate_result(ino, fh, mode)
                .map_err(super::ReplyError::errno),
            Err(fuser::Errno::EROFS)
        );
    }
}

impl<B: MountBackend> GranaryFs<B> {
    fn write_overlay(
        &self,
        ino: INodeNo,
        fh: fuser::FileHandle,
        offset: u64,
        bytes: &[u8],
    ) -> Result<u32, super::ReplyError> {
        let flags = self.write_inner(|i| {
            Ok(i.write_handles
                .get(&u64::from(fh))
                .copied()
                .unwrap_or(fuser::OpenFlags(0)))
        })?;
        self.write_overlay_request(ino, fh, offset, bytes, flags)
            .map(|(written, _)| written)
    }
}
#[test]
fn writable_write_uses_current_append_and_refuses_request_sync() {
    #[cfg(target_os = "linux")]
    const APPEND: i32 = 1024;
    #[cfg(target_os = "macos")]
    const APPEND: i32 = 8;
    #[cfg(target_os = "linux")]
    const SYNC: i32 = 0x0010_1000;
    #[cfg(target_os = "macos")]
    const SYNC: i32 = 0x80;
    #[cfg(target_os = "linux")]
    const DSYNC: i32 = 0x1000;
    #[cfg(target_os = "macos")]
    const DSYNC: i32 = 0x0040_0000;
    for opened in [2, 2 | APPEND] {
        let fs = bound_adapter();
        let (attr, fh) = fs
            .create_overlay(
                INodeNo::ROOT,
                b"file",
                NodeKind::File,
                0o644,
                Some(fuser::OpenFlags(opened)),
            )
            .unwrap();
        let ino = INodeNo(attr.ino);
        let fh = fh.unwrap();
        fs.setattr_overlay(ino, None, Some(8), false, Some(fh))
            .unwrap();
        fs.write_overlay_request(ino, fh, 0, b"X", fuser::OpenFlags(2))
            .unwrap();
        assert_eq!(
            fs.getattr_attr(ino).unwrap().size,
            8,
            "cleared append wrote at EOF"
        );
        fs.write_overlay_request(ino, fh, 0, b"X", fuser::OpenFlags(2 | APPEND))
            .unwrap();
        assert_eq!(
            fs.getattr_attr(ino).unwrap().size,
            9,
            "current append overwrote offset zero"
        );
        for (flag, expected_call) in [(DSYNC, "fdatasync"), (SYNC, "fsync")] {
            let delivered = Arc::new(Mutex::new(None));
            let slot = delivered.clone();
            fs.write_with_sync(
                ino,
                fh,
                0,
                b"Z",
                fuser::OpenFlags(2 | flag),
                move |result| {
                    *slot.lock().unwrap() = Some(result);
                },
            );
            let last_call = fs
                .write_inner(|i| Ok(i.backend.calls.last().copied()))
                .unwrap();
            assert_eq!(
                (*delivered.lock().unwrap(), last_call),
                (Some(Ok(1)), Some(expected_call))
            );
        }
        let ro = mutable_adapter(false);
        assert_eq!(
            ro.write_overlay_request(ino, fh, 0, b"X", fuser::OpenFlags(2 | DSYNC))
                .map_err(super::ReplyError::errno),
            Err(fuser::Errno::EROFS)
        );
    }
}

impl<B: MountBackend> GranaryFs<B> {
    fn directory_entries<S: crate::DirSink>(
        &self,
        ino: u64,
        offset: u64,
        sink: &mut S,
    ) -> Result<(), super::ReplyError> {
        let fh = self.opendir_handle(INodeNo(ino))?;
        let result = self.directory_entries_handle(ino, fh, offset, sink);
        self.release_handle(fh, HandleKind::Directory)?;
        result
    }
    fn directory_entries_plus<S: crate::DirPlusSink>(
        &self,
        ino: u64,
        offset: u64,
        sink: &mut S,
    ) -> Result<(), super::ReplyError> {
        let fh = self.opendir_handle(INodeNo(ino))?;
        let result = self.directory_entries_plus_handle(ino, fh, offset, sink);
        self.release_handle(fh, HandleKind::Directory)?;
        result
    }
}

#[test]
fn writable_directory_cookie_exhaustion_refuses_without_reuse() {
    let fs = mutable_adapter(true);
    let fh = fs.opendir_handle(INodeNo::ROOT).unwrap();
    fs.write_inner(|inner| {
        inner
            .directory_cursors
            .get_mut(&u64::from(fh))
            .unwrap()
            .insert(b".".to_vec(), u64::MAX);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        fs.directory_entries_handle(1, fh, 0, &mut LiveSink::default())
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EOVERFLOW)
    );
    assert_eq!(
        fs.directory_entries_plus_handle(1, fh, 0, &mut LiveSink::default())
            .map_err(super::ReplyError::errno),
        Err(fuser::Errno::EOVERFLOW)
    );
}

// Discarded pages are owned by their attempt even when no row reaches a sink.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one listing witness joins retry outcomes with measured copies for every attempt"
)]
fn writable_listing_copy_bound_counts_each_attempt_owned_rows() {
    let mut cases = 0;
    for plus in [false, true] {
        for changes in [0, 1, 2, 3] {
            let fs = mutable_adapter(true);
            fs.write_inner(|inner| {
                for index in 0..513 {
                    let path = vec![Name::new(format!("child-{index:04}").into_bytes()).unwrap()];
                    inner.backend.nodes.insert(
                        path.clone(),
                        crate::OverlayNode {
                            path,
                            kind: NodeKind::File,
                            size: 7,
                            exec: false,
                            stage: None,
                        },
                    );
                }
                let cardinality = inner.backend.nodes.len();
                assert_eq!(cardinality, 514, "fixture cardinality: {cardinality}");
                inner.backend.page_changes = changes;
                Ok(())
            })
            .unwrap();
            let fh = fs.opendir_handle(INodeNo::ROOT).unwrap();
            fs.write_inner(|inner| {
                inner.backend.attempt_child_rows.clear();
                inner.backend.attempt_copy_starts.clear();
                Ok(())
            })
            .unwrap();
            let mut sink = LiveSink::default();
            let result = if plus {
                fs.directory_entries_plus_handle(1, fh, 0, &mut sink)
            } else {
                fs.directory_entries_handle(1, fh, 0, &mut sink)
            }
            .map_err(super::ReplyError::errno);
            let (copied, pages, attempts, whole_views, measured_copies) = fs
                .write_inner(|inner| {
                    Ok((
                        inner.backend.copied_child_rows,
                        inner.backend.page_calls,
                        inner.backend.attempt_child_rows.clone(),
                        inner.backend.view_calls,
                        inner
                            .backend
                            .attempt_copy_starts
                            .iter()
                            .enumerate()
                            .map(|(i, start)| {
                                inner
                                    .backend
                                    .attempt_copy_starts
                                    .get(i + 1)
                                    .copied()
                                    .unwrap_or_else(crate::source::entry_copies)
                                    - start
                            })
                            .collect::<Vec<_>>(),
                    ))
                })
                .unwrap();
            let offered = if plus {
                sink.plus.len()
            } else {
                sink.plain.len()
            };
            let mut expected_attempts = vec![256; changes.min(3)];
            if changes < 3 {
                expected_attempts.push(513);
            }
            let expected = if changes == 3 {
                (Err(fuser::Errno::EAGAIN), 0, 768, 6)
            } else {
                (Ok(()), 515, 513 + changes * 256, 3 + changes * 2)
            };
            assert_eq!(
                ((result, offered, copied, pages), &attempts, whole_views),
                (expected, &expected_attempts, 0),
                "listing plus={plus}, context changes={changes}"
            );
            // Directory and parent copies are the only entries beyond owned children.
            let per_attempt: Vec<_> = attempts
                .iter()
                .zip(measured_copies)
                .map(|(owned, copies)| {
                    (
                        *owned,
                        copies,
                        listing_attempt_bound(*owned, (0, 0, copies)),
                    )
                })
                .collect();
            let expected_bounds: Vec<_> = expected_attempts
                .iter()
                .map(|owned| (*owned, *owned + 2, Ok(())))
                .collect();
            assert_eq!(
                per_attempt, expected_bounds,
                "per-attempt extra-entry ceiling"
            );
            eprintln!(
                "listing plus={plus}, changes={changes}: owned_children={attempts:?}, copied_children={copied}, extra_entries_per_attempt=2, returned={offered}"
            );
            fs.release_handle(fh, HandleKind::Directory).unwrap();
            cases += 1;
        }
    }
    assert_eq!(cases, 8, "nonempty listing attempt cases: {cases}");
}

fn listing_attempt_bound(owned: usize, work: (usize, usize, usize)) -> Result<(), &'static str> {
    match work {
        (copies, _, _) if copies != 0 => Err("listing attempt copied a whole namespace"),
        (_, visits, _) if visits != 0 => Err("listing attempt iterated the primary map"),
        (_, _, entries) if entries.saturating_sub(owned) > 2 => {
            Err("listing attempt copied more than 2 extra entries")
        }
        _ => Ok(()),
    }
}

#[test]
fn listing_attempt_accounting_rejects_each_independent_work_violation() {
    let mut cases = 0;
    for (malformed, refusal) in [
        ((1, 0, 258), "listing attempt copied a whole namespace"),
        ((0, 1, 258), "listing attempt iterated the primary map"),
        (
            (0, 0, 259),
            "listing attempt copied more than 2 extra entries",
        ),
    ] {
        assert_eq!(
            (
                listing_attempt_bound(256, (0, 0, 258)),
                listing_attempt_bound(256, malformed)
            ),
            (Ok(()), Err(refusal)),
            "owned=256, valid=(0, 0, 258), malformed={malformed:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 3, "independent accounting paired controls: {cases}");
}

#[test]
fn writable_creation_and_detach_query_sequences_are_bounded() {
    let mut cases = 0;
    for (kind, opened, expected_size, expected_nlink) in [
        (NodeKind::File, true, 0, 1),
        (NodeKind::File, false, 0, 1),
        (NodeKind::Dir, false, 4096, 2),
        (NodeKind::Symlink, false, 5, 1),
    ] {
        let fs = mutable_adapter(true);
        fs.write_inner(|inner| {
            inner.backend.bind_objects = true;
            Ok(())
        })
        .unwrap();
        let initial = fs
            .write_inner(|inner| Ok((inner.backend.nodes.len(), inner.backend.objects.len())))
            .unwrap();
        assert_eq!(
            initial,
            (1, 0),
            "actual namespace/held cardinalities: {initial:?}"
        );
        let (attr, fh) = if kind == NodeKind::Symlink {
            (
                fs.symlink_overlay(INodeNo::ROOT, b"new", b"f.txt").unwrap(),
                None,
            )
        } else {
            fs.create_overlay(
                INodeNo::ROOT,
                b"new",
                kind,
                0o644,
                opened.then_some(fuser::OpenFlags(2)),
            )
            .unwrap()
        };
        let created = fs
            .write_inner(|i| {
                Ok((
                    i.backend.path_queries,
                    i.backend.open_queries,
                    i.backend.view_calls,
                    i.backend.calls.len(),
                    i.backend.nodes.len(),
                ))
            })
            .unwrap();
        assert_eq!(
            ((attr.kind, attr.size, attr.nlink, fh.is_some()), created),
            (
                (kind, expected_size, expected_nlink, opened),
                (1, usize::from(opened), 0, 1, 2)
            ),
            "creation must query final metadata once and bind only an opened file"
        );
        fs.remove_overlay(INodeNo::ROOT, b"new", kind == NodeKind::Dir)
            .unwrap();
        let removed = fs
            .write_inner(|i| {
                Ok((
                    i.backend.path_queries,
                    i.backend.open_queries,
                    i.backend.detach_preparations,
                    i.backend.view_calls,
                    i.backend.calls.len(),
                    i.backend.nodes.len(),
                ))
            })
            .unwrap();
        let detached = fs
            .getattr_attr(INodeNo(attr.ino))
            .map(|a| (a.kind, a.size, a.nlink))
            .map_err(super::ReplyError::errno);
        assert_eq!(
            (removed, detached),
            (
                (
                    2,
                    usize::from(opened),
                    usize::from(kind != NodeKind::Dir),
                    0,
                    2,
                    1
                ),
                Ok((kind, expected_size, 0))
            ),
            "detach must retain metadata before removal without a whole-tree or second path query"
        );
        if let Some(fh) = fh {
            fs.release_handle(fh, HandleKind::File).unwrap();
        }
        cases += 1;
    }
    assert_eq!(
        cases, 4,
        "nonempty creation/detach adapter controls: {cases}"
    );
}

fn malformed_backend_row(fault: ChildReply) {
    let mut cases = 0;
    for plus in [false, true] {
        for fault in [ChildReply::Valid, fault] {
            let valid = matches!(fault, ChildReply::Valid);
            let mut fs = mutable_adapter(true);
            let observer = Arc::new(Replies::default());
            fs.observer = Some(observer.clone());
            fs.write_inner(|inner| {
                for index in 0..257 {
                    let path = vec![Name::new(format!("child-{index:04}").into_bytes()).unwrap()];
                    inner.backend.nodes.insert(
                        path.clone(),
                        crate::OverlayNode {
                            path,
                            kind: NodeKind::File,
                            size: 7,
                            exec: false,
                            stage: None,
                        },
                    );
                }
                assert_eq!(inner.backend.nodes.len(), 258, "nonempty two-page fixture");
                inner.backend.child_reply = fault;
                Ok(())
            })
            .unwrap();
            let fh = fs.opendir_handle(INodeNo::ROOT).unwrap();
            let mut sink = LiveSink::default();
            let callback = if plus {
                crate::Callback::Readdirplus
            } else {
                crate::Callback::Readdir
            };
            let result = if plus {
                fs.directory_entries_plus_handle(1, fh, 0, &mut sink)
            } else {
                fs.directory_entries_handle(1, fh, 0, &mut sink)
            };
            let answer = fs.completed(callback, result);
            let offered = if plus {
                sink.plus.len()
            } else {
                sink.plain.len()
            };
            let expected = if valid {
                (Ok(()), 259, crate::CallbackOutcome::Ok)
            } else {
                (
                    Err(fuser::Errno::EIO),
                    0,
                    crate::CallbackOutcome::Failed(crate::MountError::Io),
                )
            };
            assert_eq!(
                (answer, offered, observer.0.lock().unwrap().clone()),
                (expected.0, expected.1, vec![(callback, expected.2)]),
                "malformed listing plus={plus}, valid={valid}"
            );
            fs.release_handle(fh, HandleKind::Directory).unwrap();
            cases += 1;
        }
    }
    assert_eq!(
        cases, 4,
        "nonempty malformed-row and valid controls: {cases}"
    );
}

#[test]
fn writable_lookup_refuses_wrong_backend_path_before_inode_credit() {
    for valid in [true, false] {
        let mut fs = mutable_adapter(true);
        fs.create_overlay(INodeNo::ROOT, b"leaf", NodeKind::File, 0o644, None)
            .unwrap();
        let observer = Arc::new(Replies::default());
        fs.observer = Some(observer.clone());
        fs.write_inner(|inner| {
            inner.backend.child_reply = if valid {
                ChildReply::Valid
            } else {
                ChildReply::WrongLookup
            };
            Ok(())
        })
        .unwrap();
        let before = fs.write_inner(|i| Ok(i.inodes.resident_count())).unwrap();
        let result = fs.lookup_entry(INodeNo::ROOT, b"leaf").map(|_| ());
        let answer = fs.completed(crate::Callback::Lookup, result);
        let after = fs
            .write_inner(|i| {
                Ok((
                    i.inodes.resident_count(),
                    i.inodes.peek(&vec![b"other".to_vec()]),
                ))
            })
            .unwrap();
        let outcome = if valid {
            crate::CallbackOutcome::Ok
        } else {
            crate::CallbackOutcome::Failed(crate::MountError::Io)
        };
        assert_eq!(
            (answer, after, observer.0.lock().unwrap().clone()),
            (
                if valid {
                    Ok(())
                } else {
                    Err(fuser::Errno::EIO)
                },
                (before, None),
                vec![(crate::Callback::Lookup, outcome)]
            ),
            "lookup path/credit/terminal tuple, valid={valid}"
        );
    }
}

#[test]
fn listing_measured_copies_detect_an_extra_directory_entry() {
    let mut cases = 0;
    for extra in [false, true] {
        let fs = mutable_adapter(true);
        fs.write_inner(|i| {
            i.backend.child_reply = if extra {
                ChildReply::ExtraDirectoryCopy
            } else {
                ChildReply::Valid
            };
            Ok(())
        })
        .unwrap();
        let fh = fs.opendir_handle(INodeNo::ROOT).unwrap();
        let before = crate::source::entry_copies();
        fs.directory_entries_handle(1, fh, 0, &mut LiveSink::default())
            .unwrap();
        let copies = crate::source::entry_copies() - before;
        assert_eq!(
            (copies, listing_attempt_bound(0, (0, 0, copies))),
            if extra {
                (3, Err("listing attempt copied more than 2 extra entries"))
            } else {
                (2, Ok(()))
            }
        );
        fs.release_handle(fh, HandleKind::Directory).unwrap();
        cases += 1;
    }
    assert_eq!(cases, 2, "measured-copy paired controls: {cases}");
}

#[test]
fn writable_child_wrong_parent_refuses_with_one_terminal_completion() {
    malformed_backend_row(ChildReply::WrongParent);
}
#[test]
fn writable_child_nested_path_refuses_with_one_terminal_completion() {
    malformed_backend_row(ChildReply::Nested);
}
#[test]
fn writable_child_repeated_page_refuses_with_one_terminal_completion() {
    malformed_backend_row(ChildReply::Repeated);
}
#[test]
fn writable_child_descending_names_refuse_with_one_terminal_completion() {
    malformed_backend_row(ChildReply::Descending);
}
#[test]
fn writable_child_empty_continuation_refuses_with_one_terminal_completion() {
    malformed_backend_row(ChildReply::EmptyContinuation);
}
