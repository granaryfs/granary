// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::store` — the grain-per-file local
//! store: content-hash fanout CAS, uncompressed bytes, atomic
//! writes.
//!
//! Out-of-line: `granary-client`'s non-test artifact has other
//! workspace crates depending on it (`granary-sim`,
//! `granary-server`, `granary-cli`) and its own `tests/` directory
//! (`crates/granary-client/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;
use crate::fsguard::testutil::{mkfifo, within_deadline};
use std::sync::atomic::{AtomicU64, Ordering};

/// Test-only scratch dir: unique per test, removed on drop. 0444
/// files resist removal of their PARENT on some systems — chmod
/// the tree writable first if the plain remove fails.
struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        #[expect(
            clippy::disallowed_methods,
            reason = "the lint row this licenses bans `std::process::id` as AMBIENT INPUT, because the preimage of a \
            hashed or signed value must take a `WriterIdentity` instead. Here it is a SCRATCH-DIRECTORY NAME \
            and nothing else (`granary-store-test-<pid>-<counter>` under the temp dir, created and removed by \
            this fixture), and it is load-bearing for correctness there: the counter beside it is \
            per-process, and every test binary runs in its own process, so without the pid two concurrent \
            runs generate the same name and share one directory. It reaches no hashed or signed value, and \
            nothing under test reads it: this store's hashed values are object digests taken over CONTENT, \
            and the path a digest lands at is derived from the digest rather than the other way round"
        )]
        let dir = std::env::temp_dir().join(format!(
            "granary-store-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if std::fs::remove_dir_all(&self.0).is_err() {
            make_tree_writable(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn make_tree_writable(dir: &std::path::Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
            if path.is_dir() {
                make_tree_writable(&path);
            }
        }
    }
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
}

/// The marker checks the store version, chunker specification and hash algorithm.
/// Pin its exact bytes as a literal here
/// (not `marker_contents()`, which would be a tautology): a rename
/// of any key, a dropped chunker line, or a silent `STORE_VERSION`
/// bump must move this test red, not slip through as a "migration"
/// (the marker body is the one frozen on-disk string that would
/// otherwise have no literal pin).
#[test]
fn marker_body_is_pinned() {
    assert_eq!(STORE_VERSION, 1, "store version bump is a migration event");
    assert_eq!(
        marker_contents(),
        "granary-store-version 1\n\
         chunker fastcdc-v2020/4.0.1 min=131072 avg=262144 max=2097152 nl=1\n\
         hash blake3\n"
    );
}

#[test]
fn open_creates_marker() {
    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let marker =
        std::fs::read_to_string(dir.0.join("granary-store")).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(marker, marker_contents());
    drop(store);
}

#[test]
fn reopen_verifies() {
    let dir = ScratchDir::new();
    {
        Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    }
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    drop(store);
}

#[test]
fn marker_tamper_rejected() {
    let dir = ScratchDir::new();
    {
        Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    }
    let marker_path = dir.0.join("granary-store");
    std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|e| panic!("{e}"));
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&marker_path)
        .unwrap_or_else(|e| panic!("{e}"));
    f.write_all(b"X").unwrap_or_else(|e| panic!("{e}"));
    drop(f);
    let Err(err) = Store::open(&dir.0) else {
        panic!("tampered marker must be rejected");
    };
    assert!(matches!(err, StoreError::Incompatible { .. }));
}

/// The flock must gate EVERY store mutation — a second opener
/// racing a fresh store must lose cleanly (`Locked`) without
/// writing a marker or sweeping a live writer's txn/ files.
#[test]
fn locked_open_writes_no_marker_and_sweeps_nothing() {
    let dir = ScratchDir::new();
    std::fs::create_dir_all(dir.0.join("txn")).unwrap_or_else(|e| panic!("{e}"));
    std::fs::create_dir_all(dir.0.join("objects")).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(dir.0.join("txn/staged"), b"live writer's staging file")
        .unwrap_or_else(|e| panic!("{e}"));
    let holder = File::create(dir.0.join("lock")).unwrap_or_else(|e| panic!("{e}"));
    holder.try_lock().unwrap_or_else(|e| panic!("{e:?}"));
    let Err(err) = Store::open(&dir.0) else {
        panic!("locked store must refuse a second opener");
    };
    assert!(matches!(err, StoreError::Locked), "got {err:?}");
    assert!(
        !dir.0.join("granary-store").exists(),
        "no marker write before the lock is held"
    );
    assert!(
        dir.0.join("txn/staged").exists(),
        "txn/ must not be swept without the lock"
    );
}

/// A marker holding non-UTF-8 bytes is a tampered/torn store —
/// `Incompatible`, not a bare I/O error.
#[test]
fn non_utf8_marker_is_incompatible() {
    let dir = ScratchDir::new();
    std::fs::write(dir.0.join("granary-store"), [0xff, 0xfe, 0x80, 0x00])
        .unwrap_or_else(|e| panic!("{e}"));
    let Err(err) = Store::open(&dir.0) else {
        panic!("non-utf-8 marker must be rejected");
    };
    assert!(
        matches!(err, StoreError::Incompatible { .. }),
        "got {err:?}"
    );
}

/// F2: pointing harvest at a
/// mistaken directory that happens to hold `txn/` files must NOT
/// delete them. The wholesale sweep runs only on an ESTABLISHED
/// store (marker verified), never on the create path.
#[test]
fn create_path_does_not_sweep_preexisting_txn_files() {
    let dir = ScratchDir::new();
    std::fs::create_dir_all(dir.0.join("txn")).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(dir.0.join("txn/user.txt"), b"keep me").unwrap_or_else(|e| panic!("{e}"));
    // objects/ empty → this becomes a fresh store; the user file
    // must survive regardless of whether open succeeds.
    let _ = Store::open(&dir.0);
    assert!(
        dir.0.join("txn/user.txt").exists(),
        "create path must not sweep user files from txn/"
    );
}

/// F5: objects present with NO marker is a foreign directory or a
/// store whose marker was lost/tampered — refuse rather than
/// silently adopt the objects under this build's (possibly
/// different) chunker/hash tuple.
#[test]
fn objects_without_marker_are_refused_not_adopted() {
    let dir = ScratchDir::new();
    std::fs::create_dir_all(dir.0.join("objects/ab")).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(dir.0.join("objects/ab/cafe"), b"prior object")
        .unwrap_or_else(|e| panic!("{e}"));
    let Err(err) = Store::open(&dir.0) else {
        panic!("objects without a marker must be refused");
    };
    assert!(
        matches!(err, StoreError::Incompatible { .. }),
        "got {err:?}"
    );
    assert!(
        dir.0.join("objects/ab/cafe").exists(),
        "refusal must not delete the pre-existing objects"
    );
}

/// The established-store sweep still cleans orphan staging left by a
/// crashed writer of THIS store — the case the sweep exists for.
#[test]
fn established_open_sweeps_orphan_txn_staging() {
    let dir = ScratchDir::new();
    drop(Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}")));
    std::fs::write(dir.0.join("txn/12345-0"), b"orphan staging").unwrap_or_else(|e| panic!("{e}"));
    let _s = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !dir.0.join("txn/12345-0").exists(),
        "established open must sweep orphan staging"
    );
}

/// F6: a stray directory in `txn/` must not wedge the store — the
/// sweep skips non-files instead of erroring on every open.
#[test]
fn stray_directory_in_txn_does_not_wedge_open() {
    let dir = ScratchDir::new();
    drop(Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}")));
    std::fs::create_dir_all(dir.0.join("txn/stray")).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        Store::open(&dir.0).is_ok(),
        "a directory in txn/ must not wedge open"
    );
}

/// The absent case is `Missing`, not `Backend`. `Store::get` has no
/// `Missing` variant of its own — an absent object arrives as an
/// `Io` error — so a mapping that sends every `Io` to `Backend`
/// leaves `Missing` unreachable in the only production
/// implementation and the trait's `# Errors` doc overclaiming.
#[test]
fn grain_source_get_on_an_absent_object_is_missing() {
    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let absent = GrainId::of(b"never stored");
    assert_eq!(
        GrainSource::get(&store, &absent),
        Err(GrainSourceError::Missing(absent))
    );
    assert!(!GrainSource::has(&store, &absent));
    // Positive control: the same seam still returns bytes, so the
    // assertion above is about the ABSENT case and not about a
    // uniformly failing impl.
    let bytes = b"a stored object".to_vec();
    let id = GrainId::of(&bytes);
    store.put(&id, &bytes).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(GrainSource::get(&store, &id), Ok(bytes));
    assert!(GrainSource::has(&store, &id));
}

/// No machine-local path may reach a `GrainSource` error, because
/// this error text is compared across processes,
/// and `StoreError::Io`'s `context` carries the store root.
///
/// The non-`NotFound` io failure is produced by putting a DIRECTORY
/// where the object belongs: `File::open` succeeds and the read
/// fails `EISDIR` on every unix. A 0000-mode file would have been
/// the other option and is rejected — root reads it anyway, so the
/// test would pass vacuously through the `Missing`-free happy path
/// in a root container.
#[test]
fn grain_source_backend_errors_carry_no_filesystem_path() {
    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let id = GrainId::of(b"a directory stands where the object should");
    let path = store.object_path(&id);
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("{e}"));

    let err = GrainSource::get(&store, &id)
        .expect_err("a directory at the object path is not a readable object");
    // The no-path property is only meaningful on the Backend arm:
    // if this were Missing or Corrupt the assertions below would
    // hold for a rendering that never had a path to leak.
    assert!(matches!(err, GrainSourceError::Backend(_)), "got {err:?}");
    let rendered = err.to_string();
    let root = dir.0.display().to_string();
    for needle in ["/Users", "/var", "/tmp", root.as_str()] {
        assert!(
            !rendered.contains(needle),
            "{rendered:?} leaks {needle:?} into a compared artifact"
        );
    }
    // Non-vacuous in both directions: it NAMES the object, and it is
    // not `io::Error`'s Display (whose text is locale-sensitive and
    // carries `os error N`).
    assert!(
        rendered.contains(&id.to_string()),
        "{rendered:?} names no object"
    );
    assert!(
        !rendered.contains("os error"),
        "{rendered:?} is io::Error's Display, not the ErrorKind"
    );
}

/// The read path VERIFIES, and that survives the mapping:
/// bytes that do not hash to their id are `Corrupt`, never
/// `Backend`.
#[test]
fn grain_source_get_on_tampered_bytes_is_corrupt() {
    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let bytes = b"original bytes".to_vec();
    let id = GrainId::of(&bytes);
    store.put(&id, &bytes).unwrap_or_else(|e| panic!("{e}"));
    let path = store.object_path(&id);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(&path, b"tampered bytes!").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        GrainSource::get(&store, &id),
        Err(GrainSourceError::Corrupt(id))
    );
    // Presence is not integrity: `has` still says yes.
    assert!(GrainSource::has(&store, &id));
}

/// A derived `Debug` prints `_lock: File { fd: 3, path: … }` — an
/// fd number that depends on how many files the process had open,
/// and a second copy of the resolved path. Only the root is
/// printed. The root is stripped before the fd check so a temp
/// directory that happens to contain the letters `fd` cannot make
/// this pass or fail by accident.
#[test]
fn debug_prints_the_root_and_no_file_descriptor() {
    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let rendered = format!("{store:?}");
    let root = dir.0.display().to_string();
    assert!(rendered.contains(&root), "{rendered:?} omits the root");
    let without_root = rendered.replace(&root, "");
    for needle in ["fd", "File", "_lock"] {
        assert!(
            !without_root.contains(needle),
            "{rendered:?} exposes the lock file ({needle:?})"
        );
    }
}

#[test]
fn put_novel_then_duplicate() {
    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let bytes = b"hello granary";
    let id = GrainId::of(bytes);
    assert!(!store.has(&id));
    assert!(store.put(&id, bytes).unwrap_or_else(|e| panic!("{e}")));
    assert!(store.has(&id));
    assert!(!store.put(&id, bytes).unwrap_or_else(|e| panic!("{e}")));
}

#[test]
fn get_roundtrip() {
    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let bytes = b"round trip bytes".to_vec();
    let id = GrainId::of(&bytes);
    store.put(&id, &bytes).unwrap_or_else(|e| panic!("{e}"));
    let back = store.get(&id).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back, bytes);
}

#[test]
fn get_on_tampered_bytes_is_corrupt() {
    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let bytes = b"original bytes".to_vec();
    let id = GrainId::of(&bytes);
    store.put(&id, &bytes).unwrap_or_else(|e| panic!("{e}"));
    let path = store.object_path(&id);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(&path, b"tampered bytes!").unwrap_or_else(|e| panic!("{e}"));
    let err = store
        .get(&id)
        .expect_err("tampered bytes must fail hash verification");
    assert!(matches!(err, StoreError::Corrupt { id: got } if got == id));
}

#[test]
fn stored_object_permissions_are_0444() {
    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let bytes = b"perm check".to_vec();
    let id = GrainId::of(&bytes);
    store.put(&id, &bytes).unwrap_or_else(|e| panic!("{e}"));
    let path = store.object_path(&id);
    let mode = std::fs::metadata(&path)
        .unwrap_or_else(|e| panic!("{e}"))
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o444);
}

#[test]
fn second_open_while_held_is_locked() {
    let dir = ScratchDir::new();
    let _store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let Err(err) = Store::open(&dir.0) else {
        panic!("second open must fail while locked");
    };
    assert!(matches!(err, StoreError::Locked));
}

#[test]
fn orphan_txn_sweep_on_open() {
    let dir = ScratchDir::new();
    {
        Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    }
    let junk = dir.0.join("txn").join("junk");
    std::fs::write(&junk, b"leftover from a crashed writer").unwrap_or_else(|e| panic!("{e}"));
    assert!(junk.exists());
    {
        Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    }
    assert!(!junk.exists());
}

/// The store's twin of the cache's symlinked-staging sweep, and the
/// same permanent wedge: `atomic_write` stages under
/// `<pid>-<counter>`, pids are reused and every fresh process
/// restarts its counter at zero, so a link planted at
/// `txn/<pid>-0` fails `create_new` with `EEXIST` for that pid
/// forever unless the sweep clears the NAME. `remove_file` never
/// follows its final component, so it is the link that goes and the
/// target that stays. The directory half of this row is what pins
/// the one entry the sweep still leaves (F6).
#[test]
fn established_open_sweeps_a_symlinked_txn_entry_without_following_it() {
    let dir = ScratchDir::new();
    {
        Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    }

    let outside = ScratchDir::new();
    let victim = outside.0.join("someone-elses-file");
    std::fs::write(&victim, b"must survive byte for byte").unwrap_or_else(|e| panic!("{e}"));

    let planted = dir.0.join("txn").join("12345-0");
    std::os::unix::fs::symlink(&victim, &planted).unwrap_or_else(|e| panic!("{e}"));

    {
        Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    }

    assert!(
        std::fs::symlink_metadata(&planted).is_err(),
        "a symlink at a staging name wedges create_new EEXIST for that pid forever; the \
         sweep must remove the NAME"
    );
    assert_eq!(
        std::fs::read(&victim).unwrap_or_else(|e| panic!("{e}")),
        b"must survive byte for byte".to_vec(),
        "and remove_file must not have followed the link — the target is untouched"
    );

    // A DIRECTORY under txn/ is an anomaly, not staging (F6), and
    // must still be left alone.
    let subdir = dir.0.join("txn").join("a-directory");
    std::fs::create_dir(&subdir).unwrap_or_else(|e| panic!("{e}"));
    {
        Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    }
    assert!(
        std::fs::symlink_metadata(&subdir)
            .unwrap_or_else(|e| panic!("{e}"))
            .file_type()
            .is_dir(),
        "a directory under txn/ must not be swept"
    );
}

/// The store's twin of the cache's FIFO sweep row, and the same
/// argument: a FIFO, socket or device node at `txn/<pid>-0` wedges
/// `create_new` with `EEXIST` for that pid exactly as a symlink
/// does, and `unlink(2)` removes every one of them. The line the
/// sweep draws is DIRECTORY, not file-or-symlink.
#[test]
fn established_open_sweeps_a_fifo_at_a_staging_name_and_still_leaves_a_directory() {
    use std::os::unix::fs::FileTypeExt as _;

    let dir = ScratchDir::new();
    {
        Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    }

    let planted = dir.0.join("txn").join("12345-0");
    crate::fsguard::testutil::mkfifo(&planted);
    assert!(
        std::fs::symlink_metadata(&planted).is_ok_and(|meta| meta.file_type().is_fifo()),
        "control: the plant really is a FIFO, not a regular file"
    );
    let subdir = dir.0.join("txn").join("a-directory");
    std::fs::create_dir(&subdir).unwrap_or_else(|e| panic!("{e}"));

    {
        Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    }

    assert!(
        std::fs::symlink_metadata(&planted).is_err(),
        "a FIFO at a staging name wedges create_new EEXIST for that pid forever and unlink \
         removes it; the sweep must clear the NAME"
    );
    assert!(
        std::fs::symlink_metadata(&subdir)
            .unwrap_or_else(|e| panic!("{e}"))
            .file_type()
            .is_dir(),
        "a directory under txn/ is the one plant the sweep leaves alone"
    );
}

/// The store's twin of the cache's un-sweepable-entry row: an entry
/// the sweep cannot unlink (EPERM/EACCES) must not `?`-propagate out
/// of `sweep_established_txn`, or ONE such name makes every
/// established `Store::open` fail forever. Warn, count, skip. Unlink
/// permission comes from the DIRECTORY, so a `0o555` `txn/` is the
/// portable fixture — and it is also the
/// shape where nothing can be staged at all, which the open
/// deliberately does not detect: a `put` that cannot stage fails
/// loudly on its own (see the sweep's doc).
#[test]
fn a_txn_entry_that_cannot_be_unlinked_is_skipped_not_propagated() {
    use std::os::unix::fs::FileTypeExt as _;

    let dir = ScratchDir::new();
    {
        Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    }

    let txn = dir.0.join("txn");
    let planted = txn.join("12345-0");
    crate::fsguard::testutil::mkfifo(&planted);
    assert!(
        std::fs::symlink_metadata(&planted).is_ok_and(|meta| meta.file_type().is_fifo()),
        "control: the plant really is a FIFO, not a regular file"
    );
    std::fs::set_permissions(&txn, std::fs::Permissions::from_mode(0o555))
        .unwrap_or_else(|e| panic!("{e}"));

    let opened = Store::open(&dir.0);
    let restored = std::fs::set_permissions(&txn, std::fs::Permissions::from_mode(0o755));

    assert!(
        opened.is_ok(),
        "an entry the sweep cannot remove must be skipped, never propagated — one such \
         name would otherwise wedge every established open of this store forever: {:?}",
        opened.err()
    );
    restored.unwrap_or_else(|e| panic!("{e}"));
    assert!(
        std::fs::symlink_metadata(&planted).is_ok_and(|meta| meta.file_type().is_fifo()),
        "control: the plant really was un-sweepable — if it is gone this test proved \
         nothing about the skip"
    );
    drop(opened);
}

// -------------------------------------------------- symlink hardening

/// A fanout directory is structural too: `put` must refuse a
/// pre-planted `objects/<2hex> -> <victim>` rather than following it
/// during `create_dir_all` and renaming the object into the victim.
#[test]
fn put_refuses_a_symlinked_fanout_dir_and_preserves_the_victim() {
    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let bytes = b"fanout symlink target";
    let id = GrainId::of(bytes);
    let object_path = store.object_path(&id);
    let fanout = object_path
        .parent()
        .unwrap_or_else(|| panic!("an object path must have a fanout parent"));

    // Control: the same `put` and fanout work when the fanout is a
    // real directory, so a later refusal is about the symlink plant.
    assert!(store.put(&id, bytes).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(store.get(&id).unwrap_or_else(|e| panic!("{e}")), bytes);
    std::fs::remove_file(&object_path).unwrap_or_else(|e| panic!("{e}"));
    std::fs::remove_dir(fanout).unwrap_or_else(|e| panic!("{e}"));

    let victim = ScratchDir::new();
    std::os::unix::fs::symlink(&victim.0, fanout).unwrap_or_else(|e| panic!("{e}"));
    let victim_object = victim.0.join(id.digest_hex());

    let err = store
        .put(&id, bytes)
        .expect_err("a symlinked object fanout must be refused, not followed");
    assert!(matches!(err, StoreError::Io { .. }), "got {err:?}");
    assert!(
        !victim_object.exists(),
        "put must not rename an object through a symlinked fanout"
    );
}

/// The victim that is NOT empty. `put`'s companion row above plants
/// a link to an EMPTY directory, so the leaf under it is absent and
/// the refusal can come from anywhere downstream. Here the far side
/// already HOLDS the object: content addressing puts identical bytes
/// at the identical relative path in every CAS, so
/// `objects/<2hex> -> <other store>/objects/<2hex>` makes a
/// leaf-first classification follow the link, find a regular file
/// and answer "already present" — `put` reports `Ok(false)` having
/// written nothing, `has` reports `true`, and every read of that id
/// serves the OTHER tree's bytes through this store's name.
#[test]
fn has_and_put_refuse_a_symlinked_fanout_that_already_holds_the_object() {
    let bytes = b"the same object lives in both content-addressed trees";
    let id = GrainId::of(bytes);

    // The far store, holding the object at the same relative path.
    let far = ScratchDir::new();
    let far_fanout;
    let far_object;
    {
        let store = Store::open(&far.0).unwrap_or_else(|e| panic!("{e}"));
        assert!(store.put(&id, bytes).unwrap_or_else(|e| panic!("{e}")));
        far_object = store.object_path(&id);
        far_fanout = far_object
            .parent()
            .unwrap_or_else(|| panic!("an object path must have a fanout parent"))
            .to_path_buf();
    }

    let near = ScratchDir::new();
    let store = Store::open(&near.0).unwrap_or_else(|e| panic!("{e}"));
    let near_object = store.object_path(&id);
    let near_fanout = near_object
        .parent()
        .unwrap_or_else(|| panic!("an object path must have a fanout parent"));
    std::os::unix::fs::symlink(&far_fanout, near_fanout).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        std::fs::symlink_metadata(&far_object).is_ok_and(|m| m.file_type().is_file()),
        "control: the far store really holds the object at the identically-named leaf"
    );

    assert!(
        !store.has(&id),
        "has must classify the FANOUT before the leaf: a symlinked objects/<2hex> makes the \
         leaf stat describe another store's file, and publish's pre-flight then passes on a \
         store that holds nothing"
    );

    let err = store
        .put(&id, bytes)
        .expect_err("put must refuse a foreign fanout, never report the far file as present");
    let StoreError::Io { context, .. } = &err else {
        panic!("got {err:?}");
    };
    assert!(
        context.contains("object fanout"),
        "the refusal must come FROM the fanout classification, not from a later step: \
         {context}"
    );
    assert_eq!(
        std::fs::read(&far_object).unwrap_or_else(|e| panic!("{e}")),
        bytes.to_vec(),
        "and the far store's object must be byte-identical — the store reports, never erases"
    );
    assert!(
        std::fs::symlink_metadata(near_fanout).is_ok_and(|m| m.file_type().is_symlink()),
        "the refusal leaves the planted fanout link in place for an operator to see"
    );
}

/// The read half of the same plant. `has` and `put` classify the
/// fanout; `get` handed `object_path(id)` straight to the guarded
/// open, and a guarded open is guarded on its FINAL component only
/// — every path operation follows a symlinked INTERMEDIATE one. So
/// a planted `objects/<2hex> -> <other store>/objects/<2hex>` made
/// this store serve the far tree's bytes under its own name, for an
/// id it does not hold. The bytes even hash-verify: content
/// addressing puts identical content at the identical relative path
/// in every CAS, which is exactly why the far file is there.
#[test]
fn get_refuses_a_symlinked_fanout_that_already_holds_the_object() {
    let bytes = b"the same object lives in both content-addressed trees";
    let id = GrainId::of(bytes);

    let far = ScratchDir::new();
    let far_fanout;
    let far_object;
    {
        let store = Store::open(&far.0).unwrap_or_else(|e| panic!("{e}"));
        assert!(store.put(&id, bytes).unwrap_or_else(|e| panic!("{e}")));
        far_object = store.object_path(&id);
        far_fanout = far_object
            .parent()
            .unwrap_or_else(|| panic!("an object path must have a fanout parent"))
            .to_path_buf();
    }

    let near = ScratchDir::new();
    let store = Store::open(&near.0).unwrap_or_else(|e| panic!("{e}"));
    let near_object = store.object_path(&id);
    let near_fanout = near_object
        .parent()
        .unwrap_or_else(|| panic!("an object path must have a fanout parent"));
    std::os::unix::fs::symlink(&far_fanout, near_fanout).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        std::fs::symlink_metadata(&far_object).is_ok_and(|m| m.file_type().is_file()),
        "control: the far store really holds the object at the identically-named leaf"
    );

    let err = store
        .get(&id)
        .expect_err("get must not serve another tree's bytes through a symlinked fanout");
    let StoreError::Io { context, .. } = &err else {
        panic!("got {err:?}");
    };
    assert!(
        context.contains("object fanout"),
        "the refusal must come FROM the fanout classification, not from a read that \
         happens to fail too: {context}"
    );
    assert_eq!(
        std::fs::read(&far_object).unwrap_or_else(|e| panic!("{e}")),
        bytes.to_vec(),
        "and the far store's object must be byte-identical — the store reports, never \
         touches"
    );
    assert!(
        std::fs::symlink_metadata(near_fanout).is_ok_and(|m| m.file_type().is_symlink()),
        "the refusal leaves the planted fanout link in place for an operator to see"
    );
}

/// The non-`NotFound` half of the same classification. A REGULAR
/// FILE where the fanout directory belongs makes every stat of the
/// leaf below it fail `ENOTDIR` — not `NotFound` — and a two-valued
/// fold reads that as "absent" and walks on into the write path.
/// Fail closed instead: refuse, and write nothing.
///
/// The refusal comes from the FANOUT classification, one step
/// earlier than the leaf's: a regular file at `objects/<2hex>` is
/// not a real directory, and that is decided before anything below
/// it is stat'ed. Both refusals are the same fail-closed property
/// and the assertion below is on the context, so which one fires is
/// exactly what it pins.
#[test]
fn put_refuses_when_the_object_leaf_cannot_be_classified_at_all() {
    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let bytes = b"enotdir fanout";
    let id = GrainId::of(bytes);
    let object_path = store.object_path(&id);
    let fanout = object_path
        .parent()
        .unwrap_or_else(|| panic!("an object path must have a fanout parent"));

    // A FILE at the fanout name: stat'ing anything beneath it is
    // ENOTDIR, which is neither "present" nor "absent".
    std::fs::write(fanout, b"not a directory").unwrap_or_else(|e| panic!("{e}"));

    let err = store
        .put(&id, bytes)
        .expect_err("an unclassifiable leaf must fail closed, never be treated as absent");
    // The ERROR'S OWN CONTEXT is what discriminates, and asserting
    // only the on-disk outcome would not: `create_dir_all` refuses
    // the same ENOTDIR one step later, so the disk looks identical
    // whether the classification failed closed or fell through to
    // the write path. The refusal has to come FROM the
    // classification.
    let StoreError::Io { context, .. } = &err else {
        panic!("got {err:?}");
    };
    assert!(
        context.contains("classify object fanout"),
        "the refusal must come from the put-if-absent classification chain, not from a \
         later write step that happens to fail too: {context}"
    );
    assert_eq!(
        std::fs::read(fanout).unwrap_or_else(|e| panic!("{e}")),
        b"not a directory".to_vec(),
        "and nothing may have been written through it"
    );
    assert!(
        !store.has(&id),
        "has must report absent-or-unusable, never present, for the same state"
    );
}

/// The object read open must return promptly for a FIFO, rather than
/// blocking before any byte bound or hash verification can run.
#[test]
fn get_refuses_an_object_fifo_without_blocking() {
    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let bytes = b"object replaced by fifo";
    let id = GrainId::of(bytes);
    let object_path = store.object_path(&id);

    // Control: this exact id is readable while its leaf is the regular
    // file written by `put`; the refusal below is about the FIFO type.
    assert!(store.put(&id, bytes).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(store.get(&id).unwrap_or_else(|e| panic!("{e}")), bytes);
    std::fs::remove_file(&object_path).unwrap_or_else(|e| panic!("{e}"));
    mkfifo(&object_path);

    let result = within_deadline("Store::get on an object FIFO", move || store.get(&id));
    assert!(
        matches!(result, Err(StoreError::Io { .. })),
        "a FIFO object must be refused as an I/O error, got {result:?}"
    );
}

/// A symlink is refused at open rather than followed to an attacker-
/// selected large regular file. The target is over the metadata cap so
/// following it would also exercise the formerly unbounded allocation.
#[test]
fn get_refuses_a_symlink_to_an_oversized_regular_file() {
    use granary_store::bounds::META_MAX_BYTES;

    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let bytes = b"object replaced by large symlink target";
    let id = GrainId::of(bytes);
    let object_path = store.object_path(&id);

    // Control: an ordinary object leaf remains readable through the
    // hardened path before the adversarial replacement is planted.
    assert!(store.put(&id, bytes).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(store.get(&id).unwrap_or_else(|e| panic!("{e}")), bytes);
    std::fs::remove_file(&object_path).unwrap_or_else(|e| panic!("{e}"));

    let victim = ScratchDir::new();
    let large = victim.0.join("large-file");
    File::create(&large)
        .and_then(|f| f.set_len(META_MAX_BYTES + 1))
        .unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&large, &object_path).unwrap_or_else(|e| panic!("{e}"));

    let err = store
        .get(&id)
        .expect_err("an object symlink must be refused without reading its target");
    assert!(matches!(err, StoreError::Io { .. }), "got {err:?}");
}

/// Even a regular object leaf is read through a hard cap. Oversize is
/// distinguished from a completed, in-bounds hash mismatch by the
/// `InvalidData` I/O refusal.
#[test]
fn get_refuses_an_oversized_regular_file_at_the_metadata_cap() {
    use granary_store::bounds::META_MAX_BYTES;

    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let bytes = b"object replaced by oversized regular file";
    let id = GrainId::of(bytes);
    let object_path = store.object_path(&id);

    // Control: an in-bounds regular leaf still completes and verifies.
    assert!(store.put(&id, bytes).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(store.get(&id).unwrap_or_else(|e| panic!("{e}")), bytes);
    std::fs::set_permissions(&object_path, std::fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|e| panic!("{e}"));
    File::create(&object_path)
        .and_then(|f| f.set_len(META_MAX_BYTES + 1))
        .unwrap_or_else(|e| panic!("{e}"));

    let err = store
        .get(&id)
        .expect_err("an over-cap regular object must be refused after a bounded read");
    assert!(
        matches!(
            err,
            StoreError::Io { ref source, .. }
                if source.kind() == io::ErrorKind::InvalidData
        ),
        "got {err:?}"
    );
}

/// Presence means a REGULAR leaf exists at the reconstructed name,
/// never merely that following the name reaches something — and a
/// leaf that is not regular makes `put` REFUSE rather than write.
///
/// Both halves matter and only the first is obvious. `has` must say
/// "not an object" for a symlink of either kind, because following
/// the name is not the question. `put` must then refuse, because
/// `atomic_write` ends in a `rename` ONTO the leaf name: reading
/// "not an object" as "absent" makes the write replace the planted
/// link, so tampered state inside the store root is erased instead
/// of reported, and nothing downstream re-checks. The link's TARGET
/// was never at risk either way (`rename` does not follow its final
/// component), which is exactly why only the on-disk link itself
/// discriminates the two behaviours.
#[test]
fn has_and_put_both_refuse_an_object_symlink_of_either_kind() {
    let dir = ScratchDir::new();
    let store = Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let bytes = b"object replacing symlink";
    let id = GrainId::of(bytes);
    let object_path = store.object_path(&id);

    // Control: the real object is present, readable, and non-novel.
    assert!(store.put(&id, bytes).unwrap_or_else(|e| panic!("{e}")));
    assert!(store.has(&id));
    assert!(!store.put(&id, bytes).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(store.get(&id).unwrap_or_else(|e| panic!("{e}")), bytes);
    std::fs::remove_file(&object_path).unwrap_or_else(|e| panic!("{e}"));

    let victim = ScratchDir::new();
    let existing_target = victim.0.join("existing-target");
    std::fs::write(&existing_target, b"must stay unchanged").unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&existing_target, &object_path).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !store.has(&id),
        "an existing-target symlink is not an object"
    );
    let err = store
        .put(&id, bytes)
        .expect_err("put must refuse an existing-target symlink, not rename over it");
    assert!(matches!(err, StoreError::Io { .. }), "got {err:?}");
    assert_eq!(
        std::fs::read(&existing_target).unwrap_or_else(|e| panic!("{e}")),
        b"must stay unchanged"
    );
    assert!(
        std::fs::symlink_metadata(&object_path)
            .unwrap_or_else(|e| panic!("{e}"))
            .file_type()
            .is_symlink(),
        "THE DEFECT: the planted link must still be there — replacing it erases the \
         tampered state instead of reporting it"
    );

    std::fs::remove_file(&object_path).unwrap_or_else(|e| panic!("{e}"));
    let dangling_target = victim.0.join("missing-target");
    std::os::unix::fs::symlink(&dangling_target, &object_path).unwrap_or_else(|e| panic!("{e}"));
    assert!(!store.has(&id), "a dangling symlink is not an object");
    let err = store
        .put(&id, bytes)
        .expect_err("put must refuse a dangling symlink too");
    assert!(matches!(err, StoreError::Io { .. }), "got {err:?}");
    assert!(
        std::fs::symlink_metadata(&object_path)
            .unwrap_or_else(|e| panic!("{e}"))
            .file_type()
            .is_symlink(),
        "and the dangling link must still be in place"
    );
    assert!(
        std::fs::symlink_metadata(&dangling_target).is_err(),
        "and nothing may have been created at its target"
    );

    // CONTROL, after both refusals: with the link removed, the very
    // same put works. The refusal is about the plant, not a store
    // that has stopped accepting objects.
    std::fs::remove_file(&object_path).unwrap_or_else(|e| panic!("{e}"));
    assert!(store.put(&id, bytes).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(store.get(&id).unwrap_or_else(|e| panic!("{e}")), bytes);
}

/// The live exploit: plant `txn -> <victim dir>`
/// on an ESTABLISHED store and reopen. Two guards stand between that
/// and the victim's files: `create_structural_dir` refuses to follow
/// the planted link at open (a plain `create_dir_all` would follow it,
/// a silent no-op since the target exists), and
/// `sweep_established_txn` refuses a symlinked `txn/` before it
/// enumerates (tested directly below). Deleting them takes BOTH gone;
/// this test asserts the refusal, not which guard raised it.
/// `Store::open` is reached through `harvest` and `publish`.
#[test]
fn established_open_refuses_a_symlinked_txn_dir_and_preserves_the_victim() {
    let dir = ScratchDir::new();
    Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}")); // establish a real store

    let victim = ScratchDir::new();
    let victim_file = victim.0.join("do-not-delete");
    std::fs::write(&victim_file, b"must survive").unwrap_or_else(|e| panic!("{e}"));

    std::fs::remove_dir_all(dir.0.join("txn")).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&victim.0, dir.0.join("txn")).unwrap_or_else(|e| panic!("{e}"));

    let err = Store::open(&dir.0).expect_err("a symlinked txn/ must be refused, not followed");
    assert!(matches!(err, StoreError::Io { .. }), "got {err:?}");
    assert!(
        victim_file.exists(),
        "opening the store must never delete a symlink target's files"
    );
}

/// The sweep's OWN independent guard, exercised directly —
/// bypassing `create_structural_dir`'s earlier open-time check
/// entirely, so this proves the sweep does not merely rely on
/// running after that check. A guard whose failure mode was never
/// demonstrated does not exist.
///
/// It fails CLOSED, exactly as the cache's sweep does: a store root
/// whose `txn/` is not a real directory is TAMPERED, and a clean
/// `Ok` blesses it. The two sweeps must not differ here — the day
/// the open's guard moves or is reordered, a divergent arm becomes
/// the answer without anything saying so.
#[test]
fn established_sweep_fails_closed_on_a_symlinked_txn_dir_directly() {
    let dir = ScratchDir::new();
    Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));

    let victim = ScratchDir::new();
    let victim_file = victim.0.join("do-not-delete");
    std::fs::write(&victim_file, b"must survive").unwrap_or_else(|e| panic!("{e}"));

    std::fs::remove_dir_all(dir.0.join("txn")).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&victim.0, dir.0.join("txn")).unwrap_or_else(|e| panic!("{e}"));

    let err = sweep_established_txn(&dir.0)
        .err()
        .unwrap_or_else(|| panic!("a symlinked txn/ must fail the sweep, not be tolerated"));
    assert!(matches!(err, StoreError::Io { .. }), "got {err:?}");

    assert!(
        victim_file.exists(),
        "the sweep must refuse a symlinked txn/ entirely, never delete through it"
    );
}

/// A pre-planted `objects -> <victim dir>` must be refused the same
/// way `txn/` is — `create_dir_all` would otherwise follow it and
/// every subsequent object write would land outside the store root.
#[test]
fn open_refuses_a_symlinked_objects_dir() {
    let dir = ScratchDir::new();
    let elsewhere = ScratchDir::new();
    std::os::unix::fs::symlink(&elsewhere.0, dir.0.join("objects"))
        .unwrap_or_else(|e| panic!("{e}"));

    let err = Store::open(&dir.0).expect_err("a symlinked objects/ must be refused, not followed");
    assert!(matches!(err, StoreError::Io { .. }), "got {err:?}");
    assert!(
        fs::read_dir(&elsewhere.0)
            .unwrap_or_else(|e| panic!("{e}"))
            .next()
            .is_none(),
        "nothing must be written through the symlink into the target dir"
    );
}

/// The CACHE's lock already carries `O_NOFOLLOW` against this exact
/// class; the STORE did not, so a planted `lock` symlink was a
/// truncation primitive until this guard landed.
#[test]
fn lock_symlink_is_refused_without_truncating_the_target() {
    let dir = ScratchDir::new();
    Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));

    let outside = ScratchDir::new();
    let outside_file = outside.0.join("do-not-truncate");
    std::fs::write(&outside_file, b"must survive intact").unwrap_or_else(|e| panic!("{e}"));

    std::fs::remove_file(dir.0.join("lock")).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&outside_file, dir.0.join("lock")).unwrap_or_else(|e| panic!("{e}"));

    let err = Store::open(&dir.0)
        .expect_err("a symlinked lock path must refuse (O_NOFOLLOW), never follow");
    assert!(matches!(err, StoreError::Io { .. }), "got {err:?}");
    assert_eq!(
        std::fs::read(&outside_file).unwrap_or_else(|e| panic!("{e}")),
        b"must survive intact",
        "O_NOFOLLOW must refuse before any truncation, not after"
    );
}

/// `is_store_marker` must not read an attacker-planted
/// file unbounded. The content DOES start with the marker's
/// identifying key (so a bound is the only thing distinguishing
/// this from a real marker) — an unbounded read would say `true`.
#[test]
fn is_store_marker_refuses_an_oversized_file() {
    let dir = ScratchDir::new();
    let mut content = String::from(MARKER_KEY);
    content.push_str(&"x".repeat(100_000));
    std::fs::write(dir.0.join("granary-store"), content.as_bytes())
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !is_store_marker(&dir.0.join("granary-store")),
        "an oversized file must not be identified as a marker, even with the right prefix"
    );
}

/// `Store::open`'s own marker read must be bounded too.
/// An unbounded read still returns `Incompatible` for an oversized
/// mismatched marker (via the ordinary mismatch arm) — the
/// DISTINGUISHING behaviour a bound adds is that the error message
/// stays a fixed size instead of echoing the whole unbounded content
/// back into the diagnostic.
#[test]
fn open_refuses_an_oversized_marker_without_echoing_its_content() {
    let dir = ScratchDir::new();
    Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    let marker_path = dir.0.join("granary-store");
    // The marker was just written 0444 by `atomic_write` — chmod it
    // writable first (same idiom as `marker_tamper_rejected`).
    std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(&marker_path, "x".repeat(100_000).as_bytes()).unwrap_or_else(|e| panic!("{e}"));

    let err = Store::open(&dir.0).expect_err("an over-cap marker must be refused, not adopted");
    assert!(
        matches!(err, StoreError::Incompatible { .. }),
        "got {err:?}"
    );
    let rendered = err.to_string();
    assert!(
        rendered.len() < 1000,
        "an over-cap marker must be refused with a FIXED-size message, not by reading the \
         unbounded content into the diagnostic (which would defeat the point of bounding \
         the read): got a {}-byte message",
        rendered.len()
    );
}

/// `open_for_verify`'s own symlinked-`objects/` guard — the entry
/// point `gran verify` actually uses. A pre-planted `objects ->
/// <victim dir>` must be refused before any walk, not just at
/// `Store::open`'s dir-creation time.
#[test]
fn open_for_verify_refuses_a_symlinked_objects_dir() {
    let dir = ScratchDir::new();
    Store::open(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    std::fs::remove_dir_all(dir.0.join("objects")).unwrap_or_else(|e| panic!("{e}"));
    let elsewhere = ScratchDir::new();
    std::os::unix::fs::symlink(&elsewhere.0, dir.0.join("objects"))
        .unwrap_or_else(|e| panic!("{e}"));

    let err = Store::open_for_verify(&dir.0)
        .expect_err("a symlinked objects/ must be refused, not walked");
    assert!(matches!(err, StoreError::Io { .. }), "got {err:?}");
}

#[test]
fn a_store_error_reports_the_class_its_own_variant_names() {
    use crate::FailureClass;
    let io = StoreError::Io {
        context: String::new(),
        source: io::Error::from(io::ErrorKind::PermissionDenied),
    };
    let incompatible = StoreError::Incompatible {
        detail: String::new(),
    };
    let corrupt = StoreError::Corrupt {
        id: GrainId::of(b"synthetic"),
    };
    assert_eq!(
        io.failure_class(),
        FailureClass::Io,
        "store error class: io"
    );
    assert_eq!(
        incompatible.failure_class(),
        FailureClass::Refused,
        "store error class: incompatible"
    );
    assert_eq!(
        corrupt.failure_class(),
        FailureClass::Corrupt,
        "store error class: corrupt"
    );
    assert_eq!(
        StoreError::Locked.failure_class(),
        FailureClass::Conflict,
        "store error class: locked"
    );
}
