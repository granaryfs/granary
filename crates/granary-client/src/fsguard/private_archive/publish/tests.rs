// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "publication tests create and attack test-owned files"
)]

use super::*;
use crate::fsguard::private_archive::{ArchiveSources, prepare_private_archive_parent};
use std::{
    cell::Cell,
    os::unix::{ffi::OsStrExt as _, fs::PermissionsExt as _},
    sync::atomic::{AtomicU64, Ordering},
};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let test = std::thread::current();
        let test = test.name().unwrap_or("unnamed");
        let path = base.join(format!(
            "granary-archive-publish-{test}-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn uid(&self) -> u32 {
        std::fs::symlink_metadata(&self.0).unwrap().uid()
    }

    fn parent(&self, name: &str) -> PrivateArchiveParent {
        prepare_private_archive_parent(
            &self.0.join(name),
            ArchiveSources::new(&[], None),
            self.uid(),
        )
        .unwrap()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn refusal(result: Result<(), PrivateArchiveError>) -> &'static str {
    match result {
        Err(PrivateArchiveError::Refused(reason)) => reason.reason(),
        other => panic!("expected refusal, got {other:?}"),
    }
}

#[derive(Default)]
struct FaultOps {
    insert_final: Cell<bool>,
    replace_temporary_before_link: Cell<bool>,
    created_calls: Cell<usize>,
    created_mode: Cell<Option<u32>>,
    fail_sync: Cell<Option<usize>>,
    sync_calls: Cell<usize>,
    fail_remove_once: Cell<bool>,
    remove_calls: Cell<usize>,
}

impl ArchiveOps for FaultOps {
    fn created(&self, file: &File, _path: &Path) -> io::Result<()> {
        self.created_calls.set(self.created_calls.get() + 1);
        self.created_mode
            .set(Some(file.metadata()?.mode() & 0o7777));
        Ok(())
    }

    fn before_link(&self, temporary: &Path, output: &Path) -> io::Result<()> {
        if self.replace_temporary_before_link.replace(false) {
            std::fs::remove_file(temporary)?;
            std::fs::write(temporary, b"archive")?;
            std::fs::set_permissions(temporary, std::fs::Permissions::from_mode(0o600))?;
        }
        if self.insert_final.replace(false) {
            std::fs::write(output, b"sentinel")?;
        }
        Ok(())
    }

    fn sync(&self, file: &File) -> io::Result<()> {
        let call = self.sync_calls.get();
        self.sync_calls.set(call + 1);
        if self.fail_sync.get() == Some(call) {
            return Err(io::Error::other("injected sync failure"));
        }
        RealArchiveOps.sync(file)
    }

    fn link(&self, temporary: &Path, output: &Path) -> io::Result<()> {
        RealArchiveOps.link(temporary, output)
    }

    fn remove(&self, temporary: &Path) -> io::Result<()> {
        self.remove_calls.set(self.remove_calls.get() + 1);
        if self.fail_remove_once.replace(false) {
            return Err(io::Error::other("injected remove failure"));
        }
        RealArchiveOps.remove(temporary)
    }
}

fn temporary_count(path: &Path) -> usize {
    std::fs::read_dir(path)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .as_bytes()
                .starts_with(b".SUPPORT-BUNDLE-")
        })
        .count()
}

#[test]
fn exact_bytes_publish_at_0600_and_cleanup_disarms() {
    let scratch = Scratch::new();
    let output = scratch.0.join("bundle.gsb");
    let ops = FaultOps::default();
    publish_with_ops(&scratch.parent("bundle.gsb"), b"bounded archive", &ops).unwrap();
    assert_eq!(std::fs::read(&output).unwrap(), b"bounded archive");
    assert_eq!(
        std::fs::symlink_metadata(&output).unwrap().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        ops.remove_calls.get(),
        1,
        "successful unlink must disarm Drop cleanup"
    );
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 1);
}

#[test]
fn existing_final_and_link_race_never_replace() {
    let scratch = Scratch::new();
    let output = scratch.0.join("bundle.gsb");
    std::fs::write(&output, b"original").unwrap();
    let preflight = FaultOps::default();
    assert_eq!(
        refusal(publish_with_ops(
            &scratch.parent("bundle.gsb"),
            b"new",
            &preflight
        )),
        "output already exists"
    );
    assert_eq!(std::fs::read(&output).unwrap(), b"original");
    assert_eq!(
        (preflight.created_calls.get(), temporary_count(&scratch.0)),
        (0, 0)
    );
    std::fs::remove_file(&output).unwrap();

    let ops = FaultOps::default();
    ops.insert_final.set(true);
    assert_eq!(
        refusal(publish_with_ops(
            &scratch.parent("bundle.gsb"),
            b"new",
            &ops
        )),
        "output already exists"
    );
    assert_eq!(std::fs::read(&output).unwrap(), b"sentinel");
    assert_eq!(temporary_count(&scratch.0), 0);
}

#[test]
fn existing_temporary_is_skipped_and_private_mode_is_verified() {
    let scratch = Scratch::new();
    let planted = scratch.0.join(".SUPPORT-BUNDLE-9.tmp");
    std::fs::write(&planted, b"planted").unwrap();
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o600)).unwrap();
    let ops = FaultOps::default();
    let (temporary, file) = create_temporary(&scratch.0, scratch.uid(), 9, &ops).unwrap();
    assert_ne!(
        temporary.path, planted,
        "exclusive creation must not reuse the planted inode"
    );
    assert_eq!(std::fs::read(&planted).unwrap(), b"planted");
    assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o600);
}

#[test]
fn verifier_refuses_wrong_mode_and_different_same_length_bytes() {
    let scratch = Scratch::new();
    let path = scratch.0.join("temporary");
    std::fs::write(&path, b"wrong").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let created_identity = identity(&std::fs::symlink_metadata(&path).unwrap());
    assert_eq!(
        refusal(verify_temporary(&path, b"right", scratch.uid(), created_identity).map(|_| ())),
        "archive temporary content mismatch"
    );
    assert_eq!(
        refusal(
            verify_temporary(&path, b"wrong-length", scratch.uid(), created_identity).map(|_| ())
        ),
        "archive temporary content mismatch"
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        refusal(verify_temporary(&path, b"wrong", scratch.uid(), created_identity).map(|_| ())),
        "archive temporary is not sole private regular"
    );
}

#[test]
fn verifier_binds_reopened_name_to_created_inode() {
    let scratch = Scratch::new();
    let path = scratch.0.join("temporary");
    std::fs::write(&path, b"same bytes").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let created_identity = identity(&std::fs::symlink_metadata(&path).unwrap());
    let original = scratch.0.join("original");
    std::fs::rename(&path, &original).unwrap();
    std::fs::write(&path, b"same bytes").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let replacement_identity = identity(&std::fs::symlink_metadata(&path).unwrap());
    assert_ne!(
        replacement_identity, created_identity,
        "replacement fixture must retain the original inode"
    );
    assert_eq!(
        refusal(
            verify_temporary(&path, b"same bytes", scratch.uid(), created_identity).map(|_| ())
        ),
        "archive temporary changed"
    );
}

#[test]
fn named_temporary_is_rechecked_after_sync_and_rebound_immediately_before_link() {
    let scratch = Scratch::new();
    let ops = FaultOps::default();
    ops.replace_temporary_before_link.set(true);
    assert_eq!(
        refusal(publish_with_ops(
            &scratch.parent("bundle.gsb"),
            b"archive",
            &ops
        )),
        "archive temporary changed"
    );
    assert!(!scratch.0.join("bundle.gsb").exists());
}

#[test]
fn pre_link_sync_refuses_but_post_link_failures_are_uncertain() {
    let scratch = Scratch::new();
    let pre = FaultOps::default();
    pre.fail_sync.set(Some(0));
    assert_eq!(
        refusal(publish_with_ops(&scratch.parent("pre.gsb"), b"bytes", &pre)),
        "archive write unavailable"
    );
    assert!(!scratch.0.join("pre.gsb").exists());

    let post = FaultOps::default();
    post.fail_sync.set(Some(1));
    assert_eq!(
        publish_with_ops(&scratch.parent("post.gsb"), b"bytes", &post),
        Err(PrivateArchiveError::PublicationUncertain)
    );
    assert_eq!(std::fs::read(scratch.0.join("post.gsb")).unwrap(), b"bytes");

    let unlink = FaultOps::default();
    unlink.fail_remove_once.set(true);
    assert_eq!(
        publish_with_ops(&scratch.parent("unlink.gsb"), b"bytes", &unlink),
        Err(PrivateArchiveError::PublicationUncertain)
    );
    assert_eq!(
        std::fs::read(scratch.0.join("unlink.gsb")).unwrap(),
        b"bytes"
    );
    assert_eq!(
        unlink.remove_calls.get(),
        2,
        "a failed explicit cleanup leaves the armed guard one cleanup attempt"
    );
}

#[cfg(target_os = "linux")]
mod linux_attacks {
    use super::*;

    #[test]
    fn rows_3_and_4_existing_symlink_regular_and_hardlink_are_refused() {
        let scratch = Scratch::new();
        let sentinel = scratch.0.join("sentinel");
        std::fs::write(&sentinel, b"sentinel").unwrap();
        for name in ["symlink.gsb", "dangling.gsb", "regular.gsb", "hardlink.gsb"] {
            let output = scratch.0.join(name);
            if name == "symlink.gsb" {
                std::os::unix::fs::symlink(&sentinel, &output).unwrap();
            } else if name == "dangling.gsb" {
                std::os::unix::fs::symlink(scratch.0.join("absent"), &output).unwrap();
            } else if name == "regular.gsb" {
                std::fs::write(&output, b"sentinel").unwrap();
            } else {
                std::fs::hard_link(&sentinel, &output).unwrap();
            }
            let ops = FaultOps::default();
            assert_eq!(
                refusal(publish_with_ops(&scratch.parent(name), b"new", &ops)),
                "output already exists"
            );
            assert_eq!(ops.created_calls.get(), 0, "preflight must precede create");
            assert_eq!(temporary_count(&scratch.0), 0);
        }
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"sentinel");
    }

    #[test]
    fn row_6_umask_subprocess_creates_private_and_skips_planted_temporary() {
        const CHILD: &str = "GRANARY_PRIVATE_ARCHIVE_UMASK_CHILD";
        const IDENTITY: &str = "fsguard::private_archive::publish::tests::linux_attacks::row_6_umask_subprocess_creates_private_and_skips_planted_temporary";
        if let Ok(value) = std::env::var(CHILD) {
            let requested = u32::from_str_radix(&value, 8).unwrap();
            nix::sys::stat::umask(Mode::from_bits_truncate(requested));
            let scratch = Scratch::new();
            let planted = scratch.0.join(".SUPPORT-BUNDLE-700.tmp");
            std::fs::write(&planted, b"planted").unwrap();
            std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o600)).unwrap();
            let ops = FaultOps::default();
            let (temporary, file) = create_temporary(&scratch.0, scratch.uid(), 700, &ops).unwrap();
            assert_ne!(temporary.path, planted);
            assert_eq!(std::fs::read(&planted).unwrap(), b"planted");
            assert_eq!(
                ops.created_mode.get(),
                Some(if requested == 0 { 0o600 } else { 0 })
            );
            assert_eq!(file.metadata().unwrap().mode() & 0o7777, 0o600);
            return;
        }

        for value in ["000", "777"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .env_clear()
                .env(CHILD, value)
                .args(["--exact", IDENTITY, "--nocapture"])
                .output()
                .unwrap();
            assert!(output.status.success(), "isolated umask {value} row failed");
        }
    }

    #[test]
    fn row_8_no_replace_link_race_preserves_sentinel() {
        let scratch = Scratch::new();
        let ops = FaultOps::default();
        ops.insert_final.set(true);
        assert_eq!(
            refusal(publish_with_ops(
                &scratch.parent("race.gsb"),
                b"archive",
                &ops
            )),
            "output already exists"
        );
        assert_eq!(
            std::fs::read(scratch.0.join("race.gsb")).unwrap(),
            b"sentinel"
        );
        assert_eq!(temporary_count(&scratch.0), 0);
    }

    #[test]
    fn row_9_hardlinked_temporary_and_post_link_failures_are_distinct() {
        let scratch = Scratch::new();
        let victim = scratch.0.join("victim");
        std::fs::write(&victim, b"bytes").unwrap();
        let symlink = scratch.0.join("symlink");
        std::os::unix::fs::symlink(&victim, &symlink).unwrap();
        assert_eq!(
            refusal(verify_temporary(&symlink, b"bytes", scratch.uid(), (0, 0)).map(|_| ())),
            "archive temporary is not sole private regular"
        );
        let fifo = scratch.0.join("fifo");
        crate::fsguard::testutil::mkfifo(&fifo);
        assert_eq!(
            refusal(verify_temporary(&fifo, b"bytes", scratch.uid(), (0, 0)).map(|_| ())),
            "archive temporary is not sole private regular"
        );
        let path = scratch.0.join("temporary");
        let alias = scratch.0.join("alias");
        std::fs::write(&path, b"bytes").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        let path_identity = identity(&std::fs::symlink_metadata(&path).unwrap());
        assert_eq!(
            refusal(verify_temporary(&path, b"bytes", scratch.uid(), path_identity).map(|_| ())),
            "archive temporary is not sole private regular"
        );
        let ops = FaultOps::default();
        ops.fail_sync.set(Some(1));
        assert_eq!(
            publish_with_ops(&scratch.parent("bundle.gsb"), b"bytes", &ops),
            Err(PrivateArchiveError::PublicationUncertain)
        );
        assert_eq!(
            std::fs::read(scratch.0.join("bundle.gsb")).unwrap(),
            b"bytes"
        );
    }
}
