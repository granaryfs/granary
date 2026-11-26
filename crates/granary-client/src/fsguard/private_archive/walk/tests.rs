// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "walk tests create and attack test-owned directories"
)]

use super::*;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::atomic::{AtomicU64, Ordering};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let test = std::thread::current();
        let test = test.name().unwrap_or("unnamed");
        let path = base.join(format!(
            "granary-archive-walk-{test}-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn uid(&self) -> u32 {
        std::fs::symlink_metadata(&self.0).unwrap().uid()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn refusal(result: Result<PrivateArchiveParent, PrivateArchiveError>) -> &'static str {
    match result {
        Err(PrivateArchiveError::Refused(reason)) => reason.reason(),
        other => panic!("expected refusal, got {other:?}"),
    }
}

#[test]
fn spelling_and_temporary_namespace_are_closed_before_the_walk() {
    let scratch = Scratch::new();
    let valid = scratch.0.join("bundle.gsb");
    assert!(
        prepare_private_archive_parent(&valid, ArchiveSources::new(&[], None), scratch.uid())
            .is_ok()
    );

    let long = PathBuf::from(format!("/{}", "a".repeat(4_096)));
    let many = PathBuf::from(format!("/{}", vec!["a"; 257].join("/")));
    for path in [
        PathBuf::from("relative"),
        PathBuf::from("/tmp/./out"),
        PathBuf::from("/tmp/../out"),
        PathBuf::from("/tmp/"),
        long,
        many,
    ] {
        assert_eq!(
            refusal(prepare_private_archive_parent(
                &path,
                ArchiveSources::new(&[], None),
                scratch.uid()
            )),
            "invalid output path",
            "input: {path:?}"
        );
    }
    assert_eq!(
        refusal(prepare_private_archive_parent(
            &scratch.0.join(".sUpPoRt-BuNdLe-x"),
            ArchiveSources::new(&[], None),
            scratch.uid()
        )),
        "output name is in temporary namespace"
    );
}

#[test]
fn directory_spelling_accepts_root_duplicate_separators_and_trailing_slashes() {
    assert_eq!(
        directory_components(Path::new("/")).unwrap(),
        Vec::<Vec<u8>>::new()
    );
    assert_eq!(
        directory_components(Path::new("//var///lib//granary///")).unwrap(),
        [b"var".to_vec(), b"lib".to_vec(), b"granary".to_vec()]
    );
    assert!(raw_components(Path::new("/tmp//bundle.gsb"), false).is_err());
    assert!(raw_components(Path::new("/tmp/bundle.gsb/"), false).is_err());
}

#[test]
fn parent_mode_and_source_identity_refuse_without_creating_a_temporary() {
    let scratch = Scratch::new();
    let output = scratch.0.join("bundle.gsb");
    let missing = scratch.0.join("missing");
    assert_eq!(
        refusal(prepare_private_archive_parent(
            &output,
            ArchiveSources::new(&[missing.as_path()], None),
            scratch.uid()
        )),
        "source separation unavailable"
    );
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);

    let source = scratch.0.join("source");
    std::fs::create_dir(&source).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        refusal(prepare_private_archive_parent(
            &source.join("missing/out.gsb"),
            ArchiveSources::new(&[source.as_path()], None),
            scratch.uid()
        )),
        "output inside source tree"
    );
    assert_eq!(
        refusal(prepare_private_archive_parent(
            &output,
            ArchiveSources::new(&[scratch.0.as_path()], None),
            scratch.uid()
        )),
        "output inside source tree"
    );
    std::fs::set_permissions(&scratch.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        refusal(prepare_private_archive_parent(
            &output,
            ArchiveSources::new(&[], None),
            scratch.uid()
        )),
        "output parent must be invoking uid and 0700"
    );
}

#[test]
fn unprotected_ancestor_refuses_before_parent_policy() {
    let scratch = Scratch::new();
    let parent = scratch.0.join("parent");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&scratch.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        refusal(prepare_private_archive_parent(
            &parent.join("bundle.gsb"),
            ArchiveSources::new(&[], None),
            scratch.uid()
        )),
        "output path ancestor is not protected"
    );
}

#[cfg(target_vendor = "apple")]
#[test]
fn granting_ancestor_acl_is_refused() {
    let scratch = Scratch::new();
    let parent = scratch.0.join("parent");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let status = std::process::Command::new("chmod")
        .args([
            "+a",
            "everyone allow add_subdirectory,delete_child,add_file",
        ])
        .arg(&scratch.0)
        .status()
        .unwrap();
    assert!(status.success(), "could not plant granting ancestor ACL");
    assert_eq!(
        refusal(prepare_private_archive_parent(
            &parent.join("bundle.gsb"),
            ArchiveSources::new(&[], None),
            scratch.uid()
        )),
        "output path ancestor is not protected"
    );
}

#[test]
fn mounted_identity_and_fuse_device_are_excluded() {
    let scratch = Scratch::new();
    let metadata = std::fs::symlink_metadata(&scratch.0).unwrap();
    let mounted = MountedNamespace::new(&scratch.0, identity(&metadata), None);
    assert_eq!(
        refusal(prepare_private_archive_parent(
            &scratch.0.join("bundle.gsb"),
            ArchiveSources::new(&[], Some(mounted)),
            scratch.uid()
        )),
        "output inside mounted namespace"
    );

    let device_only = MountedNamespace::new(
        Path::new("/declared/mountpoint"),
        (u64::MAX, u64::MAX),
        Some(metadata.dev()),
    );
    assert_eq!(
        refusal(prepare_private_archive_parent(
            &scratch.0.join("bundle.gsb"),
            ArchiveSources::new(&[], Some(device_only)),
            scratch.uid()
        )),
        "output inside mounted namespace"
    );

    let absent = scratch.0.join("mountpoint-is-offline");
    let offline = MountedNamespace::new(&absent, (u64::MAX, 1), None);
    assert!(
        prepare_private_archive_parent(
            &scratch.0.join("bundle.gsb"),
            ArchiveSources::new(&[], Some(offline)),
            scratch.uid()
        )
        .is_ok(),
        "declared offline mountpoint must not be opened"
    );
}

#[test]
fn mounted_lexical_descendant_refuses_before_output_walk() {
    let scratch = Scratch::new();
    let absent_mount = scratch.0.join("unserved-mount");
    let mounted = MountedNamespace::new(&absent_mount, (u64::MAX, u64::MAX), Some(u64::MAX));
    assert_eq!(
        refusal(prepare_private_archive_parent(
            &absent_mount.join("nested/bundle.gsb"),
            ArchiveSources::new(&[], Some(mounted)),
            scratch.uid(),
        )),
        "output inside mounted namespace"
    );
}

#[test]
fn mounted_lexical_prefix_is_ascii_case_insensitive() {
    let mount = Path::new("/mnt/x");
    let mounted = MountedNamespace::new(mount, (u64::MAX, u64::MAX), Some(u64::MAX));
    let mut cases = 0;
    for output in [Path::new("/MNT/x"), Path::new("/mnt/X/sub")] {
        assert_eq!(
            refusal(prepare_private_archive_parent(
                output,
                ArchiveSources::new(&[], Some(mounted)),
                u32::MAX,
            )),
            "output inside mounted namespace",
            "output={output:?}, mount={mount:?}"
        );
        cases += 1;
    }
    let unrelated = Path::new("/other/MNT/x");
    assert!(
        !mounted_path_prefix(unrelated, mount),
        "unrelated output matched: output={unrelated:?}, mount={mount:?}"
    );
    cases += 1;
    assert_eq!(cases, 3);
}

#[test]
fn authenticated_source_identity_binds_the_held_walk() {
    let scratch = Scratch::new();
    let source = scratch.0.join("source");
    let output_parent = scratch.0.join("output");
    std::fs::create_dir(&source).unwrap();
    std::fs::create_dir(&output_parent).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&output_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let actual = identity(&std::fs::symlink_metadata(&source).unwrap());
    assert_eq!(
        refusal(prepare_private_archive_parent(
            &output_parent.join("bundle.gsb"),
            ArchiveSources::with_expected_identities(
                &[source.as_path()],
                &[(actual.0, actual.1.saturating_add(1))],
                None,
            ),
            scratch.uid(),
        )),
        "source separation unavailable"
    );
    assert_eq!(std::fs::read_dir(output_parent).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
mod linux_attacks {
    use super::*;

    #[test]
    fn row_3_parent_symlink_is_refused() {
        let scratch = Scratch::new();
        let real = scratch.0.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let alias = scratch.0.join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        assert_eq!(
            refusal(prepare_private_archive_parent(
                &alias.join("bundle.gsb"),
                ArchiveSources::new(&[], None),
                scratch.uid()
            )),
            "output path contains symlink or non-directory"
        );
    }

    #[test]
    fn writable_linux_private_archive_row_5_wrong_real_owner_refuses() {
        let scratch = Scratch::new();
        let invoking_uid = nix::unistd::geteuid();
        if !invoking_uid.is_root() {
            eprintln!(
                "SKIPPED-NOT-ROOT writable_linux_private_archive_row_5_wrong_real_owner_refuses"
            );
            return;
        }
        let foreign = nix::unistd::Uid::from_raw(1);
        nix::unistd::chown(&scratch.0, Some(foreign), None).unwrap();
        assert_eq!(
            refusal(prepare_private_archive_parent(
                &scratch.0.join("bundle.gsb"),
                ArchiveSources::new(&[], None),
                invoking_uid.as_raw()
            )),
            "output parent must be invoking uid and 0700"
        );
    }

    #[test]
    fn row_6_wrong_modes_refuse() {
        let scratch = Scratch::new();
        let output = scratch.0.join("bundle.gsb");
        for mode in [0o755, 0o770, 0o500] {
            std::fs::set_permissions(&scratch.0, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                refusal(prepare_private_archive_parent(
                    &output,
                    ArchiveSources::new(&[], None),
                    scratch.uid()
                )),
                "output parent must be invoking uid and 0700"
            );
        }
    }

    #[test]
    fn writable_linux_private_archive_row_7_bind_source_alias_and_declared_mount_device_refuse() {
        use nix::mount::{MsFlags, mount, umount};

        let scratch = Scratch::new();
        if !nix::unistd::geteuid().is_root() {
            eprintln!(
                "SKIPPED-NOT-ROOT writable_linux_private_archive_row_7_bind_source_alias_and_declared_mount_device_refuse"
            );
            return;
        }
        let source = scratch.0.join("source");
        let alias = scratch.0.join("alias");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&alias).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&alias, std::fs::Permissions::from_mode(0o700)).unwrap();
        mount(
            Some(source.as_path()),
            alias.as_path(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .unwrap();
        let result = prepare_private_archive_parent(
            &alias.join("bundle.gsb"),
            ArchiveSources::new(&[source.as_path()], None),
            scratch.uid(),
        );
        umount(alias.as_path()).unwrap();
        assert_eq!(refusal(result), "output inside source tree");

        let device = std::fs::symlink_metadata(&scratch.0).unwrap().dev();
        assert_eq!(
            refusal(prepare_private_archive_parent(
                &scratch.0.join("bundle.gsb"),
                ArchiveSources::new(
                    &[],
                    Some(MountedNamespace::new(
                        Path::new("/declared/mountpoint"),
                        (u64::MAX, u64::MAX),
                        Some(device)
                    ))
                ),
                scratch.uid()
            )),
            "output inside mounted namespace"
        );
    }
}
