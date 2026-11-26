// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::options` — the FUSE mount session's option set.
//!
//! Out-of-line: `granary-fuse`'s non-test artifact
//! has a workspace consumer (`granary-client`), so
//! the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use fuser::{MountOption, SessionACL};

#[test]
fn shipped_option_set_is_ro_nosuid_nodev_and_not_noexec() {
    let config = super::session_config(false);
    assert!(config.mount_options.contains(&MountOption::RO));
    assert!(config.mount_options.contains(&MountOption::NoSuid));
    assert!(config.mount_options.contains(&MountOption::NoDev));
    assert!(
        !config.mount_options.contains(&MountOption::NoExec),
        "noexec must not be forced: the smoke test executes a binary from the mount"
    );
}

#[test]
fn n_threads_is_explicitly_one() {
    let config = super::session_config(false);
    assert_eq!(config.n_threads, Some(1));
}

// Test BOTH ACL arms, because
// `session_config(true)` was never called anywhere in the crate
// before this test — half the only parameter's domain was
// untested, and inverting the mapping (`SessionACL::All` when
// `!allow_other`) passed the whole suite. This is the one field
// in the file that decides who can read the filesystem.
#[test]
fn acl_is_all_when_allow_other_and_owner_otherwise() {
    assert_eq!(super::session_config(true).acl, SessionACL::All);
    assert_eq!(super::session_config(false).acl, SessionACL::Owner);
}

// FSName is load-bearing
// for the CI teardown gate, which matches on mount SOURCE
// precisely because the fstype is `fuse` on the privileged path
// and `fuse.gran` on the unprivileged one — an unpinned constant
// here silently disarms that gate with a green suite.
#[test]
fn fsname_and_subtype_are_pinned_to_gran() {
    let config = super::session_config(false);
    assert!(
        config
            .mount_options
            .contains(&MountOption::FSName("gran".to_owned()))
    );
    assert!(
        config
            .mount_options
            .contains(&MountOption::Subtype("gran".to_owned()))
    );
}

// `default_permissions` and `clone_fd` are both named in the shipped
// option set and both free to change silently without this.
#[test]
fn default_permissions_is_set_and_clone_fd_is_false() {
    let config = super::session_config(false);
    assert!(
        config
            .mount_options
            .contains(&MountOption::DefaultPermissions)
    );
    assert!(!config.clone_fd);
}

#[test]
fn writable_options_are_rw_owner_nosuid_nodev_default_permissions() {
    let config = super::writable_session_config();
    assert_eq!(
        config.mount_options,
        vec![
            MountOption::RW,
            MountOption::NoSuid,
            MountOption::NoDev,
            MountOption::DefaultPermissions,
            MountOption::FSName("gran".to_owned()),
            MountOption::Subtype("gran".to_owned())
        ]
    );
    assert_eq!(
        (config.acl, config.n_threads, config.clone_fd),
        (SessionACL::Owner, Some(1), false)
    );
}
