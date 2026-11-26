// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use nix::{
    mount::{MntFlags, MsFlags, mount, umount2},
    unistd::{Uid, fchown, linkat},
};
use std::os::unix::fs::PermissionsExt as _;

fn foreign(plant: impl FnOnce(&Path)) {
    let (_scratch, root, area, volume, _) = fixture();
    let plan = discard_overlay(&root, [1; 32], &volume, None).unwrap();
    plant(&area);
    refuses_unchanged(&root, &volume, &plan);
}

fn refuses_unchanged(root: &Path, volume: &VolumeName, plan: &Row) {
    let before = snapshot(root);
    assert_eq!(
        discard_overlay(
            root,
            [1; 32],
            volume,
            Some((plan.name.writer, plan.name.incarnation))
        ),
        Err(DiscardError(FOREIGN))
    );
    assert_eq!(snapshot(root), before);
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "give the fixture journal a foreign mode without altering its bytes"
)]
fn discard_refuses_foreign_mode() {
    foreign(|area| {
        std::fs::set_permissions(area.join("journal"), std::fs::Permissions::from_mode(0o640))
            .unwrap();
    });
}

#[test]
#[ignore = "requires CAP_CHOWN, exercised in the Linux overlay fault lane"]
fn discard_refuses_foreign_owner() {
    foreign(|area| {
        let file = fsguard::open_regular_read(&area.join("journal")).unwrap();
        let uid = Uid::from_raw(if nix::unistd::geteuid().as_raw() == 65534 {
            65533
        } else {
            65534
        });
        fchown(&file, Some(uid), None).unwrap();
        assert_eq!(file.metadata().unwrap().uid(), uid.as_raw());
    });
}

#[test]
fn discard_refuses_granting_posix_acl() {
    use rustix::fs::{XattrFlags, fgetxattr_query, fsetxattr};

    foreign(|area| {
        // A granting default ACL leaves the directory's 0700 access mode
        // intact, so mode checking alone cannot explain this refusal.
        let staging = fsguard::open_directory(&area.join("staging")).unwrap();
        let name = "system.posix_acl_default";
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in [
            (1u16, 7u16, u32::MAX), // USER_OBJ
            (2, 7, 65533),          // USER
            (4, 0, u32::MAX),       // GROUP_OBJ
            (16, 7, u32::MAX),      // MASK
            (32, 0, u32::MAX),      // OTHER
        ] {
            acl.extend(tag.to_le_bytes());
            acl.extend(perm.to_le_bytes());
            acl.extend(id.to_le_bytes());
        }
        fsetxattr(&staging, name, &acl, XattrFlags::CREATE).unwrap();
        assert_eq!(staging.metadata().unwrap().mode() & 0o7777, 0o700);
        assert_eq!(fgetxattr_query(&staging, name).unwrap(), acl.len());
    });
}

#[test]
fn discard_refuses_unpaired_hard_link() {
    foreign(|area| {
        let dir = fsguard::open_directory(area).unwrap();
        let parent = fsguard::open_directory(area.parent().unwrap()).unwrap();
        linkat(
            &dir,
            "journal",
            &parent,
            "foreign-link",
            nix::fcntl::AtFlags::empty(),
        )
        .unwrap();
        assert_eq!(
            fsguard::open_regular_read(&area.join("journal"))
                .unwrap()
                .metadata()
                .unwrap()
                .nlink(),
            2
        );
    });
}

struct Bind(PathBuf);
impl Drop for Bind {
    fn drop(&mut self) {
        umount2(&self.0, MntFlags::MNT_DETACH).unwrap();
    }
}

#[test]
#[ignore = "requires an isolated Linux mount namespace, exercised in the overlay fault lane"]
fn discard_refuses_mount_crossing() {
    let (_scratch, root, area, volume, _) = fixture();
    let plan = discard_overlay(&root, [1; 32], &volume, None).unwrap();
    let donor = root.join("other");
    OverlayDisk::new(&root, nix::unistd::geteuid().as_raw())
        .create_directory(&donor)
        .unwrap();
    put(&donor.join("0000000000000001"), b"foreign mount bytes");
    let staging = area.join("staging");
    mount(
        Some(&donor),
        &staging,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .unwrap();
    let bind = Bind(staging.clone());
    let original = fsguard::open_directory(&area).unwrap();
    let crossed = fsguard::open_directory(&staging).unwrap();
    assert_eq!(
        original.metadata().unwrap().dev(),
        crossed.metadata().unwrap().dev()
    );
    assert_ne!(disk::mount(&original), disk::mount(&crossed));
    refuses_unchanged(&root, &volume, &plan);
    drop(bind);
    assert!(snapshot(&staging)[Path::new("")].bytes.is_none());
    assert_eq!(snapshot(&staging).len(), 1);
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "plant a foreign destination in the test-owned scope"
)]
fn discard_refuses_empty_destination_race() {
    collision(|target| {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(target)
            .unwrap();
    });
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "plant a foreign destination in the test-owned scope"
)]
fn discard_refuses_nonempty_destination_race() {
    collision(|target| {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(target)
            .unwrap();
        put(&target.join("foreign"), b"keep");
    });
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "plant a foreign destination in the test-owned scope"
)]
fn discard_refuses_dangling_destination_race() {
    collision(|target| std::os::unix::fs::symlink("absent", target).unwrap());
}

fn collision(plant: impl FnOnce(&Path)) {
    let (_scratch, root, area, volume, _) = fixture();
    let plan = discard_overlay(&root, [1; 32], &volume, None).unwrap();
    let target = area.with_file_name(plan.name.leaf(false));
    let mut plant = Some(plant);
    let mut planted = None;
    let mut inject = |step: &str, after: bool| {
        if step == "rename" && !after {
            plant.take().unwrap()(&target);
            planted = Some(snapshot(&root));
        }
        Ok(())
    };
    let tuple = Some((plan.name.writer, plan.name.incarnation));
    assert_eq!(
        run(&root, [1; 32], &volume, tuple, &mut inject),
        Err(COLLISION)
    );
    assert_eq!(snapshot(&root), planted.unwrap());
}
