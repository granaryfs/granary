// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{OverlayDisk, OverlayIo as _, fsguard, overlay_test_support::ScratchDir};
use granary_core::{
    hash::GrainId,
    overlay_journal::{JournalHeader, WriterRecord},
};
use std::{
    collections::BTreeMap,
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _},
    path::PathBuf,
};

mod crash;
mod gates;
#[cfg(target_os = "linux")]
mod linux;

#[expect(
    clippy::disallowed_methods,
    reason = "use the physical path to this test-owned scratch tree"
)]
pub(crate) fn empty_store(scope: &str, volume: &VolumeName) -> (ScratchDir, PathBuf, PathBuf) {
    let scratch = ScratchDir::new();
    let root = scratch.0.canonicalize().unwrap().join("store");
    drop(Store::open(&root).unwrap());
    let scope_dir = root.join("overlay").join(scope);
    let area = scope_dir.join(volume.as_str());
    let mut io = OverlayDisk::new(&root, nix::unistd::geteuid().as_raw());
    for dir in [
        root.join("overlay"),
        scope_dir,
        area.clone(),
        area.join("staging"),
    ] {
        io.create_directory(&dir).unwrap();
    }
    (scratch, root, area)
}

pub(super) fn fixture() -> (ScratchDir, PathBuf, PathBuf, VolumeName, Vec<u8>) {
    let volume = VolumeName::from_bytes(b"vol").unwrap();
    let (scratch, root, area) = empty_store(&hex(&[1; 32]), &volume);
    let writer = WriterRecord {
        writer: [2; 16],
        ceiling: 0,
        volume: volume.clone(),
    };
    let header = JournalHeader {
        writer: writer.writer,
        base_root: GrainId::of(b"test"),
        base_seq: 1,
        next_stage_id: 1,
        receipt_generation: 0,
    };
    let mut journal = header.encode().unwrap();
    journal.push(1);
    put(&area.join("writer"), &writer.encode().unwrap());
    put(&area.join("journal"), &journal);
    (scratch, root, area, volume, journal)
}

pub(crate) fn put(path: &Path, bytes: &[u8]) {
    fsguard::create_regular_exclusive(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

/// Install the exact intent for a healthy overlay, then let discard finish it.
pub(crate) fn claim_healthy_store(
    root: &Path,
    area: &Path,
    scope: [u8; 32],
    volume: &VolumeName,
) -> ([u8; 16], [u8; 32]) {
    let digest = hex(&scope);
    let selected = fsguard::open_directory(area).unwrap();
    let mount = disk::mount(&selected).unwrap();
    let store = fsguard::open_directory(root).unwrap();
    let publications = disk::directory(&store, OsStr::new("publications"), mount).unwrap();
    let publication_scope = publications
        .as_ref()
        .and_then(|parent| disk::directory(parent, OsStr::new(&digest), mount).unwrap());
    let mut walk = Walk {
        mount,
        barriers: None,
    };
    let (tree, writer, _) = walk.overlay(&selected, &digest, volume).unwrap();
    let (published, _) = walk
        .publications(publication_scope.as_ref(), &digest, volume)
        .unwrap();
    let incarnation = incarnation(
        root.as_os_str().as_bytes(),
        &scope,
        volume,
        &writer,
        &tree.entries,
        &published.entries,
    )
    .unwrap();
    let tuple = (writer, incarnation);
    let name = DiscardName {
        volume: volume.clone(),
        writer,
        incarnation,
    };
    assert_eq!(
        discard_overlay(root, scope, volume, Some(tuple)).map_err(DiscardError::reason),
        Err(NOT_ELIGIBLE),
        "an acknowledged tuple alone does not establish a claim",
    );
    put(&area.parent().unwrap().join(name.leaf(true)), b"");
    let retry = || {
        discard_overlay(root, scope, volume, Some(tuple))
            .map(|row| (row.name, row.outcome))
            .map_err(DiscardError::reason)
    };
    assert_eq!(retry(), Ok((name.clone(), Outcome::Moved)));
    assert_eq!(retry(), Ok((name, Outcome::AlreadyArchived)));
    tuple
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    identity: (u64, u64),
    custody: (u32, u32, u64),
    changed: (i64, i64, i64, i64),
    bytes: Option<Vec<u8>>,
}

pub(crate) fn snapshot(root: &Path) -> BTreeMap<PathBuf, Entry> {
    #[expect(
        clippy::disallowed_methods,
        reason = "snapshot the bytes and dangling links in the test-owned tree"
    )]
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Entry>) {
        let m = std::fs::symlink_metadata(path).unwrap();
        let bytes = if m.is_dir() {
            let dir = fsguard::open_directory(path).unwrap();
            for leaf in disk::names(&dir).unwrap() {
                visit(root, &path.join(leaf), result);
            }
            None
        } else if m.is_symlink() {
            Some(
                std::fs::read_link(path)
                    .unwrap()
                    .as_os_str()
                    .as_bytes()
                    .to_vec(),
            )
        } else {
            Some(std::fs::read(path).unwrap())
        };
        result.insert(
            path.strip_prefix(root).unwrap().into(),
            Entry {
                identity: (m.dev(), m.ino()),
                custody: (m.uid(), m.mode(), m.nlink()),
                changed: (m.ctime(), m.ctime_nsec(), m.mtime(), m.mtime_nsec()),
                bytes,
            },
        );
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

fn replace_root(root: &Path, replacement: &Path) -> PathBuf {
    let parent = fsguard::open_directory(root.parent().unwrap()).unwrap();
    let replacement_parent = fsguard::open_directory(replacement.parent().unwrap()).unwrap();
    let name = root.file_name().unwrap();
    nix::fcntl::renameat(&parent, name, &parent, "parked").unwrap();
    nix::fcntl::renameat(
        &replacement_parent,
        replacement.file_name().unwrap(),
        &parent,
        name,
    )
    .unwrap();
    root.with_file_name("parked")
}

#[test]
fn discard_refuses_root_rebind_before_creating_intent() {
    let (_scratch, root, _, volume, _) = fixture();
    let (_replacement, replacement, _, _, _) = fixture();
    let plan = discard_overlay(&root, [1; 32], &volume, None).unwrap();
    let tuple = Some((plan.name.writer, plan.name.incarnation));
    let mut rebound = None;
    let result = run(&root, [1; 32], &volume, tuple, &mut |step, after| {
        if step == "intent create" && !after {
            let parked = replace_root(&root, &replacement);
            rebound = Some((snapshot(&parked), snapshot(&root), parked));
        }
        Ok(())
    });
    let (original, substituted, parked) = rebound.unwrap();
    assert_eq!(result, Err(CHANGED));
    assert_eq!(snapshot(&parked), original);
    assert_eq!(snapshot(&root), substituted);
}

#[test]
fn discard_plan_refuses_root_rebind_after_open() {
    let (_scratch, root, _, volume, _) = fixture();
    let (_replacement, replacement, _, _, _) = fixture();
    let target = root.clone();
    fsguard::DIRECTORY_OPEN_HOOK.with_borrow_mut(|hook| {
        *hook = Some((
            root.clone(),
            Box::new(move || {
                // The first open pins the root. The store's ancestry check
                // next opens the path and will accept the substitute.
                fsguard::DIRECTORY_OPEN_HOOK.with_borrow_mut(|hook| {
                    *hook = Some((
                        target.clone(),
                        Box::new(move || {
                            replace_root(&target, &replacement);
                        }),
                    ));
                });
            }),
        ));
    });
    assert_eq!(
        discard_overlay(&root, [1; 32], &volume, None),
        Err(DiscardError(CHANGED))
    );
    assert!(fsguard::open_directory(&root.with_file_name("parked")).is_ok());
}

#[test]
fn discard_plan_scans_cross_scope_claims_from_held_root() {
    let (_scratch, root, _, volume, _) = fixture();
    let plan = discard_overlay(&root, [1; 32], &volume, None).unwrap();
    let overlay = root.join("overlay");
    let other_scope = overlay.join(hex(&[3; 32]));
    OverlayDisk::new(&root, nix::unistd::geteuid().as_raw())
        .create_directory(&other_scope)
        .unwrap();
    put(&other_scope.join(plan.name.leaf(true)), b"");

    fsguard::DIRECTORY_OPEN_HOOK.with_borrow_mut(|hook| {
        *hook = Some((overlay, Box::new(|| {})));
    });
    let result = discard_overlay(&root, [1; 32], &volume, None);
    let used_held_root = fsguard::DIRECTORY_OPEN_HOOK.with_borrow_mut(|hook| hook.take().is_some());
    assert_eq!(result, Err(DiscardError(CHANGED)));
    assert!(
        used_held_root,
        "claim scan reopened the overlay by pathname"
    );
}

#[test]
fn discard_rechecks_widened_root_mode_before_writing() {
    use nix::sys::stat::{Mode, fchmod};

    let (_scratch, root, _, volume, _) = fixture();
    let plan = discard_overlay(&root, [1; 32], &volume, None).unwrap();
    let tuple = Some((plan.name.writer, plan.name.incarnation));
    let root_fd = fsguard::open_directory(&root).unwrap();
    let mut widened = None;
    let result = run(&root, [1; 32], &volume, tuple, &mut |step, after| {
        if step == "intent create" && !after {
            fchmod(&root_fd, Mode::from_bits_truncate(0o755)).unwrap();
            widened = Some(snapshot(&root));
        }
        Ok(())
    });
    assert_eq!(result, Err(FOREIGN));
    assert_eq!(snapshot(&root), widened.unwrap());
}

#[test]
fn discard_reports_unsupported_exclusive_rename_without_retry() {
    for errno in [libc::EINVAL, libc::ENOSYS, libc::ENOTSUP] {
        let (_scratch, root, area, volume, _) = fixture();
        let plan = discard_overlay(&root, [1; 32], &volume, None).unwrap();
        let tuple = Some((plan.name.writer, plan.name.incarnation));
        let result = run_with_rename(
            &root,
            [1; 32],
            &volume,
            tuple,
            &mut |_, _| Ok(()),
            |_, _, _| Err(io::Error::from_raw_os_error(errno)),
        );
        assert_eq!(
            DiscardError(result.unwrap_err()).to_string(),
            "OverlayDiscardUnsupported"
        );
        assert!(fsguard::open_directory(&area).is_ok());
        assert!(fsguard::open_regular_read(&area.with_file_name(plan.name.leaf(true))).is_ok());
        let parent = fsguard::open_directory(area.parent().unwrap()).unwrap();
        assert!(
            !disk::names(&parent)
                .unwrap()
                .contains(&plan.name.leaf(false).into())
        );
    }
}

#[test]
fn discard_refuses_symlink_substituted_for_intent_before_rename() {
    let (_scratch, root, area, volume, _) = fixture();
    let plan = discard_overlay(&root, [1; 32], &volume, None).unwrap();
    let tuple = Some((plan.name.writer, plan.name.incarnation));
    let scope = fsguard::open_directory(area.parent().unwrap()).unwrap();
    let intent = plan.name.leaf(true);
    let result = run(&root, [1; 32], &volume, tuple, &mut |label, after| {
        if label == "rename" && !after {
            nix::fcntl::renameat(&scope, intent.as_str(), &scope, "held-intent").unwrap();
            nix::unistd::symlinkat("absent", &scope, intent.as_str()).unwrap();
        }
        Ok(())
    });
    assert_eq!(result, Err(FOREIGN));
    assert!(fsguard::open_directory(&area).is_ok());
}

#[test]
fn discard_reports_post_rename_io_with_same_tuple_retry() {
    for failed in [
        "destination reopen",
        "live absence",
        "final reread",
        "intent reopen",
    ] {
        let (_scratch, root, area, volume, _) = fixture();
        let plan = discard_overlay(&root, [1; 32], &volume, None).unwrap();
        let archive = plan.name.leaf(false);
        let intent = plan.name.leaf(true);
        let tuple = Some((plan.name.writer, plan.name.incarnation));
        let (step, leaf) = match failed {
            "destination reopen" => ("rename", archive.as_str()),
            "live absence" => ("rename", volume.as_str()),
            "intent reopen" => ("archive scope", intent.as_str()),
            _ => ("archive scope", "journal"),
        };
        let result = run(&root, [1; 32], &volume, tuple, &mut |label, after| {
            if label == step && after {
                disk::OPEN_ERROR.with_borrow_mut(|error| *error = Some(leaf.into()));
            }
            Ok(())
        });
        assert!(disk::OPEN_ERROR.with_borrow(Option::is_none), "{failed}");
        assert_eq!(result, Err(DURABILITY), "{failed}");
        assert!(
            DiscardError(result.unwrap_err())
                .to_string()
                .contains("retry the same tuple")
        );
        assert!(fsguard::open_directory(&area.with_file_name(&archive)).is_ok());
        assert_eq!(
            discard_overlay(&root, [1; 32], &volume, tuple)
                .unwrap()
                .outcome,
            Outcome::AlreadyArchived
        );
    }
}

#[test]
fn discard_reports_post_rename_root_open_io_with_same_tuple_retry() {
    let (_scratch, root, area, volume, _) = fixture();
    let plan = discard_overlay(&root, [1; 32], &volume, None).unwrap();
    let tuple = Some((plan.name.writer, plan.name.incarnation));
    let result = run(&root, [1; 32], &volume, tuple, &mut |label, after| {
        if label == "archive scope" && after {
            disk::OPEN_ERROR.with_borrow_mut(|error| *error = Some(root.as_os_str().into()));
        }
        Ok(())
    });
    assert!(disk::OPEN_ERROR.with_borrow_mut(|error| error.take().is_none()));
    assert_eq!(result, Err(DURABILITY));
    assert!(fsguard::open_directory(&area.with_file_name(plan.name.leaf(false))).is_ok());
    assert_eq!(
        discard_overlay(&root, [1; 32], &volume, tuple)
            .unwrap()
            .outcome,
        Outcome::AlreadyArchived
    );
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "adversarially rebind directories within the test-owned store"
)]
fn discard_refuses_source_rebind_and_never_reopens_rename_parent() {
    for rebind in ["source", "scope", "pathname lookup"] {
        let (_scratch, root, area, volume, _) = fixture();
        let scope = area.parent().unwrap().to_owned();
        let plan = discard_overlay(&root, [1; 32], &volume, None).unwrap();
        let tuple = Some((plan.name.writer, plan.name.incarnation));
        let target = area.with_file_name(plan.name.leaf(false));
        let parked = root.join("parked");
        let contents = snapshot(&area);
        let original = disk::identity(&fsguard::open_directory(&area).unwrap()).unwrap();
        let substitute = {
            let (area, scope, parked) = (area.clone(), scope.clone(), parked.clone());
            move || {
                let victim = if rebind == "source" { &area } else { &scope };
                std::fs::rename(victim, parked).unwrap();
                if rebind != "source" {
                    std::fs::DirBuilder::new()
                        .mode(0o700)
                        .create(scope)
                        .unwrap();
                }
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&area)
                    .unwrap();
                put(&area.join("witness"), b"substitute");
            }
        };
        let mut substitute = Some(substitute);
        let mut inject = |label: &str, after: bool| {
            if label == "rename" && !after {
                let substitute = substitute.take().unwrap();
                if rebind == "pathname lookup" {
                    // A pathname reopened after the descriptor recheck can
                    // resolve to a new directory even though the recheck passed.
                    fsguard::DIRECTORY_OPEN_HOOK.with_borrow_mut(|hook| {
                        *hook = Some((scope.clone(), Box::new(substitute)));
                    });
                } else {
                    substitute();
                }
            }
            Ok(())
        };
        let result = run(&root, [1; 32], &volume, tuple, &mut inject);
        let remained_pinned =
            fsguard::DIRECTORY_OPEN_HOOK.with_borrow_mut(|hook| hook.take().is_some());
        if rebind == "pathname lookup" {
            assert_eq!(
                disk::identity(&fsguard::open_directory(&target).unwrap()).unwrap(),
                original,
                "rename moved the substituted directory"
            );
            assert!(remained_pinned, "rename reopened the scope by pathname");
            assert_eq!(result.unwrap().outcome, Outcome::Moved);
            continue;
        }
        assert!(
            !target.exists(),
            "a rename moved the substituted source: {rebind}"
        );
        assert_eq!(result, Err(CHANGED), "{rebind}");
        let saved = if rebind == "source" {
            parked
        } else {
            parked.join(volume.as_str())
        };
        let kept = snapshot(&saved);
        assert_eq!(kept[Path::new("")].identity, original);
        assert_eq!(
            kept.iter().map(|(p, e)| (p, &e.bytes)).collect::<Vec<_>>(),
            contents
                .iter()
                .map(|(p, e)| (p, &e.bytes))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            snapshot(&area)[Path::new("witness")].bytes.as_deref(),
            Some(&b"substitute"[..])
        );
    }
}

#[test]
fn discard_exact_selection_retries_and_keeps_charge() {
    let (_scratch, root, area, volume, journal) = fixture();
    let scope = [1; 32];
    let live = discard_overlay(&root, scope, &volume, None).unwrap();
    assert_eq!(live.outcome, Outcome::Live(2));
    assert!(live.bytes > journal.len() as u64);
    let tuple = Some((live.name.writer, live.name.incarnation));
    for (scope, volume, identity) in [
        ([9; 32], volume.clone(), tuple),
        (scope, VolumeName::from_bytes(b"other").unwrap(), tuple),
        (
            scope,
            volume.clone(),
            Some(([0; 16], live.name.incarnation)),
        ),
        (scope, volume.clone(), Some((live.name.writer, [0; 32]))),
    ] {
        assert!(discard_overlay(&root, scope, &volume, identity).is_err());
    }
    put(&area.join("journal.next"), b"new bytes");
    assert_eq!(
        discard_overlay(&root, scope, &volume, tuple),
        Err(DiscardError(CHANGED))
    );
    let live = discard_overlay(&root, scope, &volume, None).unwrap();
    let tuple = Some((live.name.writer, live.name.incarnation));
    let cut = run(&root, scope, &volume, tuple, &mut |step, after| {
        if step == "intent scope" && after {
            return Err(DURABILITY);
        }
        Ok(())
    });
    assert_eq!(cut, Err(DURABILITY));
    assert_eq!(
        discard_overlay(&root, scope, &volume, None)
            .unwrap()
            .outcome,
        Outcome::Pending(3)
    );
    let mut store = Store::open_existing(&root).unwrap().0;
    let refused = |store: &mut Store| {
        store
            .publications(nix::unistd::geteuid().as_raw())
            .unwrap()
            .select_direct(&volume, None)
            .unwrap_err()
            .to_string()
    };
    assert!(refused(&mut store).contains("OverlayDiscardPending"));
    drop(store);
    let moved = discard_overlay(&root, scope, &volume, tuple).unwrap();
    assert_eq!((moved.outcome, moved.bytes), (Outcome::Moved, live.bytes));
    assert_eq!(
        discard_overlay(&root, scope, &volume, tuple)
            .unwrap()
            .outcome,
        Outcome::AlreadyArchived
    );
    let mut store = Store::open_existing(&root).unwrap().0;
    assert!(refused(&mut store).contains("OverlayArchived"));
    let archived = area.with_file_name(moved.name.leaf(false)).join("journal");
    let mut bytes = Vec::new();
    fsguard::open_regular_read(&archived)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, journal);
}
