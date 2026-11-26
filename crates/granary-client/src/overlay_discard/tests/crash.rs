// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::overlay_store::tests::SimIo;

type Tree = BTreeMap<PathBuf, Option<Vec<u8>>>;

fn evidence(root: &Path) -> Tree {
    ["overlay", "publications"]
        .into_iter()
        .flat_map(|name| {
            let dir = root.join(name);
            snapshot(&dir).into_iter().map(move |(p, e)| {
                (
                    if p.as_os_str().is_empty() {
                        dir.clone()
                    } else {
                        dir.join(p)
                    },
                    e.bytes,
                )
            })
        })
        .collect()
}

fn model(root: &Path, tree: &Tree, already_durable: bool) -> SimIo {
    let mut io = SimIo::default();
    io.establish(root).unwrap();
    for (path, bytes) in tree {
        if let Some(bytes) = bytes {
            io.create(path).unwrap();
            io.write_at(path, 0, bytes).unwrap();
            if already_durable {
                io.sync(path).unwrap();
            }
        } else {
            io.create_directory(path).unwrap();
        }
    }
    if already_durable {
        for (path, bytes) in tree {
            if bytes.is_none() {
                io.sync_directory(path).unwrap();
            }
        }
        io.sync_directory(root).unwrap();
    }
    io
}

#[expect(
    clippy::disallowed_methods,
    reason = "restore the simulator's durable namespace only in the test-owned store"
)]
fn restore(root: &Path, io: &SimIo) {
    std::fs::remove_dir_all(root.join("overlay")).unwrap();
    std::fs::remove_dir_all(root.join("publications")).unwrap();
    for (path, bytes) in io.tree() {
        if let Some(bytes) = bytes {
            put(&path, &bytes);
        } else if path != root {
            std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
        }
    }
}

#[derive(Clone, Copy)]
enum Operation {
    File,
    Directory,
    Create,
    Rename,
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the expected operation schedule and its per-cut retry assertions form one matrix"
)]
fn discard_crash_every_durable_step() {
    use Operation::{Create, Directory, File, Rename};
    // Cut at both sides of each actual operation. At every cut with an
    // unsynced rename, exercise both legal outcomes of the parent update.
    const STEPS: usize = 22;
    const RENAME: usize = STEPS - 3;
    for (cut, rename_survives) in (0..2 * STEPS)
        .map(|cut| (cut, false))
        .chain((2 * RENAME + 1..2 * STEPS - 1).map(|cut| (cut, true)))
        .chain([(2 * STEPS, false)])
    {
        let (_scratch, root, area, volume, _) = fixture();
        let scope = area.parent().unwrap();
        let publications = root.join("publications");
        let pub_scope = publications.join(hex(&[1; 32]));
        let mut disk = OverlayDisk::new(&root, nix::unistd::geteuid().as_raw());
        let unmerged = area.join("unmerged");
        for dir in [&publications, &pub_scope, &unmerged] {
            disk.create_directory(dir).unwrap();
        }
        for (dir, name, bytes) in [
            (
                area.clone(),
                "journal.next",
                b"journal temporary".as_slice(),
            ),
            (area.clone(), "ownership.tmp", b"ownership temporary"),
            (area.join("staging"), "0000000000000001", b"stage one"),
            (area.join("staging"), "0000000000000002", b"stage two"),
            (unmerged.clone(), "0000000000000003", b"unmerged stage"),
            (pub_scope.clone(), "vol.sub.tmp-1", b"publication temporary"),
        ] {
            put(&dir.join(name), bytes);
        }
        let plan = discard_overlay(&root, [1; 32], &volume, None).unwrap();
        let tuple = Some((plan.name.writer, plan.name.incarnation));
        let archive = scope.join(plan.name.leaf(false));
        let intent = scope.join(plan.name.leaf(true));
        let before = evidence(&root);
        let unsynced = cut == 2 * STEPS;
        let mut io = model(&root, &before, !unsynced);
        let schedule = [
            ("writer", File, area.join("writer")),
            ("journal", File, area.join("journal")),
            ("journal.next", File, area.join("journal.next")),
            ("ownership.tmp", File, area.join("ownership.tmp")),
            (
                "staging/0000000000000001",
                File,
                area.join("staging/0000000000000001"),
            ),
            (
                "staging/0000000000000002",
                File,
                area.join("staging/0000000000000002"),
            ),
            ("staging", Directory, area.join("staging")),
            (
                "unmerged/0000000000000003",
                File,
                unmerged.join("0000000000000003"),
            ),
            ("unmerged", Directory, unmerged),
            ("vol.sub.tmp-1", File, pub_scope.join("vol.sub.tmp-1")),
            ("selected", Directory, area.clone()),
            ("scope", Directory, scope.into()),
            ("overlay", Directory, root.join("overlay")),
            ("publication scope", Directory, pub_scope),
            ("publications", Directory, publications),
            ("store root", Directory, root.clone()),
            ("intent create", Create, intent.clone()),
            ("intent file", File, intent.clone()),
            ("intent scope", Directory, scope.into()),
            ("rename", Rename, area.clone()),
            ("archive", Directory, archive.clone()),
            ("archive scope", Directory, scope.into()),
        ];
        assert_eq!(schedule.len(), STEPS);
        assert_eq!(schedule[RENAME].0, "rename");
        let mut observed = 0;
        let mut intent_synced = false;
        let mut archive_synced = false;
        let result = run(&root, [1; 32], &volume, tuple, &mut |label, after| {
            let (wanted, operation, path) = &schedule[observed / 2];
            assert_eq!(
                (label, after),
                (*wanted, observed % 2 == 1),
                "event {observed}"
            );
            if after {
                match operation {
                    Create => io.create(path),
                    File => io.sync(path),
                    Directory => io.sync_directory(path),
                    Rename => io.rename(path, &archive),
                }
                .unwrap();
                intent_synced |= label == "intent scope";
                archive_synced |= label == "archive scope";
            }
            if observed == cut {
                return Err(DURABILITY);
            }
            observed += 1;
            Ok(())
        });
        if unsynced {
            assert_eq!(result.unwrap().outcome, Outcome::Moved);
            assert_eq!(observed, cut);
        } else {
            assert_eq!(result, Err(DURABILITY), "cut {cut}");
            assert_eq!(observed, cut);
            assert_eq!(
                evidence(&root),
                io.tree().into_iter().filter(|(p, _)| p != &root).collect()
            );
        }
        let rename_visible = std::fs::symlink_metadata(&archive).is_ok();
        if rename_survives && rename_visible {
            io.sync_directory(scope).unwrap();
        }
        io.crash();
        restore(&root, &io);
        let reopened = discard_overlay(&root, [1; 32], &volume, None).unwrap();
        let files = 7;
        let expected = if archive_synced || (rename_visible && rename_survives) {
            Outcome::Archived(files)
        } else if intent_synced {
            Outcome::Pending(files)
        } else {
            Outcome::Live(files)
        };
        assert_eq!(
            reopened.outcome, expected,
            "cut {cut}, rename persists {rename_survives}"
        );
        assert_eq!(
            (&reopened.name, reopened.bytes),
            (&plan.name, plan.bytes),
            "cut {cut}"
        );
        let retry = discard_overlay(&root, [1; 32], &volume, tuple).unwrap();
        let expected = if matches!(reopened.outcome, Outcome::Archived(_)) {
            Outcome::AlreadyArchived
        } else {
            Outcome::Moved
        };
        assert_eq!(
            (retry.outcome, retry.bytes, retry.name),
            (expected, plan.bytes, plan.name)
        );
        let mut expected: Tree = before
            .into_iter()
            .map(|(p, bytes)| {
                let path = match p.strip_prefix(&area) {
                    Ok(rest) if rest.as_os_str().is_empty() => archive.clone(),
                    Ok(rest) => archive.join(rest),
                    Err(_) => p,
                };
                (path, bytes)
            })
            .collect();
        expected.insert(intent, Some(Vec::new()));
        // The complete evidence tree includes exactly the original writer
        // record and all publication bytes. Discard has no authority input.
        assert_eq!(
            evidence(&root),
            expected,
            "cut {cut}, rename persists {rename_survives}"
        );
    }
}
