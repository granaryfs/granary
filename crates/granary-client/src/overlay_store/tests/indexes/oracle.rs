// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::overlay_store::{OverlayQuery, OverlayQueryEntry};

pub(super) fn names(path: &str) -> Vec<Name> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(name)
        .collect()
}

pub(super) fn location(path: &str) -> codec::Location {
    let mut path = names(path);
    let name = path.pop().unwrap();
    codec::Location {
        parent: codec::Parent::new(path).unwrap(),
        name,
    }
}

pub(super) fn directory(path: &str) -> OverlayEntry {
    OverlayEntry {
        path: names(path),
        inode: 0,
        kind: OverlayKind::Directory,
        stage_id: None,
        size: 0,
        exec: false,
    }
}

fn found<T>(answer: OverlayQuery<T>) -> Result<T, &'static str> {
    match answer {
        OverlayQuery::Found(value) => Ok(value),
        _ => Err("expected found answer"),
    }
}

fn nlink(primary: &BTreeMap<Vec<Name>, OverlayEntry>, path: &[Name]) -> u32 {
    if !path.is_empty()
        && !primary
            .get(path)
            .is_some_and(|e| matches!(e.kind, OverlayKind::Directory))
    {
        return 1;
    }
    2 + u32::try_from(
        primary
            .values()
            .filter(|e| {
                matches!(e.kind, OverlayKind::Directory)
                    && e.path.len() == path.len() + 1
                    && e.path.starts_with(path)
            })
            .count(),
    )
    .unwrap()
}

fn row(primary: &BTreeMap<Vec<Name>, OverlayEntry>, path: &[Name]) -> OverlayQueryEntry {
    OverlayQueryEntry {
        entry: primary.get(path).cloned(),
        nlink: nlink(primary, path),
    }
}

/// Expected values depend only on primary entries, never derived associations.
pub(super) fn answers(f: &mut Fixture) -> Result<[usize; 5], &'static str> {
    let primary: BTreeMap<_, _> = f
        .overlay
        .namespace
        .entries
        .iter()
        .map(|(p, e)| (p.clone(), e.clone()))
        .collect();
    let mut counts = [0; 5];
    let mut directories = vec![Vec::new()];
    directories.extend(
        primary
            .iter()
            .filter(|(_, e)| matches!(e.kind, OverlayKind::Directory))
            .map(|(p, _)| p.clone()),
    );
    for path in directories {
        let expected = primary
            .values()
            .filter(|e| e.path.len() == path.len() + 1 && e.path.starts_with(&path))
            .map(|e| row(&primary, &e.path))
            .collect::<Vec<_>>();
        let observation = found(
            f.overlay
                .query_directory(&f.store, &f.owner, &path)
                .map_err(|_| "directory refused")?,
        )?;
        let mut parent = path.clone();
        parent.pop();
        if (observation.directory, observation.parent)
            != (row(&primary, &path), row(&primary, &parent))
        {
            return Err("directory/parent metadata mismatch");
        }
        let mut cursor = observation.cursor;
        let mut rows = Vec::new();
        let mut pages = 0;
        loop {
            pages += 1;
            if pages > primary.len() + 1 {
                return Err("page continuation did not terminate");
            }
            let page = found(
                f.overlay
                    .query_children(&f.store, &f.owner, &cursor)
                    .map_err(|_| "children refused")?,
            )?;
            rows.extend(page.entries);
            counts[4] += 1;
            match page.next {
                Some(next) if rows.len() <= primary.len() => cursor = next,
                Some(_) => return Err("page continuation did not terminate"),
                None => break,
            }
        }
        if rows != expected {
            return Err("missing-child mismatch");
        }
        let absent = name("absent-oracle-child");
        if f.overlay
            .query_lookup(&f.store, &f.owner, &path, &absent)
            .map_err(|_| "absent lookup refused")?
            != OverlayQuery::Missing
        {
            return Err("absent child mismatch");
        }
        counts[3] += 1;
    }
    for (path, entry) in &primary {
        let expected = row(&primary, path);
        let by_path = f
            .overlay
            .query_path(&f.store, &f.owner, path)
            .map_err(|_| "path refused")?;
        let by_inode = f
            .overlay
            .query_inode(&f.store, &f.owner, entry.inode)
            .map_err(|_| "inode refused")?;
        let (name, parent) = path.split_last().unwrap();
        let by_lookup = f
            .overlay
            .query_lookup(&f.store, &f.owner, parent, name)
            .map_err(|_| "lookup refused")?;
        if (found(by_path)?, found(by_inode)?, found(by_lookup)?)
            != (expected.clone(), expected.clone(), expected)
        {
            return Err("path/inode/lookup mismatch");
        }
        counts[0] += 1;
        counts[1] += 1;
        counts[2] += 1;
    }
    Ok(counts)
}

#[test]
fn independent_answers_detect_missing_child_without_exhaustive_checks() {
    let mut base = vec![directory("d")];
    base.extend((0..257).map(|i| directory(&format!("d/child-{i:04}"))));
    let mut f = Fixture::with_base(base, Source::default());
    let (valid, _) = measure_query(|| answers(&mut f));
    assert_eq!(
        (valid, f.overlay.namespace.entries.len()),
        (Ok([258, 258, 258, 259, 260]), 258)
    );
    f.overlay
        .namespace
        .remove_child_reference(&names("d"), &name("child-0256"))
        .unwrap();
    let (bad, _) = measure_query(|| answers(&mut f));
    assert_eq!(
        (bad, f.overlay.namespace.entries.len()),
        (Err("missing-child mismatch"), 258)
    );
    eprintln!(
        "primary entries=258; valid query routes=(258,258,258,259,260); omitted second-page child refusals=1"
    );
}
