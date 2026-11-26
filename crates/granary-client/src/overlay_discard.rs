// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Offline overlay retirement under the existing exclusive store lock.

pub(crate) mod claims;
mod disk;
mod inventory;
mod reconcile;

pub use reconcile::{ArchiveReconciliation, ReconcileRow};
#[cfg(test)]
pub(crate) use reconcile::{archive_publication_bindings, probe_archive_rows};

use crate::{Store, StoreError, publication_store::native_no_replace};
use granary_core::{
    overlay_discard::{DiscardName, Outcome, Row, hex, incarnation},
    root::VolumeName,
};
use inventory::{Inventory, Step, Walk, durable, sync};
use nix::fcntl::OFlag;
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io,
    os::unix::ffi::OsStrExt as _,
    path::Path,
};

use OverlayRefusal as Refusal;
use OverlayRefusal::{
    AmbiguousCustody as AMBIGUOUS, Collision as COLLISION, Durability as DURABILITY,
    ForeignCustody as FOREIGN, Missing as MISSING, NotEligible as NOT_ELIGIBLE,
    SelectionChanged as CHANGED, Unsupported as UNSUPPORTED,
};

/// Closed operational refusal reasons for the offline overlay verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayRefusal {
    /// The command's process failed set-ID admission.
    SetId,
    /// The store lock is held.
    Busy,
    /// Required evidence is absent.
    Missing,
    /// Conflicting evidence prevents a unique custody decision.
    AmbiguousCustody,
    /// Evidence failed custody checks.
    ForeignCustody,
    /// The archive destination or live name collides.
    Collision,
    /// The exact selection no longer matches.
    SelectionChanged,
    /// No eligible work was selected.
    NotEligible,
    /// A barrier, move or output failed.
    Durability,
    /// Exclusive rename is unavailable.
    Unsupported,
    /// The discard is pending and reconciliation needs the archive.
    Pending,
    /// Reconciliation could not establish an outcome.
    Unresolved,
    /// Reconciliation found invalid or contradictory authority evidence.
    RemoteIntegrity,
}

impl OverlayRefusal {
    /// Stable event reason and, where applicable, terminal refusal identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SetId => "set_id",
            Self::Busy => "OverlayDiscardBusy",
            Self::Missing => "OverlayDiscardMissing",
            Self::AmbiguousCustody => "OverlayDiscardAmbiguousCustody",
            Self::ForeignCustody => "OverlayDiscardForeignCustody",
            Self::Collision => "OverlayDiscardCollision",
            Self::SelectionChanged => "OverlayDiscardSelectionChanged",
            Self::NotEligible => "OverlayDiscardNotEligible",
            Self::Durability => "OverlayDiscardDurability",
            Self::Unsupported => "OverlayDiscardUnsupported",
            Self::Pending => "OverlayDiscardPending",
            Self::Unresolved => "OverlayArchiveUnresolved",
            Self::RemoteIntegrity => "OverlayArchiveRemoteIntegrity",
        }
    }

    pub(crate) fn admits(text: &str) -> bool {
        [
            Self::SetId,
            Self::Busy,
            Self::Missing,
            Self::AmbiguousCustody,
            Self::ForeignCustody,
            Self::Collision,
            Self::SelectionChanged,
            Self::NotEligible,
            Self::Durability,
            Self::Unsupported,
            Self::Pending,
            Self::Unresolved,
            Self::RemoteIntegrity,
        ]
        .iter()
        .any(|reason| reason.as_str() == text)
    }
}

pub(crate) use inventory::temporary;

/// A fixed operator-facing discard refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscardError(Refusal);

impl DiscardError {
    /// The closed reason, independent of any terminal remedy.
    #[must_use]
    pub const fn reason(self) -> OverlayRefusal {
        self.0
    }
}

impl std::fmt::Display for DiscardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.as_str())?;
        if self.0 == DURABILITY {
            f.write_str(": retry the same tuple; the move may already be visible")?;
        }
        Ok(())
    }
}

impl std::error::Error for DiscardError {}

/// Plan when no writer and incarnation were supplied, or retire the exact
/// acknowledged selection. Both modes hold the existing store's exclusive lock.
/// A healthy overlay has a clean journal, empty staging and unmerged areas,
/// no publication debt and either no ownership carrier or a settled one.
///
/// # Errors
/// Refuses busy, missing, healthy unclaimed, changed or untrusted evidence and
/// reports uncertain durability or unavailable exclusive rename support.
/// A refusal never removes evidence.
pub fn discard_overlay(
    root: &Path,
    scope: [u8; 32],
    volume: &VolumeName,
    acknowledged: Option<([u8; 16], [u8; 32])>,
) -> Result<Row, DiscardError> {
    run(root, scope, volume, acknowledged, &mut |_, _| Ok(())).map_err(DiscardError)
}

struct Selection {
    overlay: File,
    scope: File,
    area: File,
    publications: Option<File>,
    publication_scope: Option<File>,
    mount: u64,
}

impl Selection {
    fn read(
        &self,
        scope: &str,
        volume: &VolumeName,
        step: Option<&mut Step<'_>>,
    ) -> Result<(Inventory, Inventory, [u8; 16], bool), disk::Error> {
        let mut walk = Walk {
            mount: self.mount,
            barriers: step,
        };
        let (tree, writer, retained) = walk.overlay(&self.area, scope, volume)?;
        let (published, publication_debt) =
            walk.publications(self.publication_scope.as_ref(), scope, volume)?;
        if let Some(step) = walk.barriers {
            sync(step, "selected", &self.area)?;
            sync(step, "scope", &self.scope)?;
            sync(step, "overlay", &self.overlay)?;
            if let Some(dir) = &self.publication_scope {
                sync(step, "publication scope", dir)?;
            }
            if let Some(dir) = &self.publications {
                sync(step, "publications", dir)?;
            }
        }
        Ok((tree, published, writer, retained || publication_debt))
    }

    fn rebound(&self, root: &File, scope: &OsStr, leaf: &OsStr) -> Result<(), disk::Error> {
        let bound = |parent: &File, name, expected: &File| {
            let reopened = disk::directory(parent, name, self.mount)?.ok_or(CHANGED)?;
            if disk::identity(&reopened).map_err(|_| disk::Error::Io)?
                != disk::identity(expected).map_err(|_| disk::Error::Io)?
            {
                return Err(disk::Error::Refused(CHANGED));
            }
            Ok(())
        };
        bound(root, OsStr::new("overlay"), &self.overlay)?;
        bound(&self.overlay, scope, &self.scope)?;
        bound(&self.scope, leaf, &self.area)?;
        match (&self.publications, &self.publication_scope) {
            (Some(publications), selected) => {
                bound(root, OsStr::new("publications"), publications)?;
                match selected {
                    Some(selected) => bound(publications, scope, selected)?,
                    None if disk::directory(publications, scope, self.mount)?.is_some() => {
                        return Err(CHANGED.into());
                    }
                    None => {}
                }
            }
            (None, _)
                if disk::directory(root, OsStr::new("publications"), self.mount)?.is_some() =>
            {
                return Err(CHANGED.into());
            }
            _ => {}
        }
        Ok(())
    }
}

fn run(
    path: &Path,
    scope: [u8; 32],
    volume: &VolumeName,
    acknowledged: Option<([u8; 16], [u8; 32])>,
    step: &mut Step<'_>,
) -> Result<Row, Refusal> {
    run_with_rename(path, scope, volume, acknowledged, step, native_no_replace)
}

fn run_with_rename(
    path: &Path,
    scope: [u8; 32],
    volume: &VolumeName,
    acknowledged: Option<([u8; 16], [u8; 32])>,
    step: &mut Step<'_>,
    rename: impl FnOnce(&File, &CString, &CString) -> io::Result<()>,
) -> Result<Row, Refusal> {
    run_selected(
        path,
        scope,
        volume,
        Action::Discard(acknowledged),
        step,
        rename,
    )
}

type Tuple = ([u8; 16], [u8; 32]);
type ReadArchive<'a> = dyn FnMut(&Selection, &Inventory, &Inventory) -> Result<(), Refusal> + 'a;

enum Action<'a> {
    Discard(Option<Tuple>),
    Reconcile(Tuple, &'a mut ReadArchive<'a>),
}

#[expect(
    clippy::too_many_lines,
    reason = "selection verification precedes either evidence access or the ordered discard transaction"
)]
fn run_selected(
    path: &Path,
    scope: [u8; 32],
    volume: &VolumeName,
    action: Action<'_>,
    step: &mut Step<'_>,
    rename: impl FnOnce(&File, &CString, &CString) -> io::Result<()>,
) -> Result<Row, Refusal> {
    let (store, root) = Store::open_existing(path).map_err(|e| match e {
        StoreError::Locked => Refusal::Busy,
        StoreError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound => MISSING,
        _ => FOREIGN,
    })?;
    let path = store.publication_root();
    let mount = disk::mount(&root)?;
    disk::protected(&root, mount, true)?;
    let binding_io = |after_move| {
        move |_: io::Error| {
            if after_move {
                disk::Error::Io
            } else {
                CHANGED.into()
            }
        }
    };
    let verify_root = |after_move| -> Result<(), disk::Error> {
        // Check the held descriptor even if lost custody now blocks the reopen.
        disk::protected(&root, mount, true)?;
        // Reopen the absolute path to verify the root's visible binding.
        let reopened = disk::at(&root, path.as_os_str(), OFlag::O_DIRECTORY).map_err(|error| {
            match error.raw_os_error() {
                Some(libc::ENOENT | libc::ELOOP | libc::ENOTDIR) => CHANGED.into(),
                _ => binding_io(after_move)(error),
            }
        })?;
        if disk::identity(&reopened).map_err(binding_io(after_move))?
            != disk::identity(&root).map_err(binding_io(after_move))?
        {
            return Err(CHANGED.into());
        }
        disk::protected(&reopened, mount, true)?;
        Ok(())
    };
    let overlay = disk::directory(&root, OsStr::new("overlay"), mount)?.ok_or(MISSING)?;
    let claims = claims::scan_locked(&overlay, mount)?;
    let scope_text = hex(&scope);
    let scope_leaf = OsStr::new(&scope_text);
    let claim = claims.get(volume);
    if claim.is_some_and(|c| c.scope != scope_text) {
        return Err(CHANGED);
    }
    let live = OsStr::new(volume.as_str());
    for other in disk::names(&overlay)? {
        if other != scope_leaf {
            let other = disk::directory(&overlay, &other, mount)?.ok_or(FOREIGN)?;
            if disk::directory(&other, live, mount)?.is_some() {
                return Err(AMBIGUOUS);
            }
        }
    }
    let parent = disk::directory(&overlay, scope_leaf, mount)?.ok_or(MISSING)?;
    let archived = claim.and_then(|c| c.archive.as_ref());
    let archive_leaf = archived.map(|a| a.leaf(false));
    let source = archive_leaf.as_deref().map_or(live, OsStr::new);
    if archived.is_some() && disk::directory(&parent, live, mount)?.is_some() {
        return Err(COLLISION);
    }
    let area = disk::directory(&parent, source, mount)?.ok_or(if claim.is_some() {
        AMBIGUOUS
    } else {
        MISSING
    })?;
    let acknowledged = match &action {
        Action::Discard(tuple) => *tuple,
        Action::Reconcile(tuple, _) => {
            let intent = claim.and_then(|c| c.intent.as_ref()).ok_or(NOT_ELIGIBLE)?;
            if *tuple != (intent.writer, intent.incarnation) {
                return Err(CHANGED);
            }
            if archived.is_none() {
                return Err(Refusal::Pending);
            }
            Some(*tuple)
        }
    };
    let publications = disk::directory(&root, OsStr::new("publications"), mount)?;
    let publication_scope = publications
        .as_ref()
        .map(|p| disk::directory(p, scope_leaf, mount))
        .transpose()?
        .flatten();
    let selection = Selection {
        overlay,
        scope: parent,
        area,
        publications,
        publication_scope,
        mount,
    };
    let existing_intent = claim
        .and_then(|c| c.intent.as_ref())
        .map(|intent| -> Result<File, Refusal> {
            let file = disk::at(
                &selection.scope,
                OsStr::new(&intent.leaf(true)),
                OFlag::empty(),
            )
            .map_err(|_| FOREIGN)?;
            disk::check_intent(&file, mount)?;
            Ok(file)
        })
        .transpose()?;
    let initial = selection.read(&scope_text, volume, None)?;
    let (tree, published, writer, eligible) = &initial;
    if claim.is_none() && !eligible {
        return Err(NOT_ELIGIBLE);
    }
    let incarnation = incarnation(
        path.as_os_str().as_bytes(),
        &scope,
        volume,
        writer,
        &tree.entries,
        &published.entries,
    )
    .map_err(|_| FOREIGN)?;
    let name = DiscardName {
        volume: volume.clone(),
        writer: *writer,
        incarnation,
    };
    if claim
        .and_then(|c| c.intent.as_ref())
        .is_some_and(|intent| intent != &name)
        || acknowledged.is_some_and(|tuple| tuple != (*writer, incarnation))
    {
        return Err(CHANGED);
    }
    let mut row = Row {
        scope,
        name,
        bytes: tree.bytes,
        outcome: match (claim, archived) {
            (_, Some(_)) => Outcome::Archived(tree.files),
            (Some(_), None) => Outcome::Pending(tree.files),
            (None, None) => Outcome::Live(tree.files),
        },
    };
    verify_root(false)?;
    selection.rebound(&root, scope_leaf, source)?;
    if let Action::Reconcile(_, read) = action {
        read(&selection, tree, published)?;
        return Ok(row);
    }
    if acknowledged.is_none() {
        return Ok(row);
    }

    if selection.read(&scope_text, volume, Some(step))? != initial {
        return Err(CHANGED);
    }
    sync(step, "store root", &root)?;
    if selection.read(&scope_text, volume, None)? != initial {
        return Err(CHANGED);
    }
    selection.rebound(&root, scope_leaf, source)?;
    let intent_name = row.name.leaf(true);
    let intent_leaf = OsStr::new(&intent_name);
    let intent = if let Some(existing) = existing_intent {
        verify_root(false)?;
        existing
    } else {
        durable(step, "intent create", || {
            verify_root(false)?;
            disk::at(
                &selection.scope,
                intent_leaf,
                OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
            )
            .map_err(|e| move_error(&e))
        })?
    };
    disk::check_intent(&intent, mount)?;
    sync(step, "intent file", &intent)?;
    sync(step, "intent scope", &selection.scope)?;

    let archive_name = row.name.leaf(false);
    let target = OsStr::new(&archive_name);
    let verify_intent = |after_move| -> Result<(), disk::Error> {
        let named = disk::at(&selection.scope, intent_leaf, OFlag::empty()).map_err(|error| {
            match disk::Error::open(&error, CHANGED) {
                disk::Error::Io => binding_io(after_move)(error),
                refused @ disk::Error::Refused(_) => refused,
            }
        })?;
        if disk::identity(&named).map_err(binding_io(after_move))?
            != disk::identity(&intent).map_err(binding_io(after_move))?
        {
            return Err(CHANGED.into());
        }
        disk::check_intent(&named, mount)
    };
    if archived.is_none() {
        let from = CString::new(live.as_bytes()).map_err(|_| FOREIGN)?;
        let to = CString::new(target.as_bytes()).map_err(|_| FOREIGN)?;
        durable(step, "rename", || {
            verify_root(false)?;
            selection.rebound(&root, scope_leaf, source)?;
            verify_intent(false)?;
            rename(&selection.scope, &from, &to).map_err(|error| match error.raw_os_error() {
                Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP) => UNSUPPORTED,
                _ => move_error(&error),
            })
        })?;
    }
    let moved = disk::directory(&selection.scope, target, mount)
        .map_err(disk::Error::after_move)?
        .ok_or(DURABILITY)?;
    if disk::identity(&moved).map_err(|_| DURABILITY)?
        != disk::identity(&selection.area).map_err(|_| DURABILITY)?
    {
        return Err(CHANGED);
    }
    selection
        .rebound(&root, scope_leaf, target)
        .map_err(disk::Error::after_move)?;
    if disk::directory(&selection.scope, live, mount)
        .map_err(disk::Error::after_move)?
        .is_some()
    {
        return Err(COLLISION);
    }
    sync(step, "archive", &moved)?;
    sync(step, "archive scope", &selection.scope)?;
    verify_root(true).map_err(disk::Error::after_move)?;
    selection
        .rebound(&root, scope_leaf, target)
        .map_err(disk::Error::after_move)?;
    verify_intent(true).map_err(disk::Error::after_move)?;
    if selection
        .read(&scope_text, volume, None)
        .map_err(disk::Error::after_move)?
        != initial
    {
        return Err(CHANGED);
    }
    row.outcome = if archived.is_some() {
        Outcome::AlreadyArchived
    } else {
        Outcome::Moved
    };
    Ok(row)
}

fn move_error(error: &io::Error) -> Refusal {
    if error.kind() == io::ErrorKind::AlreadyExists {
        COLLISION
    } else {
        DURABILITY
    }
}

#[cfg(test)]
pub(crate) mod tests;
