// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Claim discovery for ordinary opens and offline discard selection.

use super::{AMBIGUOUS, COLLISION, FOREIGN, Refusal, disk};
use crate::{OverlayError, OverlayIo};
use granary_core::{
    overlay_discard::DiscardName, retained_archive::is_scope_digest, root::VolumeName,
};
use nix::fcntl::OFlag;
use std::{collections::BTreeMap, fs::File, io::ErrorKind, path::Path};

#[derive(Debug, Default)]
pub(crate) struct Claim {
    pub scope: String,
    pub intent: Option<DiscardName>,
    pub archive: Option<DiscardName>,
}

pub(crate) fn scan(
    io: &mut impl OverlayIo,
    root: &Path,
) -> Result<BTreeMap<VolumeName, Claim>, OverlayError> {
    let overlay = root.join("overlay");
    let scopes = match io.entries(&overlay) {
        Ok(scopes) => scopes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(_) => return Err(OverlayError::refused(FOREIGN.as_str())),
    };
    let mut claims = Claims::default();
    for scope in scopes {
        if !is_scope_digest(scope.as_bytes()) {
            return Err(OverlayError::refused(FOREIGN.as_str()));
        }
        let directory = overlay.join(&scope);
        for leaf in io
            .entries(&directory)
            .map_err(|_| OverlayError::refused(FOREIGN.as_str()))?
        {
            claims
                .record(&scope, leaf.as_bytes(), |intent| {
                    let path = directory.join(&leaf);
                    if intent {
                        matches!(io.length(&path), Ok(Some(0)))
                            .then_some(())
                            .ok_or(FOREIGN)
                    } else {
                        io.directory(&path).map_err(|_| COLLISION)
                    }
                })
                .map_err(|reason| OverlayError::refused(reason.as_str()))?;
        }
    }
    claims
        .finish()
        .map_err(|reason| OverlayError::refused(reason.as_str()))
}

pub(super) fn scan_locked(
    overlay: &File,
    mount: u64,
) -> Result<BTreeMap<VolumeName, Claim>, Refusal> {
    let mut claims = Claims::default();
    for scope in disk::names(overlay).map_err(disk::Error::refusal)? {
        let scope_text = scope
            .to_str()
            .filter(|name| is_scope_digest(name.as_bytes()))
            .ok_or(FOREIGN)?;
        let directory = disk::directory(overlay, &scope, mount)
            .map_err(disk::Error::refusal)?
            .ok_or(FOREIGN)?;
        for leaf in disk::names(&directory).map_err(disk::Error::refusal)? {
            claims.record(
                scope_text,
                leaf.to_str().ok_or(FOREIGN)?.as_bytes(),
                |intent| {
                    if intent {
                        let file =
                            disk::at(&directory, &leaf, OFlag::empty()).map_err(|_| FOREIGN)?;
                        disk::check_intent(&file, mount).map_err(disk::Error::refusal)
                    } else {
                        let dir = disk::at(&directory, &leaf, OFlag::O_DIRECTORY)
                            .map_err(|_| COLLISION)?;
                        disk::protected(&dir, mount, true).map_err(disk::Error::refusal)?;
                        Ok(())
                    }
                },
            )?;
        }
    }
    claims.finish()
}

#[derive(Default)]
struct Claims(BTreeMap<VolumeName, Claim>);

impl Claims {
    fn record(
        &mut self,
        scope: &str,
        leaf: &[u8],
        check: impl FnOnce(bool) -> Result<(), Refusal>,
    ) -> Result<(), Refusal> {
        let Some((name, intent)) = DiscardName::parse(leaf).map_err(|_| FOREIGN)? else {
            return Ok(());
        };
        let claim = self.0.entry(name.volume.clone()).or_default();
        if !claim.scope.is_empty() && claim.scope != scope {
            return Err(AMBIGUOUS);
        }
        scope.clone_into(&mut claim.scope);
        check(intent)?;
        let slot = if intent {
            &mut claim.intent
        } else {
            &mut claim.archive
        };
        if slot.replace(name).is_some() {
            return Err(AMBIGUOUS);
        }
        Ok(())
    }

    fn finish(self) -> Result<BTreeMap<VolumeName, Claim>, Refusal> {
        if self
            .0
            .values()
            .any(|claim| claim.archive.is_some() && claim.archive != claim.intent)
        {
            return Err(AMBIGUOUS);
        }
        Ok(self.0)
    }
}

pub(crate) fn gate(
    io: &mut impl OverlayIo,
    root: &Path,
    volume: &VolumeName,
) -> Result<(), OverlayError> {
    if let Some(claim) = scan(io, root)?.get(volume) {
        return Err(OverlayError::refused(if claim.archive.is_some() {
            "OverlayArchived"
        } else {
            "OverlayDiscardPending"
        }));
    }
    Ok(())
}

pub(crate) fn gate_area(io: &mut impl OverlayIo, area: &Path) -> Result<(), OverlayError> {
    let root = area
        .ancestors()
        .nth(3)
        .ok_or_else(|| OverlayError::refused(FOREIGN.as_str()))?;
    let volume = area
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| VolumeName::from_bytes(name.as_bytes()).ok())
        .ok_or_else(|| OverlayError::refused(FOREIGN.as_str()))?;
    gate(io, root, &volume)
}
