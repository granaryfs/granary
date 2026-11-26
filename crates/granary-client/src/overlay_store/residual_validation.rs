// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Validation of a saved choice against the shared residual inventory.

use super::{OverlayConfig, OverlayIo, Path, codec, inventory};
use crate::{CoordinationError, recovery::ResidualEvidence, sync::refused};

pub(crate) fn validate_residual_sources(
    io: &mut impl OverlayIo,
    area: &Path,
    config: &OverlayConfig,
    evidence: &ResidualEvidence,
    check: impl FnMut() -> Result<(), CoordinationError>,
) -> Result<(), CoordinationError> {
    let inventory = inventory(io, area, config, &evidence.source, check)?;
    if u32::try_from(inventory.collisions.len()).ok() != Some(evidence.disposition.collision_count)
    {
        return Err(refused("RecoveryResidualInventoryCount"));
    }
    if codec::residual_inventory_check(&inventory.collisions)
        .map_err(|_| refused("RecoveryResidualInventoryCheck"))?
        != evidence.disposition.inventory_check
    {
        return Err(refused("RecoveryResidualInventoryCheck"));
    }
    Ok(())
}
