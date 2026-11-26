// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A process incarnation: one complete secure draw, shared without mutation.

use std::sync::Arc;

use granary_core::debug_grant::Incarnation;
use granary_core::secure_random::{EntropyUnavailable, SecureRandom};

/// The immutable marker shared by serving clones and the grant reader.
#[derive(Clone, Debug)]
pub(crate) struct ServerIncarnation(Arc<Incarnation>);

impl ServerIncarnation {
    /// Draw all sixteen bytes. A failed fill is discarded and returned.
    pub(crate) fn draw(random: &mut dyn SecureRandom) -> Result<Self, EntropyUnavailable> {
        let mut bytes = [0; 16];
        random.fill(&mut bytes)?;
        Ok(Self(Arc::new(Incarnation::from_bytes(bytes))))
    }

    pub(crate) fn value(&self) -> Incarnation {
        *self.0
    }
}

impl std::fmt::Display for ServerIncarnation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("incarnation:")?;
        for byte in self.0.as_bytes() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
