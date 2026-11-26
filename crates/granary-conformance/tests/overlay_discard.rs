// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use granary_core::{
    overlay_discard::{DiscardName, Outcome, Row},
    root::VolumeName,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn discard_round_trips(
        scope in any::<[u8; 32]>(), writer in any::<[u8; 16]>(),
        incarnation in any::<[u8; 32]>(), volume in "[a-z][a-z0-9]{0,62}",
        bytes in any::<u64>(), files in any::<u64>(), intent in any::<bool>(),
    ) {
        let name = DiscardName { volume: VolumeName::from_bytes(volume.as_bytes()).unwrap(), writer, incarnation };
        prop_assert_eq!(DiscardName::parse(name.leaf(intent).as_bytes()), Ok(Some((name.clone(), intent))));
        for outcome in [Outcome::Live(files), Outcome::Pending(files), Outcome::Archived(files),
                        Outcome::Moved, Outcome::AlreadyArchived] {
            let row = Row { scope, name: name.clone(), bytes, outcome };
            prop_assert_eq!(Row::parse(row.to_string().as_bytes()), Ok(row));
        }
    }
}
