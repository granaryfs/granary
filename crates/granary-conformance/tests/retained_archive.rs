// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
use granary_core::{retained_archive::ArchiveName, root::VolumeName};
use proptest::prelude::*;
proptest! {
    #[test]
    fn archive_name_round_trip(volume in "[a-z0-9][a-z0-9-]{0,61}[a-z0-9]", id in any::<[u8;16]>(), settled in any::<bool>()) {
        let name = ArchiveName { settled, volume: VolumeName::from_bytes(volume.as_bytes()).unwrap(), publication_id: id };
        let encoded = name.file_name();
        prop_assert_eq!(ArchiveName::parse(encoded.as_bytes()), Ok(Some(name)));
    }
    #[test]
    fn archive_name_canonical_or_refused(bytes in prop::collection::vec(any::<u8>(),0..4096)) {
        if let Ok(Some(name)) = ArchiveName::parse(&bytes) {
            let encoded = name.file_name();
            prop_assert_eq!(encoded.as_bytes(), bytes);
        }
    }
}
