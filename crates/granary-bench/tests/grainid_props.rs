// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! `GrainId` encoder/decoder properties (standards rule 15: round-trip +
//! no-panic for every decoder).

use granary_core::hash::{GRAIN_ID_BINARY_LEN, GrainId, HashAlgorithm};
use proptest::prelude::*;

proptest! {
    #[test]
    fn text_roundtrip(digest in any::<[u8; 32]>()) {
        let id = GrainId::from_parts(HashAlgorithm::Blake3, digest);
        prop_assert_eq!(id.to_string().parse::<GrainId>(), Ok(id));
    }

    #[test]
    fn binary_roundtrip(digest in any::<[u8; 32]>()) {
        let id = GrainId::from_parts(HashAlgorithm::Blake3, digest);
        prop_assert_eq!(GrainId::from_bytes(&id.to_bytes()), Ok(id));
    }

    /// Arbitrary bytes: decode never panics; only well-formed 33-byte
    /// 0x01-tagged buffers succeed, and success implies canonical
    /// re-encode.
    #[test]
    fn binary_decode_total(bytes in proptest::collection::vec(any::<u8>(), 0..=64)) {
        if let Ok(id) = GrainId::from_bytes(&bytes) {
            prop_assert_eq!(bytes.len(), GRAIN_ID_BINARY_LEN);
            prop_assert_eq!(bytes.first().copied(), Some(0x01));
            let encoded = id.to_bytes();
            prop_assert_eq!(encoded.as_slice(), bytes.as_slice());
        } else {
            let well_formed =
                bytes.len() == GRAIN_ID_BINARY_LEN && bytes.first() == Some(&0x01);
            prop_assert!(!well_formed, "well-formed buffer rejected");
        }
    }

    /// Arbitrary strings: parse never panics.
    #[test]
    fn text_parse_total(s in "\\PC*") {
        let _ = s.parse::<GrainId>();
    }
}
