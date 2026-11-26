// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use granary_core::overlay_ownership as codec;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn canonical_ownership_roundtrip(revision in any::<u64>(), high in 0..u64::MAX,
        writer in any::<[u8;16]>(), instance in any::<[u8;16]>()) {
        let mut c = granary_core::testkit::ownership_fixture();
        c.revision = revision; c.allocated = high; c.sent = high;
        c.writer = writer; c.instance = instance;
        let bytes = codec::encode(&c).unwrap();
        prop_assert_eq!(codec::decode(&bytes).unwrap(), c);
        prop_assert_eq!(codec::encode(&codec::decode(&bytes).unwrap()).unwrap(), bytes);
    }
    #[test]
    fn arbitrary_ownership_decode_is_total(bytes in proptest::collection::vec(any::<u8>(), 0..8192)) {
        granary_core::testkit::overlay_ownership_decode_probe(&bytes);
    }
}
