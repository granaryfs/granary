// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    granary_core::testkit::overlay_journal_decode_probe(data);
    if let Ok(file) = granary_core::overlay_journal::ResidualFile::decode(data) {
        assert_eq!(file.encode().as_deref(), Ok(data));
    }
});
