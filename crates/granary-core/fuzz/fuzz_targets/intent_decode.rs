// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
#![no_main]
// Probe all six unfrozen intent carriers, requiring byte-exact re-encoding.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    granary_core::testkit::intent_decode_probe(data);
});
