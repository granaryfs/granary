// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0
#![no_main]
// The banned call is `libfuzzer_sys`'s, not this crate's:
// `fuzz_target!` expands to a body that opens
// `$RUST_LIBFUZZER_DEBUG_PATH` with `std::fs::File::create` to dump the
// input being replayed. The fs ban reaches it because the nested
// `crates/granary-client/clippy.toml` is the nearest clippy config for
// this crate too.
//
// FILE-SCOPED because the narrow form does not exist here, measured
// rather than assumed: an `#[expect]` on the `fuzz_target!` INVOCATION
// is discarded by rustc — "the built-in attribute `expect` will be
// ignored, since it's applied to the macro invocation" — and the lint
// fires on that invocation's span, so there is no inner item to put it
// on. The cost is stated plainly: this licence covers the whole file,
// so an fs call added to this target later would be silently licensed.
// The file is this attribute, one `use`, and one call into a pure
// decode probe; a target that needs to touch the filesystem does not
// belong in it.
#![expect(
    clippy::disallowed_methods,
    reason = "the std::fs::File::create is inside libfuzzer_sys::fuzz_target!'s expansion (its \
              RUST_LIBFUZZER_DEBUG_PATH input dump), where no narrower attribute is honoured; \
              the probe body below is a pure decode and touches no filesystem"
)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    granary_client::fuzz_probe::anchor_decode_probe(data);
});
