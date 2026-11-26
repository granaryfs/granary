// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Effectful adapters around granary-core's pure formats:
//! `codec` (zstd grain frames), `crypto` (Ed25519 root signatures),
//! `backend` (`object_store` bins + `RootStore` CAS, and the no-redirect
//! HTTP client every S3 store is built with). Feature-
//! structured so a future verify-only consumer takes `crypto` without
//! the object-store closure; everything is on by default.

// `disallowed_types` is `allow` on the workspace line. This crate opts in
// because aws-lc is in its graph: `clippy.toml` bans aws-lc's generator
// outside the cryptographic-randomness seam's one sanctioned draw, and a
// ban the root does not deny would be configured and never enforced.
#![deny(clippy::disallowed_types)]

#[cfg(feature = "backend")]
pub mod backend;
// NOT feature-gated, unlike every other module here: `bounds` holds two
// `u64`s derived from granary-core values alone, and gating them behind
// `backend` would make naming a number cost the whole `object_store`
// closure. `backend` re-exports both, so its existing callers are
// unaffected.
pub mod bounds;
#[cfg(feature = "codec")]
pub mod codec;
#[cfg(feature = "crypto")]
pub mod crypto;
// With `backend`, which owns the object_store dependency it plugs into.
#[cfg(feature = "backend")]
pub mod http_client;
// Gated with `codec` for the same reason `verify` below is: the probe's
// whole body is a `verify_bin` call. Test/fuzz instrumentation shipped
// in `src/` and not behind `cfg(test)`, deliberately — an integration
// test and a separate fuzz workspace are two OTHER crates, and neither
// can see a `cfg(test)` item (the `granary_core::testkit` precedent).
// `doc(hidden)` for the same reason granary-core's `testkit` carries it:
// it is instrumentation with no stability promise, and it has no place
// in the crate's published API surface.
#[doc(hidden)]
#[cfg(feature = "codec")]
pub mod fuzz_probe;
// Gated with `codec` and not separately: verification IS decompression
// plus a hash, so a build without the codec has nothing to verify with.
#[cfg(feature = "codec")]
pub mod verify;
