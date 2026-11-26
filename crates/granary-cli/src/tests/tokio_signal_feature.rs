// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A leaf of the crate root's `tests`: a
//! second body of that module's own tests belongs under `tests/<concern>.rs`,
//! never in a second `mod` declaration beside the first in the parent.
//!
//! **Two inner attributes, and both are load-bearing rather than tidy** —
//! the same pair, for the same reason, as
//! `granary-client/src/fsguard/tests/testutil.rs`. Nesting this body under
//! `tests` put it inside `tests.rs`'s file-scoped
//! `#![expect(clippy::disallowed_methods)]`, which it was never under as an
//! inline sibling in `main.rs`: a lint level set by an inner attribute is
//! inherited down the module tree, so the relocation alone WIDENS the
//! licence silently. The `deny` restores the ban for this file without
//! moving `EXPECTED_CLI_LICENSED_SITES` — a `deny` is not a licence, so the
//! scanner does not count it. The file-scoped `cfg(test)` is a
//! shield: a file carrying it cannot reach a production build whatever
//! declares it, which is redundant with the ancestor's gate today and is
//! written anyway.
#![cfg(test)]
#![deny(clippy::disallowed_methods)]

//! The positive control for the workspace `tokio`
//! line's `signal` feature the daemon needs.
//!
//! A feature addition has no gate of its own: `cargo-shear` polices
//! unused DEPENDENCIES, not unused features, so a `signal` that was
//! already active transitively — or one later trimmed back out — would
//! look identical to a working one in every check this repo runs. This
//! test is the difference.
//!
//! **The negative was demonstrated, not assumed.** With `"signal"`
//! removed from the workspace line, this fails to compile:
//! `error[E0433]: ... the item is gated here`. That is also the
//! measurement showing that nothing else in the graph
//! enabled it — the resolved feature set is large (dev-dependencies pull
//! in `fs`, `net`, `rt-multi-thread` and more), so "it appears in
//! `cargo tree`" proves nothing on its own.

/// Names the exact API `gran mount`'s shutdown coordinator needs.
#[test]
fn tokio_signal_unix_is_reachable() {
    let _kind = tokio::signal::unix::SignalKind::terminate();
}
