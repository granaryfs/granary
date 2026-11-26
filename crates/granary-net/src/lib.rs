// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! HTTP transport plumbing for the grain protocol: TLS config (both
//! sides). Phase 1 speaks HTTP semantics over TCP — HTTP/1.1 is the
//! mandatory baseline and h2 is offered alongside it via ALPN, with no
//! protocol feature depending on an h2-only mechanism; any later h3
//! transport would use the same seam, and the adoption gate for it was
//! evaluated at the Phase-1 exit and did NOT pass, so TCP carries on.
//! It also holds the cryptographic-randomness seam's production
//! implementation, because aws-lc, its generator's source, is already
//! this crate's TLS backend and both binaries link it.

// `disallowed_types` is `allow` on the workspace line. This crate opts in
// because it is where the operating system's generator is constructed:
// `clippy.toml` bans that type everywhere but `secure_random`'s one
// `#[expect]`, and a ban the root does not deny would be configured and
// never enforced.
#![deny(clippy::disallowed_types)]

pub mod accept;
pub mod alpn;
pub mod b64;
pub mod config;
pub mod credential;
pub mod identity;
pub mod metrics_listener;
pub mod pin;
mod preface;
pub mod secure_random;
pub mod tls;

/// The process-wide TLS provider: aws-lc-rs, always.
#[must_use]
pub fn crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

#[cfg(test)]
mod tests;
