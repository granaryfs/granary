// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::pin` — the pinned SPKI verifier, granary's
//! server-authentication anchor: digest membership in a
//! configured pin set, with no Web PKI chain, no name match, and no
//! clock read.
//!
//! Out-of-line: `granary-net`'s non-test artifact has
//! workspace consumers (`granary-client`,
//! `granary-server`), so the module's own tests move out
//! of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use super::{CHAIN_MAX, is_pin_rejection};
use rustls::{CertificateError, Error};

/// Wrap `error` in `depth` nested [`std::io::Error`] layers — the
/// shape `tokio-rustls`/`hyper-rustls` actually produce, measured at
/// two.
fn wrapped(error: Error, depth: usize) -> std::io::Error {
    let mut out = std::io::Error::new(std::io::ErrorKind::InvalidData, error);
    for _layer in 1..depth {
        out = std::io::Error::new(std::io::ErrorKind::InvalidData, out);
    }
    out
}

/// **The DISCRIMINATION, which the end-to-end rows in
/// `granary-client` cannot make.** Those drive one real handshake
/// each, so they show a pin miss saying so and a refused connection
/// staying quiet — they never present a rustls certificate error
/// that is NOT the pin's. `verify_tls12_signature` and its 1.3
/// sibling delegate to rustls and can fail on their own account, so
/// a predicate matching `InvalidCertificate(_)` would pass every row
/// in this workspace and tell an operator to check their pins when
/// the peer's signature was bad.
#[test]
fn only_the_pin_verifier_s_own_variant_counts_as_a_pin_miss() {
    let miss = Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure);
    assert!(is_pin_rejection(&wrapped(miss.clone(), 2)));
    // The direct arm, for a future layer that stops wrapping.
    assert!(is_pin_rejection(&miss));

    for other in [
        Error::InvalidCertificate(CertificateError::Expired),
        Error::InvalidCertificate(CertificateError::BadSignature),
        Error::InvalidCertificate(CertificateError::UnknownIssuer),
        Error::NoCertificatesPresented,
        Error::DecryptError,
    ] {
        assert!(
            !is_pin_rejection(&wrapped(other.clone(), 2)),
            "{other:?} is not this module's pin rejection"
        );
    }

    // A connect failure with no TLS in it at all — the class the
    // dead-port control drives for real.
    let refused = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    assert!(!is_pin_rejection(&refused));
}

/// The peel and the walk are both BOUNDED, and a chain deeper than
/// the bound answers `false` rather than looping.
///
/// `Error::source` is a trait method whose contract does not forbid
/// a cycle, and this predicate runs on a path where something has
/// already gone wrong — the safe answer to "I could not tell" is the
/// one that claims nothing.
#[test]
fn a_chain_deeper_than_the_bound_is_not_diagnosed() {
    let miss = Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure);
    assert!(is_pin_rejection(&wrapped(miss.clone(), CHAIN_MAX)));
    assert!(!is_pin_rejection(&wrapped(miss, CHAIN_MAX + 2)));
}
