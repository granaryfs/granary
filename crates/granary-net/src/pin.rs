// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The pinned SPKI verifier — granary's server-authentication anchor.
//!
//! A client trusts a server because the SHA-256 digest of its
//! certificate's DER `SubjectPublicKeyInfo` is a member of a configured pin
//! set. The Web PKI plays no part: no chain is built, no intermediate is
//! consulted, no name is matched, and no clock is read.
//!
//! **Digests only, no rendering.** The configuration distinguishes
//! `sha256/`-base64 TLS pins, `ed25519:`-hex root-signing public keys, and
//! `keyid:`-hex key locators. `crate::config::parse_tls_pin` parses TLS pins;
//! `crate::config::parse_signing_key` parses public keys. Each rejects the
//! other forms and unprefixed values, and neither accepts a `keyid:` locator.
//! `GRANARY_TLS_PINS` and `GRANARY_ROOT_KEYS` are distinct configuration
//! names for the TLS and root-signing consumers, respectively.
//! This module works in `[u8; 32]` and renders nothing.
//!
//! **The backup slot is decorative without offline custody.** RFC 7469 §4.3
//! makes a backup pin useful for emergency rotation only if it is
//! pre-generated and its key kept offline. Phase 1 has no rotation
//! mechanism. The set exists because a list costs one line now and a schema
//! break later, not because a fleet needs it — Phase 1 has
//! no fleet.

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{CertificateError, DigitallySignedStruct, Error, SignatureScheme};

/// Width of an [`SpkiPin`]: SHA-256's output, in bytes.
pub const PIN_LEN: usize = 32;

/// A SHA-256 digest of a DER-encoded `SubjectPublicKeyInfo` (RFC 7469 §2.4).
pub type SpkiPin = [u8; PIN_LEN];

/// The largest pin set [`PinnedServerVerifier::new`] accepts.
///
/// The cap is here to make the domain finite, which is the only way a test
/// suite can close it. Every membership property written over "arbitrary
/// cardinality" is bounded somewhere, and an implementation that accepts
/// unconditionally one cardinality above that bound passes the property.
/// Eight is ample for RFC 7469's model — one primary plus a pre-generated
/// backup — and raising the cap later is a smaller break than shipping a
/// surface no finite test can cover.
pub const PIN_SET_MAX: usize = 8;

/// Why a pin set was refused at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSetError {
    /// More than [`PIN_SET_MAX`] pins were supplied.
    TooManyPins {
        /// How many pins the caller supplied.
        got: usize,
    },
    /// The all-zero digest was supplied as a pin.
    ///
    /// It is not a plausible SHA-256 of any `SubjectPublicKeyInfo` anyone
    /// holds, and it is exactly what an unset, zeroed configuration field
    /// looks like — so accepting it is how a fail-open default reaches
    /// production.
    ZeroPin,
}

impl fmt::Display for PinSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooManyPins { got } => {
                write!(f, "pin set has {got} entries, more than {PIN_SET_MAX}")
            }
            Self::ZeroPin => f.write_str("pin set contains the all-zero digest"),
        }
    }
}

impl std::error::Error for PinSetError {}

/// SHA-256 over the certificate's DER `SubjectPublicKeyInfo`.
///
/// This is RFC 7469 §2.4's digest domain — "the DER-encoded ASN.1
/// representation of the Subject Public Key Info" — which includes the
/// outer SEQUENCE tag and length and the `AlgorithmIdentifier`. Two other
/// stable 32-byte key-derived digests are wrong here in ways no
/// self-consistent test suite notices: hashing the `subjectPublicKey` BIT
/// STRING alone refuses every pin an operator generates with standard
/// tooling, and hashing the whole certificate refuses the renewed
/// certificate of an unrotated key — the flag-day SPKI pinning exists to
/// avoid.
///
/// # Errors
///
/// [`Error::InvalidCertificate`] if `cert` does not parse.
pub fn spki_digest(cert: &CertificateDer<'_>) -> Result<SpkiPin, Error> {
    let parsed = ParsedCertificate::try_from(cert)?;
    let spki = parsed.subject_public_key_info();
    let raw = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, spki.as_ref());
    // SHA-256 is 32 bytes wide by definition; the fallible conversion keeps
    // the no-panic rule absolute rather than resting on that.
    let Ok(pin) = SpkiPin::try_from(raw.as_ref()) else {
        return Err(Error::General("sha-256 digest is not 32 bytes".into()));
    };
    Ok(pin)
}

/// A [`ServerCertVerifier`] that anchors trust in a set of SPKI pins.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    pins: Vec<SpkiPin>,
    provider: Arc<CryptoProvider>,
}

impl PinnedServerVerifier {
    /// Build a verifier over `pins`, using `provider` for signature
    /// verification.
    ///
    /// An **empty** set is legal and refuses every certificate: "not
    /// configured yet" must never mean "accept anything".
    ///
    /// # Errors
    ///
    /// [`PinSetError::TooManyPins`] above [`PIN_SET_MAX`], and
    /// [`PinSetError::ZeroPin`] if any entry is the all-zero digest. Both
    /// are configuration errors by design — refusing them here is what
    /// keeps an over-large set from becoming an untestable surface and a
    /// zeroed default from becoming a fail-open sentinel.
    pub fn new(pins: Vec<SpkiPin>, provider: Arc<CryptoProvider>) -> Result<Self, PinSetError> {
        if pins.len() > PIN_SET_MAX {
            return Err(PinSetError::TooManyPins { got: pins.len() });
        }
        if pins.contains(&[0u8; PIN_LEN]) {
            return Err(PinSetError::ZeroPin);
        }
        Ok(Self { pins, provider })
    }

    /// Is `digest` a member of the pin set?
    ///
    /// One call, deliberately: any branch on pin value, set size or digest
    /// content beyond `contains` is a defect a reader can see, and for a
    /// predicate over a 256-bit domain reading is the only exhaustive
    /// review there is. Both operands are public — the certificate is
    /// broadcast in every handshake and the pin is configuration — so a
    /// variable-time comparison leaks nothing that is not already on the
    /// wire.
    #[must_use]
    pub fn is_pinned(&self, digest: &SpkiPin) -> bool {
        self.pins.contains(digest)
    }
}

/// How many links of a `source()` chain [`is_pin_rejection`] will walk,
/// and how many nested [`std::io::Error`] wrappers it will peel.
///
/// A bound rather than a `while let`, because `Error::source` is a trait
/// method and nothing in its contract forbids a cycle — an implementation
/// that returned `Some(self)` would hang the caller's error path forever.
/// The measured chain is three links deep at its longest and one peel
/// deep, so this is two orders of margin over anything the shipped
/// connector produces.
const CHAIN_MAX: usize = 16;

/// The `rustls::Error` a link of an error chain IS, peeling any
/// [`std::io::Error`] wrappers around it.
///
/// **The peel is the whole reason this function exists, and it was
/// measured rather than assumed.** `std::io::Error`'s own
/// `Error::source` returns `c.error.source()` — its inner error's
/// SOURCE, skipping the inner error itself — so walking `source()` alone
/// never yields the `rustls::Error` at all: the walk sees the
/// `io::Error` (whose `Display` forwards the rustls text) and then ends,
/// because `rustls::Error::source` is `None`. `get_ref` is what reaches
/// past that, and the shipped connector nests TWO `io::Error` layers
/// around the rustls one, which is why the peel loops.
fn as_rustls<'link>(link: &'link (dyn std::error::Error + 'static)) -> Option<&'link Error> {
    if let Some(direct) = link.downcast_ref::<Error>() {
        return Some(direct);
    }
    let mut inner = link.downcast_ref::<std::io::Error>()?.get_ref()?;
    for _peel in 0..CHAIN_MAX {
        if let Some(tls) = inner.downcast_ref::<Error>() {
            return Some(tls);
        }
        inner = inner.downcast_ref::<std::io::Error>()?.get_ref()?;
    }
    None
}

/// Does `error`'s chain bottom out in THIS module's pin rejection?
///
/// **The answer is DEFINITE and not a heuristic, for one reason that
/// belongs here rather than at the caller: rustls never produces
/// [`CertificateError::ApplicationVerificationFailure`] itself.** Its
/// whole crate holds three occurrences — the enum definition, the alert
/// mapping (`AccessDenied`) and one test — so the variant exists for a
/// custom [`ServerCertVerifier`] to return and for nothing else.
/// [`PinnedServerVerifier::verify_server_cert`] above returns it on a pin
/// miss and on no other path, and a granary client installs that verifier
/// and no other ([`crate::tls::client_tls_config`] takes exactly one).
/// So on a granary client connection the variant means a pin miss, full
/// stop.
///
/// **What it must NOT be used to claim.** A connect failure is
/// `is_connect() == true` for seven distinct classes —
/// a wrong pin, a refused connection, a DNS failure, a TLS version
/// mismatch, a peer closing mid-handshake, a non-TLS peer, a
/// stock-verifier rejection — and a stalled handshake produces no error
/// object at all. This predicate answers the first and says nothing
/// about the other six: `false` means "not a pin miss, or not
/// determinable", never "some other named thing".
///
/// **Typed, never a string match.** The `Display` text
/// (`invalid peer certificate: ApplicationVerificationFailure`) is
/// reachable and would have been easier; it is also a rustls rendering
/// this crate does not own, free to change in a patch release, and a
/// substring an attacker-supplied error text could contain. The variant
/// is the fact.
#[must_use]
pub fn is_pin_rejection(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut link = Some(error);
    for _depth in 0..CHAIN_MAX {
        let Some(current) = link else { return false };
        if matches!(
            as_rustls(current),
            Some(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure
            ))
        ) {
            return true;
        }
        link = current.source();
    }
    false
}

impl ServerCertVerifier for PinnedServerVerifier {
    /// The pin replaces the Web PKI chain outright: `intermediates`,
    /// `server_name` and `ocsp_response` are not consulted because the
    /// pinned key *is* the identity, and `now` is deliberately unread —
    /// nothing in a pin-only path consults expiry, which is what keeps the
    /// `Clock` seam out of this path. A pinned server whose certificate
    /// has expired still authenticates; expiry is an assertion by a CA and
    /// there is no CA here.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let digest = spki_digest(end_entity)?;
        if self.is_pinned(&digest) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    /// Delegated to rustls, never stubbed.
    ///
    /// Returning `HandshakeSignatureValid::assertion()` here would accept a
    /// server that presents the pinned certificate while holding a
    /// different private key. The certificate is public — every client that
    /// connects receives a copy — so "pin matches, signature unchecked" is
    /// impersonation by anyone who has ever seen one handshake.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    /// Delegated to rustls, never stubbed — see
    /// [`Self::verify_tls12_signature`] for what a stub costs.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests;
