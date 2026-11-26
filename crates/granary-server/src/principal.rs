// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrolled principals for writes and the intent control read, resolved per
//! authenticated request from its connection's identity and current enrollment.
//!
//! The connection's identity is what its TLS handshake verified, put in
//! every request's extensions by the accept loop
//! ([`granary_net::identity::ConnectionIdentity`]). It is the only thing
//! the connection keeps: [`resolve_write_principal`] looks the digest up in
//! the enrollment set on every call, through [`EnrollmentReader::lookup`],
//! which answers from a refresh that began after the call arrived. Nothing
//! here caches an answer, positive or negative, so a revocation that has
//! returned is seen by the next authenticated request on every connection, each HTTP/2
//! stream on its own.
//!
//! | identity / lookup | answer |
//! |---|---|
//! | none in the extensions, or anonymous | `403` + `no-principal`; the set is not consulted |
//! | verified, enrolled | the principal and its tenant |
//! | verified, absent | `403` + `not-enrolled` |
//! | verified, unavailable | `503` + `enrollment-unavailable`, no `Retry-After` |
//!
//! A request with no identity in its extensions did not come through the
//! accept loop's wrapper; it has no principal, and is never taken for a
//! server without an authority.
//!
//! Writes and the principal-scoped intent control read call this. Other reads
//! are served anonymously whatever their connection's identity, without a lookup.

use granary_core::enrollment::{PrincipalId, TenantName};
use granary_net::identity::ConnectionIdentity;
use hyper::http::Extensions;

use crate::enrollment::{EnrollmentReader, Lookup, UnavailableReason};
use crate::wire::Outcome;

/// Bound enrolled principal for this authenticated request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritePrincipal {
    /// The principal the connection's credential is enrolled to.
    pub principal: PrincipalId,
    /// The principal's tenant.
    pub tenant: TenantName,
}

/// Why an authenticated request bears no principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalRefusal {
    /// The connection is anonymous, or the request carries no identity:
    /// `403` + `no-principal`.
    NoPrincipal,
    /// The connection's credential is not in the set: `403` +
    /// `not-enrolled`.
    NotEnrolled,
    /// The set could not be consulted: `503` + `enrollment-unavailable`,
    /// with no `Retry-After`.
    EnrollmentUnavailable(UnavailableReason),
}

impl PrincipalRefusal {
    /// The answer on the wire.
    #[must_use]
    pub const fn outcome(self) -> Outcome {
        match self {
            Self::NoPrincipal => Outcome::no_principal(),
            Self::NotEnrolled => Outcome::not_enrolled(),
            Self::EnrollmentUnavailable(_) => Outcome::enrollment_unavailable(),
        }
    }
}

/// The request's principal: the identity in `extensions`, looked up in
/// `reader`'s current set (module docs).
///
/// # Errors
///
/// [`PrincipalRefusal`]: no identity or an anonymous one, a credential not
/// enrolled, or a set that could not be consulted.
///
/// # Cancellation safety
///
/// Cancel-safe: the only await is [`EnrollmentReader::lookup`], which is.
pub async fn resolve_write_principal(
    extensions: &Extensions,
    reader: &EnrollmentReader,
) -> Result<WritePrincipal, PrincipalRefusal> {
    let Some(ConnectionIdentity::Verified(digest)) = extensions.get::<ConnectionIdentity>() else {
        return Err(PrincipalRefusal::NoPrincipal);
    };
    match reader.lookup(digest).await {
        Lookup::Enrolled { principal, tenant } => Ok(WritePrincipal { principal, tenant }),
        Lookup::Absent => Err(PrincipalRefusal::NotEnrolled),
        Lookup::Unavailable(reason) => Err(PrincipalRefusal::EnrollmentUnavailable(reason)),
    }
}

#[cfg(test)]
mod tests;
