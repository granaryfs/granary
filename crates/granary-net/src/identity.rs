// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The connection's client identity: what the TLS handshake established
//! about the client, bound once per connection and handed to every request
//! on it.
//!
//! The accept loop reads the verified peer certificates right after the
//! handshake and before the stream reaches hyper. A connection with none is
//! [`ConnectionIdentity::Anonymous`]. One with a chain is
//! [`ConnectionIdentity::Verified`], carrying the end entity's client-SPKI
//! digest in the enrollment domain ([`ClientSpkiDigest::from_spki_der`] over
//! the complete DER `SubjectPublicKeyInfo`), which is what the enrollment set
//! is keyed by. A chain that is present but cannot be read fails the
//! connection: it is never served as anonymous.
//!
//! The identity is the only thing kept. Which principal and tenant the
//! digest is enrolled to, or whether it is enrolled at all, is looked up per
//! write by the server, never
//! cached on the connection.
//!
//! The identity reaches a request as a value in its extensions, inserted by
//! the accept loop's service wrapper on both the HTTP/1.1 and the HTTP/2
//! leg. A request with no [`ConnectionIdentity`] in its extensions did not
//! come through that wrapper, and a reader treats it as having no principal.

use granary_core::enrollment::ClientSpkiDigest;
use hyper::Request;
use hyper::service::Service;
use rustls::pki_types::CertificateDer;
use rustls::server::ParsedCertificate;

/// What the TLS handshake established about the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionIdentity {
    /// The client presented no certificate.
    Anonymous,
    /// The client presented a certificate chain that verified in this
    /// handshake, and this is its end entity's client-SPKI digest.
    Verified(ClientSpkiDigest),
}

/// Why a connection's peer certificates did not yield an identity.
#[derive(Debug)]
pub enum IdentityError {
    /// rustls reported a peer chain with no certificate in it.
    EmptyChain,
    /// The end-entity certificate does not parse.
    Unparseable(rustls::Error),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyChain => f.write_str("the peer certificate chain is empty"),
            Self::Unparseable(error) => {
                write!(
                    f,
                    "the peer's end-entity certificate does not parse: {error}"
                )
            }
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::EmptyChain => None,
            Self::Unparseable(error) => Some(error),
        }
    }
}

impl ConnectionIdentity {
    /// The identity of a connection whose verified peer certificates are
    /// `chain`, as rustls's `peer_certificates` reports them: `None` when
    /// the client presented none, the end entity first otherwise.
    ///
    /// # Errors
    ///
    /// [`IdentityError`] when the chain is present but empty or its end
    /// entity does not parse. The connection must then be closed, not
    /// served as anonymous.
    pub fn from_peer_certificates(
        chain: Option<&[CertificateDer<'_>]>,
    ) -> Result<Self, IdentityError> {
        let Some(chain) = chain else {
            return Ok(Self::Anonymous);
        };
        let end_entity = chain.first().ok_or(IdentityError::EmptyChain)?;
        client_spki_digest(end_entity)
            .map(Self::Verified)
            .map_err(IdentityError::Unparseable)
    }
}

/// The enrollment digest of `certificate`: [`ClientSpkiDigest`] over its
/// full `SubjectPublicKeyInfo`. The one derivation both sides use: the
/// handshake, for the connection's identity, and the enrollment verbs, for
/// the credential they enrol. A key renewed into a new certificate keeps
/// its digest; a new key does not.
///
/// # Errors
///
/// The parse error when `certificate` is not an X.509 certificate.
pub fn client_spki_digest(
    certificate: &CertificateDer<'_>,
) -> Result<ClientSpkiDigest, rustls::Error> {
    let parsed = ParsedCertificate::try_from(certificate)?;
    Ok(ClientSpkiDigest::from_spki_der(
        parsed.subject_public_key_info().as_ref(),
    ))
}

/// A connection's service: inserts the connection's identity into every
/// request's extensions, then delegates.
///
/// One per connection, built after the handshake; the identity is fixed for
/// the connection's life. An identity already in a request's extensions is
/// replaced.
#[derive(Debug, Clone)]
pub(crate) struct Identified<S> {
    identity: ConnectionIdentity,
    inner: S,
}

impl<S> Identified<S> {
    pub(crate) const fn new(identity: ConnectionIdentity, inner: S) -> Self {
        Self { identity, inner }
    }
}

impl<S, B> Service<Request<B>> for Identified<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn call(&self, mut request: Request<B>) -> Self::Future {
        request.extensions_mut().insert(self.identity);
        self.inner.call(request)
    }
}
