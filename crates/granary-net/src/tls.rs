// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The server TLS configuration, as shipping code builds it.
//!
//! There is one constructor and every caller uses it, which is the point: a
//! per-call-site config is how a server ends up offering a different ALPN set
//! than the one the accept path enforces, and how the TLS-1.3 restriction
//! goes missing from the one config that ships while every test builds its
//! own correct one.
//!
//! The constructor has two modes ([`ClientAuth`]). Without an authority
//! there is no client authentication at all. With one, the server requests
//! a client certificate in every handshake, verifies a presented one against
//! the cell's client CA at the [`Clock`] seam's time, and resumes nothing.
//!
//!
//! Loading keys and certificates from disk is deliberately NOT here. This
//! takes already-parsed DER; the config surface that reads them belongs to
//! the configuration task.

use std::sync::Arc;
use std::time::Duration;

use granary_core::clock::Clock;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{NoServerSessionStorage, VerifierBuilderError, WebPkiClientVerifier};
use rustls::sign::SingleCertAndKey;
use rustls::time_provider::TimeProvider;

use crate::alpn::GRANARY_ALPN;
use crate::credential::ClientCertifiedKey;

/// Whether, and how, the server authenticates its clients.
pub enum ClientAuth {
    /// No client authentication: the handshake requests no client
    /// certificate. A server with no authority configured runs this.
    None,
    /// Optional client authentication against the cell's client CA, for a
    /// server with an authority configured.
    Enrolled {
        /// The cell CA's certificates, each a trust anchor. At least one;
        /// every one must parse.
        ca: Vec<CertificateDer<'static>>,
        /// The clock whose time a presented certificate's validity is
        /// judged at.
        clock: Arc<dyn Clock>,
    },
}

impl std::fmt::Debug for ClientAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Enrolled { ca, .. } => f
                .debug_struct("Enrolled")
                .field("ca_certificates", &ca.len())
                .finish_non_exhaustive(),
        }
    }
}

/// A resumption setting of the [`ClientAuth::Enrolled`] configuration.
/// Each must hold, and each is checked once the configuration is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumptionPin {
    /// The session storage can cache, so a stateful ticket could resume.
    SessionStorage,
    /// The ticketer is enabled, so a stateless ticket could resume.
    Ticketer,
    /// `send_tls13_tickets` is above zero, so tickets would be issued.
    SendTickets,
    /// `max_tls13_tickets` is above zero, so a client's ticket request
    /// could select a ticket count.
    MaxTickets,
    /// `max_early_data_size` is above zero, so 0-RTT data could be
    /// accepted.
    EarlyData,
}

impl ResumptionPin {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SessionStorage => "the session storage can cache",
            Self::Ticketer => "the ticketer is enabled",
            Self::SendTickets => "send_tls13_tickets is above zero",
            Self::MaxTickets => "max_tls13_tickets is above zero",
            Self::EarlyData => "max_early_data_size is above zero",
        }
    }
}

/// Why the server TLS configuration could not be built.
#[derive(Debug)]
pub enum TlsConfigError {
    /// rustls refused the protocol versions, or the certificate chain and
    /// key are not a usable pair.
    Rustls(rustls::Error),
    /// [`ClientAuth::Enrolled`] was given no client CA certificate.
    NoClientCa,
    /// A client CA certificate does not parse as a trust anchor.
    ClientCa {
        /// Its position in the list, from zero.
        index: usize,
        /// rustls's refusal.
        error: rustls::Error,
    },
    /// rustls refused to build the client certificate verifier.
    Verifier(VerifierBuilderError),
    /// A resumption setting is not pinned off.
    Resumption(ResumptionPin),
}

impl std::fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rustls(error) => write!(f, "{error}"),
            Self::NoClientCa => f.write_str("the client ca holds no certificate"),
            Self::ClientCa { index, error } => {
                write!(f, "client ca certificate {index} does not parse: {error}")
            }
            Self::Verifier(error) => write!(f, "client certificate verifier: {error}"),
            Self::Resumption(pin) => write!(f, "resumption is not off: {}", pin.as_str()),
        }
    }
}

impl std::error::Error for TlsConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rustls(error) | Self::ClientCa { error, .. } => Some(error),
            Self::Verifier(error) => Some(error),
            Self::NoClientCa | Self::Resumption(_) => None,
        }
    }
}

impl From<rustls::Error> for TlsConfigError {
    fn from(error: rustls::Error) -> Self {
        Self::Rustls(error)
    }
}

/// rustls's time source, read from the [`Clock`] seam.
///
/// rustls passes the configuration's time to the client certificate
/// verifier, so this is the time a client certificate's validity period is
/// judged at. It reads [`Clock::now`] on every call. A time before the Unix
/// epoch, or one whose nanoseconds are out of range, is `None`: rustls then
/// fails the handshake. Such a time is never clamped, and never replaced by
/// the wall clock.
#[derive(Clone)]
pub struct ClockTime(Arc<dyn Clock>);

impl ClockTime {
    /// A time source reading `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self(clock)
    }
}

impl std::fmt::Debug for ClockTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClockTime")
    }
}

impl TimeProvider for ClockTime {
    fn current_time(&self) -> Option<UnixTime> {
        let now = self.0.now();
        if !now.is_valid() {
            return None;
        }
        let secs = u64::try_from(now.secs).ok()?;
        Some(UnixTime::since_unix_epoch(Duration::new(secs, now.nanos)))
    }
}

/// Build the server-side TLS configuration granary serves with.
///
/// Two properties are not defaults and must be read as deliberate:
///
/// - **TLS 1.3 only.** rustls's `DEFAULT_VERSIONS` is `[TLS13, TLS12]` and
///   its `tls12` feature is on by default, so the *default* config negotiates
///   TLS 1.2 happily. The restriction is applied explicitly, on the
///   explicit-provider builder chain.
/// - **ALPN is populated from [`GRANARY_ALPN`], by iterating the constant.**
///   rustls defaults `alpn_protocols` to EMPTY, and a server that negotiates
///   no ALPN at all still serves HTTP by preface sniffing — so the omission
///   is silent. Building the list from the constant rather than a literal is
///   what keeps the offered set and the admitted set from drifting apart.
///
/// # Client authentication
///
/// With [`ClientAuth::None`] there is none, and no `CertificateRequest` is
/// sent: the server authenticates only itself, to a client holding its SPKI
/// pin, and every application endpoint is available to any peer that can
/// reach the listener.
///
/// With [`ClientAuth::Enrolled`] the server requests a client certificate in
/// every handshake and accepts a handshake with none, whose connection is
/// anonymous. A presented chain is checked by rustls's own
/// `WebPkiClientVerifier`, rooted at the given CA certificates and nothing
/// else:
///
/// - a path to one of those anchors through the presented intermediates;
/// - the validity of the leaf and the intermediates at the time [`ClockTime`]
///   reads from the clock;
/// - the extended key usage: when the extension is present it must include
///   `clientAuth`;
/// - basic constraints, which decide the CA and end-entity roles, path
///   length, name constraints, and unsupported critical extensions;
/// - the `CertificateVerify` signature, the proof of possession of the key.
///
/// **The X.509 `KeyUsage` extension is not examined**, on the leaf or on an
/// intermediate: the pinned webpki ignores it, and no check is added here.
/// Every chain that verifies ends at the operator's own CA, and what a
/// verified certificate is allowed to do is decided by the enrollment set,
/// not by its extensions.
///
/// A chain that fails any check fails the handshake; rustls never demotes
/// it to an anonymous connection. The anchors' own validity, CA flag and
/// self-signature are not checked: the operator is responsible for the CA.
///
/// Nothing resumes: no session cache, no ticketer, no tickets issued even
/// when a client asks for some, and no early data. Each of those settings
/// is checked once the configuration is built, so a reconnect is always a
/// full handshake whose certificate is verified again.
///
/// # Errors
///
/// [`TlsConfigError::Rustls`] if the provider rejects the requested protocol
/// versions, or if the certificate chain and key do not form a usable pair.
/// With [`ClientAuth::Enrolled`], also [`TlsConfigError::NoClientCa`] for an
/// empty CA list, [`TlsConfigError::ClientCa`] for a CA certificate that
/// does not parse (every one is added on its own, and any failure refuses),
/// [`TlsConfigError::Verifier`] if rustls refuses the verifier, and
/// [`TlsConfigError::Resumption`] if a resumption setting is not off.
pub fn server_tls_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_auth: ClientAuth,
) -> Result<rustls::ServerConfig, TlsConfigError> {
    let provider = Arc::new(crate::crypto_provider());
    match client_auth {
        ClientAuth::None => {
            let mut config = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(cert_chain, key)?;
            config.alpn_protocols = granary_alpn();
            Ok(config)
        }
        ClientAuth::Enrolled { ca, clock } => {
            let roots = client_ca_roots(ca)?;
            let verifier =
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                    .allow_unauthenticated()
                    .build()
                    .map_err(TlsConfigError::Verifier)?;
            enrolled_config(provider, cert_chain, key, verifier, clock)
        }
    }
}

fn granary_alpn() -> Vec<Vec<u8>> {
    GRANARY_ALPN.iter().map(|token| token.to_vec()).collect()
}

/// The client CA's trust anchors: each certificate added on its own, any
/// failure refusing, and an empty list refused.
fn client_ca_roots(ca: Vec<CertificateDer<'static>>) -> Result<RootCertStore, TlsConfigError> {
    if ca.is_empty() {
        return Err(TlsConfigError::NoClientCa);
    }
    let mut roots = RootCertStore::empty();
    for (index, certificate) in ca.into_iter().enumerate() {
        roots
            .add(certificate)
            .map_err(|error| TlsConfigError::ClientCa { index, error })?;
    }
    Ok(roots)
}

/// The [`ClientAuth::Enrolled`] configuration over `verifier`.
///
/// Production passes the stock verifier [`server_tls_config`] builds; the
/// unit tests pass one that counts its calls and delegates to it, which is
/// why this is a separate function.
pub(crate) fn enrolled_config(
    provider: Arc<rustls::crypto::CryptoProvider>,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    verifier: Arc<dyn ClientCertVerifier>,
    clock: Arc<dyn Clock>,
) -> Result<rustls::ServerConfig, TlsConfigError> {
    let mut config =
        rustls::ServerConfig::builder_with_details(provider, Arc::new(ClockTime::new(clock)))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, key)?;
    config.alpn_protocols = granary_alpn();
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_tls13_tickets = 0;
    config.max_early_data_size = 0;
    // The ticketer is the builder's, which is disabled; rustls does not
    // export a disabled one to install by name. The check below holds it.
    resumption_is_off(&config).map_err(TlsConfigError::Resumption)?;
    Ok(config)
}

/// Whether every resumption setting of `config` is off: the first one that
/// is not, otherwise.
pub(crate) fn resumption_is_off(config: &rustls::ServerConfig) -> Result<(), ResumptionPin> {
    if config.session_storage.can_cache() {
        return Err(ResumptionPin::SessionStorage);
    }
    if config.ticketer.enabled() {
        return Err(ResumptionPin::Ticketer);
    }
    if config.send_tls13_tickets != 0 {
        return Err(ResumptionPin::SendTickets);
    }
    if config.max_tls13_tickets != 0 {
        return Err(ResumptionPin::MaxTickets);
    }
    if config.max_early_data_size != 0 {
        return Err(ResumptionPin::EarlyData);
    }
    Ok(())
}

/// Build the client-side TLS configuration granary connects with:
/// the configured pin verifier installed, TLS 1.3 only.
///
/// The mirror of [`server_tls_config`] in purpose — one constructor, every
/// caller — and deliberately NOT its mirror in two places, both of which
/// are the natural thing to write and both of which are wrong here:
///
/// - **TLS 1.3 only, on the EXPLICIT-PROVIDER builder chain.** `rustls`'s
///   `DEFAULT_VERSIONS` is `[TLS13, TLS12]` and its `tls12` feature is on
///   by default, so `ClientConfig::builder()` negotiates TLS 1.2 happily.
///   `builder_with_provider(...).with_protocol_versions(&[&TLS13])` is the
///   route taken rather than `builder_with_protocol_versions`, so the
///   provider this workspace uses (aws-lc-rs) and the version
///   restriction are stated in the same expression instead of one of them
///   coming from a process-wide default that some other crate may have
///   installed.
/// - **`alpn_protocols` is left EMPTY, and that is load-bearing.**
///   `hyper_rustls::HttpsConnectorBuilder::with_tls_config` asserts the
///   list is empty and PANICS otherwise — it writes the list itself from
///   the protocols enabled on the builder (`enable_http1().enable_http2()`
///   yields `h2, http/1.1`, the required offer). Populating it here from
///   [`GRANARY_ALPN`], one line from what the server does, aborts the
///   client at construction. The `debug_assert!` states the invariant at
///   the site that must hold it.
///
/// The parameter is the CONCRETE [`crate::pin::PinnedServerVerifier`] and
/// not `Arc<dyn ServerCertVerifier>`: the pin verifier must be
/// installed on the production path, and a `dyn` parameter would let any
/// verifier — including one that accepts everything — satisfy the same
/// signature. The type is the discharge.
///
/// # The client's certificate
///
/// With a `credential`, the configuration answers every
/// `CertificateRequest` with it, whatever CA names the server hints: the
/// server is the pinned one, and a client holds one credential for it. A
/// server with no authority configured sends no `CertificateRequest`, so
/// the same configuration connects to it unchanged. Without a credential,
/// the configuration answers a `CertificateRequest` with an empty
/// certificate list, so against a server with an authority configured its
/// connection is anonymous.
///
/// The credential is installed here, before any connection exists: a
/// connection made without it stays anonymous for its life.
///
/// # Errors
///
/// Returns the rustls error if the provider rejects the requested protocol
/// versions.
pub fn client_tls_config(
    verifier: Arc<crate::pin::PinnedServerVerifier>,
    credential: Option<&ClientCertifiedKey>,
) -> Result<rustls::ClientConfig, rustls::Error> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(crate::crypto_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = match credential {
        Some(credential) => builder.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(
            credential.certified_key(),
        ))),
        None => builder.with_no_client_auth(),
    };
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    debug_assert!(
        config.alpn_protocols.is_empty(),
        "hyper-rustls rewrites this list and panics on a pre-filled one"
    );
    Ok(config)
}

#[cfg(test)]
mod tests;
