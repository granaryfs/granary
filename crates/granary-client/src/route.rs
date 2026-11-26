// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Which store `gran publish` writes through.
//!
//! **THROUGH THE SERVER IS THE DEFAULT.** A publish supplies
//! TLS pins — `--pin`, or `GRANARY_TLS_PINS` — and writes through a
//! granary server, which is what makes "the client holds no bucket
//! credentials on the normal path" a property of the shipped binary.
//!
//! **There is no silent fallback.** A publish with neither pins nor the
//! explicit opt-out is a usage error naming BOTH options, and never a
//! quiet drop back to the bucket — a fallback is exactly how the property
//! above stops being true without anyone noticing, and the operator who
//! forgot to set `GRANARY_TLS_PINS` is the person it happens to.
//!
//! **The direct-S3 path survives only behind `--direct-s3`**, kept for the
//! `MinIO` conformance harness and for local development. Supplying pins AND
//! the opt-out asks for two different trust models and is refused: an
//! invocation that quietly picked one would leave an operator believing
//! the wrong thing about which one they got.

use granary_net::config::ENV_TLS_PINS;
use granary_net::pin::SpkiPin;
use granary_store::backend::GranaryStore;
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::{BackoffConfig, ClientOptions, RetryConfig};

use crate::credential::ClientCredential;
use crate::direct_deadline::{
    DIRECT_STORE_BACKOFF_BASE, DIRECT_STORE_INIT_BACKOFF, DIRECT_STORE_MAX_BACKOFF,
    DIRECT_STORE_MAX_RETRIES, DIRECT_STORE_REQUEST_TIMEOUT, DIRECT_STORE_RETRY_BUDGET,
    DirectStoreDeadline,
};
use crate::http_store::{HttpStore, HttpStoreError, check_endpoint_userinfo};
use crate::netid::AmbientNetwork;

/// The access key id, read BY NAME.
pub const ENV_AWS_ACCESS_KEY_ID: &str = "AWS_ACCESS_KEY_ID";
/// The secret access key, read BY NAME.
pub const ENV_AWS_SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";
/// The session token, read BY NAME. Optional.
pub const ENV_AWS_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";
/// The region, read BY NAME.
pub const ENV_AWS_REGION: &str = "AWS_REGION";

/// `object_store`'s own default region.
const DEFAULT_REGION: &str = "us-east-1";

const SCHEME_HTTP: &str = "http://";
const SCHEME_HTTPS: &str = "https://";

/// The store a publish writes through.
#[derive(Debug)]
pub enum PublishRoute {
    /// Through a granary server.
    Server(Box<HttpStore>),
    /// Straight at the bucket, every `RootStore`/`BinStore` call bounded
    /// by `DirectStoreDeadline`'s own flat per-call deadline —
    /// the route the `HttpStore` seam clock cannot reach.
    DirectS3(Box<DirectStoreDeadline<GranaryStore<AmazonS3>>>),
}

/// Why a route could not be opened.
#[derive(Debug)]
pub enum RouteError {
    /// Neither pins nor the opt-out.
    NoTransport,
    /// Both.
    BothTransports,
    /// Pins were supplied, and the set is empty.
    EmptyPins,
    /// `--direct-s3` without a bucket.
    NoBucket,
    /// A server route was given a bucket.
    ServerBucket,
    /// A direct route was given a TLS client credential.
    DirectCredential,
    /// The endpoint could not be used.
    Endpoint(String),
    /// The pinned store refused its configuration.
    Http(HttpStoreError),
    /// `object_store` refused the builder.
    Store(String),
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTransport => write!(
                f,
                "no transport chosen: publish through a granary server with \
                 --pin sha256/... (or {ENV_TLS_PINS}), or opt out to the \
                 bucket with --direct-s3 --bucket <name>"
            ),
            Self::BothTransports => write!(
                f,
                "--pin (or {ENV_TLS_PINS}) and --direct-s3 are two different \
                 trust models; choose one"
            ),
            Self::EmptyPins => write!(
                f,
                "--pin (or {ENV_TLS_PINS}) names no pins: an empty pin set refuses every \
                 certificate, so it names no server to publish through"
            ),
            Self::ServerBucket => f.write_str("a server route may not name a bucket"),
            Self::DirectCredential => {
                f.write_str("a client credential is available only on the server route")
            }
            Self::NoBucket => f.write_str("--direct-s3 needs --bucket <name>"),
            Self::Endpoint(e) => write!(f, "endpoint: {e}"),
            Self::Http(e) => write!(f, "{e}"),
            Self::Store(e) => write!(f, "object store: {e}"),
        }
    }
}

impl std::error::Error for RouteError {}

/// Open the store `gran publish` writes through.
///
/// `pins` present and NON-EMPTY routes through a granary server;
/// `direct_s3` without pins routes at the bucket; neither, both, and a
/// pin set that is present but empty are all usage errors.
///
/// `env` is the environment as a FUNCTION rather than an ambient read, so
/// the credential names this reads are observable from a test — the
/// difference between a configuration this file decides and one the
/// ambient environment decides is the whole point of the builder below,
/// and it is not a claim a test can check if the reads are invisible.
///
/// # Errors
/// [`RouteError`].
pub fn open_publish_route(
    endpoint: &str,
    pins: Option<Vec<SpkiPin>>,
    direct_s3: bool,
    bucket: Option<&str>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<PublishRoute, RouteError> {
    open_publish_route_with_client_credential(endpoint, pins, direct_s3, bucket, None, env)
}

/// Open a route with a checked client credential installed before pool construction.
/// Construction sends no request and the server route performs no environment lookup.
/// The server store retains [`HttpStore::key_file_identity`] for protected harvest.
///
/// # Errors
/// [`RouteError`] for invalid route combinations, endpoints or transport configuration.
pub fn open_publish_route_with_client_credential(
    endpoint: &str,
    pins: Option<Vec<SpkiPin>>,
    direct_s3: bool,
    bucket: Option<&str>,
    credential: Option<ClientCredential>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<PublishRoute, RouteError> {
    if direct_s3 && credential.is_some() {
        return Err(RouteError::DirectCredential);
    }
    // BEFORE the pair below, because an empty set is not "pins supplied"
    // in any useful sense: `parse_pin_set` answers `Ok(vec![])` for a
    // blank list and `PinnedServerVerifier::new` accepts one on purpose
    // ("not configured yet" must never mean "accept anything"), so
    // `Some(vec![])` reaching the Server arm opens the through-the-server
    // route behind a verifier that refuses every certificate. That fails
    // CLOSED — no wrong peer is trusted — but it fails as a handshake
    // error against a route the operator never asked for, which is a
    // diagnosis this refuses to hand out. `gran`'s own parser refuses it
    // at both entry points; this is the same answer for every other
    // caller of the library.
    if pins.as_ref().is_some_and(Vec::is_empty) {
        return Err(RouteError::EmptyPins);
    }
    match (pins, direct_s3) {
        (Some(_), true) => Err(RouteError::BothTransports),
        (Some(pins), false) => {
            if bucket.is_some() {
                return Err(RouteError::ServerBucket);
            }
            Ok(PublishRoute::Server(Box::new(
                HttpStore::with_client_credential(endpoint, pins, &AmbientNetwork, credential)
                    .map_err(RouteError::Http)?,
            )))
        }
        (None, true) => {
            let bucket = bucket.ok_or(RouteError::NoBucket)?;
            let store = GranaryStore::new(
                s3_builder(endpoint, bucket, env)?
                    .build()
                    .map_err(|e| RouteError::Store(e.to_string()))?,
            );
            Ok(PublishRoute::DirectS3(Box::new(DirectStoreDeadline::new(
                store,
            ))))
        }
        (None, false) => Err(RouteError::NoTransport),
    }
}

/// The S3 builder, every parameter NAMED and nothing swept.
///
/// `AmazonS3Builder::from_env()` is not called here and must not be: it
/// sweeps the whole `AWS_*`/`OBJECT_STORE_*` namespace, so an
/// `AWS_ALLOW_HTTP` or an `AWS_SKIP_SIGNATURE` sitting in a shell for some
/// other tool silently downgrades this client's transport or drops request
/// signing altogether. Naming each variable is the difference between a
/// configuration this file decides and one the ambient environment
/// decides. (`granary-server`'s `config.rs` makes the same argument for
/// the server; the code cannot be shared across the licence boundary, so
/// the reasoning is restated rather than referenced.)
fn s3_builder(
    endpoint: &str,
    bucket: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<AmazonS3Builder, RouteError> {
    // VALIDATION and DERIVATION in ONE comparison. A `starts_with` for the
    // flag plus a separate check for the refusal is two accept sets, and
    // two accept sets drift — into a client that accepts a schemeless
    // endpoint and then fails every request.
    let allow_http = scheme_allows_http(endpoint)?;
    // The client below ignores ambient proxies; say so, by name, so a site
    // that relies on one sees why its requests fail.
    for variable in granary_store::http_client::ambient_proxy_variables(env) {
        crate::observe::OperatorDiagnostic::set_in_the_environment_and_ignored_the_direct_s3(
            crate::observe::ProxyVariableName::from_adapter(variable),
        )
        .emit();
    }
    let region = env(ENV_AWS_REGION)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_REGION.to_owned());
    // ONE `ClientOptions` value AND ONE `RetryConfig` value, both OURS:
    // `with_client_options` REPLACES whatever the builder held, so a
    // separate `with_allow_http`/`with_timeout` call site would be
    // silently discarded by whichever ran second. `with_timeout` states
    // `object_store`'s own 30 s default EXPLICITLY (`DIRECT_STORE_REQUEST_TIMEOUT`,
    // one of the three durations `DirectStoreDeadline`'s compile-time
    // check sums) rather than leaving it to whatever the dependency's
    // default happens to be on whichever version is locked. `with_retry`
    // states the same dependency's default retry envelope explicitly,
    // for the identical reason: `DIRECT_STORE_RETRY_BUDGET` and
    // `DIRECT_STORE_MAX_BACKOFF` (nested in `backoff`) are the other two
    // durations that check sums. `DIRECT_STORE_MAX_RETRIES` is a COUNT,
    // not a duration, and does not enter that inequality at all: the
    // sum is a bound on ELAPSED time, and `RetryContext::exhausted`
    // (`src/client/retry.rs:98-100`) stops the sequence on
    // `start.elapsed() > retry_timeout` for ANY count, so no arithmetic
    // over the count is needed to know the budget bounds it.
    //
    // EVERY FIELD OF BOTH STRUCTS IS NAMED, and neither carries a
    // struct-update tail. One policy, and the reason is the same for
    // both: a field `object_store` ADDS in a later version is then a
    // loud compile error right here — a missing-field error naming it —
    // rather than a new default silently governing this route.
    let mut builder = AmazonS3Builder::new()
        // Never follows a redirect: a signed request carries its session
        // token across whatever origin a 3xx names.
        .with_http_connector(granary_store::http_client::NoRedirectConnector)
        .with_bucket_name(bucket)
        .with_endpoint(endpoint)
        .with_region(region)
        .with_client_options(
            ClientOptions::default()
                .with_allow_http(allow_http)
                .with_timeout(DIRECT_STORE_REQUEST_TIMEOUT),
        )
        .with_retry(RetryConfig {
            max_retries: DIRECT_STORE_MAX_RETRIES,
            retry_timeout: DIRECT_STORE_RETRY_BUDGET,
            backoff: BackoffConfig {
                init_backoff: DIRECT_STORE_INIT_BACKOFF,
                max_backoff: DIRECT_STORE_MAX_BACKOFF,
                base: DIRECT_STORE_BACKOFF_BASE,
            },
        });
    // BY NAME, one at a time (R11-d/e). Absent is not an error — but it
    // is a NARROWING, and this is what it costs.
    //
    // `object_store-0.14.1`'s `build()` (src/aws/builder.rs) picks a
    // credential provider down a fixed chain: an explicit provider, then
    // STATIC (`access_key_id` + `secret_access_key`), then WEB IDENTITY
    // (`web_identity_token_file` + `role_arn`), then the ECS TASK
    // provider (`container_credentials_relative_uri`), then EKS POD
    // IDENTITY (`container_credentials_full_uri` +
    // `container_authorization_token_file`), and finally INSTANCE (IMDS)
    // as the unconditional `else`. Those five middle fields have NO
    // dedicated setter: the only writer is `with_config`, and the only
    // caller that reaches them from the environment is `from_env`, which
    // sweeps every `AWS_*` variable into it. Naming four variables
    // instead therefore leaves the WebIdentity, ECS-task and
    // EKS-pod-identity branches permanently unreachable from here.
    // Static (the three below) and IMDS (the `else`, which needs no field
    // at all) are the two that survive.
    //
    // That is the deliberate price of not sweeping the environment,
    // not an oversight: `from_env` is the same call that would
    // let an `AWS_ALLOW_HTTP` or an `AWS_SKIP_SIGNATURE` left in a shell
    // reach this builder, and this path is the LOCAL-DEV/`MinIO` opt-out
    // behind `--direct-s3` — the deployed path is through the server,
    // where the client holds no bucket credential of any kind. A
    // federated-identity deployment that needs one of the three uses
    // static credentials or an instance role.
    if let Some(id) = env(ENV_AWS_ACCESS_KEY_ID).filter(|v| !v.is_empty()) {
        builder = builder.with_access_key_id(id);
    }
    if let Some(secret) = env(ENV_AWS_SECRET_ACCESS_KEY).filter(|v| !v.is_empty()) {
        builder = builder.with_secret_access_key(secret);
    }
    if let Some(token) = env(ENV_AWS_SESSION_TOKEN).filter(|v| !v.is_empty()) {
        builder = builder.with_token(token);
    }
    Ok(builder)
}

/// The endpoint's scheme, as the one bit `allow_http` records — or a
/// value-free refusal for an unsupported scheme, userinfo or invalid authority.
///
/// Case-INSENSITIVE, because a URL scheme is (RFC 3986 §3.1).
fn scheme_allows_http(endpoint: &str) -> Result<bool, RouteError> {
    check_endpoint_userinfo(endpoint).map_err(RouteError::Http)?;
    if endpoint.split_once("://").is_some_and(|(_, rest)| {
        rest.split(['/', '?', '#']).next().is_some_and(|authority| {
            authority.is_empty()
                || authority
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        })
    }) {
        return Err(RouteError::Endpoint("endpoint must name a host".to_owned()));
    }
    for (scheme, plaintext) in [(SCHEME_HTTP, true), (SCHEME_HTTPS, false)] {
        // `get` rather than a slice: indexing is denied workspace-wide,
        // and a prefix length landing mid-character is `None` here rather
        // than a panic.
        if endpoint
            .get(..scheme.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(scheme))
        {
            return Ok(plaintext);
        }
    }
    Err(RouteError::Endpoint(format!(
        "endpoint carries no scheme this build can open; it must begin \
         {SCHEME_HTTP:?} or {SCHEME_HTTPS:?}, in any case (RFC 3986 §3.1)"
    )))
}

#[cfg(test)]
mod tests;
