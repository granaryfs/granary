// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The server's STORE schema and the seam-dispatch deadline.
//!
//! **`GRANARY_STORE` is a bare DISCRIMINANT, not a URL.** `memory:` or
//! `s3:`, and every parameter the chosen form needs arrives in its own
//! named variable. A URL would put bucket, host, scheme, credentials and
//! path into one string this process then has to parse — and the parse
//! would decide `allow_http` from a scheme buried inside a value an
//! operator pasted, which is the shape §9a's pinned-key work exists to
//! avoid.
//!
//! **The S3 store is built EXPLICITLY and its credentials are read BY
//! NAME.** `AmazonS3Builder::from_env()` is not called here and must not
//! be: it sweeps the WHOLE `AWS_*`/`OBJECT_STORE_*` namespace, so an
//! `AWS_ALLOW_HTTP` or an `AWS_SKIP_SIGNATURE` sitting in a deploy's
//! environment for some other tool silently downgrades this server's
//! transport or drops request signing altogether. Naming each variable
//! is the difference between a configuration this file decides and one
//! the ambient environment decides.
//!
//! **`allow_http` has exactly ONE site and it is derived from the
//! ENDPOINT'S OWN SCHEME — the same comparison that VALIDATES it.** An
//! `http://` endpoint is a plaintext endpoint whether or not the client
//! admits it, so the flag records what the operator already asked for
//! rather than granting anything extra; an `https://` endpoint leaves it
//! off, and no `AWS_*` variable can turn it on. A scheme that is neither
//! is refused at startup naming [`ENV_STORE_ENDPOINT`], which is this
//! module's contract and not a nicety: without it `HTTP://host` and a
//! schemeless `host:9000` started a server that answered every request
//! `500` + `internal`. One comparison decides both because two would
//! drift, and the drift is precisely a server that starts and then
//! refuses everything.
//!
//! **The store's own request CLOCK is set here too, and above the dispatch
//! deadline**. Inheriting `object_store`'s default put the
//! two clocks on the same figure, and the tie decided a wire status:
//! see [`STORE_CLIENT_TIMEOUT`]. Same principle as the paragraphs
//! above — what this server answers a peer is not something an upstream
//! default gets to choose.
//!
//! **The publication authority's configuration is [`authority`]'s**, read
//! by the same convention: named variables, a lookup seam, a refusal that
//! names the variable.

pub mod authority;

use std::sync::Arc;
use std::time::Duration;

use object_store::ClientOptions;
use object_store::aws::AmazonS3Builder;
use object_store::memory::InMemory;
use object_store::{ObjectStore, RetryConfig};

/// Which store to serve from: exactly one of the two discriminants.
pub const ENV_STORE: &str = "GRANARY_STORE";

/// The in-process store. Nothing is durable and nothing leaves the
/// process — the conformance and process-test form.
pub const STORE_MEMORY: &str = "memory:";

/// An S3-compatible endpoint, configured by the three `GRANARY_STORE_*`
/// variables below and credentialed by name.
pub const STORE_S3: &str = "s3:";

/// The S3 bucket. Required by [`STORE_S3`].
///
/// **THE BUCKET MUST ALREADY EXIST. This server never creates it.**
/// Nothing in the startup path or in any handler issues a
/// `CreateBucket`, and the store client cannot: `AmazonS3Builder` builds
/// an object client, not an admin client. A server pointed at a bucket
/// that is not there starts, binds, logs its readiness line and then
/// fails every store call for as long as it runs. Before this documentation, that fact
/// lived in ONE place — a comment in `scripts/minio-harness.sh`, which
/// pre-creates `granary-test` and is the only reason the first real
/// run worked — so an operator reading this variable's documentation had
/// no way to learn it.
///
/// **A startup PROBE was considered and REFUSED**, and the refusal is
/// recorded here because the next person to meet a `500` from a missing
/// bucket will propose it again. Three reasons, each sufficient:
///
/// 1. **It reverses a tested, settled property.**
///    `tests/shipped_store_config.rs` drives the shipped binary at an
///    endpoint that accepts and never answers and asserts that it
///    STARTS and then answers `503`/`unavailable` per request; its own
///    header states the design — "the store constructs lazily, so
///    pointing it at an endpoint that never answers changes nothing
///    about startup and everything about the first request". A probe
///    makes that row's premise false.
/// 2. **The dispatch-deadline rationale here says the same thing about the
///    bucket specifically**: [`STORE_CLIENT_TIMEOUT`]'s note ends "a
///    quiet bucket is not a defect in this server". Refusing to boot
///    over one contradicts it.
/// 3. **A probe cannot tell "missing" from "transiently
///    unreachable".** Both answer the same way from here, so a probe
///    that fails closed converts every dependency blip into a boot
///    crash-loop — strictly worse availability than serving and
///    refusing per request, and another instance of a control added for one
///    failure creating another, here in availability. A probe that
///    fails OPEN on the ambiguity diagnoses nothing and is the current
///    behaviour with a delay.
///
/// The per-request failure is what has to be DIAGNOSABLE, and that half
/// is `handlers.rs`'s: see the `internal failure` event its three
/// funnels emit, which carry the store's own text — or, when the store
/// answered `Ok` with something its contract forbids, the rule it broke
/// — where the wire may not.
pub const ENV_STORE_BUCKET: &str = "GRANARY_STORE_BUCKET";

/// The S3 endpoint URL, scheme included. Required by [`STORE_S3`]; its
/// scheme is the sole input to `allow_http`.
pub const ENV_STORE_ENDPOINT: &str = "GRANARY_STORE_ENDPOINT";

/// The S3 region. Required by [`STORE_S3`] — a default would be this
/// file inventing a value that decides where data lands.
pub const ENV_STORE_REGION: &str = "GRANARY_STORE_REGION";

/// The access key id, read BY NAME rather than swept.
pub const ENV_AWS_ACCESS_KEY_ID: &str = "AWS_ACCESS_KEY_ID";

/// The secret access key, read BY NAME rather than swept.
pub const ENV_AWS_SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";

/// The session token, read BY NAME rather than swept. Optional: a
/// long-lived key pair has none.
pub const ENV_AWS_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";

/// The plaintext endpoint scheme, lowercase. The comparison folds the
/// VALUE's case, never this one.
const SCHEME_HTTP: &str = "http://";

/// The TLS endpoint scheme, lowercase. As [`SCHEME_HTTP`].
const SCHEME_HTTPS: &str = "https://";

/// The longest one seam dispatch against a NETWORK store may take
/// before the request is answered `503`/`unavailable` (§5.10, "refusing
/// load").
///
/// **A bound on the AWAIT, not a retry budget.** The store below it has
/// its own retries and its own per-request clocks; what this covers is
/// the whole of them, so a request cannot outlive it however many
/// attempts happen underneath. Thirty seconds is generous for a bucket
/// that is answering and short enough that a bucket that is not stops
/// holding a connection, a write charge and a verify permit.
pub const STORE_DISPATCH_DEADLINE: Duration = Duration::from_secs(30);

/// The store client's OWN per-request clock — set HERE
/// rather than inherited from `object_store`'s default.
///
/// **This is a DIFFERENT clock from [`STORE_DISPATCH_DEADLINE`], and the
/// gap between them is the point.** The dispatch deadline bounds the await
/// this server performs; the value below bounds the single HTTP request
/// the store performs underneath it. Both are tokio timers on the same
/// runtime, and `tokio::time::timeout` polls its inner future BEFORE its
/// own delay — so whichever clock is shorter decides what the peer is
/// told, and at equal values the inner one wins the tie.
///
/// **MEASURED, 2026-08-19.** `object_store` 0.14.1's
/// `ClientOptions::default()` sets `timeout` to thirty seconds, the same
/// figure as [`STORE_DISPATCH_DEADLINE`]. Against a stalled endpoint the
/// two expired in the same timer tick, and the answer then depended on
/// whether the store's retry loop swallowed its own expiry: a listing is
/// a safe method and is retried, so the dispatch deadline fired and the peer saw
/// `503`/`unavailable`; a conditional `PUT` is marked non-idempotent by
/// `aws/mod.rs`, so its single attempt ERRORED and the peer saw
/// `HTTP/1.1 500 Internal Server Error` with `granary-error: internal`
/// after 30.66 s. §5.10 wants the first: `unavailable` says "refusing
/// load, retry later", `internal` says "this server has a defect", and a
/// quiet bucket is not a defect in this server.
///
/// **Sixty seconds, so the DISPATCH DEADLINE OWNS THE REFUSAL TOKEN.** Doubling the
/// store's clock does not lengthen any request — the dispatch deadline still answers at
/// thirty — it removes the tie, so every seam stall renders §5.10's
/// status whatever the operation's idempotency. What the value must
/// never be is *below* the deadline: there the store's clock decides the
/// status instead of ours, and the write paths silently go back to
/// `500`.
///
/// Seconds and not `from_mins(1)`: the figure only means anything beside
/// [`STORE_DISPATCH_DEADLINE`]'s thirty, and two units make the
/// comparison the `const _` below performs unreadable at the call site.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "the unit is shared with STORE_DISPATCH_DEADLINE on purpose; \
              a minute here hides the relation the assert enforces"
)]
pub const STORE_CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

/// The relation above, gated at COMPILE TIME so an inversion cannot ship.
///
/// Below the deadline, the store's own clock decides the status instead
/// of ours — and on the non-retried write paths that status is
/// `500`/`internal` rather than §5.10's `503`/`unavailable`. `as_secs`
/// is `const`, so the check costs a build and nothing else.
const _: () = assert!(
    STORE_CLIENT_TIMEOUT.as_secs() > STORE_DISPATCH_DEADLINE.as_secs(),
    "STORE_CLIENT_TIMEOUT must exceed STORE_DISPATCH_DEADLINE, or the store's \
     per-request clock, not STORE_DISPATCH_DEADLINE, is what decides the wire status"
);

/// A constructed store and the deadline its dispatches run under.
#[derive(Debug)]
pub struct StoreConfig {
    /// The store itself. `Arc<dyn ObjectStore>` and not a generic: the
    /// discriminant is a runtime value, and `object_store` blanket-impls
    /// `ObjectStore` for `Arc<T>` (its `as_ref_impl!` macro), so the
    /// erased handle is a store in its own right.
    pub store: Arc<dyn ObjectStore>,
    /// Bounded admission reads from the same backend.
    pub admission: crate::Admission,
    /// `Some` for a store that can stop answering, `None` for one
    /// that cannot. A deadline on an in-process `BTreeMap` would bound
    /// nothing and would turn a slow test machine into a `503`.
    pub dispatch_deadline: Option<Duration>,
    /// The ambient proxy variables set in the environment, which the store
    /// ignores: it connects directly. Names only, never values; startup logs
    /// each, so a site that relied on one learns why its requests fail.
    pub ignored_proxy_variables: Vec<&'static str>,
}

/// Read the store schema from the process environment.
///
/// # Errors
/// A message naming the variable at fault, ready for the composition
/// root's startup refusal.
pub fn store_from_env() -> Result<StoreConfig, String> {
    store_from(&|name| std::env::var(name).ok())
}

/// [`store_from_env`] over an arbitrary lookup.
///
/// The seam is the LOOKUP, never the schema: `get` decides what a name
/// resolves to and nothing else, so no caller can widen the discriminant
/// set, skip a required variable, or move the deadline. `std::env::var`
/// is `unsafe` to WRITE under edition 2024 and this workspace forbids
/// `unsafe_code`, so a row cannot plant a variable — which is the reason
/// the lookup is a parameter at all.
fn store_from(get: &dyn Fn(&str) -> Option<String>) -> Result<StoreConfig, String> {
    let discriminant = get(ENV_STORE).ok_or_else(|| {
        format!("{ENV_STORE} is not set; it names the store form, {STORE_MEMORY:?} or {STORE_S3:?}")
    })?;
    match discriminant.as_str() {
        STORE_MEMORY => {
            let store = Arc::new(InMemory::new());
            Ok(StoreConfig {
                admission: crate::Admission::memory(store.clone()),
                store,
                dispatch_deadline: None,
                ignored_proxy_variables: Vec::new(),
            })
        }
        STORE_S3 => s3_from(get),
        other => Err(format!(
            "{ENV_STORE}={other:?} is not a store form this build can open; \
             the forms are {STORE_MEMORY:?} and {STORE_S3:?}"
        )),
    }
}

#[cfg(all(test, feature = "overlay-fault-tests"))]
pub(crate) fn store_from_lookup(
    get: &dyn Fn(&str) -> Option<String>,
) -> Result<StoreConfig, String> {
    store_from(get)
}

/// The S3 form: every parameter named, nothing swept.
fn s3_from(get: &dyn Fn(&str) -> Option<String>) -> Result<StoreConfig, String> {
    let builder = s3_builder(get)?;
    let build_error = |error| format!("{ENV_STORE}={STORE_S3:?}: {error}");
    let store = builder.clone().build().map_err(build_error)?;
    let single_attempt = builder
        .with_http_connector(crate::authority::BoundedListingConnector)
        .with_retry(RetryConfig {
            max_retries: 0,
            ..RetryConfig::default()
        })
        .build()
        .map_err(build_error)?;
    Ok(StoreConfig {
        store: Arc::new(store),
        admission: crate::Admission::s3(single_attempt),
        dispatch_deadline: Some(STORE_DISPATCH_DEADLINE),
        ignored_proxy_variables: granary_store::http_client::ambient_proxy_variables(get),
    })
}

/// [`s3_from`]'s builder, up to but not including `build()`.
///
/// **Split out so the settings can be READ BACK.** `build()` erases
/// everything into an `Arc<dyn ObjectStore>`, and two mutations that
/// every text-level gate survives are only visible before that: ordering
/// `.with_allow_http(..)` ahead of `.with_client_options(..)`, which
/// discards it, and rebinding `.with_timeout(..)` onto a `ClientOptions`
/// value that is then dropped. `AmazonS3Builder::get_config_value` reads
/// both off the builder, so those are catchable in-crate — see
/// `the_endpoint_scheme_decides_allow_http_and_the_client_clock_is_set`.
fn s3_builder(get: &dyn Fn(&str) -> Option<String>) -> Result<AmazonS3Builder, String> {
    let bucket = required(get, ENV_STORE_BUCKET)?;
    let endpoint = required(get, ENV_STORE_ENDPOINT)?;
    let region = required(get, ENV_STORE_REGION)?;
    // BEFORE the builder is touched: an endpoint this build cannot open
    // is a startup refusal naming the variable, not a server that comes
    // up and then answers `500` to everything.
    let allow_http = scheme_allows_http(&endpoint)?;

    // THE CLIENT'S OWN OPTIONS, CONSTRUCTED HERE AND IN ONE VALUE.
    // `AmazonS3Builder::with_client_options` REPLACES whatever the
    // builder held (`aws/builder.rs:1050`), and the builder's own
    // `with_allow_http` is nothing but a setter on that same value
    // (`aws/builder.rs:944`) — so two call sites would mean the later
    // one silently discarded the earlier, with the endpoint's scheme as
    // the thing quietly dropped. One value, both settings, no ordering
    // to get wrong.
    //
    // `ClientOptions::default()` is not a sweep: its `Default` impl
    // (`client/mod.rs:368-406`) assigns literals and reads no
    // environment variable. It is the base rather than
    // `ClientOptions::new()` for the connect timeout and the HTTP/1
    // pin that come with it; what this file overrides is the one figure
    // that decides a wire status.
    let client_options = ClientOptions::default()
        .with_timeout(STORE_CLIENT_TIMEOUT)
        // THE ONLY `allow_http` SITE, and its input is the endpoint the
        // operator wrote — never `AWS_ALLOW_HTTP`, which a sweep would
        // have honoured against an `https://` endpoint. The value comes
        // from the comparison that ACCEPTED the endpoint, so the flag
        // and the validation cannot disagree.
        .with_allow_http(allow_http);

    let mut builder = AmazonS3Builder::new()
        // Never follows a redirect. This path holds the real bucket
        // credentials, and a signed request would otherwise carry its session
        // token to whatever origin a 3xx names; reqwest strips only
        // `Authorization`. A setting the connector cannot honour refuses at
        // `build()`, which startup runs, so it is a startup failure. It also
        // ignores ambient proxy variables (reported in `StoreConfig`), and it
        // does not shuffle resolved addresses, so pooled connections are not
        // spread across the endpoint's IPs.
        .with_http_connector(granary_store::http_client::NoRedirectConnector)
        .with_bucket_name(bucket)
        .with_endpoint(&endpoint)
        .with_region(region)
        .with_client_options(client_options);

    // BY NAME, one at a time. Absent is not an error: an instance-role
    // deployment supplies none of these and the store's own provider
    // chain takes over.
    if let Some(id) = get(ENV_AWS_ACCESS_KEY_ID).filter(|v| !v.is_empty()) {
        builder = builder.with_access_key_id(id);
    }
    if let Some(secret) = get(ENV_AWS_SECRET_ACCESS_KEY).filter(|v| !v.is_empty()) {
        builder = builder.with_secret_access_key(secret);
    }
    if let Some(token) = get(ENV_AWS_SESSION_TOKEN).filter(|v| !v.is_empty()) {
        builder = builder.with_token(token);
    }

    Ok(builder)
}

/// The endpoint's scheme, as the one bit `allow_http` records — or a
/// refusal naming [`ENV_STORE_ENDPOINT`].
///
/// **VALIDATION and DERIVATION in one comparison**, which is the whole
/// design: a `starts_with` for the flag and a separate check for the
/// refusal are two accept sets, and two accept sets drift. Here an
/// endpoint that does not match a listed scheme cannot reach the
/// builder at all, so there is no third state for the flag to be wrong
/// about.
///
/// **Case-INSENSITIVE, because a URL scheme is** — RFC 3986 §3.1 makes
/// it case-insensitive and normalises to lowercase, and `Url` does
/// exactly that for the store underneath. So `HTTP://host` IS a
/// plaintext endpoint down there, and a case-sensitive comparison up
/// here disagreed with the layer that acts on the answer: the flag
/// stayed off, the store refused its own endpoint, and every request
/// came back `500` + `internal` from a server that had started
/// cleanly.
///
/// **Not a URL parse, and deliberately not.** The module docs give the
/// reason a URL is not the configuration surface in the first place;
/// what this needs is the leading token and nothing else, and
/// hand-rolling the rest of RFC 3986 to get it would be the parser this
/// file exists to avoid.
fn scheme_allows_http(endpoint: &str) -> Result<bool, String> {
    for (scheme, plaintext) in [(SCHEME_HTTP, true), (SCHEME_HTTPS, false)] {
        // `get` rather than a slice: an index is denied workspace-wide,
        // and a prefix length that lands mid-character is `None` here
        // instead of a panic.
        if endpoint
            .get(..scheme.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(scheme))
        {
            return Ok(plaintext);
        }
    }
    Err(format!(
        "{ENV_STORE_ENDPOINT}={endpoint:?} carries no scheme this build can \
         open; it must begin {SCHEME_HTTP:?} or {SCHEME_HTTPS:?}, in any case \
         (RFC 3986 §3.1)"
    ))
}

/// A variable the chosen form cannot do without, or a refusal naming it.
fn required(get: &dyn Fn(&str) -> Option<String>, name: &str) -> Result<String, String> {
    match get(name) {
        Some(value) if !value.is_empty() => Ok(value),
        Some(_empty) => Err(format!(
            "{name} is empty; {ENV_STORE}={STORE_S3:?} needs it set"
        )),
        None => Err(format!(
            "{name} is not set; {ENV_STORE}={STORE_S3:?} needs it"
        )),
    }
}

#[cfg(test)]
mod tests;
