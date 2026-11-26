// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The HTTP client for every S3 store granary builds — the client's
//! `--direct-s3` route and the server's object store: the one `object_store`
//! would build, except that it never follows a redirect.
//!
//! `object_store` 0.14.1 builds its `reqwest` client with reqwest's default
//! redirect policy, which follows up to ten redirects, across origins, still
//! carrying `x-amz-security-token` (reqwest strips `Authorization` on a
//! cross-origin hop, not that header). `object_store` itself turns any 3xx it
//! *receives* into an error (`RetryExt::send_retry`), so a client that follows
//! nothing makes every redirect a failed request. `object_store` has no option
//! for this, so each caller installs this connector with
//! `AmazonS3Builder::with_http_connector`. It lives here, under `backend`, so
//! that one implementation serves both callers.
//!
//! **It builds each client from the options that `connect` receives.** The store
//! calls it once for S3 and, when credentials come from the instance, once more
//! for the metadata endpoint with that endpoint's own overrides (plain HTTP
//! allowed, a one-second connect timeout). Capturing the caller's settings
//! instead would refuse the plaintext metadata endpoint. `connect` runs inside
//! `AmazonS3Builder::build`, so a refused option fails the build, not a later
//! request.
//!
//! **It reproduces what `object_store`'s crate-private `ClientOptions::client`
//! applies for the options its callers carry**: the request and connect
//! timeouts, plain-HTTP permission, HTTP/1-only (`object_store`'s default), its
//! user agent, and no transparent decompression (object sizes come from
//! `Content-Length`). **An option it does not reproduce is refused when set**,
//! rather than ignored, so a caller that starts setting one finds out. Values
//! are compared as `object_store` prints them; a spelling this module does not
//! recognise (`"0"` for false, `"30 seconds"`) is refused, never guessed. It
//! deliberately drops `object_store`'s DNS address shuffling, whose resolver is
//! private: connections go to the first address the system resolver returns.
//!
//! **It ignores ambient proxies.** reqwest otherwise reads `ALL_PROXY`,
//! `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` from the process environment,
//! with no default exemption for loopback or link-local addresses, so an
//! inherited `HTTP_PROXY` would carry the instance-metadata exchange, and its
//! temporary credentials, through the proxy in plaintext. Both callers read
//! their configuration by name and let nothing ambient decide the transport,
//! so the client this module builds connects directly. Each caller reports an
//! ambient proxy variable it ignores ([`ambient_proxy_variables`]), so a site
//! that needed one learns why its requests fail. Supporting an explicit egress
//! proxy is a deployment decision this module does not take: `object_store`'s
//! own proxy options are refused like any other it does not reproduce.
//!
//! **What it cannot see:** `ClientOptions::with_root_certificate` and
//! `with_default_headers` have no configuration key, so a caller setting them
//! would have them dropped without an error. Neither caller sets them; a change
//! that starts to must move them into this connector first.
//!
//! On an `object_store` upgrade, re-read `ClientOptions::client` and the
//! `ClientConfigKey` list against `UNSUPPORTED` and this module's tests, and
//! restate `USER_AGENT`: a setting `object_store` starts applying is not
//! applied here until it is named.

use std::time::Duration;

use object_store::client::{HttpClient, HttpConnector};
use object_store::{ClientConfigKey, ClientOptions};

/// The user agent `object_store` sends by default, stated for the version this
/// workspace pins (`Cargo.toml`: `object_store = "=0.14.1"`).
pub(crate) const USER_AGENT: &str = "object_store/0.14.1";

/// Options this connector refuses when they carry anything but their default:
/// each is applied by `object_store`'s own client and not reproduced here.
pub(crate) const UNSUPPORTED: [(ClientConfigKey, &str); 14] = [
    (ClientConfigKey::AllowInvalidCertificates, "false"),
    (ClientConfigKey::NoSystemCertificates, "false"),
    (ClientConfigKey::Http2Only, "false"),
    (ClientConfigKey::Http2KeepAliveWhileIdle, "false"),
    (ClientConfigKey::UserAgent, ""),
    (ClientConfigKey::ProxyUrl, ""),
    (ClientConfigKey::ProxyCaCertificate, ""),
    (ClientConfigKey::ProxyExcludes, ""),
    (ClientConfigKey::ReadTimeout, ""),
    (ClientConfigKey::PoolIdleTimeout, ""),
    (ClientConfigKey::PoolMaxIdlePerHost, ""),
    (ClientConfigKey::Http2KeepAliveInterval, ""),
    (ClientConfigKey::Http2KeepAliveTimeout, ""),
    (ClientConfigKey::Http2MaxFrameSize, ""),
];

/// An [`HttpConnector`] whose clients never follow a redirect.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoRedirectConnector;

impl HttpConnector for NoRedirectConnector {
    fn connect(&self, options: &ClientOptions) -> object_store::Result<HttpClient> {
        client(options)
            .map(HttpClient::new)
            .map_err(|reason| object_store::Error::Generic {
                store: "S3",
                source: reason.into(),
            })
    }
}

/// The client for one `connect`, or why these options cannot be honoured.
pub(crate) fn client(options: &ClientOptions) -> Result<reqwest::Client, String> {
    for (key, default) in UNSUPPORTED {
        let set = options.get_config_value(&key).unwrap_or_default();
        if set != default {
            return Err(format!(
                "the no-redirect S3 connector does not apply {key:?} (set to {set:?})"
            ));
        }
    }
    let flag = |key: ClientConfigKey| -> Result<bool, String> {
        match options.get_config_value(&key).as_deref() {
            Some("true") => Ok(true),
            Some("false") | None => Ok(false),
            Some(other) => Err(format!("{key:?} is {other:?}, not a boolean")),
        }
    };
    let mut builder = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .https_only(!flag(ClientConfigKey::AllowHttp)?);
    if flag(ClientConfigKey::Http1Only)? {
        builder = builder.http1_only();
    }
    if let Some(text) = options.get_config_value(&ClientConfigKey::Timeout) {
        builder = builder.timeout(parse_duration(&text)?);
    }
    if let Some(text) = options.get_config_value(&ClientConfigKey::ConnectTimeout) {
        builder = builder.connect_timeout(parse_duration(&text)?);
    }
    builder.build().map_err(|e| e.to_string())
}

/// The proxy variables reqwest would read from the environment, in the
/// spellings it accepts: what [`ambient_proxy_variables`] looks for.
pub const AMBIENT_PROXY_VARIABLES: [&str; 6] = [
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
];

/// Which ambient proxy variables `get` reports set (non-empty), so a caller can
/// say it ignores them. Names only: a proxy URL can carry credentials, and a
/// value is never returned.
pub fn ambient_proxy_variables(get: &dyn Fn(&str) -> Option<String>) -> Vec<&'static str> {
    AMBIENT_PROXY_VARIABLES
        .into_iter()
        .filter(|name| get(name).is_some_and(|v| !v.is_empty()))
        .collect()
}

/// A duration in the form `object_store` prints one (humantime's): whole
/// numbers with a unit, separated by spaces — `30s`, `1s 500ms`. Anything else is
/// refused, never guessed.
pub(crate) fn parse_duration(text: &str) -> Result<Duration, String> {
    let mut total = Duration::ZERO;
    let mut parts = 0_u32;
    for part in text.split_whitespace() {
        let split = part
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| format!("{text:?}: {part:?} has no unit"))?;
        let (digits, unit) = part.split_at(split);
        let n: u64 = digits
            .parse()
            .map_err(|_| format!("{text:?}: {part:?} is not a whole number"))?;
        let secs = |per: u64| {
            n.checked_mul(per)
                .map(Duration::from_secs)
                .ok_or_else(|| format!("{text:?}: {part:?} overflows"))
        };
        let one = match unit {
            "d" | "day" | "days" => secs(86_400)?,
            "h" => secs(3600)?,
            "m" => secs(60)?,
            "s" => Duration::from_secs(n),
            "ms" => Duration::from_millis(n),
            "us" => Duration::from_micros(n),
            "ns" => Duration::from_nanos(n),
            _ => return Err(format!("{text:?}: unknown unit {unit:?}")),
        };
        // Refused, not clamped: an overflowing duration is a wrong configuration,
        // and a clamp would turn it into a timeout of centuries.
        total = total
            .checked_add(one)
            .ok_or_else(|| format!("{text:?} overflows"))?;
        parts += 1;
    }
    if parts == 0 {
        return Err(format!("{text:?} is not a duration"));
    }
    Ok(total)
}

#[cfg(test)]
mod tests;
