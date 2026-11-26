// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::route` — which store `gran publish`
//! writes through (the server by default).
//!
//! Out-of-line: `granary-client`'s non-test artifact has other
//! workspace crates depending on it (`granary-sim`,
//! `granary-server`, `granary-cli`) and its own `tests/` directory
//! (`crates/granary-client/tests/`), so the module's own tests move
//! out of the parent file while it keeps its path and declares
//! `#[cfg(test)] mod tests;` — the sibling-directory form.

use object_store::aws::AmazonS3ConfigKey;
use object_store::{ClientConfigKey, ClientOptions};

use super::*;

/// `s3_builder`, panicking on a refusal named by the caller's
/// endpoint — the one call every test below builds through.
///
/// `#[track_caller]`: the panic then reports the ROW that asked for
/// the builder, not this line, which is the only location that
/// tells a reader which case failed (SHOULD-15).
#[track_caller]
fn built(endpoint: &str) -> AmazonS3Builder {
    s3_builder(endpoint, "a-bucket", &|_| None)
        .unwrap_or_else(|reason| panic!("{endpoint}: {reason}"))
}

/// What the builder ended up holding for one client option —
/// RESTATED, not shared, from `granary-server`'s `config.rs` test
/// module of the same shape: the licence boundary forbids sharing
/// code across the AGPL/Apache split. `s3_builder` sets `allow_http`
/// exclusively through the `ClientOptions` value passed to
/// `with_client_options` (never through `AmazonS3Builder`'s own
/// top-level `with_allow_http`, the convenience method
/// `granary-server`'s comment warns is discarded when ordered before
/// `with_client_options`), so that specific ordering hazard does not
/// exist in this shape of the code; a text scan still cannot see
/// whether the value THREADED THROUGH actually varies by endpoint,
/// which is what the row below checks by reading it off the built
/// value rather than off the source.
fn client_option(builder: &AmazonS3Builder, key: ClientConfigKey) -> String {
    builder
        .get_config_value(&AmazonS3ConfigKey::Client(key))
        .unwrap_or_else(|| panic!("the builder holds no value for {key:?}"))
}

/// Both settings READ BACK OFF THE BUILDER, not off the source, for
/// the reason `client_option`'s own doc states.
///
/// Dropping `.with_timeout(DIRECT_STORE_REQUEST_TIMEOUT)` is an
/// EQUIVALENT MUTANT at `object_store` 0.14.1, not a red:
/// `AmazonS3Builder::default()` already carries
/// `ClientOptions::default()`, whose own timeout is `Some(30s)` —
/// the SAME figure `DIRECT_STORE_REQUEST_TIMEOUT` states, deliberately
/// (stating the default rather than changing it), so a read-back
/// cannot distinguish an explicit call from a dropped one TODAY.
/// Not a test gap: this assertion checks the EFFECTIVE value the
/// route's client runs on, and it goes red exactly when a future
/// `object_store` upgrade moves the default while the call stays
/// absent — the regression the explicit call exists to prevent.
/// Unlike `granary-server`'s analogous test (whose pinned
/// `STORE_CLIENT_TIMEOUT` is deliberately 60s against a 30s default,
/// so a dropped call IS visible there today), this crate's figure is
/// deliberately not chosen to differ.
#[test]
fn the_endpoint_scheme_decides_allow_http_and_the_client_clock_is_set() {
    let expected_timeout = ClientOptions::default()
        .with_timeout(DIRECT_STORE_REQUEST_TIMEOUT)
        .get_config_value(&ClientConfigKey::Timeout)
        .unwrap_or_else(|| panic!("a set timeout reads back"));

    // `allow_http` follows the ENDPOINT'S SCHEME and nothing else,
    // so both schemes are driven — one arm alone passes for a
    // builder that hardcodes either answer.
    for (endpoint, allow_http) in [
        ("http://s3.example.invalid", "true"),
        ("https://s3.example.invalid", "false"),
    ] {
        let builder = built(endpoint);
        assert_eq!(
            client_option(&builder, ClientConfigKey::AllowHttp),
            allow_http,
            "{endpoint} must decide allow_http — a dropped or scrambled \
             `.with_allow_http(..)` call reads back as AllowHttp's own \
             default (false) regardless of scheme"
        );
        assert_eq!(
            client_option(&builder, ClientConfigKey::Timeout),
            expected_timeout,
            "{endpoint}: the per-request clock must be DIRECT_STORE_REQUEST_TIMEOUT"
        );
    }
}

/// The retry envelope has no `object_store` config key — unlike
/// `AllowHttp`/`Timeout` above, `RetryConfig` is not one of
/// `AmazonS3ConfigKey`'s variants, and the builder's `retry_config`
/// field is private, so `get_config_value` cannot read it back. The
/// one thing left to ask the builder is its own `Debug` rendering
/// (`object_store` 0.14.1 derives it, `aws/builder.rs:126`) — an
/// unstable string this test does NOT invent a stable contract
/// around: the expected text is one WHOLE `RetryConfig` rendering,
/// produced by the same derive from the same constants, so nothing
/// here is a typed-out literal that could drift from them and the
/// row cannot pass on a partial match. If a future `object_store`
/// upgrade changes the derive's output, the two renderings change
/// together and the row still compares like for like; if it changes
/// the FIELDS, `s3_builder`'s exhaustive struct literals fail to
/// compile first.
///
/// **The failure message prints `expected` ONLY, never the whole
/// builder rendering.** `AmazonS3Builder`'s `derive(Debug)` covers
/// `secret_access_key` and `token` with no redaction. They are
/// `None` on this row today, but [`built`] is now every test's
/// entry point, and a panic message is the one place a credential
/// would be copied into a log without anyone deciding to.
///
/// Dropping `.with_retry(..)` WHOLE is an EQUIVALENT MUTANT here,
/// for the identical reason as the timeout above:
/// `RetryConfig::default()` and `BackoffConfig::default()` already
/// hold these exact figures, so this row checks the effective values
/// the route's client runs on and goes red exactly when a future
/// upgrade moves any one default while the call stays absent —
/// which is what
/// [`the_stated_figures_are_object_stores_own_defaults`] pins
/// separately.
///
/// Dropping ONE FIELD of it is not a mutant this row has to catch:
/// neither struct literal carries a struct-update tail, so a missing
/// field is `E0063` at the call site and never reaches a test.
#[test]
fn the_retry_envelope_reaches_the_builder() {
    let expected = format!(
        "{:?}",
        RetryConfig {
            max_retries: DIRECT_STORE_MAX_RETRIES,
            retry_timeout: DIRECT_STORE_RETRY_BUDGET,
            backoff: BackoffConfig {
                init_backoff: DIRECT_STORE_INIT_BACKOFF,
                max_backoff: DIRECT_STORE_MAX_BACKOFF,
                base: DIRECT_STORE_BACKOFF_BASE,
            },
        }
    );
    assert!(
        format!("{:?}", built("https://s3.example.invalid")).contains(&expected),
        "the builder's retry_config must render as {expected:?}"
    );
}

/// **The doc claim "these five figures ARE `object_store` 0.14.1's
/// own defaults", pinned as code.** Every constant in
/// `direct_deadline.rs` states that in prose, and the whole point of
/// naming them explicitly at the builder is that the route keeps
/// running on THIS file's figures when the dependency's move. A
/// prose claim cannot notice the move; this row can, and it is here
/// rather than beside the constants because `RetryConfig`,
/// `BackoffConfig` and `ClientOptions` are in scope here.
///
/// **A red here is not a failure to fix by editing a number.** It
/// means the dependency moved a default out from under a decision
/// this project made deliberately (stating the default rather than
/// changing it). The answer is to restate the decision — is 30 s
/// still the request clock we want, is 180 s still the budget — and
/// then either keep the figure with the new divergence recorded, or
/// follow the upgrade on purpose. Silently keeping it, or silently
/// following it, are both wrong.
#[test]
fn the_stated_figures_are_object_stores_own_defaults() {
    let retry = RetryConfig::default();
    assert_eq!(retry.retry_timeout, DIRECT_STORE_RETRY_BUDGET);
    assert_eq!(retry.max_retries, DIRECT_STORE_MAX_RETRIES);
    assert_eq!(retry.backoff.max_backoff, DIRECT_STORE_MAX_BACKOFF);
    assert_eq!(retry.backoff.init_backoff, DIRECT_STORE_INIT_BACKOFF);
    assert!(
        (retry.backoff.base - DIRECT_STORE_BACKOFF_BASE).abs() < f64::EPSILON,
        "backoff base: {} is not {DIRECT_STORE_BACKOFF_BASE}",
        retry.backoff.base
    );
    // The client timeout has no public field to read, only the
    // config key — so the comparison is against the SAME key read
    // off a `ClientOptions` this row sets the constant on, exactly
    // as `the_endpoint_scheme_decides_allow_http_and_the_client_clock_is_set`
    // does. `unwrap_or_else` on BOTH sides rather than comparing two
    // `Option`s: a key that stopped resolving would make both
    // `None` and pass a bare `assert_eq!` while checking nothing.
    let stated = ClientOptions::default()
        .with_timeout(DIRECT_STORE_REQUEST_TIMEOUT)
        .get_config_value(&ClientConfigKey::Timeout)
        .unwrap_or_else(|| panic!("a set timeout reads back"));
    let inherited = ClientOptions::default()
        .get_config_value(&ClientConfigKey::Timeout)
        .unwrap_or_else(|| panic!("object_store's own default client timeout reads back"));
    assert_eq!(
        inherited, stated,
        "object_store's own default client timeout must still be DIRECT_STORE_REQUEST_TIMEOUT"
    );
}

// ------------------------------------------------ redirects are never followed

/// What the client did when stub A answered with a redirect.
#[derive(Debug, PartialEq, Eq)]
enum Redirected {
    /// The request returned, and whether it returned an error.
    Returned { failed: bool },
    /// The client opened a connection to the redirect target.
    Followed,
}

/// Which of two futures finished first.
enum First<L, R> {
    Left(L),
    Right(R),
}

/// Polls `left` then `right` in one task, in that fixed order every time, and
/// returns whichever finishes first. `tokio::spawn`, `select!` and `join!` are
/// banned in this crate (the scheduler must decide interleaving), so the stub
/// servers and the client progress together through these two helpers.
async fn first<L: std::future::Future, R: std::future::Future>(
    left: L,
    right: R,
) -> First<L::Output, R::Output> {
    use std::task::Poll;
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    std::future::poll_fn(|cx| {
        if let Poll::Ready(v) = left.as_mut().poll(cx) {
            return Poll::Ready(First::Left(v));
        }
        if let Poll::Ready(v) = right.as_mut().poll(cx) {
            return Poll::Ready(First::Right(v));
        }
        Poll::Pending
    })
    .await
}

/// Polls both futures to completion in one task, `left` first each time.
async fn both<L: std::future::Future, R: std::future::Future>(
    left: L,
    right: R,
) -> (L::Output, R::Output) {
    use std::task::Poll;
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let (mut l, mut r) = (None, None);
    std::future::poll_fn(|cx| {
        if l.is_none()
            && let Poll::Ready(v) = left.as_mut().poll(cx)
        {
            l = Some(v);
        }
        if r.is_none()
            && let Poll::Ready(v) = right.as_mut().poll(cx)
        {
            r = Some(v);
        }
        match (l.take(), r.take()) {
            (Some(a), Some(b)) => Poll::Ready((a, b)),
            (a, b) => {
                l = a;
                r = b;
                Poll::Pending
            }
        }
    })
    .await
}

/// Reads one HTTP/1.1 request head (bounded), lowercased for header matching.
async fn request_head(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 64 * 1024 {
        let n = stream.read(&mut byte).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        head.extend_from_slice(&byte);
    }
    String::from_utf8_lossy(&head).to_lowercase()
}

/// Drives one GET through the production `s3_builder`, with static credentials
/// and a session token, against stub A answering `status` with a `Location`
/// pointing at stub B, or at A itself for a same-origin redirect. Returns A's
/// view of the request and what the client did. A follow is checked FIRST each
/// poll, so a follow that also makes the request fail still reads as a follow.
async fn get_redirected(status: u16, same_origin: bool) -> (String, Redirected) {
    use tokio::io::AsyncWriteExt;
    let a = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a");
    let b = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind b");
    let a_addr = a.local_addr().expect("a addr");
    let target = if same_origin {
        a_addr
    } else {
        b.local_addr().expect("b addr")
    };
    let env = |name: &str| match name {
        ENV_AWS_ACCESS_KEY_ID => Some("AKIDEXAMPLE".to_owned()),
        ENV_AWS_SECRET_ACCESS_KEY => Some("secret".to_owned()),
        ENV_AWS_SESSION_TOKEN => Some("session-token".to_owned()),
        _ => None,
    };
    let store = s3_builder(&format!("http://{a_addr}"), "a-bucket", &env)
        .expect("builder")
        .build()
        .expect("store");
    // A same-origin follow arrives as a SECOND connection to A; A reports it on
    // this channel so the client side ends instead of waiting on an answer.
    let (followed_tx, followed_rx) = tokio::sync::oneshot::channel::<()>();
    // The client side reports it has returned, so A stops waiting for a follow.
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let serve_a = async {
        let (mut stream, _) = a.accept().await.expect("accept on a");
        let head = request_head(&mut stream).await;
        let reply = format!(
            "HTTP/1.1 {status} Redirect\r\nLocation: http://{target}/a-bucket/elsewhere\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(reply.as_bytes()).await.expect("reply");
        if same_origin {
            let second = tokio::time::timeout(std::time::Duration::from_secs(2), a.accept());
            if let First::Left(Ok(_)) = first(second, done_rx).await {
                let _ = followed_tx.send(());
            }
        }
        head
    };
    let followed = async {
        let reported = async {
            if followed_rx.await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        let _ = first(b.accept(), reported).await;
    };
    let path = object_store::path::Path::from("x");
    let client = async {
        let outcome = match first(followed, object_store::ObjectStoreExt::get(&store, &path)).await
        {
            First::Left(()) => Redirected::Followed,
            First::Right(outcome) => Redirected::Returned {
                failed: outcome.is_err(),
            },
        };
        let _ = done_tx.send(());
        outcome
    };
    let (head, outcome) = both(serve_a, client).await;
    // And B's backlog holds no connection, whatever the race above saw.
    // A connection already in B's backlog is only seen once the reactor has
    // delivered B's readiness, which a zero wait does not give it time to do.
    let b_touched = tokio::time::timeout(std::time::Duration::from_millis(100), b.accept())
        .await
        .is_ok();
    let outcome = if b_touched {
        Redirected::Followed
    } else {
        outcome
    };
    (head, outcome)
}

/// A signed direct-S3 request answered with any redirect status fails, and the
/// redirect target is never contacted — cross-origin, where the session token
/// would otherwise travel with it.
#[tokio::test]
async fn a_redirect_is_never_followed_and_the_target_never_contacted() {
    for status in [301_u16, 302, 303, 307, 308] {
        let (head, outcome) = get_redirected(status, false).await;
        assert!(
            head.starts_with("get /a-bucket/x"),
            "{status}: not the GET: {head}"
        );
        assert!(
            head.contains("x-amz-security-token: session-token"),
            "{status}: the request was not signed with the session token: {head}"
        );
        assert_eq!(outcome, Redirected::Returned { failed: true }, "{status}");
    }
}

/// A redirect back to the same origin is refused too: the policy is "never",
/// not "never across origins".
#[tokio::test]
async fn a_same_origin_redirect_is_not_followed_either() {
    let (_, outcome) = get_redirected(307, true).await;
    assert_eq!(outcome, Redirected::Returned { failed: true });
}

/// An ordinary successful GET still works through the no-redirect client, with
/// `object_store`'s user agent and no request for compressed bodies (object
/// sizes come from `Content-Length`). Without this row, a connector that broke
/// every request would pass the two redirect rows above.
#[tokio::test]
async fn an_ordinary_get_succeeds_through_the_no_redirect_client() {
    use tokio::io::AsyncWriteExt;
    let a = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = a.local_addr().expect("addr");
    let store = s3_builder(&format!("http://{addr}"), "a-bucket", &|_| None)
        .expect("builder")
        .with_skip_signature(true)
        .build()
        .expect("store");
    let serve = async {
        let (mut stream, _) = a.accept().await.expect("accept");
        let head = request_head(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nLast-Modified: \
                  Mon, 01 Jan 2024 00:00:00 GMT\r\nETag: \"e\"\r\nConnection: close\r\n\r\nhello",
            )
            .await
            .expect("reply");
        head
    };
    let path = object_store::path::Path::from("x");
    let get = async {
        let result = object_store::ObjectStoreExt::get(&store, &path).await;
        match result {
            Ok(r) => r
                .bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        }
    };
    let (head, body) = both(serve, get).await;
    assert_eq!(body.as_deref(), Ok(&b"hello"[..]), "{head}");
    // The exact version is pinned where the connector lives, by a test that
    // fails on an object_store upgrade (granary-store's `http_client` tests).
    assert!(head.contains("user-agent: object_store/"), "{head}");
    assert!(
        !head.contains("accept-encoding"),
        "compression was requested: {head}"
    );
}

/// The route reports an ambient proxy variable it ignores, by NAME: the
/// warning is emitted, it names the variable, and the value (a proxy URL can
/// carry a credential) appears in no field of any event.
#[test]
fn an_ignored_ambient_proxy_is_reported_by_name_and_never_by_value() {
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt as _;

    /// Every event, every field, as text.
    #[derive(Clone, Default)]
    struct Events(Arc<Mutex<Vec<String>>>);
    struct Fields<'a>(&'a mut String);
    impl tracing::field::Visit for Fields<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={value:?} ", field.name());
        }
    }
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Events {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut text = format!("{} ", event.metadata().level());
            event.record(&mut Fields(&mut text));
            if let Ok(mut events) = self.0.lock() {
                events.push(text);
            }
        }
    }

    const SECRET: &str = "proxy-secret-must-not-print";
    let events = Events::default();
    let env = |name: &str| match name {
        "HTTPS_PROXY" => Some(format!("http://user:{SECRET}@proxy.invalid:3128")),
        _ => None,
    };
    let subscriber = tracing_subscriber::registry().with(events.clone());
    let built = tracing::subscriber::with_default(subscriber, || {
        s3_builder("https://s3.example.invalid", "a-bucket", &env)
    });
    assert!(built.is_ok(), "{:?}", built.err());
    let seen = events.0.lock().map(|e| e.clone()).unwrap_or_default();
    assert!(
        seen.iter()
            .any(|e| e.starts_with("WARN") && e.contains("\"HTTPS_PROXY\"")),
        "no warning named the ignored variable: {seen:?}"
    );
    assert!(
        seen.iter().all(|e| !e.contains(SECRET)),
        "a proxy variable's VALUE reached an event: {seen:?}"
    );
}

#[test]
fn endpoints_reject_userinfo_before_discovery_and_redact_errors() {
    for authority in [
        "SECRET_SENTINEL@host",
        "@host",
        "user:SECRET_SENTINEL@host",
        "a@SECRET_SENTINEL@host",
    ] {
        let endpoint = format!("https://{authority}");
        let server = open_publish_route_with_client_credential(
            &endpoint,
            Some(vec![[1; 32]]),
            false,
            None,
            None,
            &|_| panic!("server discovery"),
        );
        let error = server.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("endpoint userinfo is not permitted")
        );
        assert!(!format!("{error} {error:?}").contains("SECRET_SENTINEL"));
        for scheme in ["http", "https"] {
            let error = s3_builder(&format!("{scheme}://{authority}"), "bucket", &|_| {
                panic!("invalid endpoint reached environment")
            })
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("endpoint userinfo is not permitted")
            );
            assert!(!format!("{error} {error:?}").contains("SECRET_SENTINEL"));
        }
    }
    for endpoint in ["https://host/a@b", "https://HOST:443/a@b"] {
        assert!(
            open_publish_route(endpoint, Some(vec![[1; 32]]), false, None, &|_| panic!(
                "server discovery"
            ))
            .is_ok()
        );
        assert!(s3_builder(endpoint, "bucket", &|_| None).is_ok());
    }
    for endpoint in [
        "SECRET_SENTINEL",
        "https://SECRET_SENTINEL host",
        "ftp://SECRET_SENTINEL",
    ] {
        let error =
            open_publish_route(endpoint, Some(vec![[1; 32]]), false, None, &|_| None).unwrap_err();
        assert!(!format!("{error} {error:?}").contains("SECRET_SENTINEL"));
    }
    for endpoint in [
        "SECRET_SENTINEL",
        "https://SECRET_SENTINEL host",
        "ftp://SECRET_SENTINEL",
    ] {
        let error = s3_builder(endpoint, "bucket", &|_| {
            panic!("invalid endpoint discovery")
        })
        .unwrap_err();
        assert!(!format!("{error} {error:?}").contains("SECRET_SENTINEL"));
    }
}

#[test]
fn server_constructor_has_no_environment_reads_and_refuses_bucket() {
    let route = open_publish_route_with_client_credential(
        "https://host",
        Some(vec![[1; 32]]),
        false,
        None,
        None,
        &|_| panic!("server discovery"),
    )
    .unwrap();
    assert!(matches!(route, PublishRoute::Server(_)));
    assert!(matches!(
        open_publish_route_with_client_credential(
            "https://host",
            Some(vec![[1; 32]]),
            false,
            Some("bucket"),
            None,
            &|_| panic!("bucket discovery")
        ),
        Err(RouteError::ServerBucket)
    ));
}

#[test]
fn userinfo_refusals_are_typed_across_configuration_paths() {
    use crate::http_store::check_base;
    use crate::publication_config::{CredentialContext, publication_scope};
    let context = CredentialContext::new("ctx").unwrap();
    for endpoint in [
        "https://@host",
        "https://SECRET_SENTINEL@host",
        "https://user:SECRET_SENTINEL@host",
        "https://a@b@host",
    ] {
        assert_eq!(check_base(endpoint), Err(HttpStoreError::Userinfo));
        assert!(matches!(
            s3_builder(endpoint, "bucket", &|_| panic!(
                "userinfo reached discovery"
            )),
            Err(RouteError::Http(HttpStoreError::Userinfo))
        ));
        let error = publication_scope(endpoint, &[[1; 32]], &context).unwrap_err();
        assert_eq!(error.to_string(), "endpoint userinfo is not permitted");
        assert!(!format!("{error:?}").contains("SECRET_SENTINEL"));
    }
    assert!(check_base("https://host/a@b").is_ok());
    assert!(publication_scope("https://host/a@b", &[[1; 32]], &context).is_ok());
}

#[test]
fn direct_s3_preserves_idn_and_path_acceptance_while_refusing_authority_userinfo() {
    for endpoint in [
        "https://bücher.example",
        "http://bücher.example/a|b",
        "https://host/a|b",
        "https://host/a@b",
        "https://host?user@value",
        "https://host#user@value",
        "https://host:443/a|b",
        "http://[::1]:9000/a|b",
        "https://[2001:db8::1]",
    ] {
        assert!(
            matches!(
                open_publish_route(endpoint, None, true, Some("bucket"), &|name| match name {
                    ENV_AWS_ACCESS_KEY_ID => Some("test-id".to_owned()),
                    ENV_AWS_SECRET_ACCESS_KEY => Some("test-secret".to_owned()),
                    _ => None,
                }),
                Ok(PublishRoute::DirectS3(_))
            ),
            "{endpoint}"
        );
    }
    for endpoint in [
        "https://user@bücher.example/a|b",
        "http://@host/a|b",
        "https://user@host?query",
        "https://user@host#fragment",
    ] {
        assert!(matches!(
            open_publish_route(endpoint, None, true, Some("bucket"), &|_| {
                panic!("userinfo reached discovery")
            }),
            Err(RouteError::Http(HttpStoreError::Userinfo))
        ));
    }
}

#[test]
fn direct_s3_refuses_empty_and_ascii_whitespace_or_control_authorities() {
    let mut endpoints = Vec::new();
    for scheme in ["http", "https", "HTTP", "HTTPS"] {
        for suffix in ["", "/path", "?q", "#fragment"] {
            endpoints.push(format!("{scheme}://{suffix}"));
        }
        for byte in 0..=127_u8 {
            if byte.is_ascii_whitespace() || byte.is_ascii_control() {
                endpoints.push(format!("{scheme}://host{}name/path", char::from(byte)));
            }
        }
    }
    for endpoint in endpoints {
        let error = s3_builder(&endpoint, "bucket", &|_| {
            panic!("invalid authority reached discovery")
        })
        .unwrap_err();
        assert!(matches!(
            &error,
            RouteError::Endpoint(message) if message == "endpoint must name a host"
        ));
        assert_eq!(error.to_string(), "endpoint: endpoint must name a host");
    }
    // Only authority text is checked, including when a query or fragment ends it.
    for endpoint in ["https://host/a b", "http://host?q= ", "https://host#\t"] {
        assert!(s3_builder(endpoint, "bucket", &|_| None).is_ok());
    }
}
