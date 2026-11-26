// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for `crate::config` — the server's STORE schema
//! and the seam-dispatch deadline.
//!
//! Out-of-line: `granary-server`'s non-test artifact has
//! its own `[[bin]]` (`granary-server`) and its own
//! `tests/` directory (`crates/granary-server/tests/`),
//! so the module's own tests move out of the parent file
//! while it keeps its path and declares `#[cfg(test)]
//! mod tests;` — the sibling-directory form.

use super::{
    ENV_AWS_ACCESS_KEY_ID, ENV_AWS_SECRET_ACCESS_KEY, ENV_AWS_SESSION_TOKEN, ENV_STORE,
    ENV_STORE_BUCKET, ENV_STORE_ENDPOINT, ENV_STORE_REGION, STORE_CLIENT_TIMEOUT,
    STORE_DISPATCH_DEADLINE, STORE_MEMORY, STORE_S3, s3_builder, store_from,
};
use object_store::aws::AmazonS3ConfigKey;
use object_store::{ClientConfigKey, ClientOptions};
use std::time::Duration;

/// A lookup over a fixed table. `std::env::set_var` is `unsafe`
/// under edition 2024 and `unsafe_code` is forbidden workspace-wide,
/// test targets included — so the environment is never written.
fn from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let owned: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |name| {
        owned
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }
}

#[test]
fn unknown_discriminant_is_named() {
    let reason = store_from(&from(&[(ENV_STORE, "disk:")]))
        .err()
        .unwrap_or_else(|| panic!("`disk:` is not a store form this build has"));
    assert!(
        reason.contains(ENV_STORE),
        "the refusal must name the variable at fault: {reason}"
    );
    assert!(
        reason.contains("disk:"),
        "and the value it carried: {reason}"
    );

    let unset = store_from(&from(&[]))
        .err()
        .unwrap_or_else(|| panic!("an unset store form is not a default"));
    assert!(unset.contains(ENV_STORE), "{unset}");
}

#[test]
fn memory_store_has_no_deadline() {
    let config =
        store_from(&from(&[(ENV_STORE, STORE_MEMORY)])).unwrap_or_else(|reason| panic!("{reason}"));
    assert_eq!(
        config.dispatch_deadline, None,
        "an in-process BTreeMap cannot stop answering, and a deadline \
         on it would turn a slow machine into a 503"
    );
}

#[test]
fn s3_store_builds_explicitly_and_has_a_deadline() {
    let config = store_from(&from(&[
        (ENV_STORE, STORE_S3),
        (ENV_STORE_BUCKET, "granary"),
        (ENV_STORE_ENDPOINT, "https://s3.example.invalid"),
        (ENV_STORE_REGION, "us-east-1"),
        (ENV_AWS_ACCESS_KEY_ID, "an-id"),
        (ENV_AWS_SECRET_ACCESS_KEY, "a-secret"),
    ]))
    .unwrap_or_else(|reason| panic!("{reason}"));
    assert_eq!(
        config.dispatch_deadline,
        Some(STORE_DISPATCH_DEADLINE),
        "a network store's dispatch is bounded"
    );
    assert_eq!(STORE_DISPATCH_DEADLINE, Duration::from_secs(30));

    // Each required variable, missing one at a time: the refusal
    // names it rather than inventing a default.
    for missing in [ENV_STORE_BUCKET, ENV_STORE_ENDPOINT, ENV_STORE_REGION] {
        let pairs: Vec<(&str, &str)> = [
            (ENV_STORE, STORE_S3),
            (ENV_STORE_BUCKET, "granary"),
            (ENV_STORE_ENDPOINT, "https://s3.example.invalid"),
            (ENV_STORE_REGION, "us-east-1"),
        ]
        .into_iter()
        .filter(|(k, _)| *k != missing)
        .collect();
        let reason = store_from(&from(&pairs))
            .err()
            .unwrap_or_else(|| panic!("{missing} has no default"));
        assert!(reason.contains(missing), "{reason}");
    }
}

/// The `s3:` environment every row below starts from, so a row that
/// varies one variable is visibly varying one variable.
fn s3_env(endpoint: &'static str) -> Vec<(&'static str, &'static str)> {
    vec![
        (ENV_STORE, STORE_S3),
        (ENV_STORE_BUCKET, "granary"),
        (ENV_STORE_ENDPOINT, endpoint),
        (ENV_STORE_REGION, "us-east-1"),
        (ENV_AWS_ACCESS_KEY_ID, "an-id"),
        (ENV_AWS_SECRET_ACCESS_KEY, "a-secret"),
    ]
}

/// What the builder ended up holding for one client option.
fn client_option(builder: &object_store::aws::AmazonS3Builder, key: ClientConfigKey) -> String {
    builder
        .get_config_value(&AmazonS3ConfigKey::Client(key))
        .unwrap_or_else(|| panic!("the builder holds no value for {key:?}"))
}

/// **The two settings READ BACK OFF THE BUILDER, not off the source.**
///
/// `the_s3_builder_is_explicit_and_never_sweeps_the_environment`
/// below is a text scan, and text is blind to two mutations that
/// change what the store does:
///
/// - ordering `.with_allow_http(..)` BEFORE `.with_client_options(..)`
///   — the latter REPLACES the builder's options wholesale
///   (`aws/builder.rs:1050`), so the flag is silently discarded and
///   an `http://` endpoint is then refused by the store's own scheme
///   check;
/// - rebinding `.with_timeout(..)` onto a `ClientOptions` value that
///   is subsequently dropped, leaving the INHERITED thirty-second
///   default — tying the store-client timeout to the dispatch deadline.
///
/// Both survived every unit row here and were caught only by the
/// thirty-second process test. They are catchable in-crate after all:
/// `AmazonS3Builder::get_config_value` reads client options back
/// through `AmazonS3ConfigKey::Client` (`aws/builder.rs:750`), which
/// is why `s3_builder` is split out of `s3_from` — `build()` erases
/// the settings into an `Arc<dyn ObjectStore>` and nothing can read
/// them after that.
///
/// **The timeout arm compares against BOTH references.** Equal to a
/// `ClientOptions` this row builds with [`STORE_CLIENT_TIMEOUT`], and
/// NOT equal to `ClientOptions::default()`'s — the second half is
/// what makes it detect an inherited default rather than merely
/// agree with itself, and it does not restate the rendering, so a
/// change to how `object_store` formats a duration cannot rot it.
#[test]
fn the_endpoint_scheme_decides_allow_http_and_the_client_clock_is_set() {
    let pinned = ClientOptions::default().with_timeout(STORE_CLIENT_TIMEOUT);
    let pinned = pinned
        .get_config_value(&ClientConfigKey::Timeout)
        .unwrap_or_else(|| panic!("a set timeout reads back"));
    let inherited = ClientOptions::default()
        .get_config_value(&ClientConfigKey::Timeout)
        .unwrap_or_else(|| panic!("object_store 0.14.1 defaults the timeout, not None"));
    assert_ne!(
        pinned, inherited,
        "the pin must differ from the default, or the timeout arm below \
         cannot tell them apart"
    );

    // `allow_http` follows the ENDPOINT'S SCHEME and nothing else,
    // so both schemes are driven — one arm alone passes for a
    // builder that hardcodes either answer.
    for (endpoint, allow_http) in [
        ("http://s3.example.invalid", "true"),
        ("https://s3.example.invalid", "false"),
    ] {
        let builder = s3_builder(&from(&s3_env(endpoint)))
            .unwrap_or_else(|reason| panic!("{endpoint}: {reason}"));
        assert_eq!(
            client_option(&builder, ClientConfigKey::AllowHttp),
            allow_http,
            "{endpoint} must decide allow_http; a `.with_allow_http(..)` \
             call ordered before `.with_client_options(..)` is discarded \
             by the replacement and reads back as the default here"
        );
        assert_eq!(
            client_option(&builder, ClientConfigKey::Timeout),
            pinned,
            "{endpoint}: the store's per-request clock must be the pinned \
             STORE_CLIENT_TIMEOUT and not object_store's inherited \
             {inherited} — at the default it equals STORE_DISPATCH_DEADLINE \
             and the non-retried write paths render 500/internal where \
             §5.10 wants 503/unavailable"
        );
    }
}

/// **The endpoint's SCHEME is validated at startup, and the same
/// comparison decides `allow_http`.**
///
/// `starts_with("http://")` is case-SENSITIVE and matches nothing
/// else, so `HTTP://host`, `hTTp://host` and a schemeless
/// `host:9000` all started a server that then failed every request
/// `500` + `granary-error: internal` — this module's whole contract
/// is that a misconfiguration is refused at startup naming the
/// variable at fault, and those three values got no refusal at all.
///
/// **It failed CLOSED, which is why it is a diagnosis defect rather
/// than a security one**: an unrecognised scheme left `allow_http`
/// off, so a plaintext endpoint was refused by the store rather than
/// silently downgraded. The refusal just arrived per-request, from
/// the wrong layer, without naming anything.
///
/// **Case-insensitive because a URL scheme is** (RFC 3986 §3.1: the
/// scheme is case-insensitive and should be normalised to
/// lowercase). `Url` lowercases it for the store underneath, so
/// `HTTP://` IS a plaintext endpoint there and a case-sensitive
/// derivation here disagreed with the layer that acts on it.
///
/// **The flag is read back OFF THE BUILDER**, for the reason
/// `the_endpoint_scheme_decides_allow_http_and_the_client_clock_is_set`
/// gives: a source scan cannot see which value a call site bound.
#[test]
fn an_endpoint_scheme_is_refused_unless_it_is_http_or_https() {
    // 1 — REFUSED, naming the variable and the value it carried.
    // The wrong-case pair is the defect; the schemeless and unknown
    // forms are the class it belongs to.
    for bad in [
        "s3.example.invalid:9000",
        "ftp://s3.example.invalid",
        "httpx://s3.example.invalid",
        "//s3.example.invalid",
        "http:/s3.example.invalid",
        "https:s3.example.invalid",
    ] {
        let reason = s3_builder(&from(&s3_env(bad)))
            .err()
            .unwrap_or_else(|| panic!("{bad:?} carries no scheme this build can open"));
        assert!(
            reason.contains(ENV_STORE_ENDPOINT),
            "a refusal names the variable at fault: {reason}"
        );
        assert!(
            reason.contains(bad),
            "and the value it carried, or an operator cannot see which \
             of their endpoints is wrong: {reason}"
        );
    }

    // 2 — ACCEPTED in either case, and the SAME comparison decides
    // the flag. `HTTP://` reaching `allow_http == false` is the
    // shipped defect: the store lowercases the scheme, sees `http`,
    // and refuses every request against a flag this file left off.
    for (endpoint, allow_http) in [
        ("http://s3.example.invalid", "true"),
        ("HTTP://s3.example.invalid", "true"),
        ("hTTp://s3.example.invalid", "true"),
        ("https://s3.example.invalid", "false"),
        ("HTTPS://s3.example.invalid", "false"),
        ("HtTpS://s3.example.invalid", "false"),
    ] {
        let builder = s3_builder(&from(&s3_env(endpoint)))
            .unwrap_or_else(|reason| panic!("{endpoint:?}: {reason}"));
        assert_eq!(
            client_option(&builder, ClientConfigKey::AllowHttp),
            allow_http,
            "{endpoint:?} must decide allow_http on a case-INSENSITIVE \
             comparison (RFC 3986 §3.1), through the same match that \
             accepted it — two comparisons drift, and the drift is a \
             server that starts and then refuses every request"
        );
        // AND IT BUILDS. Without this the row is consistent with a
        // widening that only moved the refusal from `500`-per-request
        // to `build()` — still no startup message naming the endpoint,
        // which is the whole contract being repaired.
        let built = store_from(&from(&s3_env(endpoint)))
            .unwrap_or_else(|reason| panic!("{endpoint:?} was accepted, then: {reason}"));
        assert_eq!(built.dispatch_deadline, Some(STORE_DISPATCH_DEADLINE));
    }
}

/// **The three credential variables, including the two no other row
/// reaches.**
///
/// `AWS_SESSION_TOKEN` was never set by any test, the
/// zero-credentials instance-role path was never exercised, and
/// `.filter(|v| !v.is_empty())` treating `AWS_ACCESS_KEY_ID=""` as
/// ABSENT had no row at all — three untested branches on the path
/// that decides whether this server signs its requests with the
/// operator's key or falls through to the store's own provider
/// chain.
///
/// Read back off the builder for the same reason as the row above:
/// after `build()` there is nothing to read.
#[test]
fn credentials_are_read_by_name_and_an_empty_value_is_absent() {
    let endpoint = "https://s3.example.invalid";
    let key = AmazonS3ConfigKey::AccessKeyId;
    let secret = AmazonS3ConfigKey::SecretAccessKey;
    let token = AmazonS3ConfigKey::Token;

    // 1 — all three supplied. The session-token arm exists for
    // STS/instance-role deployments and had no coverage.
    let mut with_token = s3_env(endpoint);
    with_token.push((ENV_AWS_SESSION_TOKEN, "a-session-token"));
    let builder = s3_builder(&from(&with_token)).unwrap_or_else(|reason| panic!("{reason}"));
    assert_eq!(builder.get_config_value(&key).as_deref(), Some("an-id"));
    assert_eq!(
        builder.get_config_value(&secret).as_deref(),
        Some("a-secret")
    );
    assert_eq!(
        builder.get_config_value(&token).as_deref(),
        Some("a-session-token"),
        "AWS_SESSION_TOKEN is read BY NAME; a long-lived key pair has \
         none, which is why it is optional rather than required"
    );

    // 2 — a long-lived pair: the token stays unset rather than
    // becoming an empty string the store would sign with.
    let builder = s3_builder(&from(&s3_env(endpoint))).unwrap_or_else(|reason| panic!("{reason}"));
    assert_eq!(
        builder.get_config_value(&token),
        None,
        "an absent token must not become a present empty one"
    );

    // 3 — INSTANCE ROLE: none of the three supplied. Absent is not
    // an error; the store's own provider chain takes over, and a
    // refusal here would break every deployment that credentials
    // itself from the instance metadata service.
    let bare: Vec<(&str, &str)> = s3_env(endpoint)
        .into_iter()
        .filter(|(name, _)| *name != ENV_AWS_ACCESS_KEY_ID && *name != ENV_AWS_SECRET_ACCESS_KEY)
        .collect();
    let builder = s3_builder(&from(&bare))
        .unwrap_or_else(|reason| panic!("an instance-role deployment supplies none: {reason}"));
    for absent in [&key, &secret, &token] {
        assert_eq!(
            builder.get_config_value(absent),
            None,
            "{absent:?} must be left for the store's provider chain"
        );
    }

    // 4 — EMPTY IS ABSENT. `AWS_ACCESS_KEY_ID=""` is what an unset
    // variable expands to in a shell that exports it anyway, and
    // signing with an empty key id fails at the endpoint with an
    // authentication error rather than falling through to the
    // provider chain. `.filter(|v| !v.is_empty())` is what makes the
    // two the same state; nothing tested it.
    let mut emptied = s3_env(endpoint);
    for slot in &mut emptied {
        if slot.0 == ENV_AWS_ACCESS_KEY_ID || slot.0 == ENV_AWS_SECRET_ACCESS_KEY {
            slot.1 = "";
        }
    }
    emptied.push((ENV_AWS_SESSION_TOKEN, ""));
    let builder = s3_builder(&from(&emptied)).unwrap_or_else(|reason| panic!("{reason}"));
    for empty in [&key, &secret, &token] {
        assert_eq!(
            builder.get_config_value(empty),
            None,
            "{empty:?} set to the empty string must read as ABSENT, not as \
             a credential this server signs with"
        );
    }
}

/// **The `from_env()` sweep hazard, gated mechanically.**
///
/// `AmazonS3Builder::from_env()` reads the whole `AWS_*` /
/// `OBJECT_STORE_*` namespace, so an `AWS_ALLOW_HTTP=true` or an
/// `AWS_SKIP_SIGNATURE=true` left in a deploy environment for some
/// other tool would silently reconfigure this server's transport and
/// its request signing. Nothing about the STORE THAT COMES BACK
/// distinguishes a swept build from an explicit one, so no
/// behavioural row can catch a regression here — the source is the
/// only place the difference is visible.
///
/// **What a text scan is NOT, and where that job now lives.** This
/// row reads presence, never semantics: it can see that
/// `.with_client_options(` appears once and cannot see the ORDER of
/// the calls around it, nor which value a `let` bound. Two mutations
/// that survived every unit row here belong to that blind spot —
/// `.with_allow_http(..)` ordered AHEAD of the replacement (which
/// discards it), and `.with_timeout(..)` rebound onto a
/// `ClientOptions` value that is then dropped. They are now
/// `the_endpoint_scheme_decides_allow_http_and_the_client_clock_is_set`'s
/// job, which reads both settings back off the builder through
/// `AmazonS3ConfigKey::Client` (`aws/builder.rs:750`) in
/// milliseconds; until it existed they were reachable only through
/// the thirty-second process test, and the ordering one only
/// INCIDENTALLY, via a park proof that named the wrong cause. The
/// sweep table below stays a text scan because a swept builder and
/// an explicit one genuinely do read back identically.
#[test]
fn the_s3_builder_is_explicit_and_never_sweeps_the_environment() {
    const SOURCE: &str = include_str!("../config.rs");
    // The PRODUCTION half, comments stripped. Both exclusions are
    // load-bearing: this row's own banned-string table would match
    // itself, and so would the module docs that explain the hazard.
    let production: String = SOURCE
        .split("#[cfg(test)]")
        .next()
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    // Positive control FIRST: a gate that cannot tell "clean" from
    // "read nothing" is not a gate.
    assert!(
        production.contains("AmazonS3Builder::new()"),
        "this row did not read the code it is judging"
    );
    assert!(
        !production.contains("mod tests"),
        "the split kept the test module, so the table below matches itself"
    );

    for swept in [
        "AmazonS3Builder::from_env",
        "aws_skip_signature",
        "AWS_SKIP_SIGNATURE",
        "AWS_ALLOW_HTTP",
        // `ClientOptions` carries the transport half — timeouts,
        // proxies, certificate trust, `allow_http`. `with_config`
        // takes a `ClientConfigKey` and is the same widening as the
        // builder's; `from_env` does not exist on this type at
        // 0.14.1 (verified 2026-08-19: `src/client/mod.rs` contains
        // no `env::var` at all) and the row is here so a version
        // that adds one cannot arrive quietly.
        "ClientOptions::from_env",
        "with_config",
    ] {
        assert!(
            !production.contains(swept),
            "{swept:?} would let the ambient environment decide this \
             server's transport or its request signing"
        );
    }
    // And `allow_http` is derived from the endpoint, once, through
    // the comparison that validated it.
    assert_eq!(
        production.matches(".with_allow_http(").count(),
        1,
        "one site, or the derivation is not the only route"
    );
    assert!(production.contains(".with_allow_http(allow_http)"));
    assert_eq!(
        production.matches("fn scheme_allows_http").count(),
        1,
        "one derivation, so the flag and the startup refusal cannot \
         be decided by different comparisons"
    );
    assert!(
        !production.contains("starts_with(SCHEME_HTTP)")
            && !production.contains(r#"starts_with("http"#),
        "a case-SENSITIVE scheme comparison is the defect: RFC 3986 §3.1 \
         makes the scheme case-insensitive, `Url` lowercases it for the \
         store, and `HTTP://host` then reached the store as plaintext \
         with allow_http off"
    );

    // **The pinned client timeout, gated the same way and for the
    // same reason.** Nothing about the `Arc<dyn ObjectStore>` that
    // comes back says what its per-request clock is, so no
    // behavioural row in this crate can tell an inherited default
    // from a pinned value — the process test in
    // `tests/shipped_store_config.rs` is the behavioural half, and it
    // costs a thirty-second stall to run. This is the source half.
    assert!(
        production.contains(".with_timeout(STORE_CLIENT_TIMEOUT)"),
        "the store's own request clock must be SET here, not inherited: \
         at object_store 0.14.1's default it equals \
         STORE_DISPATCH_DEADLINE and the non-retried write paths then \
         render 500/internal where §5.10 wants \
         503/unavailable"
    );
    assert_eq!(
        production.matches(".with_client_options(").count(),
        1,
        "`with_client_options` REPLACES the builder's options wholesale \
         (aws/builder.rs:1050), so a second site would silently discard \
         the first — `allow_http` included"
    );
}

/// **The dispatch deadline owns the refusal token, and this is the arithmetic.**
///
/// The RELATION is gated at compile time by the `const _` next to
/// the constants — a build cannot produce an inverted pair. What
/// this row adds is the two FIGURES, so a change to either is a
/// deliberate edit here rather than a silent slide, and the
/// measurement that fixed them stays attached to a runnable thing.
#[test]
#[expect(
    clippy::duration_suboptimal_units,
    reason = "the two figures are pinned in the SAME unit, which is the \
              whole readability of the pair"
)]
fn the_store_clients_clock_sits_above_the_dispatch_deadline() {
    assert_eq!(STORE_DISPATCH_DEADLINE, Duration::from_secs(30));
    assert_eq!(STORE_CLIENT_TIMEOUT, Duration::from_secs(60));
    assert!(
        STORE_CLIENT_TIMEOUT > STORE_DISPATCH_DEADLINE,
        "below the deadline the store's own clock decides the wire \
         status instead of ours, and on the non-retried write paths \
         that status is 500/internal"
    );
}

// ------------------------------------------------ the store never follows a redirect

/// Which of two futures finished first, polled in one task (the crate bans
/// `tokio::spawn`, and a fixed poll order keeps the witness deterministic).
enum First<L, R> {
    Left(L),
    Right(R),
}

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

/// The whole exchange must finish inside this, or the row FAILS: a hang is
/// never read as "did not follow".
const WITNESS_BOUND: Duration = Duration::from_secs(20);

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

#[derive(Debug, PartialEq, Eq)]
enum Redirected {
    /// The redirect target was contacted.
    Followed,
    /// The GET returned without contacting the target.
    Returned { failed: bool },
}

/// The server's `s3:` environment against a local endpoint, signed with a
/// session token: what the deployed path holds.
fn signed_env(endpoint: &str) -> impl Fn(&str) -> Option<String> {
    let endpoint = endpoint.to_owned();
    move |name| {
        match name {
            ENV_STORE => Some(STORE_S3),
            ENV_STORE_BUCKET => Some("granary"),
            ENV_STORE_ENDPOINT => Some(endpoint.as_str()),
            ENV_STORE_REGION => Some("us-east-1"),
            ENV_AWS_ACCESS_KEY_ID => Some("AKIDEXAMPLE"),
            ENV_AWS_SECRET_ACCESS_KEY => Some("secret"),
            ENV_AWS_SESSION_TOKEN => Some("session-token"),
            _ => None,
        }
        .map(str::to_owned)
    }
}

/// One GET through the server's own `store_from`, against stub A answering
/// `status` with a `Location` naming stub B, or A itself for a same-origin
/// redirect. Returns A's view of the request and what the store did. A follow
/// is checked FIRST each poll, so a follow that then fails still reads as a
/// follow; and B's backlog is checked after, whatever that race saw.
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
    let store = store_from(&signed_env(&format!("http://{a_addr}")))
        .unwrap_or_else(|reason| panic!("{reason}"))
        .store;
    // A same-origin follow arrives as a SECOND connection to A; A reports it
    // here so the store side ends instead of waiting on an answer.
    let (followed_tx, followed_rx) = tokio::sync::oneshot::channel::<()>();
    // The store side reports it has returned, so A stops waiting for a follow.
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let serve_a = async {
        let (mut stream, _) = a.accept().await.expect("accept on a");
        let head = request_head(&mut stream).await;
        let reply = format!(
            "HTTP/1.1 {status} Redirect\r\nLocation: http://{target}/granary/elsewhere\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(reply.as_bytes()).await.expect("reply");
        if same_origin && let First::Left(_) = first(a.accept(), done_rx).await {
            let _ = followed_tx.send(());
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
    let get = async {
        let outcome = match first(followed, object_store::ObjectStoreExt::get(&*store, &path)).await
        {
            First::Left(()) => Redirected::Followed,
            First::Right(outcome) => Redirected::Returned {
                failed: outcome.is_err(),
            },
        };
        let _ = done_tx.send(());
        outcome
    };
    let (head, outcome) = tokio::time::timeout(WITNESS_BOUND, both(serve_a, get))
        .await
        .unwrap_or_else(|_| panic!("{status}: the exchange did not finish in {WITNESS_BOUND:?}"));
    // A connection already in B's backlog is only seen once the reactor has
    // delivered B's readiness, which a zero wait does not give it time to do.
    let b_touched = tokio::time::timeout(Duration::from_millis(100), b.accept())
        .await
        .is_ok();
    let outcome = if b_touched {
        Redirected::Followed
    } else {
        outcome
    };
    (head, outcome)
}

/// A signed store request answered with any redirect status fails, and the
/// target is never contacted: the session token stays with the endpoint the
/// operator configured.
#[tokio::test]
async fn the_store_never_follows_a_redirect_and_never_contacts_the_target() {
    for status in [301_u16, 302, 303, 307, 308] {
        let (head, outcome) = get_redirected(status, false).await;
        assert!(
            head.starts_with("get /granary/x"),
            "{status}: not the GET: {head}"
        );
        assert!(
            head.contains("x-amz-security-token: session-token"),
            "{status}: the request was not signed with the session token: {head}"
        );
        assert_eq!(outcome, Redirected::Returned { failed: true }, "{status}");
    }
}

/// The policy is "never", not "never across origins".
#[tokio::test]
async fn the_store_does_not_follow_a_same_origin_redirect_either() {
    let (_, outcome) = get_redirected(307, true).await;
    assert_eq!(outcome, Redirected::Returned { failed: true });
}

/// The control for the two rows above: an ordinary signed GET through the same
/// configuration still returns its body, so a connector that broke every
/// request cannot pass them.
#[tokio::test]
async fn an_ordinary_store_get_still_succeeds() {
    use tokio::io::AsyncWriteExt;
    let a = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = a.local_addr().expect("addr");
    let store = store_from(&signed_env(&format!("http://{addr}")))
        .unwrap_or_else(|reason| panic!("{reason}"))
        .store;
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
        match object_store::ObjectStoreExt::get(&*store, &path).await {
            Ok(r) => r
                .bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        }
    };
    let (head, body) = tokio::time::timeout(WITNESS_BOUND, both(serve, get))
        .await
        .unwrap_or_else(|_| panic!("the exchange did not finish in {WITNESS_BOUND:?}"));
    assert_eq!(body.as_deref(), Ok(&b"hello"[..]), "{head}");
    assert!(
        head.contains("x-amz-security-token: session-token"),
        "{head}"
    );
}

/// With no static credentials the store takes instance credentials, and
/// `build()` connects a second client for the metadata endpoint with that
/// endpoint's own overrides of the server's options. Both pass the connector,
/// or startup would refuse: `connect` runs inside `build()`.
#[test]
fn the_server_options_and_their_metadata_overrides_pass_the_connector_at_startup() {
    for endpoint in ["https://s3.example.invalid", "http://127.0.0.1:9"] {
        let pairs: Vec<(&str, &str)> = s3_env(endpoint)
            .into_iter()
            .filter(|(k, _)| *k != ENV_AWS_ACCESS_KEY_ID && *k != ENV_AWS_SECRET_ACCESS_KEY)
            .collect();
        if let Err(reason) = store_from(&from(&pairs)) {
            panic!("{endpoint}: {reason}");
        }
    }
}

/// The S3 form reports the ambient proxy variables it ignores, by name, for
/// startup to log; the memory form makes no network call and reports none.
#[test]
fn the_s3_form_reports_ignored_ambient_proxy_variables_by_name() {
    let mut pairs = s3_env("https://s3.example.invalid");
    pairs.push(("HTTPS_PROXY", "http://user:secret@proxy.invalid:3128"));
    pairs.push(("no_proxy", "169.254.169.254"));
    let config = store_from(&from(&pairs)).unwrap_or_else(|reason| panic!("{reason}"));
    assert_eq!(config.ignored_proxy_variables, ["HTTPS_PROXY"]);
    let memory = store_from(&from(&[
        (ENV_STORE, STORE_MEMORY),
        ("HTTP_PROXY", "http://p"),
    ]))
    .unwrap_or_else(|reason| panic!("{reason}"));
    assert!(memory.ignored_proxy_variables.is_empty());
}
