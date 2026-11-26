// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::http_client`. The redirect behaviour itself is
//! tested end to end through each caller's own builder: the client's
//! `route/tests.rs` and the server's `config/tests.rs`.

use std::time::Duration;

use object_store::{ClientConfigKey, ClientOptions};

use super::*;

#[test]
fn durations_in_object_stores_printed_form_parse() {
    for (text, want) in [
        ("30s", Duration::from_secs(30)),
        ("5s", Duration::from_secs(5)),
        ("1s 500ms", Duration::from_millis(1500)),
        ("2m", Duration::from_mins(2)),
        ("1h 1m 1s", Duration::from_secs(3661)),
        ("250us", Duration::from_micros(250)),
        ("1day 2h", Duration::from_hours(26)),
    ] {
        assert_eq!(parse_duration(text), Ok(want), "{text}");
    }
}

#[test]
fn a_duration_this_parser_cannot_read_is_refused_not_guessed() {
    for text in [
        "",
        "30",
        "s",
        "30 s",
        "1.5s",
        "30sec",
        "-1s",
        "30s,",
        "213503982334602days",
        "18446744073709551615s 1s",
    ] {
        assert!(parse_duration(text).is_err(), "{text:?} was accepted");
    }
}

/// The option sets `object_store` passes: a caller's own (a request timeout
/// over the defaults), and the metadata endpoint's overrides of it (plain HTTP,
/// a one-second connect timeout). Both must build. Each caller's exact options
/// are also built through its own builder, in its own tests.
#[test]
fn a_callers_options_and_the_metadata_overrides_both_build() {
    let caller = ClientOptions::default().with_timeout(Duration::from_secs(30));
    assert!(client(&caller).is_ok(), "{:?}", client(&caller).err());
    let metadata = caller
        .clone()
        .with_allow_http(true)
        .with_connect_timeout(Duration::from_secs(1));
    assert!(client(&metadata).is_ok(), "{:?}", client(&metadata).err());
}

/// An option the connector does not reproduce is refused, naming it, rather
/// than silently dropped.
#[test]
fn an_option_this_connector_does_not_apply_is_refused_by_name() {
    for (key, value) in [
        (ClientConfigKey::ProxyUrl, "http://proxy.invalid:3128"),
        (ClientConfigKey::AllowInvalidCertificates, "true"),
        (ClientConfigKey::Http2Only, "true"),
        (ClientConfigKey::UserAgent, "someone-else/1.0"),
        (ClientConfigKey::ReadTimeout, "10s"),
    ] {
        let options = ClientOptions::default().with_config(key, value);
        let reason = client(&options).expect_err("an unsupported option must refuse");
        assert!(reason.contains(&format!("{key:?}")), "{reason}");
    }
}

/// Every `ClientConfigKey` `object_store` 0.14.1 defines is either applied by
/// this connector, ignored by design, or refused when set — and each refused
/// key really refuses. A key on none of the three lists is one the connector
/// would drop in silence. (`ClientConfigKey` is `#[non_exhaustive]`, so this
/// list is restated on an `object_store` upgrade — see the module doc.)
#[test]
fn every_client_option_is_applied_ignored_by_design_or_refused() {
    use ClientConfigKey as K;
    let applied = [K::AllowHttp, K::Timeout, K::ConnectTimeout, K::Http1Only];
    // Not client settings (content type) or a documented loss (DNS shuffle).
    let ignored = [K::DefaultContentType, K::RandomizeAddresses];
    let every = [
        K::AllowHttp,
        K::AllowInvalidCertificates,
        K::NoSystemCertificates,
        K::ConnectTimeout,
        K::DefaultContentType,
        K::Http1Only,
        K::Http2KeepAliveInterval,
        K::Http2KeepAliveTimeout,
        K::Http2KeepAliveWhileIdle,
        K::Http2MaxFrameSize,
        K::Http2Only,
        K::PoolIdleTimeout,
        K::PoolMaxIdlePerHost,
        K::ProxyUrl,
        K::ProxyCaCertificate,
        K::ProxyExcludes,
        K::RandomizeAddresses,
        K::ReadTimeout,
        K::Timeout,
        K::UserAgent,
    ];
    for key in every {
        let places = usize::from(applied.contains(&key))
            + usize::from(ignored.contains(&key))
            + usize::from(UNSUPPORTED.iter().any(|(k, _)| *k == key));
        assert_eq!(places, 1, "{key:?} is on {places} lists, not exactly one");
    }
    for (key, default) in UNSUPPORTED {
        let set = match default {
            "false" => "true",
            _ if matches!(key, K::PoolMaxIdlePerHost | K::Http2MaxFrameSize) => "7",
            _ if format!("{key:?}").contains("Timeout")
                || format!("{key:?}").contains("Interval") =>
            {
                "10s"
            }
            _ => "http://x.invalid",
        };
        let options = ClientOptions::default().with_config(key, set);
        let reason = client(&options).expect_err("a refused option must refuse");
        assert!(reason.contains(&format!("{key:?}")), "{key:?}: {reason}");
    }
}

/// The lists above, `UNSUPPORTED` and `USER_AGENT` are all stated for one
/// `object_store` version, and `ClientConfigKey` is `#[non_exhaustive]`, so a
/// key an upgrade adds would fall on no list and be dropped without an error.
/// This row fails on any other locked version, so an upgrade cannot land
/// without the re-read the module doc asks for: restate the lists and the user
/// agent, then this version.
#[test]
fn the_connector_is_stated_for_the_locked_object_store_version() {
    const LOCK: &str = include_str!("../../../../Cargo.lock");
    let versions: Vec<&str> = LOCK
        .split("[[package]]")
        .filter(|block| block.contains("\nname = \"object_store\"\n"))
        .filter_map(|block| {
            block
                .lines()
                .find_map(|l| l.strip_prefix("version = \""))
                .and_then(|v| v.strip_suffix('"'))
        })
        .collect();
    assert_eq!(
        versions,
        ["0.14.1"],
        "object_store is not locked at exactly the version this connector was \
         written against: re-read ClientOptions::client and the ClientConfigKey \
         list, restate UNSUPPORTED and USER_AGENT, then this row"
    );
    assert_eq!(USER_AGENT, "object_store/0.14.1");
}

/// No ambient proxy matcher is installed. reqwest's `Client` Debug output lists
/// `proxies` exactly when a matcher is installed, and without `no_proxy` the
/// ambient one always is, whatever the environment holds, so this needs no
/// environment writes. The control is a plain default builder, whose only
/// matcher is that ambient one: it must show `proxies`, so a change to
/// reqwest's Debug output, or to its default, cannot make the first assertion
/// pass vacuously.
#[test]
fn the_client_installs_no_ambient_proxy() {
    let ours = format!(
        "{:?}",
        client(&ClientOptions::default()).expect("the default options build")
    );
    assert!(
        !ours.contains("proxies"),
        "a proxy matcher is installed: {ours}"
    );
    let ambient_only = format!(
        "{:?}",
        reqwest::Client::builder()
            .build()
            .expect("a default client")
    );
    assert!(
        ambient_only.contains("proxies"),
        "POSITIVE CONTROL FAILED: a default client's ambient matcher does not show in \
         Debug, so the row above cannot see one: {ambient_only}"
    );
}

/// The report names what is set and never returns a value.
#[test]
fn ambient_proxy_variables_are_reported_by_name_only() {
    let env = |name: &str| match name {
        "HTTPS_PROXY" => Some("http://user:secret@proxy.invalid:3128".to_owned()),
        "http_proxy" => Some("http://proxy.invalid".to_owned()),
        "ALL_PROXY" => Some(String::new()),
        _ => None,
    };
    assert_eq!(ambient_proxy_variables(&env), ["HTTPS_PROXY", "http_proxy"]);
    assert!(ambient_proxy_variables(&|_| None).is_empty());
}
