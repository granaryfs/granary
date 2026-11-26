// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use super::*;
use granary_net::config::render_tls_pin;
use granary_net::credential::PemRefusal;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;

fn args(extra: &[&str]) -> Vec<OsString> {
    [
        "store",
        "src",
        "vol",
        "--endpoint",
        "https://host",
        "--key-seed",
        "seed",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(OsString::from)
    .collect()
}
fn parse(extra: &[&str]) -> Result<PublishConfiguration, String> {
    let mut config = PublishConfiguration::default();
    crate::parse_publish_options(&args(extra), &|_| None, &mut config)?;
    Ok(config)
}

#[test]
fn scalar_last_wins_publishers_accumulate_and_every_occurrence_validates() {
    let pin = render_tls_pin(&[1; 32]);
    let a = granary_store::crypto::SigningKey::from_seed(&[1; 32]).unwrap();
    let b = granary_store::crypto::SigningKey::from_seed(&[2; 32]).unwrap();
    let render = |key: &[u8; 32]| {
        use std::fmt::Write as _;
        let mut value = "ed25519:".to_owned();
        for byte in key {
            write!(value, "{byte:02x}").unwrap();
        }
        value
    };
    let config = parse(&[
        "--pin",
        &pin,
        "--client-cert",
        "first",
        "--client-cert",
        "last",
        "--client-key",
        "old",
        "--client-key",
        "new",
        "--credential-context",
        "old",
        "--credential-context",
        "New",
        "--publisher-key",
        &render(b.public_key()),
        "--publisher-key",
        &render(a.public_key()),
    ])
    .unwrap();
    assert_eq!(config.certificate, Some(PathBuf::from("last")));
    assert_eq!(config.key, Some(PathBuf::from("new")));
    assert_eq!(config.context.unwrap().as_str(), "New");
    assert_eq!(config.publishers.build(*a.public_key()).unwrap().len(), 2);
    assert!(
        parse(&[
            "--pin",
            &pin,
            "--credential-context",
            "bad value",
            "--credential-context",
            "good"
        ])
        .is_err()
    );
    assert!(
        parse(&[
            "--pin",
            &pin,
            "--client-cert",
            "",
            "--client-cert",
            "good",
            "--client-key",
            "key"
        ])
        .is_err()
    );
}

#[test]
fn new_flags_refuse_missing_or_flag_shaped_values() {
    let pin = render_tls_pin(&[1; 32]);
    for flag in FLAGS {
        for value in [None, Some("--pin"), Some("-x")] {
            let mut extra = vec!["--pin", &pin, flag];
            if let Some(value) = value {
                extra.push(value);
            }
            assert_eq!(parse(&extra).unwrap_err(), format!("{flag} needs a value"));
        }
    }
}

#[test]
fn half_pairs_and_direct_s3_options_refuse() {
    let pin = render_tls_pin(&[1; 32]);
    for flag in ["--client-cert", "--client-key"] {
        assert_eq!(
            parse(&["--pin", &pin, flag, "file"]).unwrap_err(),
            "--client-cert and --client-key must be supplied together"
        );
        assert_eq!(
            parse(&["--pin", &pin, flag, ""]).unwrap_err(),
            format!("{flag} needs a nonempty file path")
        );
    }
    let publisher = format!("ed25519:{}", "ab".repeat(32));
    for (flag, value) in [
        ("--client-cert", "cert"),
        ("--client-key", "key"),
        ("--credential-context", "context"),
        ("--publisher-key", &publisher),
    ] {
        assert_eq!(
            parse(&["--direct-s3", "--bucket", "b", flag, value]).unwrap_err(),
            format!("{flag} is available only on the server route")
        );
    }
    assert!(parse(&["--pin", &pin, "--credential-context", "context"]).is_ok());
    assert!(
        parse(&[
            "--pin",
            &pin,
            "--client-cert",
            "cert",
            "--client-key",
            "key"
        ])
        .is_ok()
    );
}

#[test]
fn native_paths_and_utf8_only_names() {
    let mut config = PublishConfiguration::default();
    let native = OsString::from_vec(vec![0xff]);
    for flag in ["--client-cert", "--client-key"] {
        config.option(flag, Some(&native)).unwrap();
    }
    assert!(config.validate(false).is_ok());
    for flag in ["--credential-context", "--publisher-key"] {
        assert!(config.option(flag, Some(&native)).is_err());
    }
}

#[test]
fn pin_precedence_callback_and_input_cap_are_preserved() {
    let pin = render_tls_pin(&[1; 32]);
    let parsed = crate::parse_publish_options(
        &args(&["--pin", &pin, "--credential-context", "ctx"]),
        &|_| panic!("explicit pins must prevent discovery"),
        &mut PublishConfiguration::default(),
    )
    .unwrap();
    assert_eq!(parsed.tls_pins, Some(vec![[1; 32]]));
    for fallback in ["", " "] {
        let error = crate::parse_publish_options(
            &args(&[]),
            &|name| {
                assert_eq!(name, "GRANARY_TLS_PINS");
                Some(fallback.to_owned())
            },
            &mut PublishConfiguration::default(),
        )
        .unwrap_err();
        assert!(error.contains("names no pins"));
    }
    for pins in [render_tls_pin(&[0; 32]), [pin.as_str(); 9].join(",")] {
        assert!(parse(&["--pin", &pins]).is_err());
    }
    let parsed = crate::parse_publish_options(
        &args(&[]),
        &|name| {
            assert_eq!(name, "GRANARY_TLS_PINS");
            Some(pin.clone())
        },
        &mut PublishConfiguration::default(),
    )
    .unwrap();
    assert_eq!(parsed.tls_pins, Some(vec![[1; 32]]));
    assert_eq!(
        crate::parse_publish_options(
            &args(&["--direct-s3", "--bucket", "b"]),
            &|_| Some(pin.clone()),
            &mut PublishConfiguration::default(),
        )
        .unwrap_err(),
        "--pin (or GRANARY_TLS_PINS) and --direct-s3 are two different trust models; choose one"
    );
}

#[test]
fn activated_options_are_accepted_by_operational_dispatch() {
    let pin = render_tls_pin(&[1; 32]);
    let parsed = crate::tests::parse_publish(
        &args(&[
            "--pin",
            &pin,
            "--client-cert",
            "cert",
            "--client-key",
            "key",
            "--credential-context",
            "writer",
        ]),
        &|_| None,
    )
    .unwrap();
    assert!(parsed.configuration.certificate.is_some());
    for option in ["--SECRET_SENTINEL", "--SECRET_SENTINEL=value"] {
        assert_eq!(
            crate::tests::parse_publish(&args(&[option]), &|_| None).unwrap_err(),
            "unknown publish option"
        );
    }
}

#[test]
fn cli_refusals_and_debug_do_not_relay_secrets() {
    use std::io::Write as _;
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .args([
            "--exact",
            "publish_config::tests::credential_refusal_output_probe",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    for bytes in [output.stdout, output.stderr] {
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("SECRET_SENTINEL"));
        assert!(text.contains("client credential key content is invalid"));
    }

    let sentinel = "SECRET_SENTINEL";
    let content = ContentError::Key(PemRefusal::UnknownBlock {
        block: 1,
        label: sentinel.to_owned(),
    });
    let error = CredentialError::Content {
        certificate: PathBuf::from(sentinel),
        key: PathBuf::from(sentinel),
        error: Box::new(content),
    };
    let refusal = CredentialRefusal::from_error(&error);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    writeln!(stderr, "gran publish: {refusal}").unwrap();
    write!(stdout, "{refusal:?}").unwrap();
    for bytes in [stdout, stderr] {
        assert!(!String::from_utf8(bytes).unwrap().contains(sentinel));
    }
    assert_eq!(
        refusal.to_string(),
        "client credential key content is invalid"
    );
    let mut config = PublishConfiguration::default();
    config
        .option("--client-cert", Some(OsStr::new(sentinel)))
        .unwrap();
    config
        .option("--client-key", Some(OsStr::new(sentinel)))
        .unwrap();
    assert!(!format!("{config:?}").contains(sentinel));
    assert_eq!(
        config.load(0).unwrap_err().to_string(),
        "client credential certificate file could not be loaded"
    );
    for (file, expected) in [
        (
            CredentialFile::Certificate,
            "client credential certificate file could not be loaded",
        ),
        (
            CredentialFile::Key,
            "client credential key file could not be loaded or failed custody",
        ),
    ] {
        let error = CredentialError::File {
            file,
            path: sentinel.into(),
            reason: sentinel.into(),
        };
        assert_eq!(CredentialRefusal::from_error(&error).to_string(), expected);
    }
}

#[test]
fn new_option_bytes_never_panic() {
    for flag in FLAGS {
        for byte in 0..=255u8 {
            let value = OsString::from_vec(vec![byte; 256]);
            let _ = PublishConfiguration::default().option(flag, Some(&value));
        }
    }
}

#[test]
fn credential_refusal_output_probe() {
    let error = CredentialError::Content {
        certificate: PathBuf::from("SECRET_SENTINEL"),
        key: PathBuf::from("SECRET_SENTINEL"),
        error: Box::new(ContentError::Key(PemRefusal::UnknownBlock {
            block: 1,
            label: "SECRET_SENTINEL".to_owned(),
        })),
    };
    let refusal = CredentialRefusal::from_error(&error);
    println!("{refusal:?}");
    eprintln!("{refusal}");
}

#[test]
fn parsed_publish_debug_redacts_unvalidated_endpoint_and_paths() {
    let pin = render_tls_pin(&[1; 32]);
    let mut config = PublishConfiguration::default();
    let parsed = crate::parse_publish_options(
        &args(&[
            "--pin",
            &pin,
            "--endpoint",
            "https://SECRET_SENTINEL@host",
            "--key-seed",
            "KEY_SENTINEL",
            "--client-cert",
            "CERT_SENTINEL",
            "--client-key",
            "PEM_SENTINEL",
            "--credential-context",
            "CONTEXT_SENTINEL",
        ]),
        &|_| panic!("explicit pins must prevent discovery"),
        &mut config,
    )
    .unwrap();
    let text = format!("{parsed:?} {config:?}");
    for sentinel in [
        "SECRET_SENTINEL",
        "KEY_SENTINEL",
        "CERT_SENTINEL",
        "PEM_SENTINEL",
        "CONTEXT_SENTINEL",
    ] {
        assert!(!text.contains(sentinel));
    }
    let error =
        granary_client::open_publish_route(&parsed.endpoint, parsed.tls_pins, false, None, &|_| {
            panic!("server discovery")
        })
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("endpoint userinfo is not permitted")
    );
    assert!(!format!("{error} {error:?}").contains("SECRET_SENTINEL"));
}

#[test]
fn pin_errors_keep_verifier_details_and_existing_refusal_order() {
    let pin = render_tls_pin(&[1; 32]);
    let many = [pin.as_str(); 9].join(",");
    let zero = render_tls_pin(&[0; 32]);
    for (pins, expected) in [
        (
            many.as_str(),
            "tls pin set: pin set has 9 entries, more than 8",
        ),
        (
            zero.as_str(),
            "tls pin set: pin set contains the all-zero digest",
        ),
    ] {
        assert_eq!(parse(&["--pin", pins]).unwrap_err(), expected);
        assert_eq!(
            parse(&["--pin", pins, "--direct-s3", "--bucket", "b"]).unwrap_err(),
            "--pin (or GRANARY_TLS_PINS) and --direct-s3 are two different trust models; choose one"
        );
        assert_eq!(
            parse(&["--pin", pins, "--bucket", "b"]).unwrap_err(),
            "--pin (or GRANARY_TLS_PINS) publishes THROUGH a granary server, which never names a bucket, and --bucket names one; choose one — drop --bucket, or opt out to the bucket with --direct-s3 --bucket <name>"
        );
    }
    for (fallback, expected) in [
        (many, "tls pin set: pin set has 9 entries, more than 8"),
        (zero, "tls pin set: pin set contains the all-zero digest"),
    ] {
        assert_eq!(
            crate::parse_publish_options(
                &args(&[]),
                &|_| Some(fallback.clone()),
                &mut PublishConfiguration::default(),
            )
            .unwrap_err(),
            expected
        );
    }
}

#[test]
fn known_options_consume_values_and_unknown_options_refuse_without_a_value() {
    let pin = render_tls_pin(&[1; 32]);
    for flag in [
        "--endpoint",
        "--bucket",
        "--key-seed",
        "--cache-dir",
        "--wire-snapshot",
        "--wire-run-id",
        "--wire-role",
        "--pin",
    ] {
        assert_eq!(
            parse(&["--pin", &pin, flag]).unwrap_err(),
            format!("{flag} needs a value")
        );
    }
    for extra in [
        vec!["--UNKNOWN_SENTINEL"],
        vec!["--UNKNOWN_SENTINEL", "value"],
    ] {
        assert_eq!(parse(&extra).unwrap_err(), "unknown publish option");
    }
    // Existing flags still accept flag-shaped values; new flags refuse them.
    let mut configuration = PublishConfiguration::default();
    let parsed = crate::parse_publish_options(
        &args(&["--pin", &pin, "--key-seed", "--flag-shaped"]),
        &|_| None,
        &mut configuration,
    )
    .unwrap();
    assert_eq!(parsed.key_seed, PathBuf::from("--flag-shaped"));
}
