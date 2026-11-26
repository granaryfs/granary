// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for `crate::config::authority`: the authority's
//! configuration, every refusal and the one accepted shape.
//!
//! The environment is never written: `std::env::set_var` is `unsafe`
//! under edition 2024 and `unsafe_code` is forbidden workspace-wide, so
//! every row drives [`authority_from`] through a fixed lookup table.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::path::PathBuf;

use granary_core::root::{VolumeName, is_reserved_volume_name};

use super::{
    AUTHORITY_SINGLE_PROCESS, AuthorityConfig, ENV_ACCEPT_UNSUPPORTED_FILESYSTEM, ENV_AUTHORITY,
    ENV_CLIENT_CA, ENV_ENROLLMENT_DIR, ENV_STATE_DIR, ENV_VOLUMES, MAX_PUBLISHER_KEYS,
    MAX_VALUE_BYTES, MAX_VOLUMES, authority_from, publisher_keys_variable,
};

/// The four names the predicate requires.
const REQUIRED: [&str; 4] = [
    ENV_STATE_DIR,
    ENV_ENROLLMENT_DIR,
    ENV_CLIENT_CA,
    ENV_VOLUMES,
];

/// Every fixed name: the set that must be unset without the predicate.
const FIXED: [&str; 5] = [
    ENV_STATE_DIR,
    ENV_ENROLLMENT_DIR,
    ENV_CLIENT_CA,
    ENV_VOLUMES,
    ENV_ACCEPT_UNSUPPORTED_FILESYSTEM,
];

/// The derived name for the volume `alpha`.
const ALPHA_KEYS: &str = "GRANARY_AUTHORITY_VOLUME_ALPHA_PUBLISHER_KEYS";

/// A well-formed key whose 32 bytes are all `byte`.
fn key(byte: u8) -> String {
    format!("ed25519:{}", format!("{byte:02x}").repeat(32))
}

/// A lookup over a fixed table of raw values.
fn lookup(pairs: Vec<(String, OsString)>) -> impl Fn(&str) -> Option<OsString> {
    move |name| {
        pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }
}

/// A lookup over a fixed table of text values.
fn from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
    lookup(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(*v)))
            .collect(),
    )
}

/// A complete, valid configuration with the one volume `alpha`.
fn valid() -> Vec<(String, String)> {
    vec![
        (
            ENV_AUTHORITY.to_owned(),
            AUTHORITY_SINGLE_PROCESS.to_owned(),
        ),
        (
            ENV_STATE_DIR.to_owned(),
            "/var/lib/granary/authority".to_owned(),
        ),
        (
            ENV_ENROLLMENT_DIR.to_owned(),
            "/etc/granary/enrollment".to_owned(),
        ),
        (
            ENV_CLIENT_CA.to_owned(),
            "/etc/granary/client-ca.pem".to_owned(),
        ),
        (ENV_VOLUMES.to_owned(), "alpha".to_owned()),
        (ALPHA_KEYS.to_owned(), key(1)),
    ]
}

/// [`valid`] with `name` replaced by `value`, or removed when `None`.
fn with(name: &str, value: Option<&str>) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = valid().into_iter().filter(|(k, _)| k != name).collect();
    if let Some(value) = value {
        pairs.push((name.to_owned(), value.to_owned()));
    }
    pairs
}

fn run(pairs: Vec<(String, String)>) -> Result<Option<AuthorityConfig>, String> {
    authority_from(&lookup(
        pairs
            .into_iter()
            .map(|(k, v)| (k, OsString::from(v)))
            .collect(),
    ))
}

/// The refusal, or a panic saying the row expected one.
fn refused(result: Result<Option<AuthorityConfig>, String>, why: &str) -> String {
    match result {
        Err(reason) => reason,
        Ok(config) => panic!("{why}; accepted {config:?}"),
    }
}

fn accepted(result: Result<Option<AuthorityConfig>, String>) -> AuthorityConfig {
    match result {
        Ok(Some(config)) => config,
        Ok(None) => panic!("a configuration with the predicate is an authority"),
        Err(reason) => panic!("refused: {reason}"),
    }
}

fn volume(name: &str) -> VolumeName {
    VolumeName::new(name.to_owned()).unwrap_or_else(|error| panic!("{name}: {error}"))
}

#[test]
fn nothing_set_is_the_authority_free_server() {
    assert_eq!(authority_from(&from(&[])), Ok(None));
}

#[test]
fn the_full_configuration_is_read() {
    let config = accepted(run(vec![
        (
            ENV_AUTHORITY.to_owned(),
            AUTHORITY_SINGLE_PROCESS.to_owned(),
        ),
        (
            ENV_STATE_DIR.to_owned(),
            "/var/lib/granary/authority".to_owned(),
        ),
        (
            ENV_ENROLLMENT_DIR.to_owned(),
            "/etc/granary/enrollment".to_owned(),
        ),
        (
            ENV_CLIENT_CA.to_owned(),
            "/etc/granary/client-ca.pem".to_owned(),
        ),
        (ENV_VOLUMES.to_owned(), " alpha , my-vol-2 ".to_owned()),
        (ALPHA_KEYS.to_owned(), key(1)),
        (
            "GRANARY_AUTHORITY_VOLUME_MY_VOL_2_PUBLISHER_KEYS".to_owned(),
            format!("{} , {}", key(2), key(3)),
        ),
        (
            ENV_ACCEPT_UNSUPPORTED_FILESYSTEM.to_owned(),
            "true".to_owned(),
        ),
    ]));
    assert_eq!(
        config.authority_profile,
        super::AuthorityProfile::SingleProcess
    );
    assert_eq!(
        config.state_dir,
        PathBuf::from("/var/lib/granary/authority")
    );
    assert_eq!(
        config.enrollment_dir,
        PathBuf::from("/etc/granary/enrollment")
    );
    assert_eq!(
        config.client_ca,
        PathBuf::from("/etc/granary/client-ca.pem")
    );
    assert!(config.accept_unsupported_filesystem);
    assert_eq!(config.volumes.len(), 2);
    assert_eq!(
        config.volumes.get(&volume("alpha")),
        Some(&vec![[1_u8; 32]])
    );
    assert_eq!(
        config.volumes.get(&volume("my-vol-2")),
        Some(&vec![[2_u8; 32], [3_u8; 32]])
    );
}

#[test]
fn the_filesystem_acknowledgement_is_false_when_absent_and_reads_false() {
    assert!(!accepted(run(valid())).accept_unsupported_filesystem);
    assert!(
        !accepted(run(with(ENV_ACCEPT_UNSUPPORTED_FILESYSTEM, Some("false"))))
            .accept_unsupported_filesystem
    );
}

#[test]
fn each_required_name_missing_with_the_predicate_refuses_naming_it() {
    for missing in REQUIRED {
        let reason = refused(
            run(with(missing, None)),
            &format!("{missing} is required with the predicate"),
        );
        assert!(
            reason.contains(&format!("{missing} (unset)")),
            "the refusal must name {missing} as unset: {reason}"
        );
        for other in REQUIRED.iter().filter(|name| **name != missing) {
            assert!(
                reason.contains(&format!("{other} (set)")),
                "and each other required name as set: {reason}"
            );
        }
    }
}

#[test]
fn each_fixed_name_set_alone_without_the_predicate_refuses_naming_it() {
    for name in FIXED {
        let reason = refused(
            authority_from(&from(&[(name, "x")])),
            &format!("{name} set without the predicate"),
        );
        assert!(
            reason.contains(name),
            "the refusal must name {name}: {reason}"
        );
        assert!(
            reason.contains(ENV_AUTHORITY),
            "and say the predicate is missing: {reason}"
        );
    }
}

#[test]
fn an_unlisted_volumes_variable_is_inert_with_and_without_the_predicate() {
    let stray = "GRANARY_AUTHORITY_VOLUME_BETA_PUBLISHER_KEYS";
    assert_eq!(
        authority_from(&from(&[(stray, "not even a key")])),
        Ok(None),
        "without the predicate a derived name is never read"
    );
    let mut pairs = valid();
    pairs.push((stray.to_owned(), "not even a key".to_owned()));
    let config = accepted(run(pairs));
    assert_eq!(
        config
            .volumes
            .keys()
            .map(VolumeName::as_str)
            .collect::<Vec<_>>(),
        vec!["alpha"],
        "an unlisted volume's keys configure nothing"
    );
}

#[test]
fn a_listed_volume_without_its_keys_refuses_naming_the_derived_variable() {
    let reason = refused(run(with(ALPHA_KEYS, None)), "alpha's keys are required");
    assert!(reason.contains(ALPHA_KEYS), "{reason}");
    let reason = refused(run(with(ALPHA_KEYS, Some(" "))), "empty keys refuse");
    assert!(
        reason.contains(ALPHA_KEYS) && reason.contains("empty"),
        "{reason}"
    );
}

#[test]
fn a_duplicate_volume_refuses() {
    let mut pairs = with(ENV_VOLUMES, Some("alpha,alpha"));
    pairs.push((ALPHA_KEYS.to_owned(), key(1)));
    let reason = refused(run(pairs), "a volume listed twice");
    assert!(
        reason.contains(ENV_VOLUMES) && reason.contains("more than once"),
        "{reason}"
    );
}

#[test]
fn a_reserved_volume_name_is_accepted() {
    let reserved = volume("gran-x");
    assert!(
        is_reserved_volume_name(&reserved),
        "positive control: the row must use a name the registry reserves"
    );
    let mut pairs = with(ENV_VOLUMES, Some("gran-x"));
    pairs.push((publisher_keys_variable(&reserved), key(4)));
    let config = accepted(run(pairs));
    assert_eq!(config.volumes.get(&reserved), Some(&vec![[4_u8; 32]]));
}

#[test]
fn the_volume_list_refuses_bad_names_empty_tokens_and_overflow() {
    for (list, why) in [
        ("", "an empty list"),
        ("alpha,,beta", "an empty token"),
        ("Alpha", "an uppercase name"),
        ("alpha_beta", "an underscore"),
        ("-alpha", "a leading dash"),
    ] {
        let reason = refused(run(with(ENV_VOLUMES, Some(list))), why);
        assert!(reason.contains(ENV_VOLUMES), "{why}: {reason}");
    }

    let names: Vec<String> = (0..=MAX_VOLUMES).map(|i| format!("v{i}")).collect();
    let mut pairs = with(ENV_VOLUMES, Some(&names.join(",")));
    for name in &names {
        pairs.push((publisher_keys_variable(&volume(name)), key(1)));
    }
    let reason = refused(run(pairs), "one volume over the cap");
    assert!(reason.contains(ENV_VOLUMES), "{reason}");

    // Positive control: exactly the cap is accepted.
    let names = names.get(..MAX_VOLUMES).unwrap_or_default();
    let mut pairs = with(ENV_VOLUMES, Some(&names.join(",")));
    for name in names {
        pairs.push((publisher_keys_variable(&volume(name)), key(1)));
    }
    assert_eq!(accepted(run(pairs)).volumes.len(), MAX_VOLUMES);
}

#[test]
fn nine_keys_refuse_and_eight_are_accepted() {
    let nine: Vec<String> = (1..=9).map(key).collect();
    let reason = refused(
        run(with(ALPHA_KEYS, Some(&nine.join(",")))),
        "nine keys exceed the cap",
    );
    assert!(reason.contains(ALPHA_KEYS), "{reason}");

    let eight = nine.get(..MAX_PUBLISHER_KEYS).unwrap_or_default().join(",");
    let config = accepted(run(with(ALPHA_KEYS, Some(&eight))));
    assert_eq!(
        config.volumes.get(&volume("alpha")).map(Vec::len),
        Some(MAX_PUBLISHER_KEYS)
    );
}

#[test]
fn a_duplicate_key_refuses() {
    let reason = refused(
        run(with(ALPHA_KEYS, Some(&format!("{},{}", key(5), key(5))))),
        "a key listed twice",
    );
    assert!(
        reason.contains(ALPHA_KEYS) && reason.contains("more than once"),
        "{reason}"
    );
}

#[test]
fn a_tls_pin_or_a_client_spki_value_is_not_a_publisher_key() {
    for value in [
        "sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
        "clientspki-v1:0101010101010101010101010101010101010101010101010101010101010101",
    ] {
        let reason = refused(run(with(ALPHA_KEYS, Some(value))), value);
        assert!(reason.contains(ALPHA_KEYS), "{value}: {reason}");
    }
}

#[test]
fn a_relative_or_empty_path_refuses_naming_it() {
    for name in [ENV_STATE_DIR, ENV_ENROLLMENT_DIR, ENV_CLIENT_CA] {
        let reason = refused(run(with(name, Some("relative/path"))), "a relative path");
        assert!(
            reason.contains(name) && reason.contains("relative"),
            "{reason}"
        );
        let reason = refused(run(with(name, Some(""))), "an empty path");
        assert!(
            reason.contains(name) && reason.contains("empty"),
            "{reason}"
        );
    }
}

#[test]
fn a_value_over_the_bound_refuses_naming_it() {
    let long = format!("/{}", "a".repeat(MAX_VALUE_BYTES));
    for name in [ENV_AUTHORITY, ENV_STATE_DIR, ENV_VOLUMES, ALPHA_KEYS] {
        let reason = refused(run(with(name, Some(&long))), "an over-bound value");
        assert!(
            reason.contains(name) && reason.contains(&MAX_VALUE_BYTES.to_string()),
            "{name}: {reason}"
        );
    }
    // Without the predicate too: the bound is checked before anything else.
    let reason = refused(
        authority_from(&from(&[(ENV_CLIENT_CA, &long)])),
        "an over-bound value without the predicate",
    );
    assert!(reason.contains(ENV_CLIENT_CA), "{reason}");
}

#[test]
fn a_predicate_other_than_single_process_refuses() {
    for value in ["", "single_process", "Single-Process", "replicated"] {
        let reason = refused(run(with(ENV_AUTHORITY, Some(value))), value);
        assert!(reason.contains(ENV_AUTHORITY), "{value:?}: {reason}");
    }
}

#[test]
fn the_filesystem_acknowledgement_accepts_only_true_or_false() {
    for value in ["", "yes", "1", "TRUE", "True"] {
        let reason = refused(
            run(with(ENV_ACCEPT_UNSUPPORTED_FILESYSTEM, Some(value))),
            value,
        );
        assert!(
            reason.contains(ENV_ACCEPT_UNSUPPORTED_FILESYSTEM),
            "{value:?}: {reason}"
        );
    }
}

#[test]
fn a_non_utf8_path_is_a_path_and_a_non_utf8_text_value_refuses_naming_it() {
    let raw = OsString::from_vec(b"/var/lib/granary-\xff".to_vec());
    let text = |pairs: Vec<(String, String)>| -> Vec<(String, OsString)> {
        pairs
            .into_iter()
            .map(|(k, v)| (k, OsString::from(v)))
            .collect()
    };

    let mut pairs = text(with(ENV_STATE_DIR, None));
    pairs.push((ENV_STATE_DIR.to_owned(), raw.clone()));
    let config = accepted(authority_from(&lookup(pairs)));
    assert_eq!(config.state_dir, PathBuf::from(raw.clone()));

    for name in [ENV_AUTHORITY, ENV_VOLUMES, ALPHA_KEYS] {
        let mut pairs = text(with(name, None));
        pairs.push((name.to_owned(), raw.clone()));
        let reason = refused(authority_from(&lookup(pairs)), "non-UTF-8 text");
        assert!(
            reason.contains(name) && reason.contains("UTF-8"),
            "{name}: {reason}"
        );
    }
}

#[test]
fn the_derived_name_maps_dashes_and_case_and_inverts() {
    let name = publisher_keys_variable(&volume("my-vol-2"));
    assert_eq!(name, "GRANARY_AUTHORITY_VOLUME_MY_VOL_2_PUBLISHER_KEYS");
    // The inverse the injectivity argument relies on.
    let body = name
        .strip_prefix(super::PUBLISHER_KEYS_PREFIX)
        .and_then(|rest| rest.strip_suffix(super::PUBLISHER_KEYS_SUFFIX))
        .unwrap_or_else(|| panic!("{name} lost its affixes"));
    let back: String = body
        .chars()
        .map(|c| {
            if c == '_' {
                '-'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    assert_eq!(back, "my-vol-2");
}

#[test]
fn controls_configuration_is_validated() {
    use super::ENV_CONTROLS;
    use crate::controls::ControlsConfig;
    assert_eq!(
        accepted(run(valid())).controls.tuple(),
        (46, 5, 33_554_432, 268_435_456, 4)
    );
    for cap in 1..=7 {
        let tuple = format!("4,4,33554432,268435456,{cap}");
        assert_eq!(
            accepted(run(with(ENV_CONTROLS, Some(&tuple))))
                .controls
                .tuple()
                .4,
            cap
        );
    }
    for invalid in [
        "",
        "4",
        "4,4,33554432,268435456",
        "4,4,33554432,268435456,4,1",
        "0,4,33554432,268435456,4",
        "4,0,33554432,268435456,4",
        "4,4,0,268435456,4",
        "4,4,33554432,0,4",
        "4,4,33554432,268435456,0",
        "4,4,33554432,268435455,4",
        "4,4,33554432,268435456,8",
        "+4,4,33554432,268435456,4",
        " 4,4,33554432,268435456,4",
        "4,,33554432,268435456,4",
        "18446744073709551616,4,33554432,268435456,4",
        "1,4294967296,33554432,268435456,4",
        "4,4,1,4294967296,4",
        "4,4,33554432,268435456,18446744073709551615",
    ] {
        let reason = run(with(ENV_CONTROLS, Some(invalid))).unwrap_err();
        assert!(reason.contains(ENV_CONTROLS), "{invalid}: {reason}");
    }
    assert!(
        ControlsConfig::parse(
            "18446744073709551615,18446744073709551615,18446744073709551615,18446744073709551615,7"
        )
        .is_ok()
    );
    assert!(
        authority_from(&from(&[(ENV_CONTROLS, "4,4,33554432,268435456,4")]))
            .unwrap_err()
            .contains(ENV_CONTROLS)
    );
}
