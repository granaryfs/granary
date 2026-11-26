// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use granary_core::hash::GrainId;
use granary_core::root::{self, RootDoc, RootSig, Timestamp, VolumeName};
use granary_store::crypto::{SigningKey, check_head};

fn public(key: &SigningKey) -> String {
    use std::fmt::Write as _;
    let mut value = "ed25519:".to_owned();
    for byte in key.public_key() {
        write!(value, "{byte:02x}").unwrap_or_else(|e| panic!("{e}"));
    }
    value
}
fn signed(key: &SigningKey) -> Vec<u8> {
    let id = GrainId::of(b"fixture");
    let mut doc = RootDoc {
        volume: VolumeName::new("vol".to_owned()).unwrap(),
        seq: 1,
        parent: None,
        writer_uuid: [1; 16],
        epoch: 1,
        timestamp: Timestamp { secs: 1, nanos: 0 },
        chunker_spec: "opaque".to_owned(),
        manifest_root: id,
        binmap_index: id,
        sheaf_head: id,
        sigs: vec![RootSig {
            key_id: key.key_id(),
            sig: [0; 64],
        }],
    };
    let bytes = root::encode_root(&doc).unwrap();
    doc.sigs.first_mut().unwrap().sig = key.sign(root::signed_prefix(&bytes).unwrap());
    root::encode_root(&doc).unwrap()
}

#[test]
fn publisher_overlap_defaults_and_direct_policy() {
    let a = SigningKey::from_seed(&[1; 32]).unwrap();
    let b = SigningKey::from_seed(&[2; 32]).unwrap();
    let mut configured = PublisherTrust::default();
    let own = configured.build(*a.public_key()).unwrap();
    assert!(check_head(&signed(&a), "vol", 1, &own).is_ok());
    assert!(check_head(&signed(&b), "vol", 1, &own).is_err());
    assert!(configured.require_authority().is_ok());
    let mut singleton = PublisherTrust::default();
    singleton.push(&public(&a)).unwrap();
    assert!(singleton.require_authority().is_err());
    for key in [&a, &b, &a] {
        configured.push(&public(key)).unwrap();
    }
    let overlap = configured.build(*a.public_key()).unwrap();
    assert_eq!(overlap.len(), 2);
    for key in [&a, &b] {
        assert!(check_head(&signed(key), "vol", 1, &overlap).is_ok());
    }
    assert!(configured.require_authority().is_err());
    assert!(PublisherTrust::default().build([0; 32]).is_err());
}

#[test]
fn explicit_trust_requires_signer_without_appending() {
    let a = SigningKey::from_seed(&[1; 32]).unwrap();
    let b = SigningKey::from_seed(&[2; 32]).unwrap();
    let mut trust = PublisherTrust::default();
    trust.push(&public(&b)).unwrap();
    assert_eq!(
        trust.build(*a.public_key()).unwrap_err().to_string(),
        "publisher trust must include the current signing key"
    );
    trust.push(&public(&a)).unwrap();
    assert!(trust.build(*a.public_key()).is_ok());
}

#[test]
fn publisher_parser_is_canonical() {
    let canonical = format!("ed25519:{}", "ab".repeat(32));
    for value in [
        String::new(),
        "ab".repeat(32),
        canonical.to_uppercase(),
        format!(" {canonical}"),
        format!("{canonical} "),
        format!("{canonical},{canonical}"),
        format!("keyid:{}", "ab".repeat(32)),
        format!("sha256/{}", "A".repeat(43)),
        "ed25519:abcd".to_owned(),
    ] {
        assert_eq!(
            PublisherTrust::default()
                .push(&value)
                .unwrap_err()
                .to_string(),
            "--publisher-key must be ed25519: followed by 64 lowercase hex digits"
        );
    }
    assert!(PublisherTrust::default().push(&canonical).is_ok());
    assert_eq!(
        PublisherTrust::default()
            .push(&format!("ed25519:{}", "00".repeat(32)))
            .unwrap_err()
            .to_string(),
        "--publisher-key must not be the all-zero key"
    );
}

#[test]
fn scope_is_exact_sorted_deduplicated_and_pin_bounded() {
    let context = CredentialContext::new("Team.A_-9").unwrap();
    let scope = publication_scope(
        "https://HOST:443/a@b",
        &[[2; 32], [1; 32], [2; 32]],
        &context,
    )
    .unwrap();
    assert_eq!(scope.authority_base, b"https://HOST:443/a@b");
    assert_eq!(scope.credential_context, b"Team.A_-9");
    assert_eq!(scope.pins, vec![[1; 32], [2; 32]]);
    let reordered =
        publication_scope("https://HOST:443/a@b", &[[1; 32], [2; 32]], &context).unwrap();
    assert_eq!(scope, reordered);
    let changed = publication_scope("https://HOST:443/a@b", &[[3; 32]], &context).unwrap();
    assert_eq!(scope.digest().unwrap(), changed.digest().unwrap());
    assert_ne!(scope, changed);
    assert_ne!(
        scope.digest().unwrap(),
        publication_scope("https://host:443/a@b", &[[1; 32]], &context)
            .unwrap()
            .digest()
            .unwrap()
    );
    assert_ne!(
        scope.digest().unwrap(),
        publication_scope(
            "https://HOST:443/a@b",
            &[[1; 32]],
            &CredentialContext::new("team.A_-9").unwrap()
        )
        .unwrap()
        .digest()
        .unwrap()
    );
    for pins in [vec![], vec![[0; 32]], vec![[1; 32]; 9]] {
        assert!(publication_scope("https://host", &pins, &context).is_err());
    }
    assert!(publication_scope("https://host", &[[1; 32]; 8], &context).is_ok());
    let max = format!("https://h/{}", "a".repeat(8182));
    assert_eq!(max.len(), 8192);
    assert!(publication_scope(&max, &[[1; 32]], &context).is_ok());
    assert!(publication_scope(&(max + "a"), &[[1; 32]], &context).is_err());
}

#[test]
fn context_boundaries_and_untrusted_configuration_never_panic() {
    for value in ["", "a b", "é", " x", "x\n", "x/", "x@", "x\0"] {
        assert!(CredentialContext::new(value).is_err());
    }
    assert!(CredentialContext::new(&"a".repeat(255)).is_ok());
    assert!(CredentialContext::new(&"a".repeat(256)).is_err());
    for byte in 0..=255u8 {
        for length in [0, 1, 32, 64, 255, 256] {
            let raw = vec![byte; length];
            if let Ok(value) = std::str::from_utf8(&raw) {
                let _ = CredentialContext::new(value);
                let _ = PublisherTrust::default().push(value);
                let _ = publication_scope(value, &[[1; 32]], &CredentialContext::new("a").unwrap());
            }
        }
    }
}

#[test]
fn scope_rejects_and_redacts_bad_endpoints() {
    let context = CredentialContext::new("context").unwrap();
    for endpoint in [
        "https://SECRET_SENTINEL@host",
        "https://user:SECRET_SENTINEL@host",
        "https://@host",
    ] {
        let error = publication_scope(endpoint, &[[1; 32]], &context).unwrap_err();
        assert_eq!(error.to_string(), "endpoint userinfo is not permitted");
        assert!(!format!("{error} {error:?}").contains("SECRET_SENTINEL"));
    }
    let error =
        publication_scope("https://SECRET_SENTINEL host", &[[1; 32]], &context).unwrap_err();
    assert_eq!(error.to_string(), "invalid endpoint URL");
    assert!(!format!("{error} {error:?}").contains("SECRET_SENTINEL"));
    assert!(publication_scope("https://host/a@b", &[[1; 32]], &context).is_ok());
}
