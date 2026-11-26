// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Synthetic credential state and exhaustive module Debug policy.
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: read only this module's source for its inventory and descriptor identity; no credential file is opened"
)]

use super::*;

fn source_path() -> PathBuf {
    std::env::current_dir()
        .expect("runtime directory")
        .ancestors()
        .map(|root| root.join("crates/granary-client/src/credential.rs"))
        .find(|file| file.is_file())
        .expect("credential source is readable from runtime directory")
}

fn debug_inventory(source: &str) -> Result<usize, &'static str> {
    let words = source
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    let mut types = words
        .windows(2)
        .filter(|pair| matches!(pair[0], "struct" | "enum"))
        .map(|pair| pair[1])
        .collect::<Vec<_>>();
    types.sort_unstable();
    if types != ["ClientCredential", "CredentialError", "CredentialFile"] {
        return Err("unclassified credential type");
    }
    let debug_count = words.iter().filter(|word| **word == "Debug").count();
    if debug_count != 3 {
        return Err("credential Debug inventory changed");
    }
    let compact = source.split_whitespace().collect::<Vec<_>>().join(" ");
    for (name, class) in [
        ("ClientCredential", "<credential>"),
        ("CredentialError", "<credential-error>"),
    ] {
        let body = format!(
            "impl std::fmt::Debug for {name} {{ fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{ f.write_str(\"{class}\") }} }}"
        );
        if !compact.contains(&body) {
            return Err("credential Debug must emit only its fixed class");
        }
    }
    // CredentialFile is the exhaustive role enum; it retains no caller bytes.
    if !compact.contains(
        "pub enum CredentialFile { /// The certificate file. Certificate, /// The key file. Key, }",
    ) {
        return Err("credential file role must remain closed");
    }
    Ok(types.len())
}

#[test]
fn module_debug_inventory_requires_fixed_classes_for_every_carrier() {
    let source = std::fs::read_to_string(source_path()).expect("credential source read");
    assert_eq!(debug_inventory(&source), Ok(3), "module Debug inventory");
    let cases = [
        (
            format!("{source}\n// Debug"),
            "credential Debug inventory changed",
        ),
        (
            format!("{source}\nstruct Extra {{ path: PathBuf }}"),
            "unclassified credential type",
        ),
        (
            source.replace(
                "f.write_str(\"<credential-error>\")",
                "std::fmt::Display::fmt(self, f)",
            ),
            "credential Debug must emit only its fixed class",
        ),
        (
            source.replace("Certificate,", "Certificate(String),"),
            "credential file role must remain closed",
        ),
    ];
    for (malformed, refusal) in &cases {
        assert_eq!(
            debug_inventory(malformed),
            Err(*refusal),
            "inventory refusal"
        );
    }
    assert_eq!(cases.len(), 4, "nonempty inventory controls");
}

fn assert_debug_class(value: &impl std::fmt::Debug, class: &str) {
    assert!(format!("{value:?}") == class, "Debug class mismatch");
    assert!(
        format!("{value:#?}") == class,
        "alternate Debug class mismatch"
    );
}

#[test]
fn credential_debug_retains_no_certified_key_or_file_identity() {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["sentinel-principal.invalid".to_owned()])
            .expect("synthetic certificate");
    let certified = ClientCertifiedKey::from_pem(
        cert.pem().as_bytes(),
        signing_key.serialize_pem().as_bytes(),
    )
    .expect("synthetic certified key");
    let source = File::open(source_path()).expect("source descriptor");
    let credential = ClientCredential {
        certified,
        key_identity: FileIdentity::from_file(&source).expect("source identity"),
    };
    assert_debug_class(&credential, "<credential>");
}

#[test]
fn credential_error_debug_retains_no_paths_reason_or_nested_error() {
    let errors = [
        CredentialError::Incomplete {
            missing: CredentialFile::Key,
        },
        CredentialError::File {
            file: CredentialFile::Certificate,
            path: PathBuf::from("sentinel-directory/sentinel-certificate"),
            reason: "sentinel-provider-chain".to_owned(),
        },
        CredentialError::Content {
            certificate: PathBuf::from("sentinel-directory/sentinel-certificate"),
            key: PathBuf::from("sentinel-directory/sentinel-key"),
            error: Box::new(ContentError::Mismatch(rustls::Error::General(
                "sentinel-nested-error".to_owned(),
            ))),
        },
    ];
    for error in &errors {
        assert_debug_class(error, "<credential-error>");
    }
    assert_eq!(errors.len(), 3, "every credential refusal variant");
}
