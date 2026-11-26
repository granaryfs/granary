// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! The client credential's strict PEM profile and its key correspondence,
//! through `ClientCertifiedKey::from_pem`.
//!
//! Every refusal row starts from a pair that loads (the control, asserted
//! in the row itself) and changes one thing, so a refusal cannot come from
//! a fixture that was never valid. The certificates are minted in-test by
//! rcgen; its PEM output is the well-formed baseline.
//!
//! **`unwrap()` is a hard error in the helpers below.** `clippy.toml`'s
//! `allow-unwrap-in-tests` covers `#[test]` items, not the plain functions
//! of an integration-test target. The workspace idiom is
//! `.unwrap_or_else(|e| panic!("{e}"))`.

use rcgen::PublicKeyData as _;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::server::ParsedCertificate;

use granary_net::credential::{
    CERTIFICATE_CHAIN_MAX, CREDENTIAL_FILE_MAX, ClientCertifiedKey, CredentialError, PemRefusal,
};

/// A CA and one leaf it issued, with the leaf's key, as PEM.
struct Pair {
    leaf: String,
    ca: String,
    key: String,
}

fn keypair() -> rcgen::KeyPair {
    rcgen::KeyPair::generate().unwrap_or_else(|e| panic!("keypair: {e}"))
}

fn mint() -> Pair {
    let ca_key = keypair();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|e| panic!("ca params: {e}"));
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params
        .self_signed(&ca_key)
        .unwrap_or_else(|e| panic!("ca: {e}"));
    let key = keypair();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|e| panic!("leaf params: {e}"));
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf = params
        .signed_by(&key, &issuer)
        .unwrap_or_else(|e| panic!("leaf: {e}"));
    Pair {
        leaf: leaf.pem(),
        ca: ca.pem(),
        key: key.serialize_pem(),
    }
}

/// Load `certificate` and `key`; the refusal, or a panic if they load.
fn refused(certificate: &str, key: &str) -> CredentialError {
    match ClientCertifiedKey::from_pem(certificate.as_bytes(), key.as_bytes()) {
        Ok(credential) => panic!("loaded, but should have been refused: {credential:?}"),
        Err(error) => error,
    }
}

/// The control every row starts from: the unmodified pair loads.
fn loads(pair: &Pair) {
    if let Err(e) = ClientCertifiedKey::from_pem(pair.leaf.as_bytes(), pair.key.as_bytes()) {
        panic!("the control pair must load: {e}");
    }
}

/// A PEM block with `label` around `body`.
fn block(label: &str, body: &str) -> String {
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

/// The base64 body of the first block of `pem`.
fn body(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn certificate_refusal(error: CredentialError) -> PemRefusal {
    match error {
        CredentialError::Certificate(refusal) => refusal,
        other => panic!("want a certificate-file refusal, got {other:?}"),
    }
}

fn key_refusal(error: CredentialError) -> PemRefusal {
    match error {
        CredentialError::Key(refusal) => refusal,
        other => panic!("want a key-file refusal, got {other:?}"),
    }
}

// ------------------------------------------------------------- admitted

#[test]
fn a_leaf_and_its_key_load_and_the_chain_is_kept_in_order() {
    let pair = mint();
    loads(&pair);
    let chain = format!("{}{}", pair.leaf, pair.ca);
    let credential = ClientCertifiedKey::from_pem(chain.as_bytes(), pair.key.as_bytes()).unwrap();
    let held = credential.certificate_chain();
    assert_eq!(held.len(), 2);
    let leaf = CertificateDer::from_pem_slice(pair.leaf.as_bytes()).unwrap();
    assert_eq!(held[0], leaf, "the end entity is first");
}

#[test]
fn an_ed25519_v2_key_with_a_public_key_loads() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let der = key.serialize_der();
    assert!(der.starts_with(&[0x30, 0x51, 0x02, 0x01, 0x01]));
    assert!(der.ends_with(&[&[0x81, 0x21, 0x00], key.public_key_raw()].concat()));
    let leaf = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .self_signed(&key)
        .unwrap();
    ClientCertifiedKey::from_pem(leaf.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
}

#[test]
fn a_p384_key_loads_with_its_certificate() {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let leaf = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .self_signed(&key)
        .unwrap();
    ClientCertifiedKey::from_pem(leaf.pem().as_bytes(), key.serialize_pem().as_bytes()).unwrap();
}

#[test]
fn crlf_line_ends_and_surrounding_whitespace_are_admitted() {
    let pair = mint();
    loads(&pair);
    let certificate = format!("\n  \n{}\t\n\n", pair.leaf).replace('\n', "\r\n");
    let key = format!("\r\n{}  \r\n", pair.key);
    assert!(ClientCertifiedKey::from_pem(certificate.as_bytes(), key.as_bytes()).is_ok());
}

#[test]
fn eight_certificates_are_admitted_and_a_ninth_is_refused() {
    let pair = mint();
    loads(&pair);
    let eight = format!("{}{}", pair.leaf, pair.ca.repeat(CERTIFICATE_CHAIN_MAX - 1));
    assert!(ClientCertifiedKey::from_pem(eight.as_bytes(), pair.key.as_bytes()).is_ok());
    let nine = format!("{eight}{}", pair.ca);
    assert!(matches!(
        certificate_refusal(refused(&nine, &pair.key)),
        PemRefusal::TooManyCertificates
    ));
}

// ------------------------------------------------------- the key file

#[test]
fn an_encrypted_key_is_refused_by_name() {
    let pair = mint();
    loads(&pair);
    let key = block("ENCRYPTED PRIVATE KEY", &body(&pair.key));
    assert!(matches!(
        key_refusal(refused(&pair.leaf, &key)),
        PemRefusal::EncryptedKey { block: 1 }
    ));
}

#[test]
fn a_pkcs1_key_is_refused_by_name() {
    let pair = mint();
    loads(&pair);
    let key = block("RSA PRIVATE KEY", &body(&pair.key));
    assert!(matches!(
        key_refusal(refused(&pair.leaf, &key)),
        PemRefusal::Pkcs1Key { block: 1 }
    ));
}

#[test]
fn a_sec1_key_is_refused_by_name() {
    let pair = mint();
    loads(&pair);
    let key = block("EC PRIVATE KEY", &body(&pair.key));
    assert!(matches!(
        key_refusal(refused(&pair.leaf, &key)),
        PemRefusal::Sec1Key { block: 1 }
    ));
}

#[test]
fn a_second_key_is_refused_even_when_it_is_the_same_key() {
    let pair = mint();
    loads(&pair);
    let key = format!("{}{}", pair.key, pair.key);
    assert!(matches!(
        key_refusal(refused(&pair.leaf, &key)),
        PemRefusal::SecondKey { block: 2 }
    ));
}

#[test]
fn a_certificate_in_the_key_file_is_refused() {
    let pair = mint();
    loads(&pair);
    let key = format!("{}{}", pair.key, pair.leaf);
    assert!(matches!(
        key_refusal(refused(&pair.leaf, &key)),
        PemRefusal::CertificateInKeyFile { block: 2 }
    ));
}

#[test]
fn a_key_whose_der_is_not_a_key_is_refused() {
    let pair = mint();
    loads(&pair);
    // Not a DER structure at all: refused before the key parser sees it.
    let key = block("PRIVATE KEY", "AAAAAAAA");
    assert!(matches!(
        key_refusal(refused(&pair.leaf, &key)),
        PemRefusal::KeyNotOneStructure { block: 1 }
    ));
    // A well-formed PKCS#8 shape (version, an unknown algorithm, an empty
    // key) that no key parser accepts: the key parser refuses it.
    let shaped = [
        0x30, 0x0a, 0x02, 0x01, 0x00, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x04, 0x00,
    ];
    let key = block("PRIVATE KEY", &base64(&shaped));
    assert!(matches!(
        key_refusal(refused(&pair.leaf, &key)),
        PemRefusal::Key(_)
    ));
}

#[test]
fn a_key_file_with_no_block_is_refused() {
    let pair = mint();
    loads(&pair);
    assert!(matches!(
        key_refusal(refused(&pair.leaf, "\n  \n")),
        PemRefusal::Empty
    ));
}

// ---------------------------------------------- the certificate file

#[test]
fn a_key_in_the_certificate_file_is_refused() {
    let pair = mint();
    loads(&pair);
    let certificate = format!("{}{}", pair.leaf, pair.key);
    assert!(matches!(
        certificate_refusal(refused(&certificate, &pair.key)),
        PemRefusal::KeyInCertificateFile { block: 2 }
    ));
}

#[test]
fn a_valid_leaf_followed_by_a_malformed_certificate_is_refused() {
    let pair = mint();
    loads(&pair);
    // Valid base64, not an X.509 certificate: only a parse of the second
    // block can refuse it, since the key matches the first.
    let certificate = format!("{}{}", pair.leaf, block("CERTIFICATE", "AAAAAAAA"));
    assert!(matches!(
        certificate_refusal(refused(&certificate, &pair.key)),
        PemRefusal::Certificate { block: 2, .. }
    ));
}

#[test]
fn a_certificate_file_with_no_block_is_refused() {
    let pair = mint();
    loads(&pair);
    assert!(matches!(
        certificate_refusal(refused("", &pair.key)),
        PemRefusal::Empty
    ));
}

// --------------------------------------------------- both files alike

#[test]
fn an_unknown_block_is_refused_in_either_file() {
    let pair = mint();
    loads(&pair);
    let crl = block("X509 CRL", "AAAAAAAA");
    let certificate = format!("{}{crl}", pair.leaf);
    match certificate_refusal(refused(&certificate, &pair.key)) {
        PemRefusal::UnknownBlock { block: 2, label } => assert_eq!(label, "X509 CRL"),
        other => panic!("want the unknown block named, got {other:?}"),
    }
    let key = format!("{crl}{}", pair.key);
    assert!(matches!(
        key_refusal(refused(&pair.leaf, &key)),
        PemRefusal::UnknownBlock { block: 1, .. }
    ));
}

#[test]
fn malformed_base64_is_refused_in_either_file() {
    let pair = mint();
    loads(&pair);
    let certificate = format!("{}{}", pair.leaf, block("CERTIFICATE", "AAAA!AAA"));
    assert!(matches!(
        certificate_refusal(refused(&certificate, &pair.key)),
        PemRefusal::Base64 { block: 2 }
    ));
    // Base64 alphabet throughout, and still not base64: bad padding.
    let key = block("PRIVATE KEY", "A===");
    assert!(matches!(
        key_refusal(refused(&pair.leaf, &key)),
        PemRefusal::Base64 { block: 1 }
    ));
    // A header line inside a block is not base64 either.
    let key = block(
        "PRIVATE KEY",
        &format!("Proc-Type: 4,ENCRYPTED\n{}", body(&pair.key)),
    );
    assert!(matches!(
        key_refusal(refused(&pair.leaf, &key)),
        PemRefusal::Base64 { block: 1 }
    ));
}

#[test]
fn text_before_between_or_after_the_blocks_is_refused() {
    let pair = mint();
    loads(&pair);
    let chain = format!("{}{}", pair.leaf, pair.ca);
    let leaf_lines = pair.leaf.lines().count();
    for (certificate, line) in [
        (format!("subject=CN=x\n{chain}"), 1),
        (format!("{}junk\n{}", pair.leaf, pair.ca), leaf_lines + 1),
        (format!("{chain}trailing"), chain.lines().count() + 1),
    ] {
        match certificate_refusal(refused(&certificate, &pair.key)) {
            PemRefusal::Text { line: at } => assert_eq!(at, line),
            other => panic!("want the text's line named, got {other:?}"),
        }
    }
    let key = format!("{}.", pair.key);
    assert!(matches!(
        key_refusal(refused(&pair.leaf, &key)),
        PemRefusal::Text { .. }
    ));
}

#[test]
fn malformed_boundaries_are_refused() {
    let pair = mint();
    loads(&pair);
    let mismatched = pair
        .leaf
        .replace("-----END CERTIFICATE-----", "-----END PRIVATE KEY-----");
    let trailing = pair.leaf.replace(
        "-----BEGIN CERTIFICATE-----",
        "-----BEGIN CERTIFICATE----- x",
    );
    let stray_end = format!("-----END CERTIFICATE-----\n{}", pair.leaf);
    for certificate in [mismatched, trailing, stray_end] {
        assert!(
            matches!(
                certificate_refusal(refused(&certificate, &pair.key)),
                PemRefusal::Boundary { .. }
            ),
            "{certificate}"
        );
    }
    let unterminated = pair.leaf.replace("-----END CERTIFICATE-----\n", "");
    assert!(matches!(
        certificate_refusal(refused(&unterminated, &pair.key)),
        PemRefusal::Unterminated { line: 1 }
    ));
}

#[test]
fn a_file_over_the_bound_is_refused_and_one_at_it_is_not() {
    let pair = mint();
    loads(&pair);
    let at_bound = format!(
        "{}{}",
        pair.leaf,
        "\n".repeat(CREDENTIAL_FILE_MAX - pair.leaf.len())
    );
    assert_eq!(at_bound.len(), CREDENTIAL_FILE_MAX);
    assert!(ClientCertifiedKey::from_pem(at_bound.as_bytes(), pair.key.as_bytes()).is_ok());
    let over = format!("{at_bound}\n");
    assert!(matches!(
        certificate_refusal(refused(&over, &pair.key)),
        PemRefusal::TooLarge
    ));
    let key_over = format!("{}{}", pair.key, "\n".repeat(CREDENTIAL_FILE_MAX));
    assert!(matches!(
        key_refusal(refused(&pair.leaf, &key_over)),
        PemRefusal::TooLarge
    ));
}

// ------------------------------------------------------ correspondence

#[test]
fn a_key_that_is_not_the_end_entitys_is_refused() {
    let pair = mint();
    let other = mint();
    loads(&pair);
    loads(&other);
    assert!(matches!(
        refused(&pair.leaf, &other.key),
        CredentialError::Mismatch(_)
    ));
    // The CA's certificate first, the leaf's key: the key must be the
    // FIRST certificate's.
    let reversed = format!("{}{}", pair.ca, pair.leaf);
    assert!(matches!(
        refused(&reversed, &pair.key),
        CredentialError::Mismatch(_)
    ));
}

/// Standard base64 with padding, for building key blocks byte by byte.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                let sextet = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0);
                out.push(char::from(ALPHABET.get(sextet).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A key block holding more than one DER structure is refused: the key
/// parser would take the first key and ignore the rest. Two keys in one
/// block, and one key with a trailing byte, each paired with the first
/// key's certificate (the control: the first key alone loads).
#[test]
fn a_key_block_holding_more_than_one_structure_is_refused() {
    let key = keypair();
    let other = keypair();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|e| panic!("leaf params: {e}"));
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let leaf = params
        .self_signed(&key)
        .unwrap_or_else(|e| panic!("leaf: {e}"))
        .pem();
    let one = key.serialize_der();
    let alone = block("PRIVATE KEY", &base64(&one));
    if let Err(e) = ClientCertifiedKey::from_pem(leaf.as_bytes(), alone.as_bytes()) {
        panic!("the control key must load: {e}");
    }
    let two = [one.clone(), other.serialize_der()].concat();
    let trailing = [one, vec![0]].concat();
    for der in [two, trailing] {
        let pem = block("PRIVATE KEY", &base64(&der));
        let refusal = key_refusal(refused(&leaf, &pem));
        assert!(
            matches!(refusal, PemRefusal::KeyNotOneStructure { block: 1 }),
            "{refusal:?}"
        );
    }
}

/// DER `der` with `extra` appended INSIDE its outer `SEQUENCE`, the outer
/// length rewritten to cover it.
fn inside(der: &[u8], extra: &[u8]) -> Vec<u8> {
    let first = *der.get(1).unwrap_or_else(|| panic!("no length byte"));
    let header = if first < 0x80 {
        2
    } else {
        2 + usize::from(first & 0x7f)
    };
    let contents = der.get(header..).unwrap_or_else(|| panic!("short DER"));
    let len = contents.len() + extra.len();
    let mut out = vec![0x30];
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or_else(|e| panic!("{e}")));
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).unwrap_or_else(|e| panic!("{e}")));
        out.extend(bytes);
    }
    out.extend_from_slice(contents);
    out.extend_from_slice(extra);
    out
}

/// Bytes after the key's last field, inside its outer SEQUENCE, are refused
/// in every build: a zero byte, and a whole second key. Some key parsers
/// stop at the last field they know and ignore the rest.
#[test]
fn bytes_inside_the_key_structure_after_its_fields_are_refused() {
    let key = keypair();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap_or_else(|e| panic!("leaf params: {e}"));
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let leaf = params
        .self_signed(&key)
        .unwrap_or_else(|e| panic!("leaf: {e}"))
        .pem();
    let one = key.serialize_der();
    let control = block("PRIVATE KEY", &base64(&inside(&one, &[])));
    if let Err(e) = ClientCertifiedKey::from_pem(leaf.as_bytes(), control.as_bytes()) {
        panic!("the re-wrapped control key must load: {e}");
    }
    for extra in [vec![0u8], keypair().serialize_der()] {
        let pem = block("PRIVATE KEY", &base64(&inside(&one, &extra)));
        let refusal = key_refusal(refused(&leaf, &pem));
        assert!(
            matches!(refusal, PemRefusal::KeyNotOneStructure { block: 1 }),
            "{refusal:?}"
        );
    }
}

#[test]
fn attributes_in_the_key_structure_are_refused() {
    let pair = mint();
    loads(&pair);
    let one = PrivatePkcs8KeyDer::from_pem_slice(pair.key.as_bytes()).unwrap();
    let mut wrapped = inside(&[0x30, 0x00], &keypair().serialize_der());
    wrapped[0] = 0xa0;
    for attributes in [vec![0xa0, 0x01, 0xff], wrapped] {
        let pem = block(
            "PRIVATE KEY",
            &base64(&inside(one.secret_pkcs8_der(), &attributes)),
        );
        let refusal = key_refusal(refused(&pair.leaf, &pem));
        assert!(
            matches!(refusal, PemRefusal::KeyNotOneStructure { block: 1 }),
            "{refusal:?}"
        );
    }
}

/// Pins the pinned provider's boundary: the explicit P-256 curve seed is
/// a field's contents the provider does not read, here a malformed BIT
/// STRING (`03 01 ff`). This does not promise acceptance. If a provider
/// tightens, flip the expectation to a refusal and re-read the credential
/// module doc's limit sentence.
#[test]
fn the_provider_skips_the_explicit_curve_seed_without_changing_the_public_key() {
    let from_hex = |hex: &str| {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    let witness = from_hex(concat!(
        "3082012e020100301306072a8648ce3d020106082a8648ce3d03010704820112",
        "3082010e02010104200000000000000000000000000000000000000000000000",
        "000000000000000001a081e63081e3020101302c06072a8648ce3d0101022100",
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "30470420ffffffff00000001000000000000000000000000ffffffffffffffff",
        "fffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce",
        "3c3e27d2604b0301ff0441046b17d1f2e12c4247f8bce6e563a440f277037d81",
        "2deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce3357",
        "6b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffffbc",
        "e6faada7179e84f3b9cac2fc632551020101",
    ));
    let clean = from_hex(concat!(
        "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420",
        "0000000000000000000000000000000000000000000000000000000000000001",
    ));
    let clean = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(clean),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(witness.as_slice()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    let leaf = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let pem = block("PRIVATE KEY", &base64(&witness));
    let credential = ClientCertifiedKey::from_pem(leaf.pem().as_bytes(), pem.as_bytes()).unwrap();
    // Loading requires the held key's SPKI to equal this certificate's.
    let held = ParsedCertificate::try_from(&credential.certificate_chain()[0]).unwrap();
    assert_eq!(
        held.subject_public_key_info().as_ref(),
        clean.subject_public_key_info(),
    );
}

#[test]
fn content_error_layers_redact_display_debug_and_sources() {
    use std::error::Error as _;
    use std::io::Write as _;
    let pair = mint();
    loads(&pair);
    let sentinel = "SECRET_SENTINEL";
    let bad = block(sentinel, sentinel);
    let parsed = refused(&pair.leaf, &bad);
    let provider = || rustls::Error::General(sentinel.into());
    let refusals = [
        PemRefusal::UnknownBlock {
            block: 1,
            label: sentinel.into(),
        },
        PemRefusal::Key(provider()),
        PemRefusal::Certificate {
            block: 1,
            error: provider(),
        },
    ];
    for refusal in refusals {
        assert!(!format!("{refusal} {refusal:?}").contains(sentinel));
        assert!(refusal.source().is_none());
    }
    for error in [
        parsed,
        CredentialError::Key(PemRefusal::Key(provider())),
        CredentialError::Certificate(PemRefusal::Certificate {
            block: 1,
            error: provider(),
        }),
        CredentialError::Mismatch(provider()),
    ] {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        write!(stdout, "{error:?}").unwrap();
        writeln!(stderr, "{error}").unwrap();
        for bytes in [stdout, stderr] {
            let text = String::from_utf8(bytes).unwrap();
            assert!(!text.contains(sentinel));
            assert!(!text.contains(&pair.key));
        }
        assert!(error.source().is_none());
    }
    assert!(format!("{:?}", refused(&pair.leaf, &bad)).contains("unknown PEM block"));
    let loaded = ClientCertifiedKey::from_pem(pair.leaf.as_bytes(), pair.key.as_bytes()).unwrap();
    assert!(!format!("{loaded:?}").contains(&body(&pair.key)));
}
