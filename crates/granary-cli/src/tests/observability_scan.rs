// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use std::fmt::Write as _;

pub(crate) const SECRETS: &[&str] = &[
    "seed-endpoint-731",
    "seed-bucket-732",
    "seed-region-733",
    "seed-scope-734",
    "seed-principal-735",
    "seed-volume-736",
    "seed-digest-737",
    "seed-key-identity-738",
    "seed-certificate-path-739",
    "seed-token-740",
    "seed-key-bytes-741",
    "seed-provider-error-742",
    "seed-escaped-743\n\"\\\u{1b}",
];
pub(crate) const ORDINARY: &[&str] = &[
    "seed-directory-744/seed-basename-745",
    "seed-basename-745",
    "seed-entry-746",
];

fn forms(secret: &str) -> Vec<String> {
    let mut escaped = String::new();
    let mut unicode = String::new();
    let mut hex = String::new();
    for byte in secret.bytes() {
        let _ = write!(unicode, "\\u{byte:04x}");
        let _ = write!(hex, "{byte:02x}");
        match byte {
            b'"' => escaped.push_str("\\\""),
            b'\\' => escaped.push_str("\\\\"),
            b'\n' => escaped.push_str("\\n"),
            0..=31 => {
                let _ = write!(escaped, "\\u{byte:04x}");
            }
            _ => escaped.push(char::from(byte)),
        }
    }
    let nested = escaped.replace('\\', "\\\\").replace('"', "\\\"");
    let array = secret
        .bytes()
        .map(|byte| byte.to_string())
        .collect::<Vec<_>>()
        .join(",");
    vec![
        secret.to_owned(),
        escaped,
        nested,
        unicode,
        hex.to_uppercase(),
        hex,
        format!("[{array}]"),
    ]
}

pub(crate) fn scan(captures: &[String], secrets: &[&str]) -> Result<(), &'static str> {
    if captures.is_empty() || captures.iter().any(String::is_empty) || secrets.is_empty() {
        return Err("missing or empty capture premise");
    }
    for capture in captures {
        let compact: String = capture.chars().filter(|c| !c.is_whitespace()).collect();
        for secret in secrets {
            for form in forms(secret) {
                if capture.contains(&form) || compact.contains(&form) {
                    return Err("seeded material reached a protected surface");
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn scan_reads(
    captures: impl IntoIterator<Item = std::io::Result<String>>,
    secrets: &[&str],
) -> Result<Vec<String>, &'static str> {
    let captures = captures
        .into_iter()
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|_| "capture unavailable")?;
    scan(&captures, secrets)?;
    Ok(captures)
}

#[test]
fn encoded_scanner_pairs_each_representation_with_clean_and_missing_controls() {
    let mut cases = 0;
    for secret in SECRETS.iter().chain(ORDINARY) {
        for form in forms(secret) {
            assert_eq!(
                scan(&[form], &[*secret]),
                Err("seeded material reached a protected surface"),
                "encoded scanner missed seeded representation"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 112, "nonempty encoding control inventory");
    assert_eq!(scan(&["safe count=7".to_owned()], SECRETS), Ok(()));
    for captures in [vec![], vec![String::new()]] {
        assert_eq!(
            scan(&captures, SECRETS),
            Err("missing or empty capture premise")
        );
    }
    let read = |result: std::io::Result<String>| scan_reads([result], SECRETS);
    assert!(read(Ok("safe count=7".to_owned())).is_ok());
    for kind in [
        std::io::ErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied,
    ] {
        assert_eq!(
            read(Err(std::io::Error::from(kind))),
            Err("capture unavailable")
        );
    }
}
