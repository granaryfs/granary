// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The boot id's parser on every platform, and on Linux the kernel's own
//! file.

use super::*;

const GOOD: &[u8] = b"0123abcd-4567-89ef-fedc-ba9876543210\n";

#[test]
fn the_canonical_text_parses_to_its_sixteen_bytes() {
    let id = parse_boot_id(GOOD).unwrap();
    assert_eq!(
        id.to_bytes(),
        [
            0x01, 0x23, 0xab, 0xcd, 0x45, 0x67, 0x89, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10
        ]
    );
}

#[test]
fn uppercase_hex_is_refused() {
    let text = b"0123ABCD-4567-89ef-fedc-ba9876543210\n";
    assert_eq!(parse_boot_id(text), Err(Malformed::Digit { at: 4 }));
}

#[test]
fn a_wrong_length_is_refused() {
    assert_eq!(parse_boot_id(b""), Err(Malformed::Length { len: 0 }));
    assert_eq!(parse_boot_id(b"\n"), Err(Malformed::Length { len: 1 }));
    // The text without its newline.
    assert_eq!(
        parse_boot_id(&GOOD[..36]),
        Err(Malformed::Length { len: 36 })
    );
    // One digit short, newline kept.
    assert_eq!(
        parse_boot_id(b"0123abcd-4567-89ef-fedc-ba987654321\n"),
        Err(Malformed::Length { len: 36 })
    );
}

#[test]
fn a_non_hex_byte_is_refused() {
    let text = b"0123abcd-4567-89ef-fedc-ba98765432g0\n";
    assert_eq!(parse_boot_id(text), Err(Malformed::Digit { at: 34 }));
    let text = b"0123abcd-4567-89ef-fedc-ba98765432 0\n";
    assert_eq!(parse_boot_id(text), Err(Malformed::Digit { at: 34 }));
}

#[test]
fn a_missing_or_moved_hyphen_is_refused() {
    // The 32 digits with no hyphens, padded to the right length.
    let text = b"0123abcd456789effedcba98765432100000\n";
    assert_eq!(parse_boot_id(text), Err(Malformed::Hyphen { at: 8 }));
    let text = b"0123abc-d4567-89ef-fedc-ba9876543210\n";
    assert_eq!(parse_boot_id(text), Err(Malformed::Digit { at: 7 }));
    let text = b"0123abcd-4567_89ef-fedc-ba9876543210\n";
    assert_eq!(parse_boot_id(text), Err(Malformed::Hyphen { at: 13 }));
}

#[test]
fn trailing_junk_is_refused() {
    // A second newline, or anything after the first, is a wrong length.
    let mut text = GOOD.to_vec();
    text.push(b'\n');
    assert_eq!(parse_boot_id(&text), Err(Malformed::Length { len: 38 }));
    // The right length, but no newline at the end.
    let text = b"0123abcd-4567-89ef-fedc-ba9876543210 ";
    assert_eq!(parse_boot_id(text), Err(Malformed::NoNewline));
    // A newline inside the text.
    let text = b"0123abcd-4567-89ef-fedc-ba987654321\n\n";
    assert_eq!(parse_boot_id(text), Err(Malformed::Digit { at: 35 }));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn every_other_platform_refuses_naming_linux() {
    let refused = host_boot_id().unwrap_err();
    assert!(matches!(refused, BootIdError::NotLinux));
    assert!(refused.to_string().contains("only on Linux"), "{refused}");
}

#[cfg(target_os = "linux")]
#[test]
fn the_kernels_boot_id_reads_the_same_twice() {
    let first = host_boot_id().unwrap();
    let second = host_boot_id().unwrap();
    assert_eq!(first, second);
}
