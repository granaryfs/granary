// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

struct FailedRead;
impl io::Read for FailedRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected stream failure"))
    }
}

#[test]
fn boot_start_requires_one_complete_value() {
    assert_eq!(parse_boot_start("cpu 1 2 3\nbtime 123\n").unwrap(), 123);
    assert_eq!(parse_boot_start("btime 0\n").unwrap(), 0);
    assert_eq!(parse_boot_start("btime -1\n").unwrap(), -1);
    for text in [
        "",
        "btime",
        "btime 123 extra",
        "btime 123\nbtime 124",
        "btime 99999999999999999999",
    ] {
        assert!(parse_boot_start(text).is_err(), "accepted {text:?}");
    }
}

#[test]
fn boot_reader_refuses_changed_identity_and_oversize_text() {
    use granary_core::runmarker::BootId;
    let first = BootId::from_bytes([1; 16]);
    let second = BootId::from_bytes([2; 16]);
    let mut calls = 0;
    let result = read_boot_start(
        || {
            calls += 1;
            Ok(if calls == 1 { first } else { second })
        },
        || Ok(io::Cursor::new(b"btime 123\n")),
    );
    assert_eq!(
        (calls, result.unwrap_err().to_string()),
        (2, "the host's boot identity changed".into())
    );
    let mut text = b"btime 123\n".to_vec();
    text.resize(1_048_577, b' ');
    let result = read_boot_start(|| Ok(first), || Ok(io::Cursor::new(&text)));
    assert_eq!(
        result.unwrap_err().to_string(),
        "the host's proc stat exceeds 1048576 bytes"
    );
    text.truncate(1_048_576);
    assert_eq!(
        read_boot_start(|| Ok(first), || Ok(io::Cursor::new(&text))).unwrap(),
        123
    );
}

#[test]
fn boot_reader_propagates_open_read_and_both_identity_failures() {
    use granary_core::runmarker::BootId;
    let id = BootId::from_bytes([1; 16]);
    let failure = || io::Error::other("injected boot read failure");
    let result = read_boot_start::<io::Cursor<Vec<u8>>>(|| Ok(id), || Err(failure()));
    assert_eq!(
        result.unwrap_err().to_string(),
        "injected boot read failure"
    );
    let result = read_boot_start(|| Ok(id), || Ok(FailedRead));
    assert_eq!(result.unwrap_err().to_string(), "injected stream failure");
    for fail_at in [1, 2] {
        let mut calls = 0;
        let result = read_boot_start(
            || {
                calls += 1;
                if calls == fail_at {
                    Err(failure())
                } else {
                    Ok(id)
                }
            },
            || Ok(io::Cursor::new(b"btime 123\n")),
        );
        assert_eq!(
            (calls, result.unwrap_err().to_string()),
            (fail_at, "injected boot read failure".into())
        );
    }
}
