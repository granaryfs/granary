// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use super::super::{
    testkit::{ScriptedStream, frame},
    tests::hello,
};
use super::*;

#[test]
fn control_frame_bound_precedes_allocation() {
    let mut cases = 0;
    for length in [11_u32, 8192, 8193, u32::MAX, 0, 10] {
        let mut allocations = Vec::new();
        let actual = allocate_body(length.to_be_bytes(), |size| {
            allocations.push(size);
            if size <= 8192 {
                vec![0; size]
            } else {
                Vec::new()
            }
        });
        let valid = (11..=8192).contains(&length);
        let observed = (
            actual.as_ref().ok().map(Vec::len),
            allocations.clone(),
            actual.as_ref().err().map(ToString::to_string),
        );
        let expected = if valid {
            (Some(length as usize), vec![length as usize], None)
        } else {
            (
                None,
                Vec::new(),
                Some("invalid mount control body length (must be 11..=8192)".to_owned()),
            )
        };
        assert_eq!(observed, expected, "length={length}, actual={actual:?}");
        cases += 1;
    }
    assert_eq!(cases, 6);
}

#[tokio::test]
async fn control_frame_truncation() {
    let mut cases = 0;
    for message in [
        Message::Hello(hello()),
        Message::Stop {
            instance: hello().instance,
            key: hello().key,
        },
        Message::Accepted(hello().instance),
    ] {
        let bytes = frame(&message);
        for cut in 0..=bytes.len() {
            let (mut stream, script) = ScriptedStream::new(bytes[..cut].to_vec());
            script.lock().unwrap().eof = true;
            let actual = Reader::default().read(&mut stream).await;
            if cut == bytes.len() {
                assert_eq!(actual.unwrap(), message);
            } else {
                assert_eq!(actual.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
            }
            cases += 1;
        }
    }
    assert!(cases > 100, "framing cases={cases}");
}
