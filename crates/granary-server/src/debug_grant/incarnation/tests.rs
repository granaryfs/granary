// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

struct Script {
    fills: usize,
    fail: bool,
}
impl SecureRandom for Script {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
        self.fills += 1;
        assert_eq!(dest.len(), 16, "one complete sixteen-byte secure draw");
        for (byte, n) in dest.iter_mut().zip(0_u8..) {
            *byte = n;
        }
        if self.fail {
            Err(EntropyUnavailable)
        } else {
            Ok(())
        }
    }
}

#[test]
fn debug_grant_incarnation_draw_preserves_every_byte_and_clones_share_it() {
    let mut random = Script {
        fills: 0,
        fail: false,
    };
    let token = ServerIncarnation::draw(&mut random).unwrap();
    assert_eq!(random.fills, 1);
    assert_eq!(
        token.value().as_bytes(),
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
    let clone = token.clone();
    assert!(Arc::ptr_eq(&token.0, &clone.0));
    assert_eq!(
        clone.to_string(),
        "incarnation:000102030405060708090a0b0c0d0e0f"
    );
}

#[test]
fn debug_grant_incarnation_failed_partial_draw_has_no_fallback() {
    let mut random = Script {
        fills: 0,
        fail: true,
    };
    assert!(matches!(
        ServerIncarnation::draw(&mut random),
        Err(EntropyUnavailable)
    ));
    assert_eq!(random.fills, 1, "no retry or substitute draw");
}
