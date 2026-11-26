// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
#[test]
fn support_export_dispatch_uses_its_own_usage() {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let args = [std::ffi::OsString::from("support-export")];
    let (code, diagnostic) = command_line_code(&args, &mut out, &mut err);
    assert_eq!(
        (
            code,
            out.is_empty() && err.is_empty(),
            diagnostic
                .as_deref()
                .is_some_and(|text| text.contains("usage: granary-server support-export"))
        ),
        (64, true, true),
        "support dispatch: diagnostic={diagnostic:?} out={out:?} err={err:?}"
    );
    err.clear();
    let (code, diagnostic) =
        command_line_code(&[std::ffi::OsString::from("--help")], &mut out, &mut err);
    assert_eq!(
        (
            code,
            out.is_empty(),
            diagnostic.is_none()
                && String::from_utf8_lossy(&err).contains("usage: granary-server\n")
        ),
        (64, true, true),
        "ordinary dispatch positive control: {err:?}"
    );
}
