// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#[test]
fn lifecycle_commands_dispatch_before_configuration() {
    for verb in ["initialise", "unfence"] {
        let args = vec![std::ffi::OsString::from(verb)];
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = super::command_line_code(&args, &mut out, &mut err);
        assert_eq!(result, (64, None));
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("usage: granary-server initialise")
        );
    }
}
