// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
#[test]
fn support_export_reports_fixed_io_reasons() {
    let poison = "SECRET arbitrary error\nsecond line";
    for (error, expected) in [
        (
            SupportExportError::Io(std::io::Error::other(poison)),
            "I/O failure",
        ),
        (
            SupportExportError::PublicationUncertain(std::io::Error::other(poison)),
            "publication uncertain",
        ),
    ] {
        assert_eq!(failure(&error), (74, expected.to_owned()));
    }
}

// A missing source directory is the operator's precondition, refused before
// publication like every other protection failure, not an I/O failure.
#[test]
fn support_export_missing_directory_is_a_refusal() {
    let missing = ProtectionError::Missing {
        component: std::path::PathBuf::from("/absent"),
    };
    assert_eq!(
        failure(&SupportExportError::Io(std::io::Error::other(missing))),
        (65, "directory missing".to_owned())
    );
}
