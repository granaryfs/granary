// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Shared mountinfo parser instrumentation for fuzzing and stable corpus replay.
//! No stability promise attaches to this entry point.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

/// Query path bytes, a NUL separator, then the mountinfo body. NUL cannot
/// occur in a filesystem path; using it preserves literal newlines in paths.
/// Inputs without a separator query an empty body.
///
/// Exercises parser and decoder panic freedom. The assertion repeats the
/// selector's own decoder, so it is not an independent correctness oracle.
/// Well-formed non-canonical octal escapes are accepted too: `\101` decodes
/// to `A`, although the kernel would write `A` literally.
///
/// # Panics
/// If an accepted row's mount point cannot decode or differs from the query.
pub fn mountinfo_body_probe(data: &[u8]) {
    let mut parts = data.splitn(2, |&byte| byte == 0);
    let wanted = parts.next().unwrap_or_default();
    let body = parts.next().unwrap_or_default();
    let path = Path::new(OsStr::from_bytes(wanted));
    if let Ok(rows) = crate::mountinfo_rows_at(body, path) {
        for row in rows {
            assert_eq!(
                super::mountinfo_unescape(row.mount_point).as_deref().ok(),
                Some(wanted),
                "selected mount point must decode to the query bytes"
            );
        }
    }
}
