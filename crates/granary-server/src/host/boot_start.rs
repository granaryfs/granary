// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Host kernel boot start, in Unix seconds, for the operator's unfence rule.

use std::io;

/// Parse exactly one signed Unix-seconds `btime` from the kernel's proc-stat text.
///
/// # Errors
/// Refuses absent, duplicate, malformed or out-of-range boot times.
pub fn parse_boot_start(text: &str) -> io::Result<i64> {
    let mut found = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("btime") {
            continue;
        }
        let value = fields.next().and_then(|word| word.parse::<i64>().ok());
        if found.is_some() || fields.next().is_some() || value.is_none() {
            return Err(io::Error::other("the host's boot start is malformed"));
        }
        found = value;
    }
    found.ok_or_else(|| io::Error::other("the host's boot start is missing"))
}

#[cfg(any(target_os = "linux", test))]
fn read_boot_start<R: io::Read>(
    mut boot_id: impl FnMut() -> io::Result<granary_core::runmarker::BootId>,
    open_stat: impl FnOnce() -> io::Result<R>,
) -> io::Result<i64> {
    use std::io::Read as _;
    let before = boot_id()?;
    let mut text = String::new();
    open_stat()?.take(1_048_577).read_to_string(&mut text)?;
    if text.len() > 1_048_576 {
        return Err(io::Error::other(
            "the host's proc stat exceeds 1048576 bytes",
        ));
    }
    let start = parse_boot_start(&text)?;
    let after = boot_id()?;
    if before != after {
        return Err(io::Error::other("the host's boot identity changed"));
    }
    Ok(start)
}

/// Read the host kernel's boot start from `/proc/stat`, bounded to 1 MiB.
/// Reads the boot id on both sides to refuse a changing boot identity.
/// The proc mount must describe the kernel whose page cache holds the state.
///
/// # Errors
/// Refuses other platforms, unreadable or malformed proc data, and a changed
/// boot identity. No process-start or container-start fallback exists.
pub fn host_boot_start() -> io::Result<i64> {
    #[cfg(target_os = "linux")]
    {
        read_boot_start(
            || super::boot_id::host_boot_id().map_err(io::Error::other),
            || std::fs::File::open("/proc/stat"),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::other(
            "this platform has no host boot start reader; unfence requires Linux",
        ))
    }
}

#[cfg(test)]
mod tests;
