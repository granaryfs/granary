// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Nonshipping process rendezvous. Only an existing fallible boundary can fail.

use std::collections::BTreeMap;
use std::io::{self, BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::Duration;

use granary_core::retained_submission::{Phase, Submission};

/// The single registry shared by the executable and the coverage gate.
pub const CUTS: &[&str] = &[
    "load",
    "begin",
    "probe-save",
    "probe-delivered",
    "probe-result",
    "attempt-save",
    "dispatch",
    "answer-save",
    "epoch-save",
    "operation-save",
    "replacement-save",
    "complete-save",
    "cache-repair",
    "hint-repair",
    "output-write",
    "abandon-save",
    "archive-rename",
    "archive-sync",
    "archive-marker-sync",
    "archive-root-sync",
    "archive-parent-sync",
    "archive-publications-sync",
    "archive-scope-sync",
    "archive-open",
    "archive-file-sync",
    "archive-final-sync",
    "marker-sync",
    "root-sync",
    "parent-sync",
    "publications-create",
    "publications-root-sync",
    "scope-create",
    "publications-sync",
    "temporary-create",
    "temporary-write",
    "temporary-sync",
    "temporary-install",
    "scope-sync",
];

/// Delivery is observed only after the transport returns.
pub const AFTER_ONLY_CUTS: &[&str] = &["probe-delivered"];

/// Physical persistence operations, independent of registry order.
pub const PHYSICAL_CUTS: &[&str] = &[
    "marker-sync",
    "root-sync",
    "parent-sync",
    "publications-create",
    "publications-root-sync",
    "scope-create",
    "publications-sync",
    "temporary-create",
    "temporary-write",
    "temporary-sync",
    "temporary-install",
    "scope-sync",
];

/// Re-establishing an existing archive never advances its generation.
pub const ARCHIVE_CUTS: &[&str] = &[
    "archive-marker-sync",
    "archive-root-sync",
    "archive-parent-sync",
    "archive-publications-sync",
    "archive-scope-sync",
    "archive-open",
    "archive-file-sync",
    "archive-final-sync",
];

#[cfg(test)]
mod tests;

struct Control {
    stream: BufReader<UnixStream>,
    cut: String,
    side: String,
    occurrence: u64,
    hits: BTreeMap<(String, String), u64>,
}
static CONTROL: Mutex<Option<Control>> = Mutex::new(None);

#[cfg(test)]
thread_local! {
    static TEST_FAILURE: std::cell::Cell<Option<(&'static str, &'static str)>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(crate) fn fail_once_for_test(cut: &'static str, side: &'static str) {
    TEST_FAILURE.set(Some((cut, side)));
}

/// Connect only when explicitly armed by the parent. The reply wait is bounded
/// to thirty seconds; disconnect, malformed reply and timeout fail the operation.
/// # Errors
/// Invalid test configuration or rendezvous connection.
pub fn initialize() -> io::Result<()> {
    let Some(socket) = std::env::var_os("GRANARY_RESTART_SOCKET") else {
        return Ok(());
    };
    let cut = std::env::var("GRANARY_RESTART_CUT").map_err(io::Error::other)?;
    let side = std::env::var("GRANARY_RESTART_SIDE").map_err(io::Error::other)?;
    let occurrence = std::env::var("GRANARY_RESTART_OCCURRENCE")
        .map_err(io::Error::other)?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    if !CUTS.contains(&cut.as_str())
        || !["before", "after"].contains(&side.as_str())
        || AFTER_ONLY_CUTS.contains(&cut.as_str()) && side != "after"
        || occurrence == 0
    {
        return Err(io::Error::other("invalid restart rendezvous selection"));
    }
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    *CONTROL
        .lock()
        .map_err(|_| io::Error::other("rendezvous lock poisoned"))? = Some(Control {
        stream: BufReader::new(stream),
        cut,
        side,
        occurrence,
        hits: BTreeMap::new(),
    });
    Ok(())
}

// Unarmed component models can exercise the physical seam with opaque bytes.
// Decode observation identity only for an armed executable, after persist has
// already validated and encoded its record.
pub(crate) fn persistence_record(bytes: &[u8]) -> io::Result<Option<Submission>> {
    if CONTROL
        .lock()
        .map_err(|_| io::Error::other("rendezvous lock poisoned"))?
        .is_none()
    {
        return Ok(None);
    }
    granary_core::retained_submission::decode(bytes)
        .map(Some)
        .map_err(io::Error::other)
}

pub(crate) fn persistence_point(
    cut: &str,
    side: &str,
    record: Option<&Submission>,
) -> io::Result<()> {
    record.map_or(Ok(()), |record| point(cut, side, record))
}

fn phase(record: &Submission) -> &'static str {
    match record.phase {
        Phase::Ready => "ready",
        Phase::ProbeStarted(_) => "probe-started",
        Phase::Unresolved(_) => "unresolved",
        Phase::AwaitingAnswer { .. } => "awaiting-answer",
        Phase::Rebase => "rebase",
        Phase::EpochRecovery { .. } => "epoch-recovery",
        Phase::Complete(_) => "complete",
    }
}

/// Observe a boundary, preserving the exact publication. At persistence cuts,
/// `fail` propagates an I/O error through the caller's existing failure path.
/// At observation-only cuts it is a protocol error and terminates the child.
/// # Errors
/// Parent-injected failure or broken rendezvous.
pub fn point(cut: &str, side: &str, record: &Submission) -> io::Result<()> {
    #[cfg(test)]
    if TEST_FAILURE.get() == Some((cut, side)) {
        TEST_FAILURE.set(None);
        return handle_reply(cut, "fail\n");
    }
    let mut control = CONTROL
        .lock()
        .map_err(|_| io::Error::other("rendezvous lock poisoned"))?;
    let Some(c) = control.as_mut() else {
        return Ok(());
    };
    let hit = c.hits.entry((cut.to_owned(), side.to_owned())).or_default();
    *hit = hit
        .checked_add(1)
        .ok_or_else(|| io::Error::other("rendezvous occurrence exhausted"))?;
    if c.cut != cut || c.side != side || *hit != c.occurrence {
        return Ok(());
    }
    let mut id = String::new();
    for byte in record.publication_id {
        use std::fmt::Write as _;
        write!(&mut id, "{byte:02x}").map_err(io::Error::other)?;
    }
    writeln!(
        c.stream.get_mut(),
        "REACHED {cut} {side} {hit} {id} {} {}",
        phase(record),
        record.generation
    )?;
    // Read only a tiny fixed command. No unbounded read of parent input.
    let mut reply = String::new();
    c.stream.by_ref().take(16).read_line(&mut reply)?;
    handle_reply(cut, &reply)
}

fn handle_reply(cut: &str, reply: &str) -> io::Result<()> {
    match reply {
        "continue\n" => Ok(()),
        "fail\n"
            if PHYSICAL_CUTS.contains(&cut)
                || ARCHIVE_CUTS.contains(&cut)
                || matches!(
                    cut,
                    "load"
                        | "begin"
                        | "probe-save"
                        | "probe-result"
                        | "attempt-save"
                        | "answer-save"
                        | "epoch-save"
                        | "operation-save"
                        | "replacement-save"
                        | "complete-save"
                        | "abandon-save"
                        | "archive-rename"
                        | "archive-sync"
                ) =>
        {
            Err(io::Error::other("restart rendezvous injected failure"))
        }
        _ => {
            let _ = writeln!(
                io::stderr(),
                "restart rendezvous protocol error: invalid reply {reply:?} at {cut}"
            );
            std::process::exit(1)
        }
    }
}
