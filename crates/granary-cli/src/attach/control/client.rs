// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! A single authenticated exchange; failures after Stop never retarget.

use super::super::{MountOutcome, mount_status_line};
use super::{
    mount_result, peer_admitted, report_from_wire,
    transport::{Reader, Stream, Writer, malformed},
};
use granary_client::{SyncRuntime, TokioSyncRuntime};
use granary_core::mount_control::{Hello, Message, Mode, MountKey};
use std::{io, time::Duration};
#[cfg(target_os = "linux")]
use tokio::net::UnixStream;

const HANDSHAKE_BOUND: Duration = Duration::from_secs(2);
const REPORT_ALLOWANCE: Duration = Duration::from_millis(35_500);

fn final_wait(hello: &Hello) -> Duration {
    let seconds = match &hello.mode {
        Mode::ReadOnly => 0,
        Mode::Writable { bound_seconds, .. } => *bound_seconds,
    };
    Duration::from_secs(seconds.into()).saturating_add(REPORT_ALLOWANCE)
}

fn unknown(hello: Option<&Hello>) -> String {
    match hello.map(|hello| &hello.mode) {
        Some(Mode::Writable { store, .. }) => format!(
            "gran umount: shutdown outcome unknown; preserve store {}; inspect the daemon's status",
            super::escaped_path(store)
        ),
        _ => "gran umount: shutdown outcome unavailable; inspect the daemon's status".into(),
    }
}

fn status(hello: &Hello, message: &Message) -> io::Result<(MountOutcome, String)> {
    hello.validate_final(message).map_err(malformed)?;
    let Message::Final { result, report, .. } = message else {
        return Err(malformed("expected Final"));
    };
    let outcome = mount_result(*result);
    let line = match &hello.mode {
        Mode::ReadOnly => mount_status_line("gran umount", None, outcome),
        Mode::Writable { store, .. } => {
            use std::os::unix::ffi::OsStrExt as _;
            mount_status_line(
                "gran umount",
                Some((
                    report.map(report_from_wire),
                    std::path::Path::new(std::ffi::OsStr::from_bytes(store)),
                )),
                outcome,
            )
        }
    };
    Ok((outcome, line))
}

/// # Cancellation safety
/// The caller closes this stream on error or cancellation. Partial Stop and
/// lost Accepted never authorize reconnect, detach or another stop request.
pub(super) async fn exchange<R: SyncRuntime, S: Stream>(
    mut stream: S,
    key: MountKey,
    owner: u32,
    admitted: u32,
    handshake: tokio::time::Instant,
    runtime: &R,
    report: &dyn Fn(String),
) -> io::Result<MountOutcome> {
    let mut reader = Reader::default();
    let initial = async {
        if !peer_admitted(stream.peer_uid(), owner, admitted) {
            return Err(malformed(
                "refusing: control server peer uid mismatch or unavailable",
            ));
        }
        match runtime
            .timeout_at(handshake, reader.read(&mut stream))
            .await
            .map_err(|_| malformed("control Hello deadline"))??
        {
            Message::Hello(hello) if hello.key == key => Ok(hello),
            Message::Hello(_) => Err(malformed("refusing: control mount identity mismatch")),
            _ => Err(malformed("refusing: expected control Hello")),
        }
    }
    .await;
    let hello = match initial {
        Ok(hello) => hello,
        Err(error) => {
            report(unknown(None));
            return Err(error);
        }
    };
    let stop_start = runtime.now();
    let result = async {
        let accepted_deadline = stop_start
            .checked_add(HANDSHAKE_BOUND)
            .ok_or_else(|| malformed("control deadline overflow"))?;
        let final_deadline = stop_start
            .checked_add(final_wait(&hello))
            .ok_or_else(|| malformed("control deadline overflow"))?;
        let mut stop = Writer::new(&Message::Stop {
            instance: hello.instance,
            key,
        })?;
        runtime
            .timeout_at(accepted_deadline, stop.write(&mut stream))
            .await
            .map_err(|_| malformed("control Stop deadline"))??;
        let accepted = runtime
            .timeout_at(accepted_deadline, reader.read(&mut stream))
            .await
            .map_err(|_| malformed("control Accepted deadline"))??;
        if accepted != Message::Accepted(hello.instance) {
            return Err(malformed("refusing: expected matching control Accepted"));
        }
        let final_message = runtime
            .timeout_at(final_deadline, reader.read(&mut stream))
            .await
            .map_err(|_| malformed("control Final deadline"))??;
        let (outcome, line) = status(&hello, &final_message)?;
        report(line);
        Ok(outcome)
    }
    .await;
    if result.is_err() {
        report(unknown(Some(&hello)));
    }
    result
}

#[derive(Debug)]
pub(in crate::attach) struct Failure {
    pub absent_before_stop: bool,
}

#[cfg(target_os = "linux")]
pub(in crate::attach) fn umount(
    target: &std::path::Path,
    mount: super::super::mount_table::ControlMount,
    admitted: u32,
    report: &dyn Fn(String),
) -> Result<MountOutcome, Failure> {
    let exchange_started = std::cell::Cell::new(false);
    let result = (|| {
        let directory = super::endpoint::Directory::open(mount.owner, false)
            .map_err(|error| (error.kind() == io::ErrorKind::NotFound, error))?;
        let name = super::endpoint::socket_name(
            (mount.key.namespace_dev, mount.key.namespace_ino),
            target,
        );
        let (path, meta) = directory
            .connect_path(&name, mount.owner)
            .map_err(|error| (error.kind() == io::ErrorKind::NotFound, error))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| (false, error))?;
        runtime.block_on(async {
            let deadline = TokioSyncRuntime
                .now()
                .checked_add(HANDSHAKE_BOUND)
                .ok_or_else(|| (false, malformed("control handshake deadline overflow")))?;
            let stream = TokioSyncRuntime
                .timeout_at(deadline, UnixStream::connect(&path))
                .await
                .map_err(|_| (false, malformed("control connect deadline")))?
                .map_err(|error| (directory.connection_absent(&name, &meta, &error), error))?;
            directory
                .recheck_socket(&name, &meta)
                .map_err(|error| (false, error))?;
            exchange_started.set(true);
            exchange(
                stream,
                mount.key,
                mount.owner,
                admitted,
                deadline,
                &TokioSyncRuntime,
                report,
            )
            .await
            .map_err(|error| (false, error))
        })
    })();
    result.map_err(|(absent_before_stop, error)| {
        report(format!("gran umount: {error}"));
        if !exchange_started.get() {
            report(unknown(None));
        }
        Failure { absent_before_stop }
    })
}

#[cfg(test)]
mod tests;
