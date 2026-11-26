// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded output capture for binary-verb fixtures.
use super::process::ChildGuard;
use std::{io, sync::mpsc, time::Duration};

/// Capture both pipes while retaining the child through every refusing path.
pub(super) fn output_within(
    command: &mut std::process::Command,
    bound: Duration,
) -> io::Result<std::process::Output> {
    use std::io::Read as _;
    use std::process::Stdio;
    let mut child = ChildGuard(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("stdout pipe missing"))?;
    let stderr = child
        .0
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("stderr pipe missing"))?;
    let (sender, receiver) = mpsc::channel();
    for (is_stdout, mut pipe) in [
        (true, Box::new(stdout) as Box<dyn io::Read + Send>),
        (false, Box::new(stderr) as Box<dyn io::Read + Send>),
    ] {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = pipe.read_to_end(&mut bytes).map(|_| bytes);
            let _ = sender.send((is_stdout, result));
        });
    }
    drop(sender);
    let status = child.wait_within(bound)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "child did not exit within fixture bound",
        )
    })?;
    let mut output = std::process::Output {
        status,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    for _ in 0..2 {
        let (is_stdout, result) = receiver
            .recv_timeout(Duration::from_secs(2))
            .map_err(|error| io::Error::other(format!("child pipe did not close: {error}")))?;
        if is_stdout {
            output.stdout = result?;
        } else {
            output.stderr = result?;
        }
    }
    Ok(output)
}

pub(super) trait CommandExt {
    fn guarded_output(&mut self) -> io::Result<std::process::Output>;
}

impl CommandExt for std::process::Command {
    fn guarded_output(&mut self) -> io::Result<std::process::Output> {
        output_within(self, Duration::from_secs(20))
    }
}
