// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private process fixtures shared by integration and socket-free controls.
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::Duration;
use tokio::time::{sleep, timeout};

pub(crate) const WAIT: Duration = Duration::from_secs(10);
pub(crate) const HOST_DRAIN: Duration = granary_net::accept::SHUTDOWN_DEADLINE;
pub(crate) const HOST_EXIT: Duration = HOST_DRAIN.saturating_add(Duration::from_secs(2));

pub(crate) fn prepare_root(root: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(root)?;
    root.canonicalize()
}

pub(crate) struct Scratch(pub(crate) PathBuf);
impl Scratch {
    #[expect(
        clippy::disallowed_methods,
        reason = "process ID isolates test-owned private scratch"
    )]
    pub(crate) fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        #[cfg(target_os = "macos")]
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target");
        #[cfg(not(target_os = "macos"))]
        let root = std::env::temp_dir();
        let dir = prepare_root(&root)
            .unwrap()
            .join(format!("gran-r-{}-{n}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) struct Process {
    pub(super) child: Option<Child>,
    log: Option<PathBuf>,
    captured: Option<Output>,
}
impl Process {
    pub(crate) fn spawn(cmd: &mut Command) -> Self {
        Self {
            log: None,
            captured: None,
            child: Some(
                cmd.stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
            ),
        }
    }
    pub(crate) fn spawn_logged(cmd: &mut Command, path: &Path) -> Self {
        let log = std::fs::File::create(path).unwrap();
        cmd.stdout(log.try_clone().unwrap()).stderr(log);
        Self {
            child: Some(cmd.spawn().unwrap()),
            log: Some(path.to_owned()),
            captured: None,
        }
    }
    fn append_log(&self, output: &mut Output) {
        if let Some(path) = &self.log {
            let log = std::fs::read(path).unwrap_or_else(|error| {
                format!("cannot read host log {}: {error}", path.display()).into_bytes()
            });
            output.stderr.extend_from_slice(b"host log:\n");
            output.stderr.extend_from_slice(&log);
        }
    }
    /// Reap only this fixture's child and retain output for later callers too.
    pub(crate) fn stop_and_capture(&mut self) -> &Output {
        if self.captured.is_none() {
            let mut child = self.child.take().unwrap();
            let _ = child.kill();
            let mut output = child.wait_with_output().unwrap();
            self.append_log(&mut output);
            self.captured = Some(output);
        }
        self.captured.as_ref().unwrap()
    }
    pub(crate) async fn host_output(self) -> Output {
        self.output_with_bound(HOST_EXIT).await
    }
    #[cfg(feature = "crash-points")]
    pub(crate) fn id(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }
    pub(crate) fn close_stdout(&mut self) {
        drop(self.child.as_mut().unwrap().stdout.take());
    }
    pub(crate) async fn output(self) -> Output {
        self.output_with_bound(WAIT).await
    }
    pub(crate) fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child.as_mut().unwrap().try_wait().unwrap()
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "test process liveness uses a bounded runtime timer outside simulator execution"
    )]
    pub(crate) async fn wait_for_exit(
        &mut self,
        bound: Duration,
    ) -> Result<ExitStatus, tokio::time::error::Elapsed> {
        timeout(bound, async {
            loop {
                if let Some(status) = self.try_wait() {
                    return status;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
    }
    pub(crate) async fn output_with_bound(mut self, bound: Duration) -> Output {
        if let Some(output) = self.captured.take() {
            return output;
        }
        let timed_out = self.wait_for_exit(bound).await.is_err();
        if timed_out {
            let _ = self.child.as_mut().unwrap().kill();
        }
        let mut output = self.child.take().unwrap().wait_with_output().unwrap();
        self.append_log(&mut output);
        assert!(
            !timed_out,
            "child exit exceeded rendezvous bound\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }
    #[cfg(feature = "crash-points")]
    pub(crate) fn assert_or_kill(&mut self, condition: bool, message: &str) {
        if !condition {
            let output = self.stop_and_capture();
            assert!(
                condition,
                "{message}\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    pub(crate) async fn kill(mut self) -> Output {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }
        self.output().await
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
