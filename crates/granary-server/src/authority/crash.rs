// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crash points: named sites between the engine's and the adapter's
//! mutations, where a test process can report that it passed or stop
//! dead for a harness to kill it (the `crash-points` feature, never in a
//! release build: the crate root's wall).
//!
//! A site is `crash_point!(Site)` (or `crash_point!(Site, line)`, which
//! first writes `line` to the pipe). With the feature off the macro
//! expands to nothing. With it on, a site does nothing until a process
//! installs a [`Plan`]:
//!
//! - [`Plan::List`]: every hit appends `HIT <site> <k>` to the pipe, `k`
//!   counting that site's hits in this process, and continues;
//! - [`Plan::Kill`]: the named hit appends `REACHED <site> <k>` and parks
//!   the thread forever. A site never kills its process: the harness
//!   does, after it reads the line.
//!
//! The binary harness additionally uses [`install_host_test_plan`]: a
//! synchronous operation hold reports REACHED and waits for
//! an explicit release file, then continues or returns a sync failure.
//!
//! The pipe is a regular file opened for append; each line is one
//! `write`, in the page cache when it returns, so it outlives a kill.

// The SIGKILL harness installs List/Kill plans; the shipped-binary
// harness uses install_host_test_plan. Feature-on alone
// arms neither facility.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "only the crash harness uses Site::parse and constructs Plan::Kill"
    )
)]

use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// Every crash site, in the order the harness reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub(crate) enum Site {
    /// Intent transaction boundary.
    IntentBeforeTemporary,
    /// Intent transaction boundary.
    IntentTemporaryCreated,
    /// A partial snapshot write reached storage.
    IntentPartialWrite,
    /// Intent transaction boundary.
    IntentTemporaryWritten,
    /// Intent transaction boundary.
    IntentFileSynced,
    /// Intent transaction boundary.
    IntentRenamed,
    /// Intent transaction boundary.
    IntentDirectorySynced,
    /// Intent transaction boundary.
    IntentStateInstalled,
    /// Intent transaction boundary.
    IntentBeforeReply,
    /// Intent transaction boundary.
    IntentReplySent,
    /// Explicit initialise has durably installed its snapshot, before log creation.
    IntentProvisioned,
    /// Explicit initialise has durably published the log after its snapshot.
    IntentProvisionLogSynced,
    /// Intent transaction boundary.
    IntentRebound,
    /// Intent transaction boundary.
    IntentEvicted,

    /// A marker write's removal of a leftover temporary was made (whether
    /// or not one was there).
    MarkerLeftoverRemoved,
    /// A log's removal of a leftover initialise temporary was made
    /// (whether or not one was there): a state-directory mutation.
    LogLeftoverRemoved,
    /// A marker write's temporary was created.
    MarkerTempCreated,
    /// A marker write's temporary was written.
    MarkerTempWritten,
    /// A marker write's temporary was synced.
    MarkerTempSynced,
    /// A marker write's temporary was renamed over the marker.
    MarkerRenamed,
    /// A marker write synced the state directory.
    MarkerStateSynced,
    /// A marker write synced the anchor.
    MarkerAnchorSynced,
    /// Initialise created its temporary.
    InitTempCreated,
    /// Initialise wrote the envelope to its temporary.
    InitTempWritten,
    /// Initialise synced its temporary.
    InitTempSynced,
    /// Initialise linked its temporary to the log's name.
    InitLinked,
    /// Initialise removed its temporary's name.
    InitUnlinked,
    /// Initialise synced the state directory.
    InitStateSynced,
    /// Initialise synced the anchor.
    InitAnchorSynced,
    /// A validation bin read collected its response and has yet to return it.
    ValidationBinRead,
    /// Intake yielded an exhausted slice without writing any authority state.
    IntakeSlice,
    /// Intake finished validation, before it checks the head again.
    IntakeBeforeRecheck,
    /// The candidate passed validation and its decision has not reached append.
    ValidatedBeforeAppend,
    /// The decision append returned durably before the worker sent a reply.
    ValidatedDecisionCommitted,
    /// An append wrote its record.
    RecordWritten,
    /// An append synced its record.
    RecordSynced,
    /// An append wrote its mark.
    MarkWritten,
    /// An append synced its mark: the record is acknowledged.
    MarkSynced,
    /// A truncation cut the log.
    Truncated,
    /// A truncation was synced.
    TruncateSynced,
    /// A log was re-synced.
    Resynced,
    /// A namespace completion removed the temporary's name.
    NamespaceUnlinked,
    /// A namespace completion synced the state directory.
    NamespaceStateSynced,
    /// A namespace completion synced the anchor.
    NamespaceAnchorSynced,
    /// The engine sent a reply.
    ReplySent,
    /// Startup recovery made its last write; no worker has run.
    Recovered,
    /// The harness's driver reported the recovered state; no worker has
    /// run.
    Reported,
    /// A store PUT is about to be sent (the harness's store).
    PutSent,
    /// The store wrote a PUT's temporary.
    PutTempWritten,
    /// The store linked a PUT's temporary to the root's name.
    PutLinked,
    /// The store removed a PUT's temporary.
    PutTempRemoved,
    /// A store PUT returned.
    PutReturned,
}

impl Site {
    /// Every site.
    pub(crate) const ALL: [Self; 52] = [
        Self::IntentBeforeTemporary,
        Self::IntentTemporaryCreated,
        Self::IntentPartialWrite,
        Self::IntentTemporaryWritten,
        Self::IntentFileSynced,
        Self::IntentRenamed,
        Self::IntentDirectorySynced,
        Self::IntentStateInstalled,
        Self::IntentBeforeReply,
        Self::IntentReplySent,
        Self::IntentProvisioned,
        Self::IntentProvisionLogSynced,
        Self::IntentRebound,
        Self::IntentEvicted,
        Self::MarkerLeftoverRemoved,
        Self::LogLeftoverRemoved,
        Self::MarkerTempCreated,
        Self::MarkerTempWritten,
        Self::MarkerTempSynced,
        Self::MarkerRenamed,
        Self::MarkerStateSynced,
        Self::MarkerAnchorSynced,
        Self::InitTempCreated,
        Self::InitTempWritten,
        Self::InitTempSynced,
        Self::InitLinked,
        Self::InitUnlinked,
        Self::InitStateSynced,
        Self::InitAnchorSynced,
        Self::ValidationBinRead,
        Self::IntakeSlice,
        Self::IntakeBeforeRecheck,
        Self::ValidatedBeforeAppend,
        Self::ValidatedDecisionCommitted,
        Self::RecordWritten,
        Self::RecordSynced,
        Self::MarkWritten,
        Self::MarkSynced,
        Self::Truncated,
        Self::TruncateSynced,
        Self::Resynced,
        Self::NamespaceUnlinked,
        Self::NamespaceStateSynced,
        Self::NamespaceAnchorSynced,
        Self::ReplySent,
        Self::Recovered,
        Self::Reported,
        Self::PutSent,
        Self::PutTempWritten,
        Self::PutLinked,
        Self::PutTempRemoved,
        Self::PutReturned,
    ];

    /// The site's name in the pipe.
    #[must_use]
    pub(crate) fn name(self) -> String {
        format!("{self:?}")
    }

    /// The site with `name`, if there is one.
    #[must_use]
    pub(crate) fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|site| site.name() == name)
    }

    /// Its place in [`Self::ALL`], which lists the sites in declaration
    /// order (a test holds it to that).
    fn index(self) -> usize {
        self as usize
    }
}

/// What the installed process does at its sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Report every hit and continue.
    List,
    /// Report every hit; stop dead at the `k`th hit of `site`.
    Kill {
        /// The site.
        site: Site,
        /// Which of its hits, from 1.
        k: u32,
    },
}

/// The installed plan: the pipe, and each site's hits so far.
struct Installed {
    plan: Plan,
    pipe: File,
    hits: [u32; Site::ALL.len()],
    host: Option<HostPlan>,
}

static INSTALLED: Mutex<Option<Installed>> = Mutex::new(None);

/// Install `plan` for this process, its lines appended to the file at
/// `pipe`.
///
/// # Errors
/// The pipe's open error.
pub(crate) fn install(pipe: &Path, plan: Plan) -> std::io::Result<()> {
    let pipe = File::options().create(true).append(true).open(pipe)?;
    *INSTALLED.lock().unwrap_or_else(PoisonError::into_inner) = Some(Installed {
        plan,
        pipe,
        hits: [0; Site::ALL.len()],
        host: None,
    });
    Ok(())
}

/// Select the next observed occurrence without resetting the process counters.
#[cfg(all(test, feature = "overlay-fault-tests"))]
pub(crate) fn arm_next(site: Site, hold: bool) -> u32 {
    let mut guard = INSTALLED.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(installed) = guard.as_mut() else {
        return 0;
    };
    let Some(slot) = installed.hits.get(site.index()) else {
        return 0;
    };
    let k = slot.saturating_add(1);
    installed.plan = if hold {
        Plan::Kill { site, k }
    } else {
        Plan::List
    };
    k
}

/// Append `line` to the installed pipe, if a plan is installed.
pub(crate) fn note(line: &str) {
    if let Some(installed) = INSTALLED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_mut()
    {
        write_line(&mut installed.pipe, line);
    }
}

/// One whole line in one `write`. A failure to write the pipe is a harness
/// failure the harness sees as a missing line.
fn write_line(pipe: &mut File, line: &str) {
    let _ = pipe.write_all(format!("{line}\n").as_bytes());
}

/// A site was reached (the module docs). `line`, if any, is written to the
/// pipe first.
pub(crate) fn hit(site: Site, line: Option<&str>) {
    let stop = {
        let mut guard = INSTALLED.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(installed) = guard.as_mut() else {
            return;
        };
        if let Some(line) = line {
            write_line(&mut installed.pipe, line);
        }
        let Some(slot) = installed.hits.get_mut(site.index()) else {
            return;
        };
        *slot = slot.saturating_add(1);
        let k = *slot;
        let name = site.name();
        match installed.plan {
            Plan::Kill { site: at, k: at_k } if at == site && at_k == k => {
                write_line(&mut installed.pipe, &format!("REACHED {name} {k}"));
                true
            }
            _ => {
                write_line(&mut installed.pipe, &format!("HIT {name} {k}"));
                false
            }
        }
    };
    if stop {
        // Stopped dead, the lock released: the harness kills the process.
        loop {
            std::thread::park();
        }
    }
}

#[cfg(test)]
mod tests;

/// Operations held by the binary harness, separate from the SIGKILL sweep's
/// between-mutation sites. No ordinary crash plan arms these waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostSite {
    /// A support job is about to wait for its directory flock.
    SupportLock,
    /// The real log adapter is about to read a volume at startup.
    LogRead,
    /// The real log adapter is about to append a record.
    LogAppend,
    /// The real log adapter is about to write a marker.
    MarkerWrite,
    /// A committed publication answer, before the final fence check/send.
    Reply,
}

/// Only the shipped-binary test path installs this plan. A release file
/// containing exactly `release` completes the reached/release handshake.
/// The wait is deliberately synchronous: it must occupy the log's thread.
struct HostPlan {
    site: HostSite,
    hits: u32,
    k: u32,
    release: PathBuf,
    fail: bool,
    worker: bool,
}

/// Arm disposable-state process instrumentation. Compiled only with `crash-points`,
/// behind the crate's release wall. No environment variable arms a default
/// build. This is a repository test interface, never an operator option.
///
/// `GRANARY_TEST_HOST_PLAN` is `site:hit:hold` or `site:hit:fail` for
/// `HostLogRead`, `HostLogAppend`, `HostSupportLock` or `HostMarkerWrite`; `HostReply` accepts
/// only `hold`, because a reply cut cannot fabricate a failure. The test supplies
/// `GRANARY_TEST_HOST_REACHED` (an append-only report path),
/// `GRANARY_TEST_HOST_RELEASE` (initially absent), and optionally
/// `GRANARY_TEST_HOST_WORKER=hold` to pin a runtime blocking worker too.
///
/// # Errors
/// Invalid or incomplete instrumentation or a report-file open failure.
pub fn install_host_test_plan() -> std::io::Result<()> {
    let Some(plan) = std::env::var_os("GRANARY_TEST_HOST_PLAN") else {
        return Ok(());
    };
    let invalid = || std::io::Error::other("invalid host test plan");
    let text = plan.to_str().ok_or_else(invalid)?;
    let mut fields = text.split(':');
    let site = match fields.next() {
        Some("HostLogRead") => HostSite::LogRead,
        Some("HostSupportLock") => HostSite::SupportLock,
        Some("HostLogAppend") => HostSite::LogAppend,
        Some("HostMarkerWrite") => HostSite::MarkerWrite,
        Some("HostReply") => HostSite::Reply,
        _ => return Err(invalid()),
    };
    let k = fields
        .next()
        .ok_or_else(invalid)?
        .parse::<u32>()
        .map_err(|_| invalid())?;
    let fail = match fields.next() {
        Some("hold") => false,
        Some("fail") => true,
        _ => return Err(invalid()),
    };
    if !valid_host_plan(site, k, fail, fields.next().is_some()) {
        return Err(invalid());
    }
    let pipe = PathBuf::from(std::env::var_os("GRANARY_TEST_HOST_REACHED").ok_or_else(invalid)?);
    let release = PathBuf::from(std::env::var_os("GRANARY_TEST_HOST_RELEASE").ok_or_else(invalid)?);
    if !pipe.is_absolute() || !release.is_absolute() || release.try_exists()? {
        return Err(invalid());
    }
    let worker = match std::env::var_os("GRANARY_TEST_HOST_WORKER").as_deref() {
        None => false,
        Some(value) if value == "hold" => true,
        _ => return Err(invalid()),
    };
    install(&pipe, Plan::List)?;
    if let Some(installed) = INSTALLED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_mut()
    {
        installed.host = Some(HostPlan {
            site,
            hits: 0,
            k,
            release,
            fail,
            worker,
        });
    }
    Ok(())
}

fn valid_host_plan(site: HostSite, k: u32, fail: bool, trailing: bool) -> bool {
    k != 0 && !trailing && !(site == HostSite::Reply && fail)
}

/// Real adapter operation: report reaching the selected call, wait for an
/// explicit release, then either perform the real operation or fail it.
pub(crate) fn host_io(site: HostSite) -> Result<(), granary_core::decisionlog::LogIoError> {
    let action = {
        let mut guard = INSTALLED.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(installed) = guard.as_mut() else {
            return Ok(());
        };
        let Some(plan) = &mut installed.host else {
            return Ok(());
        };
        if site != plan.site {
            return Ok(());
        }
        plan.hits = plan.hits.saturating_add(1);
        if plan.hits != plan.k {
            return Ok(());
        }
        let action = (plan.release.clone(), plan.fail);
        write_line(
            &mut installed.pipe,
            &format!("REACHED Host{site:?} {}", plan.k),
        );
        action
    };
    let (_keep, wait) = std::sync::mpsc::channel::<()>();
    while !std::fs::read(&action.0).is_ok_and(|bytes| bytes == b"release") {
        let _elapsed = wait.recv_timeout(std::time::Duration::from_millis(10));
    }
    note(&format!("RELEASED Host{site:?}"));
    if action.1 {
        Err(granary_core::decisionlog::LogIoError::SyncFailed)
    } else {
        Ok(())
    }
}

/// Pin a runtime blocking worker for the immediate-process-exit test.
/// The reached line distinguishes this from only pinning the detached
/// authority thread, which runtime destruction would never join.
#[expect(
    clippy::disallowed_methods,
    reason = "test-only runtime destruction discriminator, outside simulator execution"
)]
pub fn hold_host_test_worker() {
    let hold = INSTALLED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .and_then(|installed| installed.host.as_ref())
        .is_some_and(|plan| plan.worker);
    if hold {
        let _worker = tokio::task::spawn_blocking(|| {
            note("REACHED RuntimeWorker 1");
            loop {
                std::thread::park();
            }
        });
    }
}

/// Record the actual write-drain level and transport allowance immediately
/// before the binary forwards host shutdown. Test-only observation.
pub fn observe_host_test_forward(draining: &crate::Draining, deadline: std::time::Duration) {
    note(&format!(
        "FORWARD draining={} deadline={}",
        draining.test_is_draining(),
        deadline.as_secs()
    ));
}

/// Hold the answer to a decision committed by this submission, before its
/// final fence check. Recorded outcomes and refusals do not count as hits.
/// A dropped gateway wait cannot cancel the decision. Reply plans accept only
/// release, never an injected failure.
pub(crate) fn hold_reply() {
    let _released = host_io(HostSite::Reply);
}

/// Observe a reply wait whose gateway deadline expired after successful
/// authority inbox handoff. Admission, inbox waits and draining refusals
/// cannot emit this marker, even if their gateway answer is unavailable.
pub(crate) fn observe_dispatch_loss() {
    note("GATEWAY post-dispatch unavailable");
}

/// Exact publication bytes observed at the real gateway's dispatch boundary.
pub(crate) fn observe_post(
    volume: &str,
    epoch: granary_core::authlog::Epoch,
    operation: &[u8],
    body: &[u8],
) {
    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _written = write!(text, "{byte:02x}");
            text
        })
    }
    note(&format!(
        "POST {volume} {} {} {}",
        hex(&epoch.to_bytes()),
        hex(operation),
        hex(body)
    ));
}
