// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Canonical local mount control.

use crate::encoding::DecodeError;

mod codec;
pub use codec::{decode, encode, frame_length};

/// Common body magic.
pub const MAGIC: [u8; 8] = *b"GRNUMCTL";
/// Only supported wire version.
pub const VERSION: u16 = 1;
/// Maximum body allocation, excluding the four-byte length prefix.
pub const MAX_BODY: usize = 8192;
/// Maximum raw store path in Hello.
pub const MAX_STORE_PATH: usize = 4096;

/// One public daemon incarnation, drawn before mounting.
pub type Instance = [u8; 16];

/// Kernel identity independently observed by both processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountKey {
    pub namespace_dev: u64,
    pub namespace_ino: u64,
    pub mount_id: u32,
    pub fuse_major: u32,
    pub fuse_minor: u32,
}

/// The serving mode and its reporting parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    ReadOnly,
    Writable { bound_seconds: u32, store: Vec<u8> },
}
impl Mode {
    /// Validate reporting parameters before endpoint setup or allocation.
    ///
    /// # Errors
    /// Refuses writable bounds outside 1–3600 and empty, overlong or NUL paths.
    pub fn validate(&self) -> Result<(), Error> {
        if let Self::Writable {
            bound_seconds,
            store,
        } = self
            && (!(1..=3600).contains(bound_seconds)
                || store.is_empty()
                || store.len() > MAX_STORE_PATH
                || store.contains(&0))
        {
            return Err(invalid("mount control mode/bound/store"));
        }
        Ok(())
    }
}

/// A checked daemon advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub instance: Instance,
    pub key: MountKey,
    pub mode: Mode,
}

/// The daemon's complete decision, independent of its data report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultKind {
    Clean,
    RuntimeFailure,
    CacheCloseFailed,
    Stopped,
    Fenced,
}

/// Closed failure-class domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    Io,
    Refused,
    Conflict,
    Unavailable,
    Corrupt,
    Internal,
}

/// The shutdown's data outcome, including the recorded cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKind {
    Committed(u64),
    Clean,
    Bound,
    Signal,
    UnknownCut,
    Failed(FailureClass),
    Internal,
    Fenced,
}

/// Counts read after shutdown, absent when unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Residue {
    pub files: u64,
    pub bytes: u64,
    pub operations: u64,
}

/// Status accompanying a complete daemon decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub kind: ReportKind,
    pub elapsed_ms: u64,
    pub residue: Option<Residue>,
}

/// Exchange refusal; credential failures send no frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    Starting,
    IdentityMismatch,
    MalformedRequest,
    Busy,
    Closing,
    CoordinatorLost,
}

/// One body. Stream ordering is checked by the exchange state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Hello(Hello),
    Stop {
        instance: Instance,
        key: MountKey,
    },
    Accepted(Instance),
    Final {
        instance: Instance,
        result: ResultKind,
        report: Option<Report>,
    },
    Reject(Reject),
}

/// A strict encoding/decoding failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    BadMagic,
    UnknownVersion(u16),
    Fields(DecodeError),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => f.write_str("bad mount control magic"),
            Self::UnknownVersion(v) => write!(f, "unknown mount control version {v}"),
            Self::Fields(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
impl From<DecodeError> for Error {
    fn from(error: DecodeError) -> Self {
        Self::Fields(error)
    }
}
fn invalid(what: &'static str) -> Error {
    DecodeError::Invalid { what }.into()
}

fn report_result(result: ResultKind, report: ReportKind) -> bool {
    match report {
        ReportKind::Committed(_) | ReportKind::Clean => matches!(
            result,
            ResultKind::Clean | ResultKind::RuntimeFailure | ResultKind::CacheCloseFailed
        ),
        ReportKind::Bound | ReportKind::Signal | ReportKind::UnknownCut => {
            result == ResultKind::Stopped
        }
        ReportKind::Failed(_) | ReportKind::Internal => result == ResultKind::RuntimeFailure,
        ReportKind::Fenced => result == ResultKind::Fenced,
    }
}

impl Hello {
    /// Check the Final's identity, mode and report/result consistency.
    ///
    /// # Errors
    /// Refuses any non-Final, wrong instance or inconsistent combination.
    pub fn validate_final(&self, message: &Message) -> Result<(), Error> {
        let Message::Final {
            instance,
            result,
            report,
        } = message
        else {
            return Err(invalid("mount control message order"));
        };
        if *instance != self.instance {
            return Err(invalid("mount control instance"));
        }
        let valid = match (&self.mode, report) {
            (Mode::ReadOnly, None) => matches!(
                result,
                ResultKind::Clean | ResultKind::RuntimeFailure | ResultKind::CacheCloseFailed
            ),
            (Mode::ReadOnly, Some(_)) => false,
            (Mode::Writable { .. }, None) => *result == ResultKind::RuntimeFailure,
            (Mode::Writable { .. }, Some(report)) => report_result(*result, report.kind),
        };
        if !valid {
            return Err(invalid("mount control final result/report/mode"));
        }
        Ok(())
    }
}
