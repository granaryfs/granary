// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Symmetric, bounded body codec and frame-prefix validation.

use super::{
    Error, FailureClass, Hello, Instance, MAGIC, MAX_BODY, MAX_STORE_PATH, Message, Mode, MountKey,
    Reject, Report, ReportKind, Residue, ResultKind, VERSION, invalid,
};
use crate::encoding::{Cursor, DecodeError};

/// Validate a frame prefix before allocating its body.
///
/// # Errors
/// Refuses bodies shorter than 11 or longer than 8192 bytes.
pub fn frame_length(prefix: [u8; 4]) -> Result<usize, Error> {
    let length = u32::from_be_bytes(prefix);
    if !(11..=8192).contains(&length) {
        return Err(invalid("mount control body length (must be 11..=8192)"));
    }
    usize::try_from(length).map_err(|_| invalid("mount control body length"))
}

fn instance(c: &mut Cursor<'_>) -> Result<Instance, Error> {
    c.take(16)?
        .try_into()
        .map_err(|_| DecodeError::Truncated.into())
}
fn key(c: &mut Cursor<'_>) -> Result<MountKey, Error> {
    let key = MountKey {
        namespace_dev: c.u64()?,
        namespace_ino: c.u64()?,
        mount_id: c.u32()?,
        fuse_major: c.u32()?,
        fuse_minor: c.u32()?,
    };
    if key.namespace_ino == 0 || key.mount_id == 0 {
        return Err(invalid("mount control mount key"));
    }
    Ok(key)
}
fn result(c: &mut Cursor<'_>) -> Result<ResultKind, Error> {
    match c.u8()? {
        1 => Ok(ResultKind::Clean),
        2 => Ok(ResultKind::RuntimeFailure),
        3 => Ok(ResultKind::CacheCloseFailed),
        4 => Ok(ResultKind::Stopped),
        5 => Ok(ResultKind::Fenced),
        _ => Err(invalid("mount control result")),
    }
}
fn class(c: &mut Cursor<'_>) -> Result<FailureClass, Error> {
    match c.u8()? {
        1 => Ok(FailureClass::Io),
        2 => Ok(FailureClass::Refused),
        3 => Ok(FailureClass::Conflict),
        4 => Ok(FailureClass::Unavailable),
        5 => Ok(FailureClass::Corrupt),
        6 => Ok(FailureClass::Internal),
        _ => Err(invalid("mount control failure class")),
    }
}
fn report(c: &mut Cursor<'_>) -> Result<Option<Report>, Error> {
    let kind = match c.u8()? {
        0 => return Ok(None),
        1 => {
            let seq = c.u64()?;
            if seq == 0 || seq == u64::MAX {
                return Err(invalid("mount control sequence"));
            }
            ReportKind::Committed(seq)
        }
        2 => ReportKind::Clean,
        3 => ReportKind::Bound,
        4 => ReportKind::Signal,
        5 => ReportKind::UnknownCut,
        6 => ReportKind::Failed(class(c)?),
        7 => ReportKind::Internal,
        8 => ReportKind::Fenced,
        _ => return Err(invalid("mount control report tag")),
    };
    let elapsed_ms = c.u64()?;
    let residue = match c.u8()? {
        0 => None,
        1 => Some(Residue {
            files: c.u64()?,
            bytes: c.u64()?,
            operations: c.u64()?,
        }),
        _ => return Err(invalid("mount control residue presence")),
    };
    if residue.is_some() && matches!(kind, ReportKind::Committed(_) | ReportKind::Clean) {
        return Err(invalid("mount control released residue"));
    }
    Ok(Some(Report {
        kind,
        elapsed_ms,
        residue,
    }))
}

/// Decode exactly one body, without its frame prefix.
///
/// # Errors
/// Refuses excess size, unknown values, invalid fields, truncation and tails.
/// Finals additionally require [`Hello::validate_final`] at the exchange boundary.
pub fn decode(bytes: &[u8]) -> Result<Message, Error> {
    if bytes.len() > MAX_BODY {
        return Err(invalid("mount control body length (must be 11..=8192)"));
    }
    let mut c = Cursor::new(bytes);
    if c.take(8).ok() != Some(MAGIC.as_slice()) {
        return Err(Error::BadMagic);
    }
    let version = c.u16()?;
    if version != VERSION {
        return Err(Error::UnknownVersion(version));
    }
    let message = match c.u8()? {
        1 => {
            let instance = instance(&mut c)?;
            let key = key(&mut c)?;
            let mode = c.u8()?;
            let bound_seconds = c.u32()?;
            let store = c.take(c.remaining())?;
            let mode = match mode {
                1 if bound_seconds == 0 && store.is_empty() => Mode::ReadOnly,
                2 if (1..=3600).contains(&bound_seconds)
                    && !store.is_empty()
                    && store.len() <= MAX_STORE_PATH
                    && !store.contains(&0) =>
                {
                    Mode::Writable {
                        bound_seconds,
                        store: store.to_vec(),
                    }
                }
                _ => return Err(invalid("mount control mode/bound/store")),
            };
            Message::Hello(Hello {
                instance,
                key,
                mode,
            })
        }
        2 => Message::Stop {
            instance: instance(&mut c)?,
            key: key(&mut c)?,
        },
        3 => Message::Accepted(instance(&mut c)?),
        4 => {
            let instance = instance(&mut c)?;
            let result = result(&mut c)?;
            let report = report(&mut c)?;
            // Present reports constrain the result independently of Hello.
            let valid = report.map_or(
                !matches!(result, ResultKind::Stopped | ResultKind::Fenced),
                |report| super::report_result(result, report.kind),
            );
            if !valid {
                return Err(invalid("mount control final result/report/mode"));
            }
            Message::Final {
                instance,
                result,
                report,
            }
        }
        5 => Message::Reject(match c.u8()? {
            1 => Reject::Starting,
            2 => Reject::IdentityMismatch,
            3 => Reject::MalformedRequest,
            4 => Reject::Busy,
            5 => Reject::Closing,
            6 => Reject::CoordinatorLost,
            _ => return Err(invalid("mount control rejection")),
        }),
        _ => return Err(invalid("mount control kind")),
    };
    c.finish()?;
    Ok(message)
}

fn put_key(out: &mut Vec<u8>, key: MountKey) {
    out.extend_from_slice(&key.namespace_dev.to_be_bytes());
    out.extend_from_slice(&key.namespace_ino.to_be_bytes());
    out.extend_from_slice(&key.mount_id.to_be_bytes());
    out.extend_from_slice(&key.fuse_major.to_be_bytes());
    out.extend_from_slice(&key.fuse_minor.to_be_bytes());
}
fn put_report(out: &mut Vec<u8>, report: Option<Report>) {
    let Some(report) = report else {
        out.push(0);
        return;
    };
    match report.kind {
        ReportKind::Committed(seq) => {
            out.push(1);
            out.extend_from_slice(&seq.to_be_bytes());
        }
        ReportKind::Clean => out.push(2),
        ReportKind::Bound => out.push(3),
        ReportKind::Signal => out.push(4),
        ReportKind::UnknownCut => out.push(5),
        ReportKind::Failed(class) => {
            out.push(6);
            out.push(match class {
                FailureClass::Io => 1,
                FailureClass::Refused => 2,
                FailureClass::Conflict => 3,
                FailureClass::Unavailable => 4,
                FailureClass::Corrupt => 5,
                FailureClass::Internal => 6,
            });
        }
        ReportKind::Internal => out.push(7),
        ReportKind::Fenced => out.push(8),
    }
    out.extend_from_slice(&report.elapsed_ms.to_be_bytes());
    out.push(u8::from(report.residue.is_some()));
    if let Some(residue) = report.residue {
        out.extend_from_slice(&residue.files.to_be_bytes());
        out.extend_from_slice(&residue.bytes.to_be_bytes());
        out.extend_from_slice(&residue.operations.to_be_bytes());
    }
}

/// Encode a body, applying the decoder's exact field validation.
///
/// # Errors
/// Refuses every shape the body decoder refuses. When encoding a Final,
/// the exchange also calls [`Hello::validate_final`] against its advertisement.
pub fn encode(message: &Message) -> Result<Vec<u8>, Error> {
    if let Message::Hello(Hello { mode, .. }) = message {
        mode.validate()?;
    }
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    match message {
        Message::Hello(Hello {
            instance,
            key,
            mode,
        }) => {
            out.push(1);
            out.extend_from_slice(instance);
            put_key(&mut out, *key);
            match mode {
                Mode::ReadOnly => {
                    out.push(1);
                    out.extend_from_slice(&0_u32.to_be_bytes());
                }
                Mode::Writable {
                    bound_seconds,
                    store,
                } => {
                    out.push(2);
                    out.extend_from_slice(&bound_seconds.to_be_bytes());
                    out.extend_from_slice(store);
                }
            }
        }
        Message::Stop { instance, key } => {
            out.push(2);
            out.extend_from_slice(instance);
            put_key(&mut out, *key);
        }
        Message::Accepted(instance) => {
            out.push(3);
            out.extend_from_slice(instance);
        }
        Message::Final {
            instance,
            result,
            report,
        } => {
            out.push(4);
            out.extend_from_slice(instance);
            out.push(match result {
                ResultKind::Clean => 1,
                ResultKind::RuntimeFailure => 2,
                ResultKind::CacheCloseFailed => 3,
                ResultKind::Stopped => 4,
                ResultKind::Fenced => 5,
            });
            put_report(&mut out, *report);
        }
        Message::Reject(reason) => {
            out.push(5);
            out.push(match reason {
                Reject::Starting => 1,
                Reject::IdentityMismatch => 2,
                Reject::MalformedRequest => 3,
                Reject::Busy => 4,
                Reject::Closing => 5,
                Reject::CoordinatorLost => 6,
            });
        }
    }
    decode(&out)?;
    Ok(out)
}
