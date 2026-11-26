// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! misclassifying process identities or set-ID taint admits execution that
//! `gran publish`, `gran mount` and `gran umount` require to refuse.
//!
//! **It is also the crate's IDENTITY snapshot, not only its admission
//! predicate**, and the register row must say both: custody compares a seed
//! file's owner against `euid`, and the mount path uses `euid`/`egid` as its
//! default ownership. A consumer of this module is not always asking
//! permission.
//!
//! **EVERY command of the crate's seven that touches the filesystem comes
//! through here.** `gran harvest`, `gran cat`, `gran thresh`, `gran verify`,
//! `publish`, `mount` and `umount` each acquire the snapshot and refuse a
//! set-ID invocation before their own first filesystem effect.
//!
//! **An enumeration of these commands keyed on a NAMING CONVENTION is blind
//! to a command that does not follow it.** `gran verify` has a `cmd_verify`
//! only so the refusal has a place to live: its work is
//! `granary_client::run_verify`, and a list derived from the `cmd_*`
//! functions would miss any command dispatched straight into a library call.
//!
//! Inbound names: `ProcessCredentials` (and its `ruid`, `euid`, `rgid`,
//! `egid` and `set_id_tainted` fields), `process_credentials` and
//! `set_id_refusal`. Reach into the crate root: NONE. The seam measurement
//! found ZERO outbound; its verdict is scoped `ONE-DIRECTIONAL AMONG CHILDREN`.
//!
//!
//! This subject is at the BOTTOM of the sibling dependency order: `publish`,
//! `attach` and `keys` all reach it and it reaches none of them.

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProcessCredentials {
    pub(crate) ruid: u32,
    pub(crate) euid: u32,
    pub(crate) rgid: u32,
    pub(crate) egid: u32,
    pub(crate) set_id_tainted: bool,
}

/// Snapshot the process identities and the platform's durable set-ID taint.
///
/// No test on an ordinary process can distinguish `geteuid` from `getuid`
/// here: the two agree unless the process was entered through set-ID
/// handling, which a test cannot construct. The compensating control is
/// that the taint probe is INDEPENDENT of the identity comparison — on
/// Apple and Linux a set-ID entry is refused by `issetugid`/`AT_SECURE`
/// even if the uid comparison were blinded — so the two would have to be
/// wrong together to admit a set-ID process.
///
/// The Apple and Linux probes preserve evidence that the executable entered
/// through set-ID handling even if its visible real and effective identities
/// have since been normalised. Other Unix targets have no durable platform
/// taint probe here, so their fallback records the same visible-ID mismatch
/// that the refusal policy independently rejects.
#[expect(
    unsafe_code,
    reason = "Unix process credentials and set-ID taint require libc FFI"
)]
pub(crate) fn process_credentials() -> ProcessCredentials {
    #[cfg(target_vendor = "apple")]
    {
        // SAFETY: the credential getters and issetugid take no arguments, cannot fail, and
        // cannot observe or mutate any Rust-visible state.
        unsafe {
            ProcessCredentials {
                ruid: libc::getuid(),
                euid: libc::geteuid(),
                rgid: libc::getgid(),
                egid: libc::getegid(),
                set_id_tainted: libc::issetugid() != 0,
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // SAFETY: the credential getters take no arguments and getauxval receives the fixed
        // AT_SECURE key; these queries cannot fail and cannot observe or mutate any
        // Rust-visible state.
        unsafe {
            ProcessCredentials {
                ruid: libc::getuid(),
                euid: libc::geteuid(),
                rgid: libc::getgid(),
                egid: libc::getegid(),
                set_id_tainted: libc::getauxval(libc::AT_SECURE) != 0,
            }
        }
    }

    #[cfg(all(unix, not(any(target_vendor = "apple", target_os = "linux"))))]
    {
        // SAFETY: the credential getters take no arguments, cannot fail, and cannot observe or
        // mutate any Rust-visible state.
        let (ruid, euid, rgid, egid) = unsafe {
            (
                libc::getuid(),
                libc::geteuid(),
                libc::getgid(),
                libc::getegid(),
            )
        };
        ProcessCredentials {
            ruid,
            euid,
            rgid,
            egid,
            // No durable platform taint probe is selected for this Unix target. Fall back
            // to real/effective uid or gid inequality, which `set_id_refusal` already rejects.
            set_id_tainted: ruid != euid || rgid != egid,
        }
    }
}

pub(crate) fn set_id_refusal(credentials: &ProcessCredentials) -> Option<String> {
    let mut conditions = Vec::new();
    if credentials.ruid != credentials.euid {
        conditions.push(format!(
            "real uid {} differs from effective uid {}",
            credentials.ruid, credentials.euid
        ));
    }
    if credentials.rgid != credentials.egid {
        conditions.push(format!(
            "real gid {} differs from effective gid {}",
            credentials.rgid, credentials.egid
        ));
    }
    if credentials.set_id_tainted {
        conditions.push("platform set-ID taint probe returned set_id_tainted=true".to_owned());
    }
    if conditions.is_empty() {
        None
    } else {
        Some(format!(
            "set-ID execution is unsupported; refusing: {}",
            conditions.join("; ")
        ))
    }
}
