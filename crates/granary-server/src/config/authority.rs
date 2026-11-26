// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The publication authority's configuration: whether this server hosts
//! one, and what it is given to do so.
//!
//! **Environment variables, read by name, as the rest of the boot
//! surface is.** The store schema next door and `main.rs`'s listener and
//! TLS paths all arrive this way, so an authority adds names to one
//! convention rather than a second one beside it: no file, no schema
//! version, no parser dependency in this crate. A unit supplies them with
//! systemd's `EnvironmentFile=`, which keeps them in one reviewable file
//! without this process reading or protecting a file of its own.
//!
//! **The predicate is [`ENV_AUTHORITY`] `=` [`AUTHORITY_SINGLE_PROCESS`],
//! exactly.** Absent, the server is the authority-free server it has
//! always been and [`authority_from`] answers `Ok(None)`. Any other value
//! refuses: the value names the deployment profile, and a second profile
//! would be a second value, never a reinterpretation of this one.
//!
//! **All or nothing, both ways.** With the predicate, every required name
//! must be set; without it, every fixed name must be unset. A half-written
//! configuration is a startup refusal naming each variable, never a server
//! that quietly runs without an authority or with half of one.
//!
//! **No sweep of the environment, and no unknown-name refusal is needed.**
//! The fixed names are a closed set and every one but
//! [`ENV_ACCEPT_UNSUPPORTED_FILESYSTEM`] and [`ENV_CONTROLS`] is required.
//! Every derived per-volume name for a listed volume is required too, so a misspelled
//! name is an absence and refuses as one. The optional values default
//! to filesystem refusals and the complete write-controls tuple. A per-volume
//! variable for a volume that is NOT listed is never read, with or without the predicate: the
//! volume list is the served inventory,
//! and a key for a volume this authority does not serve configures
//! nothing.
//!
//! **The per-volume name is injective.** [`publisher_keys_variable`]
//! uppercases the volume name and maps `-` to `_`. A [`VolumeName`] is
//! `[a-z0-9-]` only, so its image holds no `_` and no uppercase letter
//! the source could also have held: two distinct volumes can never share
//! a variable, and the variable names its volume losslessly.
//!
//! **Reserved volume names are accepted.** The registry bounds who may CREATE a volume;
//! an authority may serve one that already exists.
//!
//! **Bounds.** At most [`MAX_VOLUMES`] volumes, at most
//! [`MAX_PUBLISHER_KEYS`] keys per volume, and no value over
//! [`MAX_VALUE_BYTES`]. Path variables are read as bytes, so a non-UTF-8
//! path is a path; every other variable must be UTF-8, and one that is
//! not refuses naming it rather than reading as unset.
//!
//! The state and enrollment directories must have distinct held `(st_dev,
//! st_ino)` identities, checked before engine startup. The filesystem
//! acknowledgement does not waive this rule; distinct parent/child
//! directories and shared filesystems are allowed.
//!
//! Restart-only: nothing here is re-read while the process runs.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use crate::controls::ControlsConfig;
use granary_core::root::VolumeName;
use granary_net::config::{SIGNING_KEY_LEN, parse_key_set};

/// The predicate: set to [`AUTHORITY_SINGLE_PROCESS`] to host an
/// authority in this process.
pub const ENV_AUTHORITY: &str = "GRANARY_AUTHORITY";

/// The one value [`ENV_AUTHORITY`] accepts: one authority, inside this
/// server process.
pub const AUTHORITY_SINGLE_PROCESS: &str = "single-process";

/// The authority's state directory. An absolute path; required.
pub const ENV_STATE_DIR: &str = "GRANARY_AUTHORITY_STATE_DIR";

/// The enrollment directory. An absolute path; required.
pub const ENV_ENROLLMENT_DIR: &str = "GRANARY_AUTHORITY_ENROLLMENT_DIR";

/// The PEM file of the CA that client certificates chain to. An absolute
/// path; required.
pub const ENV_CLIENT_CA: &str = "GRANARY_AUTHORITY_CLIENT_CA";

/// The served volume inventory: a comma-separated list of volume names.
/// Required.
pub const ENV_VOLUMES: &str = "GRANARY_AUTHORITY_VOLUMES";

/// `true` lifts the filesystem-type refusals on the authority's
/// directories; `false` or absent leaves them in force.
pub const ENV_ACCEPT_UNSUPPORTED_FILESYSTEM: &str =
    "GRANARY_AUTHORITY_ACCEPT_UNSUPPORTED_FILESYSTEM";

/// Optional deployment-wide write controls, in tuple order.
pub const ENV_CONTROLS: &str = "GRANARY_AUTHORITY_CONTROLS";

/// The prefix of a per-volume publisher-key variable; see
/// [`publisher_keys_variable`].
pub const PUBLISHER_KEYS_PREFIX: &str = "GRANARY_AUTHORITY_VOLUME_";

/// The suffix of a per-volume publisher-key variable; see
/// [`publisher_keys_variable`].
pub const PUBLISHER_KEYS_SUFFIX: &str = "_PUBLISHER_KEYS";

/// The most volumes one authority serves.
pub const MAX_VOLUMES: usize = 64;

/// The most publisher keys one volume carries.
pub const MAX_PUBLISHER_KEYS: usize = 8;

/// The longest value any authority variable may hold, in bytes. A full
/// key list is under 700 bytes and a full volume list under 4 KiB, so
/// the bound refuses nothing legitimate.
pub const MAX_VALUE_BYTES: usize = 8 * 1024;

const _: () = assert!(
    MAX_VOLUMES * (granary_core::root::VOLUME_NAME_MAX + 1) <= MAX_VALUE_BYTES,
    "a full volume list must fit under the value bound"
);

/// A publisher key: the raw Ed25519 public key.
pub type PublisherKey = [u8; SIGNING_KEY_LEN];

pub use granary_core::support::AuthorityProfile;

/// The authority configuration the environment describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityConfig {
    /// The validated authority predicate retained at parse time.
    pub authority_profile: AuthorityProfile,
    /// [`ENV_STATE_DIR`], absolute.
    pub state_dir: PathBuf,
    /// [`ENV_ENROLLMENT_DIR`], absolute.
    pub enrollment_dir: PathBuf,
    /// [`ENV_CLIENT_CA`], absolute.
    pub client_ca: PathBuf,
    /// The served inventory: each listed volume and its publisher keys,
    /// 1..=[`MAX_VOLUMES`] volumes of 1..=[`MAX_PUBLISHER_KEYS`] distinct
    /// keys. Ordered by volume name; each volume's keys keep the order its
    /// variable listed them in.
    pub volumes: BTreeMap<VolumeName, Vec<PublisherKey>>,
    /// [`ENV_ACCEPT_UNSUPPORTED_FILESYSTEM`]; `false` when absent.
    pub accept_unsupported_filesystem: bool,
    /// The deployment-wide write traffic and occupancy limits.
    pub controls: ControlsConfig,
}

/// The variable that carries `volume`'s publisher keys:
/// [`PUBLISHER_KEYS_PREFIX`], the name uppercased with `-` mapped to `_`,
/// then [`PUBLISHER_KEYS_SUFFIX`]. Injective over [`VolumeName`]; the
/// module docs say why.
#[must_use]
pub fn publisher_keys_variable(volume: &VolumeName) -> String {
    let body: String = volume
        .as_str()
        .chars()
        .map(|c| {
            if c == '-' {
                '_'
            } else {
                c.to_ascii_uppercase()
            }
        })
        .collect();
    format!("{PUBLISHER_KEYS_PREFIX}{body}{PUBLISHER_KEYS_SUFFIX}")
}

/// Read the authority configuration from the process environment.
///
/// # Errors
/// A message naming the variable at fault, ready for the composition
/// root's startup refusal.
pub fn authority_from_env() -> Result<Option<AuthorityConfig>, String> {
    authority_from(&|name| std::env::var_os(name))
}

/// [`authority_from_env`] over an arbitrary lookup.
///
/// The lookup yields the RAW value, as `std::env::var_os` does, so a path
/// variable keeps bytes that are not UTF-8 and a test can supply them;
/// which variables must be text is this function's decision, not the
/// lookup's. `None` from the predicate is the authority-free server.
///
/// # Errors
/// A message naming the variable at fault.
pub fn authority_from(
    get: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Option<AuthorityConfig>, String> {
    let predicate = bounded(get, ENV_AUTHORITY)?;
    let state_dir = bounded(get, ENV_STATE_DIR)?;
    let enrollment_dir = bounded(get, ENV_ENROLLMENT_DIR)?;
    let client_ca = bounded(get, ENV_CLIENT_CA)?;
    let volumes = bounded(get, ENV_VOLUMES)?;
    let accept = bounded(get, ENV_ACCEPT_UNSUPPORTED_FILESYSTEM)?;
    let controls = bounded(get, ENV_CONTROLS)?;

    let Some(predicate) = predicate else {
        // Every fixed name, and only the fixed names: a derived
        // per-volume name is never read without a listed volume.
        let stray: Vec<&str> = [
            (ENV_CONTROLS, controls.is_some()),
            (ENV_STATE_DIR, state_dir.is_some()),
            (ENV_ENROLLMENT_DIR, enrollment_dir.is_some()),
            (ENV_CLIENT_CA, client_ca.is_some()),
            (ENV_VOLUMES, volumes.is_some()),
            (ENV_ACCEPT_UNSUPPORTED_FILESYSTEM, accept.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, set)| set.then_some(name))
        .collect();
        if stray.is_empty() {
            return Ok(None);
        }
        return Err(format!(
            "{} set without {ENV_AUTHORITY}={AUTHORITY_SINGLE_PROCESS:?}; an authority \
             variable configures nothing without the predicate, so set the predicate \
             or unset every authority variable",
            stray.join(", ")
        ));
    };
    let predicate = text(ENV_AUTHORITY, predicate)?;
    if predicate != AUTHORITY_SINGLE_PROCESS {
        return Err(format!(
            "{ENV_AUTHORITY}={predicate:?} is not an authority profile this build knows; \
             the one profile is {AUTHORITY_SINGLE_PROCESS:?}"
        ));
    }

    let (Some(state_dir), Some(enrollment_dir), Some(client_ca), Some(volumes)) = (
        state_dir.clone(),
        enrollment_dir.clone(),
        client_ca.clone(),
        volumes.clone(),
    ) else {
        return Err(format!(
            "{ENV_AUTHORITY}={AUTHORITY_SINGLE_PROCESS:?} needs all of {ENV_STATE_DIR} ({}), \
             {ENV_ENROLLMENT_DIR} ({}), {ENV_CLIENT_CA} ({}) and {ENV_VOLUMES} ({})",
            presence(state_dir.as_ref()),
            presence(enrollment_dir.as_ref()),
            presence(client_ca.as_ref()),
            presence(volumes.as_ref()),
        ));
    };

    let state_dir = absolute(ENV_STATE_DIR, state_dir)?;
    let enrollment_dir = absolute(ENV_ENROLLMENT_DIR, enrollment_dir)?;
    let client_ca = absolute(ENV_CLIENT_CA, client_ca)?;
    let names = volume_list(&text(ENV_VOLUMES, volumes)?)?;

    let mut inventory = BTreeMap::new();
    for volume in names {
        let keys = publisher_keys(get, &volume)?;
        inventory.insert(volume, keys);
    }

    let accept_unsupported_filesystem = match accept {
        None => false,
        Some(raw) => match text(ENV_ACCEPT_UNSUPPORTED_FILESYSTEM, raw)?.as_str() {
            "true" => true,
            "false" => false,
            other => {
                return Err(format!(
                    "{ENV_ACCEPT_UNSUPPORTED_FILESYSTEM}={other:?} is neither \"true\" nor \"false\""
                ));
            }
        },
    };

    let controls = controls
        .map(|raw| {
            ControlsConfig::parse(&text(ENV_CONTROLS, raw)?)
                .map_err(|error| format!("{ENV_CONTROLS}: {error}"))
        })
        .transpose()?
        .unwrap_or_default();

    Ok(Some(AuthorityConfig {
        authority_profile: AuthorityProfile::SingleProcess,
        state_dir,
        enrollment_dir,
        client_ca,
        volumes: inventory,
        accept_unsupported_filesystem,
        controls,
    }))
}

/// `name`'s raw value, or a refusal when it exceeds [`MAX_VALUE_BYTES`].
fn bounded(get: &dyn Fn(&str) -> Option<OsString>, name: &str) -> Result<Option<OsString>, String> {
    match get(name) {
        Some(value) if value.len() > MAX_VALUE_BYTES => Err(format!(
            "{name} is {} bytes; no authority variable may exceed {MAX_VALUE_BYTES}",
            value.len()
        )),
        other => Ok(other),
    }
}

/// `value` as text, or a refusal naming `name` when it is not UTF-8.
fn text(name: &str, value: OsString) -> Result<String, String> {
    value.into_string().map_err(|raw| {
        format!(
            "{name} is set but is not valid UTF-8 ({}); it must be legible text",
            raw.display()
        )
    })
}

/// `value` as a path that is non-empty and absolute, or a refusal naming
/// `name`.
fn absolute(name: &str, value: OsString) -> Result<PathBuf, String> {
    if value.is_empty() {
        return Err(format!("{name} is empty; it must be an absolute path"));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!(
            "{name}={:?} is relative; it must be an absolute path",
            path.display()
        ));
    }
    Ok(path)
}

/// [`ENV_VOLUMES`] parsed: trimmed tokens, each a [`VolumeName`],
/// 1..=[`MAX_VOLUMES`] of them, no duplicates.
fn volume_list(list: &str) -> Result<Vec<VolumeName>, String> {
    if list.trim().is_empty() {
        return Err(format!(
            "{ENV_VOLUMES} is empty; it lists the 1 to {MAX_VOLUMES} volumes this authority serves"
        ));
    }
    let mut names: Vec<VolumeName> = Vec::new();
    for token in list.split(',') {
        let token = token.trim();
        let name = VolumeName::new(token.to_owned())
            .map_err(|error| format!("{ENV_VOLUMES}: {token:?} is not a volume name: {error}"))?;
        if names.contains(&name) {
            return Err(format!("{ENV_VOLUMES} lists {token:?} more than once"));
        }
        names.push(name);
        if names.len() > MAX_VOLUMES {
            return Err(format!(
                "{ENV_VOLUMES} lists more than {MAX_VOLUMES} volumes"
            ));
        }
    }
    Ok(names)
}

/// `volume`'s publisher keys from its derived variable: required,
/// 1..=[`MAX_PUBLISHER_KEYS`] keys, no duplicates. `parse_key_set` checks
/// the syntax of each key; the count and the duplicates are checked here.
fn publisher_keys(
    get: &dyn Fn(&str) -> Option<OsString>,
    volume: &VolumeName,
) -> Result<Vec<PublisherKey>, String> {
    let name = publisher_keys_variable(volume);
    let Some(raw) = bounded(get, &name)? else {
        return Err(format!(
            "{name} is not set; {ENV_VOLUMES} lists {:?}, which needs its publisher keys",
            volume.as_str()
        ));
    };
    let list = text(&name, raw)?;
    if list.trim().is_empty() {
        return Err(format!(
            "{name} is empty; {ENV_VOLUMES} lists {:?}, which needs 1 to \
             {MAX_PUBLISHER_KEYS} publisher keys",
            volume.as_str()
        ));
    }
    let keys = parse_key_set(&list).map_err(|error| format!("{name}: {error}"))?;
    if keys.len() > MAX_PUBLISHER_KEYS {
        return Err(format!(
            "{name} holds {} keys; a volume carries at most {MAX_PUBLISHER_KEYS}",
            keys.len()
        ));
    }
    for (index, key) in keys.iter().enumerate() {
        if keys.iter().take(index).any(|earlier| earlier == key) {
            return Err(format!("{name} lists the same key more than once"));
        }
    }
    Ok(keys)
}

/// `"set"` or `"unset"`, for the all-or-nothing refusal.
fn presence<T>(value: Option<&T>) -> &'static str {
    if value.is_some() { "set" } else { "unset" }
}

#[cfg(test)]
mod tests;
