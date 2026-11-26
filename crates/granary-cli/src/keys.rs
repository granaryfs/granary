// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Private-key custody: creating, validating and loading the Ed25519
//! signing seed and the public sidecar derived from it. Load-only custody
//! never creates or repairs key files; publication can create and repair them.
//!
//! **Failure domain.** Incorrect creation, validation or persistence of
//! signing-seed files can expose or substitute signing authority, or lose
//! the key required to publish further revisions of a volume.
//!
//! This module holds private-key custody and nothing else. Per-publish
//! writer identity and the wall clock (in the crate root) and the
//! process-credential items (in `admission`) are separate invariants with
//! separate remedies, and live outside it.
//!
//!
//! The publication module consumes `LoadedSigningKey` and its `key` and
//! `seed_identity` fields as well as the named loading function.
//!
//! **The closed reach set is one name: `ProcessCredentials`, and only its
//! `euid` field, reached through the SIBLING `admission`, not through the
//! crate root.** This module imports it from
//! `crate::admission` directly rather than through the root's own `use`, which
//! is the rule every child cut after it was held to. Nothing here calls the credential snapshot or
//! the set-ID policy: this module READS an already-acquired `euid` to decide
//! whether a seed file's owner and mode are acceptable, and never asks whether
//! the process may run at all. The register row owes that field, not merely
//! the type.
//!
//! `admission` owns execution admission and the identity snapshot for every
//! command that acquires credentials: `cmd_mount` and `cmd_umount` in
//! `attach.rs`, publication dispatch in `publication.rs`, and `cmd_harvest`,
//! `cmd_cat`, `cmd_verify` and `cmd_thresh` in the crate root. Publication
//! dispatch refuses on `set_id_refusal` and then loads a seed through
//! `load_or_create_key_with_identity`. This module receives the
//! resulting `ProcessCredentials` value rather than acquiring it; only the
//! already-acquired `euid` crosses this module boundary, for the seed-file
//! owner and mode checks described above. The consumers are named by item,
//! never by a `main.rs:N` coordinate: four tracked files carry that
//! basename, so `check-citations.py` scores such a coordinate UNDECIDABLE
//! and no gate would see it go stale. Search for the item names to find
//! them.
//!
//! Loading an existing seed opens it through `granary_client::open_private_key`,
//! the custody check this binary shares with the TLS client credential: the
//! sole-link no-follow open, then the owner, the mode and (on macOS) the ACL
//! judged on that one descriptor. The macOS extended-ACL FFI lives beside it
//! in `granary_client`, the single audited boundary for that inspection, and
//! the shared seed loader calls its path form for the seed's ancestors.
//! Seed validation and the ancestor walk live in `granary_client::signing_input`;
//! atomic creation and public-sidecar repair stay here.

use std::path::{Path, PathBuf};

#[cfg(test)]
use granary_client::refuse_granting_acl_at_path;
use granary_client::{FileIdentity, open_directory};
#[cfg(test)]
use granary_store::crypto::SEED_LEN;
use granary_store::crypto::SigningKey;

use crate::admission::ProcessCredentials;

// The seed fixture is re-exported for the publication execution-admission test.
// It checks its scratch directory through the shared seed-ancestor policy.
#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::SeedScratchDir;
// The ACL classifiers are `granary_client`'s; the custody tests drive them
// under this name.
#[cfg(all(test, target_vendor = "apple"))]
use granary_client::private_key_acl as seed_acl;

pub(crate) fn public_key_path(seed: &Path) -> PathBuf {
    let mut name = seed.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// Create a NEW file at `path` and write `bytes` to it — one atomic
/// `O_CREAT|O_EXCL` open, never a `std::fs::write` (which opens with
/// plain `O_CREAT`, following any symlink at `path` and materialising
/// its target if dangling — a forced-write primitive to whatever an
/// attacker-planted link points at). Mirrors the seed file's own
/// create discipline in [`load_or_create_key_with_identity`]; unlike the seed, this
/// is for public content, so no mode restriction is applied.
///
/// # Errors
/// `io::ErrorKind::AlreadyExists` when `path` already names anything —
/// a real file, a dangling symlink, or a symlink to an existing file —
/// since `O_EXCL` refuses to follow a symlink regardless of its
/// target. Any other `io::Error` the open or write produced.
#[expect(
    clippy::disallowed_methods,
    reason = "the doc comment directly above is this site's own reason: O_CREAT|O_EXCL via \
              OpenOptions::new().create_new(true) is the atomic-create discipline this \
              function exists to provide instead of a plain std::fs::write, which the same \
              comment names as the unsafe alternative this refuses to be"
)]
fn create_new_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)
}

/// `fsync` the directory holding `path`, so the FILE'S EXISTENCE — not
/// just its contents — survives a crash. `sync_all` on the file itself
/// does not persist the parent's directory entry; without this the seed
/// can be fully written and still be absent after a power loss.
/// Same reasoning `store.rs` applies to grains.
///
/// A path with no parent component (a bare filename) syncs `.`, which
/// is the directory it will be created in.
fn sync_parent_dir(path: &Path) -> std::io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    open_directory(dir.unwrap_or_else(|| Path::new(".")))?.sync_all()
}

type SeedPaths = granary_client::SigningSeedPaths;

pub(crate) struct LoadedSigningKey {
    pub(crate) key: SigningKey,
    pub(crate) seed_identity: FileIdentity,
    // Publication repairs only an absence observed during this key's loading.
    public_sidecar_absent: bool,
}

/// Load an existing private seed without creating or repairing either key file.
/// Mount admission must not mint signing authority as a side effect of loading it.
#[cfg(test)]
pub(crate) fn load_signing_key_only(
    path: &Path,
    credentials: &ProcessCredentials,
) -> Result<LoadedSigningKey, String> {
    let loaded = granary_client::load_existing_signing_key(path, credentials.euid)?;
    Ok(LoadedSigningKey {
        key: loaded.key,
        seed_identity: loaded.seed_identity,
        public_sidecar_absent: loaded.public_sidecar_absent,
    })
}

#[cfg(test)]
fn validate_seed_ancestor(
    ancestor: &Path,
    metadata: &std::fs::Metadata,
    credentials: &ProcessCredentials,
) -> Result<(), String> {
    granary_client::validate_signing_seed_ancestor(ancestor, metadata, credentials.euid)
}
fn canonical_seed_paths(
    path: &Path,
    credentials: &ProcessCredentials,
) -> Result<SeedPaths, String> {
    granary_client::signing_seed_paths(path, credentials.euid)
}

#[cfg(test)]
fn load_or_create_key(path: &Path, credentials: &ProcessCredentials) -> Result<SigningKey, String> {
    load_or_create_key_with_identity(path, credentials, false).map(|loaded| loaded.key)
}

/// Load the publishing key, or create it on first use.
///
/// `path` holds the RAW 32-byte Ed25519 seed (which IS the RFC 8032
/// private key — granary-store's `crypto` doc), mode 0600. The PUBLIC
/// key is written beside it as `<path>.pub`.
///
/// The create path is one atomic `O_CREAT|O_EXCL` open at mode 0600 —
/// never a `write` followed by a separate `set_permissions` — for two
/// reasons that were MEASURED, not merely argued: (a) a two-syscall
/// create leaves the private key world-readable (0644, the process
/// umask) for the whole window between the two calls, and permanently
/// if the process is killed between them; (b) `O_EXCL` refuses to
/// follow a symlink at `path`, dangling or not (POSIX: `open` with
/// `O_CREAT|O_EXCL` on a path naming a symlink fails `EEXIST`
/// regardless of the link's target) — a plain `write` would instead
/// create the freshly generated PRIVATE key at whatever the link
/// points to, which anyone with write access to the seed's directory
/// controls. The load path in turn REFUSES a seed whose on-disk mode
/// grants any group/other access, so a seed left at 0644 is refused.
/// Atomic creation does not replace checking the mode of an existing
/// seed.
#[expect(
    clippy::disallowed_methods,
    reason = "O_CREAT|O_EXCL|0o600 create of the private seed (the doc comment above states \
              why: a symlink at the seed's path fails EEXIST rather than being followed and \
              written through), and the best-effort remove_file BY NAME on the durability \
              failure path that undoes an interrupted create — same discipline create_new_file \
              documents for the public sidecar this function also writes"
)]
pub(crate) fn load_or_create_key_with_identity(
    path: &Path,
    credentials: &ProcessCredentials,
    json: bool,
) -> Result<LoadedSigningKey, String> {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let paths = canonical_seed_paths(path, credentials)?;
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(paths.seed())
    {
        Ok(mut file) => {
            let (key, seed) = SigningKey::generate().map_err(|e| e.to_string())?;
            // DURABILITY BEFORE USE. The root this key signs is
            // PUT durably to the object store; the seed that can
            // ever produce a matching `key_id` again is this file.
            // Returning with it in page cache means a power loss
            // inside the writeback window loses or truncates the
            // seed while the root survives — and `remote_state`
            // then requires a matching `key_id` on the head root
            // (`publish.rs`), so it returns `UnknownSigner`
            // forever. There is no rotation and no `--force`: the
            // volume becomes permanently unpublishable. `store.rs`
            // already fsyncs every GRAIN; the key that authorises
            // them all was the one thing not synced.
            //
            // An interrupted create must leave NOTHING rather than
            // a partial seed: a truncated file still satisfies the
            // `create_new` guard on the next run, so it would be
            // loaded as if valid and mint a different (or invalid)
            // identity. On any failure the path is unlinked.
            let durable = file
                .write_all(&seed)
                .and_then(|()| file.sync_all())
                .and_then(|()| sync_parent_dir(paths.seed()));
            if let Err(e) = durable {
                // Best-effort cleanup: the error being reported is the
                // write failure, not whatever unlink says. The unlink
                // is itself fsynced — an unlink that is not durable can
                // be undone by a power loss, resurrecting the partial
                // seed this arm exists to destroy, which the next run
                // would then load as an identity.
                let _ = std::fs::remove_file(paths.seed());
                let _ = sync_parent_dir(paths.seed());
                return Err(format!("{}: {e}", paths.seed().display()));
            }
            let seed_identity = FileIdentity::from_file(&file)
                .map_err(|e| format!("{}: {e}", paths.seed().display()))?;
            create_new_file(paths.public(), key.public_key())
                .map_err(|e| format!("{}: {e}", paths.public().display()))?;
            let hex: String = key.public_key().iter().fold(String::new(), |mut acc, b| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{b:02x}");
                acc
            });
            let message = format!(
                "generated publishing key: {hex}\n  seed  {} (0600 — this is the private key)\n  pub   {}\n",
                paths.seed().display(),
                paths.public().display()
            );
            if json {
                std::io::Write::write_all(&mut std::io::stderr(), message.as_bytes())
            } else {
                std::io::Write::write_all(&mut std::io::stdout(), message.as_bytes())
            }
            .map_err(|e| {
                format!("publishing key generated; key announcement could not be written: {e}")
            })?;
            Ok(LoadedSigningKey {
                key,
                seed_identity,
                public_sidecar_absent: false,
            })
        }
        // `create_new` failing with AlreadyExists covers a real file, a
        // dangling symlink, and a symlink to an existing file alike —
        // in every case nothing was written through it. Fall through to
        // the load path.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            load_existing_key_from_paths(&paths)
        }
        Err(e) => Err(format!("{}: {e}", paths.seed().display())),
    }
}

/// Publication alone repairs an absent, derivable public sidecar.
fn load_existing_key_from_paths(paths: &SeedPaths) -> Result<LoadedSigningKey, String> {
    let loaded = paths.load()?;
    let loaded = LoadedSigningKey {
        key: loaded.key,
        seed_identity: loaded.seed_identity,
        public_sidecar_absent: loaded.public_sidecar_absent,
    };
    if !loaded.public_sidecar_absent {
        return Ok(loaded);
    }
    create_new_file(paths.public(), loaded.key.public_key()).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!(
                "{}: refusing to regenerate the public key sidecar through a symlink \
                 at this path (refused rather than followed) — remove it and retry, \
                 or if another process just recreated the sidecar concurrently, \
                 nothing further is needed: {e}",
                paths.public().display()
            )
        } else {
            format!(
                "{}: {e} (regenerating the public key sidecar, which is derivable \
                 from the seed at {} — nothing else recovers it)",
                paths.public().display(),
                paths.seed().display()
            )
        }
    })?;
    eprintln!(
        "gran publish: warning: {} was missing; regenerated it from the seed at {}",
        paths.public().display(),
        paths.seed().display()
    );
    Ok(loaded)
}
