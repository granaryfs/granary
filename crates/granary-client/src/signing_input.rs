// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Existing signing-seed custody, without key creation or output.

use crate::{FileIdentity, open_private_key, open_regular_read, refuse_granting_acl_at_path};
use granary_store::crypto::{SEED_LEN, SigningKey};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

/// Canonical seed paths whose ancestors passed custody for one effective uid.
#[derive(Debug)]
pub struct SigningSeedPaths {
    seed: PathBuf,
    public: PathBuf,
    euid: u32,
}
impl SigningSeedPaths {
    #[must_use]
    pub fn seed(&self) -> &Path {
        &self.seed
    }
    #[must_use]
    pub fn public(&self) -> &Path {
        &self.public
    }
    /// Load through checked descriptors without repeating the ancestor walk.
    /// # Errors
    /// Seed or public-sidecar custody, length or key binding refusal.
    pub fn load(&self) -> Result<LoadedSigningKey, String> {
        load_key_from_paths(self, self.euid, false)
    }
    /// [`Self::load`], with a [`LoadedSigningKey::spare`] built from the same
    /// seed bytes.
    /// # Errors
    /// As [`Self::load`].
    pub fn load_with_spare(&self) -> Result<LoadedSigningKey, String> {
        load_key_from_paths(self, self.euid, true)
    }
}
#[expect(
    missing_debug_implementations,
    reason = "loaded signing key must never enter Debug output"
)]
pub struct LoadedSigningKey {
    pub key: SigningKey,
    /// A second key built from the same seed bytes, for a second engine
    /// that signs in the same process, when the loader asked for one; the
    /// seed is read once and not kept.
    pub spare: Option<SigningKey>,
    pub seed_identity: FileIdentity,
    pub public_sidecar_absent: bool,
}
fn public_key_path(seed: &Path) -> PathBuf {
    let mut name = seed.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}
/// Load one existing seed and validate a present sidecar without repairing it.
/// # Errors
/// Custody, bounded input length or seed/sidecar disagreement.
pub fn load_existing_signing_key(path: &Path, euid: u32) -> Result<LoadedSigningKey, String> {
    signing_seed_paths(path, euid)?.load()
}
/// [`load_existing_signing_key`], with a spare key from the same seed bytes.
/// # Errors
/// As [`load_existing_signing_key`].
pub fn load_existing_signing_key_with_spare(
    path: &Path,
    euid: u32,
) -> Result<LoadedSigningKey, String> {
    signing_seed_paths(path, euid)?.load_with_spare()
}
/// Validate the ownership and mode of a seed ancestor's no-follow metadata.
/// # Errors
/// A non-directory, wrong owner, or writable group/other mode; ACLs are checked separately.
pub fn validate_signing_seed_ancestor(
    ancestor: &Path,
    metadata: &std::fs::Metadata,
    euid: u32,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let owner = metadata.uid();
    let mode = metadata.mode() & 0o777;
    let unsafe_reason = if !metadata.file_type().is_dir() {
        Some("not a real directory; ")
    } else if (owner != euid && owner != 0) || mode & 0o022 != 0 {
        Some("")
    } else {
        None
    };
    if let Some(reason) = unsafe_reason {
        return Err(format!(
            "{}: unsafe seed ancestor: {reason}owner uid {owner}, mode {mode:03o}; want a real \
             directory owned by uid {} or 0 with mode & 022 == 0. Run: chmod \
             g-w {} (and chmod o-w {} if it is other-writable)",
            ancestor.display(),
            euid,
            ancestor.display(),
            ancestor.display()
        ));
    }
    Ok(())
}

/// Resolve seed paths and check every ancestor before loading or creating a seed.
/// # Errors
/// Invalid final component, unsafe ancestor custody, or path-resolution failure.
#[expect(
    clippy::disallowed_methods,
    reason = "both canonicalize calls are read-only resolution (the seed's existing parent, \
              and $HOME as the ancestor-walk's stop point) feeding the acl/ownership ancestor \
              walk below — nothing here creates or opens anything; symlink_metadata (not \
              banned) is the walk's own per-ancestor check, narrowing the accepted \
              canonicalize-then-use race per the comment at that call"
)]
pub fn signing_seed_paths(path: &Path, euid: u32) -> Result<SigningSeedPaths, String> {
    use std::path::Component;

    let mut components = path.components();
    let file_name = match components.next_back() {
        Some(Component::Normal(name)) if path.as_os_str().as_bytes().last() != Some(&b'/') => {
            name.to_owned()
        }
        _ => {
            return Err(format!(
                "{}: the seed path must end in exactly one normal component; a trailing \
                 separator, `..`, or an absolute right-hand component is refused",
                path.display()
            ));
        }
    };
    let lexical_parent = components.as_path();
    let lexical_parent = if lexical_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        lexical_parent
    };
    let canonical_parent = std::fs::canonicalize(lexical_parent).map_err(|e| {
        format!(
            "{}: cannot canonicalize the seed's existing parent {}: {e}",
            path.display(),
            lexical_parent.display()
        )
    })?;

    let stop = std::env::var_os("HOME")
        .and_then(|home| std::fs::canonicalize(PathBuf::from(home)).ok())
        .filter(|home| canonical_parent.starts_with(home))
        .unwrap_or_else(|| PathBuf::from("/"));
    let mut ancestor = canonical_parent.as_path();
    loop {
        // With a stationary namespace, canonicalization has already resolved every
        // symlink, so this call cannot see one. A symlink can reach the predicate only
        // through the accepted canonicalize-then-use race; `symlink_metadata` narrows
        // that race by refusing the link instead of validating its target.
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|e| format!("{}: cannot inspect seed ancestor: {e}", ancestor.display()))?;
        validate_signing_seed_ancestor(ancestor, &metadata, euid)?;
        refuse_granting_acl_at_path(ancestor)?;
        if ancestor == stop {
            break;
        }
        ancestor = ancestor.parent().ok_or_else(|| {
            format!(
                "{}: seed ancestor walk did not reach {}",
                canonical_parent.display(),
                stop.display()
            )
        })?;
    }

    let seed = canonical_parent.join(file_name);
    let public = public_key_path(&seed);
    Ok(SigningSeedPaths { seed, public, euid })
}

fn read_public_key_sidecar(path: &Path) -> Result<Option<[u8; 32]>, String> {
    use std::io::Read as _;

    let pub_file = match open_regular_read(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(format!(
                "{} is a symlink; the public key sidecar is refused rather than followed",
                path.display()
            ));
        }
        Err(e) => {
            return Err(format!(
                "{}: {e} (the public key beside the seed)",
                path.display()
            ));
        }
    };
    let mut pub_bytes = Vec::new();
    pub_file
        .take(33)
        .read_to_end(&mut pub_bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if pub_bytes.len() > 32 {
        return Err(format!(
            "{}: public key exceeds 32 bytes, want exactly 32",
            path.display()
        ));
    }
    let public = pub_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "{}: public key is {} bytes, want exactly 32",
            path.display(),
            pub_bytes.len()
        )
    })?;
    Ok(Some(public))
}

/// Load a seed already on disk through one no-follow descriptor,
/// refusing a non-regular, multiply-linked, wrongly-owned, or
/// over-permissive seed. The sidecar follows the corresponding
/// no-follow, nonblocking regular-file discipline. Its absence derives
/// the public half in memory without writing a sidecar. With `spare`, a
/// second key is built from the same seed bytes.
fn load_key_from_paths(
    paths: &SigningSeedPaths,
    euid: u32,
    spare: bool,
) -> Result<LoadedSigningKey, String> {
    use std::io::Read as _;

    let seed_file = open_private_key(&paths.seed, euid, "seed")?;
    let seed_identity = FileIdentity::from_file(&seed_file)
        .map_err(|e| format!("{}: {e}", paths.seed.display()))?;
    let seed_read_limit = u64::try_from(SEED_LEN + 1)
        .map_err(|_| "the seed read limit cannot be represented on this platform".to_owned())?;
    let mut seed_bytes = Vec::new();
    seed_file
        .take(seed_read_limit)
        .read_to_end(&mut seed_bytes)
        .map_err(|e| format!("{}: {e}", paths.seed.display()))?;
    if seed_bytes.len() > SEED_LEN {
        return Err(format!(
            "{}: key seed exceeds {SEED_LEN} bytes, want exactly {SEED_LEN}",
            paths.seed.display()
        ));
    }
    let seed: [u8; SEED_LEN] = seed_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "{}: key seed is {} bytes, want exactly {SEED_LEN}",
            paths.seed.display(),
            seed_bytes.len()
        )
    })?;
    if let Some(public) = read_public_key_sidecar(&paths.public)? {
        let key =
            SigningKey::from_seed_and_public_key(&seed, &public).map_err(|e| e.to_string())?;
        let spare = spare
            .then(|| SigningKey::from_seed_and_public_key(&seed, &public))
            .transpose()
            .map_err(|e| e.to_string())?;
        return Ok(LoadedSigningKey {
            key,
            spare,
            seed_identity,
            public_sidecar_absent: false,
        });
    }
    let key = SigningKey::from_seed(&seed).map_err(|e| e.to_string())?;
    let spare = spare
        .then(|| SigningKey::from_seed(&seed))
        .transpose()
        .map_err(|e| e.to_string())?;
    Ok(LoadedSigningKey {
        key,
        spare,
        seed_identity,
        public_sidecar_absent: true,
    })
}
