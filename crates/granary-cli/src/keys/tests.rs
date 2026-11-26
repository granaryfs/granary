// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::keys` — seed creation at 0600, the ancestor walk
//! and its ACL refusals, and the load path's no-follow discipline.
//!
//! Out-of-line, at the sibling-directory path
//! `keys/tests.rs`: the parent keeps its path
//! and declares `#[cfg(test)] mod tests;`.
//!
//! **Twenty-four of these twenty-eight rows call `crate::admission::process_credentials()`,
//! which lives outside `crate::keys`, and that does NOT make them tests of
//! credential acquisition.** A row belongs where the item it ASSERTS ABOUT
//! lives, not wherever it happens to call; by that rule these twenty-four
//! are about custody. The four that do not call it are the three
//! `seed_acl` classifier rows and the seed fixture's own positive control.
//!
//! One row that DOES reference a custody item lives elsewhere by the same
//! rule: `refuse_key_seed_nesting_refuses_a_seed_under_the_store_or_the_cache`
//! (in `path_separation`'s tests) asserts about `refuse_key_seed_nesting`,
//! a `path_separation` item, and merely calls `public_key_path` to build a
//! path.
//!
//! `mkfifo`, `add_acl_entry` and `clear_acl` live here because no row
//! outside this file calls them. `within_deadline` has a caller in the
//! crate root's `tests` (the `gran thresh` deadline row), so it is defined
//! there and imported here.
//!
//! **`mode_of` lives here because all three of its callers are rows in
//! this file.** Its own doc names them.
//!
//! **`SeedScratchDir` lives here, although it has callers on both sides —
//! 25 rows in this file, one in the crate root's `tests`.** Its own `new()`
//! validates the directory it creates against THIS module's ancestor walk,
//! so defining it in the crate root would mean widening
//! `validate_seed_ancestor`, `refuse_granting_acl_at_path` and
//! `canonical_seed_paths` to `pub(crate)` for a test-only consumer. It
//! lives here and `keys.rs` re-exports it, the shape
//! `granary-client/src/fsguard.rs` uses for `testutil`.
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;
use crate::admission::ProcessCredentials;
use crate::admission::process_credentials;
use crate::tests::{ScratchDir, within_deadline};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use granary_core::rng::ProcessRng;

fn load_only_scratch() -> ScratchDir {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let parent = std::env::current_dir()
        .unwrap()
        .ancestors()
        .nth(2)
        .unwrap()
        .join("target/test-scratch");
    std::fs::create_dir_all(&parent).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "the row bans std::process::id as ambient input to a hashed or signed value; \
                  here it only names this fixture's own scratch directory, and nothing under \
                  test reads it"
    )]
    let pid = std::process::id();
    let dir = parent.join(format!(
        "private-seed-{pid}-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).unwrap();
    ScratchDir(dir)
}

fn write_synthetic_seed(path: &Path, length: usize) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(&vec![0x63; length]).unwrap();
}

// Assertion diagnostics exclude byte operands even when a test is defeated.
fn assert_protected_bytes_equal(left: &[u8], right: &[u8]) {
    assert!(left.iter().eq(right), "protected fixture bytes must match");
}

#[test]
fn load_only_missing_seed_refuses_without_creating_files() {
    let dir = load_only_scratch();
    let path = dir.0.join("seed");
    let result = load_signing_key_only(&path, &process_credentials());
    assert!(result.is_err(), "missing private seed must refuse");
    assert!(!path.exists() && !public_key_path(&path).exists());
}

#[test]
fn load_only_missing_sidecar_derives_without_repair() {
    let dir = load_only_scratch();
    let path = dir.0.join("seed");
    write_synthetic_seed(&path, 32);
    let loaded = load_signing_key_only(&path, &process_credentials()).unwrap();
    let expected = SigningKey::from_seed(&[0x63; 32]).unwrap();
    assert_protected_bytes_equal(loaded.key.public_key(), expected.public_key());
    assert!(
        !public_key_path(&path).exists(),
        "load-only custody must not repair the public sidecar"
    );
    assert_protected_bytes_equal(&std::fs::read(path).unwrap(), &[0x63; 32]);
}

#[test]
fn load_only_sidecar_pair_and_mismatch() {
    let dir = load_only_scratch();
    let path = dir.0.join("seed");
    write_synthetic_seed(&path, 32);
    let expected = SigningKey::from_seed(&[0x63; 32]).unwrap();
    std::fs::write(public_key_path(&path), expected.public_key()).unwrap();
    let loaded = load_signing_key_only(&path, &process_credentials()).unwrap();
    assert_protected_bytes_equal(loaded.key.public_key(), expected.public_key());
    let other = SigningKey::from_seed(&[0x64; 32]).unwrap();
    std::fs::write(public_key_path(&path), other.public_key()).unwrap();
    let Err(refusal) = load_signing_key_only(&path, &process_credentials()) else {
        panic!("mismatched public sidecar must refuse");
    };
    assert!(refusal.contains("seed/public-key pair rejected"));
    assert_protected_bytes_equal(
        &std::fs::read(public_key_path(&path)).unwrap(),
        other.public_key(),
    );
}

#[test]
fn load_only_bounded_seed_and_custody_pairs() {
    let credentials = process_credentials();
    let mut cases = 0;
    for (length, valid) in [(32, true), (31, false), (33, false)] {
        let dir = load_only_scratch();
        let path = dir.0.join("seed");
        write_synthetic_seed(&path, length);
        let result = load_signing_key_only(&path, &credentials);
        assert_eq!(result.is_ok(), valid, "bounded private seed length");
        if let Err(reason) = result {
            assert!(reason.contains("want exactly 32"));
        }
        assert!(!public_key_path(&path).exists());
        cases += 1;
    }
    let dir = load_only_scratch();
    let path = dir.0.join("seed");
    write_synthetic_seed(&path, 32);
    assert!(load_signing_key_only(&path, &credentials).is_ok());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let Err(refusal) = load_signing_key_only(&path, &credentials) else {
        panic!("custody-bad seed accepted");
    };
    assert!(
        refusal.contains("permissions are 644, want 0600"),
        "private custody refusal"
    );
    assert_eq!(cases + 1, 4);
}

#[test]
fn publish_existing_seed_keeps_sidecar_repair() {
    let dir = load_only_scratch();
    let path = dir.0.join("seed");
    write_synthetic_seed(&path, 32);
    let loaded = load_or_create_key_with_identity(&path, &process_credentials(), false).unwrap();
    assert_protected_bytes_equal(
        &std::fs::read(public_key_path(&path)).unwrap(),
        loaded.key.public_key(),
    );
    assert_protected_bytes_equal(&std::fs::read(path).unwrap(), &[0x63; 32]);
}

/// The permission bits of `path`, masked to the nine `rwxrwxrwx` bits.
///
/// **It lives here because every caller does:** its three
/// call sites are all rows in this file —
/// `seed_scratch_dir_refuses_collisions_and_replaced_drop_paths`,
/// `fresh_seed_is_created_0600` and
/// `the_created_seed_is_complete_and_reloads_identically` — and no
/// row in the crate root's `tests` calls it. A helper belongs beside
/// its callers; re-count them before moving it.
///
/// Private, not `pub(crate)`: nothing outside this file calls it, which is the
/// same count that decided where it lives. `SeedScratchDir` below is the
/// contrast — it is `pub(crate)` BECAUSE `crate::keys` re-exports it.
///
/// `#[track_caller]` so a metadata failure names the row that failed rather
/// than this helper's own line, which all three rows would otherwise share
/// (`docs/coding-standards.md` SHOULD 15).
#[track_caller]
fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("{e}"))
        .permissions()
        .mode()
        & 0o777
}

/// Seed-test scratch dir below HOME, the production ancestor-walk stop.
///
/// `pub(crate)` because it is re-exported by `crate::keys` for the two
/// `cmd_publish` refusal rows in the crate root's `tests`; the
/// other 25 callers are in this file. The field is exposed rather than an
/// accessor added, because that is what the call sites on both sides already
/// use.
pub(crate) struct SeedScratchDir(pub(crate) PathBuf, u64, u64);

impl SeedScratchDir {
    pub(crate) fn new() -> Self {
        use granary_core::rng::Rng as _;

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let configured_home = std::env::var_os("HOME").unwrap_or_else(|| {
            panic!(
                "seed test fixture requires HOME to be set; refusing to fall back to the \
                 system temporary directory"
            )
        });
        let configured_home = PathBuf::from(configured_home);
        let home = std::fs::canonicalize(&configured_home).unwrap_or_else(|e| {
            panic!(
                "seed test fixture HOME {} cannot be canonicalized: {e}; refusing to fall \
                 back to the system temporary directory",
                configured_home.display()
            )
        });
        let metadata = std::fs::symlink_metadata(&home).unwrap_or_else(|e| {
            panic!(
                "seed test fixture cannot inspect HOME {}: {e}",
                home.display()
            )
        });
        validate_seed_ancestor(&home, &metadata, &process_credentials()).unwrap_or_else(|e| {
            panic!("seed test fixture requires a safe HOME and will not skip: {e}")
        });
        refuse_granting_acl_at_path(&home).unwrap_or_else(|e| {
            panic!("seed test fixture requires a safe HOME and will not skip: {e}")
        });

        // Root at HOME ITSELF, never at the working directory. The walk
        // stops AT HOME, so rooting here inspects exactly one directory
        // that HOME's own check has already cleared. Preferring the cwd
        // when it happens to sit under HOME adds every directory between
        // the two to the walk — on a CI runner that is
        // `<home>/actions-runner/_work`, mode 775, which the policy
        // rightly refuses.
        let entropy = ProcessRng::new().next_u64();
        #[expect(
            clippy::disallowed_methods,
            reason = "the lint row this licenses bans `std::process::id` as AMBIENT INPUT, because the preimage of a \
            hashed or signed value must take a `WriterIdentity` instead. Here it is one field of a \
            SCRATCH-DIRECTORY NAME under HOME (`granary-client-main-seed-test-<pid>-<counter>-<entropy>`), \
            created and removed by this fixture, and it is load-bearing for correctness there: the counter \
            beside it is per-process, so without the pid two concurrent runs generate the same name and share \
            one directory under a HOME both are inspecting. The seed material these rows exercise comes from \
            `ProcessRng` and the committed fixture, never from the path — the entropy field beside the pid is \
            what keeps a stale directory from a previous run out of the way, and neither reaches a hashed or \
            signed value"
        )]
        let dir = home.join(format!(
            "granary-client-main-seed-test-{}-{}-{entropy:016x}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let created =
            Self::create_at(dir.clone()).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        if let Err(e) = canonical_seed_paths(
            &dir.join("seed-fixture-policy-probe"),
            &process_credentials(),
        ) {
            drop(created);
            panic!("seed test fixture root failed the production policy and will not skip: {e}");
        }
        created
    }

    /// Exclusive, identity-checked constructor kept separate so the
    /// collision and replacement behavior can be tested without
    /// touching the real HOME directory.
    fn create_at(dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir(&dir)?;
        let credentials = process_credentials();
        let path_metadata = std::fs::symlink_metadata(&dir)?;
        if !path_metadata.file_type().is_dir() || path_metadata.uid() != credentials.euid {
            return Err(std::io::Error::other(format!(
                "{} is not a real directory owned by uid {}",
                dir.display(),
                credentials.euid
            )));
        }

        let opened = open_directory(&dir)?;
        let opened_metadata = opened.metadata()?;
        let dev = opened_metadata.dev();
        let ino = opened_metadata.ino();
        if !opened_metadata.file_type().is_dir()
            || opened_metadata.uid() != credentials.euid
            || path_metadata.dev() != dev
            || path_metadata.ino() != ino
        {
            return Err(std::io::Error::other(format!(
                "{} changed identity or ownership after exclusive creation",
                dir.display()
            )));
        }
        opened.set_permissions(std::fs::Permissions::from_mode(0o700))?;

        let post = std::fs::symlink_metadata(&dir)?;
        if !post.file_type().is_dir()
            || post.uid() != credentials.euid
            || post.dev() != dev
            || post.ino() != ino
        {
            return Err(std::io::Error::other(format!(
                "{} changed identity or ownership while being initialized",
                dir.display()
            )));
        }
        Ok(Self(dir, dev, ino))
    }

    fn remove_if_same_dir(&self) {
        let Ok(metadata) = std::fs::symlink_metadata(&self.0) else {
            return;
        };
        if metadata.file_type().is_dir() && metadata.dev() == self.1 && metadata.ino() == self.2 {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

impl Drop for SeedScratchDir {
    fn drop(&mut self) {
        self.remove_if_same_dir();
    }
}

#[test]
fn seed_scratch_dir_uses_home_fixture_root() {
    let dir = SeedScratchDir::new();
    let expected = std::env::var_os("HOME").unwrap_or_else(|| panic!("HOME must be set"));
    let expected = std::fs::canonicalize(expected).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(dir.0.parent(), Some(expected.as_path()));
}

#[test]
fn seed_scratch_dir_refuses_collisions_and_replaced_drop_paths() {
    let root = ScratchDir::new();

    let outside = root.0.join("collision-target");
    std::fs::create_dir(&outside).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("{e}"));
    let collision = root.0.join("collision");
    std::os::unix::fs::symlink(&outside, &collision).unwrap_or_else(|e| panic!("{e}"));
    let Err(err) = SeedScratchDir::create_at(collision.clone()) else {
        panic!("an existing symlink must make exclusive creation fail");
    };
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::AlreadyExists,
        "exclusive create must report the existing name itself"
    );
    assert_eq!(
        mode_of(&outside),
        0o755,
        "collision refusal must not chmod the symlink target"
    );
    std::fs::remove_file(&collision).unwrap_or_else(|e| panic!("{e}"));

    let live = root.0.join("replace-before-drop");
    let fixture = SeedScratchDir::create_at(live.clone()).unwrap_or_else(|e| panic!("{e}"));
    let displaced = root.0.join("displaced-original");
    std::fs::rename(&live, &displaced).unwrap_or_else(|e| panic!("{e}"));
    let victim = root.0.join("drop-target");
    std::fs::create_dir(&victim).unwrap_or_else(|e| panic!("{e}"));
    let victim_file = victim.join("must-survive");
    std::fs::write(&victim_file, b"outside").unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&victim, &live).unwrap_or_else(|e| panic!("{e}"));
    drop(fixture);
    assert!(
        victim_file.exists(),
        "Drop must not recurse through a replacement symlink"
    );
    assert!(
        std::fs::symlink_metadata(&live).is_ok_and(|metadata| metadata.file_type().is_symlink()),
        "Drop must leave a replacement name untouched"
    );
    std::fs::remove_file(&live).unwrap_or_else(|e| panic!("{e}"));

    let ordinary = root.0.join("ordinary");
    let fixture = SeedScratchDir::create_at(ordinary.clone()).unwrap_or_else(|e| panic!("{e}"));
    assert!(ordinary.is_dir(), "positive-control directory was created");
    drop(fixture);
    assert!(
        !ordinary.exists(),
        "positive-control Drop removes the same directory it created"
    );
}

fn mkfifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap_or_else(|e| panic!("mkfifo: {e}"));
    assert!(status.success(), "mkfifo {} failed", path.display());
}

#[cfg(target_vendor = "apple")]
fn add_acl_entry(path: &Path, entry: &str) {
    let output = std::process::Command::new("/bin/chmod")
        .arg("+a")
        .arg(entry)
        .arg(path)
        .output()
        .unwrap_or_else(|e| panic!("/bin/chmod +a {}: {e}", path.display()));
    assert!(
        output.status.success(),
        "/bin/chmod +a failed for {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_vendor = "apple")]
fn clear_acl(path: &Path) {
    let output = std::process::Command::new("/bin/chmod")
        .arg("-N")
        .arg(path)
        .output()
        .unwrap_or_else(|e| panic!("/bin/chmod -N {}: {e}", path.display()));
    assert!(
        output.status.success(),
        "/bin/chmod -N failed for {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The create path is one atomic mode-0600 open, never a
/// write-then-chmod — assert the MODE, not merely that the file
/// exists (a two-syscall create would also pass an existence-only
/// check while leaving a 0644 window).
#[test]
fn fresh_seed_is_created_0600() {
    let dir = SeedScratchDir::new();
    let seed_path = dir.0.join("seed");
    let key =
        load_or_create_key(&seed_path, &process_credentials()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        mode_of(&seed_path),
        0o600,
        "seed must be created at exactly 0600"
    );
    let pub_path = dir.0.join("seed.pub");
    assert!(
        pub_path.exists(),
        "the .pub sidecar must be written alongside"
    );
    assert_eq!(
        std::fs::read(&pub_path).unwrap_or_else(|e| panic!("{e}")),
        key.public_key()
    );
}

/// A seed left at 0644 (by whatever wrote it) is refused BY
/// NAME, never silently trusted — this is what makes the atomic
/// 0600 create above a real guarantee rather than a
/// transient-window one that still trusts whatever it inherits.
#[test]
fn preexisting_0644_seed_is_refused() {
    let dir = SeedScratchDir::new();
    let seed_path = dir.0.join("seed");
    let (_key, seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(&seed_path, seed).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|e| panic!("{e}"));
    let err = load_or_create_key(&seed_path, &process_credentials())
        .expect_err("a group/other-readable seed must be refused");
    assert!(
        err.contains("0600"),
        "error must name the expected mode: {err}"
    );
    assert!(
        err.contains("chmod 600"),
        "error must name the exact recovery command: {err}"
    );
}

/// A dangling symlink at the seed path must not be followed on
/// create — the private key must never be written through it to
/// whatever the link points at. Asserts BOTH that the call is
/// refused AND that the target was never created.
#[test]
fn dangling_symlink_at_seed_path_is_refused() {
    let dir = SeedScratchDir::new();
    let seed_path = dir.0.join("seed");
    let target_path = dir.0.join("attacker-chosen-target");
    assert!(!target_path.exists(), "precondition: target absent");
    std::os::unix::fs::symlink(&target_path, &seed_path).unwrap_or_else(|e| panic!("{e}"));
    let result = load_or_create_key(&seed_path, &process_credentials());
    assert!(
        result.is_err(),
        "a dangling symlink at the seed path must be refused, not followed"
    );
    assert!(
        !target_path.exists(),
        "the symlink target must NOT have been created — the private key must never be \
         written through the link"
    );
}

#[test]
fn existing_symlink_at_seed_path_is_refused_on_load() {
    let dir = SeedScratchDir::new();
    let target_path = dir.0.join("attacker-known-seed");
    let (_key, seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(&target_path, seed).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| panic!("{e}"));
    let seed_path = dir.0.join("seed");
    std::os::unix::fs::symlink(&target_path, &seed_path).unwrap_or_else(|e| panic!("{e}"));

    let err = load_or_create_key(&seed_path, &process_credentials())
        .expect_err("an existing-target symlink at the seed path must be refused");
    assert!(
        err.contains("is a symlink") && err.contains("must not be followed"),
        "the no-follow guard itself must refuse the symlink: {err}"
    );
}

#[test]
fn hard_link_at_seed_path_is_refused_on_load() {
    let dir = SeedScratchDir::new();
    let target_path = dir.0.join("attacker-known-seed");
    let (_key, seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(&target_path, seed).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| panic!("{e}"));
    let seed_path = dir.0.join("seed");
    std::fs::hard_link(&target_path, &seed_path).unwrap_or_else(|e| panic!("{e}"));

    let err = load_or_create_key(&seed_path, &process_credentials())
        .expect_err("a multiply-linked seed must be refused");
    assert!(
        err.contains("has 2 links") && err.contains("private seed must have exactly one"),
        "the descriptor link-count guard itself must refuse the hard link: {err}"
    );
}

#[test]
fn seed_owned_by_a_different_uid_is_refused() {
    use std::os::unix::fs::MetadataExt as _;

    let dir = SeedScratchDir::new();
    let seed_path = dir.0.join("seed");
    load_or_create_key(&seed_path, &process_credentials()).unwrap_or_else(|e| panic!("{e}"));
    let owner = std::fs::metadata(&seed_path)
        .unwrap_or_else(|e| panic!("{e}"))
        .uid();
    let other_uid = owner.wrapping_add(1);

    let other_credentials = ProcessCredentials {
        euid: other_uid,
        ..process_credentials()
    };
    let Err(err) = load_signing_key_only(&seed_path, &other_credentials) else {
        panic!("a seed owned by another uid must be refused");
    };
    assert_owner_refusal(&err, owner, other_uid);
}

#[test]
fn symlinked_seed_ancestors_return_canonical_seed_and_sidecar_paths() {
    use std::os::unix::fs::MetadataExt as _;

    let dir = SeedScratchDir::new();
    let first_target = dir.0.join("first-target");
    let canonical_parent = dir.0.join("canonical").join("deep");
    std::fs::create_dir(&first_target).unwrap_or_else(|e| panic!("{e}"));
    std::fs::create_dir_all(&canonical_parent).unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&first_target, dir.0.join("first-link"))
        .unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&canonical_parent, first_target.join("second-link"))
        .unwrap_or_else(|e| panic!("{e}"));

    let lexical_seed = dir.0.join("first-link").join("second-link").join("seed");
    let canonical_parent =
        std::fs::canonicalize(&canonical_parent).unwrap_or_else(|e| panic!("{e}"));
    let expected_seed = canonical_parent.join("seed");
    let mut expected_public = expected_seed.as_os_str().to_owned();
    expected_public.push(".pub");
    let expected_public = PathBuf::from(expected_public);
    assert_ne!(
        lexical_seed, expected_seed,
        "precondition: the lexical and canonical seed paths must differ"
    );
    let owner = std::fs::symlink_metadata(&canonical_parent)
        .unwrap_or_else(|e| panic!("{e}"))
        .uid();

    let credentials = ProcessCredentials {
        euid: owner,
        ..process_credentials()
    };
    let paths = canonical_seed_paths(&lexical_seed, &credentials).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        paths.seed(),
        expected_seed,
        "the seed path must remain on the ancestor chain that was validated"
    );
    assert_eq!(
        paths.public(),
        expected_public,
        "the public-key sidecar must be derived from the canonical seed path"
    );
}

#[test]
fn seed_ancestor_policy_refuses_symlink_metadata() {
    use std::os::unix::fs::MetadataExt as _;

    let dir = SeedScratchDir::new();
    let target = dir.0.join("safe-target");
    let link = dir.0.join("ancestor-link");
    std::fs::create_dir(&target).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(&target, &link).unwrap_or_else(|e| panic!("{e}"));
    let metadata = std::fs::symlink_metadata(&link).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        metadata.file_type().is_symlink(),
        "precondition: metadata must describe the link, not its directory target"
    );

    let credentials = ProcessCredentials {
        euid: metadata.uid(),
        ..process_credentials()
    };
    let err = validate_seed_ancestor(&link, &metadata, &credentials)
        .expect_err("a symlink must not satisfy the real-directory policy");
    assert!(
        err.contains(&link.display().to_string()) && err.contains("not a real directory"),
        "the type refusal must identify the symlink path and the failed contract: {err}"
    );
}

#[cfg(target_vendor = "apple")]
#[test]
fn deny_only_acl_on_seed_ancestor_is_accepted() {
    let dir = SeedScratchDir::new();
    let ancestor = dir.0.join("deny-only");
    std::fs::create_dir(&ancestor).unwrap_or_else(|e| panic!("{e}"));
    add_acl_entry(&ancestor, "everyone deny delete");

    let result = canonical_seed_paths(&ancestor.join("seed"), &process_credentials());
    clear_acl(&ancestor);
    assert!(
        result.is_ok(),
        "a deny-only ACL removes authority and must be accepted: {:?}",
        result.err()
    );
}

#[cfg(target_vendor = "apple")]
#[test]
fn granting_acl_on_seed_ancestor_is_refused_and_named() {
    let dir = SeedScratchDir::new();
    let ancestor = dir.0.join("granting");
    std::fs::create_dir(&ancestor).unwrap_or_else(|e| panic!("{e}"));
    add_acl_entry(&ancestor, "everyone allow add_file,delete_child");

    let result = canonical_seed_paths(&ancestor.join("seed"), &process_credentials());
    clear_acl(&ancestor);
    let err = result
        .err()
        .unwrap_or_else(|| panic!("an ACL entry that grants access must be refused"));
    assert!(
        err.contains(&ancestor.display().to_string()) && err.contains("chmod -N"),
        "the refusal must name the granting ancestor and the recovery command: {err}"
    );
}

#[cfg(target_vendor = "apple")]
#[test]
fn deny_then_allow_acl_on_seed_ancestor_is_refused() {
    let dir = SeedScratchDir::new();
    let ancestor = dir.0.join("deny-then-allow");
    std::fs::create_dir(&ancestor).unwrap_or_else(|e| panic!("{e}"));
    add_acl_entry(&ancestor, "everyone deny delete");
    add_acl_entry(&ancestor, "everyone allow add_file,delete_child");

    let result = canonical_seed_paths(&ancestor.join("seed"), &process_credentials());
    clear_acl(&ancestor);
    let err = result
        .err()
        .unwrap_or_else(|| panic!("the granting second ACL entry must be refused"));
    assert!(
        err.contains(&ancestor.display().to_string()),
        "the refusal must name the ancestor whose second ACL entry grants access: {err}"
    );
}

#[cfg(target_vendor = "apple")]
#[test]
fn seed_ancestor_without_an_acl_is_accepted() {
    let dir = SeedScratchDir::new();
    let ancestor = dir.0.join("no-acl");
    std::fs::create_dir(&ancestor).unwrap_or_else(|e| panic!("{e}"));
    clear_acl(&ancestor);

    let result = canonical_seed_paths(&ancestor.join("seed"), &process_credentials());
    assert!(
        result.is_ok(),
        "an ancestor with no ACL must remain accepted: {:?}",
        result.err()
    );
}

#[cfg(target_vendor = "apple")]
#[test]
fn unsupported_acl_reporting_is_refused_while_no_acl_is_accepted() {
    let shown = Path::new("/shown/seed-ancestor");
    let unsupported = seed_acl::classify_acl_get_failure(
        &std::io::Error::from_raw_os_error(libc::EOPNOTSUPP),
        shown,
    )
    .expect_err("a volume that cannot report ACLs must be refused");
    assert!(
        unsupported.contains("volume cannot report ACLs")
            && unsupported.contains(&shown.display().to_string()),
        "the refusal must name both the reporting failure and the inspected path: \
         {unsupported}"
    );
    assert!(
        seed_acl::classify_acl_get_failure(&std::io::Error::from_raw_os_error(libc::ENOENT), shown)
            .is_ok(),
        "ENOENT from the ACL getter means the object carries no ACL"
    );
    let other =
        seed_acl::classify_acl_get_failure(&std::io::Error::from_raw_os_error(libc::EIO), shown)
            .expect_err("an unclassified ACL getter failure must fail closed");
    assert!(
        other.contains("cannot inspect ACLs") && other.contains(&shown.display().to_string()),
        "an unexpected getter failure must refuse and name the inspected path: {other}"
    );
}

#[cfg(target_vendor = "apple")]
#[test]
fn walk_step_outcome_classifies_einval_as_exhaustion_and_everything_else_as_failure() {
    use seed_acl::EntryWalkOutcome;

    let cases: &[(libc::c_int, libc::c_int, EntryWalkOutcome)] = &[
        (-1, libc::EINVAL, EntryWalkOutcome::Exhausted),
        (-1, libc::EIO, EntryWalkOutcome::Failed(libc::EIO)),
        (-1, libc::ENOMEM, EntryWalkOutcome::Failed(libc::ENOMEM)),
        (1, libc::EINVAL, EntryWalkOutcome::Failed(libc::EINVAL)),
        (-1, 0, EntryWalkOutcome::Failed(0)),
    ];
    for (ret, errno, expected) in cases.iter().copied() {
        let got = seed_acl::walk_step_outcome(ret, errno);
        assert_eq!(
            got, expected,
            "walk_step_outcome({ret}, {errno}) must classify to {expected:?}, got {got:?}"
        );
    }
}

// Regression guard for the fail-open the classifier alone cannot catch: a real
// `acl_get_entry` failure (EIO, ENOMEM, ...) never occurs from the ancestor/seed
// fixtures this suite exercises, so every FFI-driven walk in the whole test binary
// returns `Exhausted` -- a call site that dropped `Failed` on the floor (the
// classifier's own failure mode, repeated one layer up at the wiring) would
// pass every other ACL test unnoticed. This drives the wiring
// function directly with a synthetic `Failed` outcome instead.
#[cfg(target_vendor = "apple")]
#[test]
fn walk_failure_for_entry_walk_outcome_propagates_failed_and_absorbs_exhausted() {
    use seed_acl::{EntryWalkOutcome, WalkFailure};

    assert!(
        seed_acl::walk_failure_for_entry_walk_outcome(EntryWalkOutcome::Exhausted).is_none(),
        "normal exhaustion must not produce a walk failure"
    );

    match seed_acl::walk_failure_for_entry_walk_outcome(EntryWalkOutcome::Failed(libc::EIO)) {
        Some(WalkFailure::Entry(error)) => {
            assert_eq!(
                error.raw_os_error(),
                Some(libc::EIO),
                "the wired failure must carry the classifier's errno through unchanged"
            );
        }
        other => panic!(
            "a Failed outcome must be wired into Some(WalkFailure::Entry(_)), not silently \
             dropped: {other:?}"
        ),
    }
}

#[cfg(target_vendor = "apple")]
#[test]
fn granting_acl_on_seed_file_is_refused_through_held_descriptor() {
    let dir = SeedScratchDir::new();
    let seed_path = dir.0.join("seed");
    load_or_create_key(&seed_path, &process_credentials()).unwrap_or_else(|e| panic!("{e}"));
    add_acl_entry(&seed_path, "everyone allow read");

    let result = load_or_create_key(&seed_path, &process_credentials());
    clear_acl(&seed_path);
    let err = result.expect_err("a granting ACL on the seed descriptor must be refused");
    assert!(
        err.contains(&seed_path.display().to_string()) && err.contains("chmod -N"),
        "the refusal must name the seed and the recovery command: {err}"
    );
}

#[cfg(target_vendor = "apple")]
#[test]
fn load_or_create_refuses_granting_acl_on_seed_ancestor_before_creation() {
    let dir = SeedScratchDir::new();
    let ancestor = dir.0.join("end-to-end-granting");
    std::fs::create_dir(&ancestor).unwrap_or_else(|e| panic!("{e}"));
    let seed_path = ancestor.join("seed");
    add_acl_entry(&ancestor, "everyone allow add_file,delete_child");

    let result = load_or_create_key(&seed_path, &process_credentials());
    clear_acl(&ancestor);
    let err = result.expect_err("a granting ancestor ACL must stop seed creation");
    assert!(
        err.contains(&ancestor.display().to_string()),
        "the end-to-end refusal must name the granting ancestor: {err}"
    );
    assert!(
        !seed_path.exists(),
        "the ancestor ACL refusal must happen before the seed is created"
    );
}

#[test]
fn group_writable_seed_ancestor_is_refused_and_named() {
    let dir = SeedScratchDir::new();
    let unsafe_ancestor = dir.0.join("group-writable");
    let seed_parent = unsafe_ancestor.join("private");
    std::fs::create_dir_all(&seed_parent).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&unsafe_ancestor, std::fs::Permissions::from_mode(0o770))
        .unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&seed_parent, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("{e}"));

    let err = load_or_create_key(&seed_parent.join("seed"), &process_credentials())
        .expect_err("a group-writable seed ancestor must be refused");
    assert!(
        err.contains(&unsafe_ancestor.display().to_string())
            && err.contains("mode 770")
            && err.contains("chmod g-w"),
        "the refusal must name the exact directory, mode, and remedy: {err}"
    );
}

#[test]
fn seed_ancestor_owned_by_a_third_uid_is_refused_and_named() {
    use std::os::unix::fs::MetadataExt as _;

    let dir = SeedScratchDir::new();
    let foreign_ancestor = dir.0.join("foreign-owner");
    std::fs::create_dir(&foreign_ancestor).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&foreign_ancestor, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("{e}"));
    let seed_path = foreign_ancestor.join("seed");
    load_or_create_key(&seed_path, &process_credentials()).unwrap_or_else(|e| panic!("{e}"));
    let mut owner = std::fs::metadata(&foreign_ancestor)
        .unwrap_or_else(|e| panic!("{e}"))
        .uid();
    let effective_uid = if owner == 0 {
        let status = std::process::Command::new("chown")
            .arg("1")
            .arg(&foreign_ancestor)
            .status()
            .unwrap_or_else(|e| panic!("chown: {e}"));
        assert!(
            status.success(),
            "root test fixture must assign a third uid"
        );
        owner = 1;
        0
    } else {
        owner.wrapping_add(1)
    };

    let credentials = ProcessCredentials {
        euid: effective_uid,
        ..process_credentials()
    };
    let err = canonical_seed_paths(&seed_path, &credentials)
        .err()
        .unwrap_or_else(|| {
            panic!("an ancestor owned by neither root nor the effective uid must be refused")
        });
    assert!(
        err.contains(&foreign_ancestor.display().to_string())
            && err.contains(&format!("owner uid {owner}"))
            && err.contains("mode 700"),
        "the refusal must name the exact directory, owner, and mode: {err}"
    );
}

#[test]
fn seed_path_without_one_normal_final_component_is_refused() {
    let dir = SeedScratchDir::new();
    let path = dir.0.join("..");
    let err = load_or_create_key(&path, &process_credentials())
        .expect_err("a final parent component must not become the seed file name");
    assert!(
        err.contains("exactly one normal component"),
        "the refusal must identify the malformed final file name: {err}"
    );
}

#[test]
fn oversized_seed_is_bounded_and_refused_without_a_false_exact_size() {
    let dir = SeedScratchDir::new();
    let seed_path = dir.0.join("seed");
    let (key, seed) = SigningKey::generate().unwrap_or_else(|e| panic!("{e}"));
    let mut oversized = seed.to_vec();
    oversized.push(0);
    std::fs::write(&seed_path, oversized).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(dir.0.join("seed.pub"), key.public_key()).unwrap_or_else(|e| panic!("{e}"));

    let err = load_or_create_key(&seed_path, &process_credentials())
        .expect_err("an oversized seed must be refused");
    assert!(
        err.contains("key seed exceeds 32 bytes") && !err.contains("key seed is 33 bytes"),
        "the bounded read must not claim the sentinel length is the full file size: {err}"
    );
}

#[test]
fn fifo_pub_sidecar_is_refused_promptly() {
    let dir = SeedScratchDir::new();
    let seed_path = dir.0.join("seed");
    load_or_create_key(&seed_path, &process_credentials()).unwrap_or_else(|e| panic!("{e}"));
    let pub_path = dir.0.join("seed.pub");
    std::fs::remove_file(&pub_path).unwrap_or_else(|e| panic!("{e}"));
    mkfifo(&pub_path);

    let probe = seed_path.clone();
    let result = within_deadline("loading a FIFO public-key sidecar", move || {
        load_or_create_key(&probe, &process_credentials())
    });
    let err = result.expect_err("a FIFO sidecar must be refused");
    assert!(
        err.contains(&pub_path.display().to_string()) && err.contains("not a regular file"),
        "the descriptor type check must refuse the named FIFO: {err}"
    );
}

#[test]
fn oversized_pub_sidecar_is_bounded_and_refused() {
    let dir = SeedScratchDir::new();
    let seed_path = dir.0.join("seed");
    load_or_create_key(&seed_path, &process_credentials()).unwrap_or_else(|e| panic!("{e}"));
    let pub_path = dir.0.join("seed.pub");
    std::fs::write(&pub_path, [0_u8; 33]).unwrap_or_else(|e| panic!("{e}"));

    let err = load_or_create_key(&seed_path, &process_credentials())
        .expect_err("an oversized public-key sidecar must be refused");
    assert!(
        err.contains("public key exceeds 32 bytes") && !err.contains("public key is 33 bytes"),
        "the bounded read must report excess without claiming a complete size: {err}"
    );
}

/// A missing `.pub` sidecar (e.g. a prior run killed after the
/// seed write landed but before the sidecar write) is recovered
/// from the seed on the next load, not a bricked identity.
#[test]
fn missing_pub_sidecar_is_regenerated_from_seed() {
    let dir = SeedScratchDir::new();
    let seed_path = dir.0.join("seed");
    let first =
        load_or_create_key(&seed_path, &process_credentials()).unwrap_or_else(|e| panic!("{e}"));
    let pub_path = dir.0.join("seed.pub");
    std::fs::remove_file(&pub_path).unwrap_or_else(|e| panic!("{e}"));
    assert!(!pub_path.exists(), "precondition: sidecar removed");
    let second = load_or_create_key(&seed_path, &process_credentials())
        .unwrap_or_else(|e| panic!("a missing .pub sidecar must recover, not brick: {e}"));
    assert_eq!(
        second.public_key(),
        first.public_key(),
        "the recovered key must be the SAME identity, not a new one"
    );
    assert!(pub_path.exists(), "the sidecar must be rewritten to disk");
    assert_eq!(
        std::fs::read(&pub_path).unwrap_or_else(|e| panic!("{e}")),
        first.public_key()
    );
}

/// A dangling symlink planted at the `.pub` sidecar
/// path BEFORE the first run must not be followed on create — the
/// public key must never be written through it to whatever the
/// link points at. Mirrors `dangling_symlink_at_seed_path_is_refused`
/// for the sidecar rather than the seed.
#[test]
fn dangling_symlink_at_pub_sidecar_path_is_refused_on_create() {
    let dir = SeedScratchDir::new();
    let seed_path = dir.0.join("seed");
    let pub_path = dir.0.join("seed.pub");
    let target_path = dir.0.join("attacker-chosen-pub-target");
    assert!(!target_path.exists(), "precondition: target absent");
    std::os::unix::fs::symlink(&target_path, &pub_path).unwrap_or_else(|e| panic!("{e}"));

    let result = load_or_create_key(&seed_path, &process_credentials());
    assert!(
        result.is_err(),
        "a dangling symlink at the .pub sidecar path must be refused, not followed"
    );
    assert!(
        !target_path.exists(),
        "the symlink target must NOT have been created — the public key must never be \
         written through the link"
    );
}

/// The interaction between the missing-sidecar recovery path
/// (the regeneration row above) and a symlink refusal. A dangling symlink at `.pub`
/// must not be mistaken for `NotFound` and routed into regeneration;
/// the no-follow sidecar open must name the symlink refusal clearly.
#[test]
fn dangling_symlink_at_pub_sidecar_path_is_refused_on_regeneration_with_clear_error() {
    let dir = SeedScratchDir::new();
    let seed_path = dir.0.join("seed");
    // A clean first run establishes a real seed on disk.
    load_or_create_key(&seed_path, &process_credentials()).unwrap_or_else(|e| panic!("{e}"));
    let pub_path = dir.0.join("seed.pub");
    std::fs::remove_file(&pub_path).unwrap_or_else(|e| panic!("{e}"));
    let target_path = dir.0.join("attacker-chosen-regen-target");
    assert!(!target_path.exists(), "precondition: target absent");
    std::os::unix::fs::symlink(&target_path, &pub_path).unwrap_or_else(|e| panic!("{e}"));

    let err = load_or_create_key(&seed_path, &process_credentials())
        .expect_err("a dangling symlink at the .pub path must be refused on regeneration");
    assert!(
        err.contains("symlink"),
        "the error must name the symlink refusal clearly, not a bare io error: {err}"
    );
    assert!(
        !target_path.exists(),
        "the symlink target must NOT have been created — the public key must never be \
         written through the link"
    );
}

/// The seed is the ONLY thing that can ever reproduce a matching
/// `key_id`, and the root it signs is durably PUT — so a create
/// that returns before the bytes are durable can brick the
/// volume (no rotation, no `--force`). Durability itself cannot
/// be tested without crashing the machine; what IS testable is
/// that the seed is fully written, correctly sized, still 0600, and
/// that a subsequent load returns the SAME key — i.e. the fsync and
/// unlink-on-failure path do not damage the create path.
#[test]
fn the_created_seed_is_complete_and_reloads_identically() {
    let dir = SeedScratchDir::new();
    let seed_path = dir.0.join("seed");

    let first =
        load_or_create_key(&seed_path, &process_credentials()).unwrap_or_else(|e| panic!("{e}"));
    let on_disk = std::fs::read(&seed_path).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        on_disk.len(),
        SEED_LEN,
        "a partially written seed would still satisfy create_new on the next run"
    );
    assert_eq!(mode_of(&seed_path) & 0o077, 0, "seed must stay 0600");
    let again =
        load_or_create_key(&seed_path, &process_credentials()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        first.public_key(),
        again.public_key(),
        "the reload must be the same identity"
    );
}

#[test]
fn private_seed_owner_refusal_after_safe_ancestor_control() {
    let dir = load_only_scratch();
    let seed = dir.0.join("seed");
    write_synthetic_seed(&seed, 32);
    let credentials = process_credentials();
    // All ancestors pass with the real owner. Isolate the descriptor's owner
    // guard using a simulated effective uid; no chown or privileged fixture.
    let paths = canonical_seed_paths(&seed, &credentials).unwrap();
    paths.load().unwrap();
    let other_uid = credentials.euid.wrapping_add(1);
    let error = granary_client::open_private_key(paths.seed(), other_uid, "seed")
        .expect_err("seed descriptor refusal must name both ownership values");
    assert!(
        error.contains(&format!("owned by uid {}", credentials.euid))
            && error.contains(&format!("running uid is {other_uid}")),
        "seed descriptor refusal must name both ownership values"
    );
}

#[test]
fn publication_load_uses_validated_paths_without_another_walk() {
    let source = include_str!("../keys.rs");
    let loader = source
        .split("fn load_existing_key_from_paths(")
        .nth(1)
        .unwrap();
    assert!(
        loader.contains("paths.load()?"),
        "publication must load already-validated seed paths"
    );
    assert!(!loader.contains("load_signing_key_only("));
}

#[test]
fn seed_ancestor_owner_refusal_precedes_descriptor_check() {
    let dir = load_only_scratch();
    let seed = dir.0.join("seed");
    write_synthetic_seed(&seed, 32);
    let owner = process_credentials().euid;
    let other_uid = owner.wrapping_add(1);
    let credentials = ProcessCredentials {
        euid: other_uid,
        ..process_credentials()
    };
    let error = load_signing_key_only(&seed, &credentials).err().unwrap();
    assert_owner_refusal(&error, owner, other_uid);
}

fn assert_owner_refusal(error: &str, owner: u32, euid: u32) {
    // Root-owned ancestors are permitted for every uid, so the descriptor
    // supplies the refusal when a root-owned seed is loaded as another uid.
    let (reason, actual, wanted) = if owner == 0 {
        (
            "owned by uid",
            format!("owned by uid {owner}"),
            format!("running uid is {euid}"),
        )
    } else {
        (
            "unsafe seed ancestor",
            format!("owner uid {owner}"),
            format!("uid {euid} or 0"),
        )
    };
    assert!(
        error.contains(reason) && error.contains(&actual) && error.contains(&wanted),
        "ancestor-first refusal must name both ownership values"
    );
}
